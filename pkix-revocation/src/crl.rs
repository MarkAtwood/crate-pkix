//! Offline CRL-based revocation checker.
//!
//! Enabled by the `crl` feature.

use crate::{Error, RevocationChecker};
use der::{Decode as _, Encode as _};
use pkix_path::{names_match, SignatureVerifier, TrustAnchor};
use spki::der::referenced::OwnedToRef as _;
use x509_cert::{
    crl::{CertificateList, RevokedCert},
    ext::pkix::crl::CrlReason,
    Certificate,
};

// `Cow` is owned by `alloc` and re-exported by `std`. Importing it under one
// name here keeps the three use sites free of cfg noise; writing
// `alloc::borrow::Cow` unconditionally would not compile under `std`,
// because `extern crate alloc` is gated to no_std mode. Same arrangement as
// `pkix-path`.
#[cfg(not(feature = "std"))]
use alloc::{borrow::Cow, vec};
#[cfg(feature = "std")]
use std::borrow::Cow;

// OID 2.5.29.21 — id-ce-CRLReasons (RFC 5280 §5.3.1)
const OID_CRL_REASONS: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.21");

/// OID for `CRLNumber` extension (RFC 5280 §5.2.3) — id-ce-cRLNumber: 2.5.29.20
const OID_CRL_NUMBER: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.20");

/// OID for deltaCRLIndicator extension (RFC 5280 §5.2.4) — id-ce-deltaCRLIndicator: 2.5.29.27
/// This extension is CRITICAL; its presence marks a delta CRL.
const OID_DELTA_CRL_INDICATOR: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.27");

/// OID for issuingDistributionPoint extension (RFC 5280 §5.2.5) — 2.5.29.28
/// Note: x509-cert 0.2.5 has a wrong `AssociatedOid` for `IssuingDistributionPoint`
/// (it uses `SubjectInfoAccess` OID instead). Always look up this extension by
/// raw OID rather than using AssociatedOid-based helpers.
const OID_ISSUING_DISTRIBUTION_POINT: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.28");

/// OID for cRLDistributionPoints extension (RFC 5280 §4.2.1.13) — 2.5.29.31.
/// Used to extract the certificate's distribution-point claim for matching
/// against a CRL's `IssuingDistributionPoint`.
const OID_CRL_DISTRIBUTION_POINTS: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.31");

/// OID for `KeyUsage` extension (RFC 5280 §4.2.1.3) — id-ce-keyUsage: 2.5.29.15
/// Used to check the `cRLSign` bit on the CRL issuer.
const OID_KEY_USAGE_CRL: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.15");

/// OID for the `certificateIssuer` CRL entry extension (RFC 5280 §5.3.3).
///
/// Critical extension that, in indirect CRLs, identifies the actual issuer
/// of the cert that an entry refers to (which may differ from the CRL's own
/// issuer). Per §5.3.3 this extension MUST be marked critical.
const OID_CERTIFICATE_ISSUER: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.29");

/// Offline CRL-based revocation checker.
///
/// Parses a DER-encoded [`CertificateList`][x509_cert::crl::CertificateList],
/// verifies its signature against the issuer's SPKI, checks the
/// `thisUpdate`/`nextUpdate` validity window, and reports whether the
/// certificate's serial number appears in the revoked list.
///
/// To also apply a delta CRL (RFC 5280 §5.2.4), use [`CrlChecker::with_delta`].
///
/// # Feature
///
/// Only available when the `crl` feature is enabled.
///
/// # Return value semantics
///
/// [`RevocationChecker::check_revocation`] returns `Ok(())` when the CRL covers
/// the certificate type and the serial number was not found in the revoked list
/// (**not revoked**).
///
/// When the CRL does not cover the certificate — its `IssuingDistributionPoint`
/// scope flags (`onlyContainsUserCerts`, `onlyContainsCACerts`,
/// `onlyContainsAttributeCerts`) exclude this certificate type, none of the
/// certificate's `cRLDistributionPoints` points at this CRL (RFC 5280
/// §6.3.3(b)), or the CRL covers only some revocation reasons
/// (`onlySomeReasons`) and does not list the certificate — the checker returns
/// `Err(`[`Error::OutOfScope`]`)` with a variant describing the mismatch.
/// Callers enforcing a **hard-fail** revocation policy should treat `OutOfScope`
/// as a non-determination and require that at least one CRL or OCSP response
/// actually covers the certificate in question.
///
/// A CRL that cannot be used at all is refused regardless of the certificate:
/// a delta CRL supplied as the complete CRL ([`Error::DeltaCrlAsComplete`])
/// and a CRL carrying an unrecognized critical CRL or CRL-entry extension
/// ([`Error::CrlUnsupportedCriticalExtension`], RFC 5280 §5.2 / §5.3).
///
/// # Indirect CRLs (RFC 5280 §5.2.6)
///
/// When the CRL is signed by a separate `cRLIssuer` certificate (rather
/// than by the cert's own issuer), construct the checker with
/// [`CrlChecker::new_with_crl_issuer`] / [`CrlChecker::with_delta_and_crl_issuer`].
/// The CRL's `IssuingDistributionPoint.indirectCRL` flag must be `TRUE`,
/// and per-entry `certificateIssuer` extensions (RFC 5280 §5.3.3) are
/// honored to identify the actual issuer of each revoked entry. The
/// caller is responsible for having pre-validated the cRLIssuer's chain
/// back to a trusted anchor.
///
/// # Limitations
///
/// - **CRL distribution-point name matching** (CDP vs IDP `distributionPoint`)
///   is implemented for both forms (`fullName` and `nameRelativeToCRLIssuer`),
///   with `nameRelativeToCRLIssuer` resolved by appending the relative RDN to
///   the appropriate base DN (the certificate's issuer for the cert's CDP, the
///   CRL's issuer for the CRL's IDP). Same-form direct comparison and
///   cross-form resolved comparison both work, so a cert whose CDP uses
///   `nameRelativeToCRLIssuer` matches a CRL whose IDP uses `fullName` (and
///   vice versa) when both resolve to the same DN.
///   `GeneralName::DirectoryName` entries compare via
///   [`pkix_path::names_match`] (proper DN equivalence); other variants
///   (URI, dNSName, rfc822Name, IP address, etc.) compare via byte-exact DER
///   encoding equality.
///   The per-DP `cRLIssuer` field is honored (RFC 5280 §6.3.3(b)(1)): a DP
///   carrying `cRLIssuer` only matches an indirect CRL issued by that
///   `cRLIssuer`, and its `nameRelativeToCRLIssuer` is resolved against the
///   `cRLIssuer` DN (§4.2.1.13); a DP without `cRLIssuer` only matches a
///   CRL issued by the certificate's issuer. Failing DPs surface as
///   `OutOfScopeReason::CrlDistributionPointIssuerMismatch` /
///   `CrlIdpDistributionPointMismatch`.
/// - **Reason partitioning** (`onlySomeReasons`) is handled fail-safe: such a
///   CRL can report a listed certificate as revoked, but an unlisted
///   certificate yields `OutOfScopeReason::CrlOnlySomeReasons` instead of
///   `Ok(())`. Accumulating a full reasons mask over several partitioned
///   CRLs (RFC 5280 §6.3.3 `reasons_mask`) is not implemented.
/// - The checker enforces `onlyContainsUserCerts`, `onlyContainsCACerts`,
///   and `onlyContainsAttributeCerts` scope flags directly; see
///   `OutOfScopeReason` for the surfaced variants.
/// - The cRLIssuer's chain is NOT validated by this crate — callers must
///   present an already-validated cRLIssuer cert. Composing this with
///   `pkix-path` to validate the cRLIssuer chain in-process is the umbrella
///   crate's responsibility (`pkix-chain`).
/// - Path-level CRL signer discovery (RFC 5280 §6.3.3(f)) IS supported via
///   [`CrlChecker::new_with_signer_discovery`] and the free
///   [`discover_crl_signer`][crate::discover_crl_signer] helper, both gated
///   by the `crl` feature. Discovery uses `AuthorityKeyIdentifier` →
///   `SubjectKeyIdentifier` matching with issuer-DN fallback, and verifies
///   the discovered signer has `cRLSign` in `KeyUsage` and reaches a
///   self-signed cert in the supplied bundle. Full RFC 5280 §6.1 validation
///   of the signer's chain remains the responsibility of higher-layer
///   composers; see that constructor's "Limitations" section for the
///   project's documented stance on the lenient-vs-strict tradeoff.
/// - The `certificateIssuer` extension's `issuerAltName` form (a non-DN
///   GeneralName) is not currently used for entry-issuer lookup; only the
///   `directoryName` form is. Real-world indirect CRLs use directoryName.
/// - [`RevocationChecker::check_revocation_against_anchor`] is overridden.
///   For the certificate issued directly by a trust anchor, the CRL is verified
///   using the anchor's subject DN and SPKI in place of the missing issuer
///   `Certificate`.  The `cRLSign` `KeyUsage` check is omitted for trust anchors
///   (anchors are trusted by construction; they carry no `KeyUsage` to inspect).
///   If the CRL's issuer name does not match the anchor, the method returns
///   [`Error::CrlIssuerMismatch`] rather than `Ok(())`.
///
/// [`check_revocation`]: crate::RevocationChecker::check_revocation
/// [`RevocationChecker::check_revocation_against_anchor`]: crate::RevocationChecker::check_revocation_against_anchor
#[derive(Clone, Debug)]
pub struct CrlChecker<V> {
    /// Pre-parsed base CRL. Decoded once at construction; reused on every
    /// [`RevocationChecker::check_revocation`] call.
    crl: CertificateList,
    /// Optional pre-parsed delta CRL. When present, its entries are merged
    /// with the base CRL in `check_revocation` (RFC 5280 §5.2.4).
    delta_crl: Option<CertificateList>,
    /// Optional cRLIssuer cert when the CRL is indirect (RFC 5280 §5.2.6)
    /// or the signer is discovered via [`CrlChecker::new_with_signer_discovery`].
    /// `Some` ⇔ the stored cert's SPKI is used for the CRL signature check,
    /// its KeyUsage for the cRLSign bit check, and its subject DN for the
    /// CRL-issuer-identity match. The caller (or the discovery routine) is
    /// responsible for any chain validation of the cert.
    /// `None` ⇔ direct CRL: the `issuer` argument's identity is used.
    crl_issuer_cert: Option<Certificate>,
    /// Whether the stored `crl_issuer_cert` was located by path-level
    /// signer discovery rather than supplied explicitly via an indirect-CRL
    /// constructor.
    ///
    /// The two cases:
    ///
    /// - `true` — **signer from bundle**: the cert was discovered by
    ///   [`CrlChecker::new_with_signer_discovery`] via AKI/SKI or
    ///   issuer-DN matching against the caller-supplied certificate
    ///   bundle. `check_revocation` accepts the stored cert as the
    ///   effective signer regardless of whether the CRL declares itself
    ///   indirect via `IDP.indirectCRL`. This bypasses the indirect-CRL
    ///   cross-check, which is required to support PKITS §4.5 chains
    ///   where the CRL is a direct (non-indirect) CRL whose signer
    ///   happens to differ from the EE's stated issuer cert because of a
    ///   self-issued key-rollover bridge — the §4.5 CRLs do **not** set
    ///   `IDP.indirectCRL`, so the legacy `_with_crl_issuer` path would
    ///   (correctly) reject them with `IndirectCrlIssuerUnexpected`.
    ///
    /// - `false` — **normal signer selection**: either no `crl_issuer_cert`
    ///   is stored (direct CRL, signer is the `issuer` argument) or one
    ///   was supplied explicitly via `new_with_crl_issuer` /
    ///   `with_delta_and_crl_issuer` (indirect CRL). The legacy
    ///   `IndirectCrlIssuerMissing` / `IndirectCrlIssuerUnexpected`
    ///   cross-check between the constructor choice and the CRL's
    ///   `IDP.indirectCRL` flag applies.
    signer_discovered: bool,
    now_unix: u64,
    verifier: V,
}

impl<V: SignatureVerifier> CrlChecker<V> {
    /// The certificate whose key verifies this CRL's signature, when it is not
    /// the `issuer` argument passed to
    /// [`check_revocation`](RevocationChecker::check_revocation).
    ///
    /// `Some` for an indirect CRL built with
    /// [`new_with_crl_issuer`](Self::new_with_crl_issuer) or
    /// [`with_delta_and_crl_issuer`](Self::with_delta_and_crl_issuer), and for
    /// a signer located by
    /// [`new_with_signer_discovery`](Self::new_with_signer_discovery). `None`
    /// for a direct CRL, where the signer is the issuer the caller supplies at
    /// check time and so is already in hand.
    ///
    /// # Why a caller wants this
    ///
    /// **This crate does not and cannot check whether the CRL's signer has
    /// itself been revoked.** Nothing in a `CrlChecker`'s inputs carries that
    /// information. A CRL signed by a revoked certificate must not be trusted,
    /// so a caller enforcing revocation has to make that determination, and
    /// needs to know which certificate to make it about.
    ///
    /// With discovery that certificate is chosen inside the constructor, so
    /// without this accessor the caller could not find out. See
    /// [`new_with_signer_discovery`](Self::new_with_signer_discovery) for the
    /// concrete scenario.
    #[must_use]
    pub const fn crl_signer(&self) -> Option<&Certificate> {
        self.crl_issuer_cert.as_ref()
    }

    /// Whether [`crl_signer`](Self::crl_signer) was located by discovery
    /// rather than supplied by the caller.
    ///
    /// Useful to a caller that trusts a certificate it chose itself but wants
    /// to re-examine one the library picked out of a bundle.
    #[must_use]
    pub const fn crl_signer_was_discovered(&self) -> bool {
        self.signer_discovered
    }

    /// Create a new `CrlChecker`.
    ///
    /// - `crl_der`  — DER-encoded `CertificateList` (any `AsRef<[u8]>`, e.g. `Vec<u8>` or `&[u8]`)
    /// - `now_unix` — current time as seconds since the Unix epoch
    /// - `verifier` — signature verifier used to authenticate the CRL
    ///
    /// The DER is parsed once at construction time and the parsed
    /// [`CertificateList`] is reused on every check, eliminating per-check
    /// re-parse work.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CrlParseError`] if `crl_der` cannot be DER-decoded.
    ///
    /// # Delta CRLs
    ///
    /// `crl_der` must be a complete CRL. A delta CRL (a `CertificateList`
    /// containing a `deltaCRLIndicator` extension) contains only the changes
    /// since its base CRL, so [`RevocationChecker::check_revocation`] refuses it
    /// with [`Error::DeltaCrlAsComplete`]. Pass it via [`CrlChecker::with_delta`]
    /// together with the matching base CRL instead.
    pub fn new(crl_der: impl AsRef<[u8]>, now_unix: u64, verifier: V) -> crate::Result<Self> {
        let crl = CertificateList::<x509_cert::certificate::Rfc5280>::from_der(crl_der.as_ref())
            .map_err(|e| Error::CrlParseError(crate::DerError::new(e)))?;
        Ok(Self {
            crl,
            delta_crl: None,
            crl_issuer_cert: None,
            signer_discovered: false,
            now_unix,
            verifier,
        })
    }

    /// Create a `CrlChecker` for an indirect CRL (RFC 5280 §5.2.6).
    ///
    /// `crl_issuer_cert` is the certificate that signed the CRL. It MUST
    /// have its chain pre-validated by the caller back to a trusted
    /// anchor — this crate verifies only the cRLIssuer-cert-to-CRL
    /// relationship, not the cRLIssuer-cert-to-anchor chain.
    ///
    /// The supplied CRL must declare itself indirect via its
    /// `IssuingDistributionPoint.indirectCRL` flag (RFC 5280 §5.2.5);
    /// otherwise [`Error::IndirectCrlIssuerUnexpected`] is returned at
    /// `check_revocation` time.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CrlParseError`] if `crl_der` cannot be DER-decoded.
    pub fn new_with_crl_issuer(
        crl_der: impl AsRef<[u8]>,
        crl_issuer_cert: Certificate,
        now_unix: u64,
        verifier: V,
    ) -> crate::Result<Self> {
        let crl = CertificateList::<x509_cert::certificate::Rfc5280>::from_der(crl_der.as_ref())
            .map_err(|e| Error::CrlParseError(crate::DerError::new(e)))?;
        Ok(Self {
            crl,
            delta_crl: None,
            crl_issuer_cert: Some(crl_issuer_cert),
            signer_discovered: false,
            now_unix,
            verifier,
        })
    }

    /// Create a `CrlChecker` that performs path-level CRL signer discovery
    /// (RFC 5280 §6.3.3(f)).
    ///
    /// The caller supplies an unordered `bundle` of candidate certificates
    /// (typically the certs already collected for the chain plus any local
    /// CRL-signer candidates) and the certificate that will subsequently be
    /// revocation-checked. The function:
    ///
    /// 1. Parses the CRL DER.
    /// 2. Calls [`discover_crl_signer`][crate::discover_crl_signer] to locate the cert in `bundle` that
    ///    signed the CRL (AKI/SKI walk with issuer-DN fallback).
    /// 3. Verifies the discovered signer has `cRLSign` in its `KeyUsage`
    ///    extension (RFC 5280 §6.3.3(f)). A signer with no `KeyUsage`
    ///    extension passes this check (RFC 5280 leaves the extension
    ///    optional and `pkix-revocation` follows the same fail-open
    ///    interpretation as [`CrlChecker::new`] / `new_with_crl_issuer`).
    /// 4. Verifies the discovered signer chains structurally back to a
    ///    self-signed (anchor-like) certificate present in the same
    ///    bundle (see "Limitations" below for what "chains structurally"
    ///    means and why it differs from full RFC 5280 §6.1 validation).
    /// 5. Stores the discovered signer for use as the effective CRL
    ///    signer whenever [`RevocationChecker::check_revocation`] is
    ///    later called. The signer is used regardless of whether the
    ///    CRL's `IssuingDistributionPoint.indirectCRL` flag is set,
    ///    which is required to support PKITS §4.5 (direct CRLs signed by
    ///    self-issued key-rollover bridge certs).
    ///
    /// The checker is not bound to a particular certificate. It used to
    /// take a `cert_to_check` argument "for ergonomic symmetry with the
    /// discovery flow", which was misleading: the argument was never
    /// read, and the certificate whose status is actually queried is the
    /// one passed to [`RevocationChecker::check_revocation`] later. A
    /// parameter in the constructor implied a binding that did not
    /// exist, so one checker could be built naming certificate A and
    /// then used to check certificate B with no complaint.
    ///
    /// What is stored is the signer: its SPKI authenticates the CRL,
    /// while the `(issuer, serial)` lookup is driven by the `cert`
    /// argument at call time.
    ///
    /// # Errors
    ///
    /// - [`Error::CrlParseError`] if `crl_der` cannot be DER-decoded.
    /// - [`Error::CrlSignerNotFound`] if no cert in `bundle` could be
    ///   identified as the CRL's signer via AKI/SKI or issuer-DN match.
    /// - [`Error::CrlSignMissing`] if the discovered signer has a
    ///   `KeyUsage` extension that does not include `cRLSign`.
    /// - [`Error::CrlSignerNotTrusted`] if the discovered signer cannot
    ///   reach a self-signed cert in `bundle` by repeated AKI/SKI or
    ///   issuer-DN walks.
    ///
    /// # Limitations
    ///
    /// **No signature verification is performed on the signer's chain.**
    /// Step 4 above is a structural reachability check — it verifies the
    /// bundle *contains* an anchor for the signer, not that any of the
    /// signatures along the way actually verify. This intentional
    /// limitation preserves the project's one-way dependency direction
    /// (`pkix-chain` → `pkix-revocation` → `pkix-path`): pulling
    /// `pkix-path::validate_path` into this constructor would invert that
    /// direction.
    ///
    /// Higher-layer composers that need full RFC 5280 §6.1 validation of
    /// the signer's path (signature, validity, name constraints, …) MUST
    /// do that separately and then pass the validated cert via
    /// [`CrlChecker::new_with_crl_issuer`]. This constructor is the
    /// right choice when:
    ///
    /// - The bundle is already known to be path-valid (e.g.,
    ///   `pkix-chain` already validated it), OR
    /// - The caller accepts the project's documented stance that bundle
    ///   pre-validation is the caller's responsibility.
    ///
    /// **The discovered signer is not checked for revocation, and cannot
    /// be.** Nothing in this constructor's inputs says whether a bundle
    /// certificate has been revoked, so a CRL signed by a revoked
    /// certificate is accepted here. That is the one limitation above whose
    /// consequence is not merely incomplete validation: revoking a
    /// compromised CRL-signing certificate is the defence against whoever
    /// holds its key, and a validator that keeps honouring its CRLs lets
    /// them suppress revocations — including, potentially, the revocation
    /// of the certificate they compromised.
    ///
    /// Note that "the bundle is already path-valid because `pkix-chain`
    /// validated it" does **not** cover this. A CRL-signing certificate is
    /// typically a *sibling* of the chain rather than a link in it, so the
    /// chain validation never looked at it. NIST PKITS 4.4.21 is built on
    /// exactly that gap: it is structurally identical to the 4.4.19 beside
    /// it — same topology, CRL-signing certificate a sibling, empty CRL —
    /// and differs only in that its signer's certificate is revoked by the
    /// trust anchor's CRL. A validator must then treat the end entity's
    /// status as undetermined.
    ///
    /// A caller enforcing revocation should either exclude revoked
    /// certificates from `bundle` before calling, or inspect
    /// [`crl_signer`](Self::crl_signer) afterwards and make the
    /// determination itself. [`discover_crl_signer`][dcs] is public for the
    /// first approach, so the signer can be identified without building a
    /// checker.
    ///
    /// This is left to the caller rather than taken on here for the reason
    /// the rest of this section gives: deciding it requires revocation
    /// status for the signer, which is the question this type is being used
    /// to answer, and resolving it internally would have a revocation check
    /// recurse into itself.
    ///
    /// [dcs]: crate::discover_crl_signer
    ///
    /// **The bundle slice is not retained.** Only the discovered signer
    /// `Certificate` is cloned and stored.
    pub fn new_with_signer_discovery(
        crl_der: impl AsRef<[u8]>,
        bundle: &[Certificate],
        now_unix: u64,
        verifier: V,
    ) -> crate::Result<Self> {
        let crl = CertificateList::<x509_cert::certificate::Rfc5280>::from_der(crl_der.as_ref())
            .map_err(|e| Error::CrlParseError(crate::DerError::new(e)))?;

        let signer = crate::signer_discovery::discover_crl_signer(bundle, &crl)
            .ok_or(Error::CrlSignerNotFound)?;

        // RFC 5280 §6.3.3(f): the signer cert MUST assert cRLSign in
        // KeyUsage when the extension is present. Reuse the same fail-open
        // semantics as check_crl_sign (absent extension = no constraint).
        check_crl_sign(signer)?;

        // Structural anchor-reachability check. See the "Limitations"
        // section of this method's rustdoc for what this does and does
        // not guarantee.
        if !crate::signer_discovery::reaches_self_signed(bundle, signer) {
            return Err(Error::CrlSignerNotTrusted);
        }

        Ok(Self {
            crl,
            delta_crl: None,
            crl_issuer_cert: Some(signer.clone()),
            signer_discovered: true,
            now_unix,
            verifier,
        })
    }

    /// Create a `CrlChecker` with a base CRL and a delta CRL.
    ///
    /// The delta CRL is merged into the base CRL per RFC 5280 §5.2.4:
    /// - Entries in the delta that are not in the base are added.
    /// - Entries in the delta with reason `removeFromCRL` are removed from the
    ///   base.
    /// - The merged result is used for all subsequent `check_revocation` calls.
    ///
    /// # Errors
    ///
    /// Returns `Err(Error::CrlParseError)` if either the base or delta CRL DER
    /// cannot be decoded.
    ///
    /// Returns `Err(Error::DeltaCrlBaseMismatch)` if:
    /// - The delta CRL's `BaseCRLNumber` is absent (not a delta CRL), or
    /// - The delta's `BaseCRLNumber` is greater than the base CRL's `CRLNumber`
    ///   (the delta was produced against a newer base than the one supplied).
    pub fn with_delta(
        base_der: impl AsRef<[u8]>,
        delta_der: impl AsRef<[u8]>,
        now_unix: u64,
        verifier: V,
    ) -> crate::Result<Self> {
        // Parse both to validate structure and extract CRL numbers.
        let base_crl =
            CertificateList::<x509_cert::certificate::Rfc5280>::from_der(base_der.as_ref())
                .map_err(|e| Error::CrlParseError(crate::DerError::new(e)))?;
        let delta_crl =
            CertificateList::<x509_cert::certificate::Rfc5280>::from_der(delta_der.as_ref())
                .map_err(|e| Error::CrlParseError(crate::DerError::new(e)))?;

        // The base CRL MUST NOT itself be a delta CRL (RFC 5280 §5.2.4: only a
        // full CRL may serve as the base).  Detect by OID presence alone — do not
        // rely on successful decode, since a malformed deltaCRLIndicator value
        // would cause base_crl_number() to return None and silently pass as a base.
        if has_delta_crl_indicator(&base_crl) {
            return Err(Error::DeltaCrlBaseMismatch);
        }

        // The delta MUST have a deltaCRLIndicator extension (marks it as a delta CRL).
        // Check presence by OID first to distinguish "absent" from "present but malformed":
        //   - Extension absent           → not a delta CRL → DeltaCrlBaseMismatch
        //   - Extension present, value malformed → CrlParseError (structural error)
        if !has_delta_crl_indicator(&delta_crl) {
            // No deltaCRLIndicator OID → this is not a delta CRL.
            return Err(Error::DeltaCrlBaseMismatch);
        }
        // has_delta_crl_indicator confirmed OID presence above; None is unreachable.
        let delta_base_num = base_crl_number(&delta_crl)
            .ok_or(Error::DeltaCrlBaseMismatch)? // can only happen if code invariant broken
            .map_err(|e| Error::CrlParseError(crate::DerError::new(e)))?;

        // The base CRL and delta CRL MUST have the same issuer.
        if !names_match(
            &base_crl.tbs_cert_list.issuer,
            &delta_crl.tbs_cert_list.issuer,
        ) {
            return Err(Error::DeltaCrlBaseMismatch);
        }

        // If the base CRL has a CRL number, the delta's BaseCRLNumber must be
        // ≤ it (we have a base that is at least as current as what the delta expects).
        // A malformed or overflowing base CRLNumber is treated as CrlParseError
        // rather than silently skipping the freshness check.
        if let Some(base_num_result) = crl_number(&base_crl) {
            let base_num =
                base_num_result.map_err(|e| Error::CrlParseError(crate::DerError::new(e)))?;
            if delta_base_num > base_num {
                return Err(Error::CrlNumberMismatch);
            }
        }

        Ok(Self {
            crl: base_crl,
            delta_crl: Some(delta_crl),
            crl_issuer_cert: None,
            signer_discovered: false,
            now_unix,
            verifier,
        })
    }

    /// Same as [`CrlChecker::new_with_crl_issuer`] plus a delta CRL.
    ///
    /// The delta CRL must be signed by the same cRLIssuer cert and be
    /// declared indirect via its own `IssuingDistributionPoint.indirectCRL`
    /// flag. This is verified at `check_revocation` time as part of the
    /// RFC 5280 §6.3.3(c) rule that the delta's `IssuingDistributionPoint` be
    /// identical to the base CRL's ([`Error::DeltaCrlBaseMismatch`]).
    ///
    /// # Errors
    ///
    /// Same as [`CrlChecker::with_delta`], plus the indirect-CRL gates
    /// described in [`CrlChecker::new_with_crl_issuer`].
    pub fn with_delta_and_crl_issuer(
        base_der: impl AsRef<[u8]>,
        delta_der: impl AsRef<[u8]>,
        crl_issuer_cert: Certificate,
        now_unix: u64,
        verifier: V,
    ) -> crate::Result<Self> {
        // Reuse the with_delta path for the structural cross-checks
        // (issuer match, CRL number ordering, delta-base relationship),
        // then attach the cRLIssuer cert.
        let mut checker = Self::with_delta(base_der, delta_der, now_unix, verifier)?;
        checker.crl_issuer_cert = Some(crl_issuer_cert);
        Ok(checker)
    }
}

impl<V: SignatureVerifier> RevocationChecker for CrlChecker<V> {
    fn check_revocation(&self, cert: &Certificate, issuer: &Certificate) -> crate::Result<()> {
        // (1) Reuse the pre-parsed base CRL (parsed once at construction).
        let crl = &self.crl;
        // (1a) RFC 5280 §5.2 / §5.3 / §5.2.4: refuse a delta CRL in the
        //      complete-CRL slot and any CRL carrying a critical extension
        //      (CRL-level or entry-level) this checker does not process.
        check_crl_usable_as_complete(crl)?;

        // (2) Determine the effective CRL signer: either the cert's
        //     issuer (direct CRL) or a separate cRLIssuer cert (indirect
        //     CRL, RFC 5280 §5.2.6). The selection is decided at
        //     construction time:
        //     - new() / with_delta()                        → direct
        //     - new_with_crl_issuer() / _with_delta_…()    → indirect
        //
        //     Cross-check the construction choice against the CRL's own
        //     IDP.indirectCRL flag: mismatches are rejected with a
        //     specific error so the caller learns they used the wrong
        //     constructor (rather than being told "signature invalid"
        //     after the wrong key is used to verify).
        let parsed_idp = parse_issuing_dp(crl)?;
        let crl_declares_indirect = parsed_idp
            .as_ref()
            .map(|idp| idp.indirect_crl)
            .unwrap_or(false);
        let signer_subject: &x509_cert::name::Name;
        let signer_spki: spki::SubjectPublicKeyInfoRef<'_>;
        let signer_for_crlsign_check: Option<&Certificate>;
        match (&self.crl_issuer_cert, crl_declares_indirect) {
            (Some(crl_issuer), true) => {
                signer_subject = crl_issuer.tbs_certificate().subject();
                signer_spki = crl_issuer
                    .tbs_certificate()
                    .subject_public_key_info()
                    .owned_to_ref();
                signer_for_crlsign_check = Some(crl_issuer);
            }
            (Some(discovered), false) if self.signer_discovered => {
                // Path-level signer discovery (new_with_signer_discovery).
                // The CRL may be direct (§4.5 self-issued key-rollover bridge)
                // or indirect (§4.14.22-26 indirect CRLs); the cert was located
                // structurally and the cross-check between "is the CRL declared
                // indirect" and "did the caller supply a signer" is intentionally
                // bypassed here. The discovered signer's SPKI is authoritative
                // for the CRL signature verification regardless of the IDP
                // indirectCRL flag.
                signer_subject = discovered.tbs_certificate().subject();
                signer_spki = discovered
                    .tbs_certificate()
                    .subject_public_key_info()
                    .owned_to_ref();
                signer_for_crlsign_check = Some(discovered);
            }
            (Some(_), false) => {
                // Caller asserted indirect via new_with_crl_issuer; CRL says
                // direct. Reject — this rejects the wrong-constructor case.
                return Err(Error::IndirectCrlIssuerUnexpected);
            }
            (None, true) => {
                // CRL says indirect; caller did not supply cRLIssuer cert.
                return Err(Error::IndirectCrlIssuerMissing);
            }
            (None, false) => {
                signer_subject = issuer.tbs_certificate().subject();
                signer_spki = issuer
                    .tbs_certificate()
                    .subject_public_key_info()
                    .owned_to_ref();
                signer_for_crlsign_check = Some(issuer);
            }
        }

        // (2a) The CRL issuer name must match the effective signer's
        //      subject DN. This guards against a caller passing a
        //      cRLIssuer cert with a different DN than the CRL claims to
        //      have come from.
        if !names_match(&crl.tbs_cert_list.issuer, signer_subject) {
            return Err(Error::CrlIssuerMismatch);
        }
        // (2b) The cert under check must be issued by a CA in the
        //      domain this CRL covers. For direct CRLs, that is exactly
        //      the CRL issuer (cert.issuer == CRL.issuer). For indirect
        //      CRLs, cert.issuer may differ from CRL.issuer (the
        //      cRLIssuer's subject); the per-entry effective-issuer
        //      check below handles the actual matching. We still
        //      require that the supplied `issuer` cert match cert.issuer
        //      as a defense-in-depth check on the caller-supplied
        //      issuer-of-cert identity.
        if !names_match(
            issuer.tbs_certificate().subject(),
            cert.tbs_certificate().issuer(),
        ) {
            return Err(Error::CrlIssuerMismatch);
        }
        // (2c) For direct CRLs: the cert's issuer must also match the CRL
        //      issuer. For indirect CRLs this is intentionally skipped —
        //      the whole point of §5.2.6 is that the two may differ, and
        //      the per-entry certificateIssuer extension carries the
        //      actual issuer of each entry.
        //
        // Discovery mode is held to this too, but only when the CRL does
        // not declare itself indirect. It used to be exempt wholesale on
        // the grounds that the §4.5 key-rollover case satisfies the test
        // anyway (same issuer DN, different signing key), which is true
        // and is exactly why exempting it bought nothing: the check was
        // skipped precisely where it would have passed. What it did give
        // up was the direct case where the DNs genuinely disagree. There
        // the signer is discovered structurally from the bundle, so
        // without this the CRL's own claim about which CA it covers is
        // never compared against the certificate being checked.
        //
        // Gating on the IDP flag keeps the §4.14.22-26 indirect cases
        // working, where the DNs differ by design.
        let enforce_direct_crl_domain =
            self.crl_issuer_cert.is_none() || (self.signer_discovered && !crl_declares_indirect);
        if enforce_direct_crl_domain
            && !names_match(cert.tbs_certificate().issuer(), &crl.tbs_cert_list.issuer)
        {
            return Err(Error::CrlIssuerMismatch);
        }

        // (3) RFC 5280 §6.3.3(f): the CRL signer must have cRLSign in KeyUsage when present.
        //     For indirect CRLs this check runs on the cRLIssuer cert, NOT the
        //     cert's own issuer (that's the whole point of separation of duty).
        if let Some(signer_cert) = signer_for_crlsign_check {
            check_crl_sign(signer_cert)?;
        }

        // (3b) Check CRL validity window before verifying the signature.
        //     Rejecting stale CRLs early avoids a potentially expensive signature
        //     verification on a CRL we would discard anyway.
        //     Absent nextUpdate is treated as expired: an indefinitely valid CRL would
        //     allow a stale revocation list to suppress detection of revoked certificates.
        let this_update = crl.tbs_cert_list.this_update.to_unix_duration().as_secs();
        if self.now_unix < this_update {
            return Err(Error::CrlExpired);
        }
        let next_update = crl
            .tbs_cert_list
            .next_update
            .as_ref()
            .ok_or(Error::CrlExpired)?;
        if self.now_unix > next_update.to_unix_duration().as_secs() {
            return Err(Error::CrlExpired);
        }

        // (4) Verify the CRL signature against the effective signer's SPKI
        //     (issuer for direct CRLs, cRLIssuer cert for indirect CRLs).
        //     Clone the SPKI ref so the delta path below (if it runs) can
        //     consume the original — the spki ref-struct is small.
        let tbs_bytes = crl
            .tbs_cert_list
            .to_der()
            .map_err(|e| Error::CrlParseError(crate::DerError::new(e)))?;
        self.verifier
            .verify_signature(
                crl.signature_algorithm.owned_to_ref(),
                signer_spki.clone(),
                &tbs_bytes,
                crl.signature.raw_bytes(),
            )
            // Verifier returns an opaque error; no additional context available.
            .map_err(|_| Error::CrlSignatureInvalid)?;

        // (5)-(7) Scope, delta merge and serial lookup are shared with the
        //     anchor flow.
        self.check_scope_delta_and_status(cert, parsed_idp.as_ref(), signer_spki, signer_subject)
    }

    /// Check revocation for `cert` issued directly by a trust anchor.
    ///
    /// Uses the anchor's `subject` and `subject_public_key_info` in place of
    /// an issuer `Certificate` to verify the CRL.  The `cRLSign` `KeyUsage` bit
    /// check is omitted because trust anchors do not carry a `Certificate` with
    /// extensions to inspect.
    ///
    /// # Limitations
    ///
    /// CRL discovery via the `cRLDistributionPoints` extension is by
    /// design not implemented in `pkix-revocation` itself — this crate
    /// stays `no_std` for its core types and does not perform network
    /// I/O. The CRL DER must be supplied at construction time; for
    /// online fetching from CRL DPs, use `pkix-revocation-http`.
    ///
    /// Path-level CRL signer discovery (RFC 5280 §6.3.3(f)) IS supported
    /// via [`CrlChecker::new_with_signer_discovery`] on the
    /// `check_revocation` flow, but is **not** wired into the
    /// `check_revocation_against_anchor` path: trust anchors do not carry
    /// a `Certificate` for the bundle walk to terminate at, so the
    /// anchor flow continues to require an explicit `cRLIssuer` cert for
    /// indirect CRLs. Direct CRLs at the anchor level are unaffected.
    ///
    /// If the CRL's issuer name does not match the anchor's subject, this
    /// method returns [`Error::CrlIssuerMismatch`] rather than `Ok(())`,
    /// ensuring a mismatched CRL is surfaced rather than silently skipped.
    fn check_revocation_against_anchor(
        &self,
        cert: &Certificate,
        anchor: &TrustAnchor,
    ) -> crate::Result<()> {
        // (1) Reuse the pre-parsed base CRL (parsed once at construction).
        let crl = &self.crl;
        // (1a) Same complete-CRL usability gate as check_revocation.
        check_crl_usable_as_complete(crl)?;

        // (2) Determine the effective CRL signer as in check_revocation.
        //     For the anchor flow, the "issuer" identity is the anchor itself.
        let parsed_idp = parse_issuing_dp(crl)?;
        let crl_declares_indirect = parsed_idp
            .as_ref()
            .map(|idp| idp.indirect_crl)
            .unwrap_or(false);
        let signer_subject: &x509_cert::name::Name;
        let signer_spki: spki::SubjectPublicKeyInfoRef<'_>;
        let signer_for_crlsign_check: Option<&Certificate>;
        match (&self.crl_issuer_cert, crl_declares_indirect) {
            (Some(crl_issuer), true) => {
                signer_subject = crl_issuer.tbs_certificate().subject();
                signer_spki = crl_issuer
                    .tbs_certificate()
                    .subject_public_key_info()
                    .owned_to_ref();
                signer_for_crlsign_check = Some(crl_issuer);
            }
            (Some(discovered), false) if self.signer_discovered => {
                // Same discovery-mode semantics as check_revocation: the
                // discovered signer is authoritative regardless of the
                // CRL's IDP.indirectCRL flag. See the matching arm in
                // check_revocation for the full rationale.
                signer_subject = discovered.tbs_certificate().subject();
                signer_spki = discovered
                    .tbs_certificate()
                    .subject_public_key_info()
                    .owned_to_ref();
                signer_for_crlsign_check = Some(discovered);
            }
            (Some(_), false) => return Err(Error::IndirectCrlIssuerUnexpected),
            (None, true) => return Err(Error::IndirectCrlIssuerMissing),
            (None, false) => {
                signer_subject = &anchor.subject;
                signer_spki = anchor.subject_public_key_info.owned_to_ref();
                // Trust anchors have no KeyUsage extension accessible; the
                // cRLSign check is skipped — anchors are trusted by construction.
                signer_for_crlsign_check = None;
            }
        }

        // (2a) The CRL issuer must match the effective signer's subject DN.
        if !names_match(&crl.tbs_cert_list.issuer, signer_subject) {
            return Err(Error::CrlIssuerMismatch);
        }
        // (2b) The cert under check must be issued by the anchor for the
        //      anchor flow regardless of indirect-vs-direct: the anchor
        //      is the cert's *issuer*, even when the CRL is signed by a
        //      separate cRLIssuer.
        if !names_match(cert.tbs_certificate().issuer(), &anchor.subject) {
            return Err(Error::CrlIssuerMismatch);
        }
        // (2c) As in `check_revocation`: a direct CRL must name the same
        //      CA that issued the certificate.
        //
        // Without the discovery arm, (2a) and (2b) together imply this —
        // both sides reduce to the anchor's subject. Under discovery they
        // do not: (2a) ties the CRL issuer to the *discovered* signer's
        // subject while (2b) ties the cert to the anchor, leaving the two
        // free to disagree. So this is a real gap on this path rather
        // than a restatement, and it is enforced here for the same reason
        // and under the same IDP condition.
        if self.signer_discovered
            && !crl_declares_indirect
            && !names_match(cert.tbs_certificate().issuer(), &crl.tbs_cert_list.issuer)
        {
            return Err(Error::CrlIssuerMismatch);
        }

        // (3) cRLSign check on the cRLIssuer cert in the indirect case;
        //     skipped for the anchor itself in the direct case (anchors
        //     are trusted by construction; see signer_for_crlsign_check
        //     above).
        if let Some(signer_cert) = signer_for_crlsign_check {
            check_crl_sign(signer_cert)?;
        }

        // (4) Check CRL validity window before verifying the signature.
        //     Same rationale as check_revocation: reject stale CRLs early.
        let this_update = crl.tbs_cert_list.this_update.to_unix_duration().as_secs();
        if self.now_unix < this_update {
            return Err(Error::CrlExpired);
        }
        let next_update = crl
            .tbs_cert_list
            .next_update
            .as_ref()
            .ok_or(Error::CrlExpired)?;
        if self.now_unix > next_update.to_unix_duration().as_secs() {
            return Err(Error::CrlExpired);
        }

        // (5) Verify the CRL signature against the effective signer's SPKI.
        //     Clone for the same reason as in check_revocation: the delta
        //     path below may consume the original.
        let tbs_bytes = crl
            .tbs_cert_list
            .to_der()
            .map_err(|e| Error::CrlParseError(crate::DerError::new(e)))?;
        self.verifier
            .verify_signature(
                crl.signature_algorithm.owned_to_ref(),
                signer_spki.clone(),
                &tbs_bytes,
                crl.signature.raw_bytes(),
            )
            .map_err(|_| Error::CrlSignatureInvalid)?;

        // (6)-(8) Scope, delta merge and serial lookup (shared with
        //     check_revocation).
        self.check_scope_delta_and_status(cert, parsed_idp.as_ref(), signer_spki, signer_subject)
    }
}

impl<V: SignatureVerifier> CrlChecker<V> {
    /// Steps shared by [`RevocationChecker::check_revocation`] and
    /// [`RevocationChecker::check_revocation_against_anchor`] once the base
    /// CRL's signer, freshness and signature have been verified: the
    /// RFC 5280 §6.3.3(b) scope checks, the §5.2.4 delta merge, the serial
    /// lookup, and the §6.3.3 reasons-coverage gate.
    ///
    /// Scope mismatches surface as [`Error::OutOfScope`] so callers can
    /// distinguish "verified not-revoked" (`Ok(())`) from "no determination
    /// made". Hard-fail revocation policies should treat `OutOfScope` as a
    /// failure.
    fn check_scope_delta_and_status(
        &self,
        cert: &Certificate,
        parsed_idp: Option<&x509_cert::ext::pkix::crl::IssuingDistributionPoint>,
        signer_spki: spki::SubjectPublicKeyInfoRef<'_>,
        signer_subject: &x509_cert::name::Name,
    ) -> crate::Result<()> {
        let crl = &self.crl;

        // (a) RFC 5280 §5.2.5 IssuingDistributionPoint certificate-type flags.
        if let Some(idp) = parsed_idp {
            // onlyContainsAttributeCerts: attribute cert validation is out of scope
            // for pkix-revocation (RFC 5755 is handled by pkix-ac).
            if idp.only_contains_attribute_certs {
                return Err(Error::OutOfScope(
                    crate::OutOfScopeReason::CrlOnlyAttributeCerts,
                ));
            }
            let cert_is_ca = cert_is_ca_cert(cert)?;
            // onlyContainsUserCerts: CRL only covers end-entity (non-CA) certs.
            if idp.only_contains_user_certs && cert_is_ca {
                return Err(Error::OutOfScope(crate::OutOfScopeReason::CrlOnlyUserCerts));
            }
            // onlyContainsCACerts: CRL only covers CA certs.
            if idp.only_contains_ca_certs && !cert_is_ca {
                return Err(Error::OutOfScope(crate::OutOfScopeReason::CrlOnlyCaCerts));
            }
        }

        // (b) RFC 5280 §6.3.3(b)(1)/(b)(2)(i): some entry of the cert's
        //     cRLDistributionPoints must point at this CRL — by CRL issuer
        //     (the DP's cRLIssuer, or the cert issuer when absent) and, when
        //     the IDP names a distribution point, by name.
        check_dp_scope(cert, parsed_idp, &crl.tbs_cert_list.issuer)?;

        // (c) §5.2.4 delta CRL merge: if a delta CRL is present, verify and
        //     collect its revoked entries. verify_delta_crl_and_collect
        //     handles the delta's critical extensions, scope (IDP) equality
        //     with the base, expiry, signature and issuer name.
        let delta_entries: &[RevokedCert] = if let Some(delta_crl) = &self.delta_crl {
            // Delta CRL issuer must also match the base CRL issuer
            // (construction-time invariant, re-checked here for defense-in-depth).
            if !names_match(&delta_crl.tbs_cert_list.issuer, &crl.tbs_cert_list.issuer) {
                return Err(Error::CrlIssuerMismatch);
            }
            verify_delta_crl_and_collect(
                delta_crl,
                crl,
                &self.verifier,
                signer_spki,
                signer_subject,
                self.now_unix,
            )?
        } else {
            &[]
        };

        // (d) Search for the certificate's (issuer, serial) in the delta and base
        //     CRL entries. Delta CRL entries take precedence (RFC 5280 §5.2.4);
        //     a removeFromCRL reason in the delta un-revokes a cert.
        //
        //     For indirect CRLs the per-entry `certificateIssuer` extension may
        //     change the effective issuer of subsequent entries (RFC 5280 §5.3.3);
        //     entries inherit the previous extension's value, defaulting to the
        //     CRL's own issuer for the first entry.
        let cert_issuer = cert.tbs_certificate().issuer();
        let cert_serial = cert.tbs_certificate().serial_number();
        let crl_default_issuer = &crl.tbs_cert_list.issuer;
        let is_indirect = self.crl_issuer_cert.is_some();
        let status = check_revocation_status_indirect(
            cert_issuer,
            cert_serial,
            delta_entries,
            crl,
            crl_default_issuer,
            is_indirect,
        );

        // (e) RFC 5280 §6.3.3(d)/(k): a CRL whose IDP `onlySomeReasons` does
        //     not cover every reason can prove "revoked" but not "not
        //     revoked". Combining several partitioned CRLs into a full
        //     reasons mask is not implemented, so fail safe.
        if status.is_ok() {
            if let Some(reasons) = parsed_idp.and_then(|idp| idp.only_some_reasons) {
                if !covers_all_reasons(reasons) {
                    return Err(Error::OutOfScope(
                        crate::OutOfScopeReason::CrlOnlySomeReasons,
                    ));
                }
            }
        }
        status
    }
}

// ---------------------------------------------------------------------------
// Revocation status helper (with indirect-CRL per-entry issuer tracking)
// ---------------------------------------------------------------------------

/// Search for the cert's `(issuer, serial)` in the delta entries (higher
/// priority) and then in the base `crl`, returning the appropriate
/// revocation result.
///
/// RFC 5280 §5.2.4: delta CRL entries take precedence over base entries.
/// RFC 5280 §5.3.3: in indirect CRLs, the per-entry `certificateIssuer`
/// extension identifies the actual issuer of each entry. Entries inherit
/// the previous entry's effective issuer; the first entry defaults to the
/// CRL's own issuer.
///
/// - If found in `delta_entries` with reason `RemoveFromCRL` → `Ok(())`.
/// - If found in `delta_entries` for any other reason → `Err(Revoked)`.
/// - If found in the base CRL → `Err(Revoked)`.
/// - If not found in either → `Ok(())` (not revoked according to this CRL).
///
/// When `is_indirect = false` the per-entry `certificateIssuer` extension
/// is ignored and lookup degenerates to serial-only matching against
/// `crl_default_issuer` (the CRL's own issuer). This preserves the legacy
/// direct-CRL behaviour bit-for-bit.
fn check_revocation_status_indirect(
    cert_issuer: &x509_cert::name::Name,
    cert_serial: &x509_cert::serial_number::SerialNumber,
    delta_entries: &[RevokedCert],
    crl: &CertificateList,
    crl_default_issuer: &x509_cert::name::Name,
    is_indirect: bool,
) -> crate::Result<()> {
    // Delta entries take precedence (RFC 5280 §5.2.4).
    if let Some(entry) = find_matching_entry(
        cert_issuer,
        cert_serial,
        delta_entries,
        crl_default_issuer,
        is_indirect,
    )? {
        let reason = extract_reason_code(entry);
        if reason == Some(CrlReason::RemoveFromCRL) {
            // certificateHold was lifted; cert is not revoked.
            return Ok(());
        }
        return Err(Error::Revoked {
            serial: cert_serial.clone(),
            reason_code: reason,
        });
    }

    // Fall through to base entries.
    let base_entries: &[RevokedCert] = crl
        .tbs_cert_list
        .revoked_certificates
        .as_deref()
        .unwrap_or(&[]);
    if let Some(entry) = find_matching_entry(
        cert_issuer,
        cert_serial,
        base_entries,
        crl_default_issuer,
        is_indirect,
    )? {
        return Err(Error::Revoked {
            serial: cert_serial.clone(),
            reason_code: extract_reason_code(entry),
        });
    }

    Ok(())
}

/// Walk `entries` in DER order, tracking the effective issuer per RFC 5280
/// §5.3.3, and return the first entry whose `(effective_issuer, serial)`
/// matches `(cert_issuer, cert_serial)`. The `is_indirect` flag gates
/// whether `certificateIssuer` extensions are honored — for direct CRLs
/// the effective issuer is always `crl_default_issuer`.
///
/// Errors out (`CrlParseError`) if a `certificateIssuer` extension is
/// present but cannot be parsed; this is the fail-closed treatment for a
/// critical entry extension we recognize.
fn find_matching_entry<'a>(
    cert_issuer: &x509_cert::name::Name,
    cert_serial: &x509_cert::serial_number::SerialNumber,
    entries: &'a [RevokedCert],
    crl_default_issuer: &x509_cert::name::Name,
    is_indirect: bool,
) -> crate::Result<Option<&'a RevokedCert>> {
    let mut effective: Cow<'_, x509_cert::name::Name> = Cow::Borrowed(crl_default_issuer);
    for entry in entries {
        // Only honor certificateIssuer in indirect CRLs (where it has
        // defined semantics per RFC 5280 §5.2.5/§5.3.3). Direct CRLs
        // should not contain this extension; if one does, ignoring it
        // here matches the conservative interpretation used by major
        // verifiers.
        if is_indirect {
            if let Some(exts) = entry.crl_entry_extensions.as_deref() {
                if let Some(ce_ext) = exts.iter().find(|e| e.extn_id == OID_CERTIFICATE_ISSUER) {
                    effective =
                        Cow::Owned(parse_certificate_issuer_dn(ce_ext.extn_value.as_bytes())?);
                }
            }
        }
        if &entry.serial_number == cert_serial && names_match(&effective, cert_issuer) {
            return Ok(Some(entry));
        }
    }
    Ok(None)
}

/// Parse the `certificateIssuer` CRL entry extension (RFC 5280 §5.3.3),
/// extracting the first `directoryName` GeneralName. Returns
/// `Err(CrlParseError)` if the extension cannot be DER-decoded or if no
/// `directoryName` is present (the only GeneralName form supported here).
fn parse_certificate_issuer_dn(ext_value_der: &[u8]) -> crate::Result<x509_cert::name::Name> {
    use x509_cert::ext::pkix::name::{GeneralName, GeneralNames};

    let general_names = GeneralNames::from_der(ext_value_der)
        .map_err(|e| Error::CrlParseError(crate::DerError::new(e)))?;
    for gn in general_names {
        if let GeneralName::DirectoryName(name) = gn {
            return Ok(name);
        }
    }
    // RFC 5280 §5.3.3 allows multiple GeneralName forms (including
    // issuerAltName entries); for chain-validation-style lookup we only
    // use the directoryName because that is what the cert's `issuer`
    // field carries. A cert-issuer-extension carrying only non-DN
    // GeneralNames is unusable for our (issuer, serial) match.
    //
    // The error uses `ErrorKind::Value` + `Tag::Sequence` to signal
    // "structurally valid extension but no directoryName GeneralName
    // found", distinguishing it from a DER parse failure.
    Err(Error::CrlParseError(crate::DerError::new(der::Error::new(
        der::ErrorKind::Value {
            tag: der::Tag::Sequence,
        },
        der::Length::ZERO,
    ))))
}

// ---------------------------------------------------------------------------
// Delta-CRL helper
// ---------------------------------------------------------------------------

/// Verify a delta CRL and return its revoked-certificate entries.
///
/// Performs (in order):
/// 1. Check that the delta CRL issuer matches `expected_issuer_name`.
/// 2. Reject the delta if it carries a critical CRL or CRL-entry extension
///    this crate does not process (RFC 5280 §5.2 / §5.3) —
///    [`Error::CrlUnsupportedCriticalExtension`].
/// 3. Require the delta's `IssuingDistributionPoint` to be identical to the
///    base CRL's, or both to be absent (RFC 5280 §6.3.3(c)(2)/(3)) —
///    [`Error::DeltaCrlBaseMismatch`]. Byte equality of the IDP also carries
///    the base's `indirectCRL` flag over to the delta.
/// 4. Check the delta validity window against `now_unix`.
/// 5. Verify the delta signature using `issuer_spki`.
/// 6. Return the delta's revoked-certificates list (empty if absent).
///
/// The caller is responsible for parsing the `CertificateList` and for any
/// additional issuer-name cross-checks needed by the calling context (e.g.,
/// checking the delta issuer against the base CRL issuer or the subject
/// certificate's issuer).
fn verify_delta_crl_and_collect<'a, V: SignatureVerifier>(
    delta_crl: &'a CertificateList,
    base_crl: &CertificateList,
    verifier: &V,
    issuer_spki: spki::SubjectPublicKeyInfoRef<'_>,
    expected_issuer_name: &x509_cert::name::Name,
    now_unix: u64,
) -> crate::Result<&'a [RevokedCert]> {
    if !names_match(&delta_crl.tbs_cert_list.issuer, expected_issuer_name) {
        return Err(Error::CrlIssuerMismatch);
    }

    check_crl_critical_extensions(delta_crl)?;

    // Compare the DER of the IDP extension values: RFC 5280 requires the
    // delta's scope to be *identical* to the complete CRL's, so no semantic
    // comparison is needed.
    if crl_extension_value(delta_crl, &OID_ISSUING_DISTRIBUTION_POINT)
        != crl_extension_value(base_crl, &OID_ISSUING_DISTRIBUTION_POINT)
    {
        return Err(Error::DeltaCrlBaseMismatch);
    }

    // Check validity window before signature verification (same rationale as
    // the base CRL paths: reject stale deltas early without paying sig-verify cost).
    let delta_this_update = delta_crl
        .tbs_cert_list
        .this_update
        .to_unix_duration()
        .as_secs();
    if now_unix < delta_this_update {
        return Err(Error::CrlExpired);
    }
    let delta_next_update = delta_crl
        .tbs_cert_list
        .next_update
        .as_ref()
        .ok_or(Error::CrlExpired)?;
    if now_unix > delta_next_update.to_unix_duration().as_secs() {
        return Err(Error::CrlExpired);
    }

    let delta_tbs_bytes = delta_crl
        .tbs_cert_list
        .to_der()
        .map_err(|e| Error::CrlParseError(crate::DerError::new(e)))?;
    verifier
        .verify_signature(
            delta_crl.signature_algorithm.owned_to_ref(),
            issuer_spki,
            &delta_tbs_bytes,
            delta_crl.signature.raw_bytes(),
        )
        // Verifier returns an opaque error; no additional context available.
        .map_err(|_| Error::CrlSignatureInvalid)?;

    Ok(delta_crl
        .tbs_cert_list
        .revoked_certificates
        .as_deref()
        .unwrap_or(&[]))
}

// ---------------------------------------------------------------------------
// Extension helpers
// ---------------------------------------------------------------------------

/// CRL extensions (RFC 5280 §5.2) this crate recognizes. A *critical* CRL
/// extension outside this list makes the CRL unusable (§5.2: "If a CRL
/// contains a critical extension that the application cannot process, then
/// the application MUST NOT use that CRL to determine the status of
/// certificates"). AKI, issuerAltName, freshestCRL and authorityInfoAccess
/// are informational for this checker (the signer is fixed by the caller)
/// and are listed so that a CA marking them critical is not refused.
const KNOWN_CRL_EXTENSIONS: &[der::asn1::ObjectIdentifier] = &[
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.35"), // authorityKeyIdentifier
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.18"), // issuerAltName
    OID_CRL_NUMBER,
    OID_DELTA_CRL_INDICATOR,
    OID_ISSUING_DISTRIBUTION_POINT,
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.46"), // freshestCRL
    der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1"), // authorityInfoAccess
];

/// CRL entry extensions (RFC 5280 §5.3) this crate recognizes; same
/// critical-extension rule as [`KNOWN_CRL_EXTENSIONS`] (§5.3: an
/// unprocessable critical entry extension forbids using the whole CRL).
const KNOWN_CRL_ENTRY_EXTENSIONS: &[der::asn1::ObjectIdentifier] = &[
    OID_CRL_REASONS,
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.23"), // holdInstructionCode
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.24"), // invalidityDate
    OID_CERTIFICATE_ISSUER,
];

/// Returns [`Error::CrlUnsupportedCriticalExtension`] if `crl` or any of its
/// entries carries a critical extension outside the recognized lists.
fn check_crl_critical_extensions(crl: &CertificateList) -> crate::Result<()> {
    let tbs = &crl.tbs_cert_list;
    let crl_exts = tbs.crl_extensions.as_deref().unwrap_or(&[]);
    if crl_exts
        .iter()
        .any(|e| e.critical && !KNOWN_CRL_EXTENSIONS.contains(&e.extn_id))
    {
        return Err(Error::CrlUnsupportedCriticalExtension);
    }
    let entries = tbs.revoked_certificates.as_deref().unwrap_or(&[]);
    for entry in entries {
        let exts = entry.crl_entry_extensions.as_deref().unwrap_or(&[]);
        if exts
            .iter()
            .any(|e| e.critical && !KNOWN_CRL_ENTRY_EXTENSIONS.contains(&e.extn_id))
        {
            return Err(Error::CrlUnsupportedCriticalExtension);
        }
    }
    Ok(())
}

/// Gate for the CRL supplied as the *complete* CRL (every constructor's
/// `crl_der` / `base_der`), applied at `check_*` time:
///
/// - A delta CRL (`deltaCRLIndicator` present) lists only changes since its
///   base, so on its own it can never establish "not revoked" (RFC 5280
///   §5.2.4) → [`Error::DeltaCrlAsComplete`].
/// - Unrecognized critical CRL / entry extensions →
///   [`Error::CrlUnsupportedCriticalExtension`].
fn check_crl_usable_as_complete(crl: &CertificateList) -> crate::Result<()> {
    if has_delta_crl_indicator(crl) {
        return Err(Error::DeltaCrlAsComplete);
    }
    check_crl_critical_extensions(crl)
}

/// Raw DER of the value of the CRL extension `oid`, if present.
fn crl_extension_value<'a>(
    crl: &'a CertificateList,
    oid: &der::asn1::ObjectIdentifier,
) -> Option<&'a [u8]> {
    crl.tbs_cert_list
        .crl_extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find(|e| &e.extn_id == oid)
        .map(|e| e.extn_value.as_bytes())
}

/// Returns `true` if `reasons` (an IDP `onlySomeReasons` value) includes
/// every RFC 5280 §5.2.5 reason flag, i.e. the CRL is not actually
/// reason-partitioned. The `unused` bit (0) is ignored.
fn covers_all_reasons(reasons: x509_cert::ext::pkix::crl::dp::ReasonFlags) -> bool {
    use x509_cert::ext::pkix::crl::dp::Reasons;
    reasons.contains(
        Reasons::KeyCompromise
            | Reasons::CaCompromise
            | Reasons::AffiliationChanged
            | Reasons::Superseded
            | Reasons::CessationOfOperation
            | Reasons::CertificateHold
            | Reasons::PrivilegeWithdrawn
            | Reasons::AaCompromise,
    )
}

/// Convert a DER [`Uint`][der::asn1::Uint] to a `u64`, padding from the left.
///
/// Returns `None` if the integer is larger than 8 bytes (would overflow `u64`).
/// CRL numbers in PKITS are small (1–5), so this is not a practical limit.
fn uint_to_u64(n: &der::asn1::Uint) -> Option<u64> {
    let b = n.as_bytes();
    if b.len() > 8 {
        return None; // too large for u64
    }
    let mut arr = [0u8; 8];
    arr[8 - b.len()..].copy_from_slice(b);
    Some(u64::from_be_bytes(arr))
}

/// Extract the CRL number from a `CertificateList`'s extensions.
///
/// Returns:
/// - `None` — `CRLNumber` extension absent (field is optional per RFC 5280 §5.2.3)
/// - `Some(Ok(n))` — extension present and successfully decoded
/// - `Some(Err(e))` — extension present but the INTEGER value is malformed or
///   too large to fit in a `u64` (a `CRLNumber` > 2^64 is implausible in any
///   deployed PKI but must not silently disable the staleness check)
fn crl_number(crl: &CertificateList) -> Option<Result<u64, der::Error>> {
    let ext = crl
        .tbs_cert_list
        .crl_extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find(|e| e.extn_id == OID_CRL_NUMBER)?;
    let result = der::asn1::Uint::from_der(ext.extn_value.as_bytes())
        .and_then(|n| uint_to_u64(&n).ok_or_else(|| der::Error::from(der::ErrorKind::Overflow)));
    Some(result)
}

/// Returns `true` if `crl` contains a `deltaCRLIndicator` extension (OID 2.5.29.27),
/// regardless of whether the extension value can be decoded.
///
/// Presence of this OID (which MUST be critical) is the canonical marker that a
/// CRL is a delta CRL per RFC 5280 §5.2.4.  Checking presence — not decode success —
/// is important: a malformed value still makes the CRL a delta CRL and must prevent
/// it from being used as a base.
fn has_delta_crl_indicator(crl: &CertificateList) -> bool {
    crl.tbs_cert_list
        .crl_extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .any(|e| e.extn_id == OID_DELTA_CRL_INDICATOR)
}

/// Extract the `BaseCRLNumber` from a delta CRL's extensions.
///
/// The `deltaCRLIndicator` extension value IS the `BaseCRLNumber` — it is an
/// INTEGER encoding the CRL number of the base CRL this delta updates.
/// This extension MUST be critical (RFC 5280 §5.2.4).
///
/// Returns:
/// - `None` — extension absent (CRL is not a delta CRL)
/// - `Some(Ok(n))` — extension present and successfully decoded
/// - `Some(Err(e))` — extension present but the INTEGER value is malformed
fn base_crl_number(crl: &CertificateList) -> Option<Result<u64, der::Error>> {
    let ext = crl
        .tbs_cert_list
        .crl_extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find(|e| e.extn_id == OID_DELTA_CRL_INDICATOR)?;
    let result = der::asn1::Uint::from_der(ext.extn_value.as_bytes())
        .and_then(|n| uint_to_u64(&n).ok_or_else(|| der::Error::from(der::ErrorKind::Overflow)));
    Some(result)
}

/// Checks that the CRL issuer certificate has `cRLSign` set in its `KeyUsage`
/// extension, or that `KeyUsage` is absent entirely (no constraint).
///
/// RFC 5280 §6.3.3(f): a CRL issuer that has a `KeyUsage` extension MUST assert
/// the `cRLSign` bit. If `KeyUsage` is absent, there is no constraint.
///
/// # Errors
///
/// - `Err(CrlParseError)` — the `KeyUsage` extension value is structurally malformed.
/// - `Err(CrlSignMissing)` — the extension is present but `cRLSign` bit is not set.
fn check_crl_sign(cert: &Certificate) -> crate::Result<()> {
    use x509_cert::ext::pkix::KeyUsage;

    let Some(ku_ext) = cert
        .tbs_certificate()
        .extensions()
        .map_or(&[][..], |v| v.as_slice())
        .iter()
        .find(|e| e.extn_id == OID_KEY_USAGE_CRL)
    else {
        return Ok(()); // KeyUsage absent (or no extensions) → no constraint
    };
    let ku = KeyUsage::from_der(ku_ext.extn_value.as_bytes())
        .map_err(|e| Error::CrlParseError(crate::DerError::new(e)))?;
    if ku.crl_sign() {
        Ok(())
    } else {
        Err(Error::CrlSignMissing)
    }
}

/// Extract the `CRLReason` code from a revoked cert entry's extensions, if present.
///
/// Returns the `CrlReason` (RFC 5280 §5.3.1), or `None` if the extension is absent.
fn extract_reason_code(entry: &RevokedCert) -> Option<CrlReason> {
    let exts = entry.crl_entry_extensions.as_ref()?;
    exts.iter()
        .find(|ext| ext.extn_id == OID_CRL_REASONS)
        .and_then(|ext| CrlReason::from_der(ext.extn_value.as_bytes()).ok())
}

/// Extract the `IssuingDistributionPoint` from a CRL, if present.
///
/// Uses raw OID lookup because x509-cert 0.2.5 has a wrong `AssociatedOid` for
/// this type (it maps to `SubjectInfoAccess` instead of 2.5.29.28).
fn parse_issuing_dp(
    crl: &CertificateList,
) -> crate::Result<Option<x509_cert::ext::pkix::crl::IssuingDistributionPoint>> {
    use x509_cert::ext::pkix::crl::IssuingDistributionPoint;

    crl.tbs_cert_list
        .crl_extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find(|e| e.extn_id == OID_ISSUING_DISTRIBUTION_POINT)
        .map(|e| {
            IssuingDistributionPoint::from_der(e.extn_value.as_bytes())
                .map_err(|err| Error::CrlParseError(crate::DerError::new(err)))
        })
        .transpose()
}

/// Extract the `cRLDistributionPoints` extension from `cert`, if present.
///
/// Returns `Ok(None)` if the extension is absent — that means the cert
/// does not constrain which CRL(s) determine its revocation status.
/// Returns `Err(CrlParseError)` if the extension is present but cannot
/// be DER-decoded (fail-closed: a malformed CDP is a structural defect
/// in the cert, not a "no constraint" condition).
fn cert_crl_distribution_points(
    cert: &Certificate,
) -> crate::Result<Option<x509_cert::ext::pkix::CrlDistributionPoints>> {
    use x509_cert::ext::pkix::CrlDistributionPoints;

    cert.tbs_certificate()
        .extensions()
        .map_or(&[][..], |v| v.as_slice())
        .iter()
        .find(|e| e.extn_id == OID_CRL_DISTRIBUTION_POINTS)
        .map(|e| {
            CrlDistributionPoints::from_der(e.extn_value.as_bytes())
                .map_err(|err| Error::CrlParseError(crate::DerError::new(err)))
        })
        .transpose()
}

/// Resolve a `DistributionPointName` to its canonical list of
/// `GeneralName`s.
///
/// `FullName(names)` is returned as-is (borrowed). `NameRelativeToCRLIssuer(rdn)`
/// is materialized: the relative RDN is appended to `base_dn` to produce a
/// full DN, and the result is wrapped in a one-element `GeneralNames` list
/// containing a single `DirectoryName`. RFC 5280 §4.2.1.13: "the relative
/// distinguished name … is the relative distinguished name of the CRL
/// distribution point with respect to the issuer of the CRL".
///
/// `base_dn` is the certificate issuer's DN when resolving a
/// `cRLDistributionPoints` entry, and the CRL signer's subject DN when
/// resolving an `IssuingDistributionPoint`. Per the RFC, in the common case
/// where the certificate issuer also signs the CRL these two base DNs are
/// equal, and a cert that uses `NameRelativeToCRLIssuer` for its CDP can
/// match a CRL that uses `FullName` for its IDP (or vice versa).
///
/// This function lives in the `crl` feature path which requires `std`; it
/// therefore uses `std`-prelude `Vec` and `vec!` macros directly rather
/// than going through `alloc::*` (the latter would require an
/// `extern crate alloc;` declaration that the crate currently does not
/// have, since all heap-using paths are gated behind `std`).
fn dpn_to_general_names<'a>(
    dpn: &'a x509_cert::ext::pkix::name::DistributionPointName,
    base_dn: &x509_cert::name::Name,
) -> crate::Result<Cow<'a, [x509_cert::ext::pkix::name::GeneralName]>> {
    use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};

    match dpn {
        DistributionPointName::FullName(names) => Ok(Cow::Borrowed(names.as_slice())),
        DistributionPointName::NameRelativeToCRLIssuer(rdn) => {
            // Append the RDN onto the base DN. x509-cert 0.3 has no public
            // `Name` constructor from an `RdnSequence`, so the extended
            // sequence round-trips through its DER encoding (a `Name` is
            // exactly an `RDNSequence` on the wire). DNs are typically <10
            // RDNs each, so this is cheap.
            use der::{Decode as _, Encode as _};
            let mut seq: x509_cert::name::RdnSequence = base_dn.clone().into();
            seq.push(rdn.clone());
            let full_name = seq
                .to_der()
                .and_then(|der| x509_cert::name::Name::from_der(&der))
                .map_err(|e| crate::Error::CrlParseError(crate::DerError::new(e)))?;
            Ok(Cow::Owned(vec![GeneralName::DirectoryName(full_name)]))
        }
    }
}

/// Compare two `GeneralName`s for equivalence.
///
/// `DirectoryName` uses [`pkix_path::names_match`] (RFC 4518-style DN
/// equivalence). Other variants use the upstream-derived `PartialEq`
/// implementation on `GeneralName`, which compares the inner values
/// directly (e.g., `Ia5String` for URI/dNSName/rfc822Name, `OctetString`
/// for iPAddress, `ObjectIdentifier` for registeredID). This avoids
/// heap-allocating DER bytes for a comparison that the type system
/// already supports natively.
///
/// `EdiPartyName` and `OtherName` also use the derived `PartialEq`;
/// they have no canonicalization specified for IDP/CDP matching purposes
/// and are extremely rare in modern PKI.
///
/// Mismatched variants always return `false` (no cross-variant matching;
/// the derived `PartialEq` handles this correctly).
fn general_name_matches(
    a: &x509_cert::ext::pkix::name::GeneralName,
    b: &x509_cert::ext::pkix::name::GeneralName,
) -> bool {
    use x509_cert::ext::pkix::name::GeneralName as GN;

    match (a, b) {
        (GN::DirectoryName(a_dn), GN::DirectoryName(b_dn)) => names_match(a_dn, b_dn),
        // Non-DN variants: use the upstream-derived PartialEq, which
        // compares inner fields directly without DER re-encoding.
        // Mismatched variants return false via the derived impl.
        _ => a == b,
    }
}

/// Returns `true` if the two `GeneralNames` lists share at least one
/// equivalent name (RFC 5280 §6.3.3(b)(1) "matches").
fn general_names_intersect(
    a: &[x509_cert::ext::pkix::name::GeneralName],
    b: &[x509_cert::ext::pkix::name::GeneralName],
) -> bool {
    a.iter()
        .any(|ga| b.iter().any(|gb| general_name_matches(ga, gb)))
}

/// Check that some entry of the certificate's `cRLDistributionPoints`
/// points at this CRL, per RFC 5280 §6.3.3(b)(1) and (b)(2)(i).
///
/// A distribution point `dp` matches when both hold:
///
/// 1. **Issuer.** If `dp.cRLIssuer` is present, one of its `directoryName`s
///    equals the CRL issuer *and* the CRL is indirect (IDP `indirectCRL`);
///    otherwise the CRL issuer equals the certificate issuer.
/// 2. **Name** (only when the IDP names a distribution point). The DP's
///    `distributionPoint` names — or, when that field is absent, its
///    `cRLIssuer` names — intersect the IDP's. `nameRelativeToCRLIssuer`
///    is resolved against the CRL issuer on both sides: for the DP this is
///    `dp.cRLIssuer` when present (RFC 5280 §4.2.1.13) and otherwise the
///    certificate issuer, which (1) has just shown to equal the CRL issuer.
///
/// | cert CDP | Outcome |
/// |---|---|
/// | absent  | match unless the IDP names a distribution point |
/// | present | at least one DP must satisfy (1) and (2) |
///
/// Errors: [`Error::OutOfScope`] with
/// [`CrlDistributionPointIssuerMismatch`](crate::OutOfScopeReason::CrlDistributionPointIssuerMismatch)
/// if no DP passes (1), or
/// [`CrlIdpDistributionPointMismatch`](crate::OutOfScopeReason::CrlIdpDistributionPointMismatch)
/// if some DP passes (1) but none passes (2).
/// Determine revocation status across several CRLs, combining
/// reason-partitioned ones.
///
/// A CRL whose `IssuingDistributionPoint` carries `onlySomeReasons` covers
/// only those revocation reasons. It can prove a certificate **is** revoked,
/// but on its own it cannot prove the certificate is **not** revoked — some
/// other reason may be listed on a CRL covering the remaining reasons. A
/// single [`CrlChecker`] therefore returns
/// [`CrlOnlySomeReasons`](crate::OutOfScopeReason::CrlOnlySomeReasons) rather
/// than a clean bill of health, which is correct and incomplete.
///
/// This function implements RFC 5280 §6.3.3's `reasons_mask` accumulation: it
/// walks the supplied CRLs, unions the reasons each one covers, and reports
/// "not revoked" only once every reason is covered.
///
/// # Algorithm
///
/// 1. Skip any CRL the certificate's distribution points do not name
///    ([`crl_applies_to`]).
/// 2. Skip a CRL that adds no reason the mask lacks — processing it could
///    change nothing.
/// 3. Check the certificate against it. **Revoked wins immediately**: a
///    partitioned CRL is authoritative for the reasons it covers.
/// 4. Otherwise add its reasons to the mask and continue.
/// 5. Report `Ok(())` when the mask covers every RFC 5280 §5.2.5 reason, and
///    `CrlOnlySomeReasons` when it does not.
///
/// Order-independent by construction: the mask is a union and `Revoked`
/// short-circuits, so the verdict does not depend on which CRL is seen first.
///
/// # Why a free function and not a `CrlChecker` method
///
/// [`CrlChecker`] holds one base CRL and an optional delta, which is the right
/// shape for the single-CRL case and the wrong one here — reason partitioning
/// is a property of a *set*. Rather than widen that type, this composes it:
/// one checker per CRL, with the mask kept here.
///
/// # Errors
///
/// - [`Error::Revoked`] if any applicable CRL lists the certificate.
/// - [`Error::OutOfScope`] with
///   [`CrlOnlySomeReasons`](crate::OutOfScopeReason::CrlOnlySomeReasons) when
///   the applicable CRLs leave some reason uncovered. Status is undetermined;
///   a hard-fail caller must reject.
/// - When no CRL applied at all, the first error a candidate produced, so the
///   caller sees why rather than a misleading "partitioned" verdict.
pub fn check_revocation_with_crls<V>(
    cert: &Certificate,
    issuer: &Certificate,
    crls: &[&[u8]],
    now_unix: u64,
    verifier: &V,
) -> crate::Result<()>
where
    V: SignatureVerifier + Clone,
{
    use x509_cert::ext::pkix::crl::dp::ReasonFlags;

    let mut mask = ReasonFlags::default();
    let mut processed_any = false;
    let mut first_error: Option<Error> = None;

    for crl_der in crls {
        // (1) Only CRLs this certificate points at.
        if let Err(e) = crl_applies_to(cert, crl_der) {
            first_error.get_or_insert(e);
            continue;
        }
        let Ok(parsed) = CertificateList::from_der(crl_der) else {
            continue;
        };
        let reasons = match parse_issuing_dp(&parsed) {
            Ok(idp) => idp
                .and_then(|i| i.only_some_reasons)
                .unwrap_or_else(all_reasons),
            Err(e) => {
                first_error.get_or_insert(e);
                continue;
            }
        };

        // (2) Nothing new to learn from this one: every reason it covers is
        //     already in the mask, so processing it cannot change the verdict.
        if (reasons - mask).is_empty() {
            continue;
        }

        let Ok(checker) = CrlChecker::new(crl_der, now_unix, verifier.clone()) else {
            continue;
        };
        match checker.check_revocation(cert, issuer) {
            // (3) Authoritative for the reasons it covers.
            Err(e @ Error::Revoked { .. }) => return Err(e),

            // (4) Not listed. An unpartitioned CRL yields Ok; a partitioned
            //     one yields CrlOnlySomeReasons, which is the single-CRL
            //     fail-safe and exactly the case this function exists to
            //     combine. Both mean "not listed for the reasons I cover".
            Ok(()) | Err(Error::OutOfScope(crate::OutOfScopeReason::CrlOnlySomeReasons)) => {
                mask |= reasons;
                processed_any = true;
            }

            // This CRL could not be used at all.
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }

    if !processed_any {
        return Err(first_error.unwrap_or(Error::CrlIssuerMismatch));
    }
    if covers_all_reasons(mask) {
        Ok(())
    } else {
        Err(Error::OutOfScope(
            crate::OutOfScopeReason::CrlOnlySomeReasons,
        ))
    }
}

/// Every RFC 5280 §5.2.5 reason flag, for a CRL with no `onlySomeReasons`.
fn all_reasons() -> x509_cert::ext::pkix::crl::dp::ReasonFlags {
    use x509_cert::ext::pkix::crl::dp::Reasons;
    Reasons::KeyCompromise
        | Reasons::CaCompromise
        | Reasons::AffiliationChanged
        | Reasons::Superseded
        | Reasons::CessationOfOperation
        | Reasons::CertificateHold
        | Reasons::PrivilegeWithdrawn
        | Reasons::AaCompromise
}

/// Whether `crl_der` is a CRL that `cert`'s distribution points name.
///
/// This is RFC 5280 §6.3.3(b) **selection**: given a certificate and a
/// candidate CRL, does the certificate's `cRLDistributionPoints` extension
/// point at this CRL? It is the question a caller must answer before checking
/// revocation status, and the question that distinguishes "the right CRL said
/// nothing about this certificate" from "some CRL said nothing".
///
/// # The rules
///
/// A CRL applies when both hold:
///
/// 1. **Issuer.** For a direct CRL, the certificate's issuer is the CRL's
///    issuer (RFC 5280 §6.3.3(b)(1)). For an indirect CRL — one whose
///    `IssuingDistributionPoint` sets `indirectCRL` — the issuer may differ,
///    and instead one of a distribution point's `cRLIssuer` `directoryName`s
///    must equal the CRL issuer.
/// 2. **Name**, only when the CRL's IDP names a distribution point. The
///    certificate's `distributionPoint` names — or, where that field is
///    absent, its `cRLIssuer` names — must intersect the IDP's.
///    `nameRelativeToCRLIssuer` is resolved against the CRL issuer on both
///    sides.
///
/// | cert `cRLDistributionPoints` | outcome |
/// |---|---|
/// | absent  | rule 1 only; rule 2 cannot be satisfied, so an IDP that names a distribution point excludes the CRL |
/// | present | at least one distribution point must satisfy both rules |
///
/// Certificates without the extension are not an edge case — the whole NIST
/// PKITS corpus is built that way, supplying CRLs out of band — so rule 1
/// carries the weight there.
///
/// This shares its implementation with `check_revocation`: both are entry
/// points onto one predicate, not two copies of it.
///
/// # Why this is public
///
/// Anything choosing *which* CRL to fetch, cache or apply needs it, and a
/// second implementation would be a divergence hazard on security-relevant
/// matching — the DP rules cover indirect CRLs and `nameRelativeToCRLIssuer`
/// resolution, which are not obvious to restate correctly.
///
/// A differential test harness is the motivating caller: feeding every CRL to
/// every certificate and accepting whichever combination validates is not
/// RFC 5280's procedure, and it cannot distinguish a chain with no applicable
/// CRL from one whose CRL happens to be signed by somebody in the bundle.
///
/// # What this does NOT do
///
/// Selection only. It does not verify the CRL's signature, check its
/// validity window, apply `onlyContainsUserCerts` / `onlyContainsCACerts` /
/// `onlySomeReasons` scope flags, or look the certificate up in the revoked
/// list. `Ok(())` means "this CRL is addressed to this certificate", nothing
/// more; use [`CrlChecker`] for the rest.
///
/// # Errors
///
/// - [`Error::CrlParseError`] if `crl_der` is not a decodable
///   `CertificateList`, or the certificate's `cRLDistributionPoints` is
///   present but malformed.
/// - [`Error::OutOfScope`] with
///   [`CrlDistributionPointIssuerMismatch`](crate::OutOfScopeReason::CrlDistributionPointIssuerMismatch)
///   when no distribution point names this CRL's issuer, or
///   [`CrlIdpDistributionPointMismatch`](crate::OutOfScopeReason::CrlIdpDistributionPointMismatch)
///   when one does but the names do not intersect the CRL's
///   `IssuingDistributionPoint`.
///
/// - [`Error::CrlIssuerMismatch`] when a direct CRL's issuer is not the
///   certificate's issuer.
pub fn crl_applies_to(cert: &Certificate, crl_der: &[u8]) -> crate::Result<()> {
    let crl = CertificateList::from_der(crl_der)
        .map_err(|e| Error::CrlParseError(crate::DerError::new(e)))?;
    let idp = parse_issuing_dp(&crl)?;
    let crl_issuer = &crl.tbs_cert_list.issuer;

    // RFC 5280 §6.3.3(b)(1): for a DIRECT CRL the certificate's issuer must be
    // the CRL's issuer. Only an indirect CRL may come from elsewhere, and only
    // then because a distribution point named it — which check_dp_scope
    // verifies below.
    //
    // This check is here rather than left to check_dp_scope because that
    // function covers the distribution-point half of §6.3.3(b) alone, and a
    // certificate with no cRLDistributionPoints extension passes it almost
    // unconditionally. Certificates without that extension are not an edge
    // case: the whole NIST PKITS corpus is built that way, supplying CRLs out
    // of band. Without the issuer constraint this predicate would accept any
    // validly-formed CRL for such a certificate, which is the opposite of
    // what a caller asking "does this CRL apply" needs.
    let indirect = idp.as_ref().is_some_and(|i| i.indirect_crl);
    if !indirect && !names_match(crl_issuer, cert.tbs_certificate().issuer()) {
        return Err(Error::CrlIssuerMismatch);
    }

    check_dp_scope(cert, idp.as_ref(), crl_issuer)
}

fn check_dp_scope(
    cert: &Certificate,
    idp: Option<&x509_cert::ext::pkix::crl::IssuingDistributionPoint>,
    crl_issuer: &x509_cert::name::Name,
) -> crate::Result<()> {
    use x509_cert::ext::pkix::name::GeneralName;

    let idp_names = idp
        .and_then(|idp| idp.distribution_point.as_ref())
        .map(|dpn| dpn_to_general_names(dpn, crl_issuer))
        .transpose()?;
    let crl_is_indirect = idp.is_some_and(|idp| idp.indirect_crl);

    let Some(cert_cdps) = cert_crl_distribution_points(cert)? else {
        // No CDP: the cert does not constrain which CRL applies, but a CRL
        // scoped to a named distribution point cannot be shown to cover it.
        return match idp_names {
            Some(_) => Err(Error::OutOfScope(
                crate::OutOfScopeReason::CrlIdpDistributionPointMismatch,
            )),
            None => Ok(()),
        };
    };

    let cert_issuer = cert.tbs_certificate().issuer();
    let mut issuer_matched = false;
    for dp in cert_cdps.0.iter() {
        // (1) Issuer: which DN does this DP say issues its CRLs?
        let base_dn = match &dp.crl_issuer {
            Some(crl_issuer_names) => {
                let named = crl_issuer_names.iter().find_map(|gn| match gn {
                    GeneralName::DirectoryName(dn) if names_match(dn, crl_issuer) => Some(dn),
                    _ => None,
                });
                match named {
                    Some(dn) if crl_is_indirect => dn,
                    _ => continue,
                }
            }
            None if names_match(crl_issuer, cert_issuer) => cert_issuer,
            None => continue,
        };
        issuer_matched = true;

        // (2) Name, when the IDP is scoped to a distribution point.
        let Some(idp_names) = idp_names.as_deref() else {
            return Ok(());
        };
        let dp_names: Cow<'_, [GeneralName]> = match (&dp.distribution_point, &dp.crl_issuer) {
            (Some(dpn), _) => match dpn_to_general_names(dpn, base_dn) {
                Ok(names) => names,
                Err(_) => continue,
            },
            (None, Some(crl_issuer_names)) => Cow::Borrowed(crl_issuer_names.as_slice()),
            (None, None) => continue,
        };
        if general_names_intersect(&dp_names, idp_names) {
            return Ok(());
        }
    }

    Err(Error::OutOfScope(if issuer_matched {
        crate::OutOfScopeReason::CrlIdpDistributionPointMismatch
    } else {
        crate::OutOfScopeReason::CrlDistributionPointIssuerMismatch
    }))
}

/// Returns `Ok(true)` if `cert` is a CA certificate (`BasicConstraints`
/// `cA = TRUE`), `Ok(false)` if the extension is absent or `cA = FALSE`,
/// and [`Error::MalformedCertificate`] if the extension is present but
/// undecodable.
///
/// Fail-closed: a malformed `BasicConstraints` is propagated so the IDP
/// scope check cannot silently skip a CRL that should cover the certificate.
///
/// Thin wrapper over [`pkix_path::cert_is_ca`] that maps the opaque
/// [`pkix_path::DerError`] to this crate's [`Error::MalformedCertificate`].
fn cert_is_ca_cert(cert: &Certificate) -> crate::Result<bool> {
    pkix_path::cert_is_ca(cert).map_err(|_| Error::MalformedCertificate)
}
