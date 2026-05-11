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
/// [`RevocationChecker::check_revocation`] returns `Ok(())` in two distinct cases:
///
/// 1. **Not revoked**: the CRL covers this certificate type and the serial number
///    was not found in the revoked list.
/// 2. **Not covered**: the CRL's `IssuingDistributionPoint` scope flags
///    (`onlyContainsUserCerts`, `onlyContainsCACerts`, `onlyContainsAttributeCerts`)
///    indicate the CRL does not apply to this certificate type.
///
/// These two outcomes are indistinguishable from the caller's perspective.
/// Callers enforcing a **hard-fail** revocation policy must separately verify
/// that at least one CRL or OCSP response actually covers the certificate
/// in question; receiving `Ok(())` alone is not sufficient.
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
///   The per-DP `cRLIssuer` field on a `DistributionPoint` entry is **not**
///   currently honored when resolving the cert's CDP base DN; the
///   certificate's issuer is always used. This is correct for the common
///   case (RFC 5280 §4.2.1.13: "If the certificate issuer is also the CRL
///   issuer, then conforming CAs MUST omit the cRLIssuer field"). Indirect
///   CRLs with a non-issuer cRLIssuer that also use `nameRelativeToCRLIssuer`
///   on the cert's CDP would resolve against the wrong base; that scenario
///   has no PKITS coverage and is deferred.
/// - **Reasons-subset check** (`onlySomeReasons` on the IDP must cover the
///   reasons the cert's CDP asks to be checked, RFC 5280 §6.3.3(b)(1)) is
///   not implemented. PKITS §4.14 fixtures do not exercise this. Tracked
///   as future work; a separate `OutOfScopeReason` variant will be added at
///   that time.
/// - The checker enforces `onlyContainsUserCerts`, `onlyContainsCACerts`,
///   and `onlyContainsAttributeCerts` scope flags directly; see
///   `OutOfScopeReason` for the surfaced variants.
/// - The cRLIssuer's chain is NOT validated by this crate — callers must
///   present an already-validated cRLIssuer cert. Composing this with
///   `pkix-path` to validate the cRLIssuer chain in-process is the umbrella
///   crate's responsibility (`pkix-chain`).
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
    /// Optional cRLIssuer cert when the CRL is indirect (RFC 5280 §5.2.6).
    /// `Some` ⇔ this is an indirect-CRL checker; the cert's SPKI is used
    /// for the CRL signature check, its KeyUsage for the cRLSign bit check,
    /// and its subject DN for the CRL-issuer-identity match. The cert MUST
    /// have been chain-validated by the caller before being passed in.
    /// `None` ⇔ direct CRL: the `issuer` argument's identity is used.
    crl_issuer_cert: Option<Certificate>,
    now_unix: u64,
    verifier: V,
}

impl<V: SignatureVerifier> CrlChecker<V> {
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
    /// # Security
    ///
    /// **Do not pass a delta CRL** (a `CertificateList` containing a
    /// `deltaCRLIndicator` extension) as the sole `crl_der` argument. Delta CRLs
    /// contain only the changes since the last base CRL; using one alone silently
    /// under-covers revocations. Pass it via [`CrlChecker::with_delta`] together
    /// with the matching base CRL to get correct coverage.
    pub fn new(crl_der: impl AsRef<[u8]>, now_unix: u64, verifier: V) -> crate::Result<Self> {
        let crl = CertificateList::from_der(crl_der.as_ref())
            .map_err(|e| Error::CrlParseError(crate::DerError(e)))?;
        Ok(Self {
            crl,
            delta_crl: None,
            crl_issuer_cert: None,
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
        let crl = CertificateList::from_der(crl_der.as_ref())
            .map_err(|e| Error::CrlParseError(crate::DerError(e)))?;
        Ok(Self {
            crl,
            delta_crl: None,
            crl_issuer_cert: Some(crl_issuer_cert),
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
        let base_crl = CertificateList::from_der(base_der.as_ref())
            .map_err(|e| Error::CrlParseError(crate::DerError(e)))?;
        let delta_crl = CertificateList::from_der(delta_der.as_ref())
            .map_err(|e| Error::CrlParseError(crate::DerError(e)))?;

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
            .map_err(|e| Error::CrlParseError(crate::DerError(e)))?;

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
            let base_num = base_num_result.map_err(|e| Error::CrlParseError(crate::DerError(e)))?;
            if delta_base_num > base_num {
                return Err(Error::CrlNumberMismatch);
            }
        }

        Ok(Self {
            crl: base_crl,
            delta_crl: Some(delta_crl),
            crl_issuer_cert: None,
            now_unix,
            verifier,
        })
    }

    /// Same as [`CrlChecker::new_with_crl_issuer`] plus a delta CRL.
    ///
    /// The delta CRL must be signed by the same cRLIssuer cert and be
    /// declared indirect via its own `IssuingDistributionPoint.indirectCRL`
    /// flag (verified at `check_revocation` time).
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
                signer_subject = &crl_issuer.tbs_certificate.subject;
                signer_spki = crl_issuer
                    .tbs_certificate
                    .subject_public_key_info
                    .owned_to_ref();
                signer_for_crlsign_check = Some(crl_issuer);
            }
            (Some(_), false) => {
                // Caller asserted indirect; CRL says direct. Reject.
                return Err(Error::IndirectCrlIssuerUnexpected);
            }
            (None, true) => {
                // CRL says indirect; caller did not supply cRLIssuer cert.
                return Err(Error::IndirectCrlIssuerMissing);
            }
            (None, false) => {
                signer_subject = &issuer.tbs_certificate.subject;
                signer_spki = issuer
                    .tbs_certificate
                    .subject_public_key_info
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
            &issuer.tbs_certificate.subject,
            &cert.tbs_certificate.issuer,
        ) {
            return Err(Error::CrlIssuerMismatch);
        }
        // For direct CRLs only: the cert's issuer must also match the
        // CRL issuer (this is the legacy invariant). For indirect CRLs
        // this check is intentionally skipped — the whole point of
        // §5.2.6 is that they may differ.
        if self.crl_issuer_cert.is_none()
            && !names_match(&cert.tbs_certificate.issuer, &crl.tbs_cert_list.issuer)
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
            .map_err(|e| Error::CrlParseError(crate::DerError(e)))?;
        self.verifier
            .verify_signature(
                crl.signature_algorithm.owned_to_ref(),
                signer_spki.clone(),
                &tbs_bytes,
                crl.signature.raw_bytes(),
            )
            // Verifier returns an opaque error; no additional context available.
            .map_err(|_| Error::CrlSignatureInvalid)?;

        // (5) RFC 5280 §5.2.5: if the CRL has an IssuingDistributionPoint extension
        //     (critical), check scope constraints against the certificate.
        // Scope mismatches surface as Error::OutOfScope so callers can distinguish
        // "verified not-revoked" (Ok(())) from "no determination made"
        // (Err(OutOfScope(...))). Hard-fail revocation policies should treat
        // OutOfScope as a failure.
        if let Some(idp) = &parsed_idp {
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
            // RFC 5280 §6.3.3(b)(1): IDP distributionPoint must match the
            // cert's CDP (cross-form `nameRelativeToCRLIssuer` ↔ `fullName`
            // resolution is performed by `dpn_to_general_names`).
            check_idp_dp_scope(cert, idp, &cert.tbs_certificate.issuer, signer_subject)?;
        }

        // (6) §5.2.4 delta CRL merge: if a delta CRL is present, verify and collect
        //     its revoked entries.  verify_delta_crl_and_collect handles sig, expiry,
        //     and the primary issuer-name check.  The extra checks below are
        //     defense-in-depth: they guard against any future code path that bypasses
        //     the with_delta() constructor and against subtle cross-name mismatches.
        let delta_entries: Vec<RevokedCert> = if let Some(delta_crl) = &self.delta_crl {
            // Reuse the pre-parsed delta CRL (parsed once at construction).

            // Extra check: delta CRL issuer must also match the base CRL issuer
            // (construction-time invariant, re-checked here for defense-in-depth).
            if !names_match(&delta_crl.tbs_cert_list.issuer, &crl.tbs_cert_list.issuer) {
                return Err(Error::CrlIssuerMismatch);
            }
            // The delta CRL must be signed by the same effective signer as the base.
            // This is guaranteed by issuer DN match plus the cRLIssuer-vs-issuer
            // selection above, but verify_delta_crl_and_collect will recheck.
            verify_delta_crl_and_collect(
                delta_crl,
                &self.verifier,
                signer_spki,
                signer_subject,
                self.now_unix,
            )?
        } else {
            Vec::new()
        };

        // (7) Search for the certificate's (issuer, serial) in the delta and base
        //     CRL entries. Delta CRL entries take precedence (RFC 5280 §5.2.4);
        //     a removeFromCRL reason in the delta un-revokes a cert.
        //
        //     For indirect CRLs the per-entry `certificateIssuer` extension may
        //     change the effective issuer of subsequent entries (RFC 5280 §5.3.3);
        //     entries inherit the previous extension's value, defaulting to the
        //     CRL's own issuer for the first entry.
        let cert_issuer = &cert.tbs_certificate.issuer;
        let cert_serial = &cert.tbs_certificate.serial_number;
        let crl_default_issuer = &crl.tbs_cert_list.issuer;
        let is_indirect = self.crl_issuer_cert.is_some();
        check_revocation_status_indirect(
            cert_issuer,
            cert_serial,
            &delta_entries,
            crl,
            crl_default_issuer,
            is_indirect,
        )
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
    /// CRL discovery via the `cRLDistributionPoints` extension is not
    /// implemented.  The CRL DER must be supplied at construction time.
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
                signer_subject = &crl_issuer.tbs_certificate.subject;
                signer_spki = crl_issuer
                    .tbs_certificate
                    .subject_public_key_info
                    .owned_to_ref();
                signer_for_crlsign_check = Some(crl_issuer);
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
        if !names_match(&cert.tbs_certificate.issuer, &anchor.subject) {
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
            .map_err(|e| Error::CrlParseError(crate::DerError(e)))?;
        self.verifier
            .verify_signature(
                crl.signature_algorithm.owned_to_ref(),
                signer_spki.clone(),
                &tbs_bytes,
                crl.signature.raw_bytes(),
            )
            .map_err(|_| Error::CrlSignatureInvalid)?;

        // (6) IssuingDistributionPoint scope check.
        if let Some(idp) = &parsed_idp {
            if idp.only_contains_attribute_certs {
                return Err(Error::OutOfScope(
                    crate::OutOfScopeReason::CrlOnlyAttributeCerts,
                ));
            }
            let cert_is_ca = cert_is_ca_cert(cert)?;
            if idp.only_contains_user_certs && cert_is_ca {
                return Err(Error::OutOfScope(crate::OutOfScopeReason::CrlOnlyUserCerts));
            }
            if idp.only_contains_ca_certs && !cert_is_ca {
                return Err(Error::OutOfScope(crate::OutOfScopeReason::CrlOnlyCaCerts));
            }
            // RFC 5280 §6.3.3(b)(1): IDP distributionPoint must match the
            // cert's CDP. The cert's CDP base DN for resolving
            // `nameRelativeToCRLIssuer` is the cert's issuer; the CRL's IDP
            // base DN is the CRL signer's subject (anchor's subject in the
            // direct anchor flow, cRLIssuer's subject in the indirect flow).
            check_idp_dp_scope(cert, idp, &cert.tbs_certificate.issuer, signer_subject)?;
        }

        // (7) Delta CRL merge.
        let delta_entries: Vec<RevokedCert> = if let Some(delta_crl) = &self.delta_crl {
            if !names_match(&delta_crl.tbs_cert_list.issuer, &crl.tbs_cert_list.issuer) {
                return Err(Error::CrlIssuerMismatch);
            }
            verify_delta_crl_and_collect(
                delta_crl,
                &self.verifier,
                signer_spki,
                signer_subject,
                self.now_unix,
            )?
        } else {
            Vec::new()
        };

        // (8) Look up the cert's (issuer, serial) in delta then base entries,
        //     honoring per-entry certificateIssuer for indirect CRLs.
        let cert_issuer = &cert.tbs_certificate.issuer;
        let cert_serial = &cert.tbs_certificate.serial_number;
        let crl_default_issuer = &crl.tbs_cert_list.issuer;
        let is_indirect = self.crl_issuer_cert.is_some();
        check_revocation_status_indirect(
            cert_issuer,
            cert_serial,
            &delta_entries,
            crl,
            crl_default_issuer,
            is_indirect,
        )
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
    use x509_cert::name::Name;

    let mut effective: Name = crl_default_issuer.clone();
    for entry in entries {
        // Only honor certificateIssuer in indirect CRLs (where it has
        // defined semantics per RFC 5280 §5.2.5/§5.3.3). Direct CRLs
        // should not contain this extension; if one does, ignoring it
        // here matches the conservative interpretation used by major
        // verifiers.
        if is_indirect {
            if let Some(exts) = entry.crl_entry_extensions.as_deref() {
                if let Some(ce_ext) = exts.iter().find(|e| e.extn_id == OID_CERTIFICATE_ISSUER) {
                    effective = parse_certificate_issuer_dn(ce_ext.extn_value.as_bytes())?;
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
        .map_err(|e| Error::CrlParseError(crate::DerError(e)))?;
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
    Err(Error::CrlParseError(crate::DerError(der::Error::new(
        der::ErrorKind::Failed,
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
/// 2. Check the delta validity window against `now_unix`.
/// 3. Verify the delta signature using `issuer_spki`.
/// 4. Return the delta's revoked-certificates list (empty if absent).
///
/// The caller is responsible for parsing the `CertificateList` and for any
/// additional issuer-name cross-checks needed by the calling context (e.g.,
/// checking the delta issuer against the base CRL issuer or the subject
/// certificate's issuer).
fn verify_delta_crl_and_collect<V: SignatureVerifier>(
    delta_crl: &CertificateList,
    verifier: &V,
    issuer_spki: spki::SubjectPublicKeyInfoRef<'_>,
    expected_issuer_name: &x509_cert::name::Name,
    now_unix: u64,
) -> crate::Result<Vec<RevokedCert>> {
    if !names_match(&delta_crl.tbs_cert_list.issuer, expected_issuer_name) {
        return Err(Error::CrlIssuerMismatch);
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
        .map_err(|e| Error::CrlParseError(crate::DerError(e)))?;
    verifier
        .verify_signature(
            delta_crl.signature_algorithm.owned_to_ref(),
            issuer_spki,
            &delta_tbs_bytes,
            delta_crl.signature.raw_bytes(),
        )
        // Verifier returns an opaque error; no additional context available.
        .map_err(|_| Error::CrlSignatureInvalid)?;

    // NOTE: The clone produces an owned `Vec<RevokedCert>` to keep the function
    // signature simple; both call sites currently consume the result by-value.
    // After the parse-once cache landed (delta_crl is now borrowed from
    // `self.delta_crl`), a borrow-based design returning `Option<&[RevokedCert]>`
    // is feasible — it would require updating both call sites and `check_revocation`
    // / `check_revocation_against_anchor` to consume the slice in-scope. Deferred
    // as a low-priority perf cleanup; the clone is bounded by the size of the
    // revoked list and occurs at most once per call.
    Ok(delta_crl
        .tbs_cert_list
        .revoked_certificates
        .clone()
        .unwrap_or_default())
}

// ---------------------------------------------------------------------------
// Extension helpers
// ---------------------------------------------------------------------------

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
        .tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find(|e| e.extn_id == OID_KEY_USAGE_CRL)
    else {
        return Ok(()); // KeyUsage absent (or no extensions) → no constraint
    };
    let ku = KeyUsage::from_der(ku_ext.extn_value.as_bytes())
        .map_err(|e| Error::CrlParseError(crate::DerError(e)))?;
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
                .map_err(|err| Error::CrlParseError(crate::DerError(err)))
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

    cert.tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find(|e| e.extn_id == OID_CRL_DISTRIBUTION_POINTS)
        .map(|e| {
            CrlDistributionPoints::from_der(e.extn_value.as_bytes())
                .map_err(|err| Error::CrlParseError(crate::DerError(err)))
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
) -> crate::Result<std::borrow::Cow<'a, [x509_cert::ext::pkix::name::GeneralName]>> {
    use std::borrow::Cow;
    use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};

    match dpn {
        DistributionPointName::FullName(names) => Ok(Cow::Borrowed(names.as_slice())),
        DistributionPointName::NameRelativeToCRLIssuer(rdn) => {
            // Append the RDN onto the base DN. `Name = RdnSequence(Vec<RDN>)`.
            // Cloning here is unavoidable because the resolved DN is a new
            // value; cert/CRL DNs are typically <10 RDNs each so this is cheap.
            let mut full_name = base_dn.clone();
            full_name.0.push(rdn.clone());
            Ok(Cow::Owned(vec![GeneralName::DirectoryName(full_name)]))
        }
    }
}

/// Compare two `GeneralName`s for equivalence.
///
/// `DirectoryName` uses [`pkix_path::names_match`] (RFC 4518-style DN
/// equivalence). Other variants compare by byte-exact DER encoding, which
/// is correct for `Rfc822Name`, `DnsName`, `UniformResourceIdentifier`,
/// `IpAddress`, `RegisteredId`, and `OtherName` because their values are
/// either ASCII subsets, IP address bytes, OIDs, or opaque DER (no
/// canonicalization ambiguity).
///
/// `EdiPartyName` and `X400Address` also fall into the byte-equal bucket;
/// they have no canonicalization specified for IDP/CDP matching purposes
/// and are extremely rare in modern PKI.
///
/// Mismatched variants always return `false` (no cross-variant matching).
fn general_name_matches(
    a: &x509_cert::ext::pkix::name::GeneralName,
    b: &x509_cert::ext::pkix::name::GeneralName,
) -> bool {
    use x509_cert::ext::pkix::name::GeneralName as GN;

    match (a, b) {
        (GN::DirectoryName(a_dn), GN::DirectoryName(b_dn)) => names_match(a_dn, b_dn),
        // Same variant on both sides, non-DN: byte-exact DER comparison.
        // Different variants: to_der() will succeed on both but produce
        // different bytes (different context-specific tags), so this also
        // correctly fails for cross-variant pairs.
        _ => match (a.to_der(), b.to_der()) {
            (Ok(a_der), Ok(b_der)) => a_der == b_der,
            // If either side fails to encode, fail-closed.
            _ => false,
        },
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

/// Check that the CRL's `IssuingDistributionPoint.distributionPoint`
/// matches the certificate's `cRLDistributionPoints` per RFC 5280 §6.3.3(b)(1).
///
/// Returns `Err(Error::OutOfScope(CrlIdpDistributionPointMismatch))` if
/// the CRL is structurally well-formed but does not cover the certificate's
/// distribution point claim.
///
/// Algorithm:
///
/// | cert CDP | CRL IDP DP | Outcome |
/// |---|---|---|
/// | absent   | absent     | match (no DP scoping either side) |
/// | absent   | present    | mismatch (CRL is scoped, cert isn't) |
/// | present  | absent     | match (IDP doesn't constrain DP) |
/// | present  | present    | at least one CDP entry's resolved name must intersect IDP's resolved name |
///
/// `cert_issuer` is the certificate's issuer DN (used as the base when the
/// cert's CDP uses `NameRelativeToCRLIssuer`). `crl_signer_subject` is the
/// CRL signer's subject DN (used as the base when the CRL's IDP uses
/// `NameRelativeToCRLIssuer`).
fn check_idp_dp_scope(
    cert: &Certificate,
    idp: &x509_cert::ext::pkix::crl::IssuingDistributionPoint,
    cert_issuer: &x509_cert::name::Name,
    crl_signer_subject: &x509_cert::name::Name,
) -> crate::Result<()> {
    let cert_cdps = cert_crl_distribution_points(cert)?;

    match (cert_cdps.as_ref(), idp.distribution_point.as_ref()) {
        (None, None) | (Some(_), None) => Ok(()),
        (None, Some(_)) => Err(Error::OutOfScope(
            crate::OutOfScopeReason::CrlIdpDistributionPointMismatch,
        )),
        (Some(cert_cdps), Some(idp_dpn)) => {
            let idp_names = dpn_to_general_names(idp_dpn, crl_signer_subject)?;
            // At least one cert CDP entry must have a distributionPoint that
            // intersects the IDP's. CDP entries with no distributionPoint
            // (RFC 5280 §4.2.1.13: "If the distributionPoint field is omitted,
            // the cRL distribution point must not include cRLIssuer that
            // …") cannot constrain to a specific name, so they cannot match
            // a non-empty IDP DPName here.
            let matched = cert_cdps.0.iter().any(|dp| {
                let Some(cdp_dpn) = &dp.distribution_point else {
                    return false;
                };
                let cdp_names = match dpn_to_general_names(cdp_dpn, cert_issuer) {
                    Ok(n) => n,
                    Err(_) => return false,
                };
                general_names_intersect(&cdp_names, &idp_names)
            });
            if matched {
                Ok(())
            } else {
                Err(Error::OutOfScope(
                    crate::OutOfScopeReason::CrlIdpDistributionPointMismatch,
                ))
            }
        }
    }
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
