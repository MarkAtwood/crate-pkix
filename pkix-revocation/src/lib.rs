#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! Certificate revocation checking for `pkix-path` and `pkix-chain`.
//!
//! Provides the [`RevocationChecker`] trait and implementations:
//!
//! | Type | Feature | Description |
//! |---|---|---|
//! | [`NoRevocation`] | (always) | Zero-cost; always reports not-revoked |
//! | `CrlChecker` | `crl` | Offline CRL validation (you supply DER bytes) |
//! | `OcspChecker` | `ocsp` | Offline OCSP response validation |
//!
//! # `no_std` note
//!
//! The core trait and `NoRevocation` are `no_std`. Feature-gated checkers
//! that perform network I/O are `std`-only and gated behind separate features.
//!
//! # Security: anchor-issued certificate revocation
//!
//! [`RevocationChecker::check_revocation_against_anchor`] has a default
//! implementation that returns `Ok(())` (i.e., skips the check). Implementors
//! that require **full-chain** revocation coverage — including the certificate
//! issued directly by a trust anchor — **MUST** override this method. Failing
//! to override it will silently leave the anchor-issued certificate unchecked
//! with no compile error or runtime warning. See that method's documentation
//! for details.
//!
//! # Limitations
//!
//! - **No network I/O.** `CrlChecker` and `OcspChecker` operate on
//!   caller-supplied DER bytes; this crate never opens a socket. Online
//!   fetching from `CRLDistributionPoints` / `AuthorityInfoAccess` URIs
//!   lives in the optional `pkix-revocation-http` adapter crate.
//! - **OCSP response only.** OCSP request construction (the DER bytes a
//!   client POSTs to a responder) lives in `pkix-revocation-http` so it can
//!   stay paired with the HTTP transport. The `OcspChecker` in this crate
//!   validates already-fetched responses.
//! - **No OCSP stapling helpers.** TLS-layer parsing of stapled responses
//!   (RFC 6066 §8, multi-stapling RFC 6961) is a transport-protocol
//!   concern handled by the TLS stack; once extracted, the response bytes
//!   feed `OcspChecker` like any other.
//! - **Algorithm coverage tracks `pkix-path`.** CRL and OCSP-response
//!   signature verification is delegated to a `SignatureVerifier`; the
//!   same algorithm gaps documented in `pkix-path` (Ed25519, P-521,
//!   RSA-PSS — tracked under `PKIX-gphz`) apply here.

use pkix_path::TrustAnchor;
use x509_cert::{ext::pkix::crl::CrlReason, serial_number::SerialNumber, Certificate};

/// Opaque wrapper around an underlying ASN.1 / DER error.
///
/// Re-exported from [`pkix_path::DerError`] so callers can match
/// [`Error::CrlParseError`] / [`Error::OcspParseError`] against the
/// same diagnostic type used by `pkix-path::Error::Der`. The wrapped
/// `der::Error` is internal; only the [`Display`] message is in the
/// public API. This insulates callers from semver-breaking changes
/// in the `der` crate's error variants and makes the type
/// cache-friendly (Clone + PartialEq + Eq + serde-friendly).
///
/// [`Display`]: core::fmt::Display
pub use pkix_path::DerError;

#[cfg(feature = "serde")]
mod crl_reason_serde {
    //! Serde shims for `Option<CrlReason>`. `CrlReason` is `repr(u32)`
    //! upstream with stable RFC 5280 §5.3.1 numeric codes; we serialize
    //! via the discriminant value. Unknown codes round-trip as `None`
    //! so older consumers stay forward-compatible with new revocation
    //! reasons that upstream adds.
    use serde::{Deserialize as _, Deserializer, Serializer};
    use x509_cert::ext::pkix::crl::CrlReason;

    /// Convert a `CrlReason` to its RFC 5280 §5.3.1 numeric code.
    const fn to_code(r: CrlReason) -> u32 {
        match r {
            CrlReason::Unspecified => 0,
            CrlReason::KeyCompromise => 1,
            CrlReason::CaCompromise => 2,
            CrlReason::AffiliationChanged => 3,
            CrlReason::Superseded => 4,
            CrlReason::CessationOfOperation => 5,
            CrlReason::CertificateHold => 6,
            CrlReason::RemoveFromCRL => 8,
            CrlReason::PrivilegeWithdrawn => 9,
            CrlReason::AaCompromise => 10,
        }
    }

    /// Inverse of [`to_code`]; returns `None` for unrecognised values
    /// so future reason codes round-trip non-destructively.
    const fn from_code(c: u32) -> Option<CrlReason> {
        match c {
            0 => Some(CrlReason::Unspecified),
            1 => Some(CrlReason::KeyCompromise),
            2 => Some(CrlReason::CaCompromise),
            3 => Some(CrlReason::AffiliationChanged),
            4 => Some(CrlReason::Superseded),
            5 => Some(CrlReason::CessationOfOperation),
            6 => Some(CrlReason::CertificateHold),
            8 => Some(CrlReason::RemoveFromCRL),
            9 => Some(CrlReason::PrivilegeWithdrawn),
            10 => Some(CrlReason::AaCompromise),
            _ => None,
        }
    }

    pub fn serialize_opt<S: Serializer>(
        v: &Option<CrlReason>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        use serde::Serialize as _;
        v.map(to_code).serialize(s)
    }

    pub fn deserialize_opt<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<CrlReason>, D::Error> {
        let opt = Option::<u32>::deserialize(d)?;
        Ok(opt.and_then(from_code))
    }
}

/// Reason a revocation check produced no determination.
///
/// Carried by [`Error::OutOfScope`] to identify which scope-mismatch case the
/// checker hit. Distinct from `Crl*Error` (parse / signature / validity
/// failures): an `OutOfScope` outcome is structurally well-formed but the
/// revocation source's stated scope excludes the certificate being checked.
///
/// Hard-fail callers should treat any `OutOfScope` as a failure (no
/// revocation determination was made). Soft-fail callers can match on the
/// reason and decide which scopes to tolerate (for example, treating
/// `CrlOnlyAttributeCerts` as "expected and tolerable" while still hard-failing
/// on `CrlOnlyCaCerts` when checking a CA certificate).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum OutOfScopeReason {
    /// The CRL's `IssuingDistributionPoint` extension has
    /// `onlyContainsAttributeCerts = true`. Attribute-certificate revocation
    /// is out of scope for `pkix-revocation` (RFC 5755 attribute certificates
    /// are handled by `pkix-ac`); the certificate being checked is a public-key
    /// certificate, so the CRL cannot apply.
    CrlOnlyAttributeCerts,
    /// The CRL's `IssuingDistributionPoint` extension has
    /// `onlyContainsUserCerts = true` but the certificate being checked is a
    /// CA certificate (`BasicConstraints` `cA = TRUE`).
    CrlOnlyUserCerts,
    /// The CRL's `IssuingDistributionPoint` extension has
    /// `onlyContainsCACerts = true` but the certificate being checked is not a
    /// CA certificate.
    CrlOnlyCaCerts,
    /// The CRL's `IssuingDistributionPoint` `distributionPoint` field does
    /// not match (or is incompatible with) any of the certificate's
    /// `cRLDistributionPoints` extension entries (RFC 5280 §6.3.3(b)(1)).
    ///
    /// This case covers two sub-conditions, which are not distinguished in
    /// the public API to avoid leaking implementation detail:
    ///
    /// 1. The CRL's IDP names a specific distribution point but the
    ///    certificate carries no `cRLDistributionPoints` extension at all.
    /// 2. Both sides name distribution points but no entry in the
    ///    certificate's CDP resolves to a name that intersects the IDP's
    ///    distributionPoint name.
    ///
    /// Hard-fail callers should treat this exactly like the other
    /// `OutOfScope` reasons: the CRL is structurally well-formed but does
    /// not cover the certificate, and a separate CRL/OCSP source must be
    /// consulted.
    CrlIdpDistributionPointMismatch,
}

impl core::fmt::Display for OutOfScopeReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CrlOnlyAttributeCerts => f.write_str(
                "CRL onlyContainsAttributeCerts=TRUE; subject is a public-key certificate",
            ),
            Self::CrlOnlyUserCerts => {
                f.write_str("CRL onlyContainsUserCerts=TRUE; subject is a CA certificate")
            }
            Self::CrlOnlyCaCerts => {
                f.write_str("CRL onlyContainsCACerts=TRUE; subject is an end-entity certificate")
            }
            Self::CrlIdpDistributionPointMismatch => f.write_str(
                "CRL IssuingDistributionPoint distributionPoint does not match the certificate's CRLDistributionPoints",
            ),
        }
    }
}

/// Errors returned by revocation checking.
///
/// # Variant naming convention
///
/// Most variants carry a `Crl*` or `Ocsp*` prefix indicating which revocation
/// source produced the failure. Four variants intentionally do not:
///
/// - [`Error::Revoked`] applies to both CRL and OCSP outcomes; no prefix is
///   correct. This is what [`RevocationChecker::check_revocation`] returns
///   generically when a serial is found in either kind of response.
/// - [`Error::MalformedCertificate`] fires on the *subject* certificate being
///   checked (e.g., a missing serial number), not on the CRL or OCSP response.
/// - [`Error::DeltaCrlBaseMismatch`] uses `DeltaCrl*` rather than `CrlDelta*`
///   because the failure is scoped to the delta-CRL workflow — the prefix
///   reads as the noun phrase "delta CRL" rather than as a sub-namespace of
///   `Crl*`.
/// - [`Error::OutOfScope`] applies whenever a revocation source's stated
///   scope excludes the certificate being checked. Today only CRL `IDP`
///   scope mismatches produce this; the variant is named generically so that
///   future OCSP / SCT / OCSP-stapling scope-mismatch cases can reuse it
///   without an additional rename.
///
/// Renames are a semver break; do not "normalize" these without coordinating
/// a major version.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Error {
    /// The certificate has been revoked.
    Revoked {
        /// Serial number of the revoked certificate (for logging/diagnostics).
        #[cfg_attr(feature = "serde", serde(with = "pkix_path::serde_der"))]
        serial: SerialNumber,
        /// RFC 5280 §5.3.1 reason code from the CRL/OCSP entry, if present.
        /// `None` means no reason code was provided.
        #[cfg_attr(
            feature = "serde",
            serde(
                serialize_with = "crl_reason_serde::serialize_opt",
                deserialize_with = "crl_reason_serde::deserialize_opt"
            )
        )]
        reason_code: Option<CrlReason>,
    },

    /// The CRL validity window check failed.
    ///
    /// This covers two cases:
    /// - `now < thisUpdate`: the CRL is not yet valid (clock skew or future-dated CRL)
    /// - `now > nextUpdate`: the CRL has expired
    /// - `nextUpdate` absent: treated as expired (no expiry information means stale)
    CrlExpired,

    /// The CRL issuer name does not match the certificate's issuer.
    ///
    /// The CRL's `issuer` field must match the certificate's `issuer` field for the
    /// CRL to apply to that certificate. A mismatch indicates the wrong CRL was provided.
    CrlIssuerMismatch,

    /// The CRL signature did not verify against the issuer's SPKI.
    CrlSignatureInvalid,

    /// DER decoding of a CRL failed.
    CrlParseError(DerError),

    /// An OCSP response signature did not verify against the responder's key.
    OcspSignatureInvalid,

    /// The OCSP `ResponderId` does not match the expected issuer identity.
    ///
    /// Returned when the `byName` DN or `byKey` SHA-1 hash in the OCSP response
    /// does not match the issuer (or trust anchor) used for this check.
    ///
    /// - `byName`: the name in the `ResponderId` does not match the issuer's
    ///   subject DN (RFC 4518 comparison).
    /// - `byKey`: the hash in the `ResponderId` does not match SHA-1 of the
    ///   issuer's `subjectPublicKey` bit string (raw bytes, with tag, length,
    ///   and unused-bits prefix stripped — not SHA-1 of the full SPKI DER).
    ///
    /// This is a distinct failure from [`Error::OcspSignatureInvalid`]: the
    /// response may be cryptographically valid, but it was produced by a
    /// different responder than expected.
    OcspResponderIdMismatch,

    /// The OCSP response's `CertID` issuer hashes do not match the expected issuer.
    ///
    /// The `issuerNameHash` or `issuerKeyHash` field in a `SingleResponse`
    /// identifies which issuer the status assertion covers. A mismatch means
    /// the response was produced for a certificate from a *different* CA
    /// (or was tampered with) — it is not a responder-reported "unknown"
    /// status. Callers MUST NOT treat this error as "try another responder".
    OcspCertIdMismatch,

    /// The `issuer` argument passed to [`RevocationChecker::check_revocation`] is
    /// not the issuer of `cert`.
    ///
    /// This is a caller-contract violation: the subject DN of `issuer` does not
    /// match the issuer DN of `cert`. The OCSP response was not consulted.
    OcspIssuerCertMismatch,

    /// The OCSP responder returned an `unknown` status (hard-fail mode).
    OcspStatusUnknown,

    /// The OCSP response's validity window is in the past (stale) or absent.
    ///
    /// Returned in two cases:
    /// - `now > nextUpdate`: the `SingleResponse` has expired
    /// - `nextUpdate` absent: no freshness guarantee is available; treated as stale
    OcspExpired,

    /// DER decoding of an OCSP response failed.
    OcspParseError(DerError),

    /// The OCSP response is structurally invalid per RFC 6960 but DER-decodable.
    ///
    /// Currently returned in two cases:
    /// - `responseBytes` is absent in a `Successful` response (RFC 6960 §4.2.1)
    /// - `responseType` is not `id-pkix-ocsp-basic` (unrecognized response format)
    OcspMalformed,

    /// A delegated OCSP responder cert in the response's `certs` field
    /// lacks the `id-kp-OCSPSigning` Extended Key Usage (RFC 6960
    /// §4.2.2.2). Without this EKU the cert cannot legitimately sign OCSP
    /// responses, so the response is rejected.
    OcspResponderEkuMissing,

    /// A delegated OCSP responder cert's `ExtendedKeyUsage` extension is
    /// present but cannot be DER-decoded.
    ///
    /// Fail-closed: a malformed EKU on a candidate responder cert rejects
    /// the response rather than silently treating the cert as if it lacked
    /// the OCSPSigning purpose.
    OcspResponderEkuMalformed,

    /// A delegated OCSP responder cert was found whose ResponderId
    /// matches, but it was issued by a different CA than the certificate
    /// being checked.
    ///
    /// RFC 6960 §4.2.2.2 requires a "CA Designated Responder" cert to be
    /// issued directly by the CA whose certificates the responder asserts
    /// status for. A responder cert with the OCSPSigning EKU obtained
    /// from another CA could otherwise be used to forge revocation
    /// status claims on certs from a different CA.
    OcspResponderCertNotIssuedByCa,

    /// A delegated OCSP responder cert's validity period does not include
    /// the response's `producedAt` timestamp. The signing key was not
    /// authoritative when the response was generated.
    OcspResponderCertExpired,

    /// The CA-supplied signature on a delegated OCSP responder cert
    /// failed to verify against the issuer's SPKI.
    ///
    /// Distinct from [`Error::OcspSignatureInvalid`] (which is the
    /// response's own signature failing): this is the issuer-of-cert's
    /// signature on the responder cert's TBS, validated to confirm the
    /// responder cert was actually issued by the expected CA.
    OcspResponderCertSigInvalid,

    /// The CRL declares itself an indirect CRL (RFC 5280 §5.2.6:
    /// `IssuingDistributionPoint.indirectCRL = TRUE`) but the checker
    /// was constructed without a `cRLIssuer` certificate.
    ///
    /// Use [`crate::CrlChecker::new_with_crl_issuer`] (or its delta
    /// sibling) and supply the cert that actually signed the CRL.
    IndirectCrlIssuerMissing,

    /// The CRL does NOT declare itself an indirect CRL but the checker
    /// was constructed with a `cRLIssuer` certificate.
    ///
    /// This rejects the inverse of [`Error::IndirectCrlIssuerMissing`]:
    /// a caller asserting a separate CRL signer for what is actually a
    /// direct CRL signed by the cert's own issuer. Direct CRLs should
    /// be loaded via [`crate::CrlChecker::new`] / `with_delta`.
    IndirectCrlIssuerUnexpected,

    /// The CRL issuer certificate does not have the `cRLSign` bit set in
    /// its `KeyUsage` extension (RFC 5280 §6.3.3(f)).
    ///
    /// Returned when the certificate used to verify a CRL's signature has
    /// a `KeyUsage` extension present but the `cRLSign` bit (bit 6) is not
    /// asserted. If the `KeyUsage` extension is absent entirely, this
    /// error is **not** raised (no extension = no constraint).
    ///
    /// **Disambiguation:** [`pkix_path::Error::CrlSignMissing`] (same
    /// variant name, different crate) fires during *path validation* when
    /// an intermediate CA cert in the chain lacks `cRLSign` and the caller
    /// opted into [`pkix_path::ValidationPolicy::require_crl_sign_on_cas`].
    /// This variant fires during *CRL verification* when the CRL signer
    /// cert itself lacks `cRLSign`.
    ///
    /// [`pkix_path::Error::CrlSignMissing`]: https://docs.rs/pkix-path/latest/pkix_path/enum.Error.html#variant.CrlSignMissing
    CrlSignMissing,

    /// Path-level CRL signer discovery (RFC 5280 §6.3.3(f)) could not
    /// locate a certificate in the caller-supplied bundle that signed
    /// the CRL.
    ///
    /// Returned by [`CrlChecker::new_with_signer_discovery`] when neither
    /// the CRL's `AuthorityKeyIdentifier` matches any bundle cert's
    /// `SubjectKeyIdentifier`, nor any bundle cert's subject DN matches
    /// the CRL's issuer DN. The caller must either supply a more
    /// complete bundle or use a different constructor.
    ///
    /// [`CrlChecker::new_with_signer_discovery`]: crate::CrlChecker::new_with_signer_discovery
    CrlSignerNotFound,

    /// Path-level CRL signer discovery found a candidate cert in the
    /// bundle, but the candidate does not chain back to a self-signed
    /// (anchor-like) cert in the same bundle.
    ///
    /// Returned by [`CrlChecker::new_with_signer_discovery`]. This is
    /// the structural half of RFC 5280 §6.3.3(f)'s "chain back to a
    /// trust anchor" gate; it ensures the bundle is not missing the
    /// signer's CA path. Full RFC 5280 §6.1 signature/policy validation
    /// of the signer's chain is the responsibility of higher-layer
    /// composers such as `pkix-chain` and is intentionally not
    /// performed here.
    ///
    /// [`CrlChecker::new_with_signer_discovery`]: crate::CrlChecker::new_with_signer_discovery
    CrlSignerNotTrusted,

    /// The base/delta CRL pair cannot be used together.
    ///
    /// Returned in any of these cases:
    /// - The supplied "base" CRL is itself a delta CRL (has a `deltaCRLIndicator`
    ///   extension) — RFC 5280 §5.2.4 requires a full CRL as the base.
    /// - The supplied "delta" CRL has no `deltaCRLIndicator` extension and is
    ///   therefore not a delta CRL at all.
    /// - The base and delta CRL have different issuers.
    ///
    /// Note: when the delta's `BaseCRLNumber` exceeds the base CRL's `CRLNumber`
    /// (a staleness mismatch), [`Error::CrlNumberMismatch`] is returned instead.
    DeltaCrlBaseMismatch,

    /// The CRL's CRL number is lower than expected (base CRL must have a number
    /// ≥ the delta's `BaseCRLNumber`).
    CrlNumberMismatch,

    /// A subject certificate's `BasicConstraints` extension is present but
    /// could not be DER-decoded.
    ///
    /// Returned when the IDP scope check (`onlyContainsCACerts` /
    /// `onlyContainsUserCerts`) cannot determine whether a CRL applies to
    /// `cert` because `cert`'s own `BasicConstraints` is malformed.
    /// This is a fail-closed alternative to silently treating the cert as
    /// not-a-CA (which would let CA-scoped CRLs be skipped for an actual CA).
    MalformedCertificate,

    /// The revocation source's stated scope excludes the certificate being
    /// checked, so the checker made **no determination** about its revocation
    /// status.
    ///
    /// This is distinct from "verified not-revoked" (the historic ambiguous
    /// `Ok(())` return that this variant replaces). Hard-fail callers should
    /// treat any `OutOfScope` as a failure; soft-fail callers can match on
    /// the [`OutOfScopeReason`] and decide which scopes to tolerate.
    ///
    /// Currently produced by [`CrlChecker`] for the three
    /// `IssuingDistributionPoint` scope-flag mismatches in RFC 5280 §5.2.5
    /// (`onlyContainsAttributeCerts`, `onlyContainsUserCerts`, and
    /// `onlyContainsCACerts`). [`OcspChecker`] does **not** produce this
    /// variant: it returns [`Error::OcspStatusUnknown`] when no matching
    /// `SingleResponse` is found, which is its analogue of "not covered" and
    /// already fail-closed.
    ///
    /// [`CrlChecker`]: crate::CrlChecker
    /// [`OcspChecker`]: crate::OcspChecker
    OutOfScope(OutOfScopeReason),

    /// All known sources for revocation data failed to produce a usable
    /// response.
    ///
    /// Returned by network-fetching adapters (`pkix-revocation-http`'s
    /// `HttpCrlFetcher` / `HttpOcspFetcher`, future LDAP / out-of-band
    /// adapters) when every URL extracted from the certificate failed
    /// either at the transport layer (network, TLS, HTTP error) or at
    /// the response layer (DER parse, signature, validity). The variant
    /// is intentionally generic so that revocation sources beyond HTTP
    /// can reuse it.
    ///
    /// Distinct from:
    /// - [`Error::Revoked`] — source reached and reports revoked
    /// - [`Error::OcspStatusUnknown`] — responder reached, reports unknown
    /// - [`Error::OutOfScope`] — structurally-valid response that does
    ///   not cover the certificate
    ///
    /// Hard-fail callers MUST reject the chain on this variant.
    /// Soft-fail callers MAY treat it permissively.
    ///
    /// `description` is a human-readable summary suitable for logs; it
    /// includes per-URL transport / status hints from the adapter. The
    /// shape is deliberately a `String` rather than structured data so
    /// the variant remains `Clone + PartialEq + Eq` (matching the rest
    /// of `Error`) without leaking adapter-specific types into the
    /// trait surface. Adapters surface structured failure information
    /// through their own APIs.
    ///
    /// The variant is feature-gated behind `std` because `String` is
    /// not available in the bare `no_std` build path. Network-fetching
    /// adapters all require `std` anyway, so no-std consumers never
    /// need to construct or match this variant.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    RevocationFetchFailed {
        /// Human-readable summary of the failures, one URL per line.
        description: String,
    },
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Revoked {
                serial,
                reason_code,
            } => match reason_code {
                Some(code) => write!(
                    f,
                    "certificate {serial} is revoked (reason {})",
                    crl_reason_name(*code)
                ),
                None => write!(f, "certificate {serial} is revoked"),
            },
            Self::CrlExpired => f.write_str("CRL validity window check failed"),
            Self::CrlIssuerMismatch => f.write_str("CRL issuer does not match certificate issuer"),
            Self::CrlSignatureInvalid => f.write_str("CRL signature is invalid"),
            Self::CrlParseError(e) => write!(f, "CRL parse error: {e}"),
            Self::OcspSignatureInvalid => f.write_str("OCSP response signature is invalid"),
            Self::OcspResponderIdMismatch => {
                f.write_str("OCSP ResponderId does not match the expected issuer identity")
            }
            Self::OcspCertIdMismatch => {
                f.write_str("OCSP CertID issuer hashes do not match the expected issuer")
            }
            Self::OcspIssuerCertMismatch => f.write_str(
                "issuer certificate subject DN does not match the certificate's issuer DN",
            ),
            Self::OcspStatusUnknown => f.write_str("OCSP responder returned unknown status"),
            Self::OcspExpired => f.write_str("OCSP response is stale or has no nextUpdate"),
            Self::OcspParseError(e) => write!(f, "OCSP response parse error: {e}"),
            Self::OcspMalformed => {
                f.write_str("OCSP response is structurally invalid (malformed per RFC 6960)")
            }
            Self::OcspResponderEkuMissing => f.write_str(
                "delegated OCSP responder cert lacks id-kp-OCSPSigning Extended Key Usage",
            ),
            Self::OcspResponderEkuMalformed => {
                f.write_str("delegated OCSP responder cert ExtendedKeyUsage extension is malformed")
            }
            Self::OcspResponderCertNotIssuedByCa => {
                f.write_str("delegated OCSP responder cert was not issued by the certificate's CA")
            }
            Self::OcspResponderCertExpired => f.write_str(
                "delegated OCSP responder cert validity does not include the response's producedAt",
            ),
            Self::OcspResponderCertSigInvalid => {
                f.write_str("CA signature on delegated OCSP responder cert is invalid")
            }
            Self::IndirectCrlIssuerMissing => f.write_str(
                "CRL declares indirectCRL=TRUE but no cRLIssuer certificate was provided",
            ),
            Self::IndirectCrlIssuerUnexpected => {
                f.write_str("cRLIssuer certificate was provided but the CRL is not indirect")
            }
            Self::CrlSignMissing => {
                f.write_str("CRL issuer KeyUsage does not include cRLSign (RFC 5280 §6.3.3(f))")
            }
            Self::CrlSignerNotFound => f.write_str(
                "no certificate in the supplied bundle signed the CRL (path-level discovery)",
            ),
            Self::CrlSignerNotTrusted => f.write_str(
                "discovered CRL signer does not chain back to a self-signed anchor in the supplied bundle",
            ),
            Self::DeltaCrlBaseMismatch => {
                f.write_str("delta CRL BaseCRLNumber does not match the base CRL's CRLNumber")
            }
            Self::CrlNumberMismatch => f.write_str("CRL number is lower than expected"),
            Self::MalformedCertificate => f.write_str(
                "certificate BasicConstraints extension is present but cannot be decoded",
            ),
            Self::OutOfScope(reason) => {
                write!(f, "revocation source out of scope: {reason}")
            }
            #[cfg(feature = "std")]
            Self::RevocationFetchFailed { description } => {
                write!(f, "revocation data fetch failed: {description}")
            }
        }
    }
}

/// Map a `CrlReason` variant to its RFC 5280 §5.3.1 camelCase name.
const fn crl_reason_name(r: CrlReason) -> &'static str {
    match r {
        CrlReason::Unspecified => "unspecified",
        CrlReason::KeyCompromise => "keyCompromise",
        CrlReason::CaCompromise => "cACompromise",
        CrlReason::AffiliationChanged => "affiliationChanged",
        CrlReason::Superseded => "superseded",
        CrlReason::CessationOfOperation => "cessationOfOperation",
        CrlReason::CertificateHold => "certificateHold",
        CrlReason::RemoveFromCRL => "removeFromCRL",
        CrlReason::PrivilegeWithdrawn => "privilegeWithdrawn",
        CrlReason::AaCompromise => "aACompromise",
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CrlParseError(e) | Self::OcspParseError(e) => Some(e),
            _ => None,
        }
    }
}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Pluggable revocation checking.
///
/// Called once per certificate in the chain, in leaf-to-issuer order,
/// after path signature validation has succeeded.
///
/// Implement this trait to plug CRL, OCSP, or a custom revocation mechanism
/// into `pkix_chain::verify_chain`. Use [`NoRevocation`] for offline or
/// embedded environments.
/// # Implementing this trait
///
/// Implementors MUST provide [`RevocationChecker::check_revocation`].
///
/// Implementors that want **full-chain** revocation coverage — i.e., revocation
/// checking for every certificate including the one issued directly by a trust
/// anchor — MUST also override
/// [`RevocationChecker::check_revocation_against_anchor`]. The default
/// implementation skips the check silently; forgetting to override it will
/// leave the anchor-issued certificate unchecked with no compile error or
/// runtime warning.
pub trait RevocationChecker {
    /// Check whether `cert` has been revoked.
    ///
    /// - `cert`   — the certificate being checked
    /// - `issuer` — the certificate that issued `cert` (signature-validated)
    ///
    /// # Return value
    ///
    /// `Ok(())` means **verified not-revoked**: the revocation source covers
    /// this certificate and the serial number was not found in the revoked
    /// list. This is an unambiguous "not revoked" determination.
    ///
    /// "Not covered" — i.e., the revocation source's scope excludes the
    /// certificate so no determination was made — surfaces as
    /// <code>Err([Error::OutOfScope]([OutOfScopeReason]))</code> for CRL
    /// scope-flag mismatches and as
    /// <code>Err([Error::OcspStatusUnknown])</code> for OCSP responses with no
    /// matching `SingleResponse`. Hard-fail callers should treat both as
    /// failures; soft-fail callers can match on the specific variant /
    /// reason and decide which non-determinations to tolerate.
    ///
    /// # Errors
    ///
    /// - [`Error::Revoked`] — the certificate's serial number appears in the
    ///   CRL's or OCSP response's revoked list.
    /// - [`Error::CrlExpired`] — the CRL has passed its `nextUpdate` timestamp.
    /// - [`Error::OcspMalformed`] — the OCSP response is structurally invalid or
    ///   its validity window check failed.
    /// - [`Error::OcspStatusUnknown`] — no matching `SingleResponse` covered
    ///   the certificate (OCSP-side "not covered").
    /// - [`Error::OutOfScope`] — a CRL `IssuingDistributionPoint` scope flag
    ///   excludes the certificate being checked (CRL-side "not covered").
    /// - Other [`Error`] variants for parse failures, signature verification
    ///   failures, or structural constraint violations.
    fn check_revocation(&self, cert: &Certificate, issuer: &Certificate) -> crate::Result<()>;

    /// Check whether `cert` (issued directly by a trust anchor) has been revoked.
    ///
    /// Called by `verify_chain` for the last certificate in the chain — the one
    /// whose issuer is a [`TrustAnchor`] rather than another certificate in the
    /// chain. For example, in the chain `[leaf, intermediate_CA]` this method is
    /// called with `cert = intermediate_CA` and `anchor` set to the matched anchor.
    ///
    /// **Default implementation returns `Ok(())` (skip).** Override this method
    /// to enforce revocation checking for certificates issued directly by a trust
    /// anchor (e.g., fetch and verify the CA's CRL using the anchor's public key).
    ///
    /// `NoRevocation` inherits this default and skips the check, matching its
    /// overall no-op behaviour. `CrlChecker` and `OcspChecker` both override
    /// this method: they verify the pre-loaded CRL or OCSP response against the
    /// anchor's subject DN and SPKI.
    ///
    /// # Security
    ///
    /// **The default implementation silently skips revocation checking for the
    /// anchor-issued certificate.** If your threat model requires revocation
    /// checking for every certificate in the chain — including the one issued
    /// directly by the trust anchor — you MUST override this method. There is
    /// no compile-time or runtime warning when the default is used; the skip
    /// is intentional for environments (e.g., embedded, offline, short-lived
    /// certificates) where anchor-level revocation data is unavailable.
    ///
    /// Failing to override this method in a context that requires full-chain
    /// revocation coverage is a silent security gap.
    ///
    /// # Note: default is a no-op
    ///
    /// The default implementation performs **no revocation check** and always
    /// returns `Ok(())`. Any implementor that does not override this method
    /// silently skips revocation for the certificate directly issued by the
    /// trust anchor. Override this method to enable anchor-level revocation.
    ///
    /// # Errors
    ///
    /// The default implementation always returns `Ok(())`; override this method
    /// to enable error-returning revocation checks.
    fn check_revocation_against_anchor(
        &self,
        _cert: &Certificate,
        _anchor: &TrustAnchor,
    ) -> crate::Result<()> {
        Ok(())
    }
}

/// A no-op revocation checker that always reports certificates as not revoked.
///
/// Use this when:
/// - Running in embedded / offline environments with no revocation infrastructure
/// - Revocation is enforced at a higher layer
/// - In tests and development environments
///
/// # Security note
///
/// `NoRevocation` does **not** consult CRLs or OCSP. A revoked certificate
/// will pass validation. Only use this when your threat model permits
/// unenforced revocation (e.g., closed networks, short-lived certificates,
/// hardware attestation where issuance itself is the control).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct NoRevocation;

impl RevocationChecker for NoRevocation {
    #[inline]
    fn check_revocation(&self, _cert: &Certificate, _issuer: &Certificate) -> crate::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "crl")]
mod crl;
#[cfg(feature = "crl")]
mod signer_discovery;
#[cfg(feature = "crl")]
#[cfg_attr(docsrs, doc(cfg(feature = "crl")))]
pub use crl::CrlChecker;
#[cfg(feature = "crl")]
#[cfg_attr(docsrs, doc(cfg(feature = "crl")))]
pub use signer_discovery::discover_crl_signer;

#[cfg(feature = "ocsp")]
mod ocsp;
#[cfg(feature = "ocsp")]
#[cfg_attr(docsrs, doc(cfg(feature = "ocsp")))]
pub use ocsp::OcspChecker;

// ---------------------------------------------------------------------------
// Send + Sync compile-time assertions (AGENTS.md non-negotiable #6, PKIX-2l0v.2)
// ---------------------------------------------------------------------------

const _: fn() = || {
    fn _assert_send_sync<T: Send + Sync>() {}
    _assert_send_sync::<Error>();
};
