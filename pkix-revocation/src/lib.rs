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

use pkix_path::TrustAnchor;
use x509_cert::{ext::pkix::crl::CrlReason, serial_number::SerialNumber, Certificate};

/// Errors returned by revocation checking.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The certificate has been revoked.
    Revoked {
        /// Serial number of the revoked certificate (for logging/diagnostics).
        serial: SerialNumber,
        /// RFC 5280 §5.3.1 reason code from the CRL/OCSP entry, if present.
        /// `None` means no reason code was provided.
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
    CrlParseError(der::Error),

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
    OcspParseError(der::Error),

    /// The OCSP response is structurally invalid per RFC 6960 but DER-decodable.
    ///
    /// Currently returned in two cases:
    /// - `responseBytes` is absent in a `Successful` response (RFC 6960 §4.2.1)
    /// - `responseType` is not `id-pkix-ocsp-basic` (unrecognized response format)
    OcspMalformed,

    /// The CRL issuer certificate does not have the `cRLSign` bit set in KeyUsage
    /// (RFC 5280 §6.3.3(f)).
    CrlSignMissing,

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
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Revoked {
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
            Error::CrlExpired => f.write_str("CRL validity window check failed"),
            Error::CrlIssuerMismatch => f.write_str("CRL issuer does not match certificate issuer"),
            Error::CrlSignatureInvalid => f.write_str("CRL signature is invalid"),
            Error::CrlParseError(e) => write!(f, "CRL parse error: {e}"),
            Error::OcspSignatureInvalid => f.write_str("OCSP response signature is invalid"),
            Error::OcspResponderIdMismatch => {
                f.write_str("OCSP ResponderId does not match the expected issuer identity")
            }
            Error::OcspCertIdMismatch => {
                f.write_str("OCSP CertID issuer hashes do not match the expected issuer")
            }
            Error::OcspIssuerCertMismatch => f.write_str(
                "issuer certificate subject DN does not match the certificate's issuer DN",
            ),
            Error::OcspStatusUnknown => f.write_str("OCSP responder returned unknown status"),
            Error::OcspExpired => f.write_str("OCSP response is stale or has no nextUpdate"),
            Error::OcspParseError(e) => write!(f, "OCSP response parse error: {e}"),
            Error::OcspMalformed => {
                f.write_str("OCSP response is structurally invalid (malformed per RFC 6960)")
            }
            Error::CrlSignMissing => {
                f.write_str("CRL issuer KeyUsage does not include cRLSign (RFC 5280 §6.3.3(f))")
            }
            Error::DeltaCrlBaseMismatch => {
                f.write_str("delta CRL BaseCRLNumber does not match the base CRL's CRLNumber")
            }
            Error::CrlNumberMismatch => f.write_str("CRL number is lower than expected"),
        }
    }
}

/// Map a `CrlReason` variant to its RFC 5280 §5.3.1 camelCase name.
fn crl_reason_name(r: CrlReason) -> &'static str {
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
            Error::CrlParseError(e) => Some(e),
            Error::OcspParseError(e) => Some(e),
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
    /// `Ok(())` has **dual semantics** — it can mean either of:
    ///
    /// 1. **Not revoked**: the revocation source covers this certificate and the
    ///    serial number was not found in the revoked list.
    /// 2. **Not covered**: the revocation source's scope does not apply to this
    ///    certificate type (e.g., a CRL scoped to CA certificates when checking an
    ///    end-entity, or an OCSP response with no matching `SingleResponse`).
    ///
    /// These two outcomes are **indistinguishable** from the `Ok(())` return alone.
    /// Callers enforcing a hard-fail revocation policy must separately verify that
    /// at least one revocation source actually covers the certificate in question.
    /// Note that individual implementations may differ: [`CrlChecker`] returns
    /// `Ok(())` for out-of-scope certificates, while [`OcspChecker`] returns
    /// `Err(`[`Error::OcspStatusUnknown`]`)` when no matching `SingleResponse` is found.
    ///
    /// Returns `Err` if the certificate is confirmed revoked or if a required
    /// revocation check fails (e.g., expired CRL, invalid signature).
    ///
    /// # Errors
    ///
    /// - [`Error::Revoked`] — the certificate's serial number appears in the
    ///   CRL's or OCSP response's revoked list.
    /// - [`Error::CrlExpired`] — the CRL has passed its `nextUpdate` timestamp.
    /// - [`Error::OcspMalformed`] — the OCSP response is structurally invalid or
    ///   its validity window check failed.
    /// - Other [`Error`] variants for parse failures, signature verification
    ///   failures, or structural constraint violations.
    #[must_use = "revocation check result must not be silently discarded"]
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
    #[must_use = "revocation check result must not be silently discarded"]
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
pub use crl::CrlChecker;

#[cfg(feature = "ocsp")]
mod ocsp;
#[cfg(feature = "ocsp")]
pub use ocsp::OcspChecker;
