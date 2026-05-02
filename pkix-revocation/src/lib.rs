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

use x509_cert::{ext::pkix::crl::CrlReason, serial_number::SerialNumber, Certificate};

/// Errors returned by revocation checking.
#[derive(Debug)]
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

    /// The OCSP responder returned an `unknown` status (hard-fail mode).
    OcspStatusUnknown,

    /// DER decoding of an OCSP response failed.
    OcspParseError(der::Error),

    /// The OCSP response is structurally invalid per RFC 6960 but DER-decodable.
    ///
    /// Currently returned in two cases:
    /// - `responseBytes` is absent in a `Successful` response (RFC 6960 §4.2.1)
    /// - `responseType` is not `id-pkix-ocsp-basic` (unrecognized response format)
    OcspMalformed,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Revoked {
                serial,
                reason_code,
            } => match reason_code {
                Some(code) => write!(f, "certificate {serial} is revoked (reason {code:?})"),
                None => write!(f, "certificate {serial} is revoked"),
            },
            Error::CrlExpired => f.write_str("CRL validity window check failed"),
            Error::CrlIssuerMismatch => f.write_str("CRL issuer does not match certificate issuer"),
            Error::CrlSignatureInvalid => f.write_str("CRL signature is invalid"),
            Error::CrlParseError(e) => write!(f, "CRL parse error: {e}"),
            Error::OcspSignatureInvalid => f.write_str("OCSP response signature is invalid"),
            Error::OcspStatusUnknown => f.write_str("OCSP responder returned unknown status"),
            Error::OcspParseError(e) => write!(f, "OCSP response parse error: {e}"),
            Error::OcspMalformed => f.write_str(
                "OCSP response is structurally invalid (malformed per RFC 6960)",
            ),
        }
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
pub trait RevocationChecker {
    /// Check whether `cert` has been revoked.
    ///
    /// - `cert`   — the certificate being checked
    /// - `issuer` — the certificate that issued `cert` (signature-validated)
    ///
    /// Returns `Ok(())` if the certificate is not revoked, or an `Err` if it
    /// is revoked or if revocation status cannot be determined and the policy
    /// requires a definitive answer (hard-fail mode).
    fn check_revocation(&self, cert: &Certificate, issuer: &Certificate) -> crate::Result<()>;
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
#[derive(Clone, Copy, Debug, Default)]
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
