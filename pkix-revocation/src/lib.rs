#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
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

use x509_cert::Certificate;

/// Errors returned by revocation checking.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The certificate at the given chain index has been revoked.
    Revoked {
        /// Zero-based index into the `chain` slice of the revoked certificate.
        index: usize,
    },
    /// Revocation status could not be determined (e.g., CRL fetch failed).
    ///
    /// In hard-fail mode this is treated as a revocation error.
    Unavailable {
        /// Zero-based index into the `chain` slice of the certificate.
        index: usize,
    },
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Revoked { index } => write!(f, "certificate at index {index} is revoked"),
            Error::Unavailable { index } => {
                write!(f, "revocation status unavailable for certificate at index {index}")
            }
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
/// into [`pkix_chain::verify_chain`]. Use [`NoRevocation`] for offline or
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

// TODO(crl feature): CrlChecker — validates a DER-encoded CRL against issuer
// SPKI, checks serial against revoked list. Tracked in pkix-revocation roadmap.

// TODO(ocsp feature): OcspChecker — validates a DER-encoded OCSP response,
// checks cert status. Tracked in pkix-revocation roadmap.
