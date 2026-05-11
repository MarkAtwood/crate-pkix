#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! Certificate Transparency SCT verification for `pkix-chain` (RFC 6962).
//!
//! Verifies Signed Certificate Timestamps (SCTs) embedded in X.509
//! certificates, OCSP responses, or TLS handshake extensions against a
//! set of trusted CT log public keys.
//!
//! # Spec references
//!
//! - RFC 6962 — Certificate Transparency
//! - RFC 9162 — Certificate Transparency Version 2.0
//! - CA/Browser Forum TLS Baseline Requirements §3.2.2.9 — SCT requirements
//!
//! # Limitations
//!
//! SCT binary-format parsing (RFC 6962 §3.2 / §3.3) is implemented; see
//! [`SignedCertificateTimestamp`] and [`SctList`]. Log list management,
//! signature verification, pre-cert handling, and Merkle inclusion proof
//! verification are not yet implemented; see the project tracker
//! (PKIX-baac children) for status.

extern crate alloc;

mod sct;

pub use sct::{SctList, SignedCertificateTimestamp};

use x509_cert::Certificate;

/// A set of trusted CT log public keys used to verify SCTs.
///
/// Populate from the current CT log list (e.g. Chrome's
/// <https://www.gstatic.com/ct/log_list/v3/log_list.json>) before verifying.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct CtLogList {
    // log public keys indexed by log_id — not yet implemented (tracked as PKIX-baac.2)
}

impl CtLogList {
    /// Create an empty log list.
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }
}

/// Errors returned by SCT parsing and verification.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// The certificate contains no SCT extension.
    NoScts,
    /// None of the SCTs in the certificate were signed by a log in the [`CtLogList`].
    NoTrustedSct,
    /// An SCT signature was invalid.
    InvalidSignature,
    /// DER parsing of the SCT list extension failed.
    ParseError,
    /// The SCT version byte was not 0 (v1). RFC 6962 §3.2 defines only
    /// version 1; RFC 9162 introduces v2 but is not yet deployed.
    UnsupportedVersion(u8),
    /// A length prefix in the SCT or SCT list ran past the available input,
    /// or trailing bytes remained after the declared length was consumed.
    TruncatedOrTrailing,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoScts => f.write_str("certificate contains no SCTs"),
            Self::NoTrustedSct => f.write_str("no SCT from a trusted log found"),
            Self::InvalidSignature => f.write_str("SCT signature invalid"),
            Self::ParseError => f.write_str("SCT list parse error"),
            Self::UnsupportedVersion(v) => {
                write!(
                    f,
                    "unsupported SCT version: {v} (only v1 / version=0 is supported)"
                )
            }
            Self::TruncatedOrTrailing => {
                f.write_str("SCT or SCT list bytes were truncated or had trailing data")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Verify that `cert` contains at least one valid SCT from a log in `logs`.
///
/// Checks the `SignedCertificateTimestampList` extension (OID
/// 1.3.6.1.4.1.11129.2.4.2). Returns `Ok(())` if at least one SCT verifies
/// against a trusted log; returns [`Error::NoTrustedSct`] otherwise.
///
/// # Errors
///
/// Returns `Err(Error::NoTrustedSct)` unconditionally. This function is a stub.
///
/// # Note
///
/// This is a stub. The function always returns `Err(Error::NoTrustedSct)`
/// regardless of input. See the crate-level documentation.
///
/// # Limitations
///
/// Signature verification is not yet implemented (tracked as PKIX-baac.3).
/// SCT parsing IS implemented; use [`SctList::from_extension_value`] to
/// parse the SCT-list extension value directly.
pub const fn verify_scts(_cert: &Certificate, _logs: &CtLogList) -> Result<()> {
    Err(Error::NoTrustedSct)
}
