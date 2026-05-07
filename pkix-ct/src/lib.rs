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
//! Not yet implemented.

use x509_cert::Certificate;

/// A Signed Certificate Timestamp as defined in RFC 6962 §3.2.
///
/// SCTs are embedded in certificates via the `SignedCertificateTimestampList`
/// extension (OID 1.3.6.1.4.1.11129.2.4.2), in OCSP responses, or delivered
/// via the TLS handshake.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SignedCertificateTimestamp {
    /// Log ID: SHA-256 hash of the log's public key DER encoding.
    pub log_id: [u8; 32],
    /// Milliseconds since the Unix epoch at which the SCT was issued.
    pub timestamp_ms: u64,
}

/// A set of trusted CT log public keys used to verify SCTs.
///
/// Populate from the current CT log list (e.g. Chrome's
/// <https://www.gstatic.com/ct/log_list/v3/log_list.json>) before verifying.
#[derive(Debug, Default)]
pub struct CtLogList {
    // log public keys indexed by log_id — not yet implemented (tracked for v0.2)
}

impl CtLogList {
    /// Create an empty log list.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Errors returned by SCT verification.
#[derive(Debug)]
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
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::NoScts => f.write_str("certificate contains no SCTs"),
            Error::NoTrustedSct => f.write_str("no SCT from a trusted log found"),
            Error::InvalidSignature => f.write_str("SCT signature invalid"),
            Error::ParseError => f.write_str("SCT list parse error"),
        }
    }
}

impl std::error::Error for Error {}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Verify that `cert` contains at least one valid SCT from a log in `logs`.
///
/// Checks the `SignedCertificateTimestampList` extension (OID
/// 1.3.6.1.4.1.11129.2.4.2). Returns `Ok(())` if at least one SCT verifies
/// against a trusted log; returns [`Error::NoTrustedSct`] otherwise.
///
/// # Note
///
/// This is a stub. The function always returns `Err(Error::NoTrustedSct)`
/// regardless of input. See the crate-level documentation.
///
/// # Limitations
///
/// Not yet implemented (tracked for v0.2). Returns [`Error::NoTrustedSct`]
/// until SCT parsing, log-list lookup, and Merkle proof verification are
/// implemented.
#[deprecated = "pkix-ct is not yet implemented; this function always returns NoTrustedSct"]
pub fn verify_scts(_cert: &Certificate, _logs: &CtLogList) -> Result<()> {
    Err(Error::NoTrustedSct)
}
