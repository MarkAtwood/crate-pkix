#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! CA/Browser Forum and RFC certificate profile policies for `pkix-chain`.
//!
//! Provides pre-configured [`ValidationPolicy`][vp] values for common
//! certificate use cases, encoding the additional constraints imposed by
//! the CA/Browser Forum Baseline Requirements beyond RFC 5280.
//!
//! # Profiles
//!
//! | Function | Document | Key constraints |
//! |----------|----------|-----------------|
//! | [`web_pki_policy`] | CA/B Forum TLS BR | 398-day max validity, SAN required, SHA-1 prohibited |
//! | [`smime_policy`] | CA/B Forum S/MIME BR | Email-specific key usage, S/MIME EKU |
//! | [`code_signing_policy`] | CA/B Forum Code Signing BR | Code signing EKU, timestamping |
//! | [`rfc5280_policy`] | RFC 5280 only | No CA/B Forum additions |
//!
//! # Spec references
//!
//! - CA/Browser Forum Baseline Requirements for TLS Server Certificates
//! - CA/Browser Forum S/MIME Baseline Requirements
//! - CA/Browser Forum Code Signing Baseline Requirements
//! - RFC 5280 — Internet X.509 PKI Certificate and CRL Profile
//!
//! # Limitations
//!
//! Not yet implemented. Returned policies are identical to
//! `ValidationPolicy::default()` pending v0.2 work.

pub use pkix_path::ValidationPolicy;

/// Return a [`ValidationPolicy`] conforming to the CA/Browser Forum
/// Baseline Requirements for TLS Server Certificates.
///
/// Key constraints enforced beyond RFC 5280:
/// - Maximum validity period: 398 days
/// - Subject Alternative Name extension required
/// - SHA-1 signatures prohibited
/// - RSA keys must be ≥ 2048 bits
///
/// # Limitations
///
/// Not yet implemented. Calling this function will panic with
/// `unimplemented!`. CA/B Forum TLS constraints (398-day validity cap,
/// SAN requirement, SHA-1 prohibition, RSA ≥ 2048) are not yet enforced.
pub fn web_pki_policy(_now_unix: u64) -> ValidationPolicy {
    unimplemented!("web_pki_policy: CA/B Forum TLS constraints not yet implemented")
}

/// Return a [`ValidationPolicy`] conforming to the CA/Browser Forum
/// S/MIME Baseline Requirements.
///
/// # Limitations
///
/// Not yet implemented. Calling this function will panic with
/// `unimplemented!`.
pub fn smime_policy(_now_unix: u64) -> ValidationPolicy {
    unimplemented!("smime_policy: CA/B Forum S/MIME constraints not yet implemented")
}

/// Return a [`ValidationPolicy`] conforming to the CA/Browser Forum
/// Code Signing Baseline Requirements.
///
/// # Limitations
///
/// Not yet implemented. Calling this function will panic with
/// `unimplemented!`.
pub fn code_signing_policy(_now_unix: u64) -> ValidationPolicy {
    unimplemented!("code_signing_policy: CA/B Forum Code Signing constraints not yet implemented")
}

/// Return a plain RFC 5280 [`ValidationPolicy`] with no CA/Browser Forum additions.
pub fn rfc5280_policy(now_unix: u64) -> ValidationPolicy {
    ValidationPolicy {
        current_time_unix: now_unix,
        ..ValidationPolicy::default()
    }
}
