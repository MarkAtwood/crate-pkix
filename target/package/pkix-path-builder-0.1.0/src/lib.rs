#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! RFC 4158 certification path building for [`pkix_path`].
//!
//! Accepts an unordered collection of certificates ([`CertPool`]) and
//! constructs a valid ordered chain suitable for [`pkix_path::validate_path`].
//!
//! # Relationship to `pkix-path`
//!
//! `pkix-path` validates a caller-ordered `&[Certificate]`. This crate
//! handles the prior step: discovering and ordering that chain from a bag
//! of certificates when the caller does not know the chain order in advance.
//! Cross-certificates and bridge CA topologies are handled here, not in
//! `pkix-path`.
//!
//! # Spec references
//!
//! - RFC 4158 — Internet X.509 PKI: Certification Path Building
//! - RFC 5280 §6.1 — the validation algorithm this crate feeds into
//!
//! # Limitations
//!
//! Not yet implemented. See PKIX-y2j.

extern crate alloc;

use alloc::vec::Vec;
use x509_cert::Certificate;

/// An unordered collection of certificates used as input to path building.
///
/// Certificates are stored by DER bytes and decoded on demand. Add all
/// candidate intermediate certificates here; the path builder will select
/// and order the subset that forms a valid path to a trust anchor.
#[derive(Debug, Default)]
pub struct CertPool {
    certs: Vec<Certificate>,
}

impl CertPool {
    /// Create an empty pool.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a certificate to the pool.
    pub fn add(&mut self, cert: Certificate) {
        self.certs.push(cert);
    }

    /// Return the number of certificates in the pool.
    pub fn len(&self) -> usize {
        self.certs.len()
    }

    /// Return `true` if the pool contains no certificates.
    pub fn is_empty(&self) -> bool {
        self.certs.is_empty()
    }
}

/// Errors returned by path building.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// No valid path from the target certificate to any trust anchor was found.
    NoPathFound,
    /// Path building exceeded the configured maximum candidate depth.
    DepthExceeded,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::NoPathFound => f.write_str("no certification path found to a trust anchor"),
            Error::DepthExceeded => f.write_str("path building exceeded maximum candidate depth"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Build a certification path from `target` through certificates in `pool`
/// to one of the provided trust anchors.
///
/// Returns the ordered chain `[target, intermediate..., issuer]` ready for
/// [`pkix_path::validate_path`].
///
/// # Errors
///
/// Returns [`Error::NoPathFound`] if no valid path exists in `pool`.
///
/// # Limitations
///
/// Not yet implemented (PKIX-y2j).
pub fn build_path(
    _target: &Certificate,
    _pool: &CertPool,
    _anchors: &[pkix_path::TrustAnchor],
) -> Result<Vec<Certificate>> {
    Err(Error::NoPathFound)
}
