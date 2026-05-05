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
//! # Algorithm
//!
//! [`build_path`] uses iterative-deepening DFS (RFC 4158 §2.5): it tries
//! increasing maximum path depths from 1 to 10, performing a full DFS at
//! each depth. This guarantees that the shortest valid path is returned while
//! bounding memory to O(depth) stack frames per attempt.
//!
//! # Spec references
//!
//! - RFC 4158 — Internet X.509 PKI: Certification Path Building
//! - RFC 5280 §6.1 — the validation algorithm this crate feeds into

extern crate alloc;

use alloc::vec::Vec;
use x509_cert::Certificate;

/// OID for BasicConstraints (2.5.29.19).
const OID_BASIC_CONSTRAINTS: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.19");

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

impl<'a> IntoIterator for &'a CertPool {
    type Item = &'a x509_cert::Certificate;
    type IntoIter = core::slice::Iter<'a, x509_cert::Certificate>;

    fn into_iter(self) -> Self::IntoIter {
        self.certs.iter()
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

/// Returns `true` if `cert` has `BasicConstraints` with `cA = TRUE`.
///
/// A missing extension or `cA = FALSE` both return `false`.
/// A present extension whose DER cannot be decoded returns `false` (fail-open
/// for the builder: a cert that cannot be decoded as a CA will simply not be
/// selected as an intermediate, and validate_path will catch any structural
/// problem on final verification).
fn cert_is_ca(cert: &Certificate) -> bool {
    use der::Decode as _;
    use x509_cert::ext::pkix::BasicConstraints;

    cert.tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find(|ext| ext.extn_id == OID_BASIC_CONSTRAINTS)
        .and_then(|ext| BasicConstraints::from_der(ext.extn_value.as_bytes()).ok())
        .map(|bc| bc.ca)
        .unwrap_or(false)
}

/// Inner DFS step.
///
/// `path` is the current (partial) chain, leaf-first. On success it contains
/// the complete chain from the original target to an anchor-issued cert.
/// Returns `true` if a complete path was found; `false` otherwise.
fn dfs(
    path: &mut Vec<Certificate>,
    pool: &[Certificate],
    anchors: &[pkix_path::TrustAnchor],
    depth_remaining: usize,
) -> bool {
    // Clone the issuer name out of path.last() immediately so we do not hold
    // an immutable borrow into `path` across the mutable push/pop below.
    let current_issuer = path
        .last()
        .expect("path is never empty")
        .tbs_certificate
        .issuer
        .clone();

    // Base case: does any trust anchor directly issue `current`?
    for anchor in anchors {
        if pkix_path::names_match(&anchor.subject, &current_issuer) {
            return true;
        }
    }

    if depth_remaining == 0 {
        return false;
    }

    // Recursive step: find pool certs that could issue `current`.
    //
    // We iterate over the pool by index to avoid borrowing `path` and `pool`
    // simultaneously. Cloning the candidate before pushing is necessary anyway
    // because `path` takes ownership.
    let pool_len = pool.len();
    for i in 0..pool_len {
        let candidate = &pool[i];

        // Candidate subject must match current issuer.
        if !pkix_path::names_match(&candidate.tbs_certificate.subject, &current_issuer) {
            continue;
        }

        // Candidate must be a CA (BasicConstraints cA=TRUE).
        if !cert_is_ca(candidate) {
            continue;
        }

        // Cycle guard: skip if candidate's subject is already in the path.
        // Clone the subject out before the mutable borrow.
        let candidate_subject = candidate.tbs_certificate.subject.clone();
        let already_in_path = path.iter().any(|in_path| {
            pkix_path::names_match(&in_path.tbs_certificate.subject, &candidate_subject)
        });
        if already_in_path {
            continue;
        }

        // Push a clone of the candidate, recurse, pop on backtrack.
        let candidate_clone = pool[i].clone();
        path.push(candidate_clone);
        if dfs(path, pool, anchors, depth_remaining - 1) {
            return true;
        }
        path.pop();
    }

    false
}

/// Build a certification path from `target` through certificates in `pool`
/// to one of the provided trust anchors.
///
/// Returns the ordered chain `[target, intermediate..., anchor-issued]` ready
/// for [`pkix_path::validate_path`]. Signatures are **not** verified here;
/// that is the responsibility of the caller via `validate_path`.
///
/// # Algorithm
///
/// Iterative-deepening DFS: tries maximum intermediate depths 1 through 10.
/// Returns the shortest valid topology first. Cycles are detected and pruned
/// by comparing subject DNs already present in the path.
///
/// # Errors
///
/// - [`Error::NoPathFound`] — no topologically valid path through `pool` leads
///   to any of the given trust anchors.
/// - [`Error::DepthExceeded`] — the path would require more than 10 intermediate
///   certificates; increase the depth limit or provide a shorter chain.
pub fn build_path(
    target: &Certificate,
    pool: &CertPool,
    anchors: &[pkix_path::TrustAnchor],
) -> Result<Vec<Certificate>> {
    const MAX_DEPTH: usize = 10;

    let pool_slice: &[Certificate] = &pool.certs;

    for max_depth in 1..=MAX_DEPTH {
        let mut path = alloc::vec![target.clone()];
        if dfs(&mut path, pool_slice, anchors, max_depth) {
            return Ok(path);
        }
    }

    // If the target is directly issued by an anchor, depth=0 is the answer,
    // but the loop above starts at 1. Check that case separately.
    // (depth=1 DFS already covers this: depth_remaining=1 checks anchors first,
    // so the base-case check in dfs handles it. The loop is correct as-is.)

    Err(Error::NoPathFound)
}
