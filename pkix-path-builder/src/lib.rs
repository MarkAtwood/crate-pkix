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
//!
//! # `no_std`
//!
//! This crate is `no_std` but requires the `alloc` crate. The `extern crate alloc`
//! declaration is provided automatically; you do not need to add it yourself, but
//! your target must supply a global allocator (e.g., `#[global_allocator]`).

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
///
/// Note: `Hash` is not derived because `x509_cert::Certificate` does not
/// currently implement `Hash` (upstream limitation); `CertPool` cannot be
/// used as a hash-map key until that changes.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CertPool {
    certs: Vec<Certificate>,
}

impl CertPool {
    /// Create an empty pool.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a certificate to the pool.
    pub fn add(&mut self, cert: Certificate) {
        self.certs.push(cert);
    }

    /// Return the number of certificates in the pool.
    #[must_use]
    pub fn len(&self) -> usize {
        self.certs.len()
    }

    /// Return `true` if the pool contains no certificates.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.certs.is_empty()
    }

    /// Iterate over the certificates in the pool.
    ///
    /// Equivalent to `(&pool).into_iter()`.
    pub fn iter(&self) -> core::slice::Iter<'_, x509_cert::Certificate> {
        self.certs.iter()
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// No valid path from the target certificate to any trust anchor was found.
    NoPathFound,
    /// A topologically valid path exists but requires more than the configured
    /// maximum number of intermediates. Try increasing `max_depth` in the call
    /// to [`build_path`].
    DepthExceeded,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoPathFound => f.write_str("no certification path found to a trust anchor"),
            Self::DepthExceeded => f.write_str(
                "no certification path found within depth limit (try increasing max_depth)",
            ),
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
        .is_some_and(|bc| bc.ca)
}

/// Return the DER encoding of a SubjectPublicKeyInfo as a byte vector.
///
/// Used for SPKI-fingerprint-based cycle detection: two certificates are the
/// same node in the path graph if and only if they have byte-identical SPKIs.
/// Inner DFS step.
///
/// `path` is the current (partial) chain, leaf-first. On success it contains
/// the complete chain from the original target to an anchor-issued cert.
/// Returns `true` if a complete path was found; `false` otherwise.
///
/// The invariant `path` is never empty is established by `build_path` (which
/// pushes the target before calling `dfs`) and maintained by the push/pop
/// discipline below. `debug_assert` catches violations in test builds without
/// panicking in release builds.
fn dfs(
    path: &mut Vec<Certificate>,
    pool: &[Certificate],
    anchors: &[pkix_path::TrustAnchor],
    depth_remaining: usize,
) -> bool {
    // Extract the issuer DN by cloning so the immutable borrow on `path` is
    // released before the mutable push/pop below.
    let current_issuer = match path.last() {
        Some(c) => c.tbs_certificate.issuer.clone(),
        None => {
            // Invariant violated: path must never be empty when dfs is called.
            debug_assert!(false, "dfs called with empty path — invariant violated");
            return false;
        }
    };

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
    for candidate in pool {
        // Candidate subject must match current issuer.
        if !pkix_path::names_match(&candidate.tbs_certificate.subject, &current_issuer) {
            continue;
        }

        // Candidate must be a CA (BasicConstraints cA=TRUE).
        if !cert_is_ca(candidate) {
            continue;
        }

        // Cycle guard: skip if candidate's SPKI is already in the path.
        //
        // We compare SubjectPublicKeyInfo by value (not subject DNs) because:
        // - Multiple certificates may share a subject DN (key rollover, bridge CA).
        //   DN-based cycle detection would incorrectly prune valid paths in those
        //   topologies.
        // - SPKI uniquely identifies the signing key: two certs with the same DN
        //   but different keys have different SPKIs and are distinct nodes in the
        //   path graph.
        //
        // SubjectPublicKeyInfoOwned derives PartialEq, so no DER re-encoding is
        // needed — the comparison is a direct field-by-field equality check.
        let candidate_spki = &candidate.tbs_certificate.subject_public_key_info;
        let already_in_path = path.iter().any(|in_path| {
            &in_path.tbs_certificate.subject_public_key_info == candidate_spki
        });
        if already_in_path {
            continue;
        }

        // Push a clone of the candidate, recurse, pop on backtrack.
        // Single clone per push (no separate subject clone needed, since
        // current_issuer was extracted once at the top of this frame).
        path.push(candidate.clone());
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
/// by comparing SubjectPublicKeyInfo DER bytes of certificates already in the path.
///
/// # Errors
///
/// - [`Error::NoPathFound`] — no topologically valid path through `pool` leads
///   to any of the given trust anchors.
/// - [`Error::DepthExceeded`] — a path exists topologically but requires more
///   than 10 intermediate certificates; increase the depth limit or provide a
///   shorter chain.
///
/// # Limitations
///
/// Cycle detection is based on SubjectPublicKeyInfo DER identity rather than
/// subject DN. Two certificates with the same subject DN but different public
/// keys (e.g., during a key rollover or in a bridge CA topology) are treated
/// as distinct nodes and will not incorrectly prune valid paths.
///
/// # Security
///
/// The DFS path builder has worst-case exponential complexity in the pool size.
/// Do not populate the certificate pool from untrusted input without prior size
/// limits. A future version will add a configurable budget cap.
#[must_use = "path building result must be checked"]
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

    // No path found within MAX_DEPTH. Check if a path exists at MAX_DEPTH+1
    // to distinguish "no path exists at all" from "path exists but too deep".
    let mut probe = alloc::vec![target.clone()];
    if dfs(&mut probe, pool_slice, anchors, MAX_DEPTH + 1) {
        return Err(Error::DepthExceeded);
    }

    Err(Error::NoPathFound)
}
