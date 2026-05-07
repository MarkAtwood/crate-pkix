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
///
/// Note: `PartialEq`/`Eq` are not derived. `CertPool` is documented as an
/// unordered bag, so a derived implementation (which compares the internal
/// `Vec` in insertion order) would be semantically wrong.
#[derive(Clone, Debug, Default)]
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
    /// A topologically valid path exists but requires more intermediates than
    /// the maximum depth (10) this builder supports.
    DepthExceeded,
    /// The internal DFS node-visit budget was exhausted in a single round.
    ///
    /// This guards against adversarial certificate pools that would otherwise
    /// cause exponential search time. Each iterative-deepening round and the
    /// depth probe start with a fresh budget of `DFS_BUDGET` node visits.
    BudgetExceeded,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoPathFound => f.write_str("no certification path found to a trust anchor"),
            Self::DepthExceeded => f.write_str(
                "maximum intermediate chain depth (10) exceeded; the chain may require a deeper path than this builder supports",
            ),
            Self::BudgetExceeded => f.write_str(
                "DFS node-visit budget exceeded; pool may be adversarially large",
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

/// Inner DFS step.
///
/// `path` is the current (partial) chain, leaf-first. On success it contains
/// the complete chain from the original target to an anchor-issued cert.
///
/// Returns:
/// - `Ok(true)`  — complete path found; `path` holds the result.
/// - `Ok(false)` — no path at this depth; `path` is restored to its entry state.
/// - `Err(())`   — budget exhausted; propagate up to `build_path` immediately.
///
/// `budget` is decremented on every call (one visit = one DFS node). When it
/// reaches zero the function returns `Err(())` without further exploration.
/// The caller maps this to [`Error::BudgetExceeded`].
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
    budget: &mut usize,
) -> Result<bool> {
    // Count this node visit against the budget.
    if *budget == 0 {
        return Err(Error::BudgetExceeded);
    }
    *budget -= 1;

    // Extract the issuer DN by cloning so the immutable borrow on `path` is
    // released before the mutable push/pop below.
    let current_issuer = match path.last() {
        Some(c) => c.tbs_certificate.issuer.clone(),
        None => {
            // Invariant violated: path must never be empty when dfs is called.
            debug_assert!(false, "dfs called with empty path — invariant violated");
            return Ok(false);
        }
    };

    // Base case: does any trust anchor directly issue `current`?
    for anchor in anchors {
        if pkix_path::names_match(&anchor.subject, &current_issuer) {
            return Ok(true);
        }
    }

    if depth_remaining == 0 {
        return Ok(false);
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
        if dfs(path, pool, anchors, depth_remaining - 1, budget)? {
            return Ok(true);
        }
        path.pop();
    }

    Ok(false)
}

/// DFS node-visit budget for a single iterative-deepening round (or probe).
///
/// Each call to the inner `dfs()` function consumes one unit regardless of
/// whether the node results in a match. When the counter reaches zero,
/// [`build_path`] returns [`Error::BudgetExceeded`].
///
/// The budget is reset to this value at the start of each round of iterative
/// deepening and for the depth-probe at `MAX_DEPTH + 1`. This prevents
/// earlier rounds (which re-traverse all nodes from rounds 1..k-1) from
/// exhausting the budget before depth k is explored.
///
/// 10 000 visits is sufficient for legitimate chains (real-world PKI hierarchies
/// have at most a handful of intermediates and small pools). It prevents
/// exponential blow-up against adversarially constructed pools of O(N) CA
/// certificates with identical subject/issuer names.
const DFS_BUDGET: usize = 10_000;

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
/// Each round and the depth probe get a fresh budget of `DFS_BUDGET` node
/// visits.  Resetting per-round prevents earlier rounds (which re-traverse all
/// nodes from rounds 1..k-1) from consuming budget that round k needs.  The
/// depth probe at `MAX_DEPTH + 1` also starts with a fresh budget.
///
/// If any round exhausts its budget before finding a path, [`Error::BudgetExceeded`]
/// is returned. This bounds worst-case complexity against adversarial inputs.
///
/// # Errors
///
/// - [`Error::NoPathFound`] — no topologically valid path through `pool` leads
///   to any of the given trust anchors.
/// - [`Error::DepthExceeded`] — a path exists topologically but requires more
///   than 10 intermediate certificates; increase the depth limit or provide a
///   shorter chain.
/// - [`Error::BudgetExceeded`] — the DFS node-visit budget was exhausted in
///   some round; the pool may be adversarially large or structured to produce
///   exponential search.
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
/// Pool contents should be from a trusted source. `DFS_BUDGET` enforces a hard
/// cap on search work per round to prevent denial-of-service via oversized or
/// crafted pools.
#[must_use = "path building result must be checked"]
pub fn build_path(
    target: &Certificate,
    pool: &CertPool,
    anchors: &[pkix_path::TrustAnchor],
) -> Result<Vec<Certificate>> {
    const MAX_DEPTH: usize = 10;

    let pool_slice = pool.certs.as_slice();

    // Track whether any round was terminated by the budget (not by exhausting
    // all candidates). If every round hits the budget limit, the pool is
    // adversarially large and we return BudgetExceeded; otherwise NoPathFound.
    let mut any_round_budget_exceeded = false;

    for max_depth in 1..=MAX_DEPTH {
        // Reset budget at the start of each round so that earlier rounds
        // (which re-traverse the same shallower nodes) do not exhaust the
        // budget before deeper rounds get a chance to run.
        let mut budget = DFS_BUDGET;
        let mut path = alloc::vec![target.clone()];
        match dfs(&mut path, pool_slice, anchors, max_depth, &mut budget) {
            Ok(true) => return Ok(path),
            Ok(false) => {}
            Err(Error::BudgetExceeded) => {
                // Budget exhausted at this depth does NOT mean there is no
                // valid path at greater depth. Continue to the next round with
                // a fresh budget rather than surfacing BudgetExceeded immediately.
                any_round_budget_exceeded = true;
            }
            Err(e) => return Err(e),
        }
    }

    if any_round_budget_exceeded {
        return Err(Error::BudgetExceeded);
    }

    // No round hit the budget, but no path found within MAX_DEPTH.
    // Check if a path exists at MAX_DEPTH+1 to distinguish "no path exists
    // at all" from "path exists but too deep". The probe uses its own fresh
    // budget so it is not affected by prior rounds.
    //
    // Note: if the probe itself returns BudgetExceeded (pool is adversarially
    // large at MAX_DEPTH+1), the `?` propagates it to the caller. This is a
    // second, independent path to BudgetExceeded that does not use the
    // any_round_budget_exceeded flag — both paths produce the same observable
    // result (Err(BudgetExceeded)), but via different code paths.
    let mut probe_budget = DFS_BUDGET;
    let mut probe = alloc::vec![target.clone()];
    if dfs(&mut probe, pool_slice, anchors, MAX_DEPTH + 1, &mut probe_budget)? {
        return Err(Error::DepthExceeded);
    }

    Err(Error::NoPathFound)
}
