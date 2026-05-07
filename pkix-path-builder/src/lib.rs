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
//! [`build_path`] and [`build_path_with_config`] use iterative-deepening DFS
//! (RFC 4158 §2.5): they try increasing maximum path depths from 1 up to
//! [`PathBuilderConfig::max_depth`] (default [`DEFAULT_MAX_DEPTH`] = 10),
//! performing a full DFS at each depth. This guarantees that the shortest
//! valid path is returned while bounding memory to O(depth) stack frames
//! per attempt.
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

/// OID for `BasicConstraints` (2.5.29.19).
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
    pub const fn new() -> Self {
        Self { certs: Vec::new() }
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

    /// Return the pool contents as a slice.
    pub(crate) fn as_slice(&self) -> &[Certificate] {
        &self.certs
    }
}

impl FromIterator<Certificate> for CertPool {
    fn from_iter<I: IntoIterator<Item = Certificate>>(iter: I) -> Self {
        Self {
            certs: iter.into_iter().collect(),
        }
    }
}

impl Extend<Certificate> for CertPool {
    fn extend<I: IntoIterator<Item = Certificate>>(&mut self, iter: I) {
        self.certs.extend(iter);
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
    /// A candidate intermediate's `BasicConstraints` extension was present but
    /// could not be DER-decoded.
    ///
    /// Returning this rather than silently rejecting the candidate avoids the
    /// situation where a malformed-but-topologically-correct intermediate
    /// causes a misleading [`Error::NoPathFound`].
    MalformedIntermediate,
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
            Self::MalformedIntermediate => f.write_str(
                "a candidate intermediate's BasicConstraints extension is present but cannot be decoded",
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Returns `Ok(true)` if `cert` has `BasicConstraints` with `cA = TRUE`,
/// `Ok(false)` if the extension is absent or has `cA = FALSE`, and
/// [`Error::MalformedIntermediate`] if the extension is present but
/// cannot be DER-decoded.
///
/// Propagating decode failure (rather than silently rejecting the cert
/// as not-a-CA) avoids the situation where a topologically-valid path
/// through a malformed-BC intermediate produces a misleading
/// [`Error::NoPathFound`].
fn cert_is_ca(cert: &Certificate) -> Result<bool> {
    use der::Decode as _;
    use x509_cert::ext::pkix::BasicConstraints;

    let Some(ext) = cert
        .tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find(|ext| ext.extn_id == OID_BASIC_CONSTRAINTS)
    else {
        return Ok(false);
    };

    let bc = BasicConstraints::from_der(ext.extn_value.as_bytes())
        .map_err(|_| Error::MalformedIntermediate)?;
    Ok(bc.ca)
}

/// Inner DFS step.
///
/// `path` is the current (partial) chain, leaf-first. On success it contains
/// the complete chain from the original target to an anchor-issued cert.
///
/// Returns:
/// - `Ok(true)`  — complete path found; `path` holds the result.
/// - `Ok(false)` — no path at this depth; `path` is restored to its entry state.
/// - `Err(Error::BudgetExceeded)` — node-visit budget exhausted in this round.
/// - `Err(Error::MalformedIntermediate)` — a candidate intermediate's
///   `BasicConstraints` is present but undecodable.
///
/// `budget` is decremented on every call (one visit = one DFS node). When it
/// reaches zero the function returns [`Error::BudgetExceeded`] without further
/// exploration.
///
/// The invariant `path` is never empty is established by [`build_path`] (which
/// pushes the target before calling `dfs`) and maintained by the push/pop
/// discipline below.
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
    let Some(c) = path.last() else {
        unreachable!("dfs called with empty path — invariant violated");
    };
    let current_issuer = c.tbs_certificate.issuer.clone();

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

        // Candidate must be a CA (BasicConstraints cA=TRUE). A malformed BC
        // is propagated rather than silently rejected — see `cert_is_ca`.
        if !cert_is_ca(candidate)? {
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
        // We do NOT use `==` / `PartialEq` on `SubjectPublicKeyInfoOwned` because
        // `AlgorithmIdentifier::PartialEq` is a full field comparison that includes
        // the optional `parameters` field. For RSA, one cert may encode
        // `AlgorithmIdentifier { oid: rsaEncryption, params: NULL }` while another
        // encodes `AlgorithmIdentifier { oid: rsaEncryption, params: absent }`.
        // Both represent the same public key but compare as unequal under `PartialEq`,
        // which would allow the cycle guard to miss a loop between such encoding variants.
        // Instead we compare only the algorithm OID and the raw key bit-string, which
        // is the same approach used by `pkix_path::spki_key_matches`.
        let candidate_spki = &candidate.tbs_certificate.subject_public_key_info;
        let already_in_path = path.iter().any(|in_path| {
            let s = &in_path.tbs_certificate.subject_public_key_info;
            s.algorithm.oid == candidate_spki.algorithm.oid
                && s.subject_public_key == candidate_spki.subject_public_key
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

/// Default DFS node-visit budget for a single iterative-deepening round.
///
/// Sufficient for legitimate chains (real-world PKI hierarchies have at most
/// a handful of intermediates and small pools); prevents exponential blow-up
/// against adversarially constructed pools of O(N) CA certificates with
/// identical subject/issuer names.
pub const DEFAULT_DFS_BUDGET: usize = 10_000;

/// Default maximum number of intermediate certificates considered.
pub const DEFAULT_MAX_DEPTH: usize = 10;

/// Tunable parameters for path building.
///
/// Use [`PathBuilderConfig::default`] (or [`PathBuilderConfig::new`]) for the
/// production defaults. Embedded callers, callers with restricted compute,
/// and callers handling adversarial pools can tighten these values.
///
/// # Stability
///
/// Constructed via [`PathBuilderConfig::new`] / `Default`; the struct is
/// `#[non_exhaustive]` so additional knobs can be added without breaking
/// existing callers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub struct PathBuilderConfig {
    /// Maximum number of intermediates to explore. The depth probe runs at
    /// `max_depth + 1` to distinguish "no path exists" from "path exists
    /// but too deep". Default: [`DEFAULT_MAX_DEPTH`].
    pub max_depth: usize,
    /// Per-round node-visit budget. Default: [`DEFAULT_DFS_BUDGET`].
    pub dfs_budget: usize,
}

impl PathBuilderConfig {
    /// Construct a config with all knobs set to their default values.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DEPTH,
            dfs_budget: DEFAULT_DFS_BUDGET,
        }
    }
}

impl Default for PathBuilderConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a certification path from `target` through certificates in `pool`
/// to one of the provided trust anchors.
///
/// Returns the ordered chain `[target, intermediate..., anchor-issued]` ready
/// for [`pkix_path::validate_path`]. Signatures are **not** verified here;
/// that is the responsibility of the caller via [`pkix_path::validate_path`].
///
/// # Algorithm
///
/// Iterative-deepening DFS: tries maximum intermediate depths 1 through 10.
/// Returns the shortest valid topology first. Cycles are detected and pruned
/// by comparing each candidate's `SubjectPublicKeyInfo` algorithm OID and raw
/// public-key bits against certificates already in the path. Algorithm
/// parameters are deliberately excluded from the comparison to tolerate the
/// RFC 8017 ambiguity between absent and explicit-NULL `parameters` in
/// rsaEncryption SPKIs (see the inline comment at the cycle-detection site
/// for rationale).
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
/// Cycle detection is based on `SubjectPublicKeyInfo` algorithm OID + raw
/// public-key bits (parameters intentionally excluded — see Algorithm above)
/// rather than subject DN. Two certificates with the same subject DN but
/// different public keys (e.g., during a key rollover or in a bridge CA
/// topology) are treated as distinct nodes and will not incorrectly prune
/// valid paths.
///
/// **Anchor matching is by DN only.** When a candidate's issuer DN matches
/// any anchor in `anchors`, path building terminates immediately with that
/// chain — the anchor's `SubjectPublicKeyInfo` is **not** verified against
/// what the chain expects. In a key-rollover scenario where two anchors
/// share a subject DN but hold different keys, this builder may return a
/// chain whose top cert was actually signed by a different anchor than the
/// one it is paired with for downstream validation. The downstream caller
/// ([`pkix_path::validate_path`]) iterates all DN-matching anchors and
/// returns success if any of them verify the signature, so correctness is
/// preserved end-to-end. The caller-visible effect is a less informative
/// error in genuinely unverifiable cases (`SignatureInvalid` from
/// `validate_path` rather than `NoPathFound` here).
///
/// # Security
///
/// Pool contents should be from a trusted source. `DFS_BUDGET` enforces a hard
/// cap on search work per round to prevent denial-of-service via oversized or
/// crafted pools.
pub fn build_path(
    target: &Certificate,
    pool: &CertPool,
    anchors: &[pkix_path::TrustAnchor],
) -> Result<Vec<Certificate>> {
    build_path_with_config(target, pool, anchors, &PathBuilderConfig::new())
}

/// Build a certification path with caller-provided budget and depth tunables.
///
/// Behaves identically to [`build_path`] but uses the limits in `config`
/// instead of the workspace defaults. See [`PathBuilderConfig`] for the
/// individual knobs.
///
/// # Errors
///
/// Same as [`build_path`].
pub fn build_path_with_config(
    target: &Certificate,
    pool: &CertPool,
    anchors: &[pkix_path::TrustAnchor],
    config: &PathBuilderConfig,
) -> Result<Vec<Certificate>> {
    let pool_slice = pool.as_slice();

    // Track whether any round was terminated by the budget (not by exhausting
    // all candidates). If every round hits the budget limit, the pool is
    // adversarially large and we return BudgetExceeded; otherwise NoPathFound.
    let mut any_round_budget_exceeded = false;

    for max_depth in 1..=config.max_depth {
        // Reset budget at the start of each round so that earlier rounds
        // (which re-traverse the same shallower nodes) do not exhaust the
        // budget before deeper rounds get a chance to run.
        let mut budget = config.dfs_budget;
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

    // No round hit the budget, but no path found within max_depth.
    // Check if a path exists at max_depth+1 to distinguish "no path exists
    // at all" from "path exists but too deep". The probe uses its own fresh
    // budget so it is not affected by prior rounds.
    //
    // Note: if the probe itself returns BudgetExceeded (pool is adversarially
    // large at max_depth+1), the `?` propagates it to the caller. This is a
    // second, independent path to BudgetExceeded that does not use the
    // any_round_budget_exceeded flag — both paths produce the same observable
    // result (Err(BudgetExceeded)), but via different code paths.
    let mut probe_budget = config.dfs_budget;
    let mut probe = alloc::vec![target.clone()];
    if dfs(
        &mut probe,
        pool_slice,
        anchors,
        config.max_depth + 1,
        &mut probe_budget,
    )? {
        return Err(Error::DepthExceeded);
    }

    Err(Error::NoPathFound)
}
