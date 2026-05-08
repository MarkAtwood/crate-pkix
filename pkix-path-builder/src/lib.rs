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
use der::Decode as _;
use x509_cert::Certificate;

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
    /// the configured maximum (see [`PathBuilderConfig::max_depth`], default
    /// [`DEFAULT_MAX_DEPTH`]).
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
                "configured maximum intermediate chain depth exceeded; the chain may require a deeper path than this builder is configured to attempt",
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
///
/// Thin wrapper over [`pkix_path::cert_is_ca`] that maps the opaque
/// [`pkix_path::DerError`] to this crate's [`Error::MalformedIntermediate`].
fn cert_is_ca(cert: &Certificate) -> Result<bool> {
    pkix_path::cert_is_ca(cert).map_err(|_| Error::MalformedIntermediate)
}

/// OID `id-ce-authorityKeyIdentifier` (RFC 5280 §4.2.1.1).
const OID_AUTHORITY_KEY_IDENTIFIER: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.35");

/// OID `id-ce-subjectKeyIdentifier` (RFC 5280 §4.2.1.2).
const OID_SUBJECT_KEY_IDENTIFIER: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.14");

/// Return the bytes of `cert`'s `AuthorityKeyIdentifier::keyIdentifier`
/// extension, or `None` if the extension is absent, the `keyIdentifier`
/// field is absent, or the extension cannot be DER-decoded.
///
/// **Fail-soft semantics**: a malformed AKI is treated as if absent rather
/// than propagated as an error. The AKI keyIdentifier is used purely as
/// an *ordering heuristic* for candidate selection; it is not a security
/// gate (the actual signature check happens downstream in
/// [`pkix_path::validate_path`]). A malformed AKI on the target should
/// degrade builder selection to DN-only ranking, not abort path building.
///
/// RFC 5280 §4.2.1.1: AKI's `keyIdentifier` is normally the SHA-1 hash of
/// the issuer's `subjectPublicKey` BIT STRING (method 1). This is compared
/// byte-for-byte against candidate certs' `SubjectKeyIdentifier`; we do
/// not recompute hashes here — only opaque-byte equality matters.
fn cert_aki_key_id(cert: &Certificate) -> Option<Vec<u8>> {
    use x509_cert::ext::pkix::AuthorityKeyIdentifier;

    let extns = cert.tbs_certificate.extensions.as_deref()?;
    let extn = extns
        .iter()
        .find(|e| e.extn_id == OID_AUTHORITY_KEY_IDENTIFIER)?;
    let aki = AuthorityKeyIdentifier::from_der(extn.extn_value.as_bytes()).ok()?;
    aki.key_identifier.map(|oct| oct.as_bytes().to_vec())
}

/// Return the bytes of `cert`'s `SubjectKeyIdentifier` extension, or
/// `None` if the extension is absent or cannot be DER-decoded.
///
/// **Fail-soft semantics**: see [`cert_aki_key_id`] for rationale. A cert
/// without a parseable SKI ranks below SKI-bearing candidates in the
/// AKI-matching tier but is still considered for the DN-only fallback
/// tier.
///
/// RFC 5280 §4.2.1.2: SKI is conventionally the SHA-1 hash of the cert's
/// own `subjectPublicKey` BIT STRING; we do not recompute, we only return
/// the bytes the cert claims.
fn cert_ski_key_id(cert: &Certificate) -> Option<Vec<u8>> {
    use x509_cert::ext::pkix::SubjectKeyIdentifier;

    let extns = cert.tbs_certificate.extensions.as_deref()?;
    let extn = extns
        .iter()
        .find(|e| e.extn_id == OID_SUBJECT_KEY_IDENTIFIER)?;
    let ski = SubjectKeyIdentifier::from_der(extn.extn_value.as_bytes()).ok()?;
    Some(ski.0.as_bytes().to_vec())
}

/// Compute the DN-matching candidates of `cur` from `pool`, ordered by
/// AKI/SKI matching tier (RFC 5280 §4.2.1.1, RFC 4158 §3.2).
///
/// Returns a vector of `(tier, pool_index)` pairs:
///
/// - **Tier 0**: candidate's `SubjectKeyIdentifier` matches `cur`'s
///   `AuthorityKeyIdentifier.keyIdentifier`. This is the §4.2.1.1 method-1
///   disambiguator: in bridge-CA and key-rollover topologies, multiple CA
///   certs share an issuer DN; AKI/SKI is the only deterministic way to
///   pick the cert that actually signed `cur`.
/// - **Tier 1**: any DN-matching candidate. Used when `cur` has no AKI,
///   no candidate SKI matches, or AKI/SKI parsing failed (fail-soft — see
///   [`cert_aki_key_id`]/[`cert_ski_key_id`]).
///
/// The result is sorted **stably** by tier so candidates within the same
/// tier preserve pool insertion order. This is the documented contract for
/// the no-AKI-signal case.
///
/// **Not currently used:** the AKI `authorityCertIssuer` /
/// `authorityCertSerialNumber` fields. They are rare in practice and
/// parsing `GeneralNames` for that signal is more work than the marginal
/// disambiguation benefit justifies. Documented as a deferred enhancement.
fn rank_candidates(cur: &Certificate, pool: &[Certificate]) -> Vec<(u8, usize)> {
    let cur_issuer = &cur.tbs_certificate.issuer;
    let target_aki_kid = cert_aki_key_id(cur);
    let mut ranked: Vec<(u8, usize)> = Vec::with_capacity(pool.len());
    for (idx, candidate) in pool.iter().enumerate() {
        if !pkix_path::names_match(&candidate.tbs_certificate.subject, cur_issuer) {
            continue;
        }
        let tier: u8 = match (
            target_aki_kid.as_deref(),
            cert_ski_key_id(candidate).as_deref(),
        ) {
            (Some(aki), Some(ski)) if aki == ski => 0,
            _ => 1,
        };
        ranked.push((tier, idx));
    }
    ranked.sort_by_key(|&(tier, _)| tier);
    ranked
}

/// SPKI-based cycle detection: does `path` already contain a cert with the
/// same `SubjectPublicKeyInfo` algorithm OID and raw public-key bits as
/// `candidate`?
///
/// Algorithm parameters are deliberately excluded from the comparison to
/// tolerate the RFC 8017 ambiguity between absent and explicit-NULL
/// `parameters` in rsaEncryption SPKIs (one cert may encode
/// `AlgorithmIdentifier { oid: rsaEncryption, params: NULL }` while another
/// encodes the same key with `params: absent`; both represent the same
/// public key). DN-based cycle detection is intentionally NOT used: in
/// key-rollover or bridge-CA topologies multiple certs may share a subject
/// DN with different keys, and treating them as the same node would
/// incorrectly prune valid paths.
fn spki_already_in_path(candidate: &Certificate, path: &[Certificate]) -> bool {
    let candidate_spki = &candidate.tbs_certificate.subject_public_key_info;
    path.iter().any(|in_path| {
        let s = &in_path.tbs_certificate.subject_public_key_info;
        s.algorithm.oid == candidate_spki.algorithm.oid
            && s.subject_public_key == candidate_spki.subject_public_key
    })
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

// =========================================================================
// PathCandidates iterator (PKIX-mszo)
// =========================================================================

/// Per-frame DFS state held by [`PathCandidates`].
///
/// Each [`Frame`] mirrors one stack frame of the recursive DFS: it holds
/// the AKI-ranked candidate list for the cert at this depth and a cursor
/// into that list, plus state-machine flags so a paused-and-resumed DFS
/// can pick up where it left off without re-running the anchor check or
/// re-yielding the same chain twice.
struct Frame {
    /// Pre-ranked candidate indices (tier, pool index). Stable-sorted
    /// by tier, lower-tier first. Computed lazily on first use so that
    /// frames that yield via anchor match never pay the ranking cost.
    ranked: Option<Vec<(u8, usize)>>,
    /// Position in `ranked` to try next.
    cursor: usize,
    /// True after the anchor-match check has run for this frame.
    anchor_checked: bool,
    /// True if this frame yielded a chain via anchor match. On the next
    /// `next()` call, that frame is immediately backtracked rather than
    /// trying its candidates (the recursive DFS short-circuits on anchor
    /// match; the iterator preserves that semantic).
    anchor_yielded: bool,
}

impl Frame {
    const fn new() -> Self {
        Self {
            ranked: None,
            cursor: 0,
            anchor_checked: false,
            anchor_yielded: false,
        }
    }
}

/// Iterator over topologically-valid certification paths from a target
/// cert through a candidate pool to one of a set of trust anchors.
///
/// Each [`Iterator::next`] call returns either:
/// - `Some(Ok(chain))` — the next leaf-first chain `[target, ...,
///   anchor-issued]` that is topologically valid (DN chain links,
///   `BasicConstraints cA=TRUE` on every intermediate, no SPKI cycles).
///   Signatures are NOT verified; downstream callers must run the
///   returned chain through [`pkix_path::validate_path`].
/// - `Some(Err(e))` — a fatal error (see [`Error`]). The iterator is
///   exhausted; subsequent calls return `None`.
/// - `None` — DFS has been exhausted; no more chains exist within the
///   configured `max_depth`.
///
/// **Resumable DFS**: candidates are explored in [AKI-ranked
/// order](rank_candidates); when a chain is yielded, the next call
/// resumes from the same DFS state and explores alternate paths. This
/// is the contract S/MIME callers depend on for build-then-validate
/// retry loops in adversarial pools (CMS bags, federal-bridge cross-cert
/// topologies, etc.) where the topologically-first chain may not be the
/// cryptographically-verifying one.
///
/// **Bounded enumeration**: a single shared budget (initial value
/// [`PathBuilderConfig::dfs_budget`]) is decremented once per DFS frame
/// entry across all `next()` calls. When the budget is exhausted, the
/// next call returns `Some(Err(`[`Error::BudgetExceeded`]`))` and the
/// iterator becomes exhausted. This bounds worst-case work to
/// `O(dfs_budget)` total across the entire iterator's lifetime,
/// preventing an adversarial pool from causing unbounded enumeration.
///
/// **No iterative deepening**: unlike legacy `build_path`, this iterator
/// performs a single DFS at `max_depth`. Paths are yielded in DFS order
/// (depth-first, AKI-tier-ordered, then pool insertion order within a
/// tier). Shortest-first is no longer guaranteed; for typical pools the
/// first yielded chain is still the shortest, but adversarial pools can
/// produce a deeper chain first if its branch is explored before a
/// shallower alternative.
///
/// # Examples
///
/// Build-then-validate retry loop:
///
/// ```ignore
/// let mut candidates = pkix_path_builder::build_path_candidates(
///     &target, &pool, &anchors,
/// );
/// loop {
///     match candidates.next() {
///         None => break Err(NoVerifiableChain),
///         Some(Err(e)) => break Err(e.into()),
///         Some(Ok(chain)) => match pkix_path::validate_path(
///             &chain, &anchors, &policy, &verifier,
///         ) {
///             Ok(vp) => break Ok(vp),
///             Err(_) => continue,  // try next candidate
///         },
///     }
/// }
/// ```
pub struct PathCandidates<'a> {
    pool: &'a [Certificate],
    anchors: &'a [pkix_path::TrustAnchor],
    max_depth: usize,
    /// Current chain, leaf-first. `path[0]` is the target.
    path: Vec<Certificate>,
    /// Frame stack; `frames.len() == path.len()` while the iterator is
    /// active. When both are empty after `started` was true, the
    /// iterator is exhausted.
    frames: Vec<Frame>,
    /// Shared DFS-frame-entry budget. Decremented once per anchor check
    /// (one charge per frame entered). Bounded by the configured budget
    /// across all `next()` calls.
    budget: usize,
    /// True after the first `next()` call. Used to lazily push the
    /// initial frame.
    started: bool,
    /// True once the iterator has yielded a fatal error or exhausted
    /// the search space; subsequent calls return `None`.
    done: bool,
}

impl<'a> PathCandidates<'a> {
    /// Construct a new path-candidate iterator.
    ///
    /// The `target`, `pool`, and `anchors` references are borrowed for
    /// the lifetime of the iterator; `config` is read once at construction
    /// (its `max_depth` and `dfs_budget` values are copied in).
    fn new(
        target: &Certificate,
        pool: &'a [Certificate],
        anchors: &'a [pkix_path::TrustAnchor],
        config: &PathBuilderConfig,
    ) -> Self {
        // Pre-seed `path` with the target and `frames` with the initial
        // frame. This avoids an extra branch in `next()` for the
        // first-call case and keeps the invariant `path.len() ==
        // frames.len()` true at all times when the iterator is active.
        let path = alloc::vec![target.clone()];
        let frames = alloc::vec![Frame::new()];
        Self {
            pool,
            anchors,
            max_depth: config.max_depth,
            path,
            frames,
            budget: config.dfs_budget,
            started: false,
            done: false,
        }
    }
}

impl<'a> Iterator for PathCandidates<'a> {
    type Item = Result<Vec<Certificate>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        // The first call to `next()` finds the first chain (or exhausts
        // the search). `started` lets us distinguish "iterator just
        // constructed" (path/frames pre-seeded with the initial target
        // frame) from "iterator was previously called and yielded a
        // chain" (resume from the yielded frame).
        //
        // When resuming after a yield, the top frame's `anchor_yielded`
        // flag is true; the loop below will see this and immediately
        // backtrack from that frame, advancing the parent's candidate
        // cursor on the next iteration.
        self.started = true;

        loop {
            // Empty stack: search space exhausted.
            if self.frames.is_empty() {
                self.done = true;
                return None;
            }

            // If the top frame already yielded an anchor match on a
            // prior call, backtrack from it now (the recursive DFS
            // short-circuits on anchor match without exploring
            // candidates; the iterator preserves that semantic).
            if self.frames.last().expect("non-empty").anchor_yielded {
                self.frames.pop();
                self.path.pop();
                continue;
            }

            // Anchor check: each frame charges 1 unit of budget at this
            // point (mirrors the recursive DFS's per-call decrement).
            // Budget exhaustion makes the iterator terminal.
            if !self.frames.last().expect("non-empty").anchor_checked {
                if self.budget == 0 {
                    self.done = true;
                    return Some(Err(Error::BudgetExceeded));
                }
                self.budget -= 1;
                self.frames
                    .last_mut()
                    .expect("non-empty")
                    .anchor_checked = true;

                // Read the issuer DN of the cert at the top of the path
                // — that is the cert this frame is seeking an issuer
                // for. The path mirrors frames; path.last() corresponds
                // to frames.last() at all times.
                let cur_issuer = &self
                    .path
                    .last()
                    .expect("path mirrors frames; non-empty")
                    .tbs_certificate
                    .issuer;
                let matched = self
                    .anchors
                    .iter()
                    .any(|a| pkix_path::names_match(&a.subject, cur_issuer));
                if matched {
                    self.frames
                        .last_mut()
                        .expect("non-empty")
                        .anchor_yielded = true;
                    return Some(Ok(self.path.clone()));
                }
            }

            // Past the anchor check. If this frame is at or beyond the
            // depth limit, it cannot host any further intermediate
            // candidates — backtrack. The recursive DFS's
            // `if depth_remaining == 0 { return Ok(false); }` clause
            // corresponds to this gate: a frame exists at every depth
            // up to and including `max_depth + 1` (the deepest frame
            // performs anchor check then returns immediately).
            if self.frames.len() > self.max_depth {
                self.frames.pop();
                self.path.pop();
                continue;
            }

            // Compute candidate ranking lazily — only frames that
            // survive the anchor check pay the cost.
            if self.frames.last().expect("non-empty").ranked.is_none() {
                let cur = self.path.last().expect("non-empty");
                let ranked = rank_candidates(cur, self.pool);
                self.frames.last_mut().expect("non-empty").ranked = Some(ranked);
            }

            // Pull the next candidate index, or backtrack if exhausted.
            let frame = self.frames.last_mut().expect("non-empty");
            let ranked = frame.ranked.as_ref().expect("set above");
            if frame.cursor >= ranked.len() {
                // No more candidates: backtrack.
                self.frames.pop();
                self.path.pop();
                continue;
            }
            let (_tier, idx) = ranked[frame.cursor];
            frame.cursor += 1;

            let candidate = &self.pool[idx];

            // CA check (BasicConstraints cA=TRUE). A malformed BC is
            // propagated as an error, mirroring the legacy `dfs`. The
            // iterator becomes terminal after returning an error so the
            // caller does not see further chains.
            //
            // (PKIX-qgw1 will switch this to skip-not-fail; both build
            // paths will move together when that lands.)
            match cert_is_ca(candidate) {
                Err(e) => {
                    self.done = true;
                    return Some(Err(e));
                }
                Ok(false) => continue,
                Ok(true) => {}
            }

            // SPKI cycle guard.
            if spki_already_in_path(candidate, &self.path) {
                continue;
            }

            // Eligible: push the candidate onto path/frames and let the
            // outer loop iterate, processing the new top frame.
            self.path.push(candidate.clone());
            self.frames.push(Frame::new());
        }
    }
}

/// Construct a [`PathCandidates`] iterator using the workspace defaults
/// ([`DEFAULT_MAX_DEPTH`], [`DEFAULT_DFS_BUDGET`]).
///
/// See [`PathCandidates`] for usage and semantics.
#[must_use]
pub fn build_path_candidates<'a>(
    target: &Certificate,
    pool: &'a CertPool,
    anchors: &'a [pkix_path::TrustAnchor],
) -> PathCandidates<'a> {
    PathCandidates::new(target, pool.as_slice(), anchors, &PathBuilderConfig::new())
}

/// Construct a [`PathCandidates`] iterator with caller-provided budget
/// and depth tunables.
///
/// See [`PathCandidates`] for usage and semantics, and
/// [`PathBuilderConfig`] for the individual knobs.
#[must_use]
pub fn build_path_candidates_with_config<'a>(
    target: &Certificate,
    pool: &'a CertPool,
    anchors: &'a [pkix_path::TrustAnchor],
    config: &PathBuilderConfig,
) -> PathCandidates<'a> {
    PathCandidates::new(target, pool.as_slice(), anchors, config)
}

// =========================================================================
// build_path / build_path_with_config — single-shot wrappers
// =========================================================================

/// Build a certification path from `target` through certificates in `pool`
/// to one of the provided trust anchors.
///
/// Returns the ordered chain `[target, intermediate..., anchor-issued]` ready
/// for [`pkix_path::validate_path`]. Signatures are **not** verified here;
/// that is the responsibility of the caller via [`pkix_path::validate_path`].
///
/// # Algorithm
///
/// Single-pass depth-first search at the configured `max_depth`. Candidates
/// at each frame are ordered by AKI/SKI tier (RFC 5280 §4.2.1.1) so
/// disambiguating bridge-CA / cross-cert topologies succeeds on the first
/// candidate when AKI/SKI bindings are well-formed. Cycles are detected by
/// `SubjectPublicKeyInfo` algorithm OID + raw public-key bits; algorithm
/// parameters are excluded so RFC 8017 absent-vs-NULL ambiguity in
/// rsaEncryption SPKIs does not break detection.
///
/// This is a thin wrapper over the [`PathCandidates`] iterator: it returns
/// the iterator's first yield, or invokes a depth+1 probe (with fresh
/// budget) on `None` to distinguish [`Error::NoPathFound`] from
/// [`Error::DepthExceeded`].
///
/// # Errors
///
/// - [`Error::NoPathFound`] — no topologically valid path through `pool` leads
///   to any of the given trust anchors.
/// - [`Error::DepthExceeded`] — a path exists topologically but requires more
///   than [`PathBuilderConfig::max_depth`] intermediate certificates.
/// - [`Error::BudgetExceeded`] — the DFS frame-entry budget was exhausted
///   before a path was found; the pool may be adversarially large or
///   structured to produce exponential search.
///
/// # Choosing between `build_path` and the iterator
///
/// Use this single-shot API when:
/// - the pool is from a trusted source (in-house cert store, configured
///   intermediate bundle), and
/// - finding any topologically valid chain is sufficient (the caller does
///   not need to retry with alternate chains if signature verification
///   fails downstream).
///
/// Use [`build_path_candidates`] (or its `_with_config` sibling) for
/// adversarial pools (CMS `SignedData.certificates` bags, federal-bridge
/// cross-cert topologies, anywhere the wire-order of certs is not under
/// your control) so failed signature verification can be retried against
/// the next candidate path. See [`PathCandidates`] for the build-then-
/// validate retry-loop pattern.
///
/// # Limitations
///
/// **Candidate selection uses AKI/SKI as an ordering heuristic, not a
/// security gate.** When the cert seeking an issuer carries an
/// `AuthorityKeyIdentifier` extension with a `keyIdentifier` field
/// (RFC 5280 §4.2.1.1), pool candidates whose `SubjectKeyIdentifier`
/// (§4.2.1.2) matches are tried before DN-only matches. This is
/// best-effort disambiguation for bridge-CA and key-rollover topologies
/// where multiple CA certs share an issuer DN. The signature itself is
/// **not** verified by this crate — that happens downstream in
/// [`pkix_path::validate_path`]. Consequences:
///
/// - When the AKI heuristic picks the wrong candidate (e.g., AKI is
///   absent or malformed, multiple candidates share the same SKI, or
///   the AKI/SKI binding is wrong), the returned chain may fail
///   `validate_path` with `SignatureInvalid` rather than
///   [`Error::NoPathFound`] here. Callers handling adversarial pools
///   should use [`build_path_candidates`] to retry alternate chains.
/// - Malformed AKI or SKI extensions are treated as if absent (fail-soft).
///   They do not cause path building to abort; they simply degrade
///   selection to DN-only ranking for that cert.
/// - The AKI `authorityCertIssuer` + `authorityCertSerialNumber` fields
///   (the rare alternative to `keyIdentifier`) are not currently used for
///   ranking. Only the `keyIdentifier` field participates.
///
/// **Anchor matching is by DN only.** When a candidate's issuer DN matches
/// any anchor in `anchors`, path building terminates immediately with that
/// chain — the anchor's `SubjectPublicKeyInfo` is **not** verified against
/// what the chain expects.
///
/// **Shortest-first is no longer guaranteed.** Earlier versions of this
/// crate used iterative-deepening DFS to return the shortest topology
/// first. The single-pass DFS used now (which shares state with the
/// `PathCandidates` iterator) yields paths in depth-first order. For
/// typical pools the first yielded chain is still the shortest; for
/// adversarial pools, a deeper chain may be returned first if its branch
/// is explored before a shallower alternative. If shortest-first matters,
/// inspect the returned chain length and (rarely) re-run with a tightened
/// `max_depth`.
///
/// # Security
///
/// Pool contents should be from a trusted source. The DFS frame-entry
/// budget enforces a hard cap on search work to prevent denial-of-service
/// via oversized or crafted pools.
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
/// individual knobs and [`build_path`] for full semantics.
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

    // First pass at the configured max_depth.
    let mut iter = PathCandidates::new(target, pool_slice, anchors, config);
    match iter.next() {
        Some(Ok(chain)) => return Ok(chain),
        Some(Err(e)) => return Err(e),
        None => {}
    }

    // Iterator exhausted at max_depth. Probe at max_depth+1 to distinguish
    // NoPathFound from DepthExceeded. The probe gets a fresh budget (it is
    // a brand-new PathCandidates), matching the legacy iterative-deepening
    // probe's behaviour.
    let probe_config = PathBuilderConfig {
        max_depth: config.max_depth.saturating_add(1),
        dfs_budget: config.dfs_budget,
    };
    let mut probe = PathCandidates::new(target, pool_slice, anchors, &probe_config);
    match probe.next() {
        Some(Ok(_)) => Err(Error::DepthExceeded),
        Some(Err(e)) => Err(e),
        None => Err(Error::NoPathFound),
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the private AKI/SKI extraction helpers.
    //!
    //! Independent oracle: byte values were derived by running
    //! `openssl x509 -text` on the PKITS DER fixtures and pasting the
    //! displayed `Authority Key Identifier` / `Subject Key Identifier`
    //! hex bytes into the test expectations. The helpers are *not* used
    //! to compute the expected values — they are checked against the
    //! external openssl-derived ground truth.
    extern crate std;

    use super::{cert_aki_key_id, cert_ski_key_id};
    use der::Decode as _;
    use std::path::PathBuf;
    use x509_cert::Certificate;

    fn pkits_cert(name: &str) -> Certificate {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../pkix-path/tests/pkits/certs")
            .join(std::format!("{name}.crt"));
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|e| std::panic!("fixture not found at {}: {}", path.display(), e));
        Certificate::from_der(&bytes)
            .unwrap_or_else(|e| std::panic!("failed to parse {name}: {e}"))
    }

    #[test]
    fn cert_aki_key_id_test4ee_matches_oldkey_ski() {
        // Test4EE.AKI.keyIdentifier (per `openssl x509 -text` on the fixture):
        //   DD:0D:75:8D:53:68:12:C4:CB:15:40:C0:14:86:14:16:30:A1:BE:AF
        const EXPECTED: [u8; 20] = [
            0xdd, 0x0d, 0x75, 0x8d, 0x53, 0x68, 0x12, 0xc4, 0xcb, 0x15, 0x40, 0xc0, 0x14, 0x86,
            0x14, 0x16, 0x30, 0xa1, 0xbe, 0xaf,
        ];
        let ee = pkits_cert("ValidBasicSelfIssuedNewWithOldTest4EE");
        let aki = cert_aki_key_id(&ee).expect("Test4EE has an AKI extension");
        assert_eq!(aki.as_slice(), &EXPECTED);
    }

    #[test]
    fn cert_ski_key_id_oldkey_matches_test4ee_aki() {
        // BasicSelfIssuedOldKeyCACert.SKI must equal Test4EE.AKI.keyIdentifier.
        // Same hex bytes as the AKI test above; parsed independently from a
        // different DER file via a different code path.
        const EXPECTED: [u8; 20] = [
            0xdd, 0x0d, 0x75, 0x8d, 0x53, 0x68, 0x12, 0xc4, 0xcb, 0x15, 0x40, 0xc0, 0x14, 0x86,
            0x14, 0x16, 0x30, 0xa1, 0xbe, 0xaf,
        ];
        let oldkey = pkits_cert("BasicSelfIssuedOldKeyCACert");
        let ski = cert_ski_key_id(&oldkey).expect("OldKeyCACert has an SKI extension");
        assert_eq!(ski.as_slice(), &EXPECTED);
    }

    #[test]
    fn cert_ski_key_id_bridge_ca_differs_from_oldkey() {
        // BasicSelfIssuedOldKeyNewWithOldCACert shares a subject DN with
        // OldKeyCACert but has a distinct SPKI and SKI:
        //   88:5F:BE:3F:35:39:66:9A:EB:4D:C2:26:1B:26:B1:2A:27:B5:08:2A
        // This is the disambiguation signal AKI ranking exploits.
        const EXPECTED: [u8; 20] = [
            0x88, 0x5f, 0xbe, 0x3f, 0x35, 0x39, 0x66, 0x9a, 0xeb, 0x4d, 0xc2, 0x26, 0x1b, 0x26,
            0xb1, 0x2a, 0x27, 0xb5, 0x08, 0x2a,
        ];
        let bridge = pkits_cert("BasicSelfIssuedOldKeyNewWithOldCACert");
        let ski = cert_ski_key_id(&bridge).expect("bridge cert has an SKI extension");
        assert_eq!(ski.as_slice(), &EXPECTED);
    }

    #[test]
    fn cert_aki_key_id_returns_none_when_aki_absent() {
        // The PKITS trust anchor cert is self-signed and (per its DER) has
        // NO AuthorityKeyIdentifier extension — only a SubjectKeyIdentifier.
        // The helper must return None, exercising the early-return branch
        // in cert_aki_key_id.
        let anchor = pkits_cert("TrustAnchorRootCertificate");
        assert!(cert_aki_key_id(&anchor).is_none());
    }

    #[test]
    fn cert_ski_key_id_present_on_trust_anchor() {
        // Trust anchor's SKI per `openssl x509 -text`:
        //   E4:7D:5F:D1:5C:95:86:08:2C:05:AE:BE:75:B6:65:A7:D9:5D:A8:66
        // Round-trips the same bytes that downstream certs reference via
        // their AKI.keyIdentifier (AKI/SKI binding cross-check).
        const EXPECTED: [u8; 20] = [
            0xe4, 0x7d, 0x5f, 0xd1, 0x5c, 0x95, 0x86, 0x08, 0x2c, 0x05, 0xae, 0xbe, 0x75, 0xb6,
            0x65, 0xa7, 0xd9, 0x5d, 0xa8, 0x66,
        ];
        let anchor = pkits_cert("TrustAnchorRootCertificate");
        let ski = cert_ski_key_id(&anchor).expect("trust anchor has an SKI");
        assert_eq!(ski.as_slice(), &EXPECTED);
    }
}
