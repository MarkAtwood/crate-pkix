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
//! [`build_path`] and [`build_path_with_config`] perform a single-pass
//! depth-first search up to [`PathBuilderConfig::max_depth`] (default
//! [`DEFAULT_MAX_DEPTH`] = 10). At each step, candidates are ranked by
//! AKI/SKI match tier (RFC 4158 §3.2) so the most-likely issuer is tried
//! first. Memory is bounded to O(depth) stack frames.
//!
//! Shortest-first is **not** guaranteed: for typical pools the first chain
//! found is the shortest, but adversarial pools may yield a deeper chain
//! first. See [`PathCandidates`] for the full enumeration contract.
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
//!
//! # Limitations
//!
//! - **Caller supplies the candidate set.** [`CertPool`] takes a pool of
//!   already-loaded certificates. This crate does not fetch missing
//!   intermediates from `AuthorityInfoAccess` URIs; the optional
//!   `pkix-aia` / `pkix-aia-http` cascade handles that (tracked under
//!   `PKIX-zkjb`).
//! - **Output feeds `pkix-path`.** The validation algorithm (RFC 5280 §6.1
//!   signature chain walk, name constraints, policy machinery, revocation)
//!   lives in `pkix-path` and `pkix-revocation`. This crate's job ends
//!   when it returns an ordered candidate chain.
//! - **No known residual divergence.** The bettertls path-building corner
//!   case `pathbuilding::tc60`, which this crate used to reject where
//!   other implementations accepted, is resolved: it agrees with all
//!   three oracles in the committed limbo baseline. The fix was
//!   [`build_first_valid_path`], which iterates candidates and validates
//!   each rather than validating one topologically-chosen chain — see
//!   `pkix-difftest/baseline-limbo-analysis.md` and the
//!   `tc60_build_first_valid_path_succeeds_where_build_path_fails`
//!   regression test.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use der::referenced::OwnedToRef as _;
use der::Decode as _;
use x509_cert::spki;
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

impl IntoIterator for CertPool {
    type Item = x509_cert::Certificate;
    type IntoIter = alloc::vec::IntoIter<x509_cert::Certificate>;

    fn into_iter(self) -> Self::IntoIter {
        self.certs.into_iter()
    }
}

/// Errors returned by path building.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Error {
    /// No valid path from the target certificate to any trust anchor was found.
    NoPathFound,
    /// A topologically valid path exists but requires more intermediates than
    /// the configured maximum (see [`PathBuilderConfig::max_depth`], default
    /// [`DEFAULT_MAX_DEPTH`]).
    DepthExceeded,
    /// The internal DFS node-visit budget was exhausted.
    ///
    /// This guards against adversarial certificate pools that would otherwise
    /// cause exponential search time. Each search pass (the DFS, the depth
    /// probe, and `build_first_valid_path`'s topology-only fallback) starts
    /// with a fresh budget of [`PathBuilderConfig::dfs_budget`] units; one
    /// unit is charged per DFS frame entered and per pool candidate
    /// examined.
    BudgetExceeded,
    /// [`build_first_valid_path`] exhausted [`build_path_candidates`] without
    /// finding a candidate that [`pkix_path::validate_path`] accepted.
    ///
    /// At least one topologically valid chain was found by the path builder,
    /// but every chain was rejected by the verifier or the validation policy
    /// (e.g., mixed-signature-algorithm cross-signed pools where the DFS
    /// candidate order picks an algorithm the [`SignatureVerifier`] does not
    /// dispatch; cross-cert chains where one issuer is expired at the
    /// validation time; etc.).
    ///
    /// `tried` is the count of candidate chains rejected; it is always
    /// `>= 1` for this variant (zero-yield exhaustion is reported as
    /// [`Error::NoPathFound`] instead, matching [`build_path`]'s contract).
    ///
    /// `last_error` is the [`pkix_path::Error::Display`] rendering of the
    /// last candidate's validation failure. It is carried as a `String`
    /// rather than a `pkix_path::Error` so [`Error`] retains its `Hash`
    /// derive (the upstream error enum does not implement `Hash`). Callers
    /// that need to programmatically match on the inner error should iterate
    /// [`build_path_candidates`] directly and call [`pkix_path::validate_path`]
    /// per candidate themselves.
    ///
    /// [`SignatureVerifier`]: pkix_path::SignatureVerifier
    /// [`pkix_path::Error::Display`]: pkix_path::Error
    #[non_exhaustive]
    NoValidPath {
        /// Number of candidate chains that were tried and rejected.
        tried: usize,
        /// `Display` rendering of the last [`pkix_path::Error`] observed.
        last_error: alloc::string::String,
    },
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
            Self::NoValidPath { tried, last_error } => write!(
                f,
                "tried {tried} candidate path(s); none validated. Last validation error: {last_error}"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Returns `true` if `cert` has `BasicConstraints` with `cA = TRUE`,
/// `false` if the extension is absent, has `cA = FALSE`, or cannot be
/// DER-decoded.
///
/// Malformed `BasicConstraints` is treated as `false` (skip-not-fail):
/// a single malformed certificate in a CMS `SignedData.certificates` bag
/// must not poison verification of an otherwise-valid chain.
fn cert_is_ca(cert: &Certificate) -> bool {
    pkix_path::cert_is_ca(cert).unwrap_or(false)
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
///
/// **Note:** Returns `Vec<u8>` (owned) rather than `&[u8]` because
/// `AuthorityKeyIdentifier::from_der` produces an owned intermediate
/// whose lifetime cannot be tied to the input `cert` reference; the
/// inner `OctetString` bytes do not borrow from the cert's DER.
fn cert_aki_key_id(cert: &Certificate) -> Option<Vec<u8>> {
    use x509_cert::ext::pkix::AuthorityKeyIdentifier;

    let extns = cert.tbs_certificate().extensions().map(|v| v.as_slice())?;
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
///
/// **Note:** Returns `Vec<u8>` (owned) for the same reason as
/// [`cert_aki_key_id`]: `SubjectKeyIdentifier::from_der` produces an
/// owned `OctetString` that does not borrow from the cert's DER.
fn cert_ski_key_id(cert: &Certificate) -> Option<Vec<u8>> {
    use x509_cert::ext::pkix::SubjectKeyIdentifier;

    let extns = cert.tbs_certificate().extensions().map(|v| v.as_slice())?;
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
/// With `prefer_anchor_issued` (set for signature-checked searches),
/// candidates within a tier whose own issuer names a trust anchor come
/// first, so a path that ends one hop later is tried before deeper
/// detours (a cheap approximation of RFC 4158 §3.5's shortest-path
/// preference). Topology-only searches ([`build_path`],
/// [`build_path_candidates`]) keep the historical order, because their
/// first yield is returned unverified and the BetterTLS baseline pins it.
/// The sort is **stable**, so remaining ties preserve pool
/// insertion order. Later copies of byte-identical pool certificates
/// (`duplicate[idx]`) are omitted.
///
/// **Not currently used:** the AKI `authorityCertIssuer` /
/// `authorityCertSerialNumber` fields. They are rare in practice and
/// parsing `GeneralNames` for that signal is more work than the marginal
/// disambiguation benefit justifies. Documented as a deferred enhancement.
fn rank_candidates(
    cur: &Certificate,
    pool: &[Certificate],
    duplicate: &[bool],
    anchors: &[pkix_path::TrustAnchor],
    prefer_anchor_issued: bool,
) -> Vec<usize> {
    let cur_issuer = cur.tbs_certificate().issuer();
    let target_aki_kid = cert_aki_key_id(cur);
    let mut ranked: Vec<(u8, u8, usize)> = Vec::with_capacity(pool.len());
    for (idx, candidate) in pool.iter().enumerate() {
        if duplicate[idx]
            || !pkix_path::names_match(candidate.tbs_certificate().subject(), cur_issuer)
        {
            continue;
        }
        let tier: u8 = match (
            target_aki_kid.as_deref(),
            cert_ski_key_id(candidate).as_deref(),
        ) {
            (Some(aki), Some(ski)) if aki == ski => 0,
            _ => 1,
        };
        let reaches_anchor = prefer_anchor_issued
            && anchors
                .iter()
                .any(|a| pkix_path::names_match(&a.subject, candidate.tbs_certificate().issuer()));
        ranked.push((tier, u8::from(!reaches_anchor), idx));
    }
    ranked.sort_by_key(|&(tier, far, _)| (tier, far));
    ranked.into_iter().map(|(_, _, idx)| idx).collect()
}

/// SPKI-based cycle detection: do `a` and `b` carry the same
/// `SubjectPublicKeyInfo` algorithm OID and raw public-key bits?
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
fn same_spki(a: &Certificate, b: &Certificate) -> bool {
    let a = a.tbs_certificate().subject_public_key_info();
    let b = b.tbs_certificate().subject_public_key_info();
    a.algorithm.oid == b.algorithm.oid && a.subject_public_key == b.subject_public_key
}

/// Mark every pool entry that equals an earlier entry.
///
/// Sorting indices by signature bytes groups candidate duplicates in
/// `O(n log n)`; only entries with identical signatures are compared in
/// full. An attacker-supplied bag of many copies of one certificate thus
/// costs neither quadratic deduplication nor repeated DFS work.
fn mark_duplicates(pool: &[Certificate]) -> Vec<bool> {
    let mut order: Vec<usize> = (0..pool.len()).collect();
    // Stable sort: within a run of equal signatures, indices stay in pool
    // order, so the first occurrence is the one kept.
    order.sort_by(|&a, &b| {
        pool[a]
            .signature()
            .raw_bytes()
            .cmp(pool[b].signature().raw_bytes())
    });
    let mut duplicate = alloc::vec![false; pool.len()];
    let mut run_start = 0;
    for pos in 0..order.len() {
        let sig = pool[order[pos]].signature().raw_bytes();
        if pool[order[run_start]].signature().raw_bytes() != sig {
            run_start = pos;
        }
        let cur = &pool[order[pos]];
        duplicate[order[pos]] = order[run_start..pos]
            .iter()
            .any(|&earlier| !duplicate[earlier] && pool[earlier] == *cur);
    }
    duplicate
}

/// Default DFS budget per search pass (frame entries plus candidates
/// examined; see [`Error::BudgetExceeded`]).
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
    /// Per-pass search budget: one unit per DFS frame entered and per pool
    /// candidate examined. Default: [`DEFAULT_DFS_BUDGET`].
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

/// Search-node identifier used by [`PathCandidates`].
///
/// Node `0` is the target certificate; node `i + 1` is `pool[i]`. Using
/// indices rather than cloned certificates lets the iterator cache
/// per-node work (candidate ranking, TBS encoding, link signature
/// results) across the whole search.
type NodeId = usize;

/// Per-frame DFS state held by [`PathCandidates`].
///
/// Each [`Frame`] mirrors one stack frame of the recursive DFS: the node
/// whose issuer this frame is looking for, a cursor into that node's
/// (cached) ranked candidate list, and whether the anchor check for this
/// frame has already run.
struct Frame {
    /// The certificate at this depth of the current path.
    node: NodeId,
    /// Position in the node's ranked candidate list to try next.
    cursor: usize,
    /// True after the anchor-match check has run for this frame. A frame
    /// that matched an anchor and yielded a chain keeps exploring its pool
    /// candidates on the next `next()` call (GitHub #11: an anchor whose
    /// name matches `cur`'s issuer is not necessarily the key that signed
    /// `cur`; a same-name pool certificate, e.g. a key-rollover or
    /// cross-certificate, may be).
    anchor_checked: bool,
}

impl Frame {
    const fn new(node: NodeId) -> Self {
        Self {
            node,
            cursor: 0,
            anchor_checked: false,
        }
    }
}

/// Iterator over certification paths from a target cert through a
/// candidate pool to one of a set of trust anchors.
///
/// Each [`Iterator::next`] call returns either:
/// - `Some(Ok(chain))` — the next leaf-first chain `[target, ...,
///   anchor-issued]` that is topologically valid (DN chain links,
///   `BasicConstraints cA=TRUE` on every intermediate, no SPKI cycles).
///   Iterators from [`build_path_candidates`] do NOT verify signatures;
///   downstream callers must run the returned chain through
///   [`pkix_path::validate_path`]. The iterator used internally by
///   [`build_first_valid_path`] additionally requires every link
///   (including the anchor link) to carry a signature that verifies
///   under the candidate issuer's key before descending (RFC 4158 §3.5.1),
///   which prunes same-name decoys at the first level.
/// - `Some(Err(e))` — a fatal error (see [`Error`]). The iterator is
///   exhausted; subsequent calls return `None`.
/// - `None` — DFS has been exhausted; no more chains exist within the
///   configured `max_depth`.
///
/// **Resumable DFS**: candidates are explored in ranked order
/// (`rank_candidates`: AKI/SKI tier first, then — in the signature-checked
/// search only — candidates whose issuer names a trust anchor, then pool
/// order); when a chain is yielded, the
/// next call resumes from the same DFS state and explores alternate
/// paths. A frame whose issuer name matched an anchor still explores its
/// same-name pool candidates after yielding (GitHub #11). This is the
/// contract S/MIME callers depend on for build-then-validate retry loops
/// in adversarial pools (CMS bags, federal-bridge cross-cert topologies,
/// etc.) where the topologically-first chain may not be the
/// cryptographically-verifying one.
///
/// **Duplicates**: byte-identical pool certificates are considered once.
///
/// **Bounded enumeration**: a single shared budget (initial value
/// [`PathBuilderConfig::dfs_budget`]) is decremented once per DFS frame
/// entry and once per pool candidate examined, across all `next()` calls.
/// When the budget is exhausted, the next call returns
/// `Some(Err(`[`Error::BudgetExceeded`]`))` and the iterator becomes
/// exhausted. This bounds worst-case work to `O(dfs_budget)` candidate
/// examinations (plus one `O(pool)` ranking pass per distinct node)
/// across the entire iterator's lifetime, preventing an adversarial pool
/// from causing unbounded enumeration.
///
/// **No iterative deepening**: this iterator performs a single DFS at
/// `max_depth`. Paths are yielded in DFS order. Shortest-first is not
/// guaranteed. For typical pools the first yielded chain is the shortest;
/// the signature-checked search used by [`build_first_valid_path`] also
/// tries candidates issued by an anchor-named CA first.
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
///
/// The pattern above is what [`build_first_valid_path`] wraps (with the
/// per-link signature pruning described above): callers that only need
/// "find any chain that validates" should prefer the helper. Drop down to
/// this iterator when you need per-candidate diagnostics, want to limit
/// the number of candidates tried, or are composing the retry loop with
/// additional per-candidate policy (e.g., per-candidate revocation checks).
pub struct PathCandidates<'a> {
    target: Certificate,
    pool: &'a [Certificate],
    /// `duplicate[i]` is true when `pool[i]` equals an earlier pool entry.
    duplicate: Vec<bool>,
    anchors: &'a [pkix_path::TrustAnchor],
    /// When set, every link is signature-checked before it is used.
    verifier: Option<&'a dyn pkix_path::SignatureVerifier>,
    max_depth: usize,
    /// Frame stack, leaf-first. `frames[0].node` is the target. Empty
    /// once the search space is exhausted.
    frames: Vec<Frame>,
    /// Shared budget; see "Bounded enumeration" above.
    budget: usize,
    /// Per-node ranked candidate pool indices, computed on first use.
    ranked: Vec<Option<Vec<usize>>>,
    /// Per-node TBSCertificate DER (`None` inside = encoding failed),
    /// computed on first signature check of that node.
    tbs: Vec<Option<Option<Vec<u8>>>>,
    /// Cached `(child node, issuer pool index) -> signature verifies`.
    link_ok: BTreeMap<(NodeId, usize), bool>,
    /// Cached `(child node, anchor index) -> signature verifies`.
    anchor_ok: BTreeMap<(NodeId, usize), bool>,
    /// True once the iterator has yielded a fatal error or exhausted
    /// the search space; subsequent calls return `None`.
    done: bool,
}

impl<'a> PathCandidates<'a> {
    /// Construct a new path-candidate iterator.
    ///
    /// The `pool` and `anchors` references are borrowed for the lifetime
    /// of the iterator; `config` is read once at construction (its
    /// `max_depth` and `dfs_budget` values are copied in). `verifier`
    /// enables per-link signature pruning.
    fn new(
        target: &Certificate,
        pool: &'a [Certificate],
        anchors: &'a [pkix_path::TrustAnchor],
        config: &PathBuilderConfig,
        verifier: Option<&'a dyn pkix_path::SignatureVerifier>,
    ) -> Self {
        let duplicate = mark_duplicates(pool);
        Self {
            target: target.clone(),
            pool,
            duplicate,
            anchors,
            verifier,
            max_depth: config.max_depth,
            frames: alloc::vec![Frame::new(0)],
            budget: config.dfs_budget,
            ranked: alloc::vec![None; pool.len() + 1],
            tbs: alloc::vec![None; pool.len() + 1],
            link_ok: BTreeMap::new(),
            anchor_ok: BTreeMap::new(),
            done: false,
        }
    }

    fn cert(&self, node: NodeId) -> &Certificate {
        if node == 0 {
            &self.target
        } else {
            &self.pool[node - 1]
        }
    }

    /// Spend one unit of budget; `false` when the budget is exhausted.
    fn charge(&mut self) -> bool {
        if self.budget == 0 {
            return false;
        }
        self.budget -= 1;
        true
    }

    /// Does `child`'s signature verify under `issuer_spki`? Always `true`
    /// when no verifier is configured (topology-only mode).
    fn signed_by(&mut self, child: NodeId, issuer_spki: &spki::SubjectPublicKeyInfoOwned) -> bool {
        let Some(verifier) = self.verifier else {
            return true;
        };
        if self.tbs[child].is_none() {
            let der = pkix_path::tbs_certificate_der(self.cert(child)).ok();
            self.tbs[child] = Some(der);
        }
        let Some(Some(tbs)) = &self.tbs[child] else {
            return false;
        };
        let cert = self.cert(child);
        verifier
            .verify_signature(
                cert.signature_algorithm().owned_to_ref(),
                issuer_spki.owned_to_ref(),
                tbs,
                cert.signature().raw_bytes(),
            )
            .is_ok()
    }

    /// Does an anchor whose name matches `node`'s issuer (and, with a
    /// verifier, whose key verifies `node`'s signature) exist?
    fn anchor_matches(&mut self, node: NodeId) -> bool {
        for (idx, anchor) in self.anchors.iter().enumerate() {
            if !pkix_path::names_match(&anchor.subject, self.cert(node).tbs_certificate().issuer())
            {
                continue;
            }
            let ok = match self.anchor_ok.get(&(node, idx)) {
                Some(&ok) => ok,
                None => {
                    let ok = self.signed_by(node, &anchor.subject_public_key_info);
                    self.anchor_ok.insert((node, idx), ok);
                    ok
                }
            };
            if ok {
                return true;
            }
        }
        false
    }

    /// Is `pool[idx]` an eligible issuer for `child` (CA, and with a
    /// verifier, its key verifies `child`'s signature)?
    fn link_matches(&mut self, child: NodeId, idx: usize) -> bool {
        if let Some(&ok) = self.link_ok.get(&(child, idx)) {
            return ok;
        }
        let pool = self.pool;
        let ok = cert_is_ca(&pool[idx])
            && self.signed_by(child, pool[idx].tbs_certificate().subject_public_key_info());
        self.link_ok.insert((child, idx), ok);
        ok
    }

    fn current_chain(&self) -> Vec<Certificate> {
        self.frames
            .iter()
            .map(|f| self.cert(f.node).clone())
            .collect()
    }
}

impl Iterator for PathCandidates<'_> {
    type Item = Result<Vec<Certificate>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        loop {
            // Empty stack: search space exhausted.
            let Some(top) = self.frames.last() else {
                self.done = true;
                return None;
            };
            let node = top.node;

            // Anchor check: each frame charges 1 unit of budget here.
            // On a match the chain is yielded; the next call resumes this
            // frame's candidate exploration below (GitHub #11) rather than
            // backtracking immediately.
            if !top.anchor_checked {
                if !self.charge() {
                    self.done = true;
                    return Some(Err(Error::BudgetExceeded));
                }
                self.frames.last_mut().expect("non-empty").anchor_checked = true;
                if self.anchor_matches(node) {
                    return Some(Ok(self.current_chain()));
                }
            }

            // Past the anchor check. A frame at the depth limit cannot
            // host any further intermediate candidates — backtrack. A
            // frame exists at every depth up to and including
            // `max_depth + 1` (the deepest frame performs the anchor check
            // then returns immediately).
            if self.frames.len() > self.max_depth {
                self.frames.pop();
                continue;
            }

            // Rank candidates for this node once per iterator lifetime.
            if self.ranked[node].is_none() {
                let ranked = rank_candidates(
                    self.cert(node),
                    self.pool,
                    &self.duplicate,
                    self.anchors,
                    self.verifier.is_some(),
                );
                self.ranked[node] = Some(ranked);
            }

            // Pull the next candidate index, or backtrack if exhausted.
            let frame = self.frames.last_mut().expect("non-empty");
            let ranked = self.ranked[node].as_ref().expect("set above");
            let Some(&idx) = ranked.get(frame.cursor) else {
                self.frames.pop();
                continue;
            };
            frame.cursor += 1;

            // Every examined candidate costs budget, so pools whose
            // candidates are all rejected below still terminate within
            // `dfs_budget` steps.
            if !self.charge() {
                self.done = true;
                return Some(Err(Error::BudgetExceeded));
            }

            // SPKI cycle guard (cheap; before any signature work).
            let candidate = &self.pool[idx];
            let in_path = self
                .frames
                .iter()
                .any(|f| same_spki(self.cert(f.node), candidate));
            if in_path {
                continue;
            }

            // CA check (BasicConstraints cA=TRUE) and, with a verifier,
            // the link signature. Skip-not-fail: a candidate whose
            // `BasicConstraints` is absent, has `cA = FALSE`, or fails to
            // DER-decode is treated as "not a CA" and silently skipped.
            // This keeps DFS alive when the certificate pool carries
            // unsolicited or corrupt certs — e.g. CMS
            // `SignedData.certificates` bags routinely include certs the
            // verifier did not solicit. One bad cert in the bag must not
            // poison verification of an otherwise-valid chain; nor may a
            // bag of same-name decoys hide the real issuer, which is what
            // the signature check prevents.
            if !self.link_matches(node, idx) {
                continue;
            }

            // Eligible: push the candidate and let the loop process it.
            self.frames.push(Frame::new(idx + 1));
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
    PathCandidates::new(
        target,
        pool.as_slice(),
        anchors,
        &PathBuilderConfig::new(),
        None,
    )
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
    PathCandidates::new(target, pool.as_slice(), anchors, config, None)
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
/// # Choosing between `build_path`, the iterator, and `build_first_valid_path`
///
/// Use this single-shot API when:
/// - the pool is from a trusted source (in-house cert store, configured
///   intermediate bundle), and
/// - finding any topologically valid chain is sufficient (the caller does
///   not need to retry with alternate chains if signature verification
///   fails downstream).
///
/// Use [`build_path_candidates`] (or its `_with_config` sibling) when you
/// want full control over candidate iteration — for adversarial pools (CMS
/// `SignedData.certificates` bags, federal-bridge cross-cert topologies,
/// anywhere the wire-order of certs is not under your control) so failed
/// signature verification can be retried against the next candidate path.
/// See [`PathCandidates`] for the build-then-validate retry-loop pattern.
///
/// Use [`build_first_valid_path`] (or its `_with_config` sibling) for the
/// common case of "iterate candidates until one validates": it wraps the
/// iterator + [`pkix_path::validate_path`] retry loop and returns the
/// first chain that survives both topological build and signature
/// verification. Prefer this over `build_path` when the pool contains
/// alternatives whose signatures may be rejected by the verifier (e.g.,
/// cross-signed intermediates using algorithms outside the verifier's
/// dispatch table).
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
/// any anchor in `anchors`, `build_path` returns that chain — the anchor's
/// `SubjectPublicKeyInfo` is **not** verified against what the chain
/// expects. The iterator keeps exploring same-name pool candidates after
/// such a match (GitHub #11), and [`build_first_valid_path`] only accepts
/// an anchor link whose signature verifies.
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
/// Pool contents should be from a trusted source: a crafted pool of
/// same-name decoys can steer this topology-only search to a wrong chain
/// first (use [`build_first_valid_path`] for untrusted pools). The search
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
    let mut iter = PathCandidates::new(target, pool_slice, anchors, config, None);
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
    let mut probe = PathCandidates::new(target, pool_slice, anchors, &probe_config, None);
    match probe.next() {
        Some(Ok(_)) => Err(Error::DepthExceeded),
        Some(Err(e)) => Err(e),
        None => Err(Error::NoPathFound),
    }
}

// =========================================================================
// build_first_valid_path — candidate iteration + signature verification
// =========================================================================

/// Build a certification path that both **(a)** is topologically valid through
/// `pool` to one of `anchors` and **(b)** passes
/// [`pkix_path::validate_path`] under `policy` and `verifier`.
///
/// Iterates [`build_path_candidates`] until the first candidate chain
/// validates. Returns the validating chain. If every candidate is rejected
/// by `validate_path`, returns [`Error::NoValidPath`] carrying the count of
/// candidates tried and the `Display` rendering of the last
/// [`pkix_path::Error`].
///
/// # When to use this over [`build_path`]
///
/// [`build_path`] is single-shot: it returns the first DFS candidate without
/// any knowledge of which signature algorithms `verifier` actually dispatches
/// or which intermediates are within their validity window at `policy`'s
/// validation time. In adversarial pools — for example, cross-signed graphs
/// that include an alternative intermediate signed under
/// `ecdsa-with-SHA1` (RFC 5758 §3.2 legacy OID, not dispatched by
/// [`pkix_path::DefaultVerifier`]) — the first DFS yield can be rejected by
/// `validate_path` even though a SHA-256-only path exists in the same pool.
///
/// `build_first_valid_path` closes this gap: it runs the candidate search
/// with per-link signature checking — a pool certificate is only pushed
/// onto the path if its key verifies the signature of the certificate
/// below it, and an anchor only terminates a path if its key verifies the
/// top certificate (RFC 4158 §3.5.1; results cached per (child, issuer)
/// pair) — and tries `validate_path` per yielded chain, returning the
/// first chain that survives both passes. Same-name decoys in an
/// attacker-supplied pool (e.g. the unsigned `SignedData.certificates` of
/// a CMS message) are therefore pruned at the first level instead of
/// exhausting the search budget, and within each AKI/SKI tier candidates
/// issued by an anchor-named CA are tried first.
///
/// If no signature-consistent chain exists, one topology-only candidate
/// is validated so that the error is [`Error::NoValidPath`] carrying the
/// concrete `validate_path` failure (e.g. a bad signature), as before.
///
/// # Errors
///
/// - [`Error::NoPathFound`] — the underlying iterator yielded no candidates
///   at all (no topologically valid chain through `pool` to any anchor).
///   Matches [`build_path`]'s behaviour for that case.
/// - [`Error::DepthExceeded`] / [`Error::BudgetExceeded`] — propagated from
///   [`build_path_candidates`] when the iterator surfaces them.
/// - [`Error::NoValidPath`] — at least one candidate was yielded but none
///   passed `validate_path`. Carries `tried` (>= 1) and the last
///   `validate_path` error rendering.
///
/// # Out of scope
///
/// - Async / parallel candidate evaluation. Candidates are tried sequentially.
/// - Caching of `validate_path` failures across candidates. Each yielded
///   chain is freshly validated.
/// - Promoting [`build_path`] itself to iterate. The single-shot helper is
///   retained verbatim for backward compatibility; callers opt in to the
///   iterating semantics by using this function.
///
/// # Relationship to other path-builder entry points
///
/// | Entry point                  | Verifier? | Returns                                      |
/// |------------------------------|-----------|----------------------------------------------|
/// | [`build_path`]               | No        | First DFS topological candidate (one-shot)   |
/// | [`build_path_candidates`]    | No        | Iterator of topological candidates           |
/// | [`build_first_valid_path`]   | Yes       | First candidate that passes `validate_path`  |
pub fn build_first_valid_path<V>(
    target: &Certificate,
    pool: &CertPool,
    anchors: &[pkix_path::TrustAnchor],
    policy: &pkix_path::ValidationPolicy,
    verifier: &V,
) -> Result<Vec<Certificate>>
where
    V: pkix_path::SignatureVerifier,
{
    build_first_valid_path_with_config(
        target,
        pool,
        anchors,
        policy,
        verifier,
        &PathBuilderConfig::new(),
    )
}

/// Build a verifier-validated certification path with caller-provided
/// budget and depth tunables.
///
/// Behaves identically to [`build_first_valid_path`] but uses the limits
/// in `config` instead of the workspace defaults. See
/// [`PathBuilderConfig`] for the individual knobs and
/// [`build_first_valid_path`] for full semantics.
///
/// # Errors
///
/// Same as [`build_first_valid_path`].
pub fn build_first_valid_path_with_config<V>(
    target: &Certificate,
    pool: &CertPool,
    anchors: &[pkix_path::TrustAnchor],
    policy: &pkix_path::ValidationPolicy,
    verifier: &V,
    config: &PathBuilderConfig,
) -> Result<Vec<Certificate>>
where
    V: pkix_path::SignatureVerifier,
{
    let mut iter = PathCandidates::new(target, pool.as_slice(), anchors, config, Some(verifier));
    let mut tried: usize = 0;
    let mut last_error: Option<alloc::string::String> = None;

    loop {
        match iter.next() {
            Some(Ok(chain)) => {
                match pkix_path::validate_path(&chain, anchors, policy, verifier) {
                    Ok(_) => return Ok(chain),
                    Err(e) => {
                        tried += 1;
                        last_error = Some(alloc::format!("{e}"));
                        // Continue to the next candidate.
                    }
                }
            }
            // The iterator surfaces its own errors (BudgetExceeded; in
            // principle future variants). Propagate verbatim. We do NOT
            // wrap these in NoValidPath because they describe failures
            // of the topological search, not of signature verification.
            Some(Err(e)) => return Err(e),
            // Iterator exhausted.
            None => {
                return match last_error {
                    // At least one candidate was yielded; every one was
                    // rejected by validate_path.
                    Some(last) => Err(Error::NoValidPath {
                        tried,
                        last_error: last,
                    }),
                    // Zero signature-consistent candidates. If a purely
                    // topological chain exists, validate it so the caller
                    // still gets `NoValidPath` with the specific
                    // `validate_path` failure (e.g. "signature invalid at
                    // chain index 0") instead of a bare `NoPathFound`.
                    None => {
                        let mut topo =
                            PathCandidates::new(target, pool.as_slice(), anchors, config, None);
                        match topo.next() {
                            Some(Ok(chain)) => {
                                return match pkix_path::validate_path(
                                    &chain, anchors, policy, verifier,
                                ) {
                                    // Unreachable in practice (the verified
                                    // search would have found it), but a
                                    // validating chain is a success.
                                    Ok(_) => Ok(chain),
                                    Err(e) => Err(Error::NoValidPath {
                                        tried: 1,
                                        last_error: alloc::format!("{e}"),
                                    }),
                                };
                            }
                            Some(Err(e)) => return Err(e),
                            None => {}
                        }
                        // No topological chain either. Distinguish
                        // NoPathFound from DepthExceeded the same way
                        // build_path does: probe at max_depth + 1.
                        let probe_config = PathBuilderConfig {
                            max_depth: config.max_depth.saturating_add(1),
                            dfs_budget: config.dfs_budget,
                        };
                        let mut probe = PathCandidates::new(
                            target,
                            pool.as_slice(),
                            anchors,
                            &probe_config,
                            None,
                        );
                        match probe.next() {
                            Some(Ok(_)) => Err(Error::DepthExceeded),
                            Some(Err(e)) => Err(e),
                            None => Err(Error::NoPathFound),
                        }
                    }
                };
            }
        }
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
    #[allow(unused_extern_crates)] // load-bearing under #![no_std] default features
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
        Certificate::from_der(&bytes).unwrap_or_else(|e| std::panic!("failed to parse {name}: {e}"))
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
