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

    // Recursive step: find pool certs that could issue `current`, ordered
    // by AKI/SKI matching tier (RFC 5280 §4.2.1.1, RFC 4158 §3.2).
    //
    // Tier 0: candidate's SubjectKeyIdentifier matches the target's
    //         AuthorityKeyIdentifier `keyIdentifier` field. This is the
    //         RFC 5280 §4.2.1.1 method-1 disambiguator: in bridge-CA and
    //         key-rollover topologies, multiple CA certs share an issuer
    //         DN; AKI/SKI is the only deterministic way to pick the cert
    //         that actually signed `current`.
    // Tier 1: any DN-matching candidate. Used when target has no AKI,
    //         no candidate SKI matches, or AKI/SKI parsing failed
    //         (fail-soft — see `cert_aki_key_id`/`cert_ski_key_id`).
    //
    // Stable sort within each tier preserves pool insertion order, which
    // is the documented contract for the no-AKI-signal case.
    //
    // Note: the (issuer, serial) AKI fields (RFC 5280 §4.2.1.1's optional
    // `authorityCertIssuer` + `authorityCertSerialNumber`) are not used
    // for tier ranking. They are rare in practice and parsing GeneralNames
    // for that signal is more work than the marginal disambiguation
    // benefit justifies. Documented as a deferred enhancement.
    //
    // Allocation: one Vec<(u8, usize)> per DFS frame, capped at pool size.
    // For realistic CMS / S/MIME pools (≤ tens of certs) this is well
    // bounded; against the adversarial-pool budget test (30 same-DN
    // candidates) it adds ~30 × log(30) compares + 30 SKI parses per
    // frame, which fits comfortably under the round budget.
    let target_aki_kid = cert_aki_key_id(c);
    let mut ranked: Vec<(u8, usize)> = Vec::with_capacity(pool.len());
    for (idx, candidate) in pool.iter().enumerate() {
        if !pkix_path::names_match(&candidate.tbs_certificate.subject, &current_issuer) {
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

    for (_tier, idx) in ranked {
        let candidate = &pool[idx];

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
///   [`Error::NoPathFound`] here.
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
