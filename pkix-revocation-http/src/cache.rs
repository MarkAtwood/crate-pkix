//! In-memory cache for fetched CRL and OCSP response bytes.
//!
//! Tracked under PKIX-a1yc.7. Shape D (decided 2026-05-11 by Mark) — see
//! the bead for the rejected alternatives.
//!
//! # Motivation
//!
//! Real consumers re-validate the same chains repeatedly within a short
//! window. Without caching, each path validation refetches every CRL and
//! every OCSP response from the network. This module supplies pluggable
//! cache wrappers ([`CachedHttpCrlFetcher`], [`CachedHttpOcspFetcher`])
//! that compose with the underlying [`crate::HttpCrlFetcher`] /
//! [`crate::HttpOcspFetcher`] machinery without changing those types.
//!
//! # Design
//!
//! - [`RevocationCache`] is the trait. `Send + Sync` so the cache can be
//!   shared across validation threads. Returns `Arc<CachedCrl>` /
//!   `Arc<CachedOcspResponse>` so callers see the freshness metadata
//!   alongside the bytes without re-parsing.
//! - [`InMemoryCache`] is a reference impl backed by `RwLock<HashMap<...>>`.
//!   Nothing is evicted automatically; it reclaims on demand via
//!   [`InMemoryCache::prune_expired`] and reports its size via
//!   [`InMemoryCache::len`]. Consumers wanting a hard ceiling (LRU, LFU,
//!   a byte budget) bring a `moka` or `redis`-backed `RevocationCache`
//!   impl.
//! - [`CrlCacheKey`] keys by `(issuer_dn_der, distribution_point_uri)`:
//!   both are known a-priori to the wrapper from the cert's issuer field
//!   and the CRL DP URI it is about to fetch. `CRLNumber` is freshness
//!   metadata on the value side (RFC 5280 §5.2.3 makes it monotonic per
//!   series), NOT a key field — using it as a key would force a scan on
//!   read, and a-priori lookup with the wrapper's URL still works.
//! - [`OcspCacheKey`] keys by `(cert_serial, issuer_key_hash, responder_url)`:
//!   the same triple that uniquely identifies a [`x509_ocsp::CertID`] with
//!   one responder.
//!
//! # Persistence
//!
//! Out of scope. The trait is the extension point — a disk-backed or
//! Redis-backed impl can be supplied by the consumer.
//!
//! # Async
//!
//! No async cache variant per PKIX-a1yc.10. Async fetchers (when added)
//! will compose with the same sync trait — the cache itself is fast
//! enough that locking inside `get_*` does not need its own runtime.

use core::fmt;
use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::SystemTime;

#[cfg(test)]
#[allow(unused_imports)]
use crate::FetchError;
#[cfg(feature = "crl")]
use crate::HttpCrlFetcher;
#[cfg(feature = "ocsp")]
use crate::HttpOcspFetcher;
#[cfg(any(feature = "crl", feature = "ocsp"))]
use crate::{FetchRequest, FetchResponse, RevocationFetcher};
#[cfg(any(feature = "crl", feature = "ocsp"))]
use der::Decode as _;
#[cfg(feature = "crl")]
use der::Encode as _;
#[cfg(any(feature = "crl", feature = "ocsp"))]
use pkix_path::{SignatureVerifier, TrustAnchor};
#[cfg(any(feature = "crl", feature = "ocsp"))]
use pkix_revocation::{Error as RevError, RevocationChecker};
#[cfg(any(feature = "crl", feature = "ocsp"))]
use x509_cert::Certificate;

/// `id-ce-cRLNumber` — RFC 5280 §5.2.3.
#[cfg(feature = "crl")]
const OID_CRL_NUMBER: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.20");

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------
//
// The key types keep public fields where the value types ([`CachedCrl`],
// [`CachedOcspResponse`]) do not. That asymmetry is deliberate: a key IS
// its fields, and an out-of-process `RevocationCache` implementation has
// to read them to build whatever its backing store uses for a key — a
// Redis key string, a SQL tuple, a filesystem path. Hiding them behind
// accessors would buy no representation freedom (the fields are the
// identity tuple, and changing them is a breaking change whether they
// are public or not) and would make every external-store implementation
// clumsier. A value, by contrast, is an opaque blob plus metadata the
// wrapper derived from it, and is only meaningful as a set.

/// Cache key for a CRL.
///
/// `distribution_point_uri = None` represents "the" CRL for this issuer
/// (most certificates with a single CDP). `Some(uri)` covers partitioned
/// CRLs per RFC 5280 §5 (different reason flags, scope, or indirect
/// cRLIssuer URIs).
///
/// The wrapper sets `distribution_point_uri = Some(url)` per fetched URL,
/// so partitioned CRLs that advertise different URIs are cached separately.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CrlCacheKey {
    /// DER-encoded `Name` of the CRL issuer.
    ///
    /// For non-indirect CRLs this is the certificate issuer's DER-encoded
    /// `subject`. Indirect CRL handling (RFC 5280 §6.3.3(f)) is tracked
    /// under PKIX-cqwt and out of scope here.
    pub issuer_dn_der: Vec<u8>,
    /// The CRL distribution-point URI, if known.
    ///
    /// `None` means "the" CRL for this issuer (no partitioning).
    /// `Some(uri)` distinguishes partitioned CRLs whose URIs differ.
    pub distribution_point_uri: Option<String>,
}

/// Cache key for an OCSP response.
///
/// Mirrors the `CertID` triple in an RFC 6960 OCSP request, plus the
/// responder URL since the same `CertID` may be served by multiple
/// responders.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OcspCacheKey {
    /// `CertID.serialNumber` — the DER `INTEGER` content bytes.
    pub cert_serial: Vec<u8>,
    /// `CertID.issuerKeyHash` — hash of the issuer's `subjectPublicKey`
    /// BIT STRING value under the same `OcspHashAlg` used in the request.
    pub issuer_key_hash: Vec<u8>,
    /// HTTP/HTTPS URL of the OCSP responder.
    pub responder_url: String,
}

// ---------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------

/// Cached CRL bytes plus freshness metadata.
///
/// `crl_number` is the RFC 5280 §5.2.3 `CRLNumber` extension value when
/// the CRL carries one. Stored as the canonical unsigned-integer big-endian
/// bytes; `CachedHttpCrlFetcher` compares two `crl_number` values
/// lexicographically (after length-normalising) to detect rollback per
/// RFC 5280's monotonicity requirement.
///
/// `next_update` is `None` for CRLs that omit the `nextUpdate` field.
/// Such CRLs SHOULD NOT be issued per RFC 5280 §5.1.2.5; this struct
/// permits the value to be cached but a cache impl MAY treat
/// `next_update == None` as "never cache" or "cache for a bounded
/// fallback TTL". The reference [`InMemoryCache`] treats it as "never
/// expires until invalidated".
/// # Field privacy
///
/// The fields are private and reached through accessors. The cached
/// bytes are a DER blob plus the three freshness values the wrapper
/// derived from it, and the four are only meaningful together: a
/// `next_update` that did not come from these `bytes` would make the
/// wrapper serve a CRL it believes is live when it is not. Keeping them
/// private means the only way to build a `CachedCrl` is
/// [`CachedCrl::new`], and leaves this crate free to change how the
/// metadata is stored (a packed epoch-seconds representation, say, or a
/// parsed `CRLNumber` integer) without a breaking change.
///
/// `RevocationCache` implementors need both halves and have them:
/// [`CachedCrl::new`] to reconstruct an entry loaded from an external
/// store, and the accessors to write one out.
#[derive(Clone, Debug)]
pub struct CachedCrl {
    crl_number: Option<Vec<u8>>,
    this_update: SystemTime,
    next_update: Option<SystemTime>,
    bytes: Vec<u8>,
}

impl CachedCrl {
    /// Assemble a cache entry from DER bytes and the freshness metadata
    /// taken from them.
    ///
    /// - `crl_number` — the RFC 5280 §5.2.3 `CRLNumber` extension value as
    ///   canonical unsigned big-endian bytes, or `None` if the CRL omits
    ///   the extension. This is the monotonicity comparator; an entry
    ///   stored without it cannot be protected from rollback.
    /// - `this_update` — `tbsCertList.thisUpdate`.
    /// - `next_update` — `tbsCertList.nextUpdate`, or `None` if omitted.
    /// - `bytes` — the raw DER-encoded `CertificateList`.
    ///
    /// The metadata is not re-derived from `bytes`, so a
    /// [`RevocationCache`] implementor restoring an entry from an
    /// external store must write back the values it read out of the same
    /// entry, not values from elsewhere.
    #[must_use]
    pub const fn new(
        crl_number: Option<Vec<u8>>,
        this_update: SystemTime,
        next_update: Option<SystemTime>,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            crl_number,
            this_update,
            next_update,
            bytes,
        }
    }

    /// The `CRLNumber` extension value, if the CRL carried one.
    ///
    /// Canonical unsigned big-endian bytes — RFC 5280 §5.2.3.
    #[must_use]
    pub fn crl_number(&self) -> Option<&[u8]> {
        self.crl_number.as_deref()
    }

    /// `tbsCertList.thisUpdate`.
    #[must_use]
    pub const fn this_update(&self) -> SystemTime {
        self.this_update
    }

    /// `tbsCertList.nextUpdate` — `None` if the CRL omits it.
    #[must_use]
    pub const fn next_update(&self) -> Option<SystemTime> {
        self.next_update
    }

    /// The raw DER-encoded `CertificateList`.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Cached OCSP response bytes plus freshness metadata.
///
/// `produced_at` / `this_update` / `next_update` are taken from the
/// `BasicOcspResponse.tbsResponseData` and the first (and only relevant)
/// `SingleResponse` for the queried cert.
///
/// As with [`CachedCrl`], `next_update == None` is unusual (RFC 6960
/// §4.2.2.1 RECOMMENDS its presence); the reference cache keeps such
/// entries until invalidated.
/// # Field privacy
///
/// Private for the same reason as [`CachedCrl`]'s: the bytes and the
/// three timestamps derived from them are only meaningful as a set.
/// Build one with [`CachedOcspResponse::new`] and read it through the
/// accessors.
#[derive(Clone, Debug)]
pub struct CachedOcspResponse {
    produced_at: SystemTime,
    this_update: SystemTime,
    next_update: Option<SystemTime>,
    bytes: Vec<u8>,
}

impl CachedOcspResponse {
    /// Assemble a cache entry from DER bytes and the freshness metadata
    /// taken from them.
    ///
    /// - `produced_at` — `BasicOcspResponse.tbsResponseData.producedAt`.
    /// - `this_update` — the `SingleResponse.thisUpdate` for the queried
    ///   certificate. This is the staleness comparator; see
    ///   [`CachedHttpOcspFetcher`] for how it is used to reject a
    ///   response that would replace fresher status with older status.
    /// - `next_update` — `SingleResponse.nextUpdate`, or `None`.
    /// - `bytes` — the raw DER-encoded outer `OcspResponse`.
    #[must_use]
    pub const fn new(
        produced_at: SystemTime,
        this_update: SystemTime,
        next_update: Option<SystemTime>,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            produced_at,
            this_update,
            next_update,
            bytes,
        }
    }

    /// `BasicOcspResponse.tbsResponseData.producedAt` — when the
    /// responder signed this response.
    #[must_use]
    pub const fn produced_at(&self) -> SystemTime {
        self.produced_at
    }

    /// `SingleResponse.thisUpdate` — the time the status it carries was
    /// known to be correct.
    #[must_use]
    pub const fn this_update(&self) -> SystemTime {
        self.this_update
    }

    /// `SingleResponse.nextUpdate` — `None` if the response omits it.
    #[must_use]
    pub const fn next_update(&self) -> Option<SystemTime> {
        self.next_update
    }

    /// The raw DER-encoded outer `OcspResponse`.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Pluggable cache for fetched CRL and OCSP response bytes.
///
/// `Send + Sync` so the cache can be wrapped in `Arc` and shared across
/// validation threads.
///
/// # Expiry semantics
///
/// `get_crl` / `get_ocsp` return the cached entry if present, WITHOUT
/// applying freshness filtering. Callers (the wrapper layer) are
/// responsible for checking `next_update` against their authoritative
/// time source. This avoids a time-source mismatch between the cache
/// (which would use `SystemTime::now()`) and the validator (which uses
/// a caller-supplied `now_unix` epoch timestamp).
///
/// # Rollback
///
/// The trait does NOT enforce `CRLNumber` monotonicity. That belongs to
/// the wrapper ([`CachedHttpCrlFetcher`]), which is the only piece that
/// knows it has just fetched a newer (or older) CRL to compare against.
pub trait RevocationCache: Send + Sync {
    /// Fetch a cached CRL.
    ///
    /// Returns `None` on miss or expiry.
    fn get_crl(&self, key: &CrlCacheKey) -> Option<Arc<CachedCrl>>;

    /// Store a CRL in the cache, overwriting any existing entry for the
    /// same key.
    fn put_crl(&self, key: CrlCacheKey, entry: CachedCrl);

    /// Remove a cached CRL.
    ///
    /// Idempotent — calling on an absent key is a no-op.
    fn invalidate_crl(&self, key: &CrlCacheKey);

    /// Fetch a cached OCSP response.
    ///
    /// Returns `None` on miss or expiry.
    fn get_ocsp(&self, key: &OcspCacheKey) -> Option<Arc<CachedOcspResponse>>;

    /// Store an OCSP response in the cache, overwriting any existing
    /// entry for the same key.
    fn put_ocsp(&self, key: OcspCacheKey, entry: CachedOcspResponse);

    /// Remove a cached OCSP response.
    ///
    /// Idempotent — calling on an absent key is a no-op.
    fn invalidate_ocsp(&self, key: &OcspCacheKey);

    /// Insert `entry` under `key` unless it would roll back a
    /// newer-numbered CRL already cached there. Returns `true` if
    /// inserted, `false` if suppressed as a rollback.
    ///
    /// This is the method the CRL wrapper calls; it never calls
    /// [`put_crl`](Self::put_crl) directly. RFC 5280 §5.2.3 makes
    /// `CRLNumber` monotonic per series, so a refresh that goes
    /// backwards is a misconfigured responder serving a stale snapshot,
    /// or an attack.
    ///
    /// # Overriding
    ///
    /// The default reads with `get_crl` and then writes with `put_crl`,
    /// which is correct against an ordinary stale refresh but loses the
    /// race against a concurrent writer that inserts a newer CRL
    /// between the two calls. Override it when the backing store can do
    /// the compare and the write as one operation — under a single lock,
    /// in a transaction, or with a compare-and-set — as
    /// [`InMemoryCache`] does.
    #[cfg(feature = "crl")]
    #[cfg_attr(docsrs, doc(cfg(feature = "crl")))]
    fn put_crl_unless_rollback(&self, key: CrlCacheKey, entry: CachedCrl) -> bool {
        if is_rollback(self.get_crl(&key).as_deref(), entry.crl_number()) {
            return false;
        }
        self.put_crl(key, entry);
        true
    }

    /// Insert `entry` under `key` unless it would replace fresher status
    /// with staler status. Returns `true` if inserted, `false` if
    /// suppressed as staler.
    ///
    /// This is the method the OCSP wrapper calls; it never calls
    /// [`put_ocsp`](Self::put_ocsp) directly. Revocation is monotone, so
    /// an older `good` response displacing a cached `revoked` one is
    /// always wrong, and two threads validating the same certificate at
    /// once are enough to land responses in the opposite order to the
    /// one they were fetched in — no attacker required.
    ///
    /// # Overriding
    ///
    /// As [`put_crl_unless_rollback`](Self::put_crl_unless_rollback):
    /// the default is a non-atomic get-then-put. Override it when the
    /// store can compare and write atomically.
    #[cfg(feature = "ocsp")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ocsp")))]
    fn put_ocsp_unless_staler(&self, key: OcspCacheKey, entry: CachedOcspResponse) -> bool {
        if is_staler_ocsp(self.get_ocsp(&key).as_deref(), entry.this_update()) {
            return false;
        }
        self.put_ocsp(key, entry);
        true
    }
}

// ---------------------------------------------------------------------------
// InMemoryCache
// ---------------------------------------------------------------------------

/// `HashMap`-backed reference [`RevocationCache`].
///
/// # Growth and reclamation
///
/// Nothing is evicted automatically: this type spawns no threads,
/// registers no timers, and reads no clock, so there is nothing to run
/// an eviction pass. Entries persist until
/// [`prune_expired`](Self::prune_expired), [`clear`](Self::clear) or
/// `invalidate_*` removes them, or the cache is dropped.
///
/// A long-running process therefore accumulates entries. The usual
/// driver is not an attack but time: a validator that sees many issuers
/// and distribution points over weeks keeps every expired CRL and
/// response it ever cached, each holding its DER bytes alive. Call
/// `prune_expired` from whatever maintenance tick the consumer already
/// has, and export [`len`](Self::len) as a gauge — a count that only
/// climbs is the signal that nothing is calling it.
///
/// What bounds the key space is worth stating plainly, because it is
/// better than it looks: the wrappers store an entry only after a
/// *determinative* verdict, which means the CRL or OCSP response was
/// signature-verified against the issuer or anchor. An attacker cannot
/// insert an entry by presenting arbitrary bytes or arbitrary
/// certificates; they would need a genuinely verifiable revocation
/// source per entry. Growth is bounded by what real CAs and responders
/// will sign, not by what a peer can send.
///
/// Consumers wanting a hard ceiling — LRU, LFU, or a byte budget —
/// supply their own [`RevocationCache`] backed by a bounded store such
/// as `moka`. The trait is the extension point precisely so that this
/// reference implementation can stay simple.
///
/// Internal locking is `RwLock`, not `DashMap`, to avoid the extra
/// dependency in the reference impl. Read paths take the read lock;
/// write paths take the write lock briefly.
///
/// # Lock poisoning
///
/// Poisoning is ignored: every access recovers the guard with
/// [`PoisonError::into_inner`] and proceeds. This is sound here because
/// the only operations performed while either lock is held are
/// `HashMap` insert, get, remove and len, over keys whose `Hash` and
/// `Eq` are derived on `Vec<u8>` / `Option<String>` and values that are
/// plain data behind an `Arc`. None of those can panic part-way and
/// leave a map half-updated, so a poisoned flag here cannot mean the
/// map is inconsistent — it can only mean some unrelated panic unwound
/// through a thread that happened to hold the lock.
///
/// The alternative behaviours were both worse. Treating poisoning as a
/// miss (and silently dropping writes) turns one unrelated panic into a
/// cache that misses everything and never repopulates, for the life of
/// the process, with nothing in any error path to say so: every
/// validation silently refetches from the network forever. Panicking
/// instead would propagate an unrelated thread's failure into path
/// validation, where the cache is meant to be a transparent
/// optimisation. Recovering is the only option that keeps the cache
/// doing its job.
#[derive(Default)]
pub struct InMemoryCache {
    crl: RwLock<HashMap<CrlCacheKey, Arc<CachedCrl>>>,
    ocsp: RwLock<HashMap<OcspCacheKey, Arc<CachedOcspResponse>>>,
}

impl InMemoryCache {
    /// Construct an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop every entry whose `nextUpdate` has passed at `now`, returning
    /// how many were removed.
    ///
    /// Entries with no `nextUpdate` are kept: this cache treats a missing
    /// `nextUpdate` as "never expires until invalidated", so pruning them
    /// here would contradict [`RevocationCache::get_crl`]'s contract. In
    /// practice the wrappers never store such an entry — a CRL or OCSP
    /// response without `nextUpdate` can never be served, because the
    /// checkers treat it as stale — so this is a statement about
    /// entries a consumer inserted directly.
    ///
    /// # Why the caller supplies `now`
    ///
    /// For the same reason `get_crl` does no freshness filtering: this
    /// crate's authoritative time is the caller's `now_unix`, not the
    /// wall clock. A cache that read `SystemTime::now()` to decide what
    /// to evict could discard entries the validator still considers
    /// live, or keep ones it considers expired. Pass the same clock the
    /// fetchers use.
    ///
    /// # Scheduling
    ///
    /// Deliberately not automatic. This cache spawns no threads and
    /// registers no timers, so there is nothing to call it; a consumer
    /// calls it from whatever maintenance tick it already has. Two
    /// separate write locks are taken, one per map, so a prune does not
    /// block readers of the other map.
    ///
    /// ```
    /// # use std::time::{Duration, SystemTime};
    /// # use pkix_revocation_http::{CachedCrl, CrlCacheKey, InMemoryCache, RevocationCache};
    /// let cache = InMemoryCache::new();
    /// let key = CrlCacheKey {
    ///     issuer_dn_der: vec![1, 2, 3],
    ///     distribution_point_uri: None,
    /// };
    /// let expires_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
    /// cache.put_crl(
    ///     key.clone(),
    ///     CachedCrl::new(None, SystemTime::UNIX_EPOCH, Some(expires_at), vec![0xaa]),
    /// );
    ///
    /// // A minute before it expires, nothing is reclaimed.
    /// assert_eq!(cache.prune_expired(expires_at - Duration::from_secs(60)), 0);
    /// assert_eq!(cache.len(), 1);
    ///
    /// // A minute after, the entry goes.
    /// assert_eq!(cache.prune_expired(expires_at + Duration::from_secs(60)), 1);
    /// assert!(cache.is_empty());
    /// ```
    pub fn prune_expired(&self, now: SystemTime) -> usize {
        let mut removed = 0;
        {
            let mut guard = self.crl.write().unwrap_or_else(PoisonError::into_inner);
            let before = guard.len();
            guard.retain(|_, e| is_live(e.next_update(), now));
            removed += before - guard.len();
        }
        {
            let mut guard = self.ocsp.write().unwrap_or_else(PoisonError::into_inner);
            let before = guard.len();
            guard.retain(|_, e| is_live(e.next_update(), now));
            removed += before - guard.len();
        }
        removed
    }

    /// Number of cached CRLs.
    ///
    /// Counts entries, fresh or expired, since nothing evicts on its own.
    /// Useful as a gauge to export: a count that only ever climbs is the
    /// signal that [`Self::prune_expired`] is not being called.
    #[must_use]
    pub fn crl_len(&self) -> usize {
        self.crl
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Number of cached OCSP responses. See [`Self::crl_len`].
    #[must_use]
    pub fn ocsp_len(&self) -> usize {
        self.ocsp
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Total number of cached entries across both maps.
    #[must_use]
    pub fn len(&self) -> usize {
        self.crl_len() + self.ocsp_len()
    }

    /// Whether the cache holds no entries at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drop every entry, expired or not.
    ///
    /// For a consumer that would rather rebuild the cache than reason
    /// about its contents — after a trust-store change, say, or a
    /// configuration reload that could alter which verdicts are
    /// determinative.
    pub fn clear(&self) {
        self.crl
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        self.ocsp
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }
}

impl fmt::Debug for InMemoryCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let crl_len = self
            .crl
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .len();
        let ocsp_len = self
            .ocsp
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .len();
        f.debug_struct("InMemoryCache")
            .field("crl_entries", &crl_len)
            .field("ocsp_entries", &ocsp_len)
            .finish()
    }
}

/// Returns `true` if `next_update` is `None` (treat as live) or strictly
/// after `now`. `next_update <= now` is expired.
#[cfg(any(feature = "crl", feature = "ocsp", test))]
fn is_live(next_update: Option<SystemTime>, now: SystemTime) -> bool {
    match next_update {
        None => true,
        Some(nu) => nu > now,
    }
}

/// Every method recovers a poisoned lock with [`PoisonError::into_inner`]
/// rather than degrading to a miss or a dropped write; see the
/// [`InMemoryCache`] type-level "Lock poisoning" notes for why that is
/// sound and why the alternatives are worse.
impl RevocationCache for InMemoryCache {
    /// Overridden so the compare and the insert happen under one write
    /// lock, closing the race the default get-then-put leaves open.
    #[cfg(feature = "crl")]
    fn put_crl_unless_rollback(&self, key: CrlCacheKey, entry: CachedCrl) -> bool {
        let mut guard = self.crl.write().unwrap_or_else(PoisonError::into_inner);
        if let Some(existing) = guard.get(&key) {
            if is_rollback(Some(existing.as_ref()), entry.crl_number()) {
                return false;
            }
        }
        guard.insert(key, Arc::new(entry));
        true
    }

    /// Overridden for the same reason as
    /// [`put_crl_unless_rollback`](Self::put_crl_unless_rollback).
    #[cfg(feature = "ocsp")]
    fn put_ocsp_unless_staler(&self, key: OcspCacheKey, entry: CachedOcspResponse) -> bool {
        let mut guard = self.ocsp.write().unwrap_or_else(PoisonError::into_inner);
        if let Some(existing) = guard.get(&key) {
            if is_staler_ocsp(Some(existing.as_ref()), entry.this_update()) {
                return false;
            }
        }
        guard.insert(key, Arc::new(entry));
        true
    }

    fn get_crl(&self, key: &CrlCacheKey) -> Option<Arc<CachedCrl>> {
        self.crl
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .cloned()
    }

    fn put_crl(&self, key: CrlCacheKey, entry: CachedCrl) {
        self.crl
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key, Arc::new(entry));
    }

    fn invalidate_crl(&self, key: &CrlCacheKey) {
        self.crl
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(key);
    }

    fn get_ocsp(&self, key: &OcspCacheKey) -> Option<Arc<CachedOcspResponse>> {
        self.ocsp
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .cloned()
    }

    fn put_ocsp(&self, key: OcspCacheKey, entry: CachedOcspResponse) {
        self.ocsp
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key, Arc::new(entry));
    }

    fn invalidate_ocsp(&self, key: &OcspCacheKey) {
        self.ocsp
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(key);
    }
}

// ---------------------------------------------------------------------------
// Internal parsing helpers
// ---------------------------------------------------------------------------

/// Parsed CRL freshness metadata returned by [`parse_crl_metadata`].
#[cfg(feature = "crl")]
#[derive(Debug)]
struct CrlMetadata {
    crl_number: Option<Vec<u8>>,
    this_update: SystemTime,
    next_update: Option<SystemTime>,
}

/// Extract `(crl_number_bytes, this_update, next_update)` from a
/// DER-encoded `CertificateList`.
///
/// Returns `Err` if the bytes do not decode as a `CertificateList`.
/// `crl_number_bytes` is `None` if the optional extension is absent or
/// fails to decode as an `INTEGER` (we are conservative: a malformed
/// CRLNumber is treated as "no monotonicity comparator available" rather
/// than fatal here — the wrapper's own CRL processing path will surface
/// any structural issue when it constructs a `CrlChecker`).
#[cfg(feature = "crl")]
fn parse_crl_metadata(der_bytes: &[u8]) -> Result<CrlMetadata, der::Error> {
    let crl =
        x509_cert::crl::CertificateList::<x509_cert::certificate::Rfc5280>::from_der(der_bytes)?;
    let tbs = &crl.tbs_cert_list;

    // CRLNumber lives in tbs.crl_extensions.
    let crl_number = tbs
        .crl_extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find(|e| e.extn_id == OID_CRL_NUMBER)
        .and_then(|ext| {
            // The extn_value carries an INTEGER. Use Uint to canonicalise
            // to unsigned big-endian bytes (strips any DER sign-prefix
            // zero). We swallow decode errors here — the wrapper's
            // CrlChecker::new path will surface a real parse error if the
            // structure is genuinely broken.
            der::asn1::Uint::from_der(ext.extn_value.as_bytes())
                .ok()
                .map(|u| u.as_bytes().to_vec())
        });

    let this_update = SystemTime::UNIX_EPOCH
        + core::time::Duration::from_secs(tbs.this_update.to_unix_duration().as_secs());
    let next_update = tbs.next_update.map(|t| {
        SystemTime::UNIX_EPOCH + core::time::Duration::from_secs(t.to_unix_duration().as_secs())
    });

    Ok(CrlMetadata {
        crl_number,
        this_update,
        next_update,
    })
}

/// Parsed OCSP freshness metadata returned by [`parse_ocsp_metadata`].
#[cfg(feature = "ocsp")]
#[derive(Debug)]
struct OcspMetadata {
    produced_at: SystemTime,
    this_update: SystemTime,
    next_update: Option<SystemTime>,
}

/// Extract `(produced_at, this_update, next_update)` from a DER-encoded
/// `OcspResponse`.
///
/// Returns `Err` on any decode failure or if the response is non-successful
/// or carries no `SingleResponse` for any cert. The wrapper falls back to
/// "treat as un-cacheable" in that situation.
#[cfg(feature = "ocsp")]
fn parse_ocsp_metadata(der_bytes: &[u8]) -> Result<OcspMetadata, der::Error> {
    use x509_ocsp::{BasicOcspResponse, OcspResponse, OcspResponseStatus};

    let outer = OcspResponse::from_der(der_bytes)?;
    if outer.response_status != OcspResponseStatus::Successful {
        return Err(der::Error::from(der::ErrorKind::Failed));
    }
    let resp_bytes = outer
        .response_bytes
        .as_ref()
        .ok_or_else(|| der::Error::from(der::ErrorKind::Failed))?;
    let basic = BasicOcspResponse::from_der(resp_bytes.response.as_bytes())?;

    let produced_at = SystemTime::UNIX_EPOCH
        + core::time::Duration::from_secs(
            basic
                .tbs_response_data
                .produced_at
                .as_ref()
                .to_unix_duration()
                .as_secs(),
        );

    // Use the first SingleResponse for cache metadata. OCSP responses
    // for path validation typically contain exactly one — multi-response
    // bundling is rare and a cache key keyed on one cert serial wouldn't
    // benefit from the others anyway.
    let single = basic
        .tbs_response_data
        .responses
        .first()
        .ok_or_else(|| der::Error::from(der::ErrorKind::Failed))?;

    let this_update = SystemTime::UNIX_EPOCH
        + core::time::Duration::from_secs(single.this_update.as_ref().to_unix_duration().as_secs());
    let next_update = single.next_update.as_ref().map(|t| {
        SystemTime::UNIX_EPOCH
            + core::time::Duration::from_secs(t.as_ref().to_unix_duration().as_secs())
    });

    Ok(OcspMetadata {
        produced_at,
        this_update,
        next_update,
    })
}

/// Decide whether a newly-fetched CRL is a rollback relative to the
/// currently-cached entry.
///
/// Returns `true` (rollback — drop the incoming entry) iff:
///
/// - there IS a prior cached entry, and
/// - the prior entry carried a `CRLNumber`, and
/// - the incoming entry carries a `CRLNumber`, and
/// - the prior `CRLNumber` is strictly greater than the incoming one.
///
/// Any other combination (no prior, prior without a number, incoming
/// without a number, equal numbers, or incoming higher) returns `false`
/// — the cache should accept the new entry.
///
/// RFC 5280 §5.2.3 makes `CRLNumber` monotonic per series; a refresh
/// that goes backwards is either a misconfigured responder serving a
/// stale snapshot or an attack.
#[cfg(feature = "crl")]
fn is_rollback(prior: Option<&CachedCrl>, incoming: Option<&[u8]>) -> bool {
    match (prior, incoming) {
        (Some(p), Some(inc)) => match p.crl_number() {
            Some(prior_num) => crl_number_gt(prior_num, inc),
            None => false,
        },
        _ => false,
    }
}

/// Compare two `CRLNumber` byte strings (canonical unsigned-integer
/// big-endian) for monotonicity. Returns `true` iff `incoming > stored`.
///
/// Both values are stripped of any DER sign-prefix zero (we store the
/// `Uint::as_bytes()` representation). Length-normalise by left-padding
/// the shorter with zeros, then compare lexicographically.
#[cfg(feature = "crl")]
fn crl_number_gt(incoming: &[u8], stored: &[u8]) -> bool {
    let len = incoming.len().max(stored.len());
    let mut a = vec![0u8; len];
    let mut b = vec![0u8; len];
    a[len - incoming.len()..].copy_from_slice(incoming);
    b[len - stored.len()..].copy_from_slice(stored);
    a > b
}

/// Decide whether a newly-fetched OCSP response carries staler status
/// than the currently-cached entry.
///
/// Returns `true` (drop the incoming entry) iff there is a prior cached
/// entry whose `SingleResponse.thisUpdate` is strictly later than the
/// incoming one's. Equal `thisUpdate` values are not staler, so a
/// re-signed copy of equally fresh status still replaces the entry.
///
/// # Why `thisUpdate` and not `producedAt`
///
/// RFC 6960 §4.2.2.1 defines `thisUpdate` as the time at which the
/// status being indicated is known to have been correct, and `producedAt`
/// as the time the response was signed. Only the former measures the
/// freshness of the *status*: a responder may re-sign an old snapshot,
/// giving a new `producedAt` over an unchanged `thisUpdate`. Comparing
/// `producedAt` would let that re-signed stale snapshot displace a
/// genuinely newer answer.
///
/// # Why this matters
///
/// Revocation is monotone — a certificate that has been revoked does not
/// become un-revoked. Without this guard, a cached `revoked` response
/// could be overwritten by an older `good` one that is still inside its
/// own `nextUpdate` window, and every later cache hit would report the
/// certificate as good. That happens without an attacker: two threads
/// validating the same certificate at once can have their responses land
/// in the opposite order to the one they were fetched in.
#[cfg(feature = "ocsp")]
fn is_staler_ocsp(prior: Option<&CachedOcspResponse>, incoming_this_update: SystemTime) -> bool {
    match prior {
        Some(p) => p.this_update() > incoming_this_update,
        None => false,
    }
}

// ---------------------------------------------------------------------------
// CachedHttpCrlFetcher
// ---------------------------------------------------------------------------

/// [`HttpCrlFetcher`]-shaped wrapper that consults a [`RevocationCache`]
/// before issuing network requests, and populates the cache only with CRLs
/// that have produced a verified verdict.
///
/// # Lookup flow
///
/// For each candidate CDP URL on a certificate:
///
/// 1. Compute the [`CrlCacheKey`]: `(issuer_dn, Some(url))`, where
///    `issuer_dn` is the issuer certificate's subject (or the trust
///    anchor's subject in `check_revocation_against_anchor`).
/// 2. `cache.get_crl(&key)` — on a live hit (`nextUpdate` in the future),
///    hand the cached bytes to a fresh [`pkix_revocation::CrlChecker`]. A
///    *determinative* verdict (`Ok(())` or [`RevError::Revoked`]) is
///    returned; any other outcome (for example `CrlExpired` because the
///    clock passed `nextUpdate`, or an out-of-scope result) falls through
///    to a network refetch of the same URL. Undecodable cached bytes are
///    invalidated.
/// 3. On miss, fetch the URL via the underlying [`RevocationFetcher`].
/// 4. The fetched CRL's verdict is returned exactly as [`HttpCrlFetcher`]
///    would return it. The CRL is cached **only** when that verdict is
///    determinative — which implies its signature, issuer and validity
///    window were verified — and it carries a `nextUpdate`. Unverified
///    bytes (bad signature, wrong issuer, expired, …) therefore never reach
///    the cache, and neither does their `CRLNumber`.
/// 5. **Rollback rejection:** if a cached entry exists for this key with a
///    `CRLNumber` numerically greater than the fetched (verified) one, the
///    new entry is not stored. RFC 5280 §5.2.3 makes CRLNumber monotonic
///    per series; a refresh that goes backwards is either a misconfigured
///    responder serving a stale snapshot or an attack. The verdict of the
///    fetched CRL is still returned.
///
/// `Clone` is derived to mirror [`HttpCrlFetcher`]; consumers typically
/// `Arc`-share the cache and `Clone` the wrapper.
#[cfg(feature = "crl")]
#[cfg_attr(docsrs, doc(cfg(feature = "crl")))]
#[derive(Clone, Debug)]
pub struct CachedHttpCrlFetcher<F, V, C> {
    pub(crate) inner: HttpCrlFetcher<F, V>,
    pub(crate) cache: C,
}

#[cfg(feature = "crl")]
impl<F, V, C> CachedHttpCrlFetcher<F, V, C> {
    /// Wrap an existing [`HttpCrlFetcher`] with a [`RevocationCache`].
    ///
    /// The cache `C` is moved in. To share one cache across multiple
    /// wrappers (e.g. a CRL fetcher and an OCSP fetcher sharing storage),
    /// store it as `Arc<dyn RevocationCache>` and use that as `C`.
    pub const fn new(inner: HttpCrlFetcher<F, V>, cache: C) -> Self {
        Self { inner, cache }
    }
}

/// `true` for verdicts that required a fully verified revocation source:
/// "not revoked" or "revoked". Only such sources are cached or served from
/// the cache.
#[cfg(any(feature = "crl", feature = "ocsp"))]
fn is_determinative(verdict: &pkix_revocation::Result<()>) -> bool {
    matches!(verdict, Ok(()) | Err(RevError::Revoked { .. }))
}

#[cfg(feature = "crl")]
impl<F, V, C> RevocationChecker for CachedHttpCrlFetcher<F, V, C>
where
    F: RevocationFetcher,
    V: SignatureVerifier + Clone,
    C: RevocationCache,
{
    fn check_revocation(
        &self,
        cert: &Certificate,
        issuer: &Certificate,
    ) -> pkix_revocation::Result<()> {
        self.fetch_and_check(cert, issuer.tbs_certificate().subject(), |checker| {
            checker.check_revocation(cert, issuer)
        })
    }

    /// Same cached fetch flow, keyed by and verified against `anchor`
    /// (see [`HttpCrlFetcher`]'s anchor support).
    fn check_revocation_against_anchor(
        &self,
        cert: &Certificate,
        anchor: &TrustAnchor,
    ) -> pkix_revocation::Result<()> {
        self.fetch_and_check(cert, &anchor.subject, |checker| {
            checker.check_revocation_against_anchor(cert, anchor)
        })
    }
}

#[cfg(feature = "crl")]
impl<F, V, C> CachedHttpCrlFetcher<F, V, C>
where
    F: RevocationFetcher,
    V: SignatureVerifier + Clone,
    C: RevocationCache,
{
    /// Cached fetch loop shared by both [`RevocationChecker`] methods.
    /// `issuer_subject` keys the cache; `verdict` runs the issuer- or
    /// anchor-flavoured `CrlChecker` check.
    fn fetch_and_check(
        &self,
        cert: &Certificate,
        issuer_subject: &x509_cert::name::Name,
        verdict: impl Fn(&pkix_revocation::CrlChecker<V>) -> pkix_revocation::Result<()>,
    ) -> pkix_revocation::Result<()> {
        use pkix_revocation::CrlChecker;

        // Step 1 — CDP extraction (same as HttpCrlFetcher).
        let urls =
            crate::extract_cdp_http_urls(cert).map_err(|e| RevError::RevocationFetchFailed {
                description: format!("cRLDistributionPoints extension parse failed: {e}"),
            })?;
        if urls.is_empty() {
            return Ok(());
        }

        // Issuer-DN bytes are computed once and reused for every key.
        // A non-encodable Name shouldn't happen on a successfully-parsed
        // cert; if it does, fall back to "no cache hits possible".
        let issuer_dn_der = issuer_subject.to_der().ok();

        // Sampled once for the whole check, not per URL: a clock read
        // between two candidate distribution points could straddle a
        // nextUpdate boundary and judge two CRLs in the same check
        // against different instants.
        let now_unix = self.inner.clock.now_unix();
        let now = SystemTime::UNIX_EPOCH + core::time::Duration::from_secs(now_unix);

        // Cap the walk. URLs are tried in listed order and the loop
        // returns on the first determinative verdict, so this only bites
        // when they are failing -- which is exactly the case where an
        // uncapped walk costs (URLs listed) x (per-request timeout).
        //
        // Note the cap truncates before the cache lookup, not just before
        // the fetch, so a cached entry for a URL past the cap is not
        // consulted. That is sound because an entry can only be here if
        // this wrapper fetched it, and that fetch was itself inside the
        // cap at the same position. The one way it costs anything: if a
        // CA reorders its distribution points between certificates, an
        // entry cached when a URL sat inside the cap becomes unreachable
        // once it sits outside, and that URL is refetched. A wasted
        // request, not a wrong answer.
        let budget = self.inner.max_urls;
        let attempted = urls.len().min(budget);
        let mut failures: Vec<String> = Vec::with_capacity(attempted);
        for url in urls.iter().take(budget) {
            // Step 2 — Cache lookup.
            let key = issuer_dn_der.as_ref().map(|der| CrlCacheKey {
                issuer_dn_der: der.clone(),
                distribution_point_uri: Some(url.clone()),
            });
            if let Some(cached) = key
                .as_ref()
                .and_then(|k| self.cache.get_crl(k))
                .filter(|e| is_live(e.next_update(), now))
            {
                match CrlChecker::new(cached.bytes(), now_unix, self.inner.verifier.clone()) {
                    Ok(checker) => {
                        let cached_verdict = verdict(&checker);
                        if is_determinative(&cached_verdict) {
                            return cached_verdict;
                        }
                        // Not determinative for this cert (e.g. the
                        // clock moved past a boundary): refetch below
                        // rather than pinning the cached outcome.
                        if let Err(e) = cached_verdict {
                            failures.push(format!("{url}: cached CRL: {e}"));
                        }
                    }
                    Err(e) => {
                        // Treat a corrupt cache entry as a miss. Invalidate
                        // and fall through to network fetch so a one-off
                        // corruption doesn't permanently break this URL.
                        if let Some(k) = key.as_ref() {
                            self.cache.invalidate_crl(k);
                        }
                        failures.push(format!("{url}: cached CRL parse: {e}"));
                    }
                }
            }

            // Step 3 — Cache miss (or unusable hit). Fetch over the network.
            let req = FetchRequest::get(url);
            match self.inner.fetcher.fetch(&req) {
                Ok(resp) => {
                    // Step 4 — Try to build a CrlChecker. If parse fails,
                    // fall through to next URL exactly as HttpCrlFetcher does.
                    match CrlChecker::new(&resp.bytes, now_unix, self.inner.verifier.clone()) {
                        Ok(checker) => {
                            let fetched_verdict = verdict(&checker);
                            // Cache only CRLs that produced a verified
                            // verdict (signature, issuer and freshness all
                            // checked); see the type-level docs.
                            if is_determinative(&fetched_verdict) {
                                self.maybe_populate_cache(&resp, key);
                            }
                            return fetched_verdict;
                        }
                        Err(e) => {
                            failures.push(format!("{url}: CRL parse: {e}"));
                            continue;
                        }
                    }
                }
                Err(e) => {
                    failures.push(format!("{url}: {e}"));
                    continue;
                }
            }
        }

        Err(crate::all_urls_failed(attempted, urls.len(), &failures))
    }

    /// Parse freshness metadata out of a fetched, **already verified** CRL
    /// response and store it under `key`. Drops the new entry if
    /// `CRLNumber` monotonicity would be violated, and never stores a CRL
    /// without `nextUpdate` (it could never be served: `CrlChecker` treats
    /// a missing `nextUpdate` as expired).
    ///
    /// Goes through [`RevocationCache::put_crl_unless_rollback`] rather
    /// than `put_crl`, so the rollback check and the insert are one
    /// operation for any cache that overrides it — eliminating the
    /// TOCTOU race in a separate `get_crl` / `put_crl` pair.
    ///
    /// Best-effort: any parse failure here is silent (the response is
    /// already known to be a valid CRL — `CrlChecker::new` accepted it —
    /// so a failure to extract optional metadata is a non-fatal
    /// inconsistency).
    fn maybe_populate_cache(&self, resp: &FetchResponse, key: Option<CrlCacheKey>) {
        let Some(key) = key else {
            return;
        };
        let Ok(meta) = parse_crl_metadata(&resp.bytes) else {
            return;
        };
        if meta.next_update.is_none() {
            return;
        }

        self.cache.put_crl_unless_rollback(
            key,
            CachedCrl::new(
                meta.crl_number,
                meta.this_update,
                meta.next_update,
                resp.bytes.clone(),
            ),
        );
    }
}

// ---------------------------------------------------------------------------
// CachedHttpOcspFetcher
// ---------------------------------------------------------------------------

/// [`HttpOcspFetcher`]-shaped wrapper that consults a [`RevocationCache`]
/// before POSTing OCSP requests.
///
/// Same flow as [`CachedHttpCrlFetcher`] but for OCSP:
///
/// 1. Build the OCSP request body via [`crate::build_ocsp_request`] (or
///    [`crate::build_ocsp_request_for_anchor`] in the anchor flow); its
///    `CertID` serial and `issuerKeyHash` form the cache key.
/// 2. For each AIA OCSP URL, look up
///    `(cert_serial, issuer_key_hash, responder_url)` in the cache.
/// 3. On a live hit, construct an [`pkix_revocation::OcspChecker`] from the
///    cached bytes; a determinative verdict (`Ok(())` / `Revoked`) is
///    returned, anything else falls through to a network refetch.
/// 4. On miss, POST the request body. The response is cached only if its
///    verdict was determinative (so its signature, responder and
///    freshness were verified) and its `SingleResponse` has a
///    `nextUpdate`.
/// 5. **Staleness rejection:** if a cached entry exists for this key
///    whose `SingleResponse.thisUpdate` is later than the fetched one's,
///    the new entry is not stored. Revocation is monotone, so letting an
///    older `good` response displace a cached `revoked` one would make
///    every subsequent cache hit report a revoked certificate as good.
///    The verdict of the fetched response is still returned. See
///    [`RevocationCache::put_ocsp_unless_staler`].
#[cfg(feature = "ocsp")]
#[cfg_attr(docsrs, doc(cfg(feature = "ocsp")))]
#[derive(Clone, Debug)]
pub struct CachedHttpOcspFetcher<F, V, C> {
    pub(crate) inner: HttpOcspFetcher<F, V>,
    pub(crate) cache: C,
}

#[cfg(feature = "ocsp")]
impl<F, V, C> CachedHttpOcspFetcher<F, V, C> {
    /// Wrap an existing [`HttpOcspFetcher`] with a [`RevocationCache`].
    pub const fn new(inner: HttpOcspFetcher<F, V>, cache: C) -> Self {
        Self { inner, cache }
    }
}

#[cfg(feature = "ocsp")]
impl<F, V, C> RevocationChecker for CachedHttpOcspFetcher<F, V, C>
where
    F: RevocationFetcher,
    V: SignatureVerifier + Clone,
    C: RevocationCache,
{
    fn check_revocation(
        &self,
        cert: &Certificate,
        issuer: &Certificate,
    ) -> pkix_revocation::Result<()> {
        // Build the OCSP request once; reuse for cache-key derivation
        // AND as the POST body on miss.
        let req_bytes = crate::build_ocsp_request(cert, issuer, self.inner.hash_alg)
            .map_err(crate::ocsp::request_build_failed)?;
        self.fetch_and_check(cert, &req_bytes, |checker| {
            checker.check_revocation(cert, issuer)
        })
    }

    /// Same cached flow with a `CertID` computed from `anchor` and the
    /// response verified against it.
    fn check_revocation_against_anchor(
        &self,
        cert: &Certificate,
        anchor: &TrustAnchor,
    ) -> pkix_revocation::Result<()> {
        let req_bytes = crate::build_ocsp_request_for_anchor(cert, anchor, self.inner.hash_alg)
            .map_err(crate::ocsp::request_build_failed)?;
        self.fetch_and_check(cert, &req_bytes, |checker| {
            checker.check_revocation_against_anchor(cert, anchor)
        })
    }
}

#[cfg(feature = "ocsp")]
impl<F, V, C> CachedHttpOcspFetcher<F, V, C>
where
    F: RevocationFetcher,
    V: SignatureVerifier + Clone,
    C: RevocationCache,
{
    /// Cached POST loop shared by both [`RevocationChecker`] methods.
    fn fetch_and_check(
        &self,
        cert: &Certificate,
        req_bytes: &crate::OcspRequestBytes,
        verdict: impl Fn(&pkix_revocation::OcspChecker<V>) -> pkix_revocation::Result<()>,
    ) -> pkix_revocation::Result<()> {
        use pkix_revocation::OcspChecker;

        let aia =
            crate::extract_aia_http_urls(cert).map_err(|e| RevError::RevocationFetchFailed {
                description: format!("authorityInfoAccess extension parse failed: {e}"),
            })?;
        if aia.ocsp.is_empty() {
            return Ok(());
        }

        // The CertID identity comes from the builder that produced
        // `req_bytes`, not from re-decoding its body. Re-decoding would
        // repeat work already done and, worse, add a failure path for
        // bytes this crate encoded itself: a decode error there used to
        // abort the whole check with RevocationFetchFailed even though a
        // perfectly good request body was in hand.
        let cert_serial = &req_bytes.cert_serial;
        let issuer_key_hash = &req_bytes.issuer_key_hash;
        // Sampled once for the whole check; see the CRL twin.
        let now_unix = self.inner.clock.now_unix();
        let now = SystemTime::UNIX_EPOCH + core::time::Duration::from_secs(now_unix);

        // Cap the walk; see the CRL twin.
        let budget = self.inner.max_urls;
        let attempted = aia.ocsp.len().min(budget);
        let mut failures: Vec<String> = Vec::with_capacity(attempted);
        for url in aia.ocsp.iter().take(budget) {
            let key = OcspCacheKey {
                cert_serial: cert_serial.clone(),
                issuer_key_hash: issuer_key_hash.clone(),
                responder_url: url.clone(),
            };

            if let Some(cached) = self
                .cache
                .get_ocsp(&key)
                .filter(|e| is_live(e.next_update(), now))
            {
                match OcspChecker::new(cached.bytes(), now_unix, self.inner.verifier.clone()) {
                    Ok(checker) => {
                        let cached_verdict = verdict(&checker);
                        if is_determinative(&cached_verdict) {
                            return cached_verdict;
                        }
                        // Not determinative: refetch below.
                        if let Err(e) = cached_verdict {
                            failures.push(format!("{url}: cached OCSP: {e}"));
                        }
                    }
                    Err(e) => {
                        self.cache.invalidate_ocsp(&key);
                        failures.push(format!("{url}: cached OCSP parse: {e}"));
                    }
                }
            }

            let req = FetchRequest::post(url, &req_bytes.body, crate::OCSP_REQUEST_CT);
            match self.inner.fetcher.fetch(&req) {
                Ok(resp) => {
                    match OcspChecker::new(&resp.bytes, now_unix, self.inner.verifier.clone()) {
                        Ok(checker) => {
                            let fetched_verdict = verdict(&checker);
                            // Cache only verified responses; see type docs.
                            if is_determinative(&fetched_verdict) {
                                self.maybe_populate_cache(&resp, key);
                            }
                            return fetched_verdict;
                        }
                        Err(e) => {
                            failures.push(format!("{url}: OCSP parse: {e}"));
                            continue;
                        }
                    }
                }
                Err(e) => {
                    failures.push(format!("{url}: {e}"));
                    continue;
                }
            }
        }

        Err(crate::all_urls_failed(attempted, aia.ocsp.len(), &failures))
    }

    /// Parse freshness metadata out of a fetched, **already verified** OCSP
    /// response and store it under `key`. Responses without `nextUpdate`
    /// are not stored (`OcspChecker` treats them as stale). Best-effort;
    /// silent on metadata parse failure.
    ///
    /// Goes through [`RevocationCache::put_ocsp_unless_staler`] rather
    /// than `put_ocsp`, so a response carrying older status cannot
    /// displace a newer one.
    fn maybe_populate_cache(&self, resp: &FetchResponse, key: OcspCacheKey) {
        let Ok(meta) = parse_ocsp_metadata(&resp.bytes) else {
            return;
        };
        if meta.next_update.is_none() {
            return;
        }
        self.cache.put_ocsp_unless_staler(
            key,
            CachedOcspResponse::new(
                meta.produced_at,
                meta.this_update,
                meta.next_update,
                resp.bytes.clone(),
            ),
        );
    }
}

// ---------------------------------------------------------------------------
// Trait-object adapter
// ---------------------------------------------------------------------------

// Allow `Arc<dyn RevocationCache>` to be used directly as the `C` type
// parameter of the wrappers. Without these blanket impls, callers wanting
// to share one cache between a CRL and an OCSP fetcher would need to
// either (a) clone the concrete cache (defeats sharing) or (b) wrap the
// trait object in a newtype.

impl<T: RevocationCache + ?Sized> RevocationCache for Arc<T> {
    fn get_crl(&self, key: &CrlCacheKey) -> Option<Arc<CachedCrl>> {
        (**self).get_crl(key)
    }
    fn put_crl(&self, key: CrlCacheKey, entry: CachedCrl) {
        (**self).put_crl(key, entry)
    }
    fn invalidate_crl(&self, key: &CrlCacheKey) {
        (**self).invalidate_crl(key)
    }
    fn get_ocsp(&self, key: &OcspCacheKey) -> Option<Arc<CachedOcspResponse>> {
        (**self).get_ocsp(key)
    }
    fn put_ocsp(&self, key: OcspCacheKey, entry: CachedOcspResponse) {
        (**self).put_ocsp(key, entry)
    }
    fn invalidate_ocsp(&self, key: &OcspCacheKey) {
        (**self).invalidate_ocsp(key)
    }

    // The guarded inserts must be forwarded too, not left to the trait
    // defaults. Omitting them compiles and behaves almost correctly,
    // which is what makes it dangerous: `Arc<InMemoryCache>` and
    // `Arc<dyn RevocationCache>` would silently fall back to the
    // non-atomic get-then-put and lose the single-lock guarantee the
    // inner cache overrides them to provide — and `Arc<dyn
    // RevocationCache>` is the pattern these wrappers document for
    // sharing one store between the CRL and OCSP fetchers.
    #[cfg(feature = "crl")]
    fn put_crl_unless_rollback(&self, key: CrlCacheKey, entry: CachedCrl) -> bool {
        (**self).put_crl_unless_rollback(key, entry)
    }
    #[cfg(feature = "ocsp")]
    fn put_ocsp_unless_staler(&self, key: OcspCacheKey, entry: CachedOcspResponse) -> bool {
        (**self).put_ocsp_unless_staler(key, entry)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! Unit tests for the cache module.
    //!
    //! Test oracles:
    //! - Reuses CRL + OCSP fixtures generated by pyca/cryptography
    //!   (tests/fixtures/gen_http_crl_fixtures.py). These are independent
    //!   of the code under test (pyca emitted them; pkix-revocation parses
    //!   them).
    //! - For freshness/TTL behaviour, constructs `CachedCrl` /
    //!   `CachedOcspResponse` entries directly with chosen timestamps —
    //!   no dependence on the parsing helpers under test.
    //! - For monotonicity, tests `crl_number_gt` directly with hand-built
    //!   byte strings.

    use super::*;
    use std::time::{Duration, SystemTime};

    // -----------------------------------------------------------------
    // is_live + freshness
    // -----------------------------------------------------------------

    #[test]
    fn is_live_treats_none_as_live() {
        assert!(is_live(None, SystemTime::now()));
    }

    #[test]
    fn is_live_returns_true_when_next_update_is_in_future() {
        let now = SystemTime::now();
        let future = now + Duration::from_secs(60);
        assert!(is_live(Some(future), now));
    }

    #[test]
    fn is_live_returns_false_when_next_update_is_in_past() {
        let now = SystemTime::now();
        let past = now - Duration::from_secs(60);
        assert!(!is_live(Some(past), now));
    }

    #[test]
    fn is_live_returns_false_when_next_update_equals_now() {
        // Boundary: nextUpdate == now is treated as expired (strictly
        // greater than required for "still live").
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        assert!(!is_live(Some(now), now));
    }

    // -----------------------------------------------------------------
    // CRL number monotonicity
    // -----------------------------------------------------------------

    #[cfg(feature = "crl")]
    #[test]
    fn crl_number_gt_compares_lexicographically_after_length_normalisation() {
        // "5" > "3"
        assert!(crl_number_gt(&[5], &[3]));
        // "3" > "5" — false
        assert!(!crl_number_gt(&[3], &[5]));
        // "3" > "3" — equal, not greater
        assert!(!crl_number_gt(&[3], &[3]));
    }

    #[cfg(feature = "crl")]
    #[test]
    fn crl_number_gt_handles_different_lengths() {
        // "0x01_00" (256) > "0xff" (255). Naive byte comparison without
        // length-normalisation would say 0x01 < 0xff and get this wrong;
        // the normaliser left-pads to [0xff, 0x00] vs [0x01, 0x00] which
        // would still be wrong. Use the actual normalised values:
        // incoming = [0x01, 0x00] (256), stored = [0xff] padded to
        // [0x00, 0xff] (255). 256 > 255.
        assert!(crl_number_gt(&[0x01, 0x00], &[0xff]));
        assert!(!crl_number_gt(&[0xff], &[0x01, 0x00]));
    }

    // -----------------------------------------------------------------
    // InMemoryCache: trait-level behaviour
    // -----------------------------------------------------------------

    fn dummy_crl_key(uri: Option<&str>) -> CrlCacheKey {
        CrlCacheKey {
            issuer_dn_der: b"\x30\x06\x06\x04test".to_vec(),
            distribution_point_uri: uri.map(|s| s.to_string()),
        }
    }

    fn dummy_crl_entry(crl_number: Option<Vec<u8>>, next_update: Option<SystemTime>) -> CachedCrl {
        CachedCrl {
            crl_number,
            this_update: SystemTime::UNIX_EPOCH,
            next_update,
            bytes: b"crl-bytes".to_vec(),
        }
    }

    fn dummy_ocsp_key(url: &str) -> OcspCacheKey {
        OcspCacheKey {
            cert_serial: vec![1, 2, 3],
            issuer_key_hash: vec![0xab; 32],
            responder_url: url.to_string(),
        }
    }

    fn dummy_ocsp_entry(next_update: Option<SystemTime>) -> CachedOcspResponse {
        CachedOcspResponse {
            produced_at: SystemTime::UNIX_EPOCH,
            this_update: SystemTime::UNIX_EPOCH,
            next_update,
            bytes: b"ocsp-bytes".to_vec(),
        }
    }

    #[test]
    fn in_memory_cache_returns_none_on_miss() {
        let c = InMemoryCache::new();
        let k = dummy_crl_key(None);
        assert!(c.get_crl(&k).is_none());
        let k2 = dummy_ocsp_key("http://x/");
        assert!(c.get_ocsp(&k2).is_none());
    }

    #[test]
    fn in_memory_cache_returns_some_on_hit() {
        let c = InMemoryCache::new();
        let future = SystemTime::now() + Duration::from_secs(3600);
        let k = dummy_crl_key(None);
        c.put_crl(k.clone(), dummy_crl_entry(None, Some(future)));
        let got = c.get_crl(&k).expect("hit");
        assert_eq!(got.bytes, b"crl-bytes");
    }

    #[test]
    fn in_memory_cache_returns_arc_value_for_zero_copy_share() {
        // Acceptance criterion: returns Arc<CachedCrl> so callers see
        // freshness metadata without re-parsing.
        let c = InMemoryCache::new();
        let future = SystemTime::now() + Duration::from_secs(3600);
        let k = dummy_crl_key(None);
        c.put_crl(k.clone(), dummy_crl_entry(Some(vec![7]), Some(future)));
        let a = c.get_crl(&k).unwrap();
        let b = c.get_crl(&k).unwrap();
        // Two Arc clones of the same stored entry. They wrap the same
        // allocation, which is observable through Arc::ptr_eq.
        assert!(Arc::ptr_eq(&a, &b), "Arc clones should share allocation");
        assert_eq!(a.crl_number.as_deref(), Some(&[7][..]));
    }

    #[test]
    fn in_memory_cache_returns_expired_entry_without_filtering() {
        // The cache layer returns entries regardless of freshness.
        // Freshness filtering is the wrapper's responsibility (it has
        // access to the caller's authoritative time source).
        let c = InMemoryCache::new();
        let past = SystemTime::now() - Duration::from_secs(60);
        let k = dummy_crl_key(None);
        c.put_crl(k.clone(), dummy_crl_entry(None, Some(past)));
        let got = c.get_crl(&k).expect("expired entry must still be returned");
        assert_eq!(got.bytes, b"crl-bytes");
    }

    #[test]
    fn in_memory_cache_returns_expired_ocsp_entry_without_filtering() {
        // Same as above for OCSP entries.
        let c = InMemoryCache::new();
        let past = SystemTime::now() - Duration::from_secs(60);
        let k = dummy_ocsp_key("http://x/");
        c.put_ocsp(k.clone(), dummy_ocsp_entry(Some(past)));
        let got = c
            .get_ocsp(&k)
            .expect("expired OCSP entry must still be returned");
        assert_eq!(got.bytes, b"ocsp-bytes");
    }

    #[test]
    fn in_memory_cache_invalidate_removes_entry() {
        let c = InMemoryCache::new();
        let future = SystemTime::now() + Duration::from_secs(3600);
        let k = dummy_crl_key(None);
        c.put_crl(k.clone(), dummy_crl_entry(None, Some(future)));
        assert!(c.get_crl(&k).is_some());
        c.invalidate_crl(&k);
        assert!(c.get_crl(&k).is_none());
    }

    #[test]
    fn in_memory_cache_invalidate_is_idempotent() {
        let c = InMemoryCache::new();
        let k = dummy_crl_key(None);
        // No prior put — invalidate must not panic.
        c.invalidate_crl(&k);
    }

    #[test]
    fn in_memory_cache_partitioned_crl_keying_isolates_by_uri() {
        // Acceptance criterion: partitioned-CRL (Some(uri)) keying.
        // Same issuer, two different DP URIs ⇒ two separate cache rows.
        let c = InMemoryCache::new();
        let future = SystemTime::now() + Duration::from_secs(3600);
        let k_a = dummy_crl_key(Some("http://a/crl"));
        let k_b = dummy_crl_key(Some("http://b/crl"));

        let entry_a = CachedCrl {
            crl_number: Some(vec![1]),
            this_update: SystemTime::UNIX_EPOCH,
            next_update: Some(future),
            bytes: b"crl-A".to_vec(),
        };
        let entry_b = CachedCrl {
            crl_number: Some(vec![1]),
            this_update: SystemTime::UNIX_EPOCH,
            next_update: Some(future),
            bytes: b"crl-B".to_vec(),
        };

        c.put_crl(k_a.clone(), entry_a);
        c.put_crl(k_b.clone(), entry_b);

        assert_eq!(c.get_crl(&k_a).unwrap().bytes, b"crl-A");
        assert_eq!(c.get_crl(&k_b).unwrap().bytes, b"crl-B");

        // None-keyed entry is separate from Some("...") entries.
        let k_none = dummy_crl_key(None);
        assert!(c.get_crl(&k_none).is_none());
    }

    #[test]
    fn in_memory_cache_concurrent_insert_smoke() {
        // Acceptance criterion: concurrent access safe.
        // Run many puts and gets across threads against one shared cache.
        // Pure data-race check; we do not assert ordering, just that the
        // run finishes and the cache is internally consistent at the end.
        use std::sync::Arc as StdArc;
        use std::thread;

        let cache = StdArc::new(InMemoryCache::new());
        let future = SystemTime::now() + Duration::from_secs(3600);

        let mut handles = Vec::new();
        for i in 0..16u8 {
            let c = StdArc::clone(&cache);
            handles.push(thread::spawn(move || {
                for j in 0..50u8 {
                    let k = CrlCacheKey {
                        issuer_dn_der: vec![i, j],
                        distribution_point_uri: Some(format!("http://{i}/{j}")),
                    };
                    c.put_crl(
                        k.clone(),
                        CachedCrl {
                            crl_number: Some(vec![j]),
                            this_update: SystemTime::UNIX_EPOCH,
                            next_update: Some(future),
                            bytes: vec![i, j],
                        },
                    );
                    let _ = c.get_crl(&k);
                }
            }));
        }
        for h in handles {
            h.join().expect("worker thread panicked");
        }
        // Final state: each thread inserted 50 distinct keys → 800 rows.
        // We can't access the map directly through the trait, so probe a
        // few known keys.
        for i in 0..16u8 {
            for j in [0u8, 25, 49] {
                let k = CrlCacheKey {
                    issuer_dn_der: vec![i, j],
                    distribution_point_uri: Some(format!("http://{i}/{j}")),
                };
                assert!(
                    cache.get_crl(&k).is_some(),
                    "expected entry ({i},{j}) to survive concurrent inserts"
                );
            }
        }
    }

    #[test]
    fn arc_trait_object_delegates_through() {
        // Compile-time + behavioural check that Arc<dyn RevocationCache>
        // is usable as a RevocationCache.
        let inner: Arc<dyn RevocationCache> = Arc::new(InMemoryCache::new());
        let future = SystemTime::now() + Duration::from_secs(3600);
        let k = dummy_crl_key(None);
        inner.put_crl(k.clone(), dummy_crl_entry(None, Some(future)));
        assert!(inner.get_crl(&k).is_some());
    }

    // -----------------------------------------------------------------
    // CRL metadata parser (oracle: pyca-generated fixtures)
    // -----------------------------------------------------------------

    #[cfg(feature = "crl")]
    #[test]
    fn parse_crl_metadata_extracts_fields_from_real_crl() {
        // Oracle: fixtures generated by pyca/cryptography. The generator
        // does NOT add a CRLNumber extension (gen_http_crl_fixtures.py),
        // so meta.crl_number must be None. thisUpdate/nextUpdate are
        // populated from the generator's validity window.
        const CRL: &[u8] = include_bytes!("../tests/fixtures/http-crl-empty.der");
        let meta = parse_crl_metadata(CRL).expect("real CRL must parse");
        assert!(
            meta.crl_number.is_none(),
            "fixture has no CRLNumber; parser must return None"
        );
        let next = meta.next_update.expect("fixture has nextUpdate");
        assert!(
            meta.this_update < next,
            "thisUpdate must precede nextUpdate"
        );
    }

    #[cfg(feature = "crl")]
    #[test]
    fn parse_crl_metadata_fails_on_garbage() {
        let err = parse_crl_metadata(&[0xff, 0xff, 0xff]).unwrap_err();
        // Just confirm we got an error; the specific der::ErrorKind is
        // an implementation detail of x509-cert.
        let _ = format!("{err}");
    }

    // -----------------------------------------------------------------
    // OCSP metadata parser
    // -----------------------------------------------------------------

    #[cfg(feature = "ocsp")]
    #[test]
    fn parse_ocsp_metadata_extracts_fields_from_real_response() {
        // Oracle: fixture generated by pyca with a 30-day window
        // (gen_http_crl_fixtures.py). We assert structural plausibility,
        // not exact timestamps — the generator may re-run.
        const RESP: &[u8] = include_bytes!("../tests/fixtures/http-ocsp-good.der");
        let meta = parse_ocsp_metadata(RESP).expect("real OCSP must parse");
        // thisUpdate ≤ nextUpdate is the load-bearing invariant; producedAt
        // can fall on either side of thisUpdate depending on whether the
        // responder pre-computed the response.
        let next = meta.next_update.expect("fixture has nextUpdate");
        assert!(
            meta.this_update <= next,
            "thisUpdate ≤ nextUpdate; got this={:?} next={:?}",
            meta.this_update,
            next
        );
        // producedAt must be a positive duration since the Unix epoch
        // (sanity — not 1970-01-01).
        assert!(meta.produced_at > SystemTime::UNIX_EPOCH);
    }

    #[cfg(feature = "ocsp")]
    #[test]
    fn parse_ocsp_metadata_fails_on_garbage() {
        let err = parse_ocsp_metadata(&[0xff, 0xff, 0xff]).unwrap_err();
        let _ = format!("{err}");
    }

    // -----------------------------------------------------------------
    // Lock poisoning
    // -----------------------------------------------------------------

    /// A panic in an unrelated thread must not disable the cache.
    ///
    /// `InMemoryCache` holds its maps behind `RwLock`. If a thread
    /// panics anywhere while holding one — or, as here, panics while
    /// holding it deliberately — the lock is left poisoned forever.
    /// The cache used to map that to `None` on every read and to a
    /// dropped write on every insert, so one unrelated panic turned the
    /// process's revocation cache into a permanent miss-everything
    /// black hole with nothing anywhere reporting it.
    #[test]
    fn a_poisoned_cache_still_stores_and_serves_entries() {
        let cache = Arc::new(InMemoryCache::new());

        // Poison both locks from a thread that panics while holding them.
        let poisoner = Arc::clone(&cache);
        let joined = std::thread::spawn(move || {
            let _crl = poisoner.crl.write().unwrap();
            panic!("deliberate panic to poison the CRL lock");
        })
        .join();
        assert!(joined.is_err(), "the poisoning thread must have panicked");

        let poisoner = Arc::clone(&cache);
        let joined = std::thread::spawn(move || {
            let _ocsp = poisoner.ocsp.write().unwrap();
            panic!("deliberate panic to poison the OCSP lock");
        })
        .join();
        assert!(joined.is_err(), "the poisoning thread must have panicked");

        assert!(
            cache.crl.is_poisoned() && cache.ocsp.is_poisoned(),
            "the test's premise is that both locks are now poisoned"
        );

        // A round trip must still work on both maps.
        let crl_key = CrlCacheKey {
            issuer_dn_der: vec![1, 2, 3],
            distribution_point_uri: Some("http://crl.example/a.crl".to_string()),
        };
        cache.put_crl(
            crl_key.clone(),
            CachedCrl {
                crl_number: Some(vec![7]),
                this_update: SystemTime::UNIX_EPOCH,
                next_update: None,
                bytes: vec![0xaa],
            },
        );
        let got = cache
            .get_crl(&crl_key)
            .expect("a poisoned lock must not turn a stored CRL into a miss");
        assert_eq!(got.bytes, vec![0xaa]);

        let ocsp_key = OcspCacheKey {
            cert_serial: vec![9],
            issuer_key_hash: vec![8],
            responder_url: "http://ocsp.example/".to_string(),
        };
        cache.put_ocsp(
            ocsp_key.clone(),
            CachedOcspResponse {
                produced_at: SystemTime::UNIX_EPOCH,
                this_update: SystemTime::UNIX_EPOCH,
                next_update: None,
                bytes: vec![0xbb],
            },
        );
        let got = cache
            .get_ocsp(&ocsp_key)
            .expect("a poisoned lock must not turn a stored OCSP response into a miss");
        assert_eq!(got.bytes, vec![0xbb]);

        // Invalidation and Debug must survive it too.
        cache.invalidate_crl(&crl_key);
        assert!(cache.get_crl(&crl_key).is_none());
        let rendered = format!("{cache:?}");
        assert!(
            rendered.contains("ocsp_entries: 1"),
            "Debug must report real counts through a poisoned lock, got {rendered}"
        );
    }

    /// `put_crl_if_not_rollback` returns `false` to mean exactly one
    /// thing: the insert was suppressed because it would roll back a
    /// newer CRL. It used to also return `false` for a poisoned lock,
    /// so a caller could not distinguish "I protected you from a stale
    /// CRL" from "my lock is broken and I silently stored nothing".
    #[cfg(feature = "crl")]
    #[test]
    fn a_poisoned_lock_does_not_masquerade_as_a_rollback() {
        let cache = Arc::new(InMemoryCache::new());
        let poisoner = Arc::clone(&cache);
        let _ = std::thread::spawn(move || {
            let _g = poisoner.crl.write().unwrap();
            panic!("deliberate panic to poison the CRL lock");
        })
        .join();
        assert!(cache.crl.is_poisoned());

        let key = CrlCacheKey {
            issuer_dn_der: vec![1],
            distribution_point_uri: None,
        };
        assert!(
            cache.put_crl_unless_rollback(
                key.clone(),
                CachedCrl {
                    crl_number: Some(vec![1]),
                    this_update: SystemTime::UNIX_EPOCH,
                    next_update: None,
                    bytes: vec![0xcc],
                },
            ),
            "an insert into a poisoned-but-consistent map is not a rollback"
        );
        assert!(cache.get_crl(&key).is_some());
    }

    // -----------------------------------------------------------------
    // CertID identity carried on OcspRequestBytes (OCSP cache-key source)
    // -----------------------------------------------------------------

    /// The identity fields the builder carries must agree with the
    /// `CertID` actually encoded in the body it produced.
    ///
    /// The wrapper keys its cache off `req_bytes.cert_serial` /
    /// `req_bytes.issuer_key_hash` and never decodes the body, so a drift
    /// between the two would key every entry under an identity no
    /// responder's answer corresponds to — a silent cache that never
    /// hits, or worse, hits under the wrong certificate's key. Decoding
    /// the body here is the independent oracle for that agreement.
    #[cfg(feature = "ocsp")]
    #[test]
    fn carried_cert_id_identity_matches_the_encoded_request_body() {
        use crate::{build_ocsp_request, OcspHashAlg};
        const CA: &[u8] = include_bytes!("../tests/fixtures/http-ca.der");
        const LEAF: &[u8] = include_bytes!("../tests/fixtures/http-leaf-good.der");
        let leaf = Certificate::from_der(LEAF).unwrap();
        let ca = Certificate::from_der(CA).unwrap();
        let req = build_ocsp_request(&leaf, &ca, OcspHashAlg::Sha256).unwrap();

        // Oracle: decode the body and read its CertID back out.
        let decoded =
            x509_ocsp::OcspRequest::<x509_cert::certificate::Rfc5280>::from_der(&req.body).unwrap();
        let cert_id = &decoded.tbs_request.request_list.first().unwrap().req_cert;

        assert_eq!(
            req.cert_serial,
            cert_id.serial_number.as_bytes(),
            "carried cert_serial must match the CertID in the encoded body"
        );
        assert_eq!(
            req.issuer_key_hash,
            cert_id.issuer_key_hash.as_bytes(),
            "carried issuer_key_hash must match the CertID in the encoded body"
        );

        // Second, independent oracle: the serial is the leaf's own, and
        // the SHA-256 issuerKeyHash is 32 bytes.
        assert_eq!(
            req.cert_serial,
            leaf.tbs_certificate().serial_number().as_bytes()
        );
        assert_eq!(req.issuer_key_hash.len(), 32);
    }

    /// The same agreement for the anchor flow, which computes the
    /// `CertID` from a [`TrustAnchor`] rather than an issuer certificate.
    #[cfg(feature = "ocsp")]
    #[test]
    fn carried_cert_id_identity_matches_the_body_in_the_anchor_flow() {
        use crate::{build_ocsp_request_for_anchor, OcspHashAlg};
        const CA: &[u8] = include_bytes!("../tests/fixtures/http-ca.der");
        const LEAF: &[u8] = include_bytes!("../tests/fixtures/http-leaf-good.der");
        let leaf = Certificate::from_der(LEAF).unwrap();
        let anchor = TrustAnchor::from_cert(Certificate::from_der(CA).unwrap());
        let req = build_ocsp_request_for_anchor(&leaf, &anchor, OcspHashAlg::Sha256).unwrap();

        let decoded =
            x509_ocsp::OcspRequest::<x509_cert::certificate::Rfc5280>::from_der(&req.body).unwrap();
        let cert_id = &decoded.tbs_request.request_list.first().unwrap().req_cert;

        assert_eq!(req.cert_serial, cert_id.serial_number.as_bytes());
        assert_eq!(req.issuer_key_hash, cert_id.issuer_key_hash.as_bytes());
    }

    // -----------------------------------------------------------------
    // CachedHttpCrlFetcher: cache miss → fetch → populate → hit
    // -----------------------------------------------------------------

    #[cfg(feature = "crl")]
    mod crl_wrapper {
        use super::*;
        use crate::{FetchError, FetchRequest, FetchResponse, HttpCrlFetcher};
        use pkix_path::DefaultVerifier;
        use std::cell::RefCell;

        const CA: &[u8] = include_bytes!("../tests/fixtures/http-ca.der");
        const LEAF_GOOD: &[u8] = include_bytes!("../tests/fixtures/http-leaf-good.der");
        const CRL_EMPTY: &[u8] = include_bytes!("../tests/fixtures/http-crl-empty.der");

        /// Matches the test timestamp used in crl.rs (within the
        /// 2026-06-01 .. 2026-07-01 window — between thisUpdate and
        /// nextUpdate of the fixture CRL).
        const NOW: u64 = 1_780_272_000;

        struct CountingFetcher {
            crl_bytes: Vec<u8>,
            seen: RefCell<usize>,
        }
        impl RevocationFetcher for CountingFetcher {
            fn fetch(&self, _req: &FetchRequest<'_>) -> Result<FetchResponse, FetchError> {
                *self.seen.borrow_mut() += 1;
                Ok(FetchResponse {
                    bytes: self.crl_bytes.clone(),
                    content_type: Some("application/pkix-crl".into()),
                })
            }
        }

        fn cert(b: &[u8]) -> Certificate {
            Certificate::from_der(b).unwrap()
        }

        #[test]
        fn cache_miss_then_hit_avoids_second_fetch() {
            let fetcher = CountingFetcher {
                crl_bytes: CRL_EMPTY.to_vec(),
                seen: RefCell::new(0),
            };
            let inner = HttpCrlFetcher::new(fetcher, DefaultVerifier, NOW);
            let cache = InMemoryCache::new();
            let cached = CachedHttpCrlFetcher::new(inner, cache);

            // First call: cache miss → fetch.
            cached
                .check_revocation(&cert(LEAF_GOOD), &cert(CA))
                .expect("first call succeeds");
            assert_eq!(*cached.inner.fetcher.seen.borrow(), 1);

            // Second call: cache hit → no additional fetch.
            cached
                .check_revocation(&cert(LEAF_GOOD), &cert(CA))
                .expect("second call succeeds");
            assert_eq!(
                *cached.inner.fetcher.seen.borrow(),
                1,
                "cache hit should not refetch"
            );
        }

        #[test]
        fn cache_populated_under_partitioned_uri_key() {
            // Acceptance criterion: each fetched URL is stored under
            // CrlCacheKey { distribution_point_uri: Some(url), .. } so
            // partitioned CRLs don't collide.
            let fetcher = CountingFetcher {
                crl_bytes: CRL_EMPTY.to_vec(),
                seen: RefCell::new(0),
            };
            let inner = HttpCrlFetcher::new(fetcher, DefaultVerifier, NOW);
            let cache: Arc<dyn RevocationCache> = Arc::new(InMemoryCache::new());
            let cached = CachedHttpCrlFetcher::new(inner, Arc::clone(&cache));

            cached
                .check_revocation(&cert(LEAF_GOOD), &cert(CA))
                .unwrap();

            // The fixture's leaf advertises exactly one CDP URL:
            // http://crl.example.com/test.crl (see crl.rs tests).
            let issuer_dn = cert(CA).tbs_certificate().subject().to_der().unwrap();
            let key = CrlCacheKey {
                issuer_dn_der: issuer_dn,
                distribution_point_uri: Some("http://crl.example.com/test.crl".to_string()),
            };
            let got = cache
                .get_crl(&key)
                .expect("CRL must be cached under DP URI key");
            assert_eq!(got.bytes, CRL_EMPTY);
        }

        /// Freshness must be judged against the caller's `now_unix`, never the
        /// wall clock.
        ///
        /// The cache and the validator have to agree about whether a response
        /// is still fresh. If the cache consulted `SystemTime::now()` while
        /// the validator used a caller-supplied instant, the two could
        /// disagree — and the consequences land on exactly the deployments
        /// that pin time deliberately: offline validation, replaying an
        /// archived chain, and any reproducible audit.
        ///
        /// This entry expires one hour after `NOW` (2026-06-01), which is in
        /// the **past** by wall clock and in the **future** by `now_unix`. A
        /// cache judging freshness correctly serves it; one reading the wall
        /// clock calls it stale and refetches, so `seen` becomes 1 and this
        /// test fails.
        ///
        /// The direction is durable: wall clock only moves further past `NOW`.
        #[test]
        fn freshness_is_judged_against_now_unix_not_the_wall_clock() {
            let fetcher = CountingFetcher {
                crl_bytes: CRL_EMPTY.to_vec(),
                seen: RefCell::new(0),
            };
            let inner = HttpCrlFetcher::new(fetcher, DefaultVerifier, NOW);
            let cache = InMemoryCache::new();

            let issuer_dn = cert(CA).tbs_certificate().subject().to_der().unwrap();
            let key = CrlCacheKey {
                issuer_dn_der: issuer_dn,
                distribution_point_uri: Some("http://crl.example.com/test.crl".to_string()),
            };
            cache.put_crl(
                key,
                CachedCrl {
                    crl_number: None,
                    this_update: SystemTime::UNIX_EPOCH,
                    // One hour after the pinned NOW: future for the validator,
                    // long past for the wall clock.
                    next_update: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(NOW + 3600)),
                    bytes: CRL_EMPTY.to_vec(),
                },
            );

            let cached = CachedHttpCrlFetcher::new(inner, cache);
            cached
                .check_revocation(&cert(LEAF_GOOD), &cert(CA))
                .expect("the cached CRL is live at now_unix and must be usable");

            assert_eq!(
                *cached.inner.fetcher.seen.borrow(),
                0,
                "a cache entry live at the caller's now_unix must be served \
                 without a network fetch; a non-zero count means freshness was \
                 judged against the wall clock"
            );
        }

        /// The converse, with `now_unix` set past the entry's expiry.
        ///
        /// `next_update` is one hour *before* `NOW`, so the entry is stale for
        /// the validator. A cache reading the wall clock would reach the same
        /// verdict here, so this does not discriminate on its own — it is kept
        /// because without it the test above could be satisfied by a cache
        /// that never expires anything at all.
        #[test]
        fn a_cache_entry_stale_at_now_unix_is_refetched() {
            let fetcher = CountingFetcher {
                crl_bytes: CRL_EMPTY.to_vec(),
                seen: RefCell::new(0),
            };
            let inner = HttpCrlFetcher::new(fetcher, DefaultVerifier, NOW);
            let cache = InMemoryCache::new();

            let issuer_dn = cert(CA).tbs_certificate().subject().to_der().unwrap();
            let key = CrlCacheKey {
                issuer_dn_der: issuer_dn,
                distribution_point_uri: Some("http://crl.example.com/test.crl".to_string()),
            };
            cache.put_crl(
                key,
                CachedCrl {
                    crl_number: None,
                    this_update: SystemTime::UNIX_EPOCH,
                    next_update: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(NOW - 3600)),
                    bytes: CRL_EMPTY.to_vec(),
                },
            );

            let cached = CachedHttpCrlFetcher::new(inner, cache);
            cached
                .check_revocation(&cert(LEAF_GOOD), &cert(CA))
                .expect("must succeed after refetching");

            assert_eq!(
                *cached.inner.fetcher.seen.borrow(),
                1,
                "a cache entry stale at the caller's now_unix must be refetched"
            );
        }

        #[test]
        fn corrupt_cached_entry_falls_through_to_network_fetch() {
            // If the cache returns bytes that don't parse as a CRL, the
            // wrapper invalidates the entry and refetches.
            let fetcher = CountingFetcher {
                crl_bytes: CRL_EMPTY.to_vec(),
                seen: RefCell::new(0),
            };
            let inner = HttpCrlFetcher::new(fetcher, DefaultVerifier, NOW);
            let cache = InMemoryCache::new();
            // Seed cache with garbage under the key the wrapper will use.
            let issuer_dn = cert(CA).tbs_certificate().subject().to_der().unwrap();
            let bad_key = CrlCacheKey {
                issuer_dn_der: issuer_dn.clone(),
                distribution_point_uri: Some("http://crl.example.com/test.crl".to_string()),
            };
            cache.put_crl(
                bad_key.clone(),
                CachedCrl {
                    crl_number: None,
                    this_update: SystemTime::UNIX_EPOCH,
                    next_update: Some(SystemTime::now() + Duration::from_secs(3600)),
                    bytes: vec![0xff, 0xff, 0xff],
                },
            );

            let cached = CachedHttpCrlFetcher::new(inner, cache);
            cached
                .check_revocation(&cert(LEAF_GOOD), &cert(CA))
                .expect("must succeed after refetch");
            assert_eq!(
                *cached.inner.fetcher.seen.borrow(),
                1,
                "corrupt cache must trigger refetch"
            );
        }
    }

    // -----------------------------------------------------------------
    // CachedHttpOcspFetcher
    // -----------------------------------------------------------------

    #[cfg(feature = "ocsp")]
    mod ocsp_wrapper {
        use super::*;
        use crate::{FetchError, FetchRequest, FetchResponse, HttpOcspFetcher};
        use pkix_path::DefaultVerifier;
        use std::cell::RefCell;

        const CA: &[u8] = include_bytes!("../tests/fixtures/http-ca.der");
        const LEAF_GOOD: &[u8] = include_bytes!("../tests/fixtures/http-leaf-good.der");
        const RESP_GOOD: &[u8] = include_bytes!("../tests/fixtures/http-ocsp-good.der");
        const NOW: u64 = 1_780_272_000;

        struct CountingOcspFetcher {
            resp_bytes: Vec<u8>,
            seen: RefCell<usize>,
        }
        impl RevocationFetcher for CountingOcspFetcher {
            fn fetch(&self, _req: &FetchRequest<'_>) -> Result<FetchResponse, FetchError> {
                *self.seen.borrow_mut() += 1;
                Ok(FetchResponse {
                    bytes: self.resp_bytes.clone(),
                    content_type: Some("application/ocsp-response".into()),
                })
            }
        }

        fn cert(b: &[u8]) -> Certificate {
            Certificate::from_der(b).unwrap()
        }

        #[test]
        fn cache_miss_then_hit_avoids_second_fetch() {
            let fetcher = CountingOcspFetcher {
                resp_bytes: RESP_GOOD.to_vec(),
                seen: RefCell::new(0),
            };
            let inner = HttpOcspFetcher::new(fetcher, DefaultVerifier, NOW);
            let cache = InMemoryCache::new();
            let cached = CachedHttpOcspFetcher::new(inner, cache);

            cached
                .check_revocation(&cert(LEAF_GOOD), &cert(CA))
                .expect("first OCSP call");
            assert_eq!(*cached.inner.fetcher.seen.borrow(), 1);

            cached
                .check_revocation(&cert(LEAF_GOOD), &cert(CA))
                .expect("second OCSP call");
            assert_eq!(
                *cached.inner.fetcher.seen.borrow(),
                1,
                "second call must hit cache"
            );
        }

        #[test]
        fn cache_populated_under_responder_url_key() {
            let fetcher = CountingOcspFetcher {
                resp_bytes: RESP_GOOD.to_vec(),
                seen: RefCell::new(0),
            };
            let inner = HttpOcspFetcher::new(fetcher, DefaultVerifier, NOW);
            let cache: Arc<dyn RevocationCache> = Arc::new(InMemoryCache::new());
            let cached = CachedHttpOcspFetcher::new(inner, Arc::clone(&cache));
            cached
                .check_revocation(&cert(LEAF_GOOD), &cert(CA))
                .unwrap();

            // Find the entry under the responder URL the fixture
            // advertises ("http://ocsp.example.com/" per ocsp.rs tests).
            // Rebuild the request to recover the identity the wrapper
            // keyed by — the builder carries it, so no decode is needed.
            use crate::{build_ocsp_request, OcspHashAlg};
            let req = build_ocsp_request(&cert(LEAF_GOOD), &cert(CA), OcspHashAlg::Sha256).unwrap();
            let key = OcspCacheKey {
                cert_serial: req.cert_serial,
                issuer_key_hash: req.issuer_key_hash,
                responder_url: "http://ocsp.example.com/".to_string(),
            };
            assert!(
                cache.get_ocsp(&key).is_some(),
                "OCSP response must be cached under (serial, ikh, url) key"
            );
        }
    }

    // -----------------------------------------------------------------
    // CRL rollback decision (pure-function)
    // -----------------------------------------------------------------

    #[cfg(feature = "crl")]
    #[test]
    fn is_rollback_false_when_no_prior_entry() {
        assert!(!is_rollback(None, Some(&[1])));
        assert!(!is_rollback(None, None));
    }

    #[cfg(feature = "crl")]
    fn entry_with_crl_number(n: Option<Vec<u8>>) -> CachedCrl {
        CachedCrl {
            crl_number: n,
            this_update: SystemTime::UNIX_EPOCH,
            next_update: None,
            bytes: Vec::new(),
        }
    }

    #[cfg(feature = "crl")]
    #[test]
    fn is_rollback_false_when_prior_has_no_crl_number() {
        // Prior entry without a number can't be compared; accept new.
        let prior = entry_with_crl_number(None);
        assert!(!is_rollback(Some(&prior), Some(&[1])));
        assert!(!is_rollback(Some(&prior), None));
    }

    #[cfg(feature = "crl")]
    #[test]
    fn is_rollback_false_when_incoming_has_no_crl_number() {
        // Same shape on the other side: can't decide rollback against an
        // unmarked incoming. Default to "accept" rather than "treat any
        // CRLNumber-less response as suspect" — RFC 5280 §5.2.3 says
        // CRLNumber SHOULD be present but not MUST.
        let prior = entry_with_crl_number(Some(vec![5]));
        assert!(!is_rollback(Some(&prior), None));
    }

    #[cfg(feature = "crl")]
    #[test]
    fn is_rollback_false_when_incoming_is_newer() {
        let prior = entry_with_crl_number(Some(vec![1]));
        assert!(!is_rollback(Some(&prior), Some(&[2])));
    }

    #[cfg(feature = "crl")]
    #[test]
    fn is_rollback_false_when_incoming_equals_prior() {
        // Equal numbers: not a rollback. (Re-fetching the same version
        // is fine — happens on transient cache misses.)
        let prior = entry_with_crl_number(Some(vec![3]));
        assert!(!is_rollback(Some(&prior), Some(&[3])));
    }

    #[cfg(feature = "crl")]
    #[test]
    fn is_rollback_true_when_incoming_is_older() {
        let prior = entry_with_crl_number(Some(vec![5]));
        assert!(is_rollback(Some(&prior), Some(&[3])));
    }

    #[cfg(feature = "crl")]
    #[test]
    fn is_rollback_handles_different_byte_lengths() {
        // Prior CRLNumber 0x0100 (256), incoming 0xff (255). Rollback.
        let prior = entry_with_crl_number(Some(vec![0x01, 0x00]));
        assert!(is_rollback(Some(&prior), Some(&[0xff])));
        // Reverse: prior 0xff, incoming 0x0100 — not a rollback.
        let prior2 = entry_with_crl_number(Some(vec![0xff]));
        assert!(!is_rollback(Some(&prior2), Some(&[0x01, 0x00])));
    }

    // -----------------------------------------------------------------
    // OCSP staleness decision (pure-function)
    // -----------------------------------------------------------------

    #[cfg(feature = "ocsp")]
    fn ocsp_entry_at(this_update_secs: u64) -> CachedOcspResponse {
        CachedOcspResponse::new(
            SystemTime::UNIX_EPOCH,
            SystemTime::UNIX_EPOCH + Duration::from_secs(this_update_secs),
            None,
            Vec::new(),
        )
    }

    #[cfg(feature = "ocsp")]
    fn at_secs(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[cfg(feature = "ocsp")]
    #[test]
    fn is_staler_ocsp_false_when_no_prior_entry() {
        assert!(!is_staler_ocsp(None, at_secs(1000)));
    }

    #[cfg(feature = "ocsp")]
    #[test]
    fn is_staler_ocsp_false_when_incoming_is_newer() {
        let prior = ocsp_entry_at(1000);
        assert!(!is_staler_ocsp(Some(&prior), at_secs(2000)));
    }

    /// Equal `thisUpdate` is not staler: a re-signed copy of equally
    /// fresh status may replace the entry.
    #[cfg(feature = "ocsp")]
    #[test]
    fn is_staler_ocsp_false_when_incoming_equals_prior() {
        let prior = ocsp_entry_at(1000);
        assert!(!is_staler_ocsp(Some(&prior), at_secs(1000)));
    }

    #[cfg(feature = "ocsp")]
    #[test]
    fn is_staler_ocsp_true_when_incoming_is_older() {
        let prior = ocsp_entry_at(2000);
        assert!(is_staler_ocsp(Some(&prior), at_secs(1000)));
    }

    /// `producedAt` must not be the comparator. A responder re-signing an
    /// old snapshot produces a later `producedAt` over an unchanged
    /// `thisUpdate`; if that counted as fresher it could displace a
    /// genuinely newer answer.
    #[cfg(feature = "ocsp")]
    #[test]
    fn is_staler_ocsp_ignores_produced_at() {
        // Prior: status from t=2000, signed at t=2000.
        let prior = CachedOcspResponse::new(at_secs(2000), at_secs(2000), None, Vec::new());
        // Incoming: status from t=1000 but signed much later, at t=9000.
        // The late signature does not make the status fresh.
        assert!(
            is_staler_ocsp(Some(&prior), at_secs(1000)),
            "a late producedAt must not launder stale thisUpdate status"
        );
    }

    // -----------------------------------------------------------------
    // OCSP staleness-guarded insert
    // -----------------------------------------------------------------

    #[cfg(feature = "ocsp")]
    fn staleness_key() -> OcspCacheKey {
        OcspCacheKey {
            cert_serial: vec![0x01],
            issuer_key_hash: vec![0xaa; 32],
            responder_url: "http://ocsp.example/".to_string(),
        }
    }

    /// The case the guard exists for: a cached `revoked` answer must not
    /// be displaced by an older `good` one.
    ///
    /// Revocation is monotone, so the older answer cannot be the correct
    /// one. Before the guard, `put_ocsp` overwrote unconditionally and
    /// every later cache hit reported the revoked certificate as good.
    /// Two threads validating the same certificate at once are enough to
    /// land the responses in the opposite order to the fetch order — no
    /// attacker required.
    #[cfg(feature = "ocsp")]
    #[test]
    fn an_older_response_does_not_displace_a_newer_cached_one() {
        let cache = InMemoryCache::new();
        let key = staleness_key();

        // Cache the newer answer first (status known correct at t=2000).
        assert!(cache.put_ocsp_unless_staler(
            key.clone(),
            CachedOcspResponse::new(at_secs(2000), at_secs(2000), None, b"revoked".to_vec()),
        ));

        // An older answer arrives (status known correct at t=1000).
        assert!(
            !cache.put_ocsp_unless_staler(
                key.clone(),
                CachedOcspResponse::new(at_secs(1000), at_secs(1000), None, b"good".to_vec()),
            ),
            "an older response must be reported as suppressed"
        );

        assert_eq!(
            cache.get_ocsp(&key).expect("entry present").bytes(),
            b"revoked",
            "the newer cached response must survive the older arrival"
        );
    }

    #[cfg(feature = "ocsp")]
    #[test]
    fn a_newer_response_replaces_an_older_cached_one() {
        let cache = InMemoryCache::new();
        let key = staleness_key();
        cache.put_ocsp(
            key.clone(),
            CachedOcspResponse::new(at_secs(1000), at_secs(1000), None, b"old".to_vec()),
        );
        assert!(cache.put_ocsp_unless_staler(
            key.clone(),
            CachedOcspResponse::new(at_secs(2000), at_secs(2000), None, b"new".to_vec()),
        ));
        assert_eq!(cache.get_ocsp(&key).expect("entry present").bytes(), b"new");
    }

    /// Behind `Arc<dyn RevocationCache>` the call dispatches
    /// dynamically, so it must still reject an ordinary staler
    /// response.
    #[cfg(feature = "ocsp")]
    #[test]
    fn the_trait_object_fallback_also_rejects_a_staler_response() {
        let cache: Arc<dyn RevocationCache> = Arc::new(InMemoryCache::new());
        let key = staleness_key();
        cache.put_ocsp(
            key.clone(),
            CachedOcspResponse::new(at_secs(2000), at_secs(2000), None, b"revoked".to_vec()),
        );
        assert!(!cache.put_ocsp_unless_staler(
            key.clone(),
            CachedOcspResponse::new(at_secs(1000), at_secs(1000), None, b"good".to_vec()),
        ));
        assert_eq!(
            cache.get_ocsp(&key).expect("entry present").bytes(),
            b"revoked"
        );
    }

    /// A first insert under an unused key is never staler.
    #[cfg(feature = "ocsp")]
    #[test]
    fn a_first_insert_is_not_staler() {
        let cache = InMemoryCache::new();
        let key = staleness_key();
        assert!(cache.put_ocsp_unless_staler(
            key.clone(),
            CachedOcspResponse::new(at_secs(1), at_secs(1), None, b"first".to_vec()),
        ));
        assert_eq!(
            cache.get_ocsp(&key).expect("entry present").bytes(),
            b"first"
        );
    }
}

#[cfg(test)]
mod send_sync_smoke {
    //! Compile-time assertion that the trait + reference impl really are
    //! `Send + Sync`. Without this, a future refactor that introduces an
    //! `Rc` or non-Send field would silently regress the acceptance
    //! criterion.

    use super::*;

    fn _assert_send_sync<T: Send + Sync>() {}

    #[allow(dead_code)]
    fn check() {
        _assert_send_sync::<InMemoryCache>();
        _assert_send_sync::<Box<dyn RevocationCache>>();
        _assert_send_sync::<Arc<dyn RevocationCache>>();
    }
}
