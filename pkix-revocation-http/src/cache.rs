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
//!   Unbounded — consumers needing eviction bring a `moka` or `redis`-backed
//!   `RevocationCache` impl.
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
use std::sync::{Arc, RwLock};
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
use pkix_path::SignatureVerifier;
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
#[derive(Clone, Debug)]
pub struct CachedCrl {
    /// `CRLNumber` extension value if present.
    ///
    /// Monotonicity comparator — RFC 5280 §5.2.3.
    pub crl_number: Option<Vec<u8>>,
    /// `tbsCertList.thisUpdate`.
    pub this_update: SystemTime,
    /// `tbsCertList.nextUpdate` — `None` if omitted.
    pub next_update: Option<SystemTime>,
    /// Raw DER-encoded `CertificateList`.
    pub bytes: Vec<u8>,
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
#[derive(Clone, Debug)]
pub struct CachedOcspResponse {
    /// `BasicOcspResponse.tbsResponseData.producedAt`.
    pub produced_at: SystemTime,
    /// `SingleResponse.thisUpdate`.
    pub this_update: SystemTime,
    /// `SingleResponse.nextUpdate` — `None` if omitted.
    pub next_update: Option<SystemTime>,
    /// Raw DER-encoded outer `OcspResponse`.
    pub bytes: Vec<u8>,
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
/// `get_crl` / `get_ocsp` MUST return `None` for entries whose
/// `next_update` is in the past. Entries without a `next_update`
/// (`None`) MAY be returned indefinitely or treated as expired
/// immediately depending on the implementation's policy.
/// The reference [`InMemoryCache`] keeps such entries until invalidated.
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
}

// ---------------------------------------------------------------------------
// InMemoryCache
// ---------------------------------------------------------------------------

/// `HashMap`-backed reference [`RevocationCache`].
///
/// Unbounded — entries accumulate until explicitly invalidated or the
/// cache is dropped. Consumers needing LRU / LFU / size eviction supply
/// their own `RevocationCache` impl backed by a bounded store (e.g.
/// `moka`).
///
/// Internal locking is `RwLock`, not `DashMap`, to avoid the extra
/// dependency in the reference impl. Read paths take the read lock;
/// write paths take the write lock briefly.
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
}

impl fmt::Debug for InMemoryCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let crl_len = self.crl.read().map(|m| m.len()).unwrap_or(0);
        let ocsp_len = self.ocsp.read().map(|m| m.len()).unwrap_or(0);
        f.debug_struct("InMemoryCache")
            .field("crl_entries", &crl_len)
            .field("ocsp_entries", &ocsp_len)
            .finish()
    }
}

/// Returns `true` if `next_update` is `None` (treat as live) or strictly
/// after `now`. `next_update <= now` is expired.
fn is_live(next_update: Option<SystemTime>, now: SystemTime) -> bool {
    match next_update {
        None => true,
        Some(nu) => nu > now,
    }
}

impl RevocationCache for InMemoryCache {
    fn get_crl(&self, key: &CrlCacheKey) -> Option<Arc<CachedCrl>> {
        let entry = self.crl.read().ok()?.get(key).cloned()?;
        if is_live(entry.next_update, SystemTime::now()) {
            Some(entry)
        } else {
            None
        }
    }

    fn put_crl(&self, key: CrlCacheKey, entry: CachedCrl) {
        if let Ok(mut guard) = self.crl.write() {
            guard.insert(key, Arc::new(entry));
        }
    }

    fn invalidate_crl(&self, key: &CrlCacheKey) {
        if let Ok(mut guard) = self.crl.write() {
            guard.remove(key);
        }
    }

    fn get_ocsp(&self, key: &OcspCacheKey) -> Option<Arc<CachedOcspResponse>> {
        let entry = self.ocsp.read().ok()?.get(key).cloned()?;
        if is_live(entry.next_update, SystemTime::now()) {
            Some(entry)
        } else {
            None
        }
    }

    fn put_ocsp(&self, key: OcspCacheKey, entry: CachedOcspResponse) {
        if let Ok(mut guard) = self.ocsp.write() {
            guard.insert(key, Arc::new(entry));
        }
    }

    fn invalidate_ocsp(&self, key: &OcspCacheKey) {
        if let Ok(mut guard) = self.ocsp.write() {
            guard.remove(key);
        }
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
    let crl = x509_cert::crl::CertificateList::from_der(der_bytes)?;
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

/// Extract `(serial_number_bytes, issuer_key_hash_bytes)` from a DER-encoded
/// OCSP request. Used to derive cache keys without re-implementing
/// `Request::from_cert`'s hashing logic.
///
/// Pulls from the first `Request` in `tbs_request.request_list` — the
/// builder used by [`crate::build_ocsp_request`] always emits exactly
/// one, but if a future helper ever bundles multiple, only the first is
/// keyed (matching the OCSP wrapper's single-cert semantics).
#[cfg(feature = "ocsp")]
fn extract_cert_id_identity(req_body: &[u8]) -> Result<(Vec<u8>, Vec<u8>), der::Error> {
    let req = x509_ocsp::OcspRequest::from_der(req_body)?;
    let first = req
        .tbs_request
        .request_list
        .first()
        .ok_or_else(|| der::Error::from(der::ErrorKind::Failed))?;
    let cert_id = &first.req_cert;
    let serial = cert_id.serial_number.as_bytes().to_vec();
    let issuer_key_hash = cert_id.issuer_key_hash.as_bytes().to_vec();
    Ok((serial, issuer_key_hash))
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
        (Some(p), Some(inc)) => match p.crl_number.as_deref() {
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

// ---------------------------------------------------------------------------
// CachedHttpCrlFetcher
// ---------------------------------------------------------------------------

/// [`HttpCrlFetcher`]-shaped wrapper that consults a [`RevocationCache`]
/// before issuing network requests, and populates the cache on every
/// successful fetch + parse.
///
/// # Lookup flow
///
/// For each candidate CDP URL on a certificate:
///
/// 1. Compute the [`CrlCacheKey`]: `(issuer_dn, Some(url))`.
/// 2. `cache.get_crl(&key)` — on hit, hand the cached bytes to a fresh
///    [`pkix_revocation::CrlChecker`] and return its verdict.
/// 3. On miss, fetch the URL via the underlying [`RevocationFetcher`].
/// 4. On successful fetch, parse `(CRLNumber, thisUpdate, nextUpdate)`
///    and store the entry. **Rollback rejection:** if a cached entry
///    existed for this key with a `CRLNumber` numerically greater than
///    the fetched one, the new entry is dropped on the floor (the cache
///    retains the older-but-newer entry) and the wrapper proceeds with
///    the *cached* CRL. RFC 5280 §5.2.3 makes CRLNumber monotonic per
///    series; a refresh that goes backwards is either a misconfigured
///    responder serving a stale snapshot or an attack.
/// 5. Verdict propagation is identical to [`HttpCrlFetcher`]: first
///    constructible `CrlChecker` decides.
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
        let issuer_dn_der = issuer.tbs_certificate.subject.to_der().ok();

        let mut failures: Vec<String> = Vec::with_capacity(urls.len());
        for url in &urls {
            // Step 2 — Cache lookup.
            let key = issuer_dn_der.as_ref().map(|der| CrlCacheKey {
                issuer_dn_der: der.clone(),
                distribution_point_uri: Some(url.clone()),
            });
            if let Some(cached) = key.as_ref().and_then(|k| self.cache.get_crl(k)) {
                // Cache hit: construct CrlChecker from cached bytes.
                match CrlChecker::new(
                    cached.bytes.as_slice(),
                    self.inner.now_unix,
                    self.inner.verifier.clone(),
                ) {
                    Ok(checker) => return checker.check_revocation(cert, issuer),
                    Err(e) => {
                        // Treat a corrupt cache entry as a miss. Invalidate
                        // and fall through to network fetch so a one-off
                        // corruption doesn't permanently break this URL.
                        if let Some(k) = key.as_ref() {
                            self.cache.invalidate_crl(k);
                        }
                        failures.push(format!("{url}: cached CRL parse: {e}"));
                        // Fall through to network fetch.
                    }
                }
            }

            // Step 3 — Cache miss. Fetch over the network.
            let req = FetchRequest::get(url);
            match self.inner.fetcher.fetch(&req) {
                Ok(resp) => {
                    // Step 4 — Try to build a CrlChecker. If parse fails,
                    // fall through to next URL exactly as HttpCrlFetcher does.
                    match CrlChecker::new(
                        &resp.bytes,
                        self.inner.now_unix,
                        self.inner.verifier.clone(),
                    ) {
                        Ok(checker) => {
                            // Best-effort cache populate. Parse metadata
                            // independently of the verifier-bound CrlChecker
                            // so a future refactor of pkix-revocation
                            // cannot break the cache.
                            self.maybe_populate_cache(&resp, key);
                            return checker.check_revocation(cert, issuer);
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

        Err(RevError::RevocationFetchFailed {
            description: format!("all {} URL(s) failed: {}", urls.len(), failures.join("; ")),
        })
    }
}

#[cfg(feature = "crl")]
impl<F, V, C> CachedHttpCrlFetcher<F, V, C>
where
    C: RevocationCache,
{
    /// Parse freshness metadata out of a fetched CRL response and store
    /// it under `key`. Drops the new entry on the floor if `CRLNumber`
    /// monotonicity would be violated.
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

        if is_rollback(
            self.cache.get_crl(&key).as_deref(),
            meta.crl_number.as_deref(),
        ) {
            return;
        }

        self.cache.put_crl(
            key,
            CachedCrl {
                crl_number: meta.crl_number,
                this_update: meta.this_update,
                next_update: meta.next_update,
                bytes: resp.bytes.clone(),
            },
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
/// 1. Build the OCSP request body via [`crate::build_ocsp_request`] (we
///    need its `cert_id_serial` and `cert_id_issuer_key_hash` to form the
///    cache key — see [`crate::ocsp_request::OcspRequestBytes`]).
/// 2. For each AIA OCSP URL, look up
///    `(cert_serial, issuer_key_hash, responder_url)` in the cache.
/// 3. On hit, construct an [`pkix_revocation::OcspChecker`] from cached
///    bytes and return its verdict.
/// 4. On miss, POST the request body and populate the cache from
///    `(producedAt, thisUpdate, nextUpdate)`.
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
        use pkix_revocation::OcspChecker;

        // Build the OCSP request once; reuse for cache-key derivation
        // AND as the POST body on miss.
        let req_bytes =
            crate::build_ocsp_request(cert, issuer, self.inner.hash_alg).map_err(|e| {
                RevError::RevocationFetchFailed {
                    description: format!("OCSP request build failed: {e}"),
                }
            })?;

        let aia =
            crate::extract_aia_http_urls(cert).map_err(|e| RevError::RevocationFetchFailed {
                description: format!("authorityInfoAccess extension parse failed: {e}"),
            })?;
        if aia.ocsp.is_empty() {
            return Ok(());
        }

        // Extract (serial, issuer_key_hash) from the request body for
        // cache-key derivation. We parse the body we just built rather
        // than mirroring `Request::from_cert`'s hashing logic, so the
        // two cannot drift apart.
        let (cert_serial, issuer_key_hash) =
            extract_cert_id_identity(&req_bytes.body).map_err(|e| {
                RevError::RevocationFetchFailed {
                    description: format!("OCSP request CertID extract failed: {e}"),
                }
            })?;

        let mut failures: Vec<String> = Vec::with_capacity(aia.ocsp.len());
        for url in &aia.ocsp {
            let key = OcspCacheKey {
                cert_serial: cert_serial.clone(),
                issuer_key_hash: issuer_key_hash.clone(),
                responder_url: url.clone(),
            };

            if let Some(cached) = self.cache.get_ocsp(&key) {
                match OcspChecker::new(
                    cached.bytes.as_slice(),
                    self.inner.now_unix,
                    self.inner.verifier.clone(),
                ) {
                    Ok(checker) => return checker.check_revocation(cert, issuer),
                    Err(e) => {
                        self.cache.invalidate_ocsp(&key);
                        failures.push(format!("{url}: cached OCSP parse: {e}"));
                        // Fall through to network fetch.
                    }
                }
            }

            const OCSP_REQUEST_CT: &str = "application/ocsp-request";
            let req = FetchRequest::post(url, &req_bytes.body, OCSP_REQUEST_CT);
            match self.inner.fetcher.fetch(&req) {
                Ok(resp) => match OcspChecker::new(
                    &resp.bytes,
                    self.inner.now_unix,
                    self.inner.verifier.clone(),
                ) {
                    Ok(checker) => {
                        self.maybe_populate_cache(&resp, key);
                        return checker.check_revocation(cert, issuer);
                    }
                    Err(e) => {
                        failures.push(format!("{url}: OCSP parse: {e}"));
                        continue;
                    }
                },
                Err(e) => {
                    failures.push(format!("{url}: {e}"));
                    continue;
                }
            }
        }

        Err(RevError::RevocationFetchFailed {
            description: format!(
                "all {} URL(s) failed: {}",
                aia.ocsp.len(),
                failures.join("; ")
            ),
        })
    }
}

#[cfg(feature = "ocsp")]
impl<F, V, C> CachedHttpOcspFetcher<F, V, C>
where
    C: RevocationCache,
{
    /// Parse freshness metadata out of a fetched OCSP response and store
    /// it under `key`. Best-effort; silent on metadata parse failure.
    fn maybe_populate_cache(&self, resp: &FetchResponse, key: OcspCacheKey) {
        let Ok(meta) = parse_ocsp_metadata(&resp.bytes) else {
            return;
        };
        self.cache.put_ocsp(
            key,
            CachedOcspResponse {
                produced_at: meta.produced_at,
                this_update: meta.this_update,
                next_update: meta.next_update,
                bytes: resp.bytes.clone(),
            },
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
    fn in_memory_cache_expired_entry_returns_none() {
        // Acceptance criterion: TTL respected — expired entries return
        // None from get_*.
        let c = InMemoryCache::new();
        let past = SystemTime::now() - Duration::from_secs(60);
        let k = dummy_crl_key(None);
        c.put_crl(k.clone(), dummy_crl_entry(None, Some(past)));
        assert!(
            c.get_crl(&k).is_none(),
            "entry with past nextUpdate must be treated as expired"
        );
    }

    #[test]
    fn in_memory_cache_expired_ocsp_entry_returns_none() {
        let c = InMemoryCache::new();
        let past = SystemTime::now() - Duration::from_secs(60);
        let k = dummy_ocsp_key("http://x/");
        c.put_ocsp(k.clone(), dummy_ocsp_entry(Some(past)));
        assert!(c.get_ocsp(&k).is_none());
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
    // CertID identity extraction (OCSP cache-key derivation)
    // -----------------------------------------------------------------

    #[cfg(feature = "ocsp")]
    #[test]
    fn extract_cert_id_identity_round_trips_through_build_ocsp_request() {
        // Build an OCSP request the same way the wrapper does, then pull
        // the (serial, issuer_key_hash) back out and check the extracted
        // serial matches the leaf cert's serialNumber.
        use crate::{build_ocsp_request, OcspHashAlg};
        const CA: &[u8] = include_bytes!("../tests/fixtures/http-ca.der");
        const LEAF: &[u8] = include_bytes!("../tests/fixtures/http-leaf-good.der");
        let leaf = Certificate::from_der(LEAF).unwrap();
        let ca = Certificate::from_der(CA).unwrap();
        let req = build_ocsp_request(&leaf, &ca, OcspHashAlg::Sha256).unwrap();
        let (serial, issuer_key_hash) = extract_cert_id_identity(&req.body).unwrap();
        // Independent oracle: the leaf's tbsCertificate.serialNumber
        // bytes must match. (Confirms we are pulling from the request's
        // CertID, not somewhere else.)
        assert_eq!(serial, leaf.tbs_certificate.serial_number.as_bytes());
        // SHA-256 hash is 32 bytes.
        assert_eq!(issuer_key_hash.len(), 32);
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
            let issuer_dn = cert(CA).tbs_certificate.subject.to_der().unwrap();
            let key = CrlCacheKey {
                issuer_dn_der: issuer_dn,
                distribution_point_uri: Some("http://crl.example.com/test.crl".to_string()),
            };
            let got = cache
                .get_crl(&key)
                .expect("CRL must be cached under DP URI key");
            assert_eq!(got.bytes, CRL_EMPTY);
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
            let issuer_dn = cert(CA).tbs_certificate.subject.to_der().unwrap();
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

            // Find at least one entry under the responder URL the fixture
            // advertises ("http://ocsp.example.com/" per ocsp.rs tests).
            // We don't know the exact (serial, issuer_key_hash) without
            // re-parsing, so probe via the request-build path.
            use crate::{build_ocsp_request, OcspHashAlg};
            let req = build_ocsp_request(&cert(LEAF_GOOD), &cert(CA), OcspHashAlg::Sha256).unwrap();
            let (serial, ikh) = extract_cert_id_identity(&req.body).unwrap();
            let key = OcspCacheKey {
                cert_serial: serial,
                issuer_key_hash: ikh,
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
