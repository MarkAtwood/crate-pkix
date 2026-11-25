//! The cache types' public surface, exercised from outside the crate.
//!
//! `cache.rs`'s unit tests live in a child module of `cache`, so they can
//! reach private fields and would still compile if the public
//! constructors and accessors were deleted. These tests are the ones that
//! actually pin the contract a consumer depends on: that a
//! `RevocationCache` backed by something other than a `HashMap` — Redis,
//! a SQL table, a file — can be written using nothing but the exported
//! API.
//!
//! Run: cargo test -p pkix-revocation-http --features crl,ocsp --test cache_public_api

#![cfg(any(feature = "crl", feature = "ocsp"))]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use pkix_revocation_http::{
    CachedCrl, CachedOcspResponse, CrlCacheKey, InMemoryCache, OcspCacheKey, RevocationCache,
};

/// A `RevocationCache` that stores entries as flat bytes-and-numbers,
/// the way an out-of-process store would.
///
/// This is the point of the test: it round-trips every entry through a
/// representation that is NOT `CachedCrl`, so it can only be written if
/// the public API exposes enough to take an entry apart and put it back
/// together. It deliberately does not import anything private.
/// `(crl_number, this_update_secs, next_update_secs, der)` — a CRL entry
/// as flat values, the way an external store would hold it.
type FlatCrl = (Option<Vec<u8>>, u64, Option<u64>, Vec<u8>);

/// `(produced_at_secs, this_update_secs, next_update_secs, der)`.
type FlatOcsp = (u64, u64, Option<u64>, Vec<u8>);

#[derive(Default)]
struct FlatStore {
    crl: Mutex<HashMap<String, FlatCrl>>,
    ocsp: Mutex<HashMap<String, FlatOcsp>>,
}

fn secs(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .expect("fixture times are after the Unix epoch")
        .as_secs()
}

fn at(s: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(s)
}

impl FlatStore {
    /// An external store has to turn a key into its own key type, which
    /// is why `CrlCacheKey`'s fields stay public.
    fn crl_key(key: &CrlCacheKey) -> String {
        format!(
            "{}|{}",
            hex(&key.issuer_dn_der),
            key.distribution_point_uri.as_deref().unwrap_or("")
        )
    }

    fn ocsp_key(key: &OcspCacheKey) -> String {
        format!(
            "{}|{}|{}",
            hex(&key.cert_serial),
            hex(&key.issuer_key_hash),
            key.responder_url
        )
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl RevocationCache for FlatStore {
    fn get_crl(&self, key: &CrlCacheKey) -> Option<Arc<CachedCrl>> {
        let guard = self.crl.lock().expect("test store lock");
        let (num, this, next, der) = guard.get(&Self::crl_key(key))?;
        // Reassembled purely from the public constructor.
        Some(Arc::new(CachedCrl::new(
            num.clone(),
            at(*this),
            next.map(at),
            der.clone(),
        )))
    }

    fn put_crl(&self, key: CrlCacheKey, entry: CachedCrl) {
        // Taken apart purely through the public accessors.
        let flat = (
            entry.crl_number().map(<[u8]>::to_vec),
            secs(entry.this_update()),
            entry.next_update().map(secs),
            entry.bytes().to_vec(),
        );
        self.crl
            .lock()
            .expect("test store lock")
            .insert(Self::crl_key(&key), flat);
    }

    fn invalidate_crl(&self, key: &CrlCacheKey) {
        self.crl
            .lock()
            .expect("test store lock")
            .remove(&Self::crl_key(key));
    }

    fn get_ocsp(&self, key: &OcspCacheKey) -> Option<Arc<CachedOcspResponse>> {
        let guard = self.ocsp.lock().expect("test store lock");
        let (produced, this, next, der) = guard.get(&Self::ocsp_key(key))?;
        Some(Arc::new(CachedOcspResponse::new(
            at(*produced),
            at(*this),
            next.map(at),
            der.clone(),
        )))
    }

    fn put_ocsp(&self, key: OcspCacheKey, entry: CachedOcspResponse) {
        let flat = (
            secs(entry.produced_at()),
            secs(entry.this_update()),
            entry.next_update().map(secs),
            entry.bytes().to_vec(),
        );
        self.ocsp
            .lock()
            .expect("test store lock")
            .insert(Self::ocsp_key(&key), flat);
    }

    fn invalidate_ocsp(&self, key: &OcspCacheKey) {
        self.ocsp
            .lock()
            .expect("test store lock")
            .remove(&Self::ocsp_key(key));
    }
}

fn crl_key() -> CrlCacheKey {
    CrlCacheKey {
        issuer_dn_der: vec![0x30, 0x05, 0x01, 0x02, 0x03],
        distribution_point_uri: Some("http://crl.example/base.crl".to_string()),
    }
}

fn ocsp_key() -> OcspCacheKey {
    OcspCacheKey {
        cert_serial: vec![0x01, 0x02],
        issuer_key_hash: vec![0xaa; 32],
        responder_url: "http://ocsp.example/".to_string(),
    }
}

/// Every value a `CachedCrl` carries must survive a trip through an
/// external representation. If an accessor were missing, this would not
/// compile; if one returned the wrong field, the assertion catches it.
#[test]
fn a_cached_crl_round_trips_through_an_out_of_crate_store() {
    let store = FlatStore::default();
    let original = CachedCrl::new(
        Some(vec![0x02, 0x9a]),
        at(1_780_000_000),
        Some(at(1_780_600_000)),
        vec![0xde, 0xad, 0xbe, 0xef],
    );

    store.put_crl(crl_key(), original.clone());
    let back = store
        .get_crl(&crl_key())
        .expect("the entry just stored must be retrievable");

    assert_eq!(back.crl_number(), Some([0x02, 0x9a].as_slice()));
    assert_eq!(back.this_update(), at(1_780_000_000));
    assert_eq!(back.next_update(), Some(at(1_780_600_000)));
    assert_eq!(back.bytes(), &[0xde, 0xad, 0xbe, 0xef]);

    // And the same values as the entry we handed in.
    assert_eq!(back.crl_number(), original.crl_number());
    assert_eq!(back.this_update(), original.this_update());
    assert_eq!(back.next_update(), original.next_update());
    assert_eq!(back.bytes(), original.bytes());
}

/// A CRL with no `CRLNumber` and no `nextUpdate` — both legal-but-unusual
/// — must round-trip as absent rather than as a zero or an epoch time.
#[test]
fn absent_crl_metadata_round_trips_as_absent() {
    let store = FlatStore::default();
    store.put_crl(
        crl_key(),
        CachedCrl::new(None, at(1_780_000_000), None, vec![0x01]),
    );
    let back = store.get_crl(&crl_key()).expect("stored entry");
    assert_eq!(back.crl_number(), None);
    assert_eq!(back.next_update(), None);
}

#[test]
fn a_cached_ocsp_response_round_trips_through_an_out_of_crate_store() {
    let store = FlatStore::default();
    let original = CachedOcspResponse::new(
        at(1_780_000_100),
        at(1_780_000_000),
        Some(at(1_780_600_000)),
        vec![0x30, 0x03, 0x0a, 0x01, 0x00],
    );

    store.put_ocsp(ocsp_key(), original.clone());
    let back = store
        .get_ocsp(&ocsp_key())
        .expect("the entry just stored must be retrievable");

    // producedAt and thisUpdate are distinct values and must not be
    // swapped by the accessors: the fixture sets them 100s apart.
    assert_eq!(back.produced_at(), at(1_780_000_100));
    assert_eq!(back.this_update(), at(1_780_000_000));
    assert_eq!(back.next_update(), Some(at(1_780_600_000)));
    assert_eq!(back.bytes(), original.bytes());
}

#[test]
fn invalidate_removes_an_entry_from_an_out_of_crate_store() {
    let store = FlatStore::default();
    store.put_crl(crl_key(), CachedCrl::new(None, at(1), None, vec![0x01]));
    assert!(store.get_crl(&crl_key()).is_some());
    store.invalidate_crl(&crl_key());
    assert!(store.get_crl(&crl_key()).is_none());

    store.put_ocsp(
        ocsp_key(),
        CachedOcspResponse::new(at(1), at(1), None, vec![0x01]),
    );
    assert!(store.get_ocsp(&ocsp_key()).is_some());
    store.invalidate_ocsp(&ocsp_key());
    assert!(store.get_ocsp(&ocsp_key()).is_none());
}

/// The reference cache must honour the same contract the external one
/// does, through the same public API.
#[test]
fn the_reference_cache_round_trips_the_same_values() {
    let cache = InMemoryCache::new();
    cache.put_crl(
        crl_key(),
        CachedCrl::new(
            Some(vec![0xff, 0x01]),
            at(1_780_000_000),
            Some(at(1_780_600_000)),
            vec![0x11, 0x22],
        ),
    );
    let back = cache.get_crl(&crl_key()).expect("stored entry");
    assert_eq!(back.crl_number(), Some([0xff, 0x01].as_slice()));
    assert_eq!(back.bytes(), &[0x11, 0x22]);
    assert_eq!(back.next_update(), Some(at(1_780_600_000)));
}

/// `Arc<dyn RevocationCache>` is the shape the wrappers document for
/// sharing one store between a CRL and an OCSP fetcher, so an
/// out-of-crate implementation has to work behind the trait object.
#[test]
fn an_out_of_crate_store_works_behind_a_trait_object() {
    let store: Arc<dyn RevocationCache> = Arc::new(FlatStore::default());
    store.put_crl(
        crl_key(),
        CachedCrl::new(Some(vec![1]), at(1_780_000_000), None, vec![0x42]),
    );
    assert_eq!(
        store.get_crl(&crl_key()).expect("stored entry").bytes(),
        &[0x42]
    );
}

// ---------------------------------------------------------------------------
// Reclamation
// ---------------------------------------------------------------------------

/// `prune_expired` reclaims exactly the entries the wrappers would
/// refuse to serve, and leaves the rest.
///
/// The boundary matters: an entry whose `nextUpdate` equals `now` is
/// expired (`is_live` is strictly-after), so it must go. One a second
/// later must stay. Getting this backwards would either discard live
/// entries — turning every validation into a refetch — or retain dead
/// ones forever, which is the growth this method exists to stop.
#[test]
fn prune_expired_reclaims_exactly_the_entries_that_can_no_longer_be_served() {
    let cache = InMemoryCache::new();
    let now = at(10_000);

    let mk = |uri: &str| CrlCacheKey {
        issuer_dn_der: vec![1],
        distribution_point_uri: Some(uri.to_string()),
    };

    // Expired well before now.
    cache.put_crl(
        mk("stale"),
        CachedCrl::new(None, at(1), Some(at(9_000)), vec![0x01]),
    );
    // Expires exactly at now: `is_live` is strictly-after, so expired.
    cache.put_crl(
        mk("boundary"),
        CachedCrl::new(None, at(1), Some(now), vec![0x02]),
    );
    // One second of life left.
    cache.put_crl(
        mk("live"),
        CachedCrl::new(None, at(1), Some(at(10_001)), vec![0x03]),
    );
    // No nextUpdate: kept, per the documented "never expires until
    // invalidated" reading.
    cache.put_crl(mk("eternal"), CachedCrl::new(None, at(1), None, vec![0x04]));

    cache.put_ocsp(
        ocsp_key(),
        CachedOcspResponse::new(at(1), at(1), Some(at(9_999)), vec![0x05]),
    );

    assert_eq!(cache.len(), 5, "fixture should hold five entries");
    assert_eq!(cache.crl_len(), 4);
    assert_eq!(cache.ocsp_len(), 1);

    // Two expired CRLs plus the expired OCSP response.
    assert_eq!(cache.prune_expired(now), 3);

    assert!(cache.get_crl(&mk("stale")).is_none());
    assert!(
        cache.get_crl(&mk("boundary")).is_none(),
        "nextUpdate == now is expired, matching is_live's strictly-after test"
    );
    assert!(cache.get_crl(&mk("live")).is_some());
    assert!(
        cache.get_crl(&mk("eternal")).is_some(),
        "an entry with no nextUpdate must survive a prune"
    );
    assert!(cache.get_ocsp(&ocsp_key()).is_none());

    assert_eq!(cache.crl_len(), 2);
    assert_eq!(cache.ocsp_len(), 0);
}

/// Pruning an empty cache, or one with nothing expired, reclaims nothing
/// and is safe to call on a tick.
#[test]
fn prune_expired_is_a_no_op_when_nothing_has_expired() {
    let cache = InMemoryCache::new();
    assert_eq!(cache.prune_expired(at(10_000)), 0);
    assert!(cache.is_empty());

    cache.put_crl(
        crl_key(),
        CachedCrl::new(None, at(1), Some(at(99_999)), vec![0x01]),
    );
    assert_eq!(cache.prune_expired(at(10_000)), 0);
    assert_eq!(cache.len(), 1);
    // Idempotent.
    assert_eq!(cache.prune_expired(at(10_000)), 0);
    assert_eq!(cache.len(), 1);
}

/// `clear` drops live entries too — that is the difference from
/// `prune_expired`.
#[test]
fn clear_drops_live_entries_as_well_as_expired_ones() {
    let cache = InMemoryCache::new();
    cache.put_crl(
        crl_key(),
        CachedCrl::new(None, at(1), Some(at(99_999)), vec![0x01]),
    );
    cache.put_ocsp(
        ocsp_key(),
        CachedOcspResponse::new(at(1), at(1), Some(at(99_999)), vec![0x02]),
    );
    assert_eq!(cache.len(), 2);
    assert_eq!(
        cache.prune_expired(at(10_000)),
        0,
        "both entries are live, so a prune must leave them"
    );

    cache.clear();
    assert!(cache.is_empty());
    assert!(cache.get_crl(&crl_key()).is_none());
    assert!(cache.get_ocsp(&ocsp_key()).is_none());
}

/// An empty cache reports itself empty, and stops doing so after one
/// insert. `is_empty` has to agree with `len` or a consumer gating a
/// maintenance pass on it would skip the pass.
#[test]
fn len_and_is_empty_agree() {
    let cache = InMemoryCache::new();
    assert_eq!(cache.len(), 0);
    assert!(cache.is_empty());

    cache.put_ocsp(
        ocsp_key(),
        CachedOcspResponse::new(at(1), at(1), None, vec![0x01]),
    );
    assert_eq!(cache.len(), 1);
    assert!(!cache.is_empty());

    cache.invalidate_ocsp(&ocsp_key());
    assert_eq!(cache.len(), 0);
    assert!(cache.is_empty());
}

// ---------------------------------------------------------------------------
// Usability as the wrappers' C parameter
// ---------------------------------------------------------------------------

/// An out-of-crate cache must work as the `C` parameter of the cache
/// wrappers *by its own concrete type*, not only behind
/// `Arc<dyn RevocationCache>`.
///
/// The guarded inserts used to live on crate-private traits
/// (`CrlAtomicPut` / `OcspAtomicPut`) that the wrappers required but no
/// consumer could implement, so `FlatStore` satisfied `RevocationCache`
/// and still could not be used: the bound failed on a trait whose name
/// the error message gave and whose definition was unreachable. The
/// guarded inserts are now defaulted methods on `RevocationCache`
/// itself, so implementing that trait is sufficient.
///
/// This is a compile-time test above all — if the bound regresses, this
/// file stops building.
#[test]
fn an_out_of_crate_cache_works_as_the_wrappers_cache_parameter() {
    use der::Decode as _;
    use pkix_path::DefaultVerifier;
    use pkix_revocation::RevocationChecker as _;
    use pkix_revocation_http::{
        CachedHttpCrlFetcher, CachedHttpOcspFetcher, FetchError, FetchRequest, FetchResponse,
        HttpCrlFetcher, HttpOcspFetcher, RevocationFetcher,
    };

    struct Offline;
    impl RevocationFetcher for Offline {
        fn fetch(&self, _req: &FetchRequest<'_>) -> Result<FetchResponse, FetchError> {
            Err(FetchError::HttpStatus(503))
        }
    }

    let cert = x509_cert::Certificate::from_der(include_bytes!("fixtures/review/leaf-serial2.der"))
        .expect("fixture parses");
    let ca = x509_cert::Certificate::from_der(include_bytes!("fixtures/review/ca.der"))
        .expect("fixture parses");

    // By concrete type.
    let crl = CachedHttpCrlFetcher::new(
        HttpCrlFetcher::new(Offline, DefaultVerifier, 1_780_272_000),
        FlatStore::default(),
    );
    // The transport refuses every request, so this reports a fetch
    // failure; what matters is that it compiles and runs at all.
    assert!(crl.check_revocation(&cert, &ca).is_err());

    let ocsp = CachedHttpOcspFetcher::new(
        HttpOcspFetcher::new(Offline, DefaultVerifier, 1_780_272_000),
        FlatStore::default(),
    );
    assert!(ocsp.check_revocation(&cert, &ca).is_err());
}

/// The defaulted guarded inserts must actually guard for an
/// implementation that does not override them. `FlatStore` overrides
/// neither, so these exercise the trait's own default bodies.
#[test]
fn the_default_guarded_inserts_reject_a_rollback_and_a_staler_response() {
    let store = FlatStore::default();

    store.put_crl(
        crl_key(),
        CachedCrl::new(
            Some(vec![5]),
            at(2_000),
            Some(at(99_999)),
            b"newer".to_vec(),
        ),
    );
    assert!(
        !store.put_crl_unless_rollback(
            crl_key(),
            CachedCrl::new(
                Some(vec![4]),
                at(1_000),
                Some(at(99_999)),
                b"older".to_vec()
            ),
        ),
        "a lower CRLNumber must be rejected by the default implementation"
    );
    assert_eq!(store.get_crl(&crl_key()).expect("entry").bytes(), b"newer");

    store.put_ocsp(
        ocsp_key(),
        CachedOcspResponse::new(at(2_000), at(2_000), Some(at(99_999)), b"revoked".to_vec()),
    );
    assert!(
        !store.put_ocsp_unless_staler(
            ocsp_key(),
            CachedOcspResponse::new(at(1_000), at(1_000), Some(at(99_999)), b"good".to_vec()),
        ),
        "an older thisUpdate must be rejected by the default implementation"
    );
    assert_eq!(
        store.get_ocsp(&ocsp_key()).expect("entry").bytes(),
        b"revoked"
    );

    // And a genuine refresh still lands.
    assert!(store.put_crl_unless_rollback(
        crl_key(),
        CachedCrl::new(
            Some(vec![6]),
            at(3_000),
            Some(at(99_999)),
            b"newest".to_vec()
        ),
    ));
    assert_eq!(store.get_crl(&crl_key()).expect("entry").bytes(), b"newest");
}

/// `Arc<T>` and `Arc<dyn RevocationCache>` must forward the guarded
/// inserts to the inner cache's overrides, not fall back to the trait
/// defaults.
///
/// This is the one failure mode in this area that nothing else catches:
/// omitting the two methods from the `Arc<T>` forwarding impl compiles
/// and behaves almost correctly, because the defaults do perform the
/// same comparison — just non-atomically, across a separate get and put.
/// So `Arc<InMemoryCache>` would quietly lose the single-write-lock
/// guarantee it was given, and `Arc<dyn RevocationCache>` is exactly the
/// shape the wrappers document for sharing one store between the CRL and
/// OCSP fetchers.
///
/// `Counting` overrides both methods and records the fact, so reaching
/// the default instead is observable.
#[test]
fn arc_forwards_the_guarded_inserts_to_the_inner_override() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct Counting {
        inner: InMemoryCache,
        guarded_crl: AtomicUsize,
        guarded_ocsp: AtomicUsize,
    }

    impl RevocationCache for Counting {
        fn get_crl(&self, key: &CrlCacheKey) -> Option<Arc<CachedCrl>> {
            self.inner.get_crl(key)
        }
        fn put_crl(&self, key: CrlCacheKey, entry: CachedCrl) {
            self.inner.put_crl(key, entry);
        }
        fn invalidate_crl(&self, key: &CrlCacheKey) {
            self.inner.invalidate_crl(key);
        }
        fn get_ocsp(&self, key: &OcspCacheKey) -> Option<Arc<CachedOcspResponse>> {
            self.inner.get_ocsp(key)
        }
        fn put_ocsp(&self, key: OcspCacheKey, entry: CachedOcspResponse) {
            self.inner.put_ocsp(key, entry);
        }
        fn invalidate_ocsp(&self, key: &OcspCacheKey) {
            self.inner.invalidate_ocsp(key);
        }
        fn put_crl_unless_rollback(&self, key: CrlCacheKey, entry: CachedCrl) -> bool {
            self.guarded_crl.fetch_add(1, Ordering::SeqCst);
            self.inner.put_crl_unless_rollback(key, entry)
        }
        fn put_ocsp_unless_staler(&self, key: OcspCacheKey, entry: CachedOcspResponse) -> bool {
            self.guarded_ocsp.fetch_add(1, Ordering::SeqCst);
            self.inner.put_ocsp_unless_staler(key, entry)
        }
    }

    let counting = Arc::new(Counting::default());

    // Through Arc<Counting>.
    let via_arc: Arc<Counting> = Arc::clone(&counting);
    assert!(via_arc.put_crl_unless_rollback(
        crl_key(),
        CachedCrl::new(Some(vec![1]), at(1), None, vec![0x01]),
    ));
    assert!(via_arc.put_ocsp_unless_staler(
        ocsp_key(),
        CachedOcspResponse::new(at(1), at(1), None, vec![0x01]),
    ));

    // Through Arc<dyn RevocationCache>.
    let via_dyn: Arc<dyn RevocationCache> = Arc::clone(&counting) as Arc<dyn RevocationCache>;
    assert!(via_dyn.put_crl_unless_rollback(
        crl_key(),
        CachedCrl::new(Some(vec![2]), at(2), None, vec![0x02]),
    ));
    assert!(via_dyn.put_ocsp_unless_staler(
        ocsp_key(),
        CachedOcspResponse::new(at(2), at(2), None, vec![0x02]),
    ));

    assert_eq!(
        counting.guarded_crl.load(Ordering::SeqCst),
        2,
        "Arc<T> and Arc<dyn RevocationCache> must both reach the inner \
         put_crl_unless_rollback override, not the trait default"
    );
    assert_eq!(
        counting.guarded_ocsp.load(Ordering::SeqCst),
        2,
        "same for put_ocsp_unless_staler"
    );
}
