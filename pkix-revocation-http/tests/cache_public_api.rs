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
#[derive(Default)]
struct FlatStore {
    /// `(crl_number, this_update_secs, next_update_secs, der)`
    crl: Mutex<HashMap<String, (Option<Vec<u8>>, u64, Option<u64>, Vec<u8>)>>,
    /// `(produced_at_secs, this_update_secs, next_update_secs, der)`
    ocsp: Mutex<HashMap<String, (u64, u64, Option<u64>, Vec<u8>)>>,
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
