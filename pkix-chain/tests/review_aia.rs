//! Review tests for `Verifier::verify_one` AIA chain reassembly and
//! path building over attacker-supplied bags.
//!
//! Fixtures: `tests/fixtures/review/` (generator: `gen.sh` there; OpenSSL
//! oracle). Hierarchy: `root.der` (anchor) -> `int.der` -> `leaf.der`.
//! `leaf.der` carries caIssuers `http://aia.test/int.der`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use pkix_aia::{AiaError, AiaFetcher};
use pkix_chain::{
    verify_chain, AiaConfig, DefaultVerifier, Error, NoAiaFetcher, NoRevocation, Verifier,
};
use pkix_path::{TrustAnchor, ValidationPolicy};
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

const NOW_UNIX: u64 = 1_900_000_000;

fn bytes(dir: &str, name: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(dir)
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}
fn load(name: &str) -> Certificate {
    Certificate::from_der(&bytes("tests/fixtures/review", name)).expect("parse")
}

/// URI -> body map; records every fetched URI.
struct MapFetcher {
    map: HashMap<String, Vec<u8>>,
    log: Mutex<Vec<String>>,
}
impl MapFetcher {
    fn new(map: HashMap<String, Vec<u8>>) -> Self {
        Self {
            map,
            log: Mutex::new(Vec::new()),
        }
    }
    fn count(&self) -> usize {
        self.log.lock().unwrap().len()
    }
    fn fetched(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
}
impl AiaFetcher for MapFetcher {
    fn fetch(&self, uri: &str) -> Result<Vec<u8>, AiaError> {
        self.log.lock().unwrap().push(uri.to_owned());
        self.map.get(uri).cloned().ok_or(AiaError::HttpStatus(404))
    }
}

/// Control: DER response is accepted.
#[test]
fn review_control_der_aia_response() {
    let anchors = [TrustAnchor::from_cert(load("root.der"))];
    let policy = ValidationPolicy::new(NOW_UNIX);
    let f = MapFetcher::new(HashMap::from([(
        "http://aia.test/int.der".to_owned(),
        bytes("tests/fixtures/review", "int.der"),
    )]));
    Verifier::new(&anchors, &DefaultVerifier, &NoRevocation, &policy, &f)
        .verify_one(&[load("leaf.der")])
        .expect("DER caIssuers response must work");
}

/// BUG (false reject): RFC 5280 §4.2.2.1 — an HTTP caIssuers URI "MUST
/// point to either a single DER encoded certificate ... or a collection
/// of certificates in a BER or DER encoded 'certs-only' CMS message".
/// `build_with_aia` only tries `Certificate::from_der`, so the second,
/// equally conforming form (`.p7c`, what e.g. US FPKI and many enterprise
/// CAs publish) is rejected as `MalformedCertificate`.
#[test]
fn review_aia_certs_only_cms_response_is_accepted() {
    let anchors = [TrustAnchor::from_cert(load("root.der"))];
    let policy = ValidationPolicy::new(NOW_UNIX);
    let f = MapFetcher::new(HashMap::from([(
        "http://aia.test/int.der".to_owned(),
        bytes("tests/fixtures/review", "int.p7c"),
    )]));
    let r = Verifier::new(&anchors, &DefaultVerifier, &NoRevocation, &policy, &f)
        .verify_one(&[load("leaf.der")]);
    assert!(
        r.is_ok(),
        "certs-only CMS caIssuers response rejected: {r:?}"
    );
}

/// BUG (DoS / unbounded work): no cap on caIssuers URIs fetched per cert,
/// per iteration, or per verification. `leaf-fan64.der` has 64 URIs; each
/// response (`relay-I.der`) is a parseable non-CA cert with 64 fresh URIs.
/// All 64 + 64*64 = 4160 URIs are fetched sequentially in one
/// `verify_one` call (and the tree keeps multiplying for AIA_MAX_DEPTH
/// levels while responses parse). With `HttpFetcher`'s 10 s per-request
/// timeout and no overall deadline that is hours of blocking from one
/// attacker-presented certificate.
#[test]
fn review_aia_fetch_count_is_bounded() {
    let anchors = [TrustAnchor::from_cert(load("root.der"))];
    let policy = ValidationPolicy::new(NOW_UNIX);
    let mut map = HashMap::new();
    for i in 0..64 {
        map.insert(
            format!("http://aia.test/fan/{i}.der"),
            bytes("tests/fixtures/review", &format!("relay-{i}.der")),
        );
    }
    let f = MapFetcher::new(map);
    let r = Verifier::new(&anchors, &DefaultVerifier, &NoRevocation, &policy, &f)
        .verify_one(&[load("leaf-fan64.der")]);
    assert!(r.is_err());
    let n = f.count();
    assert!(n <= 16, "one verify_one call issued {n} AIA fetches");
}

/// BUG (false reject, attacker-triggerable): an unordered bag `[leaf,
/// 40 decoys, int]` where the decoys are self-issued `CN=Review Int` CA
/// certs copying int's SKI (see pkix-path-builder/tests/review_adversarial_pool.rs).
/// The valid path `[leaf, int]` is present, but `verify_chain` (no AIA)
/// returns `PathBuild(BudgetExceeded)`. In S/MIME the
/// `SignedData.certificates` bag is unsigned, so a MITM can append the
/// decoys to break verification of any message.
#[test]
fn review_decoy_bag_does_not_break_valid_chain() {
    let anchors = [TrustAnchor::from_cert(load("root.der"))];
    let policy = ValidationPolicy::new(NOW_UNIX);
    let mut chain = vec![load("leaf.der")];
    for i in 0..40 {
        chain.push(
            Certificate::from_der(&bytes(
                "../pkix-path-builder/tests/fixtures/review",
                &format!("bogus-int-{i}.der"),
            ))
            .unwrap(),
        );
    }
    chain.push(load("int.der"));
    let r = verify_chain(
        &chain,
        &anchors,
        &policy,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    );
    match r {
        Ok(v) => assert_eq!(v.depth, 1),
        Err(Error::PathBuild(e)) => panic!("valid [leaf, int] path not found: PathBuild({e:?})"),
        Err(e) => panic!("unexpected: {e:?}"),
    }
}

fn fan64_fetcher() -> MapFetcher {
    let mut map = HashMap::new();
    for i in 0..64 {
        map.insert(
            format!("http://aia.test/fan/{i}.der"),
            bytes("tests/fixtures/review", &format!("relay-{i}.der")),
        );
    }
    MapFetcher::new(map)
}

/// Default `AiaConfig::max_uris_per_cert` (2): only the first two of the
/// leaf's 64 caIssuers URIs are fetched, and the non-CA relay certs they
/// return are neither pooled nor asked for their own URIs.
#[test]
fn review_aia_default_per_cert_uri_cap() {
    let anchors = [TrustAnchor::from_cert(load("root.der"))];
    let policy = ValidationPolicy::new(NOW_UNIX);
    let f = fan64_fetcher();
    let r = Verifier::new(&anchors, &DefaultVerifier, &NoRevocation, &policy, &f)
        .verify_one(&[load("leaf-fan64.der")]);
    assert!(r.is_err());
    assert_eq!(
        f.fetched(),
        vec![
            "http://aia.test/fan/0.der".to_owned(),
            "http://aia.test/fan/1.der".to_owned()
        ]
    );
}

/// `max_total_fetches` caps fetches across the call even when the
/// per-cert cap would allow more.
#[test]
fn review_aia_total_fetch_cap() {
    let anchors = [TrustAnchor::from_cert(load("root.der"))];
    let policy = ValidationPolicy::new(NOW_UNIX);
    let f = fan64_fetcher();
    let mut cfg = AiaConfig::new();
    cfg.max_uris_per_cert = 64;
    cfg.max_total_fetches = 3;
    let r = Verifier::new(&anchors, &DefaultVerifier, &NoRevocation, &policy, &f)
        .with_aia_config(cfg)
        .verify_one(&[load("leaf-fan64.der")]);
    assert!(r.is_err());
    assert_eq!(f.count(), 3);
}

/// An elapsed deadline stops AIA fetching before the next round.
#[test]
fn review_aia_deadline() {
    let anchors = [TrustAnchor::from_cert(load("root.der"))];
    let policy = ValidationPolicy::new(NOW_UNIX);
    let f = fan64_fetcher();
    let mut cfg = AiaConfig::new();
    cfg.deadline = Some(std::time::Duration::ZERO);
    let r = Verifier::new(&anchors, &DefaultVerifier, &NoRevocation, &policy, &f)
        .with_aia_config(cfg)
        .verify_one(&[load("leaf-fan64.der")]);
    assert_eq!(r, Err(Error::AiaDeadlineExceeded));
    assert_eq!(f.count(), 0);
}

/// Certs that are not on a potential path from the leaf (here a second,
/// unrelated EE cert in the bag) are never asked for their URIs.
#[test]
fn review_aia_ignores_uris_of_certs_off_the_path() {
    let anchors = [TrustAnchor::from_cert(load("root.der"))];
    let policy = ValidationPolicy::new(NOW_UNIX);
    let mut map = HashMap::new();
    map.insert(
        "http://aia.test/int.der".to_owned(),
        bytes("tests/fixtures/review", "int.der"),
    );
    let f = MapFetcher::new(map);
    let v = Verifier::new(&anchors, &DefaultVerifier, &NoRevocation, &policy, &f)
        .verify_one(&[load("leaf.der"), load("leaf-fan64.der")])
        .expect("leaf -> fetched int -> root");
    assert_eq!(v.depth, 1);
    assert_eq!(f.fetched(), vec!["http://aia.test/int.der".to_owned()]);
}
