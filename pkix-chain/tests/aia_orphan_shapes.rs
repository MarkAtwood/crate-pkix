//! The two pool shapes `orphans_on_paths` has to get right.
//!
//! `Verifier::build_with_aia` asks a certificate for its `caIssuers` URIs
//! only when its issuer is not already available in the pool or the anchor
//! set. Deciding that wrongly fails quietly: the URI is never requested,
//! and a chain AIA could have completed reports "no path found".
//!
//! Both cases here are shapes the predicate has to exclude, and both are
//! real: an issuer certificate with no `basicConstraints`, and a
//! self-signed root that the relying party does not trust but whose
//! cross-certificate it can fetch.
//!
//! Fixtures and their rationale: `tests/fixtures/aia-orphan-shapes/gen.py`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use pkix_aia::{AiaError, AiaFetcher};
use pkix_chain::{DefaultVerifier, NoRevocation, Verifier};
use pkix_path::{TrustAnchor, ValidationPolicy};
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

const NOW_UNIX: u64 = 1_900_000_000;
const DIR: &str = "tests/fixtures/aia-orphan-shapes";

fn bytes(name: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(DIR)
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

fn load(name: &str) -> Certificate {
    Certificate::from_der(&bytes(name)).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

struct MapFetcher {
    map: HashMap<String, Vec<u8>>,
    log: Mutex<Vec<String>>,
}

impl MapFetcher {
    fn new(pairs: &[(&str, &str)]) -> Self {
        Self {
            map: pairs
                .iter()
                .map(|(uri, file)| ((*uri).to_owned(), bytes(file)))
                .collect(),
            log: Mutex::new(Vec::new()),
        }
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

/// An issuer-shaped certificate with no `basicConstraints` must not stand in
/// for the CA, and must not suppress the fetch that finds the real one.
///
/// `noca-int-ee` holds the same subject DN *and the same public key* as
/// `noca-int-ca`, so it does verify the leaf's signature. Only the CA bit
/// separates them, which is what makes the `cert_is_ca` test load-bearing:
/// with a different key the signature check would already have rejected it
/// and the CA bit would decide nothing.
///
/// It is also self-issued, so the pool offers no complete path to the
/// anchor. That matters for what this test measures: a copy issued by the
/// root would give the path builder a complete candidate, validation would
/// reject it with `NotCA` straight away, and the orphan predicate would
/// never be consulted.
#[test]
fn a_non_ca_issuer_in_the_pool_does_not_suppress_the_fetch() {
    let anchors = [TrustAnchor::from_cert(load("noca-root.der"))];
    let policy = ValidationPolicy::new(NOW_UNIX);
    let f = MapFetcher::new(&[("http://aia.test/noca-int-ca.der", "noca-int-ca.der")]);

    let r = Verifier::new(&anchors, &DefaultVerifier, &NoRevocation, &policy, &f)
        .verify_one(&[load("noca-leaf.der"), load("noca-int-ee.der")]);

    assert!(
        r.is_ok(),
        "the non-CA namesake must be displaced by the AIA-fetched CA; \
         got {r:?} after fetching {:?}",
        f.fetched()
    );
    assert!(
        f.fetched()
            .contains(&"http://aia.test/noca-int-ca.der".to_owned()),
        "the AIA seam must have been consulted, fetched: {:?}",
        f.fetched()
    );
}

/// The premise of the test above: without the fetch, the non-CA namesake
/// cannot complete the chain on its own.
///
/// Otherwise a predicate that wrongly accepted it would still pass, because
/// the chain would validate without ever needing AIA.
#[test]
fn the_non_ca_namesake_cannot_complete_the_chain_alone() {
    let anchors = [TrustAnchor::from_cert(load("noca-root.der"))];
    let policy = ValidationPolicy::new(NOW_UNIX);
    let f = MapFetcher::new(&[]);

    let r = Verifier::new(&anchors, &DefaultVerifier, &NoRevocation, &policy, &f)
        .verify_one(&[load("noca-leaf.der"), load("noca-int-ee.der")]);

    assert!(
        r.is_err(),
        "a certificate with no basicConstraints must not serve as a CA"
    );
}

/// A self-signed root in the pool that is not a trust anchor still needs its
/// issuer: its cross-certificate.
///
/// This is how a root transition works -- the relying party trusts A, the
/// chain was built under R, and R's `caIssuers` points at R-certified-by-A.
/// A self-signed certificate matches its own subject to its own issuer and
/// verifies its own signature, so a predicate that does not exclude the
/// certificate under consideration concludes that R is its own issuer and
/// never asks for the cross-certificate.
#[test]
fn a_self_signed_root_in_the_pool_is_still_asked_for_its_issuer() {
    let anchors = [TrustAnchor::from_cert(load("xsign-a.der"))];
    let policy = ValidationPolicy::new(NOW_UNIX);
    let f = MapFetcher::new(&[("http://aia.test/xsign-r-cross.der", "xsign-r-cross.der")]);

    let r = Verifier::new(&anchors, &DefaultVerifier, &NoRevocation, &policy, &f).verify_one(&[
        load("xsign-leaf.der"),
        load("xsign-int.der"),
        load("xsign-r-self.der"),
    ]);

    assert!(
        r.is_ok(),
        "the cross-certificate must be fetched and complete the chain to A; \
         got {r:?} after fetching {:?}",
        f.fetched()
    );
    assert!(
        f.fetched()
            .contains(&"http://aia.test/xsign-r-cross.der".to_owned()),
        "R's caIssuers URI must have been requested, fetched: {:?}",
        f.fetched()
    );
}

/// The premise: the pool on its own reaches R and stops, because R is
/// self-signed and A never certified it directly.
#[test]
fn the_untrusted_self_signed_root_cannot_reach_the_anchor_alone() {
    let anchors = [TrustAnchor::from_cert(load("xsign-a.der"))];
    let policy = ValidationPolicy::new(NOW_UNIX);
    let f = MapFetcher::new(&[]);

    let r = Verifier::new(&anchors, &DefaultVerifier, &NoRevocation, &policy, &f).verify_one(&[
        load("xsign-leaf.der"),
        load("xsign-int.der"),
        load("xsign-r-self.der"),
    ]);

    assert!(
        r.is_err(),
        "an untrusted self-signed root must not terminate the path"
    );
}
