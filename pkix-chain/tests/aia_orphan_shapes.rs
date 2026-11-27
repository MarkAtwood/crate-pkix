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

/// `verify_one`'s fast path refuses a certificate-correctness failure
/// without attempting a fetch.
///
/// The rustdoc on `verify_one` promises exactly this -- an expired leaf,
/// a wrong KeyUsage or a name-constraint violation surfaces directly,
/// "without ever attempting AIA fetching that cannot help" -- and nothing
/// asserted it. `is_aia_recoverable` is what keeps the promise; widened to
/// admit a validity failure, every expired certificate in a batch would
/// cost a round trip to its CA's AIA endpoint, which can only return a
/// certificate that changes nothing.
///
/// The leaf's validity ended in 2010, and the intermediate carries a
/// `caIssuers` URI the fetcher would serve, so a fetch would be visible.
#[test]
fn a_certificate_correctness_failure_costs_no_fetch() {
    let anchors = [TrustAnchor::from_cert(load("anchored-root.der"))];
    let policy = ValidationPolicy::new(NOW_UNIX);
    let f = MapFetcher::new(&[("http://aia.test/anchored-root.der", "anchored-root.der")]);

    let r = Verifier::new(&anchors, &DefaultVerifier, &NoRevocation, &policy, &f)
        .verify_one(&[load("anchored-leaf-expired.der"), load("anchored-int.der")]);

    assert!(r.is_err(), "an expired leaf must not validate; got {r:?}");
    assert_eq!(
        f.fetched(),
        Vec::<String>::new(),
        "nothing should have been fetched: the intermediate's issuer is the \
         anchor, so its caIssuers URI cannot contribute"
    );
}

/// The orphan walk does not ask a certificate the trust anchor issued for
/// its `caIssuers` URIs.
///
/// Fetching there can only produce a certificate the anchor set already
/// supersedes: the request tells the CA's AIA endpoint which certificate is
/// being validated and buys nothing.
///
/// Reaching the predicate with an anchor-issued certificate takes the
/// sans-I/O surface rather than `verify_one`. The walk only visits a
/// certificate it has a verified issuer link to, so an anchor-issued one is
/// visited only when the pool holds a complete, signature-valid path --
/// and `verify_one`'s fast path answers that case before reassembly starts,
/// because a validity failure is not AIA-recoverable. Driving `next_step`
/// directly skips the fast path, which is what a caller doing its own I/O
/// does.
///
/// The anchor-issued intermediate here carries a `caIssuers` URI so that a
/// wrongly-included orphan shows up as a `Fetch`. `deep-i5.der`, the
/// corpus's only other anchor-issued intermediate, carries no AIA
/// extension, which is why this conjunct had no test.
#[test]
fn the_orphan_walk_skips_an_anchor_issued_certificate() {
    use pkix_chain::sans_io::{BuildStep, ChainBuildState, ChainBuilder};
    use pkix_chain::AiaConfig;

    let anchors = [TrustAnchor::from_cert(load("anchored-root.der"))];
    let policy = ValidationPolicy::new(NOW_UNIX);
    let config = AiaConfig::default();
    let builder = ChainBuilder {
        anchors: &anchors,
        sig_verifier: &DefaultVerifier,
        policy: &policy,
        config: &config,
    };

    let chain = [load("anchored-leaf-expired.der"), load("anchored-int.der")];
    let mut state = ChainBuildState::new(&chain, &config);

    match builder.next_step(&mut state, &chain[0]) {
        BuildStep::Failed(_) => {}
        BuildStep::Fetch(uris) => panic!(
            "nothing is missing: the intermediate's issuer is the anchor, so \
             its caIssuers URI cannot contribute, yet {uris:?} was requested"
        ),
        BuildStep::Built(_) => panic!("the leaf is expired; this must not build"),
    }
}
