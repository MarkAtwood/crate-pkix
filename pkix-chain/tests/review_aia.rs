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

/// A wrong-but-DN-matching intermediate must be displaced by a
/// correctly-signed alternative fetched over AIA.
///
/// This is what `is_aia_recoverable`'s rustdoc promises:
/// "`SignatureInvalid { index }` is included because a wrong-but-DN-matching
/// intermediate in the pool can be displaced by a correctly-signed
/// alternative fetched via AIA."
///
/// The scenario is an ordinary misconfiguration, not an exotic one: a
/// server staples an intermediate from the wrong CA generation — after a
/// key rollover, or a cross-signed pair mixed up — while its leaf's
/// caIssuers URI still points at the right one. `int-wrong-key.der` has
/// the real intermediate's subject DN and its own key, so the supplied
/// chain fails on signature, and `http://aia.test/int.der` serves the
/// intermediate that works.
///
/// Both halves are asserted. Validation has to succeed, and the fetcher
/// has to have been asked — a pass with an empty fetch log would mean
/// something else repaired the chain.
#[test]
fn review_aia_displaces_a_wrong_but_dn_matching_intermediate() {
    let anchors = [TrustAnchor::from_cert(load("root.der"))];
    let policy = ValidationPolicy::new(NOW_UNIX);
    let f = MapFetcher::new(HashMap::from([(
        "http://aia.test/int.der".to_owned(),
        bytes("tests/fixtures/review", "int.der"),
    )]));

    let r = Verifier::new(&anchors, &DefaultVerifier, &NoRevocation, &policy, &f)
        .verify_one(&[load("leaf.der"), load("int-wrong-key.der")]);

    assert!(
        r.is_ok(),
        "a wrong-key intermediate must be displaced by the AIA-fetched one; \
         got {r:?} after fetching {:?}",
        f.fetched()
    );
    assert!(
        f.fetched().contains(&"http://aia.test/int.der".to_owned()),
        "the AIA seam must have been consulted, fetched: {:?}",
        f.fetched()
    );
}

/// The premise of the test above, and the reason it exercises the
/// `NoPathFound` branch rather than `NoValidPath`.
///
/// `int-wrong-key.der` is *self*-issued, so a pool holding it offers no
/// topologically complete chain to the anchor at all — the path builder
/// reports `NoPathFound`, which is precisely the signal that routes into
/// an AIA fetch. With fetching disabled there is nothing to displace it,
/// so the honest answer is that the fetch was needed and refused.
#[test]
fn review_control_self_issued_wrong_intermediate_needs_an_aia_fetch() {
    let anchors = [TrustAnchor::from_cert(load("root.der"))];
    let policy = ValidationPolicy::new(NOW_UNIX);
    let wrong = load("int-wrong-key.der");

    assert_eq!(
        wrong.tbs_certificate().subject(),
        load("int.der").tbs_certificate().subject(),
        "the fixture is only interesting if its subject DN matches the real intermediate"
    );

    let r = Verifier::new(
        &anchors,
        &DefaultVerifier,
        &NoRevocation,
        &policy,
        &NoAiaFetcher,
    )
    .verify_one(&[load("leaf.der"), wrong]);
    assert!(
        matches!(r, Err(Error::Aia(_))),
        "a self-issued wrong intermediate leaves no path, so the AIA seam \
         is the only recourse and refusing it is the failure; got {r:?}"
    );
}

/// The `NoValidPath` case: a wrong-key intermediate that DOES chain to the
/// anchor, so topology completes and only the signature is wrong.
///
/// This is the one `PKIX-q9hv.2` is about. `nvp-int-wrong.der` shares
/// `nvp-int.der`'s subject DN *and* its issuer, so a pool holding it
/// yields a topologically complete chain to the anchor;
/// `build_first_valid_path` then prunes it from the signature-aware
/// search, falls back to validating the topology-only candidate, and
/// reports `NoValidPath` carrying the signature failure rather than
/// `NoPathFound`.
///
/// `is_aia_recoverable`'s rustdoc promises this is recoverable: "a
/// wrong-but-DN-matching intermediate in the pool can be displaced by a
/// correctly-signed alternative fetched via AIA". So the AIA seam has to
/// be given the chance, and the fetched intermediate has to win.
#[test]
fn review_aia_displaces_a_wrong_key_intermediate_that_chains_to_the_anchor() {
    let anchors = [TrustAnchor::from_cert(load("nvp-root.der"))];
    let policy = ValidationPolicy::new(NOW_UNIX);
    let f = MapFetcher::new(HashMap::from([(
        "http://aia.test/nvp-int.der".to_owned(),
        bytes("tests/fixtures/review", "nvp-int.der"),
    )]));

    let r = Verifier::new(&anchors, &DefaultVerifier, &NoRevocation, &policy, &f)
        .verify_one(&[load("nvp-leaf.der"), load("nvp-int-wrong.der")]);

    assert!(
        r.is_ok(),
        "a wrong-key intermediate that chains to the anchor must still be \
         displaced by the AIA-fetched one; got {r:?} after fetching {:?}",
        f.fetched()
    );
    assert!(
        f.fetched()
            .contains(&"http://aia.test/nvp-int.der".to_owned()),
        "the AIA seam must have been consulted, fetched: {:?}",
        f.fetched()
    );
}

/// The premise of the test above: the fixtures really do produce a
/// topologically complete chain that fails only on signature, and the
/// correct intermediate really does validate.
#[test]
fn review_control_nvp_fixtures_are_shaped_as_claimed() {
    let anchors = [TrustAnchor::from_cert(load("nvp-root.der"))];
    let policy = ValidationPolicy::new(NOW_UNIX);

    // Same subject DN, same issuer — so topology completes either way.
    let wrong = load("nvp-int-wrong.der");
    let real = load("nvp-int.der");
    assert_eq!(
        wrong.tbs_certificate().subject(),
        real.tbs_certificate().subject()
    );
    assert_eq!(
        wrong.tbs_certificate().issuer(),
        real.tbs_certificate().issuer()
    );

    // The correct intermediate validates with no AIA at all.
    Verifier::new(
        &anchors,
        &DefaultVerifier,
        &NoRevocation,
        &policy,
        &NoAiaFetcher,
    )
    .verify_one(&[load("nvp-leaf.der"), real])
    .expect("the correct intermediate must validate without any fetching");

    // With fetching disabled the wrong one cannot be displaced, so the
    // chain fails. See
    // `review_a_wrong_intermediate_reports_the_same_class_either_shape`
    // for which error that is and why.
    let r = Verifier::new(
        &anchors,
        &DefaultVerifier,
        &NoRevocation,
        &policy,
        &NoAiaFetcher,
    )
    .verify_one(&[load("nvp-leaf.der"), wrong]);
    assert!(r.is_err(), "the wrong-key intermediate must not validate");
}

/// Both shapes of wrong intermediate report the same class of error when
/// no AIA fetch is available, and that is deliberate.
///
/// The two shapes are a self-issued impostor (no topological path to the
/// anchor at all) and one signed by the real root (topology completes,
/// only the signature is wrong). They used to diverge: the first reported
/// `Error::Aia`, because the builder asked for a fetch, while the second
/// reported `Error::Path(SignatureInvalid)`, because the reassembly loop
/// gave up before asking. The same misconfiguration produced two
/// different diagnoses depending on who had signed the bad certificate,
/// which is not a distinction a caller can act on.
///
/// Now both ask for the fetch, so both report `Error::Aia` when it is
/// unavailable. That is the honest answer: the chain as supplied does not
/// validate, and the only route to a valid one needs a certificate the
/// caller did not provide.
#[test]
fn review_a_wrong_intermediate_reports_the_same_class_either_shape() {
    let policy = ValidationPolicy::new(NOW_UNIX);

    // Self-issued impostor, under the gen.sh hierarchy.
    let anchors_a = [TrustAnchor::from_cert(load("root.der"))];
    let a = Verifier::new(
        &anchors_a,
        &DefaultVerifier,
        &NoRevocation,
        &policy,
        &NoAiaFetcher,
    )
    .verify_one(&[load("leaf.der"), load("int-wrong-key.der")]);

    // Root-signed wrong key, under the nvp hierarchy.
    let anchors_b = [TrustAnchor::from_cert(load("nvp-root.der"))];
    let b = Verifier::new(
        &anchors_b,
        &DefaultVerifier,
        &NoRevocation,
        &policy,
        &NoAiaFetcher,
    )
    .verify_one(&[load("nvp-leaf.der"), load("nvp-int-wrong.der")]);

    assert!(
        matches!(a, Err(Error::Aia(_))),
        "self-issued impostor: expected Error::Aia, got {a:?}"
    );
    assert!(
        matches!(b, Err(Error::Aia(_))),
        "root-signed wrong key: expected Error::Aia, got {b:?}"
    );
}

/// The fetch budget bounds the newly-reachable route too.
///
/// Letting a complete-but-invalid candidate fall through to the AIA seam
/// means a chain whose signature is simply wrong — a corrupted
/// certificate rather than a stale intermediate — now spends fetches
/// before failing. That is the documented price of the recovery, and
/// `AiaConfig` is what bounds it, so the bound has to hold on this route
/// and not only on the missing-intermediate one the caps were written
/// against.
#[test]
fn review_the_fetch_budget_bounds_the_wrong_key_route() {
    let anchors = [TrustAnchor::from_cert(load("nvp-root.der"))];
    let policy = ValidationPolicy::new(NOW_UNIX);

    // A fetcher that would happily serve the fix, under a zero budget.
    let f = MapFetcher::new(HashMap::from([(
        "http://aia.test/nvp-int.der".to_owned(),
        bytes("tests/fixtures/review", "nvp-int.der"),
    )]));
    let mut cfg = AiaConfig::new();
    cfg.max_total_fetches = 0;

    let r = Verifier::new(&anchors, &DefaultVerifier, &NoRevocation, &policy, &f)
        .with_aia_config(cfg)
        .verify_one(&[load("nvp-leaf.der"), load("nvp-int-wrong.der")]);

    assert!(r.is_err(), "a zero fetch budget cannot repair the chain");
    assert_eq!(
        f.count(),
        0,
        "a zero budget must mean no request at all, fetched: {:?}",
        f.fetched()
    );

    // And one fetch is enough when the budget allows it, so the zero-budget
    // failure above is the budget and not something else.
    let g = MapFetcher::new(HashMap::from([(
        "http://aia.test/nvp-int.der".to_owned(),
        bytes("tests/fixtures/review", "nvp-int.der"),
    )]));
    let mut ok_cfg = AiaConfig::new();
    ok_cfg.max_total_fetches = 1;
    Verifier::new(&anchors, &DefaultVerifier, &NoRevocation, &policy, &g)
        .with_aia_config(ok_cfg)
        .verify_one(&[load("nvp-leaf.der"), load("nvp-int-wrong.der")])
        .expect("one fetch is all this repair needs");
    assert_eq!(g.count(), 1);
}

// ---------------------------------------------------------------------------
// AIA depth cap boundary (PKIX-4ca.2 / PKIX-q9hv.1)
// ---------------------------------------------------------------------------

/// Serves the deep chain: every hop's issuer, by URI.
fn deep_fetcher() -> MapFetcher {
    MapFetcher::new(HashMap::from([
        (
            "http://aia.test/deep-i1.der".to_owned(),
            bytes("tests/fixtures/review", "deep-i1.der"),
        ),
        (
            "http://aia.test/deep-i2.der".to_owned(),
            bytes("tests/fixtures/review", "deep-i2.der"),
        ),
        (
            "http://aia.test/deep-i3.der".to_owned(),
            bytes("tests/fixtures/review", "deep-i3.der"),
        ),
        (
            "http://aia.test/deep-i4.der".to_owned(),
            bytes("tests/fixtures/review", "deep-i4.der"),
        ),
        (
            "http://aia.test/deep-i5.der".to_owned(),
            bytes("tests/fixtures/review", "deep-i5.der"),
        ),
    ]))
}

/// The certificates fetched in the *last* round must be consulted.
///
/// `AIA_MAX_DEPTH` is 5 and the reassembly loop performs 5 fetch rounds.
/// The loop used to add the fifth round's certificates to the pool and
/// then exit without ever asking the path builder again, so a chain that
/// needed all five was reported `AiaDepthExceeded` even though the
/// certificate completing it was already in hand — the last fetch was
/// wasted, and `AIA_MAX_DEPTH = 5` effectively meant four hops resolved.
///
/// `deep-leaf.der` needs exactly five sequential fetches: each hop's
/// issuer is discoverable only from the caIssuers URI of the certificate
/// below it. So this validates only if a build attempt runs after the
/// fifth fetch.
///
/// The decisive assertion is that `Deep I5` appears in the result. It
/// arrives in the final round, so its presence means that round was used
/// rather than merely paid for.
#[test]
fn review_aia_depth_cap_consults_the_final_fetch() {
    let anchors = [TrustAnchor::from_cert(load("deep-root.der"))];
    let policy = ValidationPolicy::new(NOW_UNIX);
    let f = deep_fetcher();

    let r = Verifier::new(&anchors, &DefaultVerifier, &NoRevocation, &policy, &f)
        .verify_one(&[load("deep-leaf.der")]);

    assert!(
        r.is_ok(),
        "a chain needing all {} fetch rounds must still validate; got {r:?} \
         after fetching {:?}",
        AiaConfig::new().max_depth,
        f.fetched()
    );

    assert_eq!(
        f.count(),
        5,
        "five sequential hops take five fetches, no more and no fewer: {:?}",
        f.fetched()
    );
    assert!(
        f.fetched()
            .contains(&"http://aia.test/deep-i5.der".to_owned()),
        "the top intermediate is only reachable in the final round: {:?}",
        f.fetched()
    );
}

/// One hop short of the cap must fail, so the test above is measuring the
/// boundary rather than a chain that was always going to fit.
///
/// With four rounds the fifth intermediate is never fetched, so no build
/// attempt can complete the chain however many times it runs.
#[test]
fn review_aia_depth_cap_one_hop_short_fails() {
    let anchors = [TrustAnchor::from_cert(load("deep-root.der"))];
    let policy = ValidationPolicy::new(NOW_UNIX);
    let f = deep_fetcher();
    let mut cfg = AiaConfig::new();
    cfg.max_depth = 4;

    let r = Verifier::new(&anchors, &DefaultVerifier, &NoRevocation, &policy, &f)
        .with_aia_config(cfg)
        .verify_one(&[load("deep-leaf.der")]);

    assert!(
        matches!(r, Err(Error::AiaDepthExceeded)),
        "four rounds cannot resolve five hops; expected AiaDepthExceeded, \
         got {r:?} after fetching {:?}",
        f.fetched()
    );
}

/// `AiaConfig::max_depth` counts hops resolved, which is what its
/// documentation claims. Raising the cap by one resolves one more hop.
///
/// This pins the off-by-one in both directions: a cap of N resolves a
/// chain needing N fetches and not one needing N + 1. Were the final
/// build attempt removed, the first of these would fail; were an extra
/// round allowed, the second would pass.
#[test]
fn review_aia_max_depth_counts_hops_resolved() {
    let anchors = [TrustAnchor::from_cert(load("deep-root.der"))];
    let policy = ValidationPolicy::new(NOW_UNIX);

    for (cap, expect_ok) in [(3usize, false), (4, false), (5, true), (6, true)] {
        let f = deep_fetcher();
        let mut cfg = AiaConfig::new();
        cfg.max_depth = cap;
        let r = Verifier::new(&anchors, &DefaultVerifier, &NoRevocation, &policy, &f)
            .with_aia_config(cfg)
            .verify_one(&[load("deep-leaf.der")]);
        assert_eq!(
            r.is_ok(),
            expect_ok,
            "max_depth = {cap} on a 5-hop chain: expected ok={expect_ok}, \
             got {r:?} after {} fetches",
            f.count()
        );
    }
}

/// With no fetcher to recover from it, a wrong-key intermediate that
/// completes the topology is reported as the path builder's own
/// `NoValidPath`, carrying the typed signature failure.
///
/// This is the terminal half of
/// `review_aia_displaces_a_wrong_key_intermediate_that_chains_to_the_anchor`
/// above: same fixtures, but `NoAiaFetcher`, so nothing can displace the
/// bad intermediate and the build has to explain itself.
///
/// It used to answer differently. The driver dropped `NoValidPath`'s
/// payload, rebuilt a chain with topology-only `build_path`, and handed
/// that back for the caller to re-validate — so the error described
/// whatever that second, signature-blind search happened to return. Since
/// `build_first_valid_path` prunes candidates by signature and
/// `build_path` does not, the two could disagree about which chain failed.
/// Now the failure from the attempt that actually ran is propagated, and
/// `last_error` is a `pkix_path::Error` the caller can match on rather
/// than a rendered string.
#[test]
fn a_wrong_key_intermediate_reports_the_typed_validation_failure() {
    let anchors = [TrustAnchor::from_cert(load("nvp-root.der"))];
    let policy = ValidationPolicy::new(NOW_UNIX);

    // `max_uris_per_cert = 0` so no caIssuers URI is ever collected: AIA
    // cannot contribute, and the build has to answer from the pool it has.
    //
    // Getting there needs care, because two other reports outrank this one
    // and both are right to. `NoAiaFetcher` fails the fetch, and an
    // attempted-and-failed fetch is the more informative signal, so that
    // yields Aia(FetchingDisabled). A fetcher that succeeds but returns a
    // certificate already in the pool adds nothing, and `absorb` reports
    // that as Aia too. Only when no URI is tried at all does the path
    // builder's own verdict become the most informative thing known.
    let mut cfg = AiaConfig::new();
    cfg.max_uris_per_cert = 0;

    let f = MapFetcher::new(HashMap::new());
    let err = Verifier::new(&anchors, &DefaultVerifier, &NoRevocation, &policy, &f)
        .with_aia_config(cfg)
        .verify_one(&[load("nvp-leaf.der"), load("nvp-int-wrong.der")])
        .expect_err("the wrong-key intermediate cannot validate and AIA cannot help");
    assert_eq!(f.count(), 0, "no URI should have been tried");

    match err {
        Error::PathBuild(pkix_path_builder::Error::NoValidPath {
            tried, last_error, ..
        }) => {
            assert!(tried >= 1, "at least one candidate was tried, got {tried}");
            assert!(
                matches!(last_error, pkix_path::Error::SignatureInvalid { .. }),
                "the intermediate's key did not sign the leaf, so the cause should be \
                 SignatureInvalid; got {last_error:?}"
            );
        }
        other => panic!("expected PathBuild(NoValidPath {{ .. }}), got {other:?}"),
    }
}

/// A fetch that succeeds and adds nothing reports `NoNewIssuer`, not
/// `FetchingDisabled`.
///
/// The repository here serves the same wrong-key intermediate the caller
/// already supplied — a stale CA generation still published at its AIA
/// URI, which is an ordinary misconfiguration rather than an attack. The
/// fetch is made and answered, so there is no fetch error to report, and
/// the pool refuses the duplicate, so nothing advances.
///
/// That used to surface as `Aia(FetchingDisabled)`, which is untrue in a
/// way that misdirects: an operator reads it as "my fetcher is switched
/// off" and goes auditing configuration, when the fetcher is working
/// perfectly and the repository is the problem. It was found while
/// writing the test for the topology-only fallback removal, where it was
/// one of two reports that outranked the one under test.
#[test]
fn a_fetch_that_adds_nothing_is_not_reported_as_fetching_disabled() {
    let anchors = [TrustAnchor::from_cert(load("nvp-root.der"))];
    let policy = ValidationPolicy::new(NOW_UNIX);
    let f = MapFetcher::new(HashMap::from([(
        "http://aia.test/nvp-int.der".to_owned(),
        bytes("tests/fixtures/review", "nvp-int-wrong.der"),
    )]));

    let err = Verifier::new(&anchors, &DefaultVerifier, &NoRevocation, &policy, &f)
        .verify_one(&[load("nvp-leaf.der"), load("nvp-int-wrong.der")])
        .expect_err("the repository serves a certificate already in the pool");

    assert_eq!(
        f.count(),
        1,
        "the fetch must actually have happened, or this proves nothing"
    );
    assert!(
        matches!(err, Error::Aia(AiaError::NoNewIssuer)),
        "expected Aia(NoNewIssuer); got {err:?}"
    );
    assert!(
        !matches!(err, Error::Aia(AiaError::FetchingDisabled)),
        "fetching was not disabled — a request was made and answered"
    );
}

/// A trust anchor whose subject matches the issuer a certificate names,
/// but whose key did not sign it, must not suppress the AIA fetch.
///
/// `orphans_on_paths` asks "is this certificate's issuer already
/// available?" and counts an anchor only when its name matches *and* its
/// key verifies the signature. Dropping the second half makes any
/// same-named anchor answer yes: the certificate stops looking like an
/// orphan, its `caIssuers` URI is never requested, and a chain that AIA
/// could have completed fails instead. An attacker who can get one
/// same-named certificate into a relying party's anchor set -- a stale
/// root, a cross-signed pair's other half, a decoy -- would then be able
/// to switch off AIA discovery for every certificate under that name.
///
/// `int-wrong-key.der` is the fixture for exactly this shape: same subject
/// DN as `int.der`, different key.
#[test]
fn review_aia_runs_despite_a_same_named_anchor_with_the_wrong_key() {
    let real_int = load("int.der");
    let decoy = load("int-wrong-key.der");
    assert_eq!(
        decoy.tbs_certificate().subject(),
        real_int.tbs_certificate().subject(),
        "fixture premise: the decoy anchor shares the real intermediate's DN"
    );

    let anchors = [
        TrustAnchor::from_cert(load("root.der")),
        TrustAnchor::from_cert(decoy),
    ];
    let policy = ValidationPolicy::new(NOW_UNIX);
    let f = MapFetcher::new(HashMap::from([(
        "http://aia.test/int.der".to_owned(),
        bytes("tests/fixtures/review", "int.der"),
    )]));

    // The pool holds the leaf alone, so the intermediate can only come
    // from the fetch.
    let r = Verifier::new(&anchors, &DefaultVerifier, &NoRevocation, &policy, &f)
        .verify_one(&[load("leaf.der")]);

    assert!(
        r.is_ok(),
        "the same-named anchor must not stand in for the missing issuer; \
         got {r:?} after fetching {:?}",
        f.fetched()
    );
    assert!(
        f.fetched().contains(&"http://aia.test/int.der".to_owned()),
        "the AIA seam must have been consulted, fetched: {:?}",
        f.fetched()
    );
}

/// The total-fetch budget has to deplete across rounds, not only within
/// one.
///
/// `review_aia_total_fetch_cap` above spends the whole budget in a single
/// round: 64 URIs on one certificate hit the limit while they are being
/// collected, before the counter is ever decremented. So it says nothing
/// about the decrement, and an arithmetic error there -- a budget that grows
/// instead of shrinking, or stays put -- left AIA fetching bounded only by
/// `max_depth`.
///
/// The deep chain is the shape that shows it: each round resolves exactly
/// one hop, so a budget of three against five hops must stop after three
/// fetches. A budget that does not deplete reaches the anchor and returns
/// `Ok`.
#[test]
fn review_aia_total_fetch_budget_depletes_across_rounds() {
    let anchors = [TrustAnchor::from_cert(load("deep-root.der"))];
    let policy = ValidationPolicy::new(NOW_UNIX);
    let f = deep_fetcher();
    let mut cfg = AiaConfig::new();
    cfg.max_total_fetches = 3;

    let r = Verifier::new(&anchors, &DefaultVerifier, &NoRevocation, &policy, &f)
        .with_aia_config(cfg)
        .verify_one(&[load("deep-leaf.der")]);

    assert!(
        r.is_err(),
        "five hops on a budget of three must not complete; got {r:?} after \
         fetching {:?}",
        f.fetched()
    );
    assert_eq!(
        f.count(),
        3,
        "the budget bounds the fetches, one per round: {:?}",
        f.fetched()
    );
}
