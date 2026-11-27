//! The sans-I/O verify surface, driven from both a synchronous and an
//! asynchronous caller.
//!
//! The point of this surface is that `pkix-chain` performs no I/O and holds no
//! opinion about runtimes: it says *what* to fetch and *what* to check, and
//! the caller does both. These tests exercise it from an async task with no
//! `async-trait`, no `AsyncAiaFetcher`, and no HTTP client anywhere in
//! `pkix-chain`'s dependency graph — which is the property that made the
//! async-twin design unnecessary.
//!
//! Fixtures are `aia_chain_build.rs`'s, because they are the ones that carry
//! an `id-ad-caIssuers` URI. The PKITS §4.1.1 chain used elsewhere in this
//! crate has no AIA extension at all, so reassembly over it reports
//! `NoPathFound` without ever asking for a fetch — correct behaviour, but it
//! demonstrates nothing about the driving loop.

use std::sync::atomic::{AtomicUsize, Ordering};

use pkix_aia::AiaError;
use pkix_chain::sans_io::{BuildStep, ChainBuildState, ChainBuilder, RevocationTarget};
use pkix_chain::{AiaConfig, DefaultVerifier, Error};
use pkix_path::{TrustAnchor, ValidationPolicy};
use x509_cert::Certificate;

const PKITS_NOW: u64 = 1_577_836_800;

const TRUST_ANCHOR_DER: &[u8] = include_bytes!("fixtures/root.der");
const GOOD_CA_DER: &[u8] = include_bytes!("fixtures/intermediate.der");
const VALID_EE_DER: &[u8] = include_bytes!("fixtures/leaf-via-intermediate.der");
/// Same shape as the leaf above but with no AIA extension, for the case where
/// there is nothing to follow.
const LEAF_NO_AIA_DER: &[u8] = include_bytes!("fixtures/leaf-via-intermediate-no-aia.der");

fn load(der: &[u8]) -> Certificate {
    use x509_cert::der::Decode as _;
    Certificate::from_der(der).expect("parse cert")
}

fn policy() -> ValidationPolicy {
    ValidationPolicy::new(PKITS_NOW)
}

/// A builder over the PKITS anchor, with default AIA bounds.
fn builder<'a>(
    anchors: &'a [TrustAnchor],
    policy: &'a ValidationPolicy,
    config: &'a AiaConfig,
) -> ChainBuilder<'a, DefaultVerifier> {
    ChainBuilder {
        anchors,
        sig_verifier: &DefaultVerifier,
        policy,
        config,
    }
}

/// A complete chain needs no fetching: the first step builds.
#[test]
fn a_complete_chain_builds_without_any_fetch() {
    let anchors = [TrustAnchor::from_cert(load(TRUST_ANCHOR_DER))];
    let policy = policy();
    let config = AiaConfig::default();
    let b = builder(&anchors, &policy, &config);

    let chain = [load(VALID_EE_DER), load(GOOD_CA_DER)];
    let fetches = AtomicUsize::new(0);

    let built = b
        .build_with(&chain, |_uris| {
            fetches.fetch_add(1, Ordering::SeqCst);
            Vec::new()
        })
        .expect("a complete chain should build");

    assert_eq!(built.len(), 2);
    assert_eq!(
        fetches.load(Ordering::SeqCst),
        0,
        "no fetch should be requested for a chain that is already complete"
    );
}

/// An incomplete chain asks for the missing issuer, and the caller supplying
/// it completes the build. This is the loop an async caller writes, run
/// synchronously.
#[test]
fn an_incomplete_chain_asks_for_what_it_needs() {
    let anchors = [TrustAnchor::from_cert(load(TRUST_ANCHOR_DER))];
    let policy = policy();
    let config = AiaConfig::default();
    let b = builder(&anchors, &policy, &config);

    // Leaf only: GoodCACert is missing.
    let chain = [load(VALID_EE_DER)];
    let leaf = &chain[0];
    let mut state = ChainBuildState::new(&chain, &config);

    let mut rounds = 0;
    let built = loop {
        match b.next_step(&mut state, leaf) {
            BuildStep::Built(built) => break built,
            BuildStep::Failed(e) => panic!("reassembly failed: {e}"),
            BuildStep::Fetch(uris) => {
                rounds += 1;
                assert!(!uris.is_empty(), "a Fetch step must name at least one URI");
                // Answer every URI with the missing CA, as an AIA endpoint
                // would.
                let results = uris
                    .iter()
                    .map(|_| Ok(GOOD_CA_DER.to_vec()))
                    .collect::<Vec<Result<Vec<u8>, AiaError>>>();
                if let Some(e) = b.absorb(&mut state, results, uris.len()) {
                    panic!("absorb failed: {e}");
                }
            }
        }
    };

    assert_eq!(rounds, 1, "one round should have sufficed");
    assert_eq!(built.len(), 2, "the built chain should be leaf + CA");
    assert_eq!(built[0], load(VALID_EE_DER));
    assert_eq!(built[1], load(GOOD_CA_DER));
}

/// The same reassembly driven from an async task.
///
/// This is the test the whole sans-I/O design exists for. Note what is absent:
/// no `AsyncAiaFetcher`, no `async-trait`, no HTTP client. `pkix-chain` does
/// not know a runtime is involved, and an async consumer needs nothing from it
/// beyond this loop.
#[tokio::test]
async fn an_async_caller_drives_the_same_reassembly() {
    /// Stands in for an async HTTP client.
    async fn fetch_all(uris: &[String]) -> Vec<Result<Vec<u8>, AiaError>> {
        // A real client would issue these concurrently; the point here is
        // only that the call is awaited.
        tokio::task::yield_now().await;
        uris.iter().map(|_| Ok(GOOD_CA_DER.to_vec())).collect()
    }

    let anchors = [TrustAnchor::from_cert(load(TRUST_ANCHOR_DER))];
    let policy = policy();
    let config = AiaConfig::default();
    let b = builder(&anchors, &policy, &config);

    let chain = [load(VALID_EE_DER)];
    let leaf = &chain[0];
    let mut state = ChainBuildState::new(&chain, &config);

    let built = loop {
        match b.next_step(&mut state, leaf) {
            BuildStep::Built(built) => break built,
            BuildStep::Failed(e) => panic!("reassembly failed: {e}"),
            BuildStep::Fetch(uris) => {
                let results = fetch_all(&uris).await;
                if let Some(e) = b.absorb(&mut state, results, uris.len()) {
                    panic!("absorb failed: {e}");
                }
            }
        }
    };

    assert_eq!(built.len(), 2);

    // And the validation that follows is pure, so it needs no runtime either.
    let validated = pkix_path::validate_path(&built, &anchors, &policy, &DefaultVerifier)
        .expect("the reassembled chain should validate");

    // Revocation likewise: the caller is told what to check and can issue the
    // checks concurrently, which the synchronous per-certificate seam cannot.
    let targets = pkix_chain::sans_io::revocation_targets(&built, &anchors, &validated);
    assert_eq!(targets.len(), built.len(), "one target per certificate");
    // Which issuer, not merely that there is one: the variant alone would
    // still be `Issuer` if a certificate were paired with itself, and a
    // caller handed that pair asks a CA whether it has revoked itself.
    match targets[0] {
        RevocationTarget::Issuer { cert, issuer } => {
            assert_eq!(cert, &built[0], "the leaf is the certificate in question");
            assert_eq!(
                issuer, &built[1],
                "and its issuer is the next certificate up the chain"
            );
        }
        other => panic!("the leaf must be checked against its issuer, got {other:?}"),
    }
    match targets[1] {
        RevocationTarget::Anchor { cert, anchor } => {
            assert_eq!(
                cert, &built[1],
                "the top certificate is the one in question"
            );
            assert_eq!(
                anchor.subject, anchors[validated.anchor_index].subject,
                "against the anchor the path validated against"
            );
        }
        other => panic!("the top certificate must be checked against the anchor, got {other:?}"),
    }
}

/// The bounds are enforced on this path, not merely on the convenience
/// wrapper. A fetch cap of zero must stop reassembly rather than being
/// ignored because the caller is driving.
#[test]
fn the_fetch_cap_is_enforced_on_the_sans_io_path() {
    let anchors = [TrustAnchor::from_cert(load(TRUST_ANCHOR_DER))];
    let policy = policy();
    let mut config = AiaConfig::default();
    config.max_total_fetches = 0;
    let b = builder(&anchors, &policy, &config);

    let chain = [load(VALID_EE_DER)];
    let result = b.build_with(&chain, |_| {
        panic!("no fetch should be attempted when the cap is zero")
    });

    assert!(
        matches!(result, Err(Error::AiaFetchLimitExceeded { limit: 0 })),
        "expected the fetch cap to stop reassembly, got {result:?}"
    );
}

/// A depth cap of zero stops before any fetch too, reporting depth rather
/// than a fetch-limit failure.
#[test]
fn the_depth_cap_is_enforced_on_the_sans_io_path() {
    let anchors = [TrustAnchor::from_cert(load(TRUST_ANCHOR_DER))];
    let policy = policy();
    let mut config = AiaConfig::default();
    config.max_depth = 0;
    let b = builder(&anchors, &policy, &config);

    let chain = [load(VALID_EE_DER)];
    let result = b.build_with(&chain, |_| {
        panic!("no fetch should be attempted at depth zero")
    });

    assert!(
        matches!(result, Err(Error::AiaDepthExceeded)),
        "expected depth exceeded, got {result:?}"
    );
}

/// A leaf with no AIA extension has nothing to follow, so reassembly reports
/// that no path could be built rather than asking for a fetch.
#[test]
fn a_leaf_without_aia_asks_for_nothing() {
    let anchors = [TrustAnchor::from_cert(load(TRUST_ANCHOR_DER))];
    let policy = policy();
    let config = AiaConfig::default();
    let b = builder(&anchors, &policy, &config);

    let chain = [load(LEAF_NO_AIA_DER)];
    let result = b.build_with(&chain, |_| {
        panic!("a leaf with no caIssuers URI gives nothing to fetch")
    });
    assert!(
        matches!(result, Err(Error::PathBuild(_))),
        "expected a path-build failure, got {result:?}"
    );
}

/// A URI is fetched at most once across the whole reassembly, not once per
/// round. A caller driving the loop inherits that deduplication rather than
/// having to implement it.
#[test]
fn uris_are_not_refetched_across_rounds() {
    let anchors = [TrustAnchor::from_cert(load(TRUST_ANCHOR_DER))];
    let policy = policy();
    let config = AiaConfig::default();
    let b = builder(&anchors, &policy, &config);

    let chain = [load(VALID_EE_DER)];
    let mut seen: Vec<String> = Vec::new();

    // Answer with nothing useful, so reassembly keeps trying until it gives
    // up; every URI it asks for is recorded.
    let _ = b.build_with(&chain, |uris| {
        for uri in uris {
            assert!(
                !seen.contains(&(*uri).to_owned()),
                "{uri} was requested twice"
            );
            seen.push((*uri).to_owned());
        }
        uris.iter().map(|_| Ok(Vec::new())).collect()
    });
}

/// An empty chain is rejected rather than panicking on the missing leaf.
#[test]
fn an_empty_chain_is_rejected() {
    let anchors = [TrustAnchor::from_cert(load(TRUST_ANCHOR_DER))];
    let policy = policy();
    let config = AiaConfig::default();
    let b = builder(&anchors, &policy, &config);

    let result = b.build_with(&[], |_| Vec::new());
    assert!(
        matches!(result, Err(Error::PathBuild(_))),
        "an empty chain should be a path-build failure, got {result:?}"
    );
}

// ---------------------------------------------------------------------------
// AiaFetcher::batch_fetch contract violations
// ---------------------------------------------------------------------------

/// A fetcher returning fewer results than it was given URIs is a bug in the
/// consumer's own code, and `absorb` surfaces it during development.
///
/// `batch_fetch` promises one index-aligned result per URI, but it is an
/// overridable trait method, so nothing enforces that promise. Before, the
/// results were zipped against the URI list, which silently truncated to the
/// shorter of the two: the unanswered URIs were already in the tried set, so
/// they were never requested again and their absence never reported. The
/// chain could fail to build where a correct fetcher would have completed it,
/// with nothing to point at the cause.
///
/// The release-mode behaviour is deliberately still graceful — missing
/// entries count as URIs that produced nothing — so this asserts the
/// development-mode signal, which is the part that was missing. `cargo test`
/// builds with debug assertions on, so the mismatch panics here.
#[test]
#[should_panic(expected = "must return exactly one result per URI")]
fn absorb_flags_a_fetcher_that_returns_too_few_results() {
    let anchors = [TrustAnchor::from_cert(load(TRUST_ANCHOR_DER))];
    let policy = policy();
    let config = AiaConfig::default();
    let b = builder(&anchors, &policy, &config);

    let chain = [load(VALID_EE_DER)];
    let leaf = &chain[0];
    let mut state = ChainBuildState::new(&chain, &config);

    match b.next_step(&mut state, leaf) {
        BuildStep::Fetch(uris) => {
            assert!(
                !uris.is_empty(),
                "the leaf should have asked for its issuer"
            );
            // Honour none of them while claiming to have been asked for all.
            let _ = b.absorb(&mut state, Vec::new(), uris.len());
        }
        other => panic!("expected a Fetch step, got {other:?}"),
    }
}

/// Too many results is flagged as well, because the promise is *index*
/// alignment: a fetcher that has lost track of the count has lost track of
/// which answer belongs to which URI, and the entries that do get absorbed
/// may be answers to URIs other than the ones they are taken for.
///
/// Release builds still ignore the extras rather than absorbing them, so an
/// implementation cannot inflate the work done; that half is not directly
/// covered here because `cargo test` builds with debug assertions on.
#[test]
#[should_panic(expected = "must return exactly one result per URI")]
fn absorb_flags_a_fetcher_that_returns_too_many_results() {
    let anchors = [TrustAnchor::from_cert(load(TRUST_ANCHOR_DER))];
    let policy = policy();
    let config = AiaConfig::default();
    let b = builder(&anchors, &policy, &config);

    let chain = [load(VALID_EE_DER)];
    let leaf = &chain[0];
    let mut state = ChainBuildState::new(&chain, &config);

    match b.next_step(&mut state, leaf) {
        BuildStep::Fetch(uris) => {
            let requested = uris.len();
            let mut results: Vec<Result<Vec<u8>, AiaError>> =
                uris.iter().map(|_| Ok(GOOD_CA_DER.to_vec())).collect();
            for _ in 0..32 {
                results.push(Ok(GOOD_CA_DER.to_vec()));
            }
            let _ = b.absorb(&mut state, results, requested);
        }
        other => panic!("expected a Fetch step, got {other:?}"),
    }
}
