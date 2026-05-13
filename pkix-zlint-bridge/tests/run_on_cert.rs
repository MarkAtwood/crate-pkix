//! Integration tests for `ZlintBridge::run_on_cert` against the
//! real zlint binary on `PATH`. Skipped automatically when zlint is
//! not installed.

use pkix_zlint_bridge::{BridgeConfig, Error, PerCertError, Verdict, ZlintBridge};

const TRUST_ANCHOR_DER: &[u8] =
    include_bytes!("../../pkix-path/tests/pkits/certs/TrustAnchorRootCertificate.crt");
const GOOD_CA_DER: &[u8] = include_bytes!("../../pkix-path/tests/pkits/certs/GoodCACert.crt");

fn zlint_available() -> bool {
    std::process::Command::new("zlint")
        .arg("-version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// `run_on_cert` on a real cert produces a non-empty verdict map
/// covering at least one of each verdict level we expect on a
/// well-formed RFC 5280 trust anchor (NA / pass at minimum;
/// notice / warn / error vary by check applicability).
#[test]
fn run_on_cert_against_real_zlint_returns_verdict_map() {
    if !zlint_available() {
        eprintln!("zlint not on PATH; skipping integration test");
        return;
    }
    let bridge = ZlintBridge::new(BridgeConfig::default()).expect("construct");

    let verdicts = bridge.run_on_cert(TRUST_ANCHOR_DER).expect("run_on_cert");
    assert!(
        verdicts.len() > 100,
        "verdict map size {} seems implausibly small",
        verdicts.len()
    );

    // We expect both NotApplicable and Pass to be present on any
    // well-formed cert (most CABF checks NA on RFC-only roots; the
    // RFC-shape checks pass on a valid trust anchor).
    let mut have_na = false;
    let mut have_pass = false;
    for v in verdicts.values() {
        match v {
            Verdict::NotApplicable => have_na = true,
            Verdict::Pass => have_pass = true,
            _ => {}
        }
    }
    assert!(have_na, "expected at least one NotApplicable verdict");
    assert!(have_pass, "expected at least one Pass verdict");
}

/// Cache hit: second call with same bytes returns the same map
/// without invoking the subprocess. We verify this by deleting
/// the zlint binary from `PATH` for the second call — but since we
/// can't actually delete a system binary, we instead test the
/// invariant directly: the second call returns a map that is
/// equal to the first call's map, and is structurally a clone.
///
/// To prove the cache is doing work, we also wall-clock the second
/// call and assert it is much faster than the first (subprocess
/// fork+exec is ~10ms minimum; an in-memory clone is microseconds).
#[test]
fn run_on_cert_cache_hit_returns_identical_map() {
    if !zlint_available() {
        eprintln!("zlint not on PATH; skipping integration test");
        return;
    }
    let bridge = ZlintBridge::new(BridgeConfig::default()).expect("construct");

    let first = bridge.run_on_cert(TRUST_ANCHOR_DER).expect("first call");

    let start = std::time::Instant::now();
    let second = bridge.run_on_cert(TRUST_ANCHOR_DER).expect("second call");
    let elapsed = start.elapsed();

    assert_eq!(first, second, "cached map must equal fresh map");

    // Sanity: cache hit completes in well under the bare minimum
    // for a subprocess fork+exec on Linux (10ms). 5ms is a
    // generous ceiling that still catches a regression where the
    // cache silently regresses to re-spawning.
    assert!(
        elapsed < std::time::Duration::from_millis(5),
        "second call took {elapsed:?}; expected sub-millisecond cache hit"
    );
}

/// Different certificates produce different verdict maps. Mutates
/// the trust anchor by using a different real PKITS cert.
#[test]
fn run_on_cert_distinct_certs_have_distinct_verdicts() {
    if !zlint_available() {
        eprintln!("zlint not on PATH; skipping integration test");
        return;
    }
    let bridge = ZlintBridge::new(BridgeConfig::default()).expect("construct");
    let anchor = bridge.run_on_cert(TRUST_ANCHOR_DER).expect("anchor");
    let ca = bridge.run_on_cert(GOOD_CA_DER).expect("ca");

    // The two certs share check coverage (same set of check_ids)
    // but should differ on at least one verdict — they have
    // different subjects, different basicConstraints, different
    // signatures, etc.
    let differing = anchor
        .iter()
        .filter(|(k, v)| ca.get(*k) != Some(*v))
        .count();
    assert!(
        differing > 0,
        "trust anchor and GoodCA should disagree on at least one check"
    );
}

/// Malformed DER input surfaces as `Error::Cert(MalformedDer)`.
#[test]
fn run_on_cert_malformed_input_returns_cert_error() {
    if !zlint_available() {
        eprintln!("zlint not on PATH; skipping integration test");
        return;
    }
    let bridge = ZlintBridge::new(BridgeConfig::default()).expect("construct");
    let err = bridge
        .run_on_cert(b"this is not a valid DER certificate")
        .expect_err("garbage input should fail");
    match err {
        Error::Cert(PerCertError::MalformedDer { .. }) => {}
        other => panic!("expected Error::Cert(MalformedDer), got {other:?}"),
    }
}

/// Empty input also classifies as malformed.
#[test]
fn run_on_cert_empty_input_returns_cert_error() {
    if !zlint_available() {
        eprintln!("zlint not on PATH; skipping integration test");
        return;
    }
    let bridge = ZlintBridge::new(BridgeConfig::default()).expect("construct");
    let err = bridge
        .run_on_cert(b"")
        .expect_err("empty input should fail");
    assert!(
        matches!(err, Error::Cert(_)),
        "expected Error::Cert, got {err:?}"
    );
}

/// Missing binary surfaces as `Error::Bridge(BinaryNotFound)` —
/// independent of zlint installation status.
#[test]
fn run_on_cert_missing_binary_returns_bridge_error() {
    use pkix_zlint_bridge::BridgeError;

    let mut config = BridgeConfig::default();
    config.zlint_path =
        std::path::PathBuf::from("/this/path/intentionally/does/not/exist/pkix-zlint-bridge-test");
    let bridge = ZlintBridge::new(config).expect("construct");
    let err = bridge
        .run_on_cert(TRUST_ANCHOR_DER)
        .expect_err("missing binary");
    match err {
        Error::Bridge(BridgeError::BinaryNotFound { .. }) => {}
        other => panic!("expected Error::Bridge(BinaryNotFound), got {other:?}"),
    }
}
