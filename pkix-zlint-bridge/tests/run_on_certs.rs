//! Integration tests for `ZlintBridge::run_on_certs` against the
//! real zlint binary on `PATH`. Skipped automatically when zlint is
//! not installed.

use pkix_zlint_bridge::{BridgeConfig, BridgeError, PerCertError, ZlintBridge};

const TRUST_ANCHOR_DER: &[u8] =
    include_bytes!("../../pkix-path/tests/pkits/certs/TrustAnchorRootCertificate.crt");
const GOOD_CA_DER: &[u8] = include_bytes!("../../pkix-path/tests/pkits/certs/GoodCACert.crt");
const VALID_EE_DER: &[u8] =
    include_bytes!("../../pkix-path/tests/pkits/certs/ValidCertificatePathTest1EE.crt");

fn zlint_available() -> bool {
    std::process::Command::new("zlint")
        .arg("-version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// Empty input returns an empty vec without invoking the
/// subprocess. Independent of whether zlint is installed.
#[test]
fn run_on_certs_empty_input_returns_empty_vec() {
    let mut config = BridgeConfig::default();
    // Use a non-existent zlint path. If the empty-input fast path
    // is correctly skipping the subprocess, we still get Ok(vec![]).
    config.zlint_path =
        std::path::PathBuf::from("/this/path/intentionally/does/not/exist/pkix-zlint-bridge-test");
    let bridge = ZlintBridge::new(config).expect("construct");
    let results = bridge.run_on_certs(&[]).expect("empty batch ok");
    assert!(results.is_empty());
}

/// Three-cert all-valid batch returns three Ok results, one per
/// input, in order. Each result has > 100 entries (zlint's
/// catalog).
#[test]
fn run_on_certs_three_valid_certs_returns_three_oks() {
    if !zlint_available() {
        eprintln!("zlint not on PATH; skipping integration test");
        return;
    }
    let bridge = ZlintBridge::new(BridgeConfig::default()).expect("construct");
    let inputs: [&[u8]; 3] = [TRUST_ANCHOR_DER, GOOD_CA_DER, VALID_EE_DER];

    let results = bridge.run_on_certs(&inputs).expect("batch ok");
    assert_eq!(results.len(), 3);
    for (i, r) in results.iter().enumerate() {
        let map = r
            .as_ref()
            .unwrap_or_else(|e| panic!("entry {i} failed: {e:?}"));
        assert!(map.len() > 100, "entry {i} map too small: {}", map.len());
    }
}

/// Mixed batch: valid + malformed + valid. The malformed cert
/// surfaces as `Err(MalformedDer)` at its index; the surrounding
/// valid certs return `Ok(verdict_map)`.
#[test]
fn run_on_certs_malformed_in_middle_isolates_failure() {
    if !zlint_available() {
        eprintln!("zlint not on PATH; skipping integration test");
        return;
    }
    let bridge = ZlintBridge::new(BridgeConfig::default()).expect("construct");
    let garbage: &[u8] = b"not a valid DER certificate";
    let inputs: [&[u8]; 3] = [TRUST_ANCHOR_DER, garbage, GOOD_CA_DER];

    let results = bridge.run_on_certs(&inputs).expect("batch outer ok");
    assert_eq!(results.len(), 3);

    assert!(results[0].is_ok(), "index 0 should be Ok: {:?}", results[0]);
    match &results[1] {
        Err(PerCertError::MalformedDer { .. }) => {}
        other => panic!("index 1 should be MalformedDer, got {other:?}"),
    }
    assert!(results[2].is_ok(), "index 2 should be Ok: {:?}", results[2]);
}

/// Malformed-first: first input is malformed, rest are valid.
#[test]
fn run_on_certs_malformed_first_isolates_failure() {
    if !zlint_available() {
        eprintln!("zlint not on PATH; skipping integration test");
        return;
    }
    let bridge = ZlintBridge::new(BridgeConfig::default()).expect("construct");
    let garbage: &[u8] = b"garbage";
    let inputs: [&[u8]; 3] = [garbage, TRUST_ANCHOR_DER, GOOD_CA_DER];

    let results = bridge.run_on_certs(&inputs).expect("batch outer ok");
    assert_eq!(results.len(), 3);

    match &results[0] {
        Err(PerCertError::MalformedDer { .. }) => {}
        other => panic!("index 0 should be MalformedDer, got {other:?}"),
    }
    assert!(results[1].is_ok());
    assert!(results[2].is_ok());
}

/// Malformed-last: malformed at the tail. Earlier entries still
/// succeed.
#[test]
fn run_on_certs_malformed_last_isolates_failure() {
    if !zlint_available() {
        eprintln!("zlint not on PATH; skipping integration test");
        return;
    }
    let bridge = ZlintBridge::new(BridgeConfig::default()).expect("construct");
    let garbage: &[u8] = b"garbage";
    let inputs: [&[u8]; 3] = [TRUST_ANCHOR_DER, GOOD_CA_DER, garbage];

    let results = bridge.run_on_certs(&inputs).expect("batch outer ok");
    assert_eq!(results.len(), 3);

    assert!(results[0].is_ok());
    assert!(results[1].is_ok());
    match &results[2] {
        Err(PerCertError::MalformedDer { .. }) => {}
        other => panic!("index 2 should be MalformedDer, got {other:?}"),
    }
}

/// Two consecutive malformed certs surrounded by valid certs.
/// Exercises the recursive-batch path: first batch fails after the
/// valid prefix, marks index 1 as malformed; second batch starts at
/// index 2, fails immediately, marks index 2 as malformed; third
/// batch processes index 3 normally.
#[test]
fn run_on_certs_two_consecutive_malformed_marks_both() {
    if !zlint_available() {
        eprintln!("zlint not on PATH; skipping integration test");
        return;
    }
    let bridge = ZlintBridge::new(BridgeConfig::default()).expect("construct");
    let garbage1: &[u8] = b"garbage1";
    let garbage2: &[u8] = b"garbage2";
    let inputs: [&[u8]; 4] = [TRUST_ANCHOR_DER, garbage1, garbage2, GOOD_CA_DER];

    let results = bridge.run_on_certs(&inputs).expect("batch outer ok");
    assert_eq!(results.len(), 4);

    assert!(results[0].is_ok(), "index 0 should be Ok: {:?}", results[0]);
    assert!(matches!(
        &results[1],
        Err(PerCertError::MalformedDer { .. })
    ));
    assert!(matches!(
        &results[2],
        Err(PerCertError::MalformedDer { .. })
    ));
    assert!(results[3].is_ok(), "index 3 should be Ok: {:?}", results[3]);
}

/// All malformed: each input fails individually, no valid entries.
#[test]
fn run_on_certs_all_malformed_returns_all_errs() {
    if !zlint_available() {
        eprintln!("zlint not on PATH; skipping integration test");
        return;
    }
    let bridge = ZlintBridge::new(BridgeConfig::default()).expect("construct");
    let g1: &[u8] = b"a";
    let g2: &[u8] = b"b";
    let inputs: [&[u8]; 2] = [g1, g2];

    let results = bridge.run_on_certs(&inputs).expect("batch outer ok");
    assert_eq!(results.len(), 2);
    for (i, r) in results.iter().enumerate() {
        match r {
            Err(PerCertError::MalformedDer { .. }) => {}
            other => panic!("index {i} expected MalformedDer, got {other:?}"),
        }
    }
}

/// Cache integration: a cert that was already run via run_on_cert
/// hits the cache when included in a batch. A cert that was
/// already run via a batch hits the cache on subsequent calls.
#[test]
fn run_on_certs_cache_integration_hits_for_repeated_inputs() {
    if !zlint_available() {
        eprintln!("zlint not on PATH; skipping integration test");
        return;
    }
    let bridge = ZlintBridge::new(BridgeConfig::default()).expect("construct");

    // Warm the cache via run_on_cert.
    let solo = bridge.run_on_cert(TRUST_ANCHOR_DER).expect("warm");

    // Now run a batch that includes that same cert. The batch
    // result for the warmed entry should equal the solo result.
    let inputs: [&[u8]; 2] = [TRUST_ANCHOR_DER, GOOD_CA_DER];
    let results = bridge.run_on_certs(&inputs).expect("batch");
    assert_eq!(results[0].as_ref().unwrap(), &solo);

    // And a second batch over the same inputs should be a complete
    // cache hit — completes in sub-millisecond time.
    let start = std::time::Instant::now();
    let _ = bridge.run_on_certs(&inputs).expect("cached batch");
    let elapsed = start.elapsed();
    assert!(
        elapsed < std::time::Duration::from_millis(5),
        "cached batch took {elapsed:?}; expected sub-millisecond"
    );
}

/// Single-cert input through run_on_certs returns a one-element vec
/// matching run_on_cert's output.
#[test]
fn run_on_certs_single_input_matches_run_on_cert() {
    if !zlint_available() {
        eprintln!("zlint not on PATH; skipping integration test");
        return;
    }
    let bridge = ZlintBridge::new(BridgeConfig::default()).expect("construct");

    let solo = bridge.run_on_cert(GOOD_CA_DER).expect("solo");
    let batch = bridge.run_on_certs(&[GOOD_CA_DER]).expect("batch");

    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].as_ref().unwrap(), &solo);
}

/// Missing binary fails the whole batch as outer `BridgeError`,
/// not as per-cert errors.
#[test]
fn run_on_certs_missing_binary_returns_bridge_error() {
    let mut config = BridgeConfig::default();
    config.zlint_path =
        std::path::PathBuf::from("/this/path/intentionally/does/not/exist/pkix-zlint-bridge-test");
    let bridge = ZlintBridge::new(config).expect("construct");
    // Non-empty input so we actually hit the subprocess path.
    let inputs: [&[u8]; 1] = [TRUST_ANCHOR_DER];
    let err = bridge.run_on_certs(&inputs).expect_err("missing binary");
    assert!(matches!(err, BridgeError::BinaryNotFound { .. }));
}
