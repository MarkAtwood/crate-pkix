//! Integration tests for `ZlintBridge::enumerate_lints` against the
//! real zlint binary on `PATH`.
//!
//! Skipped automatically when `zlint` is not installed; this lets
//! the workspace-wide `cargo test` succeed in environments without
//! zlint (CI, contributor laptops without the Go toolchain) while
//! still exercising the real catalog parse when zlint is present.

use pkix_zlint_bridge::{BridgeConfig, ZlintBridge};

/// Returns true if `zlint` is on `PATH`. Probe via spawn, not via
/// `which` (avoids a dev-dep).
fn zlint_available() -> bool {
    std::process::Command::new("zlint")
        .arg("-version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// `enumerate_lints` produces a non-empty catalog with at least one
/// entry per documented severity prefix.
///
/// Oracle: zlint's own catalog has 419 lints distributed across
/// `e_` / `w_` / `n_` prefixes (counted directly with `zlint
/// -list-lints-json | jq -r .name | sed 's/_.*$//' | sort | uniq -c`
/// against zlint dev-unknown: 353 e / 55 w / 11 n on 2026-05-12).
/// We assert presence of each, not exact counts (upstream is free
/// to add new checks).
#[test]
fn enumerate_lints_against_real_zlint_returns_full_catalog() {
    if !zlint_available() {
        eprintln!("zlint not on PATH; skipping integration test");
        return;
    }
    use pkix_lint::Severity;

    let bridge = ZlintBridge::new(BridgeConfig::default()).expect("construct bridge");
    let lints = bridge
        .enumerate_lints()
        .expect("enumerate against real zlint");

    assert!(
        lints.len() >= 200,
        "zlint catalog seems implausibly small: {} entries",
        lints.len()
    );

    let mut have_error = false;
    let mut have_warn = false;
    let mut have_notice = false;
    for info in &lints {
        assert!(!info.check_id.is_empty(), "empty check_id");
        match info.severity {
            Severity::Error => have_error = true,
            Severity::Warn => have_warn = true,
            Severity::Notice => have_notice = true,
            other => panic!("unexpected severity {other:?} for {}", info.check_id),
        }
    }

    assert!(have_error, "expected at least one Error-severity lint");
    assert!(have_warn, "expected at least one Warn-severity lint");
    assert!(have_notice, "expected at least one Notice-severity lint");
}

/// A specific known-stable check is present in the catalog. Pins
/// the catalog parse against a hand-verified entry.
///
/// `e_basic_constraints_not_critical` enforces RFC 5280's
/// requirement that the BasicConstraints extension be marked
/// critical when present in a CA cert; it is one of zlint's oldest
/// checks and ships in every release. Source is `RFC5280` per
/// `zlint -list-lints-json | grep basic_constraints_not_critical`.
#[test]
fn enumerate_lints_finds_basic_constraints_lint() {
    if !zlint_available() {
        eprintln!("zlint not on PATH; skipping integration test");
        return;
    }
    let bridge = ZlintBridge::new(BridgeConfig::default()).expect("construct bridge");
    let lints = bridge.enumerate_lints().expect("enumerate");

    let bc = lints
        .iter()
        .find(|i| i.check_id == "e_basic_constraints_not_critical")
        .unwrap_or_else(|| {
            panic!(
                "expected e_basic_constraints_not_critical in catalog; check_ids sample: {:?}",
                lints
                    .iter()
                    .take(5)
                    .map(|i| &i.check_id)
                    .collect::<Vec<_>>()
            )
        });

    assert_eq!(bc.severity, pkix_lint::Severity::Error);
    assert!(
        !bc.description.is_empty(),
        "description should not be empty"
    );
    assert!(
        !bc.source.is_empty(),
        "source should not be empty for {:?}",
        bc.check_id
    );
    // Optional fields: at least description and source are non-empty
    // for this check; citation may or may not be set depending on
    // zlint version (parser tolerates either).
}

/// `BinaryNotFound` is surfaced when the configured path does not
/// exist. Independent of whether zlint is actually installed.
#[test]
fn enumerate_lints_missing_binary_returns_binary_not_found() {
    use pkix_zlint_bridge::BridgeError;

    let mut config = BridgeConfig::default();
    config.zlint_path =
        std::path::PathBuf::from("/this/path/intentionally/does/not/exist/pkix-zlint-bridge-test");
    let bridge = ZlintBridge::new(config).expect("construct");
    let err = bridge
        .enumerate_lints()
        .expect_err("should fail for missing binary");
    assert!(
        matches!(err, BridgeError::BinaryNotFound { .. }),
        "expected BinaryNotFound, got {err:?}"
    );
}
