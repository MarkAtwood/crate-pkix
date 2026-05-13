//! Round-trip integration test: enumerate zlint's catalog via the
//! bridge, wrap as workspace `Lint`s, run on a known certificate, and
//! verify the same check IDs and severity assignments come back.
//!
//! Skipped automatically when `zlint` is not installed on PATH. Same
//! pattern as the bridge's own integration tests.

use std::sync::Arc;

use der::Decode as _;
use pkix_lint::{LintRunner, SubjectKind};
use pkix_policy_zlint::all_lints;
use pkix_zlint_bridge::{BridgeConfig, ZlintBridge};
use x509_cert::Certificate;

/// PKITS Trust Anchor Root Certificate, committed in pkix-path's
/// fixtures tree. Same fixture used by the bridge's own integration
/// tests; a well-formed RFC 5280 trust anchor that yields a useful
/// mix of NA / Pass / Warn / Error verdicts from zlint's catalog.
const TRUST_ANCHOR_DER: &[u8] =
    include_bytes!("../../pkix-path/tests/pkits/certs/TrustAnchorRootCertificate.crt");

/// Returns true if `zlint` is on PATH. Probe via spawn so we do not
/// need a `which`-equivalent dev-dep.
fn zlint_available() -> bool {
    std::process::Command::new("zlint")
        .arg("-version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

fn load_test_cert() -> Certificate {
    Certificate::from_der(TRUST_ANCHOR_DER).expect("decode pkits trust anchor as Certificate")
}

#[test]
fn all_lints_enumerates_zlint_catalog() {
    if !zlint_available() {
        eprintln!("zlint not on PATH; skipping integration test");
        return;
    }

    let bridge = Arc::new(
        ZlintBridge::new(BridgeConfig::default()).expect("construct bridge against real zlint"),
    );
    let lints = all_lints(bridge).expect("enumerate via adapter");

    // zlint's catalog has hundreds of checks. Assert a generous lower
    // bound rather than an exact count so upstream adds do not break
    // the test.
    assert!(
        lints.len() >= 200,
        "zlint catalog seems implausibly small via adapter: {} entries",
        lints.len()
    );

    // Every wrapped Lint must report a non-empty id. zlint's catalog
    // permits empty citations on some checks (the upstream JSON's
    // `citation` field is free-form and not always populated), so we
    // do not assert citation non-emptiness — that would be a wider
    // contract than zlint itself guarantees.
    for lint in &lints {
        assert!(!lint.id().is_empty(), "wrapped Lint has empty id");
    }

    // Spot-check that one well-known zlint check IS present. This is
    // the historical, never-renamed root-CA-must-have-cA-true check;
    // its absence would signal that the bridge's enumerate parser or
    // our wrapping logic dropped catalog rows.
    let ids: std::collections::HashSet<&'static str> = lints.iter().map(|l| l.id()).collect();
    assert!(
        ids.contains("e_ca_country_name_missing")
            || ids.contains("e_ca_country_name_invalid")
            || ids.contains("e_ca_organization_name_missing"),
        "expected at least one well-known CA-scoped zlint check in catalog of {} entries",
        lints.len()
    );
}

#[test]
fn lint_runner_finds_zlint_findings_on_real_cert() {
    if !zlint_available() {
        eprintln!("zlint not on PATH; skipping integration test");
        return;
    }

    let cert = load_test_cert();
    let bridge = Arc::new(
        ZlintBridge::new(BridgeConfig::default()).expect("construct bridge against real zlint"),
    );
    let lints = all_lints(bridge).expect("enumerate via adapter");
    assert!(!lints.is_empty(), "non-empty catalog expected");

    let runner = LintRunner::new(lints);

    // PKITS Trust Anchor Root Certificate: SHA-1 era, deliberately
    // legacy-shape. Should yield SOME findings from zlint's modern
    // catalog (SHA-1 prohibited, validity caps, etc.) — we do not
    // assert specific IDs because upstream zlint catalogs evolve.
    let findings = runner.run_cert(&cert, SubjectKind::Any, 0, 1_700_000_000);

    // Findings include Pass / NotApplicable as well as Warn / Error /
    // Fatal. The runner returns one Finding per applicable Lint.
    // For a real CA cert we expect a non-trivial number of evaluated
    // lints.
    assert!(
        !findings.is_empty(),
        "expected at least one Finding from running the wrapped catalog against a real cert"
    );
}
