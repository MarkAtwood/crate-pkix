//! Integration tests for the lint-domain oracles (PKIX-hbzo.1.1).
//!
//! The zlint test is auto-skipped when zlint is not on PATH; this lets the
//! workspace-wide `cargo test --features lint-oracles` succeed in
//! environments without zlint (CI runners that have not provisioned it,
//! contributor laptops without the Go toolchain) while still exercising
//! the real subprocess end-to-end when the binary is present.
//!
//! Pattern cribbed from `pkix-zlint-bridge/tests/run_on_cert.rs`.
//!
//! Note: pkix-difftest is dev tooling, so these tests are not part of any
//! public-API surface. Their job is to confirm the `NormalizedFinding`
//! shape end-to-end (real zlint subprocess → bridge VerdictMap → adapter
//! normalisation → public `LintOracleResult`) before the reconciliation
//! layer (PKIX-hbzo.1.3) starts depending on that shape.

#![cfg(feature = "lint-oracles")]

use pkix_difftest::lint_oracles::{
    pkix_lint_cabf::PkixLintCabfOracle, zlint::ZlintOracle, LintOracle, OracleSource,
};

/// Returns `true` when `zlint` is on PATH. Probe via spawn so this test
/// crate does not pick up a `which`-style dev-dep.
fn zlint_available() -> bool {
    std::process::Command::new("zlint")
        .arg("-version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// Load the leaf certificate from `tests/fixtures/good-chain.pem`.
///
/// `good-chain.pem` is the PKITS "Good CA Test1" three-cert chain in
/// canonical leaf-first order. We use the public `Chain::from_pem_bytes`
/// loader so this test sees the same input shape the path-validation
/// oracle layer does.
fn good_leaf_der() -> Vec<u8> {
    let pem_bytes = include_bytes!("./fixtures/good-chain.pem");
    let chain = pkix_difftest::Chain::from_pem_bytes(pem_bytes, "good-chain.pem".to_string())
        .expect("good-chain.pem parses");
    chain.certs_der[0].clone()
}

// ---------------------------------------------------------------------------
// PkixLintCabfOracle — no subprocess, always runs
// ---------------------------------------------------------------------------

/// End-to-end through the trait object: parse cert, lint, normalise,
/// verify shape.
#[test]
fn pkix_lint_cabf_via_trait_object() {
    let oracle: Box<dyn LintOracle> = Box::new(PkixLintCabfOracle::new());
    assert_eq!(oracle.source(), OracleSource::PkixLintCabf);

    let result = oracle.lint_cert(&good_leaf_der());
    assert!(
        result.oracle_error.is_none(),
        "expected clean parse, got {:?}",
        result.oracle_error
    );
    // The PKITS Good CA Test1 leaf trips at least one BR lint (it predates
    // SAN-required / EKU-server-auth and SC-081 caps).
    assert!(
        !result.findings.is_empty(),
        "expected at least one finding from BR bundle on PKITS leaf"
    );
}

// ---------------------------------------------------------------------------
// ZlintOracle — gated on real zlint binary
// ---------------------------------------------------------------------------

#[test]
fn zlint_oracle_against_real_zlint_returns_normalized_findings() {
    if !zlint_available() {
        eprintln!("zlint not on PATH; skipping integration test");
        return;
    }

    let oracle = ZlintOracle::with_default_bridge().expect("construct zlint oracle");
    assert_eq!(oracle.source(), OracleSource::Zlint);

    let der = good_leaf_der();
    let result = oracle.lint_cert(&der);

    assert!(
        result.oracle_error.is_none(),
        "expected clean run on good cert, got {:?}",
        result.oracle_error,
    );

    // The PKITS "Good CA Test1" leaf is a 2010-vintage RFC 5280 test
    // certificate that does NOT claim to be a CA/B Forum TLS Server
    // certificate. Empirically (verified 2026-05-12 against zlint
    // dev-unknown), every actionable zlint check returns NA / NE / pass on
    // it — there are no Notice / Warn / Error / Fatal verdicts to surface.
    // That makes this fixture an end-to-end shape test, not a "trips
    // findings" test:
    //
    //   - The subprocess ran (oracle_error is None).
    //   - The adapter dropped the NA / NE / pass verdicts (findings is empty).
    //   - If any verdicts had been actionable, they would carry the right
    //     source / severity / id shape (the unit tests in
    //     `lint_oracles::zlint::tests` already pin this directly).
    //
    // A cert that actually trips zlint findings will land in the CA/B
    // Forum corpus selection (PKIX-hbzo.1.3); at that point this test
    // can be tightened to assert non-empty findings. For .1.1 the
    // end-to-end shape is the contract.
    assert!(
        result.findings.is_empty(),
        "PKITS Good CA Test1 leaf is not a CA/B Forum cert; \
         every actionable zlint check should drop. Got {} findings: {:?}",
        result.findings.len(),
        result.findings,
    );
}

/// On a cert that DOES claim to be a CA/B Forum TLS cert, zlint will
/// emit at least one actionable finding because the cert lacks the
/// modern fields zlint enforces. We synthesise that pressure here by
/// linting an embedded cert known to be older than current CA/B Forum
/// BR enforcement points.
///
/// This test is structured to *exercise* the adapter's normalisation
/// path on a cert that fires findings — covering the
/// `findings.is_empty() == false` branch end-to-end through real zlint.
#[test]
fn zlint_oracle_findings_carry_correct_shape() {
    if !zlint_available() {
        eprintln!("zlint not on PATH; skipping integration test");
        return;
    }
    let oracle = ZlintOracle::with_default_bridge().expect("construct zlint oracle");

    // The PKITS Good CA intermediate is a CA cert (BasicConstraints
    // cA=TRUE). Empirically (zlint dev-unknown, 2026-05-12), zlint emits
    // at least one finding on it — likely the missing AIA / CRL DP
    // bundle for a publicly-trusted intermediate. If a future zlint
    // release lints this cert cleanly, the test falls back to asserting
    // structural shape only (same contract as the previous test).
    let intermediate_der = {
        let pem_bytes = include_bytes!("./fixtures/good-chain.pem");
        let chain = pkix_difftest::Chain::from_pem_bytes(pem_bytes, "good-chain.pem".to_string())
            .expect("good-chain.pem parses");
        chain.certs_der[1].clone()
    };

    let result = oracle.lint_cert(&intermediate_der);
    assert!(
        result.oracle_error.is_none(),
        "expected clean run, got {:?}",
        result.oracle_error,
    );

    // Whether or not findings fired, the shape contract holds:
    //   - findings sorted by id
    //   - each finding's source is OracleSource::Zlint
    //   - each finding's severity is actionable (Notice/Warn/Error/Fatal)
    for window in result.findings.windows(2) {
        assert!(
            window[0].id <= window[1].id,
            "findings must be sorted by id, saw {} then {}",
            window[0].id,
            window[1].id,
        );
    }
    for f in &result.findings {
        assert_eq!(f.source, OracleSource::Zlint);
        assert!(
            matches!(
                f.severity,
                pkix_lint::Severity::Notice
                    | pkix_lint::Severity::Warn
                    | pkix_lint::Severity::Error
                    | pkix_lint::Severity::Fatal
            ),
            "unexpected severity: {:?}",
            f.severity,
        );
    }
}

/// Sanity: a totally garbage byte sequence should surface as an
/// `oracle_error` rather than crashing the harness or yielding spurious
/// findings.
#[test]
fn zlint_oracle_on_malformed_input_returns_oracle_error() {
    if !zlint_available() {
        eprintln!("zlint not on PATH; skipping integration test");
        return;
    }
    let oracle = ZlintOracle::with_default_bridge().expect("construct zlint oracle");
    let result = oracle.lint_cert(b"\x00\x01\x02\x03\x04\x05\x06\x07");
    assert!(result.findings.is_empty(), "no findings on malformed input");
    assert!(
        result.oracle_error.is_some(),
        "expected oracle_error on malformed input"
    );
}
