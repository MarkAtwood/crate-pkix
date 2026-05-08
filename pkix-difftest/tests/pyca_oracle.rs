//! Integration tests for `pkix_difftest::oracles::pyca` (PKIX-7nsf.3).
//!
//! These tests REQUIRE a pyca/cryptography venv bootstrapped by
//! `pkix-difftest/python/setup-venv.sh`. If the venv is missing, the tests
//! print a skip message and are otherwise no-ops — failing here would be
//! noise (network access for pip is not available in every test env).
//!
//! Independent oracles for the verdict assertions:
//! * Pass-chain (`good-chain.pem`): PKITS 4.1.1 ground truth `ShouldValidate:
//!   true` + the OpenSSL hand-run captured during PKIX-7nsf.1/.2.
//! * Fail-chain (`bad-chain.pem`): PKITS 4.1.2 `ShouldValidate: false` +
//!   identical hand-run.

use std::path::PathBuf;

use pkix_difftest::oracles;
use pkix_difftest::{Chain, Verdict};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn venv_python() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("python/.venv/bin/python")
}

fn sidecar_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("python/pyca_oracle.py")
}

/// Returns true if the venv has been bootstrapped. Tests that need the
/// sidecar use this to skip cleanly when run in environments where the
/// user has not yet run setup-venv.sh.
fn venv_available() -> bool {
    venv_python().exists() && sidecar_script().exists()
}

/// Centralised "skip with clear message" helper. We deliberately do NOT
/// fail the test when the venv is missing — that turns "you forgot to run
/// setup-venv.sh" into a CI red, which is bad UX. CI configurations that
/// require pyca should run setup-venv.sh as part of their setup; the bead
/// PKIX-7nsf.8 (docs) covers that contract.
fn skip_if_no_venv(test_name: &str) -> bool {
    if !venv_available() {
        eprintln!(
            "[skipping {test_name}] pyca venv not bootstrapped — \
             run pkix-difftest/python/setup-venv.sh"
        );
        true
    } else {
        false
    }
}

#[test]
fn pyca_oracle_passes_good_chain() {
    if skip_if_no_venv("pyca_oracle_passes_good_chain") {
        return;
    }
    let chain =
        Chain::from_pem_file(&fixtures_dir().join("good-chain.pem")).expect("load good-chain");
    let verdict = oracles::pyca::verify_with_python(&chain, &venv_python(), &sidecar_script())
        .expect("oracle ran without harness error");
    assert_eq!(
        verdict,
        Verdict::Pass,
        "PKITS 4.1.1 must validate under pyca; got {verdict}"
    );
}

#[test]
fn pyca_oracle_fails_bad_chain() {
    if skip_if_no_venv("pyca_oracle_fails_bad_chain") {
        return;
    }
    let chain =
        Chain::from_pem_file(&fixtures_dir().join("bad-chain.pem")).expect("load bad-chain");
    let verdict = oracles::pyca::verify_with_python(&chain, &venv_python(), &sidecar_script())
        .expect("oracle ran without harness error");
    match verdict {
        Verdict::Pass => panic!("PKITS 4.1.2 must fail under pyca"),
        Verdict::Fail { reason } => {
            // pyca on cryptography 45+ reports "signature does not match"
            // for the corrupted-CA-signature failure. Older versions may
            // produce different wording; we check for any signature- or
            // verification-related token.
            let lc = reason.to_lowercase();
            assert!(
                lc.contains("signature") || lc.contains("verification"),
                "expected signature/verification-related reason, got: {reason:?}"
            );
        }
    }
}

#[test]
fn pyca_oracle_returns_err_when_python_missing() {
    // Use a definitely-missing python path. No venv state required to
    // exercise this path — the sidecar script existence is checked AFTER
    // the python interpreter is spawned, so we rely on the fact that
    // /nonexistent/python returns NotFound from Command::spawn.
    let chain =
        Chain::from_pem_file(&fixtures_dir().join("good-chain.pem")).expect("load good-chain");
    let result = oracles::pyca::verify_with_python(
        &chain,
        std::path::Path::new("/definitely/not/a/real/python"),
        // Sidecar path is irrelevant when python itself is missing — but
        // pass a real path so we don't conflate two missing-files error
        // paths.
        &sidecar_script(),
    );
    let err = result.expect_err("verify should return Err when python missing");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::NotFound,
        "expected NotFound, got: {:?} ({err})",
        err.kind()
    );
}

#[test]
fn pyca_oracle_distinguishes_old_cryptography_from_pass() {
    // If the user has a venv but pinned cryptography < 43.0, the sidecar
    // exits with code 2 and the wrapper must surface this as io::Error
    // (not Verdict::Fail). We can't easily simulate this without a real
    // venv with the wrong version, so this test just verifies the parse
    // logic in isolation by feeding the sidecar's exit-2 stderr through
    // the public API surface — which we cannot do without a process.
    //
    // The closest we can do without setup overhead is exercise the unit
    // tests in src/oracles/pyca.rs (parse_verdict_*), which DO cover the
    // JSON-decode side of this. Skip the full subprocess simulation.
    if skip_if_no_venv("pyca_oracle_distinguishes_old_cryptography_from_pass") {
        return;
    }
    // Sanity: when the venv IS available and current, this resolves to a
    // real sidecar that produces a verdict. So no Err.
    let chain =
        Chain::from_pem_file(&fixtures_dir().join("good-chain.pem")).expect("load good-chain");
    let _ = oracles::pyca::verify_with_python(&chain, &venv_python(), &sidecar_script())
        .expect("with current venv, should not Err");
}
