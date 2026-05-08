//! Integration tests for `pkix_difftest::oracles::openssl` (PKIX-7nsf.2).
//!
//! These tests require the `openssl` binary on `$PATH`. AGENTS.md names
//! OpenSSL as a required test oracle for this project, so this is consistent
//! with project posture.
//!
//! Independent oracles for the verdict assertions:
//! * Pass-chain (`good-chain.pem`): PKITS 4.1.1 ground truth `ShouldValidate:
//!   true` + the hand-run of `openssl verify` performed during PKIX-7nsf.1
//!   (recorded in `tests/smoke.rs`). The Rust wrapper is asserted to match
//!   that hand-run, which in turn matched PKITS ground truth.
//! * Fail-chain (`bad-chain.pem`): PKITS 4.1.2 `ShouldValidate: false` +
//!   identical hand-run.
//! * Reason string `certificate signature failure`: the canonical OpenSSL 3.0
//!   error string for an invalid CA signature, as observed during PKIX-7nsf.2
//!   probes.

use std::path::PathBuf;

use pkix_difftest::{oracles, Chain, Verdict};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Helper: turn a "binary not found" error into a clear test-fail message.
/// We do not silently skip — if `openssl` is missing, the test runner needs
/// to know that loudly so it can install it (or pin via the env var).
fn expect_openssl_available(result: std::io::Result<Verdict>) -> Verdict {
    match result {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            panic!(
                "openssl binary not on $PATH; install OpenSSL ≥ 1.1 or set \
                 PKIX_DIFFTEST_OPENSSL_BIN to point at one. Original: {e}"
            );
        }
        Err(e) => panic!("openssl oracle harness error: {e}"),
    }
}

#[test]
fn openssl_oracle_passes_good_chain() {
    let chain =
        Chain::from_pem_file(&fixtures_dir().join("good-chain.pem")).expect("load good-chain");
    let verdict = expect_openssl_available(oracles::openssl::verify(&chain));
    assert_eq!(
        verdict,
        Verdict::Pass,
        "PKITS 4.1.1 must validate under openssl verify; got {verdict}"
    );
}

#[test]
fn openssl_oracle_fails_bad_chain_with_signature_failure_reason() {
    let chain =
        Chain::from_pem_file(&fixtures_dir().join("bad-chain.pem")).expect("load bad-chain");
    let verdict = expect_openssl_available(oracles::openssl::verify(&chain));
    match verdict {
        Verdict::Pass => panic!("PKITS 4.1.2 must fail under openssl verify"),
        Verdict::Fail { reason } => {
            // OpenSSL 3.0 canonical reason for a corrupted CA signature is
            // "certificate signature failure". Older OpenSSL or a different
            // BadSignedCA construction could produce a slightly different
            // string; we accept any reason that mentions "signature".
            assert!(
                reason.to_lowercase().contains("signature"),
                "expected signature-related reason, got: {reason:?}"
            );
        }
    }
}

#[test]
fn openssl_oracle_returns_err_when_binary_missing() {
    // Use `verify_with_bin` directly to avoid touching the process-global
    // `$PKIX_DIFFTEST_OPENSSL_BIN` env var — that would race with the other
    // openssl tests under cargo test's default thread pool.
    let chain =
        Chain::from_pem_file(&fixtures_dir().join("good-chain.pem")).expect("load good-chain");
    let result = oracles::openssl::verify_with_bin(&chain, "/definitely/not/a/real/openssl/binary");

    let err = result.expect_err("verify should return Err when binary missing");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::NotFound,
        "expected NotFound, got: {:?} ({err})",
        err.kind()
    );
}
