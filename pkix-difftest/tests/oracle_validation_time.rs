//! Integration tests for per-chain validation time threading (PKIX-g9vc.1).
//!
//! Verifies that when `Chain::validation_time_unix` is set, every oracle
//! pins its clock to that instant — so a chain with a fixed validity window
//! passes inside the window and fails outside it regardless of the wall
//! clock at test time.
//!
//! ## Fixture
//!
//! Re-uses `tests/fixtures/good-chain.pem` (PKITS 4.1.1 "Valid Signatures
//! Test1"). All three certs in that chain (EE / Good CA / Trust Anchor)
//! carry validity `notBefore = 2010-01-01T08:30:00Z`, `notAfter =
//! 2030-12-31T08:30:00Z` (verified out-of-band with `openssl x509 -dates`).
//!
//! ## Time anchors
//!
//! | Label    | UTC                | Unix       | Relation to window      |
//! |----------|--------------------|------------|-------------------------|
//! | INSIDE   | 2020-01-01T00:00Z  | 1577836800 | Inside [2010-01, 2030-12] |
//! | BEFORE   | 2000-01-01T00:00Z  |  946684800 | Before notBefore          |
//! | AFTER    | 2040-01-01T00:00Z  | 2208988800 | After notAfter            |
//!
//! ## Why this is a real test (no self-oracle)
//!
//! The "expected verdict" for each (oracle, time) pair is set by the cert's
//! own validity window, not by re-asking the oracle under test. Every
//! oracle independently consumes the standard X.509 §4.1.2.5 validity
//! semantics; agreement is the assertion. AGENTS.md §"Test integrity"
//! forbids tests that use the code under test as their own oracle.

use std::path::PathBuf;

use pkix_difftest::{oracles, Chain, Verdict};

const INSIDE_WINDOW_UNIX: u64 = 1_577_836_800; // 2020-01-01T00:00:00Z
const BEFORE_WINDOW_UNIX: u64 = 946_684_800; // 2000-01-01T00:00:00Z
const AFTER_WINDOW_UNIX: u64 = 2_208_988_800; // 2040-01-01T00:00:00Z

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn good_chain_at(time_unix: u64) -> Chain {
    Chain::from_pem_file(&fixtures_dir().join("good-chain.pem"))
        .expect("load good-chain")
        .with_validation_time(time_unix)
}

// ---------------------------------------------------------------------------
// pkix-path oracle
// ---------------------------------------------------------------------------

#[test]
fn pkix_path_oracle_passes_inside_window() {
    let chain = good_chain_at(INSIDE_WINDOW_UNIX);
    let verdict = oracles::pkix_path::verify(&chain).expect("oracle ran");
    assert_eq!(
        verdict,
        Verdict::Pass,
        "PKITS 4.1.1 must pass at INSIDE_WINDOW (2020-01-01); got {verdict}"
    );
}

#[test]
fn pkix_path_oracle_fails_before_window() {
    let chain = good_chain_at(BEFORE_WINDOW_UNIX);
    let verdict = oracles::pkix_path::verify(&chain).expect("oracle ran");
    match verdict {
        Verdict::Pass => panic!(
            "PKITS 4.1.1 must fail at BEFORE_WINDOW (2000-01-01) — \
             every cert's notBefore is 2010-01-01"
        ),
        Verdict::Fail { reason } => {
            // pkix-path collapses RFC 5280 §6.1.3(a)(2) into a single
            // "validity period check failed" diagnostic — symmetric for
            // notBefore and notAfter. Accept the umbrella token or any of
            // the older phrasings in case the Display impl evolves.
            let lc = reason.to_lowercase();
            assert!(
                lc.contains("validity") || lc.contains("not yet valid") || lc.contains("notbefore"),
                "expected validity-window-related reason, got: {reason:?}"
            );
        }
    }
}

#[test]
fn pkix_path_oracle_fails_after_window() {
    let chain = good_chain_at(AFTER_WINDOW_UNIX);
    let verdict = oracles::pkix_path::verify(&chain).expect("oracle ran");
    match verdict {
        Verdict::Pass => panic!(
            "PKITS 4.1.1 must fail at AFTER_WINDOW (2040-01-01) — \
             every cert's notAfter is 2030-12-31"
        ),
        Verdict::Fail { reason } => {
            // pkix-path collapses RFC 5280 §6.1.3(a)(2) into a single
            // "validity period check failed" diagnostic — symmetric for
            // notBefore and notAfter. Accept the umbrella token or any of
            // the older phrasings in case the Display impl evolves.
            let lc = reason.to_lowercase();
            assert!(
                lc.contains("validity") || lc.contains("expired") || lc.contains("notafter"),
                "expected validity-window-related reason, got: {reason:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// openssl oracle
// ---------------------------------------------------------------------------

/// Copy of `tests/openssl_oracle.rs`'s helper. We do not silently skip when
/// openssl is missing — installing it is a project pre-req for these tests.
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
fn openssl_oracle_passes_inside_window() {
    let chain = good_chain_at(INSIDE_WINDOW_UNIX);
    let verdict = expect_openssl_available(oracles::openssl::verify(&chain));
    assert_eq!(
        verdict,
        Verdict::Pass,
        "PKITS 4.1.1 must pass under openssl verify -attime 1577836800; got {verdict}"
    );
}

#[test]
fn openssl_oracle_fails_before_window() {
    let chain = good_chain_at(BEFORE_WINDOW_UNIX);
    let verdict = expect_openssl_available(oracles::openssl::verify(&chain));
    match verdict {
        Verdict::Pass => {
            panic!("PKITS 4.1.1 must fail under openssl verify -attime 946684800 (2000-01-01)")
        }
        Verdict::Fail { reason } => {
            // OpenSSL 3.0 prints "certificate is not yet valid" for
            // notBefore violations.
            let lc = reason.to_lowercase();
            assert!(
                lc.contains("not yet valid") || lc.contains("notbefore"),
                "expected notBefore-related reason, got: {reason:?}"
            );
        }
    }
}

#[test]
fn openssl_oracle_fails_after_window() {
    let chain = good_chain_at(AFTER_WINDOW_UNIX);
    let verdict = expect_openssl_available(oracles::openssl::verify(&chain));
    match verdict {
        Verdict::Pass => {
            panic!("PKITS 4.1.1 must fail under openssl verify -attime 2208988800 (2040-01-01)")
        }
        Verdict::Fail { reason } => {
            // OpenSSL 3.0 prints "certificate has expired" for notAfter
            // violations.
            let lc = reason.to_lowercase();
            assert!(
                lc.contains("expired") || lc.contains("notafter"),
                "expected notAfter-related reason, got: {reason:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// pyca oracle
// ---------------------------------------------------------------------------

fn venv_python() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("python/.venv/bin/python")
}

fn sidecar_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("python/pyca_oracle.py")
}

fn venv_available() -> bool {
    venv_python().exists() && sidecar_script().exists()
}

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
fn pyca_oracle_passes_inside_window() {
    if skip_if_no_venv("pyca_oracle_passes_inside_window") {
        return;
    }
    let chain = good_chain_at(INSIDE_WINDOW_UNIX);
    let verdict = oracles::pyca::verify_with_python(&chain, &venv_python(), &sidecar_script())
        .expect("oracle ran");
    assert_eq!(
        verdict,
        Verdict::Pass,
        "PKITS 4.1.1 must pass under pyca with builder.time(2020-01-01); got {verdict}"
    );
}

#[test]
fn pyca_oracle_fails_before_window() {
    if skip_if_no_venv("pyca_oracle_fails_before_window") {
        return;
    }
    let chain = good_chain_at(BEFORE_WINDOW_UNIX);
    let verdict = oracles::pyca::verify_with_python(&chain, &venv_python(), &sidecar_script())
        .expect("oracle ran");
    match verdict {
        Verdict::Pass => panic!(
            "PKITS 4.1.1 must fail under pyca with builder.time(2000-01-01) — \
             every cert's notBefore is 2010-01-01"
        ),
        Verdict::Fail { reason } => {
            // pyca raises VerificationError with messages like
            // "validation time ... is before certificate's notBefore" or
            // similar. Accept any token that points at the validity window.
            let lc = reason.to_lowercase();
            assert!(
                lc.contains("validity")
                    || lc.contains("not yet valid")
                    || lc.contains("notbefore")
                    || lc.contains("validation time"),
                "expected validity-window reason, got: {reason:?}"
            );
        }
    }
}

#[test]
fn pyca_oracle_fails_after_window() {
    if skip_if_no_venv("pyca_oracle_fails_after_window") {
        return;
    }
    let chain = good_chain_at(AFTER_WINDOW_UNIX);
    let verdict = oracles::pyca::verify_with_python(&chain, &venv_python(), &sidecar_script())
        .expect("oracle ran");
    match verdict {
        Verdict::Pass => panic!(
            "PKITS 4.1.1 must fail under pyca with builder.time(2040-01-01) — \
             every cert's notAfter is 2030-12-31"
        ),
        Verdict::Fail { reason } => {
            // pyca raises VerificationError with messages like
            // "validation time ... is after certificate's notAfter" or
            // "expired".
            let lc = reason.to_lowercase();
            assert!(
                lc.contains("validity")
                    || lc.contains("expired")
                    || lc.contains("notafter")
                    || lc.contains("validation time"),
                "expected validity-window reason, got: {reason:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Builder + fallback
// ---------------------------------------------------------------------------

#[test]
fn with_validation_time_sets_field() {
    let chain =
        Chain::from_pem_file(&fixtures_dir().join("good-chain.pem")).expect("load good-chain");
    assert_eq!(
        chain.validation_time_unix, None,
        "loader must default validation_time_unix to None"
    );

    let chain = chain.with_validation_time(INSIDE_WINDOW_UNIX);
    assert_eq!(chain.validation_time_unix, Some(INSIDE_WINDOW_UNIX));
}

#[test]
fn validation_time_none_uses_current_clock() {
    // Sanity check: a Chain with `validation_time_unix: None` (the default
    // from the PEM loader) still validates today through the pkix-path
    // oracle. This is the same assertion `smoke::good_chain_passes_pkix_path_oracle`
    // makes; we duplicate it here as a self-contained check that the new
    // field's None branch preserves the existing system-clock behaviour.
    let chain =
        Chain::from_pem_file(&fixtures_dir().join("good-chain.pem")).expect("load good-chain");
    assert_eq!(chain.validation_time_unix, None);
    let verdict = oracles::pkix_path::verify(&chain).expect("oracle ran");
    assert_eq!(
        verdict,
        Verdict::Pass,
        "validation_time_unix=None must fall back to system clock; got {verdict}"
    );
}
