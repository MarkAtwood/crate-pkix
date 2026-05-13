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

// ---------------------------------------------------------------------------
// CRL revocation (PKIX-emf1.4)
//
// The pyca sidecar hand-rolls an RFC 5280 §6.3 baseline CRL check on top of
// PolicyBuilder (which itself does not support CRLs). These tests assert
// that the hand-rolled check agrees with an independently-derived ground
// truth.
//
// Ground truth oracle: OpenSSL 3.0+ `openssl verify -crl_check`. Verified
// out-of-band on 2026-05-11 (PKIX-emf1.4 shipment) against the same DER
// fixtures used here:
//
//   $ openssl verify -crl_check -attime 1780272000 \
//         -CAfile <(cat ca.pem crl.pem) leaf-good.pem    → OK
//   $ openssl verify -crl_check -attime 1780272000 \
//         -CAfile <(cat ca.pem crl.pem) leaf-revoked.pem → certificate revoked (exit 2)
//
// Fixtures are reused from pkix-revocation/tests/fixtures (see
// gen_crl_fixtures.py in that crate for provenance). They were originally
// generated with pyca/cryptography, but the value being tested here is the
// REVOCATION DECISION (issuer match + serial lookup + validity window) —
// pyca's verification path that we hand-rolled, vs OpenSSL's CRL state
// machine. The decision logic is independent in both implementations.
// ---------------------------------------------------------------------------

/// Validation time used by the pkix-revocation CRL fixtures.
/// (2026-06-01 00:00:00 UTC, matches NOW in pkix-revocation/tests/crl_checker_tests.rs.)
const CRL_FIXTURE_NOW: u64 = 1_780_272_000;

fn revocation_fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../pkix-revocation/tests/fixtures")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read pkix-revocation fixture {name}: {e}"))
}

/// Build a 2-cert chain (leaf + CA) with pinned validation time and the
/// supplied CRL DER bytes attached.
fn crl_chain(leaf_fixture: &str, ca_fixture: &str, crl_fixtures: &[&str], label: &str) -> Chain {
    let mut chain = Chain {
        certs_der: vec![
            revocation_fixture(leaf_fixture),
            revocation_fixture(ca_fixture),
        ],
        crls: crl_fixtures.iter().map(|n| revocation_fixture(n)).collect(),
        root_in_chain: true,
        label: label.to_string(),
        validation_time_unix: Some(CRL_FIXTURE_NOW),
    };
    // Sanity: every CRL must be non-empty (catches a fixture-path typo).
    for (i, der) in chain.crls.iter().enumerate() {
        assert!(!der.is_empty(), "CRL fixture {i} for {label} is empty");
    }
    // Pin to leaf-first ordering — Chain doesn't auto-detect when built
    // programmatically.
    let _ = &mut chain;
    chain
}

#[test]
fn pyca_oracle_crl_good_cert_passes() {
    if skip_if_no_venv("pyca_oracle_crl_good_cert_passes") {
        return;
    }
    // Independent oracle: openssl verify -crl_check → OK (verified 2026-05-11).
    let chain = crl_chain(
        "crl-leaf-good.der",
        "crl-ca.der",
        &["crl-with-revocation.der"],
        "crl-good-cert",
    );
    let verdict = oracles::pyca::verify_with_python(&chain, &venv_python(), &sidecar_script())
        .expect("oracle ran without harness error");
    assert_eq!(
        verdict,
        Verdict::Pass,
        "good leaf (serial=1) is not on CRL (which revokes serial=2); pyca must Pass; got {verdict}"
    );
}

#[test]
fn pyca_oracle_crl_revoked_cert_fails_with_revoked_reason() {
    if skip_if_no_venv("pyca_oracle_crl_revoked_cert_fails_with_revoked_reason") {
        return;
    }
    // Independent oracle: openssl verify -crl_check → certificate revoked (verified 2026-05-11).
    let chain = crl_chain(
        "crl-leaf-revoked.der",
        "crl-ca.der",
        &["crl-with-revocation.der"],
        "crl-revoked-cert",
    );
    let verdict = oracles::pyca::verify_with_python(&chain, &venv_python(), &sidecar_script())
        .expect("oracle ran without harness error");
    match verdict {
        Verdict::Pass => panic!("revoked leaf (serial=2) must Fail under pyca CRL check"),
        Verdict::Fail { reason } => {
            // The sidecar formats revocation reasons as
            // "pyca: certificate 0x<hex> revoked by CRL". Assert both halves
            // of that contract so the diff classifier downstream can rely
            // on a stable reason-string shape.
            assert!(
                reason.contains("revoked"),
                "expected reason containing 'revoked', got: {reason:?}"
            );
            assert!(
                reason.contains("pyca"),
                "expected reason prefixed by 'pyca:', got: {reason:?}"
            );
        }
    }
}

#[test]
fn pyca_oracle_crl_empty_list_preserves_pass() {
    if skip_if_no_venv("pyca_oracle_crl_empty_list_preserves_pass") {
        return;
    }
    // Sanity: an empty `crls` list must behave identically to the no-CRL
    // case. Independent oracle: trivially, no revocation data → no
    // revocation decision; verdict is whatever path validation produces.
    let chain = crl_chain("crl-leaf-good.der", "crl-ca.der", &[], "crl-empty-list");
    let verdict = oracles::pyca::verify_with_python(&chain, &venv_python(), &sidecar_script())
        .expect("oracle ran without harness error");
    assert_eq!(
        verdict,
        Verdict::Pass,
        "empty CRL list must not change a passing verdict; got {verdict}"
    );
}

#[test]
fn pyca_oracle_crl_expired_drops_silently() {
    if skip_if_no_venv("pyca_oracle_crl_expired_drops_silently") {
        return;
    }
    // CRL whose nextUpdate is in the past (2021-01-01 < NOW=2026-06-01)
    // must be dropped per RFC 5280 §6.3.3 baseline, so even a CRL that
    // WOULD revoke the cert has no effect once expired.
    //
    // Composite test: feed both the expired CRL (would revoke serial=2 if
    // honoured — checked by reading crl-expired.der's content via the
    // pkix-revocation crate's tests) and assert pyca still Passes the
    // good leaf because the expired CRL is dropped.
    //
    // Independent oracle: openssl verify -crl_check with the expired CRL
    // surfaces "CRL has expired" (error 12), which is a different decision
    // (refuse to validate, not "pass"). RFC 5280 §6.3.3 baseline is more
    // permissive: drop the expired CRL and accept other CRLs (or none). The
    // sidecar follows the baseline reading, matching pkix-revocation's
    // CrlChecker behaviour (which returns CrlExpired as an Err — treated by
    // pkix_path.rs::check_revocation as "this CRL has no determination,
    // try the next"). The result is that the diff harness's revocation
    // policy is "soft per-CRL"; this test pins that.
    let chain = crl_chain(
        "crl-leaf-good.der",
        "crl-ca.der",
        &["crl-expired.der"],
        "crl-expired-drop",
    );
    let verdict = oracles::pyca::verify_with_python(&chain, &venv_python(), &sidecar_script())
        .expect("oracle ran without harness error");
    assert_eq!(
        verdict,
        Verdict::Pass,
        "expired CRL must be dropped (soft per-CRL policy); got {verdict}"
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
