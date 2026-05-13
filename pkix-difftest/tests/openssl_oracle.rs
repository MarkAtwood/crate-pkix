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

/// Helper: load a PKITS testcase by name and return the corresponding Chain
/// (with CRLs already attached via the PKITS loader).
///
/// Independent oracle:
/// * The Chain construction uses the PkitsCorpus loader, whose CRL plumbing
///   is independently asserted in `tests/corpus_pkits.rs`. This test asserts
///   only how the openssl oracle reacts to a Chain that carries CRLs.
fn pkits_chain(name: &str) -> Chain {
    use pkix_difftest::corpus::pkits::PkitsCorpus;
    use pkix_difftest::corpus::Corpus;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("pkix-path/tests/pkits");
    let corpus = PkitsCorpus::load(&root).expect("load PKITS manifest");
    for item in corpus.iter() {
        let item = item.expect("PKITS entry resolves");
        if item.name == name {
            return item.chain;
        }
    }
    panic!("PKITS testcase not found: {name}");
}

#[test]
fn openssl_oracle_reports_revoked_for_pkits_4_4_3() {
    // Oracle: PKITS 4.4.3 "Invalid Revoked EE Test3" — the EE serial is on
    // the GoodCACRL. ShouldValidate is false. The chain ships with both
    // the trust anchor CRL and the issuer CRL. We pass them to OpenSSL via
    // `-CRLfile` + `-crl_check_all`.
    //
    // OpenSSL 3.0 reports a revoked cert with `error 23 at <depth> lookup:
    // certificate revoked`. Our extract_reason() returns the substring
    // after the last `: `, so the reason string should contain "revoked".
    let chain = pkits_chain("4.4.3 Invalid Revoked EE Test3");
    assert!(
        !chain.crls.is_empty(),
        "PKITS 4.4.3 must ship with CRLs (precondition for this test)"
    );
    let verdict = expect_openssl_available(oracles::openssl::verify(&chain));
    match verdict {
        Verdict::Pass => panic!("PKITS 4.4.3 must fail under openssl verify (EE is revoked)"),
        Verdict::Fail { reason } => {
            assert!(
                reason.to_lowercase().contains("revoked"),
                "expected revocation-related reason, got: {reason:?}"
            );
        }
    }
}

/// Build a 2-cert Chain (leaf + root) from individual DER fixture files
/// in the pkix-chain test corpus. Used by the wrapper-level VerifyArgs
/// tests below (PKIX-fmtv.18.1).
fn chain_from_pkix_chain_fixtures(leaf_name: &str) -> Chain {
    let fix_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("pkix-chain/tests/fixtures");
    let leaf_der = std::fs::read(fix_dir.join(leaf_name)).expect("read leaf");
    let root_der = std::fs::read(fix_dir.join("root.der")).expect("read root");
    Chain {
        certs_der: vec![leaf_der, root_der],
        crls: Vec::new(),
        root_in_chain: true,
        label: leaf_name.to_string(),
        validation_time_unix: Some(1_780_272_000),
    }
}

#[test]
fn verify_with_args_purpose_sslserver_with_matching_hostname() {
    // PKIX-fmtv.18.1 wrapper-level entry point: `-purpose sslserver
    // -verify_hostname X` over a leaf whose SAN matches X. Independent
    // oracle: `host-exact-foo.der` was generated by
    // `pkix-chain/tests/fixtures/gen.py` (pyca/cryptography) with SAN
    // dNSName=foo.example.com. OpenSSL must accept the binding.
    let chain = chain_from_pkix_chain_fixtures("host-exact-foo.der");
    let args = oracles::openssl::VerifyArgs {
        purpose: Some("sslserver"),
        verify_hostname: Some("foo.example.com"),
        ..oracles::openssl::VerifyArgs::default()
    };
    let verdict = expect_openssl_available(oracles::openssl::verify_with_args(&chain, &args));
    assert_eq!(
        verdict,
        Verdict::Pass,
        "host-exact-foo.der must validate as sslserver under \
         -verify_hostname foo.example.com; got {verdict}"
    );
}

#[test]
fn verify_with_args_purpose_sslserver_with_mismatched_hostname() {
    let chain = chain_from_pkix_chain_fixtures("host-exact-foo.der");
    let args = oracles::openssl::VerifyArgs {
        purpose: Some("sslserver"),
        verify_hostname: Some("bar.example.com"),
        ..oracles::openssl::VerifyArgs::default()
    };
    let verdict = expect_openssl_available(oracles::openssl::verify_with_args(&chain, &args));
    match verdict {
        Verdict::Pass => panic!(
            "host-exact-foo.der must NOT validate as sslserver under \
             -verify_hostname bar.example.com"
        ),
        Verdict::Fail { reason } => {
            // OpenSSL 3.0 reports a hostname mismatch as "Hostname
            // mismatch" or similar; accept anything case-insensitive
            // matching "hostname" or "subject" or "name".
            let r = reason.to_lowercase();
            assert!(
                r.contains("hostname") || r.contains("name") || r.contains("subject"),
                "expected hostname-related reason, got: {reason:?}"
            );
        }
    }
}

#[test]
fn verify_with_args_purpose_sslserver_with_ip_literal_match() {
    // host-ipv4.der was generated with SAN iPAddress=192.0.2.5.
    let chain = chain_from_pkix_chain_fixtures("host-ipv4.der");
    let args = oracles::openssl::VerifyArgs {
        purpose: Some("sslserver"),
        verify_ip: Some("192.0.2.5"),
        ..oracles::openssl::VerifyArgs::default()
    };
    let verdict = expect_openssl_available(oracles::openssl::verify_with_args(&chain, &args));
    assert_eq!(
        verdict,
        Verdict::Pass,
        "host-ipv4.der must validate as sslserver under \
         -verify_ip 192.0.2.5; got {verdict}"
    );
}

#[test]
fn verify_with_args_default_is_chain_only_no_extra_flags() {
    // Sanity-pin that VerifyArgs::default() reproduces the chain-shape
    // behavior — a host-exact-foo.der chain validates as a path with no
    // purpose binding, identical to plain `verify()`. This regression-
    // guards the chain-shape callers (PKITS / x509-limbo / pem-tree) from
    // any accidental flag injection when they use the new entry point.
    let chain = chain_from_pkix_chain_fixtures("host-exact-foo.der");
    let verdict = expect_openssl_available(oracles::openssl::verify_with_args(
        &chain,
        &oracles::openssl::VerifyArgs::default(),
    ));
    assert_eq!(verdict, Verdict::Pass);
}

#[test]
fn openssl_oracle_pkits_4_1_1_passes_with_crls_attached() {
    // Oracle: PKITS 4.1.1 "Valid Signatures Test1" — should pass with or
    // without CRL flags. This is the regression check that `-CRLfile` +
    // `-crl_check_all` does not flip an otherwise valid chain to Fail.
    // The chain ships with two CRLs covering anchor + intermediate.
    let chain = pkits_chain("4.1.1 Valid Signatures Test1");
    assert!(
        !chain.crls.is_empty(),
        "PKITS 4.1.1 must ship with CRLs (precondition for this test)"
    );
    let verdict = expect_openssl_available(oracles::openssl::verify(&chain));
    assert_eq!(
        verdict,
        Verdict::Pass,
        "PKITS 4.1.1 must validate under openssl verify with CRLs; got {verdict}"
    );
}
