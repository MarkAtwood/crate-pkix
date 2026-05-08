//! Smoke tests for the `pkix-difftest` skeleton (PKIX-7nsf.1).
//!
//! Test oracles for these tests are independent of `pkix-path`:
//!
//! - `good-chain.pem` is PKITS test 4.1.1 "Valid Signatures Test1".
//!   PKITS ground truth: `ShouldValidate: true`.
//!   Independently confirmed by `openssl verify`: Pass (exit 0).
//!
//! - `bad-chain.pem` is PKITS test 4.1.2 "Invalid CA Signature Test2".
//!   PKITS ground truth: `ShouldValidate: false`.
//!   Independently confirmed by `openssl verify`: Fail (`certificate signature
//!   failure` at depth 1, exit 2).
//!
//! These tests therefore assert that `pkix-path` agrees with PKITS ground
//! truth + OpenSSL on these two chains. Disagreement is a real divergence,
//! not a contrived assertion.

use std::path::PathBuf;

use pkix_difftest::{oracles, Chain, Verdict};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

#[test]
fn good_chain_loads_with_three_certs() {
    let chain =
        Chain::from_pem_file(&fixtures_dir().join("good-chain.pem")).expect("load good-chain");
    assert_eq!(
        chain.certs_der.len(),
        3,
        "good-chain.pem should contain 3 certs (leaf, intermediate, root)"
    );
    assert!(chain.root_in_chain);
}

#[test]
fn good_chain_passes_pkix_path_oracle() {
    // Independent oracle expectation: PKITS 4.1.1 ShouldValidate = true,
    // OpenSSL verify exit = 0.
    let chain =
        Chain::from_pem_file(&fixtures_dir().join("good-chain.pem")).expect("load good-chain");
    let verdict = oracles::pkix_path::verify(&chain).expect("oracle ran without harness error");
    assert_eq!(
        verdict,
        Verdict::Pass,
        "PKITS 4.1.1 should validate; pkix-path returned: {verdict}"
    );
}

#[test]
fn bad_chain_fails_pkix_path_oracle() {
    // Independent oracle expectation: PKITS 4.1.2 ShouldValidate = false,
    // OpenSSL verify exit = 2 ("certificate signature failure" at depth 1).
    let chain =
        Chain::from_pem_file(&fixtures_dir().join("bad-chain.pem")).expect("load bad-chain");
    let verdict = oracles::pkix_path::verify(&chain).expect("oracle ran without harness error");
    assert!(
        matches!(verdict, Verdict::Fail { .. }),
        "PKITS 4.1.2 should fail validation; pkix-path returned: {verdict}"
    );
}

#[test]
fn ordering_autodetect_normalises_root_first_input() {
    // Take the leaf-first fixture, re-encode in root-first order, and confirm
    // the loader produces an identical canonical leaf-first `certs_der`.
    //
    // This proves the auto-detect heuristic does what the type-level docs say
    // without depending on pkix-path itself for the assertion.
    let leaf_first =
        Chain::from_pem_file(&fixtures_dir().join("good-chain.pem")).expect("load leaf-first");

    // Re-encode reversed.
    let mut root_first_pem = String::new();
    for der in leaf_first.certs_der.iter().rev() {
        let block = pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, der)
            .expect("re-encode PEM");
        root_first_pem.push_str(&block);
    }

    let normalised = Chain::from_pem_bytes(root_first_pem.as_bytes(), "test-reversed".to_string())
        .expect("load reversed");
    assert_eq!(
        leaf_first.certs_der, normalised.certs_der,
        "auto-detected ordering should produce identical canonical form regardless of input order"
    );
}

#[test]
fn loading_a_pem_with_a_non_certificate_block_errors() {
    // RSA PRIVATE KEY mixed in with a CERTIFICATE block must not be silently
    // skipped — config bugs like that need to be surfaced loudly.
    let mut bytes = std::fs::read(fixtures_dir().join("good-chain.pem")).unwrap();
    bytes.extend_from_slice(
        b"\n-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n",
    );
    let err = Chain::from_pem_bytes(&bytes, "with-private-key".to_string()).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("RSA PRIVATE KEY") || msg.contains("CERTIFICATE"),
        "error message should mention the offending label, got: {msg}"
    );
}
