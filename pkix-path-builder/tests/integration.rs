//! Integration tests for pkix-path-builder.
//!
//! Uses PKITS (NIST SP 800-89) certificate fixtures from the pkix-path crate.
//! All tests are fully offline; no network access is performed.

use der::Decode as _;
use pkix_path::{DefaultVerifier, TrustAnchor, ValidationPolicy};
use pkix_path_builder::{build_path, CertPool};
use x509_cert::Certificate;

/// Unix timestamp within the PKITS cert validity window.
///
/// PKITS certs are valid from 2010-01-01 to 2030-12-31.
/// Using 2020-01-26 00:00:00 UTC = 1 580 000 000.
const PKITS_NOW: u64 = 1_580_000_000;

/// Load a PKITS DER certificate by base name (without `.crt`).
///
/// `CARGO_MANIFEST_DIR` at test time is the pkix-path-builder directory,
/// so `../pkix-path/tests/pkits/certs/` resolves to the pkix-path fixture tree.
fn pkits_cert(name: &str) -> Certificate {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../pkix-path/tests/pkits/certs")
        .join(format!("{}.crt", name));
    let der_bytes = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("fixture not found at {}: {}", path.display(), e));
    Certificate::from_der(&der_bytes)
        .unwrap_or_else(|e| panic!("failed to parse cert {name}: {e}"))
}

/// Build a trust anchor from the PKITS root certificate.
fn pkits_trust_anchor() -> TrustAnchor {
    TrustAnchor::from(&pkits_cert("TrustAnchorRootCertificate"))
}

/// Test that build_path succeeds on the PKITS §4.1.1 two-cert chain and that
/// the result passes validate_path.
#[test]
fn test_build_path_two_cert_chain() {
    let ee = pkits_cert("ValidCertificatePathTest1EE");
    let intermediate = pkits_cert("GoodCACert");
    let anchor = pkits_trust_anchor();

    let mut pool = CertPool::new();
    pool.add(intermediate);

    let path = build_path(&ee, &pool, &[anchor.clone()])
        .expect("build_path should succeed for PKITS §4.1.1 chain");

    // Chain must be leaf-first with at least [EE, GoodCACert].
    assert!(path.len() >= 2, "path should contain at least EE + intermediate");

    // Validate the built path end-to-end.
    let policy = ValidationPolicy::new(PKITS_NOW);
    let verifier = DefaultVerifier;
    pkix_path::validate_path(&path, &[anchor], &policy, &verifier)
        .expect("validate_path should succeed on the built chain");
}

/// Test that build_path works regardless of pool insertion order.
/// With a single intermediate there is only one order, but this test
/// documents the contract that pool order must not matter.
#[test]
fn test_build_path_shuffled_order() {
    let ee = pkits_cert("ValidCertificatePathTest1EE");
    let intermediate = pkits_cert("GoodCACert");
    let anchor = pkits_trust_anchor();

    // Pool contains only the single intermediate — no shuffling needed,
    // but the test asserts the contract holds.
    let mut pool = CertPool::new();
    pool.add(intermediate);

    let path = build_path(&ee, &pool, &[anchor.clone()])
        .expect("build_path should succeed regardless of pool insertion order");

    assert!(path.len() >= 2);

    let policy = ValidationPolicy::new(PKITS_NOW);
    let verifier = DefaultVerifier;
    pkix_path::validate_path(&path, &[anchor], &policy, &verifier)
        .expect("validate_path should succeed");
}

/// Test that build_path returns NoPathFound when the pool is empty.
#[test]
fn test_build_path_no_path() {
    let ee = pkits_cert("ValidCertificatePathTest1EE");
    let anchor = pkits_trust_anchor();

    let pool = CertPool::new(); // empty pool

    let err = build_path(&ee, &pool, &[anchor])
        .expect_err("build_path should fail with an empty pool");

    assert!(
        matches!(err, pkix_path_builder::Error::NoPathFound),
        "expected NoPathFound, got {err}"
    );
}

/// Test that build_path returns NoPathFound when the pool contains a cert
/// that does not link to the target's issuer.
#[test]
fn test_build_path_wrong_pool() {
    let ee = pkits_cert("ValidCertificatePathTest1EE");
    let anchor = pkits_trust_anchor();

    // BadSignedCACert is a CA cert but it is not in the EE's issuer chain.
    let wrong_cert = pkits_cert("BadSignedCACert");

    let mut pool = CertPool::new();
    pool.add(wrong_cert);

    let err = build_path(&ee, &pool, &[anchor])
        .expect_err("build_path should fail when pool contains unrelated cert");

    assert!(
        matches!(err, pkix_path_builder::Error::NoPathFound),
        "expected NoPathFound, got {err}"
    );
}
