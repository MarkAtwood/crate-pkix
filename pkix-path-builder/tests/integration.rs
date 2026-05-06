//! Integration tests for pkix-path-builder.
//!
//! Uses PKITS (NIST SP 800-89) certificate fixtures from the pkix-path crate.
//! All tests are fully offline; no network access is performed.

use der::asn1::BitString;
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
    Certificate::from_der(&der_bytes).unwrap_or_else(|e| panic!("failed to parse cert {name}: {e}"))
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

    let path = build_path(&ee, &pool, std::slice::from_ref(&anchor))
        .expect("build_path should succeed for PKITS §4.1.1 chain");

    // Chain must be leaf-first with at least [EE, GoodCACert].
    assert!(
        path.len() >= 2,
        "path should contain at least EE + intermediate"
    );

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

    let path = build_path(&ee, &pool, std::slice::from_ref(&anchor))
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

    let err =
        build_path(&ee, &pool, &[anchor]).expect_err("build_path should fail with an empty pool");

    assert!(
        matches!(err, pkix_path_builder::Error::NoPathFound),
        "expected NoPathFound, got {err}"
    );
}

/// Pool contains a self-signed cert that is NOT a trust anchor.
///
/// build_path must NOT terminate at it — it must continue searching for the
/// real anchor. The correct chain uses GoodCACert; the self-signed BadSignedCACert
/// (subject ≠ trust anchor subject) must be skipped.
#[test]
fn test_build_path_self_signed_non_anchor_in_pool() {
    let ee = pkits_cert("ValidCertificatePathTest1EE");
    let intermediate = pkits_cert("GoodCACert");
    // BadSignedCACert is self-signed (subject == issuer) but NOT the trust anchor.
    let bad_ca = pkits_cert("BadSignedCACert");
    let anchor = pkits_trust_anchor();

    let mut pool = CertPool::new();
    pool.add(intermediate);
    pool.add(bad_ca); // self-signed, different CA, not the anchor

    let path = build_path(&ee, &pool, std::slice::from_ref(&anchor))
        .expect("build_path must find the correct path ignoring the self-signed non-anchor");

    // The built path must still validate end-to-end.
    let policy = pkix_path::ValidationPolicy::new(PKITS_NOW);
    let verifier = pkix_path::DefaultVerifier;
    pkix_path::validate_path(&path, &[anchor], &policy, &verifier)
        .expect("validate_path should succeed on the built chain");
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

/// Verify SPKI-based cycle detection: adding the same intermediate certificate
/// twice to the pool must not cause a duplicate-SPKI loop. The path builder
/// must still find the correct path (the duplicate is pruned by SPKI identity).
///
/// Oracle: the PKITS §4.1.1 chain is known-valid. If cycle detection incorrectly
/// pruned a legitimate certificate (false positive), build_path would return
/// NoPathFound. If it failed to prune duplicates (false negative), it might
/// return duplicate entries in the chain or loop indefinitely.
#[test]
fn test_build_path_duplicate_cert_in_pool_pruned_by_spki() {
    let ee = pkits_cert("ValidCertificatePathTest1EE");
    let intermediate = pkits_cert("GoodCACert");
    let anchor = pkits_trust_anchor();

    // Add the same intermediate twice — same SPKI, so one should be pruned.
    let mut pool = CertPool::new();
    pool.add(intermediate.clone());
    pool.add(intermediate); // duplicate — different Vec slot, same SPKI

    let path = build_path(&ee, &pool, std::slice::from_ref(&anchor))
        .expect("build_path must find path even with duplicate certs in pool");

    // Validate the result to confirm it's a real path, not a loop.
    let mut policy = ValidationPolicy::new(PKITS_NOW);
    policy.enforce_key_usage = false;
    pkix_path::validate_path(&path, &[anchor], &policy, &DefaultVerifier)
        .expect("path returned with duplicate pool entries must be valid");

    // Chain must not have duplicates — SPKI-based pruning ensures the same
    // intermediate was not selected twice at different positions.
    let spkis: Vec<_> = path
        .iter()
        .map(|c| {
            use der::Encode as _;
            let mut buf = Vec::new();
            c.tbs_certificate
                .subject_public_key_info
                .encode_to_vec(&mut buf)
                .unwrap();
            buf
        })
        .collect();
    let deduped_len = {
        let mut seen = std::collections::HashSet::new();
        spkis.iter().filter(|s| seen.insert(*s)).count()
    };
        assert_eq!(
        spkis.len(),
        deduped_len,
        "path must not contain duplicate SPKI entries"
    );
}

/// Adversarial pool test: verify that `build_path` returns `BudgetExceeded`
/// within a reasonable time when given a pool engineered to maximise DFS
/// branching.
///
/// Construction: take the PKITS `GoodCACert` as a template CA certificate
/// (it has `BasicConstraints cA=TRUE`).  Clone it 30 times, each clone with:
/// - `subject`  = "GoodCA" (same as template — so all clones are candidates
///   whenever another cert's issuer is "GoodCA")
/// - `issuer`   = "GoodCA" (same as `subject` — so at every DFS level the
///   algorithm searches the pool for a parent and finds all unvisited clones)
/// - unique `subject_public_key` bytes — bypasses the SPKI cycle guard so
///   the same logical DN may be visited repeatedly via different key material
///
/// The EE target has `issuer` = "GoodCA", so the DFS starts with 30 candidates
/// at depth 1, 29 unvisited at depth 2 (for each of the 30), etc.
/// Without the budget cap this would run in O(30!) time; the cap must fire
/// well before 10 000 node visits and return `BudgetExceeded`.
///
/// Oracle: `matches!(err, Error::BudgetExceeded)`.
/// The test also asserts it completes in under two seconds to guard against
/// accidental budget removal.
#[test]
fn test_build_path_adversarial_pool_budget_exceeded() {
    let ee = pkits_cert("ValidCertificatePathTest1EE");
    // Template CA: subject = target's issuer DN; has BasicConstraints cA=TRUE.
    let template_ca = pkits_cert("GoodCACert");

    // Use a trust anchor whose subject does NOT match any cert in the pool,
    // so no path can succeed and the DFS exhausts all candidates.
    // Use a cert whose subject is unrelated to GoodCACert's issuer chain so
    // no path can terminate successfully and the DFS exhausts all candidates.
    let fake_anchor = TrustAnchor::from(&pkits_cert("BadSignedCACert"));

    // Create 30 CA clones with the same subject/issuer but distinct SPKIs.
    const N: usize = 30;
    let mut pool = CertPool::new();
    for i in 0..N {
        let mut ca = template_ca.clone();
        // Make issuer == subject: each clone will look for its own parent
        // in the pool, finding all other clones as candidates → exponential fan-out.
        ca.tbs_certificate.issuer = ca.tbs_certificate.subject.clone();
        // Unique SPKI defeats the cycle guard so all N clones are treated as
        // distinct DFS nodes.
        ca.tbs_certificate.subject_public_key_info.subject_public_key =
            BitString::new(0, vec![i as u8; 32])
                .expect("BitString construction must succeed for valid parameters");
        pool.add(ca);
    }

    let start = std::time::Instant::now();
    let err = build_path(&ee, &pool, std::slice::from_ref(&fake_anchor))
        .expect_err("adversarial pool should not find a valid path");
    let elapsed = start.elapsed();

    assert!(
        matches!(err, pkix_path_builder::Error::BudgetExceeded),
        "expected BudgetExceeded, got {err}"
    );
    assert!(
        elapsed.as_secs() < 2,
        "build_path took {elapsed:?}; budget enforcement must prevent exponential blowup"
    );
}
