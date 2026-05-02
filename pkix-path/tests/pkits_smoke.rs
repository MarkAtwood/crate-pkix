//! PKITS smoke tests — verify the test helper infrastructure and a baseline
//! happy-path / rejection path from PKITS §4.1.
//!
//! Oracle: NIST PKITS (SP 800-89) §4.1.1 specifies that
//! `ValidCertificatePathTest1EE` with `GoodCACert` and the trust anchor MUST pass.

#[path = "pkits_helper.rs"]
mod pkits_helper;

use pkits_helper::{pkits_validate, PKITS_NOW};

/// PKITS §4.1.1 — Valid Certificate Path Test 1.
///
/// Chain: [ValidCertificatePathTest1EE, GoodCACert], anchor: TrustAnchorRootCertificate.
/// Oracle: PKITS §4.1.1 requires this path to be VALID.
#[test]
fn pkits_4_1_1_valid_cert_path() {
    let result = pkits_validate(&["ValidCertificatePathTest1EE", "GoodCACert"], PKITS_NOW);
    let vp = result.expect("PKITS §4.1.1 must validate");
    assert_eq!(vp.anchor_index, 0);
    assert_eq!(vp.depth, 1, "one intermediate (GoodCACert)");
}

/// Negative: same §4.1.1 chain but now_unix=0 (before notBefore=2010-01-01).
///
/// Oracle: all PKITS certs have notBefore=2010-01-01; at Unix time 0 they are not yet valid.
#[test]
fn pkits_4_1_1_not_yet_valid_at_epoch() {
    let result = pkits_validate(&["ValidCertificatePathTest1EE", "GoodCACert"], 0);
    assert!(
        matches!(result, Err(pkix_path::Error::ValidityPeriod { .. })),
        "before notBefore must fail with ValidityPeriod, got: {result:?}"
    );
}

/// PKITS §4.1.2 — No Certificates in Path (leaf only, leaf IS the trust anchor).
///
/// Chain: [TrustAnchorRootCertificate], anchor: TrustAnchorRootCertificate (same cert).
/// Oracle: PKITS §4.1.2 specifies self-signed end-entity path — VALID.
#[test]
fn pkits_4_1_2_trust_anchor_root_only() {
    use pkix_path::{TrustAnchor, ValidationPolicy};
    use x509_cert::Certificate;
    use der::Decode as _;

    let root_der = std::fs::read(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/pkits/certs/TrustAnchorRootCertificate.crt"),
    )
    .expect("read TrustAnchorRootCertificate.crt");
    let root = Certificate::from_der(&root_der).expect("parse");
    let anchors = [TrustAnchor::from_cert(root.clone())];
    let policy = ValidationPolicy { current_time_unix: PKITS_NOW, ..Default::default() };
    let result = pkix_path::validate_path(&[root], &anchors, &policy, &pkix_path::DefaultVerifier);
    let vp = result.expect("PKITS §4.1.2 must validate");
    assert_eq!(vp.anchor_index, 0);
    assert_eq!(vp.depth, 0);
}
