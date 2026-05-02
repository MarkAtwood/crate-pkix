//! End-to-end tests for `pkix_chain::verify_chain_default` and `verify_chain`.
//!
//! Uses PKITS §4.1.1 certificates as the test vector:
//!   - TrustAnchorRootCertificate.crt (trust anchor, RSA-2048/SHA-256)
//!   - GoodCACert.crt                 (intermediate, notBefore=2010-01-01, notAfter=2030-12-31)
//!   - ValidCertificatePathTest1EE.crt (end-entity, same validity window)
//!
//! Oracle: NIST PKITS §4.1.1 specifies this path MUST validate.
//! Unix timestamps: PKITS certs valid 2010-01-01 08:30 to 2030-12-31 08:30 UTC.
//!   PKITS_NOW  = 2020-01-01 00:00:00 UTC = 1 577 836 800
//!   PKITS_PAST = 1970-01-01 00:00:00 UTC = 0  (before notBefore)

use pkix_chain::{verify_chain, verify_chain_default, DefaultVerifier, NoRevocation};
use pkix_path::{TrustAnchor, ValidationPolicy};
use x509_cert::Certificate;

// PKITS cert validity: notBefore=2010-01-01 08:30 UTC, notAfter=2030-12-31 08:30 UTC.
// PKITS_NOW is 2020-01-01 00:00:00 UTC, comfortably within the validity window.
const PKITS_NOW: u64 = 1_577_836_800;

// Cert bytes are compiled in; tests run fully offline.
const TRUST_ANCHOR_DER: &[u8] =
    include_bytes!("../../pkix-path/tests/pkits/certs/TrustAnchorRootCertificate.crt");
const GOOD_CA_DER: &[u8] =
    include_bytes!("../../pkix-path/tests/pkits/certs/GoodCACert.crt");
const VALID_EE_DER: &[u8] =
    include_bytes!("../../pkix-path/tests/pkits/certs/ValidCertificatePathTest1EE.crt");

fn load(der: &[u8]) -> Certificate {
    use x509_cert::der::Decode as _;
    Certificate::from_der(der).expect("parse cert")
}

/// PKITS §4.1.1 — verify_chain_default happy path.
///
/// Chain: [ValidCertificatePathTest1EE, GoodCACert]
/// Anchor: TrustAnchorRootCertificate
/// Oracle: PKITS §4.1.1 MUST validate; depth = 1 (one intermediate: GoodCACert).
#[test]
fn e2e_verify_chain_default_pkits_4_1_1() {
    let chain = [load(VALID_EE_DER), load(GOOD_CA_DER)];
    let anchors = [TrustAnchor::from_cert(load(TRUST_ANCHOR_DER))];
    let policy = ValidationPolicy {
        current_time_unix: PKITS_NOW,
        ..Default::default()
    };

    let result = verify_chain_default(&chain, &anchors, &policy, &NoRevocation);
    let vp = result.expect("PKITS §4.1.1 must validate via verify_chain_default");
    assert_eq!(vp.anchor_index, 0, "trust anchor must be at index 0");
    assert_eq!(vp.depth, 1, "one intermediate (GoodCACert)");
}

/// Same chain as §4.1.1 but with now_unix = 0 (before all certs' notBefore).
///
/// Oracle: PKITS certs have notBefore=2010-01-01; at Unix time 0 they are not yet valid.
/// Expected: Err(pkix_chain::Error::Path(pkix_path::Error::ValidityPeriod { .. })).
#[test]
fn e2e_verify_chain_default_expired_returns_validity_error() {
    let chain = [load(VALID_EE_DER), load(GOOD_CA_DER)];
    let anchors = [TrustAnchor::from_cert(load(TRUST_ANCHOR_DER))];
    let policy = ValidationPolicy {
        current_time_unix: 0,
        ..Default::default()
    };

    let result = verify_chain_default(&chain, &anchors, &policy, &NoRevocation);
    assert!(
        matches!(
            result,
            Err(pkix_chain::Error::Path(pkix_path::Error::ValidityPeriod { .. }))
        ),
        "before notBefore must return ValidityPeriod, got: {result:?}"
    );
}

/// Same chain as §4.1.1 but using `verify_chain` with explicit `DefaultVerifier`.
///
/// Confirms the generic `verify_chain` API works end-to-end.
/// Oracle: same as §4.1.1.
#[test]
fn e2e_verify_chain_explicit_verifier() {
    let chain = [load(VALID_EE_DER), load(GOOD_CA_DER)];
    let anchors = [TrustAnchor::from_cert(load(TRUST_ANCHOR_DER))];
    let policy = ValidationPolicy {
        current_time_unix: PKITS_NOW,
        ..Default::default()
    };

    let result = verify_chain(&chain, &anchors, &policy, &DefaultVerifier, &NoRevocation);
    let vp = result.expect("PKITS §4.1.1 must validate via verify_chain with DefaultVerifier");
    assert_eq!(vp.anchor_index, 0);
    assert_eq!(vp.depth, 1);
}
