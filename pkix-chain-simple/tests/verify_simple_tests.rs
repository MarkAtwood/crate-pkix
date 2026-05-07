//! Integration tests for `pkix_chain_simple::verify_simple`.
//!
//! All test certificate DER files were generated using pyca/cryptography as
//! the external oracle. They are committed to tests/fixtures/ and loaded
//! at test time — no network access required.
//!
//! Validation time constant: 2026-06-01 = 1_780_272_000 UTC.
//! All fixtures have notBefore=2026-01-01 and notAfter ≥ 2030-01-01.

use der::Decode as _;
use pkix_chain_simple::{verify_simple, Error};
use pkix_path::TrustAnchor;
use x509_cert::Certificate;

/// Unix timestamp within all test cert validity windows (2026-06-01).
const NOW: u64 = 1_780_272_000;

/// Unix timestamp before all test cert validity windows (1970-01-01).
const BEFORE: u64 = 0;

fn load(name: &str) -> Certificate {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let der = std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
    Certificate::from_der(&der).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

fn anchor(cert: Certificate) -> TrustAnchor {
    TrustAnchor::from_cert(cert)
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

/// Single end-entity cert whose issuer is directly trusted.
///
/// chain = [gry-leaf], anchor = gry-int.
/// Oracle: pyca chain; gry-leaf has no extensions → passes simplicity gate.
#[test]
fn verify_simple_single_cert_ok() {
    let leaf = load("gry-leaf.der");
    let int_cert = load("gry-int.der");
    let anchors = [anchor(int_cert)];
    let vp = verify_simple(&[leaf], &anchors, NOW).expect("single-cert chain must validate");
    assert_eq!(vp.anchor_index, 0);
    assert_eq!(vp.depth, 0);
}

/// Leaf + 1 intermediate, with root as anchor.
///
/// chain = [gry-leaf, gry-int], anchor = gry-root.
/// Oracle: pyca chain; gry-int has only BC + KU → passes simplicity gate.
#[test]
fn verify_simple_one_intermediate_ok() {
    let leaf = load("gry-leaf.der");
    let int_cert = load("gry-int.der");
    let root = load("gry-root.der");
    let anchors = [anchor(root)];
    let vp = verify_simple(&[leaf, int_cert], &anchors, NOW).expect("2-cert chain must validate");
    assert_eq!(vp.anchor_index, 0);
    assert_eq!(vp.depth, 1);
}

/// Leaf + 2 intermediates (MAX_INTERMEDIATES = 2) with root as anchor.
///
/// chain = [dbl-leaf, dbl-int2, dbl-int1], anchor = dbl-root.
/// Oracle: pyca chain; dbl-int1/dbl-int2 have only BC + KU → passes simplicity gate.
#[test]
fn verify_simple_two_intermediates_ok() {
    let leaf = load("dbl-leaf.der");
    let int2 = load("dbl-int2.der");
    let int1 = load("dbl-int1.der");
    let root = load("dbl-root.der");
    let anchors = [anchor(root)];
    let vp = verify_simple(&[leaf, int2, int1], &anchors, NOW)
        .expect("3-cert chain (MAX_INTERMEDIATES=2) must validate");
    assert_eq!(vp.anchor_index, 0);
    assert_eq!(vp.depth, 2);
}

// ---------------------------------------------------------------------------
// Shape errors
// ---------------------------------------------------------------------------

/// Empty chain → EmptyChain.
#[test]
fn verify_simple_empty_chain_returns_error() {
    let root = load("gry-root.der");
    let result = verify_simple(&[], &[anchor(root)], NOW);
    assert!(
        matches!(result, Err(Error::EmptyChain)),
        "empty chain must return EmptyChain, got: {result:?}"
    );
}

/// Chain with 4 certs (3 intermediates) exceeds MAX_INTERMEDIATES=2.
///
/// Chain length check fires before signature verification; unrelated certs can be used.
#[test]
fn verify_simple_chain_too_long_returns_error() {
    let c1 = load("gry-leaf.der");
    let c2 = load("gry-int.der");
    let c3 = load("dbl-int1.der");
    let c4 = load("dbl-int2.der");
    let root = load("gry-root.der");
    let result = verify_simple(&[c1, c2, c3, c4], &[anchor(root)], NOW);
    assert!(
        matches!(result, Err(Error::ChainTooLong { len: 4 })),
        "4-cert chain must return ChainTooLong {{ len: 4 }}, got: {result:?}"
    );
}

/// Empty anchors slice → NoTrustAnchors.
#[test]
fn verify_simple_no_trust_anchors_returns_error() {
    let leaf = load("gry-leaf.der");
    let result = verify_simple(&[leaf], &[], NOW);
    assert!(
        matches!(result, Err(Error::NoTrustAnchors)),
        "empty anchors must return NoTrustAnchors, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Algorithm errors
// ---------------------------------------------------------------------------

/// Cert using ECDSA-P384-SHA384 — not in ALLOWED_SIG_ALGS.
///
/// Oracle: pyca/cryptography — p384-leaf.der signed with SECP384R1/SHA384.
#[test]
fn verify_simple_algorithm_not_allowed_p384() {
    let p384_leaf = load("p384-leaf.der");
    let root = load("gry-root.der");
    let result = verify_simple(&[p384_leaf], &[anchor(root)], NOW);
    assert!(
        matches!(result, Err(Error::AlgorithmNotAllowed { index: 0 })),
        "P384/SHA384 cert must return AlgorithmNotAllowed {{ index: 0 }}, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Extension errors
// ---------------------------------------------------------------------------

/// Leaf with an unknown **critical** extension (1.3.6.1.5.5.7.99.99) → UnhandledCriticalExtension.
///
/// Oracle: pyca/cryptography — gry-leaf-unknown-crit.der has unknown critical OID.
/// A critical extension that is not in the allowed-and-handleable set must be
/// rejected as UnhandledCriticalExtension, not UnexpectedExtension.
#[test]
fn verify_simple_unknown_critical_extension_leaf() {
    let leaf = load("gry-leaf-unknown-crit.der");
    let root = load("gry-root.der");
    let result = verify_simple(&[leaf], &[anchor(root)], NOW);
    assert!(
        matches!(result, Err(Error::UnhandledCriticalExtension { index: 0 })),
        "leaf with unknown critical extension must return UnhandledCriticalExtension {{ index: 0 }}, got: {result:?}"
    );
}

/// Intermediate with FreshestCRL extension (not in ALLOWED_INTERMEDIATE_EXTENSIONS).
///
/// Oracle: pyca/cryptography — ca-freshestcrl.der is a CA cert (cA=TRUE, keyCertSign)
/// with a non-critical FreshestCRL (OID 2.5.29.46) extension.  That OID is not in
/// ALLOWED_INTERMEDIATE_EXTENSIONS, so the structural check must fire before any
/// signature verification.  Using unrelated certs in the chain is safe here.
#[test]
fn verify_simple_unexpected_extension_intermediate() {
    let ca_with_freshest_crl = load("ca-freshestcrl.der");

    let leaf = load("gry-leaf.der");
    let root = load("gry-root.der");
    let result = verify_simple(&[leaf, ca_with_freshest_crl], &[anchor(root)], NOW);
    assert!(
        matches!(result, Err(Error::UnexpectedExtension { index: 1 })),
        "intermediate with FreshestCRL must return UnexpectedExtension {{ index: 1 }}, got: {result:?}"
    );
}

/// Intermediate with no extensions at all → MissingRequiredExtension.
///
/// Oracle: pyca/cryptography — nca-int.der has no extensions.
/// check_extensions fires before validate_path.
#[test]
fn verify_simple_missing_required_extension_no_bc() {
    let leaf = load("gry-leaf.der");
    let nca_int = load("nca-int.der");
    let root = load("gry-root.der");
    let result = verify_simple(&[leaf, nca_int], &[anchor(root)], NOW);
    assert!(
        matches!(result, Err(Error::MissingRequiredExtension { index: 1 })),
        "intermediate with no extensions must return MissingRequiredExtension {{ index: 1 }}, got: {result:?}"
    );
}

/// Leaf with BasicConstraints cA=TRUE → LeafIsCA.
///
/// Oracle: pyca/cryptography — gry-root.der has BasicConstraints cA=TRUE.
#[test]
fn verify_simple_leaf_is_ca_returns_error() {
    let ca_as_leaf = load("gry-root.der");
    let root = load("dbl-root.der");
    let result = verify_simple(&[ca_as_leaf], &[anchor(root)], NOW);
    assert!(
        matches!(result, Err(Error::LeafIsCA)),
        "cert with cA=TRUE as leaf must return LeafIsCA, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Critical EKU
// ---------------------------------------------------------------------------

/// Leaf with critical ExtendedKeyUsage (serverAuth) → verify_simple must accept it.
///
/// Oracle: pyca/cryptography — eku-leaf.der issued by eku-root.der;
/// leaf has critical KeyUsage (digitalSignature) + critical EKU (serverAuth).
/// Previously rejected with UnhandledCriticalExtension before EKU was added
/// to CRITICAL_OK_LEAF_EXTENSIONS and HANDLED_CRITICAL_OIDS.
#[test]
fn verify_simple_critical_eku_accepted() {
    let leaf = load("eku-leaf.der");
    let root = load("eku-root.der");
    let vp = verify_simple(&[leaf], &[anchor(root)], NOW)
        .expect("leaf with critical EKU must be accepted");
    assert_eq!(vp.anchor_index, 0);
    assert_eq!(vp.depth, 0);
}

// ---------------------------------------------------------------------------
// Path validation errors
// ---------------------------------------------------------------------------

/// Expired certificate → Error::Path(pkix_path::Error::ValidityPeriod).
///
/// chain = [gry-leaf, gry-int], now = 0 (1970-01-01, before all cert notBefore).
#[test]
fn verify_simple_expired_returns_path_error() {
    let leaf = load("gry-leaf.der");
    let int_cert = load("gry-int.der");
    let root = load("gry-root.der");
    let result = verify_simple(&[leaf, int_cert], &[anchor(root)], BEFORE);
    assert!(
        matches!(
            result,
            Err(Error::Path(pkix_path::Error::ValidityPeriod { .. }))
        ),
        "not-yet-valid chain must return Error::Path(ValidityPeriod), got: {result:?}"
    );
}
