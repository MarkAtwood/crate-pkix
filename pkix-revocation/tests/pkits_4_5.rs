//! PKITS §4.5 revocation tests — `pkix-revocation` companion to
//! `pkix-path/tests/pkits_4_5.rs`.
//!
//! Oracle: NIST PKITS (SP 800-89) §4.5 narrative + `vectors.json`. Fully offline.
//!
//! # Test split between crates
//!
//! Of the 8 PKITS §4.5 cases:
//!
//! - 5 are structural (path validation) and live in `pkix-path/tests/pkits_4_5.rs`:
//!   4.5.1, 4.5.3, 4.5.4, 4.5.6 (PASS) and 4.5.8 (FAIL — EE signed by `cRLSign`-only
//!   self-issued cert lacking `BasicConstraints`).
//! - 3 are revocation failures and live in this file: 4.5.2, 4.5.5, 4.5.7.
//!
//! For completeness, this file also exercises the 4 PASS cases under the
//! revocation lens (verifying the EE is *not* on the relevant CRL).
//!
//! # Indirect-CRL / self-issued-bridge handling
//!
//! Several §4.5 CRLs are signed by a cert that is *not* the same as the cert
//! that issued the EE — exactly the cases that test [RFC 5280] indirect-CRL
//! handling. These are direct CRLs (no `IDP.indirectCRL` flag) but the CRL
//! signer differs from the EE issuer by SPKI (the "self-issued key-rollover
//! bridge" pattern).
//!
//! The tests below use
//! [`CrlChecker::new_with_signer_discovery`][pkix_revocation::CrlChecker::new_with_signer_discovery]
//! to let `pkix-revocation` locate the CRL signer in a caller-supplied bundle
//! via the CRL's `AuthorityKeyIdentifier` → bundle cert `SubjectKeyIdentifier`
//! walk (PKIX-cqwt). This replaces the prior manual lookup pattern in this
//! file's history.
//!
//! The bundle passed to `new_with_signer_discovery` contains:
//! - The candidate CRL signer cert(s).
//! - At least one self-signed (or self-issued) cert reachable from the signer
//!   so the structural anchor-reachability gate succeeds. For the §4.5 chains
//!   that includes `TrustAnchorRootCertificate` where required, and (where the
//!   signer is itself self-issued) the signer alone suffices.

use der::Decode as _;
use pkix_path::DefaultVerifier;
use pkix_revocation::{CrlChecker, RevocationChecker as _};
use x509_cert::Certificate;

/// Unix timestamp used as "now" for PKITS tests.
///
/// 2020-01-26T02:13:20Z — well within every §4.5 CRL window
/// (`thisUpdate=2010-01-01`, `nextUpdate=2030-12-31`). Matches
/// `pkix-revocation/tests/pkits_crl.rs:18`.
const PKITS_NOW: u64 = 1_580_000_000;

fn pkits_cert(name: &str) -> Vec<u8> {
    let base = env!("CARGO_MANIFEST_DIR");
    let path = format!("{base}/../pkix-path/tests/pkits/certs/{name}.crt");
    std::fs::read(&path).unwrap_or_else(|e| panic!("cert not found at {path}: {e}"))
}

fn pkits_crl(name: &str) -> Vec<u8> {
    let base = env!("CARGO_MANIFEST_DIR");
    let path = format!("{base}/../pkix-path/tests/pkits/crls/{name}.crl");
    std::fs::read(&path).unwrap_or_else(|e| panic!("CRL not found at {path}: {e}"))
}

fn load_cert(der: &[u8]) -> Certificate {
    Certificate::from_der(der).expect("cert DER parse")
}

/// Load a bundle of named PKITS certs.
fn load_bundle(names: &[&str]) -> Vec<Certificate> {
    names.iter().map(|n| load_cert(&pkits_cert(n))).collect()
}

// ============================================================================
// §4.5.1 / §4.5.2 — Old With New CA
//
// Both EEs are signed by the OLD key (held by `BasicSelfIssuedNewKeyOldWithNew-
// CACert`, the self-issued bridge). The CRL `BasicSelfIssuedNewKeyCACRL` covers
// EEs and is signed by the NEW key (held by `BasicSelfIssuedNewKeyCACert`).
// `BasicSelfIssuedNewKeyCACert` is therefore the CRL signer.
//
// Bundle composition: signer + bridge + TrustAnchorRootCertificate (signer's
// issuer is the trust anchor, so the bundle must include it for the
// reaches_self_signed structural check).
// ============================================================================

/// §4.5.1 Valid Basic Self-Issued Old With New Test1 — Test1EE (serial 02) is
/// not on `BasicSelfIssuedNewKeyCACRL` (revoked: serial 03 only).
///
/// Oracle: PKITS §4.5.1 MUST validate (no revocation).
#[test]
fn pkits_4_5_1_test1_not_revoked() {
    let ee = load_cert(&pkits_cert("ValidBasicSelfIssuedOldWithNewTest1EE"));
    let bundle = load_bundle(&[
        "BasicSelfIssuedNewKeyCACert",
        "BasicSelfIssuedNewKeyOldWithNewCACert",
        "TrustAnchorRootCertificate",
    ]);
    let crl = pkits_crl("BasicSelfIssuedNewKeyCACRL");

    let checker =
        CrlChecker::new_with_signer_discovery(crl, &bundle, &ee, PKITS_NOW, DefaultVerifier)
            .expect("CRL signer discovery must succeed");
    // The discovered signer is BasicSelfIssuedNewKeyCACert. The `issuer` arg
    // is the cert that issued the EE per the cert's `issuer` field — that
    // shares the subject DN with the discovered signer (key rollover case),
    // and a DN-equal cert in the bundle is the bridge. Both have DN
    // "Basic Self-Issued New Key CA"; pass the bridge as the cert.issuer
    // to mirror what a path walker would feed in.
    let bridge = load_cert(&pkits_cert("BasicSelfIssuedNewKeyOldWithNewCACert"));
    checker
        .check_revocation(&ee, &bridge)
        .expect("§4.5.1: Test1EE serial 02 is not on the CRL");
}

/// §4.5.2 Invalid Basic Self-Issued Old With New Test2 — Test2EE (serial 03) is
/// on `BasicSelfIssuedNewKeyCACRL`.
///
/// Oracle: PKITS §4.5.2 MUST NOT validate (EE is revoked).
#[test]
fn pkits_4_5_2_test2_revoked() {
    let ee = load_cert(&pkits_cert("InvalidBasicSelfIssuedOldWithNewTest2EE"));
    let bundle = load_bundle(&[
        "BasicSelfIssuedNewKeyCACert",
        "BasicSelfIssuedNewKeyOldWithNewCACert",
        "TrustAnchorRootCertificate",
    ]);
    let crl = pkits_crl("BasicSelfIssuedNewKeyCACRL");
    let bridge = load_cert(&pkits_cert("BasicSelfIssuedNewKeyOldWithNewCACert"));

    let checker =
        CrlChecker::new_with_signer_discovery(crl, &bundle, &ee, PKITS_NOW, DefaultVerifier)
            .expect("CRL signer discovery must succeed");
    let result = checker.check_revocation(&ee, &bridge);
    assert!(
        matches!(result, Err(pkix_revocation::Error::Revoked { .. })),
        "§4.5.2: Test2EE serial 03 must return Revoked, got: {result:?}"
    );
}

// ============================================================================
// §4.5.3 / §4.5.4 / §4.5.5 — New With Old CA
//
// Test3EE is signed by the NEW key (held by `BasicSelfIssuedOldKeyNewWithOld-
// CACert`, the self-issued bridge). Test4EE and Test5EE are signed by the OLD
// key (held by `BasicSelfIssuedOldKeyCACert` directly), bypassing the bridge.
// All three EEs share the issuer DN "Basic Self-Issued Old Key CA".
//
// CRL `BasicSelfIssuedOldKeyCACRL` covers EEs and is signed by the NEW key —
// `BasicSelfIssuedOldKeyNewWithOldCACert` is the CRL signer (per its
// `AuthorityKeyIdentifier`). The signer is *self-issued* (subject == issuer),
// so it serves as its own structural anchor in the discovery walk.
// ============================================================================

/// §4.5.3 Valid Basic Self-Issued New With Old Test3 — Test3EE (serial 02) is
/// not on `BasicSelfIssuedOldKeyCACRL` (revoked: serial 04 only).
///
/// Oracle: PKITS §4.5.3 MUST validate.
#[test]
fn pkits_4_5_3_test3_not_revoked() {
    let ee = load_cert(&pkits_cert("ValidBasicSelfIssuedNewWithOldTest3EE"));
    let bundle = load_bundle(&[
        "BasicSelfIssuedOldKeyNewWithOldCACert",
        "BasicSelfIssuedOldKeyCACert",
    ]);
    let crl = pkits_crl("BasicSelfIssuedOldKeyCACRL");
    let issuer = load_cert(&pkits_cert("BasicSelfIssuedOldKeyCACert"));

    let checker =
        CrlChecker::new_with_signer_discovery(crl, &bundle, &ee, PKITS_NOW, DefaultVerifier)
            .expect("CRL signer discovery must succeed");
    checker
        .check_revocation(&ee, &issuer)
        .expect("§4.5.3: Test3EE serial 02 is not on the CRL");
}

/// §4.5.4 Valid Basic Self-Issued New With Old Test4 — Test4EE (serial 03) is
/// not on `BasicSelfIssuedOldKeyCACRL`.
///
/// Even though Test4EE is signed by the OLD key directly (no self-issued cert
/// in the validation chain), the CRL covering Test4EE is still signed by the
/// NEW key, requiring the same indirect-CRL handling for revocation as §4.5.3.
///
/// Oracle: PKITS §4.5.4 MUST validate.
#[test]
fn pkits_4_5_4_test4_not_revoked() {
    let ee = load_cert(&pkits_cert("ValidBasicSelfIssuedNewWithOldTest4EE"));
    let bundle = load_bundle(&[
        "BasicSelfIssuedOldKeyNewWithOldCACert",
        "BasicSelfIssuedOldKeyCACert",
    ]);
    let crl = pkits_crl("BasicSelfIssuedOldKeyCACRL");
    let issuer = load_cert(&pkits_cert("BasicSelfIssuedOldKeyCACert"));

    let checker =
        CrlChecker::new_with_signer_discovery(crl, &bundle, &ee, PKITS_NOW, DefaultVerifier)
            .expect("CRL signer discovery must succeed");
    checker
        .check_revocation(&ee, &issuer)
        .expect("§4.5.4: Test4EE serial 03 is not on the CRL");
}

/// §4.5.5 Invalid Basic Self-Issued New With Old Test5 — Test5EE (serial 04) is
/// on `BasicSelfIssuedOldKeyCACRL`.
///
/// Oracle: PKITS §4.5.5 MUST NOT validate (EE is revoked).
#[test]
fn pkits_4_5_5_test5_revoked() {
    let ee = load_cert(&pkits_cert("InvalidBasicSelfIssuedNewWithOldTest5EE"));
    let bundle = load_bundle(&[
        "BasicSelfIssuedOldKeyNewWithOldCACert",
        "BasicSelfIssuedOldKeyCACert",
    ]);
    let crl = pkits_crl("BasicSelfIssuedOldKeyCACRL");
    let issuer = load_cert(&pkits_cert("BasicSelfIssuedOldKeyCACert"));

    let checker =
        CrlChecker::new_with_signer_discovery(crl, &bundle, &ee, PKITS_NOW, DefaultVerifier)
            .expect("CRL signer discovery must succeed");
    let result = checker.check_revocation(&ee, &issuer);
    assert!(
        matches!(result, Err(pkix_revocation::Error::Revoked { .. })),
        "§4.5.5: Test5EE serial 04 must return Revoked, got: {result:?}"
    );
}

// ============================================================================
// §4.5.6 / §4.5.7 — CRL Signing Key (split keyCertSign / cRLSign)
//
// Test6EE and Test7EE are signed by `BasicSelfIssuedCRLSigningKeyCACert` (the
// main CA cert, with `keyCertSign + cRLSign`). The CRL covering EEs
// (`BasicSelfIssuedCRLSigningKeyCACRL`) is signed by
// `BasicSelfIssuedCRLSigningKeyCRLCert` (a self-issued cert with only
// `cRLSign` — same subject DN as the CA cert but a different SPKI).
// CRLCert is therefore the CRL signer.
//
// Both candidate certs are self-issued; either alone satisfies the
// structural anchor-reachability check, but we include both in the bundle
// to exercise the AKI/SKI discriminator.
// ============================================================================

/// §4.5.6 Valid Basic Self-Issued CRL Signing Key Test6 — Test6EE (serial 02)
/// is not on `BasicSelfIssuedCRLSigningKeyCACRL` (revoked: serial 03 only).
///
/// Oracle: PKITS §4.5.6 MUST validate.
#[test]
fn pkits_4_5_6_test6_not_revoked() {
    let ee = load_cert(&pkits_cert("ValidBasicSelfIssuedCRLSigningKeyTest6EE"));
    let bundle = load_bundle(&[
        "BasicSelfIssuedCRLSigningKeyCACert",
        "BasicSelfIssuedCRLSigningKeyCRLCert",
    ]);
    let crl = pkits_crl("BasicSelfIssuedCRLSigningKeyCACRL");
    let issuer = load_cert(&pkits_cert("BasicSelfIssuedCRLSigningKeyCACert"));

    let checker =
        CrlChecker::new_with_signer_discovery(crl, &bundle, &ee, PKITS_NOW, DefaultVerifier)
            .expect("CRL signer discovery must succeed");
    checker
        .check_revocation(&ee, &issuer)
        .expect("§4.5.6: Test6EE serial 02 is not on the CRL");
}

/// §4.5.7 Invalid Basic Self-Issued CRL Signing Key Test7 — Test7EE (serial 03)
/// is on `BasicSelfIssuedCRLSigningKeyCACRL`.
///
/// Oracle: PKITS §4.5.7 MUST NOT validate (EE is revoked).
#[test]
fn pkits_4_5_7_test7_revoked() {
    let ee = load_cert(&pkits_cert("InvalidBasicSelfIssuedCRLSigningKeyTest7EE"));
    let bundle = load_bundle(&[
        "BasicSelfIssuedCRLSigningKeyCACert",
        "BasicSelfIssuedCRLSigningKeyCRLCert",
    ]);
    let crl = pkits_crl("BasicSelfIssuedCRLSigningKeyCACRL");
    let issuer = load_cert(&pkits_cert("BasicSelfIssuedCRLSigningKeyCACert"));

    let checker =
        CrlChecker::new_with_signer_discovery(crl, &bundle, &ee, PKITS_NOW, DefaultVerifier)
            .expect("CRL signer discovery must succeed");
    let result = checker.check_revocation(&ee, &issuer);
    assert!(
        matches!(result, Err(pkix_revocation::Error::Revoked { .. })),
        "§4.5.7: Test7EE serial 03 must return Revoked, got: {result:?}"
    );
}

// ============================================================================
// Negative-path tests for the new discovery constructor itself.
// ============================================================================

/// Empty bundle → CrlSignerNotFound (RFC 5280 §6.3.3(f) cannot locate signer).
#[test]
fn discovery_empty_bundle_returns_signer_not_found() {
    let ee = load_cert(&pkits_cert("ValidBasicSelfIssuedOldWithNewTest1EE"));
    let crl = pkits_crl("BasicSelfIssuedNewKeyCACRL");
    let result = CrlChecker::new_with_signer_discovery(crl, &[], &ee, PKITS_NOW, DefaultVerifier);
    assert!(
        matches!(result, Err(pkix_revocation::Error::CrlSignerNotFound)),
        "empty bundle must yield CrlSignerNotFound, got: {result:?}"
    );
}

/// Bundle with the signer but no anchor reachable → CrlSignerNotTrusted.
///
/// The §4.5.1/2 CRL signer (`BasicSelfIssuedNewKeyCACert`) is *not* self-issued
/// (its issuer is the Trust Anchor). A bundle containing only the signer has
/// no anchor candidate reachable, so the structural §6.3.3(f) gate fails.
#[test]
fn discovery_no_anchor_in_bundle_returns_not_trusted() {
    let ee = load_cert(&pkits_cert("ValidBasicSelfIssuedOldWithNewTest1EE"));
    let bundle = load_bundle(&["BasicSelfIssuedNewKeyCACert"]);
    let crl = pkits_crl("BasicSelfIssuedNewKeyCACRL");
    let result =
        CrlChecker::new_with_signer_discovery(crl, &bundle, &ee, PKITS_NOW, DefaultVerifier);
    assert!(
        matches!(result, Err(pkix_revocation::Error::CrlSignerNotTrusted)),
        "bundle without anchor must yield CrlSignerNotTrusted, got: {result:?}"
    );
}
