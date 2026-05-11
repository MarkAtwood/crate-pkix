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
//! # Indirect-CRL note
//!
//! Several §4.5 CRLs are signed by a cert that is *not* the same as the cert
//! that issued the EE — exactly the cases that test [RFC 5280] indirect-CRL
//! handling. `pkix-revocation` does not currently perform path-level CRL signer
//! discovery. Each test below explicitly identifies the
//! CRL signer cert (by matching CRL `AuthorityKeyIdentifier` against the cert
//! bundle's `SubjectKeyIdentifier`) and supplies it as the `issuer` argument
//! to [`CrlChecker::check_revocation`]. This is mechanically valid: the API
//! checks (a) `issuer.subject == CRL.issuer`, (b) `issuer` has `cRLSign` in
//! `KeyUsage`, and (c) the CRL signature verifies against `issuer.SPKI` — all
//! hold when `issuer` is the actual CRL signer.

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

// ============================================================================
// §4.5.1 / §4.5.2 — Old With New CA
//
// Both EEs are signed by the OLD key (held by `BasicSelfIssuedNewKeyOldWithNew-
// CACert`, the self-issued bridge). The CRL `BasicSelfIssuedNewKeyCACRL` covers
// EEs and is signed by the NEW key (held by `BasicSelfIssuedNewKeyCACert`).
// `BasicSelfIssuedNewKeyCACert` is therefore the CRL signer.
// ============================================================================

/// §4.5.1 Valid Basic Self-Issued Old With New Test1 — Test1EE (serial 02) is
/// not on `BasicSelfIssuedNewKeyCACRL` (revoked: serial 03 only).
///
/// Oracle: PKITS §4.5.1 MUST validate (no revocation).
#[test]
fn pkits_4_5_1_test1_not_revoked() {
    let ee = load_cert(&pkits_cert("ValidBasicSelfIssuedOldWithNewTest1EE"));
    let crl_signer = load_cert(&pkits_cert("BasicSelfIssuedNewKeyCACert"));
    let crl = pkits_crl("BasicSelfIssuedNewKeyCACRL");

    let checker = CrlChecker::new(crl, PKITS_NOW, DefaultVerifier).expect("CRL must parse");
    checker
        .check_revocation(&ee, &crl_signer)
        .expect("§4.5.1: Test1EE serial 02 is not on the CRL");
}

/// §4.5.2 Invalid Basic Self-Issued Old With New Test2 — Test2EE (serial 03) is
/// on `BasicSelfIssuedNewKeyCACRL`.
///
/// Oracle: PKITS §4.5.2 MUST NOT validate (EE is revoked).
#[test]
fn pkits_4_5_2_test2_revoked() {
    let ee = load_cert(&pkits_cert("InvalidBasicSelfIssuedOldWithNewTest2EE"));
    let crl_signer = load_cert(&pkits_cert("BasicSelfIssuedNewKeyCACert"));
    let crl = pkits_crl("BasicSelfIssuedNewKeyCACRL");

    let checker = CrlChecker::new(crl, PKITS_NOW, DefaultVerifier).expect("CRL must parse");
    let result = checker.check_revocation(&ee, &crl_signer);
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
// `AuthorityKeyIdentifier`). PKITS §4.5.3/4/5 narrative is explicit: "the CRL
// covering all certificates issued by the intermediate CA was signed using the
// intermediate CA's new private key, requiring the relying party to use the
// CA's new-signed-with-old self-issued certificate in order to validate the
// intermediate CA's CRL".
// ============================================================================

/// §4.5.3 Valid Basic Self-Issued New With Old Test3 — Test3EE (serial 02) is
/// not on `BasicSelfIssuedOldKeyCACRL` (revoked: serial 04 only).
///
/// Oracle: PKITS §4.5.3 MUST validate.
#[test]
fn pkits_4_5_3_test3_not_revoked() {
    let ee = load_cert(&pkits_cert("ValidBasicSelfIssuedNewWithOldTest3EE"));
    let crl_signer = load_cert(&pkits_cert("BasicSelfIssuedOldKeyNewWithOldCACert"));
    let crl = pkits_crl("BasicSelfIssuedOldKeyCACRL");

    let checker = CrlChecker::new(crl, PKITS_NOW, DefaultVerifier).expect("CRL must parse");
    checker
        .check_revocation(&ee, &crl_signer)
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
    let crl_signer = load_cert(&pkits_cert("BasicSelfIssuedOldKeyNewWithOldCACert"));
    let crl = pkits_crl("BasicSelfIssuedOldKeyCACRL");

    let checker = CrlChecker::new(crl, PKITS_NOW, DefaultVerifier).expect("CRL must parse");
    checker
        .check_revocation(&ee, &crl_signer)
        .expect("§4.5.4: Test4EE serial 03 is not on the CRL");
}

/// §4.5.5 Invalid Basic Self-Issued New With Old Test5 — Test5EE (serial 04) is
/// on `BasicSelfIssuedOldKeyCACRL`.
///
/// Oracle: PKITS §4.5.5 MUST NOT validate (EE is revoked).
#[test]
fn pkits_4_5_5_test5_revoked() {
    let ee = load_cert(&pkits_cert("InvalidBasicSelfIssuedNewWithOldTest5EE"));
    let crl_signer = load_cert(&pkits_cert("BasicSelfIssuedOldKeyNewWithOldCACert"));
    let crl = pkits_crl("BasicSelfIssuedOldKeyCACRL");

    let checker = CrlChecker::new(crl, PKITS_NOW, DefaultVerifier).expect("CRL must parse");
    let result = checker.check_revocation(&ee, &crl_signer);
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
// ============================================================================

/// §4.5.6 Valid Basic Self-Issued CRL Signing Key Test6 — Test6EE (serial 02)
/// is not on `BasicSelfIssuedCRLSigningKeyCACRL` (revoked: serial 03 only).
///
/// Oracle: PKITS §4.5.6 MUST validate.
#[test]
fn pkits_4_5_6_test6_not_revoked() {
    let ee = load_cert(&pkits_cert("ValidBasicSelfIssuedCRLSigningKeyTest6EE"));
    let crl_signer = load_cert(&pkits_cert("BasicSelfIssuedCRLSigningKeyCRLCert"));
    let crl = pkits_crl("BasicSelfIssuedCRLSigningKeyCACRL");

    let checker = CrlChecker::new(crl, PKITS_NOW, DefaultVerifier).expect("CRL must parse");
    checker
        .check_revocation(&ee, &crl_signer)
        .expect("§4.5.6: Test6EE serial 02 is not on the CRL");
}

/// §4.5.7 Invalid Basic Self-Issued CRL Signing Key Test7 — Test7EE (serial 03)
/// is on `BasicSelfIssuedCRLSigningKeyCACRL`.
///
/// Oracle: PKITS §4.5.7 MUST NOT validate (EE is revoked).
#[test]
fn pkits_4_5_7_test7_revoked() {
    let ee = load_cert(&pkits_cert("InvalidBasicSelfIssuedCRLSigningKeyTest7EE"));
    let crl_signer = load_cert(&pkits_cert("BasicSelfIssuedCRLSigningKeyCRLCert"));
    let crl = pkits_crl("BasicSelfIssuedCRLSigningKeyCACRL");

    let checker = CrlChecker::new(crl, PKITS_NOW, DefaultVerifier).expect("CRL must parse");
    let result = checker.check_revocation(&ee, &crl_signer);
    assert!(
        matches!(result, Err(pkix_revocation::Error::Revoked { .. })),
        "§4.5.7: Test7EE serial 03 must return Revoked, got: {result:?}"
    );
}
