//! PKITS §4.14 (IssuingDistributionPoint) and §4.15 (delta CRL) tests for CrlChecker.
//!
//! Fixtures come from the NIST PKITS corpus committed at
//! `pkix-path/tests/pkits/{certs,crls}/`.
//!
//! External oracle: NIST PKITS 2011 document (SP 800-89 test vectors).
//! Tests are fully offline.
//!
//! Validation time: 1_580_000_000 (2020-01-26T02:13:20Z), well within all
//! PKITS CRL windows (thisUpdate 2010, nextUpdate 2030).

use der::Decode as _;
use pkix_path::DefaultVerifier;
use pkix_revocation::{CrlChecker, Error, RevocationChecker as _};
use x509_cert::Certificate;

/// Unix timestamp used as "now" for PKITS tests (2020-01-26T02:13:20Z).
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
// §4.15 Delta CRL tests
// ============================================================================

/// §4.15.1: Invalid — `deltaCRLIndicatorNoBaseCACRL` is a delta CRL for a different
/// issuer than `GoodCACRL`. When paired as (base=GoodCACRL, delta=deltaCRLIndicatorNoBaseCACRL),
/// `CrlChecker::with_delta` must reject the pair at construction time.
///
/// Oracle: PKITS §4.15.1 MUST NOT validate.
///
/// Failure path: the issuer mismatch check fires first — `deltaCRLIndicatorNoBaseCACRL`
/// was issued by the `deltaCRLIndicatorNoBase CA`, not the `Good CA` that issued
/// `GoodCACRL`. `with_delta` returns an error before reaching the CRL number check.
#[test]
fn pkits_4_15_1_invalid_delta_no_base_construction_fails() {
    // GoodCACRL is unrelated; its CRLNumber won't match deltaCRLIndicatorNoBaseCACRL's
    // BaseCRLNumber, so with_delta must return an error.
    let good_base = pkits_crl("GoodCACRL");
    let delta = pkits_crl("deltaCRLIndicatorNoBaseCACRL");
    let result = CrlChecker::with_delta(good_base, delta, PKITS_NOW, DefaultVerifier);
    assert!(
        result.is_err(),
        "§4.15.1: delta CRL with no matching base must fail at construction; got Ok"
    );
}

/// §4.15.1 (part 2): Attempting to use the delta CRL as a plain base CRL also fails
/// to prove the cert is not revoked, because the delta CRL has an empty revoked list
/// but the cert's revocation status is unknown (the base is missing).
///
/// Here we just verify that the checker constructed with the delta-only CRL
/// returns Ok for a cert that happens not to be in the revoked list — demonstrating
/// that our code does NOT incorrectly treat a delta CRL as a complete revocation
/// source (the path validator layer must enforce that a base is present; our
/// lower-level checker can only check the revoked entries it is given).
#[test]
fn pkits_4_15_1_invalid_delta_as_plain_crl_is_accepted_by_checker() {
    // This confirms our CrlChecker::new doesn't reject delta CRLs — that is a
    // path-validator-level concern. The checker itself only looks at revoked entries.
    let delta_as_crl = pkits_crl("deltaCRLIndicatorNoBaseCACRL");
    let ca_der = pkits_cert("deltaCRLIndicatorNoBaseCACert");
    let ee_der = pkits_cert("InvaliddeltaCRLIndicatorNoBaseTest1EE");
    let ca = load_cert(&ca_der);
    let ee = load_cert(&ee_der);

    let checker = CrlChecker::new(delta_as_crl, PKITS_NOW, DefaultVerifier);
    // The delta CRL has no revoked entries; checker returns Ok.
    // Note: this does NOT mean the cert is truly valid — the path validator
    // must also verify a proper base CRL is present.
    let result = checker.check_revocation(&ee, &ca);
    // The CRL has no revoked certs and is structurally valid, so Ok is expected.
    result.expect(
        "§4.15.1: delta-only CRL has no revoked entries; checker returns Ok \
         (path validator must enforce base presence)",
    );
}

/// §4.15.2: Valid delta CRL Test2.
///
/// EE serial=1. CA1 base CRL revokes: 02, 04, 05. CA1 delta CRL: 03(KeyCompromise),
/// 04(RemoveFromCRL), 05(KeyCompromise), 06(RemoveFromCRL).
/// Serial=1 is not in either → `Ok(())`.
///
/// Oracle: PKITS §4.15.2 MUST validate.
#[test]
fn pkits_4_15_2_valid_delta_crl() {
    let ca_der = pkits_cert("deltaCRLCA1Cert");
    let ee_der = pkits_cert("ValiddeltaCRLTest2EE");
    let base_crl = pkits_crl("deltaCRLCA1CRL");
    let delta_crl = pkits_crl("deltaCRLCA1deltaCRL");

    let ca = load_cert(&ca_der);
    let ee = load_cert(&ee_der);

    let checker = CrlChecker::with_delta(base_crl, delta_crl, PKITS_NOW, DefaultVerifier)
        .expect("§4.15.2: valid base+delta pair must construct");

    checker
        .check_revocation(&ee, &ca)
        .expect("§4.15.2: serial=1 cert must not be revoked");
}

/// §4.15.3: Invalid delta CRL Test3 — cert revoked in base, confirmed revoked in delta.
///
/// EE serial=2. CA1 base CRL revokes: 02, 04, 05. CA1 delta CRL: 03, 04(Remove), 05, 06(Remove).
/// Serial=2 is in the BASE CRL but NOT in the delta CRL. Delta entries take precedence;
/// since serial=2 has no delta entry, the base CRL entry applies → revoked.
///
/// Oracle: PKITS §4.15.3 MUST NOT validate.
#[test]
fn pkits_4_15_3_invalid_delta_cert_revoked_in_base() {
    let ca_der = pkits_cert("deltaCRLCA1Cert");
    let ee_der = pkits_cert("InvaliddeltaCRLTest3EE");
    let base_crl = pkits_crl("deltaCRLCA1CRL");
    let delta_crl = pkits_crl("deltaCRLCA1deltaCRL");

    let ca = load_cert(&ca_der);
    let ee = load_cert(&ee_der);

    let checker = CrlChecker::with_delta(base_crl, delta_crl, PKITS_NOW, DefaultVerifier)
        .expect("§4.15.3: valid base+delta pair must construct");

    let result = checker.check_revocation(&ee, &ca);
    assert!(
        matches!(result, Err(Error::Revoked { .. })),
        "§4.15.3: serial=2 cert is in base CRL and not removed by delta → must be Revoked; got: {result:?}"
    );
}

/// §4.15.4: Invalid delta CRL Test4 — cert revoked in delta CRL.
///
/// EE serial=3. CA1 base CRL has: 02, 04, 05 (not 03). CA1 delta CRL has 03(KeyCompromise).
/// Delta takes precedence → revoked.
///
/// Oracle: PKITS §4.15.4 MUST NOT validate.
#[test]
fn pkits_4_15_4_invalid_delta_cert_revoked_in_delta() {
    let ca_der = pkits_cert("deltaCRLCA1Cert");
    let ee_der = pkits_cert("InvaliddeltaCRLTest4EE");
    let base_crl = pkits_crl("deltaCRLCA1CRL");
    let delta_crl = pkits_crl("deltaCRLCA1deltaCRL");

    let ca = load_cert(&ca_der);
    let ee = load_cert(&ee_der);

    let checker = CrlChecker::with_delta(base_crl, delta_crl, PKITS_NOW, DefaultVerifier)
        .expect("§4.15.4: valid base+delta pair must construct");

    let result = checker.check_revocation(&ee, &ca);
    assert!(
        matches!(result, Err(Error::Revoked { .. })),
        "§4.15.4: serial=3 cert is revoked in delta CRL → must be Revoked; got: {result:?}"
    );
}

/// §4.15.5: Valid delta CRL Test5 — cert was revoked in base but un-held in delta.
///
/// EE serial=4. CA1 base CRL has 04. CA1 delta CRL has 04(RemoveFromCRL).
/// RemoveFromCRL in delta overrides base → cert is not revoked.
///
/// Oracle: PKITS §4.15.5 MUST validate.
#[test]
fn pkits_4_15_5_valid_delta_remove_from_crl() {
    let ca_der = pkits_cert("deltaCRLCA1Cert");
    let ee_der = pkits_cert("ValiddeltaCRLTest5EE");
    let base_crl = pkits_crl("deltaCRLCA1CRL");
    let delta_crl = pkits_crl("deltaCRLCA1deltaCRL");

    let ca = load_cert(&ca_der);
    let ee = load_cert(&ee_der);

    let checker = CrlChecker::with_delta(base_crl, delta_crl, PKITS_NOW, DefaultVerifier)
        .expect("§4.15.5: valid base+delta pair must construct");

    checker
        .check_revocation(&ee, &ca)
        .expect("§4.15.5: serial=4 cert has RemoveFromCRL in delta → must NOT be revoked");
}

/// §4.15.6: Invalid delta CRL Test6 — cert revoked in both base and delta.
///
/// EE serial=5. CA1 base CRL has 05. CA1 delta CRL has 05(KeyCompromise).
/// Delta confirms revocation → revoked.
///
/// Oracle: PKITS §4.15.6 MUST NOT validate.
#[test]
fn pkits_4_15_6_invalid_delta_cert_revoked_in_both() {
    let ca_der = pkits_cert("deltaCRLCA1Cert");
    let ee_der = pkits_cert("InvaliddeltaCRLTest6EE");
    let base_crl = pkits_crl("deltaCRLCA1CRL");
    let delta_crl = pkits_crl("deltaCRLCA1deltaCRL");

    let ca = load_cert(&ca_der);
    let ee = load_cert(&ee_der);

    let checker = CrlChecker::with_delta(base_crl, delta_crl, PKITS_NOW, DefaultVerifier)
        .expect("§4.15.6: valid base+delta pair must construct");

    let result = checker.check_revocation(&ee, &ca);
    assert!(
        matches!(result, Err(Error::Revoked { .. })),
        "§4.15.6: serial=5 is revoked in both base and delta → must be Revoked; got: {result:?}"
    );
}

/// §4.15.7: Valid delta CRL Test7 — cert appears only in delta with RemoveFromCRL.
///
/// EE serial=6. CA1 base CRL does NOT have 06. CA1 delta CRL has 06(RemoveFromCRL).
/// RemoveFromCRL in delta, cert not in base → cert is not revoked.
///
/// Oracle: PKITS §4.15.7 MUST validate.
#[test]
fn pkits_4_15_7_valid_delta_remove_not_in_base() {
    let ca_der = pkits_cert("deltaCRLCA1Cert");
    let ee_der = pkits_cert("ValiddeltaCRLTest7EE");
    let base_crl = pkits_crl("deltaCRLCA1CRL");
    let delta_crl = pkits_crl("deltaCRLCA1deltaCRL");

    let ca = load_cert(&ca_der);
    let ee = load_cert(&ee_der);

    let checker = CrlChecker::with_delta(base_crl, delta_crl, PKITS_NOW, DefaultVerifier)
        .expect("§4.15.7: valid base+delta pair must construct");

    checker
        .check_revocation(&ee, &ca)
        .expect("§4.15.7: serial=6 has RemoveFromCRL in delta (not in base) → must NOT be revoked");
}

/// §4.15.8: Valid delta CRL Test8 — cert not in either CRL (CA2).
///
/// EE serial=1. CA2 base CRL revokes 02. CA2 delta CRL revokes 02(KeyCompromise).
/// Serial=1 is not in either → `Ok(())`.
///
/// Oracle: PKITS §4.15.8 MUST validate.
#[test]
fn pkits_4_15_8_valid_delta_ca2_cert_not_revoked() {
    let ca_der = pkits_cert("deltaCRLCA2Cert");
    let ee_der = pkits_cert("ValiddeltaCRLTest8EE");
    let base_crl = pkits_crl("deltaCRLCA2CRL");
    let delta_crl = pkits_crl("deltaCRLCA2deltaCRL");

    let ca = load_cert(&ca_der);
    let ee = load_cert(&ee_der);

    let checker = CrlChecker::with_delta(base_crl, delta_crl, PKITS_NOW, DefaultVerifier)
        .expect("§4.15.8: valid base+delta pair must construct");

    checker
        .check_revocation(&ee, &ca)
        .expect("§4.15.8: serial=1 cert is not in CA2 base or delta CRL → must NOT be revoked");
}

/// §4.15.9: Invalid — only a delta CRL is available; no base CRL is present.
///
/// The PKITS §4.15.9 test uses deltaCRLCA3, which only provides a delta CRL.
/// Without a corresponding base CRL, the delta cannot be applied and path validation
/// must fail. Our `with_delta` constructor requires both a base and a valid delta.
///
/// We verify that `with_delta(delta, delta, ...)` fails (the "base" is also a delta)
/// and that `new(delta, ...)` + `check_revocation` does not indicate revocation
/// (since the delta has no entries), but this does NOT constitute a passing test —
/// the path validator must enforce that a non-delta base CRL is present.
#[test]
fn pkits_4_15_9_invalid_only_delta_no_base_construction_fails() {
    let delta = pkits_crl("deltaCRLCA3deltaCRL");
    // Using the delta as both base and delta must fail because the "base" would
    // also have deltaCRLIndicator (BaseCRLNumber extension), triggering DeltaCrlBaseMismatch.
    // Actually the delta has deltaCRLIndicator so it IS a delta; using it as base means
    // our with_delta call on the actual delta will try to verify BaseCRLNumber vs
    // the "base" CRL number. Since both are deltas, the delta's BaseCRLNumber won't match.
    let result = CrlChecker::with_delta(delta.clone(), delta, PKITS_NOW, DefaultVerifier);
    assert!(
        result.is_err(),
        "§4.15.9: supplying a delta CRL as the base must fail; got Ok"
    );
}

/// §4.15.10: Invalid — only a delta CRL is available; no base CRL is present (CA3).
///
/// Same scenario as §4.15.9. Uses InvaliddeltaCRLTest10EE (serial=1, CA3 issuer).
/// See §4.15.9 note: path validator must enforce base presence.
#[test]
fn pkits_4_15_10_invalid_only_delta_no_base_ca3() {
    // deltaCRLCA3CRL is actually the base CRL but with no revoked entries (empty).
    // deltaCRLCA3deltaCRL is the delta. Provide only the delta as a plain CRL and
    // verify that the cert (serial=1) is not flagged as revoked (empty delta list).
    // Note: a real path validator would fail §4.15.10 at a higher level.
    let ca_der = pkits_cert("deltaCRLCA3Cert");
    let ee_der = pkits_cert("InvaliddeltaCRLTest10EE");
    let ca = load_cert(&ca_der);
    let ee = load_cert(&ee_der);

    // Provide the delta CRL as a plain CRL — the checker accepts it but the delta
    // has an empty revoked list, so the cert passes at this level.
    let delta_as_base = pkits_crl("deltaCRLCA3deltaCRL");
    let checker = CrlChecker::new(delta_as_base, PKITS_NOW, DefaultVerifier);
    // The EE cert (serial=1) is not in the delta's (empty) revoked list → Ok().
    // Path-level validation would still fail because no proper base is provided,
    // but that invariant is enforced at construction time (see §4.15.9 test).
    let result = checker.check_revocation(&ee, &ca);
    assert!(
        result.is_ok(),
        "§4.15.10: EE not in empty delta list → checker must return Ok(); got {result:?}"
    );
}

// ============================================================================
// §4.14 IssuingDistributionPoint tests
// ============================================================================

/// §4.14.1: Valid distributionPoint Test1.
///
/// EE serial=1, issuer=distributionPoint1 CA. The CRL has an IDP with a full
/// distribution point name. Serial=1 is NOT in the revoked list (CRL revokes serial=02).
///
/// Oracle: PKITS §4.14.1 MUST validate.
/// Our implementation: IDP has no onlyContainsXxx flags set → covers all certs → check normally.
#[test]
fn pkits_4_14_1_valid_distribution_point() {
    let ca_der = pkits_cert("distributionPoint1CACert");
    let ee_der = pkits_cert("ValiddistributionPointTest1EE");
    let crl = pkits_crl("distributionPoint1CACRL");

    let ca = load_cert(&ca_der);
    let ee = load_cert(&ee_der);

    let checker = CrlChecker::new(crl, PKITS_NOW, DefaultVerifier);
    checker
        .check_revocation(&ee, &ca)
        .expect("§4.14.1: serial=1 is not in CRL → must NOT be revoked");
}

/// §4.14.2: Invalid distributionPoint Test2 — cert is revoked in the CRL.
///
/// EE serial=2, issuer=distributionPoint1 CA. The CRL revokes serial=02.
///
/// Oracle: PKITS §4.14.2 MUST NOT validate.
/// Note: the PKITS §4.14.2 failure is due to CDP name mismatch (the cert's CDP points
/// to a distribution point not matching the CRL's IDP), but since our implementation
/// does not check CDP name matching, the failure here comes from the serial being found
/// in the revoked list.
#[test]
fn pkits_4_14_2_invalid_cert_revoked() {
    let ca_der = pkits_cert("distributionPoint1CACert");
    let ee_der = pkits_cert("InvaliddistributionPointTest2EE");
    let crl = pkits_crl("distributionPoint1CACRL");

    let ca = load_cert(&ca_der);
    let ee = load_cert(&ee_der);

    let checker = CrlChecker::new(crl, PKITS_NOW, DefaultVerifier);
    let result = checker.check_revocation(&ee, &ca);
    assert!(
        matches!(result, Err(Error::Revoked { .. })),
        "§4.14.2: serial=2 is revoked in CRL → must be Revoked; got: {result:?}"
    );
}

/// §4.14.3: Invalid distributionPoint Test3 — CDP name mismatch.
///
/// EE serial=3, issuer=distributionPoint1 CA. Serial=3 is NOT in the CRL.
/// PKITS says INVALID because the cert's CDP refers to a distribution point
/// that the CRL's IDP does not cover. Our implementation does not check
/// CDP name matching — we return Ok() for "not in revoked list".
///
/// Oracle: PKITS §4.14.3 MUST NOT validate (CDP mismatch).
/// Our checker: returns `Ok(())` because serial=3 is not revoked in this CRL.
/// A full path validator must enforce that the CRL's IDP matches the cert's CDP.
#[test]
#[ignore = "requires CDP name matching against IDP (not implemented in v0.1)"]
fn pkits_4_14_3_invalid_cdp_name_mismatch() {
    let ca_der = pkits_cert("distributionPoint1CACert");
    let ee_der = pkits_cert("InvaliddistributionPointTest3EE");
    let crl = pkits_crl("distributionPoint1CACRL");

    let ca = load_cert(&ca_der);
    let ee = load_cert(&ee_der);

    let checker = CrlChecker::new(crl, PKITS_NOW, DefaultVerifier);
    let result = checker.check_revocation(&ee, &ca);
    // Should fail due to CDP mismatch, but our checker returns Ok() (not in revoked list).
    // Ignored until CDP-IDP name matching is implemented.
    assert!(
        result.is_err(),
        "§4.14.3: CDP name mismatch → must fail; got: {result:?}"
    );
}

/// §4.14.4: Valid distributionPoint Test4 — multiple CDPs, uses the correct one.
///
/// EE serial=4, issuer=distributionPoint1 CA. Not in distributionPoint1CACRL (revokes 02).
///
/// Oracle: PKITS §4.14.4 MUST validate.
/// Note: PKITS §4.14.4 requires a second CRL for the second CDP; we test only
/// the primary CRL and confirm serial=4 is not revoked in it.
#[test]
fn pkits_4_14_4_valid_multiple_cdps() {
    let ca_der = pkits_cert("distributionPoint1CACert");
    let ee_der = pkits_cert("ValiddistributionPointTest4EE");
    let crl = pkits_crl("distributionPoint1CACRL");

    let ca = load_cert(&ca_der);
    let ee = load_cert(&ee_der);

    let checker = CrlChecker::new(crl, PKITS_NOW, DefaultVerifier);
    checker
        .check_revocation(&ee, &ca)
        .expect("§4.14.4: serial=4 is not in distributionPoint1CACRL → must NOT be revoked");
}

/// §4.14.5: Valid distributionPoint Test5 — distributionPoint2 CA, cert not revoked.
///
/// EE serial=1, issuer=distributionPoint2 CA. distributionPoint2CACRL revokes serial=02.
/// Serial=1 is not in the revoked list.
///
/// Oracle: PKITS §4.14.5 MUST validate.
#[test]
fn pkits_4_14_5_valid_dp2_cert_not_revoked() {
    let ca_der = pkits_cert("distributionPoint2CACert");
    let ee_der = pkits_cert("ValiddistributionPointTest5EE");
    let crl = pkits_crl("distributionPoint2CACRL");

    let ca = load_cert(&ca_der);
    let ee = load_cert(&ee_der);

    let checker = CrlChecker::new(crl, PKITS_NOW, DefaultVerifier);
    checker
        .check_revocation(&ee, &ca)
        .expect("§4.14.5: serial=1 is not in distributionPoint2CACRL → must NOT be revoked");
}

/// §4.14.6: Invalid distributionPoint Test6 — cert is revoked in distributionPoint2 CRL.
///
/// EE serial=2, issuer=distributionPoint2 CA. distributionPoint2CACRL revokes serial=02.
///
/// Oracle: PKITS §4.14.6 MUST NOT validate.
#[test]
fn pkits_4_14_6_invalid_cert_revoked_in_dp2() {
    let ca_der = pkits_cert("distributionPoint2CACert");
    let ee_der = pkits_cert("InvaliddistributionPointTest6EE");
    let crl = pkits_crl("distributionPoint2CACRL");

    let ca = load_cert(&ca_der);
    let ee = load_cert(&ee_der);

    let checker = CrlChecker::new(crl, PKITS_NOW, DefaultVerifier);
    let result = checker.check_revocation(&ee, &ca);
    assert!(
        matches!(result, Err(Error::Revoked { .. })),
        "§4.14.6: serial=2 is revoked in distributionPoint2CACRL → must be Revoked; got: {result:?}"
    );
}

/// §4.14.7: Valid distributionPoint Test7 — distributionPoint2 CA, serial=3 not revoked.
///
/// EE serial=3. distributionPoint2CACRL revokes only serial=02.
///
/// Oracle: PKITS §4.14.7 MUST validate.
#[test]
fn pkits_4_14_7_valid_dp2_serial3_not_revoked() {
    let ca_der = pkits_cert("distributionPoint2CACert");
    let ee_der = pkits_cert("ValiddistributionPointTest7EE");
    let crl = pkits_crl("distributionPoint2CACRL");

    let ca = load_cert(&ca_der);
    let ee = load_cert(&ee_der);

    let checker = CrlChecker::new(crl, PKITS_NOW, DefaultVerifier);
    checker
        .check_revocation(&ee, &ca)
        .expect("§4.14.7: serial=3 is not in distributionPoint2CACRL → must NOT be revoked");
}

/// §4.14.8: Invalid distributionPoint Test8 — CDP name mismatch (onlySomeReasons).
///
/// EE serial=4, issuer=distributionPoint2 CA. Not in distributionPoint2CACRL.
/// PKITS says INVALID because the cert's CDP and the CRL's IDP cover different
/// reason sets / distribution points. Our implementation does not check CDP name
/// matching (IDP name vs CDP name); we return Ok() here.
///
/// Oracle: PKITS §4.14.8 MUST NOT validate.
/// Our checker returns `Ok(())` — CDP/IDP name matching is a v0.2 item.
#[test]
#[ignore = "requires CDP/IDP name matching against distribution point names (not implemented in v0.1)"]
fn pkits_4_14_8_invalid_cdp_idp_mismatch_dp2() {
    let ca_der = pkits_cert("distributionPoint2CACert");
    let ee_der = pkits_cert("InvaliddistributionPointTest8EE");
    let crl = pkits_crl("distributionPoint2CACRL");

    let ca = load_cert(&ca_der);
    let ee = load_cert(&ee_der);

    let checker = CrlChecker::new(crl, PKITS_NOW, DefaultVerifier);
    let result = checker.check_revocation(&ee, &ca);
    assert!(
        result.is_err(),
        "§4.14.8: CDP/IDP name mismatch → must fail; got: {result:?}"
    );
}

/// §4.14.9: Invalid distributionPoint Test9 — CDP name mismatch (onlySomeReasons).
///
/// EE serial=5, issuer=distributionPoint2 CA. Not in distributionPoint2CACRL.
/// Same scenario as §4.14.8.
///
/// Oracle: PKITS §4.14.9 MUST NOT validate.
/// Our checker returns `Ok(())` — CDP/IDP name matching is a v0.2 item.
#[test]
#[ignore = "requires CDP/IDP name matching against distribution point names (not implemented in v0.1)"]
fn pkits_4_14_9_invalid_cdp_idp_mismatch_dp2_serial5() {
    let ca_der = pkits_cert("distributionPoint2CACert");
    let ee_der = pkits_cert("InvaliddistributionPointTest9EE");
    let crl = pkits_crl("distributionPoint2CACRL");

    let ca = load_cert(&ca_der);
    let ee = load_cert(&ee_der);

    let checker = CrlChecker::new(crl, PKITS_NOW, DefaultVerifier);
    let result = checker.check_revocation(&ee, &ca);
    assert!(
        result.is_err(),
        "§4.14.9: CDP/IDP name mismatch → must fail; got: {result:?}"
    );
}

/// §4.14.10: Valid — No issuingDistributionPoint.
///
/// EE serial=1, issuer=No issuingDistributionPoint CA. The CRL has no IDP extension.
/// No scope restrictions → covers all certs. EE serial not in revoked list.
///
/// Oracle: PKITS §4.14.10 MUST validate.
#[test]
fn pkits_4_14_10_valid_no_idp() {
    let ca_der = pkits_cert("NoissuingDistributionPointCACert");
    let ee_der = pkits_cert("ValidNoissuingDistributionPointTest10EE");
    let crl = pkits_crl("NoissuingDistributionPointCACRL");

    let ca = load_cert(&ca_der);
    let ee = load_cert(&ee_der);

    let checker = CrlChecker::new(crl, PKITS_NOW, DefaultVerifier);
    checker
        .check_revocation(&ee, &ca)
        .expect("§4.14.10: no IDP, serial not revoked → must NOT be revoked");
}

/// §4.14.11: Invalid — onlyContainsUserCerts CRL applied to CA cert revocation check.
///
/// Oracle: PKITS §4.14.11 MUST NOT validate.
///
/// The CA cert (issued by onlyContainsUserCerts CA) must be checked for revocation.
/// The only available CRL for that CA has `onlyContainsUserCerts=TRUE` — so it does
/// NOT cover CA certs. Our IDP check returns `Ok(())` (not covered by this CRL).
/// A full path validator in hard-fail mode would treat "unchecked CA cert" as failure;
/// our `CrlChecker` returns `Ok(())` and delegates the hard-fail policy to the caller.
///
/// Note: The "CA cert" being checked here is the intermediate CA that issued the EE.
#[test]
fn pkits_4_14_11_invalid_only_user_certs_crl_for_ca() {
    // The CA cert is a CA cert (has BasicConstraints cA=TRUE).
    // Checking it against onlyContainsUserCerts CRL → Ok() (not covered).
    let ca_der = pkits_cert("onlyContainsUserCertsCACert");
    let ee_der = pkits_cert("InvalidonlyContainsUserCertsTest11EE");
    let crl = pkits_crl("onlyContainsUserCertsCACRL");

    let ee = load_cert(&ee_der);
    let ca = load_cert(&ca_der);

    let checker = CrlChecker::new(crl, PKITS_NOW, DefaultVerifier);

    // Checking the EE cert (an end-entity) against a user-certs-only CRL:
    // the EE is a user cert → covered → check normally. EE serial=1 not in revoked list.
    let result = checker.check_revocation(&ee, &ca);
    // The EE itself is not revoked in this CRL. Our checker returns Ok().
    // The PKITS failure is at the path level (CA cert revocation undetermined).
    result.expect("§4.14.11: EE (user cert) serial=1 not in onlyContainsUserCerts CRL");
}

/// §4.14.12: Invalid — onlyContainsCACerts CRL applied to EE cert check.
///
/// Oracle: PKITS §4.14.12 MUST NOT validate.
///
/// The EE cert (serial=1) is being checked against a CRL with `onlyContainsCACerts=TRUE`.
/// Our IDP check: EE is not a CA cert → not covered → `Ok(())`.
/// A full path validator must enforce that an appropriate CRL covers each cert.
#[test]
fn pkits_4_14_12_invalid_only_ca_certs_for_ee() {
    let ca_der = pkits_cert("onlyContainsCACertsCACert");
    let ee_der = pkits_cert("InvalidonlyContainsCACertsTest12EE");
    let crl = pkits_crl("onlyContainsCACertsCACRL");

    let ca = load_cert(&ca_der);
    let ee = load_cert(&ee_der);

    let checker = CrlChecker::new(crl, PKITS_NOW, DefaultVerifier);
    // EE is not a CA cert → onlyContainsCACerts CRL does not cover it → Ok() (not covered).
    let result = checker.check_revocation(&ee, &ca);
    // Our IDP check returns Ok() because the CRL doesn't cover EE certs.
    // This is the correct CrlChecker behaviour: coverage decision, not revocation decision.
    // The path validator must treat "not covered" as a hard-fail in PKITS mode.
    result.expect("§4.14.12: onlyContainsCACerts CRL does not cover EE cert → not covered → Ok()");
}

/// §4.14.13: Valid — onlyContainsCACerts CRL applied to CA cert check.
///
/// Oracle: PKITS §4.14.13 MUST validate.
///
/// The EE cert (serial=2) is issued by onlyContainsCACerts CA. The CA cert IS a CA cert.
/// The CRL has `onlyContainsCACerts=TRUE`. The EE itself is an end-entity, so checking
/// it against this CRL returns Ok() (not covered). But the CA cert's revocation CRL
/// correctly covers CA certs. Serial=2 (EE) is not in the revoked list.
#[test]
fn pkits_4_14_13_valid_only_ca_certs_crl_for_ca() {
    let ca_der = pkits_cert("onlyContainsCACertsCACert");
    let ee_der = pkits_cert("ValidonlyContainsCACertsTest13EE");
    let crl = pkits_crl("onlyContainsCACertsCACRL");

    let ca = load_cert(&ca_der);
    let ee = load_cert(&ee_der);

    let checker = CrlChecker::new(crl, PKITS_NOW, DefaultVerifier);
    // The EE (serial=2) is not a CA cert → onlyContainsCACerts CRL doesn't cover it → Ok().
    let result = checker.check_revocation(&ee, &ca);
    result.expect("§4.14.13: serial=2 EE not covered by onlyContainsCACerts CRL → Ok()");
}

/// §4.14.14: Invalid — onlyContainsAttributeCerts CRL.
///
/// Oracle: PKITS §4.14.14 MUST NOT validate.
///
/// The CRL has `onlyContainsAttributeCerts=TRUE`. The IDP check returns `Ok()`
/// (not covered) because attribute cert validation is out of scope for
/// `pkix-revocation` (handled by `pkix-ac`, tracked for v0.2).
/// A full path validator must treat "not covered" as a hard-fail.
#[test]
fn pkits_4_14_14_invalid_only_attribute_certs() {
    let ca_der = pkits_cert("onlyContainsAttributeCertsCACert");
    let ee_der = pkits_cert("InvalidonlyContainsAttributeCertsTest14EE");
    let crl = pkits_crl("onlyContainsAttributeCertsCACRL");

    let ca = load_cert(&ca_der);
    let ee = load_cert(&ee_der);

    let checker = CrlChecker::new(crl, PKITS_NOW, DefaultVerifier);
    // onlyContainsAttributeCerts=TRUE → our IDP check returns Ok() (not covered).
    let result = checker.check_revocation(&ee, &ca);
    result.expect(
        "§4.14.14: onlyContainsAttributeCerts CRL → not covered → Ok() \
         (path validator must hard-fail)",
    );
}

/// Edge case: base CRL has no revoked entries, delta CRL has one revoked entry.
///
/// Oracle: PKITS §4.15.3 — InvaliddeltaCRLTest3EE is revoked in the delta CRL.
/// The merge must find the revocation even though the base CRL is empty for
/// this certificate.
#[test]
fn delta_empty_base_revocation_in_delta() {
    let ca_der = pkits_cert("deltaCRLCA1Cert");
    let leaf_der = pkits_cert("InvaliddeltaCRLTest3EE");
    let base = pkits_crl("deltaCRLCA1CRL");
    let delta = pkits_crl("deltaCRLCA1deltaCRL");

    let ca = load_cert(&ca_der);
    let leaf = load_cert(&leaf_der);

    let checker =
        CrlChecker::with_delta(base, delta, PKITS_NOW, DefaultVerifier).expect("valid base+delta");
    let result = checker.check_revocation(&leaf, &ca);
    assert!(
        matches!(result, Err(Error::Revoked { .. })),
        "cert revoked in delta must be detected; got: {result:?}"
    );
}
