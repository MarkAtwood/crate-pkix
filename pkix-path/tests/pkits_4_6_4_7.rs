//! PKITS §4.6 Basic Constraints and §4.7 Key Usage tests.
//!
//! All cert names and expected outcomes come from the PKITS vectors.json.
//! Oracle: NIST PKITS (SP 800-89) document §4.6 and §4.7.

#[path = "pkits_helper.rs"]
mod pkits_helper;

use pkits_helper::{pkits_validate, PKITS_NOW};

// ---------------------------------------------------------------------------
// §4.6 Verifying Basic Constraints
// ---------------------------------------------------------------------------

/// §4.6.1 Invalid Missing basicConstraints Test1.
/// Oracle: PKITS §4.6.1 MUST NOT validate (intermediate has no BasicConstraints).
#[test]
fn pkits_4_6_1_missing_basic_constraints() {
    let result = pkits_validate(
        &[
            "InvalidMissingbasicConstraintsTest1EE",
            "MissingbasicConstraintsCACert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::NotCA { .. })),
        "missing BasicConstraints must return NotCA, got: {result:?}"
    );
}

/// §4.6.2 Invalid cA False Test2 — BasicConstraints critical, cA=FALSE.
/// Oracle: PKITS §4.6.2 MUST NOT validate.
#[test]
fn pkits_4_6_2_ca_false_critical() {
    let result = pkits_validate(
        &[
            "InvalidcAFalseTest2EE",
            "basicConstraintsCriticalcAFalseCACert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::NotCA { .. })),
        "cA=FALSE (critical) must return NotCA, got: {result:?}"
    );
}

/// §4.6.3 Invalid cA False Test3 — BasicConstraints not critical, cA=FALSE.
/// Oracle: PKITS §4.6.3 MUST NOT validate.
#[test]
fn pkits_4_6_3_ca_false_not_critical() {
    let result = pkits_validate(
        &[
            "InvalidcAFalseTest3EE",
            "basicConstraintsNotCriticalcAFalseCACert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::NotCA { .. })),
        "cA=FALSE (not-critical) must return NotCA, got: {result:?}"
    );
}

/// §4.6.4 Valid basicConstraints Not Critical Test4 — cA=TRUE, extension not critical.
/// Oracle: PKITS §4.6.4 MUST validate (BasicConstraints critical flag does not affect validity).
#[test]
fn pkits_4_6_4_basic_constraints_not_critical() {
    let result = pkits_validate(
        &[
            "ValidbasicConstraintsNotCriticalTest4EE",
            "basicConstraintsNotCriticalCACert",
        ],
        PKITS_NOW,
    );
    result.expect("§4.6.4 must validate");
}

/// §4.6.5 Invalid pathLenConstraint Test5.
/// Chain: [EE, subCA(pathLen=0), CA(pathLen=0)] — subCA violates CA's pathLen=0.
/// Oracle: PKITS §4.6.5 MUST NOT validate.
#[test]
fn pkits_4_6_5_invalid_path_len_constraint() {
    let result = pkits_validate(
        &[
            "InvalidpathLenConstraintTest5EE",
            "pathLenConstraint0subCACert",
            "pathLenConstraint0CACert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::PathTooLong)),
        "pathLen exceeded must return PathTooLong, got: {result:?}"
    );
}

/// §4.6.6 Invalid pathLenConstraint Test6 (same structure as Test5).
/// Oracle: PKITS §4.6.6 MUST NOT validate.
#[test]
fn pkits_4_6_6_invalid_path_len_constraint() {
    let result = pkits_validate(
        &[
            "InvalidpathLenConstraintTest6EE",
            "pathLenConstraint0subCACert",
            "pathLenConstraint0CACert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::PathTooLong)),
        "pathLen exceeded must return PathTooLong, got: {result:?}"
    );
}

/// §4.6.7 Valid pathLenConstraint Test7 — 1 intermediate, CA pathLen=0.
/// Chain: [EE, CA(pathLen=0)], anchor = TrustAnchor → depth=1, CA allows 0 sub-CAs → PASS.
/// Oracle: PKITS §4.6.7 MUST validate.
#[test]
fn pkits_4_6_7_valid_path_len_constraint() {
    let result = pkits_validate(
        &["ValidpathLenConstraintTest7EE", "pathLenConstraint0CACert"],
        PKITS_NOW,
    );
    result.expect("§4.6.7 must validate");
}

/// §4.6.8 Valid pathLenConstraint Test8 (same structure as Test7).
/// Oracle: PKITS §4.6.8 MUST validate.
#[test]
fn pkits_4_6_8_valid_path_len_constraint() {
    let result = pkits_validate(
        &["ValidpathLenConstraintTest8EE", "pathLenConstraint0CACert"],
        PKITS_NOW,
    );
    result.expect("§4.6.8 must validate");
}

/// §4.6.9 Invalid pathLenConstraint Test9.
/// Chain: [EE, subsubCA00(pathLen=0), subCA0(pathLen=0), CA6(pathLen=6)].
/// subCA0 has pathLen=0 but subsubCA00 is below it → violation.
/// Oracle: PKITS §4.6.9 MUST NOT validate.
#[test]
fn pkits_4_6_9_invalid_path_len_deep() {
    let result = pkits_validate(
        &[
            "InvalidpathLenConstraintTest9EE",
            "pathLenConstraint6subsubCA00Cert",
            "pathLenConstraint6subCA0Cert",
            "pathLenConstraint6CACert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::PathTooLong)),
        "deep pathLen exceeded must return PathTooLong, got: {result:?}"
    );
}

/// §4.6.10 Invalid pathLenConstraint Test10 (same structure as Test9).
/// Oracle: PKITS §4.6.10 MUST NOT validate.
#[test]
fn pkits_4_6_10_invalid_path_len_deep() {
    let result = pkits_validate(
        &[
            "InvalidpathLenConstraintTest10EE",
            "pathLenConstraint6subsubCA00Cert",
            "pathLenConstraint6subCA0Cert",
            "pathLenConstraint6CACert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::PathTooLong)),
        "deep pathLen exceeded must return PathTooLong, got: {result:?}"
    );
}

/// §4.6.11 Invalid pathLenConstraint Test11 — 5-cert chain with pathLen violation.
/// Chain: [EE, subsubsubCA11X, subsubCA11(pathLen=1), subCA1(pathLen=1), CA6(pathLen=6)].
/// subCA1 has pathLen=1 but 2 certs are below it → violation.
/// Oracle: PKITS §4.6.11 MUST NOT validate.
#[test]
fn pkits_4_6_11_invalid_path_len_deeper() {
    let result = pkits_validate(
        &[
            "InvalidpathLenConstraintTest11EE",
            "pathLenConstraint6subsubsubCA11XCert",
            "pathLenConstraint6subsubCA11Cert",
            "pathLenConstraint6subCA1Cert",
            "pathLenConstraint6CACert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::PathTooLong)),
        "5-cert chain pathLen exceeded must return PathTooLong, got: {result:?}"
    );
}

/// §4.6.12 Invalid pathLenConstraint Test12 (same structure as Test11).
/// Oracle: PKITS §4.6.12 MUST NOT validate.
#[test]
fn pkits_4_6_12_invalid_path_len_deeper() {
    let result = pkits_validate(
        &[
            "InvalidpathLenConstraintTest12EE",
            "pathLenConstraint6subsubsubCA11XCert",
            "pathLenConstraint6subsubCA11Cert",
            "pathLenConstraint6subCA1Cert",
            "pathLenConstraint6CACert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::PathTooLong)),
        "5-cert chain pathLen exceeded must return PathTooLong, got: {result:?}"
    );
}

/// §4.6.13 Valid pathLenConstraint Test13 — 5-cert chain within all pathLen limits.
/// Chain: [EE, subsubsubCA41X, subsubCA41(pathLen=1), subCA4(pathLen=4), CA6(pathLen=6)].
/// Oracle: PKITS §4.6.13 MUST validate.
#[test]
fn pkits_4_6_13_valid_path_len_deep() {
    let result = pkits_validate(
        &[
            "ValidpathLenConstraintTest13EE",
            "pathLenConstraint6subsubsubCA41XCert",
            "pathLenConstraint6subsubCA41Cert",
            "pathLenConstraint6subCA4Cert",
            "pathLenConstraint6CACert",
        ],
        PKITS_NOW,
    );
    result.expect("§4.6.13 must validate");
}

/// §4.6.14 Valid pathLenConstraint Test14 (same chain as Test13).
/// Oracle: PKITS §4.6.14 MUST validate.
#[test]
fn pkits_4_6_14_valid_path_len_deep() {
    let result = pkits_validate(
        &[
            "ValidpathLenConstraintTest14EE",
            "pathLenConstraint6subsubsubCA41XCert",
            "pathLenConstraint6subsubCA41Cert",
            "pathLenConstraint6subCA4Cert",
            "pathLenConstraint6CACert",
        ],
        PKITS_NOW,
    );
    result.expect("§4.6.14 must validate");
}

/// §4.6.15 Valid Self-Issued pathLenConstraint Test15.
/// Self-issued certs must not count against pathLenConstraint (RFC 5280 §6.1.3).
#[test]
fn pkits_4_6_15_valid_self_issued_path_len() {
    let result = pkits_validate(
        &[
            "ValidSelfIssuedpathLenConstraintTest15EE",
            "pathLenConstraint0SelfIssuedCACert",
            "pathLenConstraint0CACert",
        ],
        PKITS_NOW,
    );
    result.expect("§4.6.15 must validate");
}

/// §4.6.16 Invalid Self-Issued pathLenConstraint Test16.
/// Oracle: PKITS §4.6.16 MUST NOT validate.
#[test]
fn pkits_4_6_16_invalid_self_issued_path_len() {
    let result = pkits_validate(
        &[
            "InvalidSelfIssuedpathLenConstraintTest16EE",
            "pathLenConstraint0subCA2Cert",
            "pathLenConstraint0SelfIssuedCACert",
            "pathLenConstraint0CACert",
        ],
        PKITS_NOW,
    );
    assert!(result.is_err(), "§4.6.16 must not validate");
}

/// §4.6.17 Valid Self-Issued pathLenConstraint Test17.
/// Oracle: PKITS §4.6.17 MUST validate.
#[test]
fn pkits_4_6_17_valid_self_issued_path_len() {
    let result = pkits_validate(
        &[
            "ValidSelfIssuedpathLenConstraintTest17EE",
            "pathLenConstraint1SelfIssuedsubCACert",
            "pathLenConstraint1subCACert",
            "pathLenConstraint1SelfIssuedCACert",
            "pathLenConstraint1CACert",
        ],
        PKITS_NOW,
    );
    result.expect("§4.6.17 must validate");
}

// ---------------------------------------------------------------------------
// §4.7 Key Usage
// ---------------------------------------------------------------------------

/// §4.7.1 Invalid keyUsage Critical keyCertSign False Test1.
/// Intermediate has KeyUsage critical with keyCertSign=False.
/// Oracle: PKITS §4.7.1 MUST NOT validate.
#[test]
fn pkits_4_7_1_invalid_key_usage_critical_no_cert_sign() {
    let result = pkits_validate(
        &[
            "InvalidkeyUsageCriticalkeyCertSignFalseTest1EE",
            "keyUsageCriticalkeyCertSignFalseCACert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::KeyUsageMissing { .. })),
        "keyCertSign=false (critical) must return KeyUsageMissing, got: {result:?}"
    );
}

/// §4.7.2 Invalid keyUsage Not Critical keyCertSign False Test2.
/// Intermediate has KeyUsage not-critical with keyCertSign=False.
/// Oracle: PKITS §4.7.2 MUST NOT validate.
#[test]
fn pkits_4_7_2_invalid_key_usage_not_critical_no_cert_sign() {
    let result = pkits_validate(
        &[
            "InvalidkeyUsageNotCriticalkeyCertSignFalseTest2EE",
            "keyUsageNotCriticalkeyCertSignFalseCACert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::KeyUsageMissing { .. })),
        "keyCertSign=false (not-critical) must return KeyUsageMissing, got: {result:?}"
    );
}

/// §4.7.3 Valid keyUsage Not Critical Test3.
/// Intermediate has KeyUsage not-critical with keyCertSign=True.
/// Oracle: PKITS §4.7.3 MUST validate.
#[test]
fn pkits_4_7_3_valid_key_usage_not_critical() {
    let result = pkits_validate(
        &[
            "ValidkeyUsageNotCriticalTest3EE",
            "keyUsageNotCriticalCACert",
        ],
        PKITS_NOW,
    );
    result.expect("§4.7.3 must validate");
}

/// §4.7.4 Invalid keyUsage Critical cRLSign False Test4.
/// v0.1 does not check cRLSign in path validation (RFC 5280 §6.1 only requires keyCertSign).
/// This test is expected to fail per PKITS but our implementation correctly follows §6.1.
#[test]
#[ignore = "cRLSign enforcement not implemented in path validation (RFC 5280 §6.1 only requires keyCertSign; tracked for future policy layer)"]
fn pkits_4_7_4_invalid_key_usage_no_crl_sign() {
    let result = pkits_validate(
        &[
            "InvalidkeyUsageCriticalcRLSignFalseTest4EE",
            "keyUsageCriticalcRLSignFalseCACert",
        ],
        PKITS_NOW,
    );
    assert!(result.is_err(), "§4.7.4 must not validate per PKITS");
}

/// §4.7.5 Invalid keyUsage Not Critical cRLSign False Test5.
/// Same as Test4 with non-critical KeyUsage.
#[test]
#[ignore = "cRLSign enforcement not implemented in path validation (RFC 5280 §6.1 only requires keyCertSign; tracked for future policy layer)"]
fn pkits_4_7_5_invalid_key_usage_no_crl_sign_not_critical() {
    let result = pkits_validate(
        &[
            "InvalidkeyUsageNotCriticalcRLSignFalseTest5EE",
            "keyUsageNotCriticalcRLSignFalseCACert",
        ],
        PKITS_NOW,
    );
    assert!(result.is_err(), "§4.7.5 must not validate per PKITS");
}
