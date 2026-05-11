//! PKITS §4.1 Signature Verification and §4.2 Validity Period tests.
//!
//! All cert names and expected outcomes come from the PKITS vectors.json.
//! Oracle: NIST PKITS (SP 800-89) document §4.1 and §4.2.

#[path = "pkits_helper.rs"]
mod pkits_helper;

use pkits_helper::{pkits_validate, PKITS_NOW};

// ---------------------------------------------------------------------------
// §4.1 Signature Verification
// ---------------------------------------------------------------------------

/// §4.1.1 Valid Signatures Test1 — basic 2-cert chain (EE + CA).
/// Oracle: PKITS §4.1.1 MUST validate.
#[test]
fn pkits_4_1_1_valid_signatures() {
    let result = pkits_validate(&["ValidCertificatePathTest1EE", "GoodCACert"], PKITS_NOW);
    let vp = result.expect("§4.1.1 must validate");
    assert_eq!(vp.depth, 1);
}

/// §4.1.2 Invalid CA Signature Test2 — CA cert signed with wrong key.
/// Oracle: PKITS §4.1.2 MUST NOT validate.
#[test]
fn pkits_4_1_2_invalid_ca_signature() {
    let result = pkits_validate(&["InvalidCASignatureTest2EE", "BadSignedCACert"], PKITS_NOW);
    assert!(
        matches!(result, Err(pkix_path::Error::SignatureInvalid { .. })),
        "invalid CA signature must return SignatureInvalid, got: {result:?}"
    );
}

/// §4.1.3 Invalid EE Signature Test3 — end-entity cert has invalid signature.
/// Oracle: PKITS §4.1.3 MUST NOT validate.
#[test]
fn pkits_4_1_3_invalid_ee_signature() {
    let result = pkits_validate(&["InvalidEESignatureTest3EE", "GoodCACert"], PKITS_NOW);
    assert!(
        matches!(result, Err(pkix_path::Error::SignatureInvalid { .. })),
        "invalid EE signature must return SignatureInvalid, got: {result:?}"
    );
}

/// §4.1.4 Valid DSA Signatures Test4 — DSA not currently supported.
/// Oracle: PKITS §4.1.4 MUST validate (requires DSA backend).
#[test]
#[ignore = "DSA signature algorithm not currently supported"]
fn pkits_4_1_4_valid_dsa_signatures() {
    let result = pkits_validate(&["ValidDSASignaturesTest4EE", "DSACACert"], PKITS_NOW);
    result.expect("§4.1.4 must validate");
}

/// §4.1.5 Valid DSA Parameter Inheritance Test5 — DSA not currently supported.
#[test]
#[ignore = "DSA signature algorithm not currently supported"]
fn pkits_4_1_5_valid_dsa_parameter_inheritance() {
    let result = pkits_validate(
        &[
            "ValidDSAParameterInheritanceTest5EE",
            "DSAParametersInheritedCACert",
            "DSACACert",
        ],
        PKITS_NOW,
    );
    result.expect("§4.1.5 must validate");
}

/// §4.1.6 Invalid DSA Signature Test6 — DSA not currently supported.
#[test]
#[ignore = "DSA signature algorithm not currently supported"]
fn pkits_4_1_6_invalid_dsa_signature() {
    let result = pkits_validate(&["InvalidDSASignatureTest6EE", "DSACACert"], PKITS_NOW);
    assert!(result.is_err(), "§4.1.6 must not validate");
}

// ---------------------------------------------------------------------------
// §4.2 Validity Period
//
// PKITS cert validity windows:
//   Most certs: notBefore=2010-01-01, notAfter=2030-12-31
//   BadnotBeforeDateCACert: notBefore=2047-01-01 (future)
//   InvalidEEnotBeforeDateTest2EE: notBefore=2047-01-01 (future)
//   BadnotAfterDateCACert: notAfter=2011-01-01 (expired at PKITS_NOW=2020)
//   InvalidEEnotAfterDateTest6EE: notAfter=2011-01-01 (expired)
//   Validpre2000UTCnotBeforeDateTest3EE: notBefore=1950-01-01 (past)
//   Invalidpre2000UTCEEnotAfterDateTest7EE: notAfter=1999-01-01 (expired)
//   ValidGeneralizedTimenotAfterDateTest8EE: notAfter=2050-01-01
// ---------------------------------------------------------------------------

/// §4.2.1 Invalid CA notBefore Date Test1 — CA not yet valid at `PKITS_NOW` (2020).
/// Oracle: PKITS §4.2.1 MUST NOT validate.
#[test]
fn pkits_4_2_1_invalid_ca_notbefore() {
    let result = pkits_validate(
        &["InvalidCAnotBeforeDateTest1EE", "BadnotBeforeDateCACert"],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::ValidityPeriod { .. })),
        "not-yet-valid CA must return ValidityPeriod, got: {result:?}"
    );
}

/// §4.2.2 Invalid EE notBefore Date Test2 — EE not yet valid at `PKITS_NOW` (2020).
/// Oracle: PKITS §4.2.2 MUST NOT validate.
#[test]
fn pkits_4_2_2_invalid_ee_notbefore() {
    let result = pkits_validate(&["InvalidEEnotBeforeDateTest2EE", "GoodCACert"], PKITS_NOW);
    assert!(
        matches!(result, Err(pkix_path::Error::ValidityPeriod { .. })),
        "not-yet-valid EE must return ValidityPeriod, got: {result:?}"
    );
}

/// §4.2.3 Valid pre-2000 UTC notBefore Date Test3.
/// The cert has notBefore=1950-01-01 (pre-Unix-epoch `UTCTime`).
/// The `der` crate cannot parse pre-1970 `UTCTime` values.
#[test]
#[ignore = "pre-1970 UTCTime (1950-01-01) cannot be parsed by der crate"]
fn pkits_4_2_3_valid_pre2000_utc_notbefore() {
    let result = pkits_validate(
        &["Validpre2000UTCnotBeforeDateTest3EE", "GoodCACert"],
        PKITS_NOW,
    );
    result.expect("§4.2.3 must validate");
}

/// §4.2.4 Valid `GeneralizedTime` notBefore Date Test4.
/// Oracle: PKITS §4.2.4 MUST validate.
#[test]
fn pkits_4_2_4_valid_generalizedtime_notbefore() {
    let result = pkits_validate(
        &["ValidGeneralizedTimenotBeforeDateTest4EE", "GoodCACert"],
        PKITS_NOW,
    );
    result.expect("§4.2.4 must validate");
}

/// §4.2.5 Invalid CA notAfter Date Test5 — CA expired at `PKITS_NOW` (2020).
/// Oracle: PKITS §4.2.5 MUST NOT validate (BadnotAfterDateCACert.notAfter=2011).
#[test]
fn pkits_4_2_5_invalid_ca_notafter() {
    let result = pkits_validate(
        &["InvalidCAnotAfterDateTest5EE", "BadnotAfterDateCACert"],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::ValidityPeriod { .. })),
        "expired CA must return ValidityPeriod, got: {result:?}"
    );
}

/// §4.2.6 Invalid EE notAfter Date Test6 — EE expired at `PKITS_NOW` (2020).
/// Oracle: PKITS §4.2.6 MUST NOT validate (EE.notAfter=2011).
#[test]
fn pkits_4_2_6_invalid_ee_notafter() {
    let result = pkits_validate(&["InvalidEEnotAfterDateTest6EE", "GoodCACert"], PKITS_NOW);
    assert!(
        matches!(result, Err(pkix_path::Error::ValidityPeriod { .. })),
        "expired EE must return ValidityPeriod, got: {result:?}"
    );
}

/// §4.2.7 Invalid pre-2000 UTC EE notAfter Date Test7.
/// Oracle: PKITS §4.2.7 MUST NOT validate (`UTCTime` notAfter=1999 → expired).
#[test]
fn pkits_4_2_7_invalid_pre2000_utc_ee_notafter() {
    let result = pkits_validate(
        &["Invalidpre2000UTCEEnotAfterDateTest7EE", "GoodCACert"],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::ValidityPeriod { .. })),
        "pre-2000 UTC expired EE must return ValidityPeriod, got: {result:?}"
    );
}

/// §4.2.8 Valid `GeneralizedTime` notAfter Date Test8.
/// Oracle: PKITS §4.2.8 MUST validate (notAfter=2050 > `PKITS_NOW=2020`).
#[test]
fn pkits_4_2_8_valid_generalizedtime_notafter() {
    let result = pkits_validate(
        &["ValidGeneralizedTimenotAfterDateTest8EE", "GoodCACert"],
        PKITS_NOW,
    );
    result.expect("§4.2.8 must validate");
}
