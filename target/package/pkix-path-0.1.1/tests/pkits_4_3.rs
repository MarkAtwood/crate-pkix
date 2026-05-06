//! PKITS §4.3 Verifying Data Signed by a CA — name chaining tests.
//!
//! These tests verify the DN name matching (issuer/subject linkage) including
//! string normalization (whitespace, capitalization, encoding variants).
//!
//! Oracle: NIST PKITS (SP 800-89) document §4.3.

#[path = "pkits_helper.rs"]
mod pkits_helper;

use pkits_helper::{pkits_validate, PKITS_NOW};

/// §4.3.1 Invalid Name Chaining EE Test1 — EE issuer does not match CA subject.
/// Oracle: PKITS §4.3.1 MUST NOT validate.
#[test]
fn pkits_4_3_1_invalid_name_chaining() {
    let result = pkits_validate(&["InvalidNameChainingTest1EE", "GoodCACert"], PKITS_NOW);
    assert!(
        matches!(result, Err(pkix_path::Error::ChainBroken { .. })),
        "mismatched issuer/subject must return ChainBroken, got: {result:?}"
    );
}

/// §4.3.2 Invalid Name Chaining Order Test2 — RDN ordering mismatch.
/// Oracle: PKITS §4.3.2 MUST NOT validate.
#[test]
fn pkits_4_3_2_invalid_name_chaining_order() {
    let result = pkits_validate(
        &["InvalidNameChainingOrderTest2EE", "NameOrderingCACert"],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::ChainBroken { .. })),
        "wrong RDN order must return ChainBroken, got: {result:?}"
    );
}

/// §4.3.3 Valid Name Chaining Whitespace Test3 — leading/trailing whitespace in CN.
/// Oracle: PKITS §4.3.3 MUST validate (RFC 4518 normalizes whitespace).
#[test]
fn pkits_4_3_3_valid_name_chaining_whitespace() {
    let result = pkits_validate(
        &["ValidNameChainingWhitespaceTest3EE", "GoodCACert"],
        PKITS_NOW,
    );
    result.expect("§4.3.3 must validate (whitespace-normalized names)");
}

/// §4.3.4 Valid Name Chaining Whitespace Test4 — internal whitespace normalization.
/// Oracle: PKITS §4.3.4 MUST validate.
#[test]
fn pkits_4_3_4_valid_name_chaining_whitespace() {
    let result = pkits_validate(
        &["ValidNameChainingWhitespaceTest4EE", "GoodCACert"],
        PKITS_NOW,
    );
    result.expect("§4.3.4 must validate (internal whitespace normalized)");
}

/// §4.3.5 Valid Name Chaining Capitalization Test5 — case-insensitive DN matching.
/// Oracle: PKITS §4.3.5 MUST validate.
#[test]
fn pkits_4_3_5_valid_name_chaining_capitalization() {
    let result = pkits_validate(
        &["ValidNameChainingCapitalizationTest5EE", "GoodCACert"],
        PKITS_NOW,
    );
    result.expect("§4.3.5 must validate (case-insensitive names)");
}

/// §4.3.6 Valid Name Chaining UIDs Test6 — names include uid attributes.
/// Oracle: PKITS §4.3.6 MUST validate.
#[test]
fn pkits_4_3_6_valid_name_uids() {
    let result = pkits_validate(&["ValidNameUIDsTest6EE", "UIDCACert"], PKITS_NOW);
    result.expect("§4.3.6 must validate (UID attribute in names)");
}

/// §4.3.7 Valid RFC3280 Mandatory Attribute Types Test7.
/// Oracle: PKITS §4.3.7 MUST validate.
#[test]
fn pkits_4_3_7_valid_mandatory_attribute_types() {
    let result = pkits_validate(
        &[
            "ValidRFC3280MandatoryAttributeTypesTest7EE",
            "RFC3280MandatoryAttributeTypesCACert",
        ],
        PKITS_NOW,
    );
    result.expect("§4.3.7 must validate (mandatory attribute types)");
}

/// §4.3.8 Valid RFC3280 Optional Attribute Types Test8.
/// Oracle: PKITS §4.3.8 MUST validate.
#[test]
fn pkits_4_3_8_valid_optional_attribute_types() {
    let result = pkits_validate(
        &[
            "ValidRFC3280OptionalAttributeTypesTest8EE",
            "RFC3280OptionalAttributeTypesCACert",
        ],
        PKITS_NOW,
    );
    result.expect("§4.3.8 must validate (optional attribute types)");
}

/// §4.3.9 Valid UTF8String Encoded Names Test9.
/// Oracle: PKITS §4.3.9 MUST validate.
#[test]
fn pkits_4_3_9_valid_utf8_encoded_names() {
    let result = pkits_validate(
        &[
            "ValidUTF8StringEncodedNamesTest9EE",
            "UTF8StringEncodedNamesCACert",
        ],
        PKITS_NOW,
    );
    result.expect("§4.3.9 must validate (UTF8String names)");
}

/// §4.3.10 Valid Rollover from PrintableString to UTF8String Test10.
/// Oracle: PKITS §4.3.10 MUST validate (same string, different encoding).
#[test]
fn pkits_4_3_10_valid_printable_to_utf8_rollover() {
    let result = pkits_validate(
        &[
            "ValidRolloverfromPrintableStringtoUTF8StringTest10EE",
            "RolloverfromPrintableStringtoUTF8StringCACert",
        ],
        PKITS_NOW,
    );
    result.expect("§4.3.10 must validate (PrintableString→UTF8String rollover)");
}

/// §4.3.11 Valid UTF8String Case Insensitive Match Test11.
/// Oracle: PKITS §4.3.11 MUST validate.
#[test]
fn pkits_4_3_11_valid_utf8_case_insensitive() {
    let result = pkits_validate(
        &[
            "ValidUTF8StringCaseInsensitiveMatchTest11EE",
            "UTF8StringCaseInsensitiveMatchCACert",
        ],
        PKITS_NOW,
    );
    result.expect("§4.3.11 must validate (case-insensitive UTF8String match)");
}
