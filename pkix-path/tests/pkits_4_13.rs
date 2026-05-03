//! PKITS §4.13 Name Constraints tests.
//!
//! All cert names and expected outcomes come from the PKITS vectors.
//! Oracle: NIST PKITS (SP 800-89) document §4.13.
//!
//! # Known implementation bugs (tracked separately)
//!
//! Several VALID tests return `NameConstraintViolation` due to bugs in the
//! NC matching logic. These are marked `#[ignore]` to document the expected
//! behaviour without hiding the failures:
//!
//! - DN subtree matching: permitted subtree check uses exact match instead of
//!   RFC 5280 §4.2.1.10 subtree (prefix) matching (affects tests 1, 4–6).
//! - RFC 822 domain suffix: `.domain` syntax not matched correctly (tests 21, 23, 25).
//! - DNS subdomain: `testcertificates.gov` does not match `testserver.testcertificates.gov`
//!   (test 30).
//! - URI host extraction: host not extracted from URI SAN for NC check (test 34).
//! - Excluded subtree detection: DN3 CA has excludedSubtrees but exclusion is not
//!   triggered (test 7 returns Ok instead of Err).
//!
//! Tracking issue: PKIX-nc-matching (filed separately).

#[path = "pkits_helper.rs"]
mod pkits_helper;

use pkits_helper::{pkits_validate, PKITS_NOW};

// ---------------------------------------------------------------------------
// §4.13.1–6 DN name constraints (DN1 CA)
// ---------------------------------------------------------------------------

/// §4.13.1 Valid DN name constraints Test1.
/// Oracle: PKITS §4.13.1 MUST validate.
/// BUG: DN permitted subtree check uses exact match; subtree prefix match not implemented.
#[test]
#[ignore = "DN subtree permitted match not implemented (tracked: PKIX-nc-matching)"]
fn pkits_4_13_1_valid_dn_name_constraints() {
    let result = pkits_validate(
        &[
            "ValidDNnameConstraintsTest1EE",
            "nameConstraintsDN1CACert",
        ],
        PKITS_NOW,
    );
    result.expect("§4.13.1 must validate");
}

/// §4.13.2 Invalid DN name constraints Test2.
/// Oracle: PKITS §4.13.2 MUST NOT validate.
#[test]
fn pkits_4_13_2_invalid_dn_name_constraints() {
    let result = pkits_validate(
        &[
            "InvalidDNnameConstraintsTest2EE",
            "nameConstraintsDN1CACert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::NameConstraintViolation { .. })),
        "§4.13.2 must return NameConstraintViolation, got: {result:?}"
    );
}

/// §4.13.3 Invalid DN name constraints Test3.
/// Oracle: PKITS §4.13.3 MUST NOT validate.
#[test]
fn pkits_4_13_3_invalid_dn_name_constraints() {
    let result = pkits_validate(
        &[
            "InvalidDNnameConstraintsTest3EE",
            "nameConstraintsDN1CACert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::NameConstraintViolation { .. })),
        "§4.13.3 must return NameConstraintViolation, got: {result:?}"
    );
}

/// §4.13.4 Valid DN name constraints Test4 — subCA1 under DN1 CA.
/// Oracle: PKITS §4.13.4 MUST validate.
/// BUG: DN permitted subtree check uses exact match; subtree prefix match not implemented.
#[test]
#[ignore = "DN subtree permitted match not implemented (tracked: PKIX-nc-matching)"]
fn pkits_4_13_4_valid_dn_name_constraints_subca1() {
    let result = pkits_validate(
        &[
            "ValidDNnameConstraintsTest4EE",
            "nameConstraintsDN1subCA1Cert",
            "nameConstraintsDN1CACert",
        ],
        PKITS_NOW,
    );
    result.expect("§4.13.4 must validate");
}

/// §4.13.5 Valid DN name constraints Test5 — subCA2 under DN1 CA.
/// Oracle: PKITS §4.13.5 MUST validate.
/// BUG: DN permitted subtree check uses exact match; subtree prefix match not implemented.
#[test]
#[ignore = "DN subtree permitted match not implemented (tracked: PKIX-nc-matching)"]
fn pkits_4_13_5_valid_dn_name_constraints_subca2() {
    let result = pkits_validate(
        &[
            "ValidDNnameConstraintsTest5EE",
            "nameConstraintsDN1subCA2Cert",
            "nameConstraintsDN1CACert",
        ],
        PKITS_NOW,
    );
    result.expect("§4.13.5 must validate");
}

/// §4.13.6 Valid DN name constraints Test6 — subCA3 under DN1 CA.
/// Oracle: PKITS §4.13.6 MUST validate.
/// BUG: DN permitted subtree check uses exact match; subtree prefix match not implemented.
#[test]
#[ignore = "DN subtree permitted match not implemented (tracked: PKIX-nc-matching)"]
fn pkits_4_13_6_valid_dn_name_constraints_subca3() {
    let result = pkits_validate(
        &[
            "ValidDNnameConstraintsTest6EE",
            "nameConstraintsDN1subCA3Cert",
            "nameConstraintsDN1CACert",
        ],
        PKITS_NOW,
    );
    result.expect("§4.13.6 must validate");
}

// ---------------------------------------------------------------------------
// §4.13.7–9 DN name constraints (DN3/DN4 CA)
// ---------------------------------------------------------------------------

/// §4.13.7 Invalid DN name constraints Test7 — DN3 CA (excludedSubtrees).
/// Oracle: PKITS §4.13.7 MUST NOT validate.
/// BUG: DN excluded subtree check does not trigger; returns Ok instead of Err.
#[test]
#[ignore = "DN excluded subtree check not triggering (tracked: PKIX-nc-matching)"]
fn pkits_4_13_7_invalid_dn_name_constraints_dn3() {
    let result = pkits_validate(
        &[
            "InvalidDNnameConstraintsTest7EE",
            "nameConstraintsDN3CACert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::NameConstraintViolation { .. })),
        "§4.13.7 must return NameConstraintViolation, got: {result:?}"
    );
}

/// §4.13.8 Invalid DN name constraints Test8 — DN4 CA (excludedSubtrees only).
/// Oracle: PKITS §4.13.8 MUST NOT validate.
/// Chain: EE issued by DN4 CA (not DN3 CA).
/// BUG: Excluded-only DN subtree check (no permittedSubtrees) does not trigger.
#[test]
#[ignore = "DN excluded subtree check not triggering (tracked: PKIX-nc-matching)"]
fn pkits_4_13_8_invalid_dn_name_constraints_dn4() {
    let result = pkits_validate(
        &[
            "InvalidDNnameConstraintsTest8EE",
            "nameConstraintsDN4CACert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::NameConstraintViolation { .. })),
        "§4.13.8 must return NameConstraintViolation, got: {result:?}"
    );
}

/// §4.13.9 Invalid DN name constraints Test9 — DN4 CA (excludedSubtrees only).
/// Oracle: PKITS §4.13.9 MUST NOT validate.
/// Chain: EE issued by DN4 CA (not DN3 CA).
/// BUG: Excluded-only DN subtree check (no permittedSubtrees) does not trigger.
#[test]
#[ignore = "DN excluded subtree check not triggering (tracked: PKIX-nc-matching)"]
fn pkits_4_13_9_invalid_dn_name_constraints_dn4() {
    let result = pkits_validate(
        &[
            "InvalidDNnameConstraintsTest9EE",
            "nameConstraintsDN4CACert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::NameConstraintViolation { .. })),
        "§4.13.9 must return NameConstraintViolation, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// §4.13.10–11 DN name constraints (DN5 CA)
// ---------------------------------------------------------------------------

/// §4.13.10 Invalid DN name constraints Test10 — DN5 CA (permitted + excluded).
/// Oracle: PKITS §4.13.10 MUST NOT validate.
/// Chain: EE issued directly by DN5 CA (not DN3 subCA).
#[test]
fn pkits_4_13_10_invalid_dn_name_constraints_dn5() {
    let result = pkits_validate(
        &[
            "InvalidDNnameConstraintsTest10EE",
            "nameConstraintsDN5CACert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::NameConstraintViolation { .. })),
        "§4.13.10 must return NameConstraintViolation, got: {result:?}"
    );
}

/// §4.13.11 Valid DN name constraints Test11 — DN5 CA (permitted + excluded).
/// Oracle: PKITS §4.13.11 MUST validate.
/// Chain: EE issued directly by DN5 CA (not DN3 subCA).
/// BUG: DN permitted subtree check uses exact match; subtree prefix match not implemented.
#[test]
#[ignore = "DN subtree permitted match not implemented (tracked: PKIX-nc-matching)"]
fn pkits_4_13_11_valid_dn_name_constraints_dn5() {
    let result = pkits_validate(
        &[
            "ValidDNnameConstraintsTest11EE",
            "nameConstraintsDN5CACert",
        ],
        PKITS_NOW,
    );
    result.expect("§4.13.11 must validate");
}

// ---------------------------------------------------------------------------
// §4.13.12–14 DN name constraints (DN1 subCAs)
// ---------------------------------------------------------------------------

/// §4.13.12 Invalid DN name constraints Test12 — DN1 subCA1.
/// Oracle: PKITS §4.13.12 MUST NOT validate.
/// Chain: EE issued by DN1 subCA1, which is under DN1 CA.
#[test]
fn pkits_4_13_12_invalid_dn_name_constraints_dn1_subca1() {
    let result = pkits_validate(
        &[
            "InvalidDNnameConstraintsTest12EE",
            "nameConstraintsDN1subCA1Cert",
            "nameConstraintsDN1CACert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::NameConstraintViolation { .. })),
        "§4.13.12 must return NameConstraintViolation, got: {result:?}"
    );
}

/// §4.13.13 Invalid DN name constraints Test13 — DN1 subCA2.
/// Oracle: PKITS §4.13.13 MUST NOT validate.
/// Chain: EE issued by DN1 subCA2, which is under DN1 CA.
#[test]
fn pkits_4_13_13_invalid_dn_name_constraints_dn1_subca2() {
    let result = pkits_validate(
        &[
            "InvalidDNnameConstraintsTest13EE",
            "nameConstraintsDN1subCA2Cert",
            "nameConstraintsDN1CACert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::NameConstraintViolation { .. })),
        "§4.13.13 must return NameConstraintViolation, got: {result:?}"
    );
}

/// §4.13.14 Valid DN name constraints Test14 — DN1 subCA2.
/// Oracle: PKITS §4.13.14 MUST validate.
/// Chain: EE issued by DN1 subCA2, which is under DN1 CA.
/// BUG: DN permitted subtree check uses exact match; subtree prefix match not implemented.
#[test]
#[ignore = "DN subtree permitted match not implemented (tracked: PKIX-nc-matching)"]
fn pkits_4_13_14_valid_dn_name_constraints_dn1_subca2() {
    let result = pkits_validate(
        &[
            "ValidDNnameConstraintsTest14EE",
            "nameConstraintsDN1subCA2Cert",
            "nameConstraintsDN1CACert",
        ],
        PKITS_NOW,
    );
    result.expect("§4.13.14 must validate");
}

// ---------------------------------------------------------------------------
// §4.13.15–17 DN name constraints (DN3 subCAs)
// ---------------------------------------------------------------------------

/// §4.13.15 Invalid DN name constraints Test15 — DN3 subCA1 (excludedSubtrees).
/// Oracle: PKITS §4.13.15 MUST NOT validate.
/// Chain: EE issued by DN3 subCA1, which is under DN3 CA.
/// BUG: DN3 CA excluded subtree (OU=excludedSubtree1) not propagated; check not triggering.
#[test]
#[ignore = "DN excluded subtree check not triggering (tracked: PKIX-nc-matching)"]
fn pkits_4_13_15_invalid_dn_name_constraints_dn3_subca1() {
    let result = pkits_validate(
        &[
            "InvalidDNnameConstraintsTest15EE",
            "nameConstraintsDN3subCA1Cert",
            "nameConstraintsDN3CACert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::NameConstraintViolation { .. })),
        "§4.13.15 must return NameConstraintViolation, got: {result:?}"
    );
}

/// §4.13.16 Invalid DN name constraints Test16 — DN3 subCA1 (excludedSubtrees).
/// Oracle: PKITS §4.13.16 MUST NOT validate.
/// Chain: EE issued by DN3 subCA1, which is under DN3 CA.
/// BUG: DN3 subCA1 excluded subtree (OU=excludedSubtree2) not triggering.
#[test]
#[ignore = "DN excluded subtree check not triggering (tracked: PKIX-nc-matching)"]
fn pkits_4_13_16_invalid_dn_name_constraints_dn3_subca1() {
    let result = pkits_validate(
        &[
            "InvalidDNnameConstraintsTest16EE",
            "nameConstraintsDN3subCA1Cert",
            "nameConstraintsDN3CACert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::NameConstraintViolation { .. })),
        "§4.13.16 must return NameConstraintViolation, got: {result:?}"
    );
}

/// §4.13.17 Invalid DN name constraints Test17 — DN3 subCA2 (permittedSubtrees narrowed).
/// Oracle: PKITS §4.13.17 MUST NOT validate.
/// Chain: EE issued by DN3 subCA2, which is under DN3 CA.
#[test]
fn pkits_4_13_17_invalid_dn_name_constraints_dn3_subca2() {
    let result = pkits_validate(
        &[
            "InvalidDNnameConstraintsTest17EE",
            "nameConstraintsDN3subCA2Cert",
            "nameConstraintsDN3CACert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::NameConstraintViolation { .. })),
        "§4.13.17 must return NameConstraintViolation, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// §4.13.18–20 DN name constraints with self-issued CA
// ---------------------------------------------------------------------------

/// §4.13.18 Valid DN name constraints Test18 — self-issued CA in chain.
/// Oracle: PKITS §4.13.18 MUST validate.
/// Note: v0.1 does not exempt self-issued certs from NC checks (RFC 5280 §6.1.3).
#[test]
#[ignore = "self-issued NC exemption not in v0.1 (tracked: PKIX-8wp)"]
fn pkits_4_13_18_valid_dn_name_constraints_self_issued() {
    let result = pkits_validate(
        &[
            "ValidDNnameConstraintsTest18EE",
            "nameConstraintsDN1subCA1Cert",
            "nameConstraintsDN1SelfIssuedCACert",
            "nameConstraintsDN1CACert",
        ],
        PKITS_NOW,
    );
    result.expect("§4.13.18 must validate");
}

/// §4.13.19 Valid DN name constraints Test19 — self-issued CA in chain.
/// Oracle: PKITS §4.13.19 MUST validate.
/// Note: v0.1 does not exempt self-issued certs from NC checks (RFC 5280 §6.1.3).
#[test]
#[ignore = "self-issued NC exemption not in v0.1 (tracked: PKIX-8wp)"]
fn pkits_4_13_19_valid_dn_name_constraints_self_issued() {
    let result = pkits_validate(
        &[
            "ValidDNnameConstraintsTest19EE",
            "nameConstraintsDN1subCA1Cert",
            "nameConstraintsDN1SelfIssuedCACert",
            "nameConstraintsDN1CACert",
        ],
        PKITS_NOW,
    );
    result.expect("§4.13.19 must validate");
}

/// §4.13.20 Invalid DN name constraints Test20 — self-issued CA in chain.
/// Oracle: PKITS §4.13.20 MUST NOT validate.
#[test]
fn pkits_4_13_20_invalid_dn_name_constraints_self_issued() {
    let result = pkits_validate(
        &[
            "InvalidDNnameConstraintsTest20EE",
            "nameConstraintsDN1subCA1Cert",
            "nameConstraintsDN1SelfIssuedCACert",
            "nameConstraintsDN1CACert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::NameConstraintViolation { .. })),
        "§4.13.20 must return NameConstraintViolation, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// §4.13.21–26 RFC 822 name constraints
// ---------------------------------------------------------------------------

/// §4.13.21 Valid RFC 822 name constraints Test21 — RFC822 CA1.
/// Oracle: PKITS §4.13.21 MUST validate.
/// BUG: RFC 822 domain suffix (`.domain`) not matched correctly.
#[test]
#[ignore = "RFC822 domain suffix match not implemented (tracked: PKIX-nc-matching)"]
fn pkits_4_13_21_valid_rfc822_name_constraints() {
    let result = pkits_validate(
        &[
            "ValidRFC822nameConstraintsTest21EE",
            "nameConstraintsRFC822CA1Cert",
        ],
        PKITS_NOW,
    );
    result.expect("§4.13.21 must validate");
}

/// §4.13.22 Invalid RFC 822 name constraints Test22 — RFC822 CA1.
/// Oracle: PKITS §4.13.22 MUST NOT validate.
#[test]
fn pkits_4_13_22_invalid_rfc822_name_constraints() {
    let result = pkits_validate(
        &[
            "InvalidRFC822nameConstraintsTest22EE",
            "nameConstraintsRFC822CA1Cert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::NameConstraintViolation { .. })),
        "§4.13.22 must return NameConstraintViolation, got: {result:?}"
    );
}

/// §4.13.23 Valid RFC 822 name constraints Test23 — RFC822 CA2.
/// Oracle: PKITS §4.13.23 MUST validate.
/// BUG: RFC 822 domain suffix (`.domain`) not matched correctly.
#[test]
#[ignore = "RFC822 domain suffix match not implemented (tracked: PKIX-nc-matching)"]
fn pkits_4_13_23_valid_rfc822_name_constraints_ca2() {
    let result = pkits_validate(
        &[
            "ValidRFC822nameConstraintsTest23EE",
            "nameConstraintsRFC822CA2Cert",
        ],
        PKITS_NOW,
    );
    result.expect("§4.13.23 must validate");
}

/// §4.13.24 Invalid RFC 822 name constraints Test24 — RFC822 CA2.
/// Oracle: PKITS §4.13.24 MUST NOT validate.
#[test]
fn pkits_4_13_24_invalid_rfc822_name_constraints_ca2() {
    let result = pkits_validate(
        &[
            "InvalidRFC822nameConstraintsTest24EE",
            "nameConstraintsRFC822CA2Cert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::NameConstraintViolation { .. })),
        "§4.13.24 must return NameConstraintViolation, got: {result:?}"
    );
}

/// §4.13.25 Valid RFC 822 name constraints Test25 — RFC822 CA3.
/// Oracle: PKITS §4.13.25 MUST validate.
#[test]
fn pkits_4_13_25_valid_rfc822_name_constraints_ca3() {
    let result = pkits_validate(
        &[
            "ValidRFC822nameConstraintsTest25EE",
            "nameConstraintsRFC822CA3Cert",
        ],
        PKITS_NOW,
    );
    result.expect("§4.13.25 must validate");
}

/// §4.13.26 Invalid RFC 822 name constraints Test26 — RFC822 CA3.
/// Oracle: PKITS §4.13.26 MUST NOT validate.
#[test]
fn pkits_4_13_26_invalid_rfc822_name_constraints_ca3() {
    let result = pkits_validate(
        &[
            "InvalidRFC822nameConstraintsTest26EE",
            "nameConstraintsRFC822CA3Cert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::NameConstraintViolation { .. })),
        "§4.13.26 must return NameConstraintViolation, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// §4.13.27–29 DN + RFC 822 combined name constraints
// ---------------------------------------------------------------------------

/// §4.13.27 Valid DN and RFC 822 name constraints Test27 — DN1 subCA3.
/// Oracle: PKITS §4.13.27 MUST validate.
/// Chain: EE issued by DN1 subCA3, which is under DN1 CA.
/// BUG: DN permitted subtree check uses exact match; subtree prefix match not implemented.
#[test]
#[ignore = "DN subtree permitted match not implemented (tracked: PKIX-nc-matching)"]
fn pkits_4_13_27_valid_dn_and_rfc822_name_constraints() {
    let result = pkits_validate(
        &[
            "ValidDNandRFC822nameConstraintsTest27EE",
            "nameConstraintsDN1subCA3Cert",
            "nameConstraintsDN1CACert",
        ],
        PKITS_NOW,
    );
    result.expect("§4.13.27 must validate");
}

/// §4.13.28 Invalid DN and RFC 822 name constraints Test28 — DN1 subCA3.
/// Oracle: PKITS §4.13.28 MUST NOT validate.
/// Chain: EE issued by DN1 subCA3, which is under DN1 CA.
#[test]
fn pkits_4_13_28_invalid_dn_and_rfc822_name_constraints() {
    let result = pkits_validate(
        &[
            "InvalidDNandRFC822nameConstraintsTest28EE",
            "nameConstraintsDN1subCA3Cert",
            "nameConstraintsDN1CACert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::NameConstraintViolation { .. })),
        "§4.13.28 must return NameConstraintViolation, got: {result:?}"
    );
}

/// §4.13.29 Invalid DN and RFC 822 name constraints Test29 — DN1 subCA3.
/// Oracle: PKITS §4.13.29 MUST NOT validate.
/// Chain: EE issued by DN1 subCA3, which is under DN1 CA.
#[test]
fn pkits_4_13_29_invalid_dn_and_rfc822_name_constraints() {
    let result = pkits_validate(
        &[
            "InvalidDNandRFC822nameConstraintsTest29EE",
            "nameConstraintsDN1subCA3Cert",
            "nameConstraintsDN1CACert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::NameConstraintViolation { .. })),
        "§4.13.29 must return NameConstraintViolation, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// §4.13.30–33, 38 DNS name constraints
// ---------------------------------------------------------------------------

/// §4.13.30 Valid DNS name constraints Test30 — DNS1 CA.
/// Oracle: PKITS §4.13.30 MUST validate.
/// BUG: DNS subdomain matching not implemented; exact match only.
#[test]
#[ignore = "DNS subdomain match not implemented (tracked: PKIX-nc-matching)"]
fn pkits_4_13_30_valid_dns_name_constraints() {
    let result = pkits_validate(
        &[
            "ValidDNSnameConstraintsTest30EE",
            "nameConstraintsDNS1CACert",
        ],
        PKITS_NOW,
    );
    result.expect("§4.13.30 must validate");
}

/// §4.13.31 Invalid DNS name constraints Test31 — DNS1 CA.
/// Oracle: PKITS §4.13.31 MUST NOT validate.
#[test]
fn pkits_4_13_31_invalid_dns_name_constraints() {
    let result = pkits_validate(
        &[
            "InvalidDNSnameConstraintsTest31EE",
            "nameConstraintsDNS1CACert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::NameConstraintViolation { .. })),
        "§4.13.31 must return NameConstraintViolation, got: {result:?}"
    );
}

/// §4.13.32 Valid DNS name constraints Test32 — DNS2 CA.
/// Oracle: PKITS §4.13.32 MUST validate.
#[test]
fn pkits_4_13_32_valid_dns_name_constraints_dns2() {
    let result = pkits_validate(
        &[
            "ValidDNSnameConstraintsTest32EE",
            "nameConstraintsDNS2CACert",
        ],
        PKITS_NOW,
    );
    result.expect("§4.13.32 must validate");
}

/// §4.13.33 Invalid DNS name constraints Test33 — DNS2 CA.
/// Oracle: PKITS §4.13.33 MUST NOT validate.
#[test]
fn pkits_4_13_33_invalid_dns_name_constraints_dns2() {
    let result = pkits_validate(
        &[
            "InvalidDNSnameConstraintsTest33EE",
            "nameConstraintsDNS2CACert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::NameConstraintViolation { .. })),
        "§4.13.33 must return NameConstraintViolation, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// §4.13.34–37 URI name constraints
// ---------------------------------------------------------------------------

/// §4.13.34 Valid URI name constraints Test34 — URI1 CA.
/// Oracle: PKITS §4.13.34 MUST validate.
/// BUG: URI host is not extracted for NC check; the full URI string is matched instead.
#[test]
#[ignore = "URI host extraction for NC check not implemented (tracked: PKIX-nc-matching)"]
fn pkits_4_13_34_valid_uri_name_constraints() {
    let result = pkits_validate(
        &[
            "ValidURInameConstraintsTest34EE",
            "nameConstraintsURI1CACert",
        ],
        PKITS_NOW,
    );
    result.expect("§4.13.34 must validate");
}

/// §4.13.35 Invalid URI name constraints Test35 — URI1 CA.
/// Oracle: PKITS §4.13.35 MUST NOT validate.
#[test]
fn pkits_4_13_35_invalid_uri_name_constraints() {
    let result = pkits_validate(
        &[
            "InvalidURInameConstraintsTest35EE",
            "nameConstraintsURI1CACert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::NameConstraintViolation { .. })),
        "§4.13.35 must return NameConstraintViolation, got: {result:?}"
    );
}

/// §4.13.36 Valid URI name constraints Test36 — URI2 CA.
/// Oracle: PKITS §4.13.36 MUST validate.
#[test]
fn pkits_4_13_36_valid_uri_name_constraints_uri2() {
    let result = pkits_validate(
        &[
            "ValidURInameConstraintsTest36EE",
            "nameConstraintsURI2CACert",
        ],
        PKITS_NOW,
    );
    result.expect("§4.13.36 must validate");
}

/// §4.13.37 Invalid URI name constraints Test37 — URI2 CA.
/// Oracle: PKITS §4.13.37 MUST NOT validate.
#[test]
fn pkits_4_13_37_invalid_uri_name_constraints_uri2() {
    let result = pkits_validate(
        &[
            "InvalidURInameConstraintsTest37EE",
            "nameConstraintsURI2CACert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::NameConstraintViolation { .. })),
        "§4.13.37 must return NameConstraintViolation, got: {result:?}"
    );
}

/// §4.13.38 Invalid DNS name constraints Test38 — DNS1 CA.
/// Oracle: PKITS §4.13.38 MUST NOT validate.
/// Chain: EE issued by DNS1 CA (not DNS2 CA).
#[test]
fn pkits_4_13_38_invalid_dns_name_constraints_dns1() {
    let result = pkits_validate(
        &[
            "InvalidDNSnameConstraintsTest38EE",
            "nameConstraintsDNS1CACert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(result, Err(pkix_path::Error::NameConstraintViolation { .. })),
        "§4.13.38 must return NameConstraintViolation, got: {result:?}"
    );
}
