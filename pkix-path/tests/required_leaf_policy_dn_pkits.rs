//! Integration tests for `ValidationPolicy::required_leaf_policy_oids` and
//! `ValidationPolicy::required_leaf_subject_dn_attrs` against PKITS fixtures
//! that carry a `CertificatePolicies` extension and a multi-attribute Subject
//! DN.
//!
//! These tests exercise the `Some(cp_ext)` branch of (e3a) and the
//! multi-attribute Subject-DN walk of (e3b), which the in-`lib.rs` unit
//! tests cannot reach with the existing P-256 policy-checks fixtures (which
//! have CN-only Subject DNs and no `CertificatePolicies` extension).
//!
//! Oracle: PKITS `AllCertificatesSamePoliciesTest10EE.crt` is independently
//! sourced from NIST SP 800-89 and is known to have:
//! - Subject: `C=US, O=Test Certificates 2011, CN=All Certificates Same
//!   Policies EE Certificate Test10`
//! - CertificatePolicies asserting `2.16.840.1.101.3.2.1.48.1` and
//!   `2.16.840.1.101.3.2.1.48.2`.
//!
//! Verified independently with `openssl x509 -text -noout` (not the code
//! under test).

#![cfg(feature = "rsa")]

#[path = "pkits_helper.rs"]
mod pkits_helper;

use der::asn1::ObjectIdentifier;
use pkits_helper::{pkits_cert, pkits_trust_anchor, PKITS_NOW};
use pkix_path::{validate_path, DefaultVerifier, DnAttrRule, Error, ValidationPolicy};

// NIST test-policy OIDs (2.16.840.1.101.3.2.1.48.N)
const P1: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.2.1.48.1");
const P2: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.2.1.48.2");
// NIST-test-policy-3 — NOT asserted by AllCertificatesSamePoliciesTest10EE.
const P3: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.2.1.48.3");

// RFC 4519 / X.520 DN attribute OIDs (values from spec, not derived from code under test).
const OID_CN: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
const OID_ORG: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");
const OID_COUNTRY: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.6");
const OID_GIVEN_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.42");

/// Load the AllCertificatesSamePoliciesTest10 chain (leaf-first).
///
/// PKITS vectors.json (§4.8.10) lists this chain root-to-leaf as
/// `[TrustAnchorRoot, PoliciesP12CA, AllCertificatesSamePoliciesTest10EE]`.
/// `validate_path` expects leaf-first without the trust anchor.
fn load_chain() -> Vec<x509_cert::Certificate> {
    vec![
        pkits_cert("AllCertificatesSamePoliciesTest10EE"),
        pkits_cert("PoliciesP12CACert"),
    ]
}

fn baseline_policy() -> ValidationPolicy {
    ValidationPolicy::new(PKITS_NOW)
}

// --------- required_leaf_policy_oids: Some(cp_ext) branch (e3a) ---------

/// Oracle: leaf asserts both P1 and P2; requiring P1 must pass.
#[test]
fn required_policy_oid_passes_when_required_oid_asserted() {
    let chain = load_chain();
    let anchors = [pkits_trust_anchor()];
    let mut policy = baseline_policy();
    policy.required_leaf_policy_oids = Some(vec![P1]);
    validate_path(&chain, &anchors, &policy, &DefaultVerifier)
        .expect("leaf asserts P1; required_leaf_policy_oids=[P1] must pass");
}

/// Oracle: leaf asserts both P1 and P2; requiring both must pass.
#[test]
fn required_policy_oid_passes_when_all_required_oids_asserted() {
    let chain = load_chain();
    let anchors = [pkits_trust_anchor()];
    let mut policy = baseline_policy();
    policy.required_leaf_policy_oids = Some(vec![P1, P2]);
    validate_path(&chain, &anchors, &policy, &DefaultVerifier)
        .expect("leaf asserts P1 and P2; required_leaf_policy_oids=[P1, P2] must pass");
}

/// Oracle: leaf asserts P1 and P2 but NOT P3. Requiring P3 must produce
/// `MissingLeafPolicyOid { required: P3 }`.
#[test]
fn required_policy_oid_fails_when_required_oid_not_in_extension() {
    let chain = load_chain();
    let anchors = [pkits_trust_anchor()];
    let mut policy = baseline_policy();
    policy.required_leaf_policy_oids = Some(vec![P3]);
    let err = validate_path(&chain, &anchors, &policy, &DefaultVerifier)
        .expect_err("leaf does not assert P3; required_leaf_policy_oids=[P3] must fail");
    match err {
        Error::MissingLeafPolicyOid { required } => {
            assert_eq!(
                required, P3,
                "reported OID must echo the missing requirement"
            );
        }
        other => panic!("expected MissingLeafPolicyOid {{ required: P3 }}, got {other:?}"),
    }
}

/// Oracle: requiring P1 (present) AND P3 (absent) fails at P3.
#[test]
fn required_policy_oid_fails_when_any_required_oid_missing() {
    let chain = load_chain();
    let anchors = [pkits_trust_anchor()];
    let mut policy = baseline_policy();
    policy.required_leaf_policy_oids = Some(vec![P1, P3]);
    let err = validate_path(&chain, &anchors, &policy, &DefaultVerifier)
        .expect_err("leaf does not assert P3; mixed list with [P1, P3] must fail");
    match err {
        Error::MissingLeafPolicyOid { required } => {
            assert_eq!(
                required, P3,
                "first missing OID in iteration order must be reported"
            );
        }
        other => panic!("expected MissingLeafPolicyOid {{ required: P3 }}, got {other:?}"),
    }
}

// --------- required_leaf_subject_dn_attrs: multi-attribute Subject (e3b) ---------

/// Oracle: leaf Subject is `C=US, O=Test Certificates 2011, CN=...`.
/// Field(organizationName) must pass.
#[test]
fn required_dn_attr_field_organization_passes_on_multi_attr_subject() {
    let chain = load_chain();
    let anchors = [pkits_trust_anchor()];
    let mut policy = baseline_policy();
    policy.required_leaf_subject_dn_attrs = Some(DnAttrRule::Field(OID_ORG));
    validate_path(&chain, &anchors, &policy, &DefaultVerifier)
        .expect("Subject has organizationName; Field(O) must pass");
}

/// Oracle: leaf Subject has C, O, CN — but not givenName.
/// Field(givenName) must fail with SubjectDnAttrRuleUnmet.
#[test]
fn required_dn_attr_field_givenname_fails_on_business_dn() {
    let chain = load_chain();
    let anchors = [pkits_trust_anchor()];
    let mut policy = baseline_policy();
    policy.required_leaf_subject_dn_attrs = Some(DnAttrRule::Field(OID_GIVEN_NAME));
    assert!(
        matches!(
            validate_path(&chain, &anchors, &policy, &DefaultVerifier),
            Err(Error::SubjectDnAttrRuleUnmet)
        ),
        "Subject lacks givenName; Field(GN) must fail with SubjectDnAttrRuleUnmet"
    );
}

/// Oracle: AllOf([CN, O, C]) — every required attribute is present in the
/// leaf Subject DN; rule must match.
#[test]
fn required_dn_attr_allof_passes_when_every_branch_matches() {
    let chain = load_chain();
    let anchors = [pkits_trust_anchor()];
    let mut policy = baseline_policy();
    policy.required_leaf_subject_dn_attrs = Some(DnAttrRule::AllOf(vec![
        DnAttrRule::Field(OID_CN),
        DnAttrRule::Field(OID_ORG),
        DnAttrRule::Field(OID_COUNTRY),
    ]));
    validate_path(&chain, &anchors, &policy, &DefaultVerifier)
        .expect("Subject has CN, O, C; AllOf must match");
}

/// Oracle: AllOf([CN, givenName]) — CN present, givenName absent; rule must fail.
#[test]
fn required_dn_attr_allof_fails_when_any_branch_misses() {
    let chain = load_chain();
    let anchors = [pkits_trust_anchor()];
    let mut policy = baseline_policy();
    policy.required_leaf_subject_dn_attrs = Some(DnAttrRule::AllOf(vec![
        DnAttrRule::Field(OID_CN),
        DnAttrRule::Field(OID_GIVEN_NAME),
    ]));
    assert!(
        matches!(
            validate_path(&chain, &anchors, &policy, &DefaultVerifier),
            Err(Error::SubjectDnAttrRuleUnmet)
        ),
        "Subject lacks givenName; AllOf with a missing branch must fail"
    );
}

/// Oracle: AnyOf([givenName, AllOf([CN, O])]) — first branch absent, second
/// branch matches; rule must succeed.
#[test]
fn required_dn_attr_anyof_matches_via_inner_allof_branch() {
    let chain = load_chain();
    let anchors = [pkits_trust_anchor()];
    let mut policy = baseline_policy();
    policy.required_leaf_subject_dn_attrs = Some(DnAttrRule::AnyOf(vec![
        DnAttrRule::Field(OID_GIVEN_NAME),
        DnAttrRule::AllOf(vec![DnAttrRule::Field(OID_CN), DnAttrRule::Field(OID_ORG)]),
    ]));
    validate_path(&chain, &anchors, &policy, &DefaultVerifier)
        .expect("inner AllOf(CN, O) branch matches; AnyOf must succeed");
}
