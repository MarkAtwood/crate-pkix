//! The two requirements `chain_walk` applies to the leaf and nothing else.
//!
//! `ValidationPolicy::required_leaf_policy_oids` and
//! `required_leaf_subject_dn_attrs` are deployment-policy requirements on
//! the leaf, each guarded by `if i == 0`. Mutated to `i != 0`, the
//! requirement applies to every certificate *except* the leaf, so a leaf
//! that fails it is accepted whenever some intermediate happens to satisfy
//! it -- the caller asked for a leaf asserting a policy OID, or carrying a
//! Subject attribute, and got neither.
//!
//! The existing tests cannot see that. They run on PKITS
//! `AllCertificatesSamePoliciesTest10`, whose name is the reason: every
//! certificate asserts the same policies, so the chain cannot tell "check
//! the leaf" from "check everything but the leaf", and its two Subject DNs
//! share the attributes those tests ask about.
//!
//! So this chain is deliberately asymmetric -- each property is in exactly
//! one of the two certificates, and in opposite directions, which pins
//! both guards from both sides. Fixture rationale and the asymmetry
//! assertions: `tests/fixtures/leaf-only-checks/gen.py`.
#![cfg(all(feature = "p256", feature = "std"))]

use der::asn1::ObjectIdentifier;
use pkix_path::{validate_path, DefaultVerifier, DnAttrRule, Error, TrustAnchor, ValidationPolicy};
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

/// 2030-01-01T00:00:00Z, inside every fixture's validity window.
const NOW: u64 = 1_893_456_000;
const DIR: &str = "tests/fixtures/leaf-only-checks";

/// Asserted by the leaf only.
const P_LEAF: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.2.1.48.1");
/// Asserted by the intermediate only.
const P_INT: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.2.1.48.2");

/// `countryName`, in the leaf's Subject only.
const OID_COUNTRY: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.6");
/// `organizationName`, in the intermediate's Subject only.
const OID_ORG: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");

fn load(name: &str) -> Certificate {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(DIR)
        .join(name);
    let der = std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
    Certificate::from_der(&der).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

fn run(policy: &ValidationPolicy) -> Result<(), Error> {
    let chain = [load("leaf.der"), load("int.der")];
    let anchors = [TrustAnchor::from_cert(load("root.der"))];
    validate_path(&chain, &anchors, policy, &DefaultVerifier).map(|_| ())
}

/// The chain validates with neither requirement set.
///
/// Both tests below turn on one requirement at a time, so this says any
/// failure they report comes from that requirement and not from the chain.
#[test]
fn the_chain_validates_with_no_leaf_requirement() {
    run(&ValidationPolicy::new(NOW)).expect("an ordinary two-certificate chain");
}

/// A required policy OID is required *of the leaf*.
///
/// `P_LEAF` is asserted by the leaf and not the intermediate; `P_INT` the
/// other way round. Requiring `P_INT` must fail even though the
/// intermediate asserts it, which is the fail-open direction: a leaf
/// asserting no required policy at all would otherwise validate.
#[test]
fn a_required_policy_oid_is_required_of_the_leaf() {
    let mut policy = ValidationPolicy::new(NOW);
    policy.required_leaf_policy_oids = Some(vec![P_LEAF]);
    run(&policy).expect("the leaf asserts P_LEAF");

    let mut policy = ValidationPolicy::new(NOW);
    policy.required_leaf_policy_oids = Some(vec![P_INT]);
    assert!(
        matches!(
            run(&policy),
            Err(Error::MissingLeafPolicyOid { required }) if required == P_INT
        ),
        "the leaf does not assert P_INT; the intermediate asserting it is not enough, got {:?}",
        run(&policy)
    );
}

/// A required Subject DN attribute is required *of the leaf*.
///
/// `countryName` is in the leaf's Subject and not the intermediate's;
/// `organizationName` the other way round. Requiring `organizationName`
/// must fail: the rule is about who the leaf says it is, and an
/// intermediate's Subject answers a different question.
#[test]
fn a_required_subject_attribute_is_required_of_the_leaf() {
    let mut policy = ValidationPolicy::new(NOW);
    policy.required_leaf_subject_dn_attrs = Some(DnAttrRule::Field(OID_COUNTRY));
    run(&policy).expect("the leaf's Subject carries countryName");

    let mut policy = ValidationPolicy::new(NOW);
    policy.required_leaf_subject_dn_attrs = Some(DnAttrRule::Field(OID_ORG));
    assert!(
        matches!(run(&policy), Err(Error::SubjectDnAttrRuleUnmet)),
        "the leaf's Subject has no organizationName; the intermediate's having one \
         is not enough, got {:?}",
        run(&policy)
    );
}
