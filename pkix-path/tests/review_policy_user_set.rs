//! Review: RFC 5280 §6.1.5(g)(iii) user-initial-policy-set intersection must
//! cover children of an anyPolicy node. (A flat tree that pruned anyPolicy
//! parents of specific children lost track of which nodes were children of
//! anyPolicy and let them through unintersected.)
//!
//! Chain (PKITS 4.8.14 certs): anchor → anyPolicyCACert (asserts anyPolicy)
//! → AnyPolicyTest14EE (asserts NIST-test-policy-1 only).
//!
//! With `initial_explicit_policy = true` and `user-initial-policy-set =
//! {NIST-test-policy-2}` RFC 5280 requires rejection: the EE's P1 node is a
//! child of the depth-1 anyPolicy node, so it is in the
//! `valid_policy_node_set`, is not in the user set, and is deleted; the tree
//! becomes NULL and `explicit_policy == 0`.

#![cfg(feature = "rsa")]

#[path = "pkits_helper.rs"]
mod pkits_helper;
use pkits_helper::{pkits_cert, pkits_trust_anchor, PKITS_NOW};
use pkix_path::{DefaultVerifier, ValidationPolicy};

const P1: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.2.1.48.1");
const ANY: der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("2.5.29.32.0");
const P2: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.2.1.48.2");

fn run(user_set: &[der::asn1::ObjectIdentifier]) -> pkix_path::Result<pkix_path::ValidatedPath> {
    let chain = vec![
        pkits_cert("AnyPolicyTest14EE"),
        pkits_cert("anyPolicyCACert"),
    ];
    let anchors = [pkits_trust_anchor()];
    let mut policy = ValidationPolicy::new(PKITS_NOW);
    policy.initial_explicit_policy = true;
    policy.initial_policy_set = user_set.to_vec();
    pkix_path::validate_path(&chain, &anchors, &policy, &DefaultVerifier)
}

/// Positive control: {P1} must validate, and the output graph must keep the
/// depth-1 anyPolicy node that is P1's parent (an anyPolicy node has
/// expected_policy_set {anyPolicy}, so pruning by "a child's policy is in my
/// expected set" wrongly deleted it).
#[test]
fn explicit_policy_user_set_p1_validates() {
    let vp = run(&[P1]).expect("P1 is in the user set and asserted by the EE");
    let tree = vp.valid_policy_tree.expect("non-NULL graph");
    let shape: Vec<_> = tree
        .iter()
        .map(|n| (n.depth, n.valid_policy, n.parent_policies.clone()))
        .collect();
    assert_eq!(
        shape,
        vec![(0, ANY, vec![]), (1, ANY, vec![ANY]), (2, P1, vec![ANY]),]
    );
}

/// False accept: {P2} with initial-explicit-policy must be rejected.
#[test]
fn explicit_policy_user_set_p2_must_reject() {
    let r = run(&[P2]);
    assert!(
        r.is_err(),
        "RFC 5280 §6.1.5(g)(iii): P1 (child of anyPolicy) is not in {{P2}}, \
         tree must become NULL and explicit_policy==0 must reject; got {r:?}"
    );
}
