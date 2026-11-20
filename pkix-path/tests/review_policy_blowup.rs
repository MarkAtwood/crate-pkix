//! Review: exponential `valid_policy_tree` growth (CVE-2023-0464 class).
//!
//! Fixture chain `tests/fixtures/review/policy-blowup/` (see `gen.sh`): four
//! intermediates, each asserting 10 policies and mapping each of them to all
//! 10 next-level policies. The literal RFC 5280 tree has 10^d nodes at depth
//! d (111 111 in total), and a quadratic §6.1.5(g) over that tree never
//! finished. The RFC 9618 policy graph has at most one node per
//! (depth, policy): 1 + 5 * 10 = 51 nodes. `openssl verify` (3.0.x, which
//! bounds the tree) accepts the chain.
//!
//! Each test runs validation on a worker thread with a time budget, so a
//! regression fails instead of hanging the suite.

#![cfg(feature = "p256")]

use der::Decode as _;
use pkix_path::{DefaultVerifier, TrustAnchor, ValidationPolicy};
use std::time::Duration;
use x509_cert::Certificate;

const NOW: u64 = 1_798_761_600; // 2027-01-01T00:00:00Z
const BUDGET: Duration = Duration::from_secs(20);

fn load(name: &str) -> Certificate {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/review/policy-blowup")
        .join(name);
    Certificate::from_der(&std::fs::read(&p).unwrap()).unwrap()
}

/// Validates the fixture chain and returns the number of nodes in the final
/// policy graph.
fn run_with_budget(policy: ValidationPolicy) -> usize {
    let chain: Vec<Certificate> = ["leaf.der", "ca4.der", "ca3.der", "ca2.der", "ca1.der"]
        .iter()
        .map(|n| load(n))
        .collect();
    let anchors = vec![TrustAnchor::from_cert(load("root.der"))];
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let r = pkix_path::validate_path(&chain, &anchors, &policy, &DefaultVerifier);
        let _ = tx.send(r.map(|vp| vp.valid_policy_tree.map_or(0, |t| t.len())));
    });
    match rx.recv_timeout(BUDGET) {
        Ok(r) => r.expect("openssl verify accepts this chain"),
        Err(_) => panic!(
            "validate_path did not return within {BUDGET:?}: policy tree grows \
             exponentially with PolicyMappings fan-out"
        ),
    }
}

/// Default policy (empty user-initial-policy-set): the graph keeps every
/// policy, one node per (depth, policy).
#[test]
fn fanout_default_policy() {
    assert_eq!(run_with_budget(ValidationPolicy::new(NOW)), 1 + 5 * 10);
}

/// A user-initial-policy-set of one depth-1 policy deletes the other nine
/// depth-1 nodes; every deeper node keeps that one surviving parent, so the
/// graph is root + 1 + 4 * 10 nodes.
#[test]
fn fanout_with_user_initial_policy_set() {
    let mut policy = ValidationPolicy::new(NOW);
    policy.initial_policy_set = vec![der::asn1::ObjectIdentifier::new_unwrap(
        "1.3.6.1.4.1.55555.1.1.1",
    )];
    assert_eq!(run_with_budget(policy), 1 + 1 + 4 * 10);
}
