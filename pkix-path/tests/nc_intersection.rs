//! RFC 5280 §6.1.4(g): permitted subtrees intersect down the path,
//! excluded subtrees union.
//!
//! `chain_walk` does both, and each keeps its set free of duplicates --
//! where "duplicate" means two entries of the same name form that contain
//! each other. Both dedup tests are three-part conjunctions, and loosening
//! any part changes which subtrees survive. Nothing in the suite had two
//! CAs whose constraints forced the question: the PKITS name-constraint
//! vectors put all their subtrees on one CA.
//!
//! Fixture rationale: `tests/fixtures/nc-intersection/gen.py`.

use pkix_path::{validate_path, DefaultVerifier, Error, TrustAnchor, ValidationPolicy};
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

const NOW: u64 = 1_600_000_000; // 2020-09-13, inside the fixtures' window
const DIR: &str = "tests/fixtures/nc-intersection";

fn load(name: &str) -> Certificate {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(DIR)
        .join(name);
    let der = std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
    Certificate::from_der(&der).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

/// `chain` is leaf-first, so the CA nearest the root comes last.
fn run(chain: &[&str]) -> pkix_path::Result<pkix_path::ValidatedPath> {
    let certs: Vec<Certificate> = chain.iter().map(|n| load(n)).collect();
    let anchors = [TrustAnchor::from_cert(load("root.der"))];
    validate_path(
        &certs,
        &anchors,
        &ValidationPolicy::new(NOW),
        &DefaultVerifier,
    )
}

/// Intersecting a two-entry permitted set against a broader one keeps both
/// entries.
///
/// `ca-specific` permits `sub.a.example` and then `a.example`;
/// `ca-broad` permits `example`, which contains both. The intersection is
/// therefore `ca-specific`'s own two entries, and `other.a.example` is
/// permitted by `a.example`.
///
/// The order inside `ca-specific` is what makes this test work.
/// `a.example` is reached with `sub.a.example` already in the result set:
/// same name form, containment in one direction only. That is the one
/// input that distinguishes a two-way containment test from a one-way one,
/// or from a bare same-form test -- and under either of those `a.example`
/// is discarded as a duplicate, leaving a permitted set that excludes a
/// name both CAs allow.
#[test]
fn intersecting_against_a_broader_subtree_keeps_the_specific_entries() {
    run(&["leaf-other-a.der", "ca-broad.der", "ca-specific.der"]).expect(
        "both CAs permit other.a.example: ca-specific through a.example, \
         ca-broad through example",
    );
}

/// The premise: the same chain refuses a name outside the intersection.
///
/// `host.other.example` is inside `ca-broad`'s `example` and outside both
/// of `ca-specific`'s entries, so the intersection is what refuses it.
/// Without this, the test above would pass for a validator that had
/// stopped applying permitted subtrees at all.
#[test]
fn a_name_outside_the_intersection_is_refused() {
    let r = run(&["leaf-other-example.der", "ca-broad.der", "ca-specific.der"]);
    assert!(
        matches!(r, Err(Error::NameConstraintViolation { index: 0 })),
        "host.other.example is permitted by ca-broad alone, got: {r:?}"
    );
}

/// Two CAs excluding different subtrees of the same name form both take
/// effect.
///
/// `ca-excl-a` excludes `a.example` and `ca-excl-b` excludes `b.example`.
/// Treat "same name form" as "already present" and the second CA's
/// exclusion is discarded as a duplicate, which is the fail-open
/// direction: `host.b.example` is a name the path excludes, and it would
/// validate.
#[test]
fn a_second_exclusion_of_the_same_name_form_still_applies() {
    let r = run(&["leaf-in-b.der", "ca-excl-b.der", "ca-excl-a.der"]);
    assert!(
        matches!(r, Err(Error::NameConstraintViolation { index: 0 })),
        "host.b.example is excluded by ca-excl-b, got: {r:?}"
    );
}

/// A broader exclusion arriving after a narrower one of the same form is
/// not a duplicate of it.
///
/// `ca-excl-sub` excludes `sub.bad.example`, then `ca-excl-bad` excludes
/// `bad.example`. The two contain each other in one direction only, so a
/// containment test satisfied by either direction discards the broader
/// one. `other.bad.example` is under `bad.example` and outside
/// `sub.bad.example`, so discarding it makes an excluded name validate --
/// the same fail-open shape as the test above, reached through the other
/// half of the same conjunction.
#[test]
fn a_broader_exclusion_is_not_a_duplicate_of_a_narrower_one() {
    let r = run(&["leaf-other-bad.der", "ca-excl-bad.der", "ca-excl-sub.der"]);
    assert!(
        matches!(r, Err(Error::NameConstraintViolation { index: 0 })),
        "other.bad.example is excluded by ca-excl-bad, got: {r:?}"
    );
}
