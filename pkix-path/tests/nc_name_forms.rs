//! RFC 5280 §4.2.1.10 on name forms this implementation cannot evaluate.
//!
//! A certificate must be rejected when a name constraint applies to a form
//! the validator cannot match. `pkix-path` cannot match `otherName`,
//! `ediPartyName` or `registeredID` constraints, so a SAN of one of those
//! forms is refused whenever a constraint on that form is in effect -- and
//! only then.
//!
//! The whole rule rests on one match guard, and the PKITS corpus carries
//! no vector for any of these forms, so the guard had no test in either
//! direction. Always false, an unevaluable form passes under a constraint
//! that applies to it; always true, it is refused with no constraint in
//! sight, which would reject certificates no rule objects to.
//!
//! Fixture rationale: `tests/fixtures/nc-name-forms/gen.py`.

use pkix_path::{validate_path, DefaultVerifier, Error, TrustAnchor, ValidationPolicy};
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

const NOW: u64 = 1_600_000_000; // 2020-09-13, inside the fixtures' window
const DIR: &str = "tests/fixtures/nc-name-forms";

fn load(name: &str) -> Certificate {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(DIR)
        .join(name);
    let der = std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
    Certificate::from_der(&der).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

fn run(leaf: &str, ca: &str) -> pkix_path::Result<pkix_path::ValidatedPath> {
    let chain = [load(leaf), load(ca)];
    let anchors = [TrustAnchor::from_cert(load("root.der"))];
    validate_path(
        &chain,
        &anchors,
        &ValidationPolicy::new(NOW),
        &DefaultVerifier,
    )
}

/// A `registeredID` SAN under a CA that constrains `registeredID` is
/// refused.
///
/// The value in the SAN is the one the permitted subtree names, on
/// purpose: the rule is that the form cannot be evaluated, not that the
/// value failed to match, and a fixture whose value differed could not
/// tell those apart. A validator that silently accepted this would be
/// honouring a constraint it cannot enforce.
#[test]
fn an_unevaluable_name_form_is_refused_under_a_constraint_on_it() {
    let r = run("leaf-regid-under-regid.der", "ca-regid.der");
    assert!(
        matches!(r, Err(Error::NameConstraintViolation { index: 0 })),
        "a registeredID SAN under a registeredID constraint must be refused, got: {r:?}"
    );
}

/// The same SAN under a CA that constrains only `dNSName` is accepted.
///
/// Only one direction of the guard is reachable through a `registeredID`
/// fixture. With the guard forced false, the certificate above is still
/// refused -- `check_name_constraints`'s own SAN loop tries to match the
/// registeredID against the permitted subtree, cannot, and reports the same
/// violation at the same index. The guard is the explicit statement of the
/// rule and the loop is a second path to the same refusal, so a fixture
/// cannot separate them; only `ediPartyName` could, and nothing in the
/// generator's toolchain emits one.
///
/// Nothing in RFC 5280 lets a dNSName constraint reach a registeredID
/// name, and the certificate carries no dNSName for the constraint to
/// apply to. Without this case the test above would pass for a validator
/// that refused every unevaluable form unconditionally.
#[test]
fn an_unevaluable_name_form_passes_with_no_constraint_on_it() {
    run("leaf-regid-under-dns.der", "ca-dns.der")
        .expect("no constraint names registeredID, so the form is not in question");
}

/// An `otherName` that is not an `SmtpUTF8Mailbox` is not read as a
/// mailbox.
///
/// `check_san_name_form` routes an `SmtpUTF8Mailbox` otherName through the
/// rfc822Name constraints (RFC 8398 §6) under a two-part condition: the
/// type-id is SmtpUTF8Mailbox *and* an rfc822Name constraint is in effect.
/// Loosened to either, every otherName reaching that point is read as a
/// mailbox -- and this one's value is a DER INTEGER, so the read fails and
/// the certificate is refused as malformed.
///
/// An rfc822Name constraint is in effect here and the leaf carries no
/// rfc822Name SAN, which is the arrangement that leaves the type-id as the
/// only thing the condition can turn on.
#[test]
fn an_other_name_that_is_not_a_mailbox_is_not_checked_as_one() {
    run("leaf-othername-under-rfc822.der", "ca-rfc822.der")
        .expect("no otherName constraint is in effect and this is not an SmtpUTF8Mailbox");
}

/// An `emailAddress` attribute that cannot be decoded is only a problem
/// when a mailbox constraint is in effect.
///
/// PKCS #9 defines `emailAddress` as IA5String. `pkix-path` cannot check
/// any other encoding against an rfc822Name constraint, so it fails closed
/// -- but only after deciding the constraint applies. The guard is
/// `forms_in_effect.intersects(RFC822) && !subject_is_empty`; loosen it to
/// either and the subject walk runs for every certificate with a subject,
/// so this leaf is refused although no rule names its mailbox.
///
/// An `emailAddress` carried as UTF8String is a known CA misissuance, not
/// an invented shape, and a validator that rejected those under a
/// dNSName-only constraint would be refusing certificates RFC 5280 does
/// not let it refuse.
#[test]
fn an_undecodable_email_attribute_passes_with_no_mailbox_constraint() {
    run("leaf-utf8-email-under-dns.der", "ca-dns.der").expect(
        "no rfc822Name constraint is in effect, so the subject's emailAddress \
         is not under examination",
    );
}

/// A `registeredID` the matchers cannot evaluate is refused under an
/// *excluded* subtree of that form.
///
/// Under a permitted subtree an unevaluable form is refused twice over:
/// step (0) refuses it, and had step (0) not run, the generic permitted
/// check refuses it anyway -- a name the matchers cannot decide matches no
/// subtree, and a constrained type matching nothing is a violation. So
/// `a_registered_id_is_refused_under_a_registered_id_constraint` above
/// cannot tell whether step (0) ran at all.
///
/// An excluded subtree inverts that. The generic excluded check asks
/// whether the name *matches* a subtree; a name it cannot decide matches
/// none, so it raises no violation and the certificate passes. Step (0) is
/// the only thing standing between a CA that said "never this
/// registeredID" and a certificate carrying exactly that registeredID --
/// RFC 5280 §4.2.1.10's requirement to reject rather than to shrug.
#[test]
fn a_registered_id_is_refused_under_an_excluded_registered_id_subtree() {
    let err = run("leaf-regid-under-excl-regid.der", "ca-excl-regid.der")
        .expect_err("an excluded registeredID subtree is in effect and cannot be evaluated");
    assert!(
        matches!(err, Error::NameConstraintViolation { .. }),
        "expected a name-constraint violation, got {err:?}"
    );
}

/// A `SmtpUTF8Mailbox` whose domain is not ASCII cannot be compared with an
/// rfc822Name subtree, so it fails closed.
///
/// RFC 8398 §6 routes these through the rfc822Name constraints, and the
/// comparison is over ASCII domains: a U-label domain is not the A-label
/// one a constraint carries, and treating the two as comparable would be
/// guessing. The excluded direction is what makes the guard load-bearing
/// --- a mailbox that cannot be compared matches no excluded subtree, so
/// dropping the ASCII requirement admits it.
///
/// Neither mailbox here is under the excluded `example.com`, so neither
/// matches the exclusion. That is the point: the pair differs only in
/// whether its domain is ASCII. A non-ASCII domain that *was* a subdomain
/// of the excluded one would be refused by the comparison regardless, and
/// would prove nothing about the guard.
#[test]
fn a_non_ascii_mailbox_domain_cannot_be_compared_and_is_refused() {
    run(
        "leaf-utf8mb-ascii-under-excl-rfc822.der",
        "ca-excl-rfc822.der",
    )
    .expect("an ASCII mailbox outside the excluded subtree is comparable and permitted");

    let err = run(
        "leaf-utf8mb-nonascii-under-excl-rfc822.der",
        "ca-excl-rfc822.der",
    )
    .expect_err("a U-label domain cannot be compared with an rfc822Name subtree");
    assert!(
        matches!(err, Error::NameConstraintViolation { .. }),
        "expected a name-constraint violation, got {err:?}"
    );
}
