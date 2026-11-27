//! `ValidationPolicy::require_rfc822_san` — chain_walk step (e4).
//!
//! The flag had no behavioural test. Only `serde_round_trip.rs` set it, to
//! check that it survives serialization, so a mutation deleting the `!` in
//! `if !has_rfc822` — accepting leaves *without* an rfc822Name SAN and
//! rejecting the ones that have it — left the whole suite green. So did
//! turning the guard's `&&` into `||`.
//!
//! Fixtures: `tests/fixtures/rfc822-san/` (see `gen.py`). A self-contained
//! chain rather than additions to `policy-checks/`, whose generator
//! randomises every key per run.

use der::Decode as _;
use pkix_path::{validate_path, DefaultVerifier, Error, TrustAnchor, ValidationPolicy};
use x509_cert::Certificate;

const NOW: u64 = 1_800_000_000; // 2027-01-15, inside the fixtures' window

fn load(name: &str) -> Certificate {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rfc822-san")
        .join(format!("{name}.der"));
    Certificate::from_der(&std::fs::read(&p).expect("fixture present")).expect("parses")
}

/// `require_subject_alt_name` and `require_rfc822_san` both on, which is the
/// only configuration under which (e4) is consulted.
fn strict() -> ValidationPolicy {
    let mut p = ValidationPolicy::new(NOW);
    p.require_subject_alt_name = true;
    p.require_rfc822_san = true;
    p
}

fn run(leaf: &str, policy: &ValidationPolicy) -> pkix_path::Result<pkix_path::ValidatedPath> {
    validate_path(
        &[load(leaf), load("rfc822-int")],
        &[TrustAnchor::from_cert(load("rfc822-root"))],
        policy,
        &DefaultVerifier,
    )
}

/// A leaf whose SAN carries an rfc822Name satisfies the requirement.
#[test]
fn an_rfc822_san_satisfies_the_requirement() {
    run("rfc822-leaf-email", &strict()).expect("SAN = rfc822Name:user@example.com");
}

/// A leaf whose SAN is present and non-empty but carries no rfc822Name does
/// not.
///
/// The SAN exists here, so this is step (e4) and not the non-empty-SAN check
/// at (e2) — which is what makes it the input that distinguishes the two.
#[test]
fn a_dns_only_san_does_not_satisfy_the_requirement() {
    assert_eq!(
        run("rfc822-leaf-dns", &strict()).err(),
        Some(Error::MissingRfc822San),
        "SAN = dNSName only; (e2) is satisfied and (e4) is not"
    );
}

/// With the flag off, the dNSName-only leaf validates.
///
/// Without this, the test above could pass because the chain is broken for
/// some reason unrelated to the SAN — a bad signature, a name-constraint
/// violation, an expired certificate.
#[test]
fn the_same_leaf_validates_when_the_flag_is_off() {
    let mut p = ValidationPolicy::new(NOW);
    p.require_subject_alt_name = true;
    run("rfc822-leaf-dns", &p).expect("only require_rfc822_san rejected it");
}

/// The flag is inert unless `require_subject_alt_name` is also set.
///
/// That is what the guard's `&&` encodes, and the comment on (e4) states it:
/// the rule is "only meaningful (and checked) when require_subject_alt_name
/// is also true". With `||` the flag would act on its own.
#[test]
fn the_flag_is_inert_without_require_subject_alt_name() {
    let mut p = ValidationPolicy::new(NOW);
    p.require_rfc822_san = true;
    // require_subject_alt_name left false.
    run("rfc822-leaf-dns", &p).expect("require_rfc822_san alone must not reject");
}

// ---------------------------------------------------------------------------
// require_crl_sign_on_cas: the positive half
// ---------------------------------------------------------------------------

/// A CA that *does* assert cRLSign still validates under the opt-in.
///
/// `pkits_4_7_4_crl_sign_flag_toggles_outcome` covers the rejection, but its
/// certificate genuinely lacks cRLSign — so mutating `has_crl_sign` to
/// return `Some(false)` unconditionally produces the same verdict for that
/// input and the test stays green. Nothing showed that the flag does not
/// simply reject every CA, which is the failure a caller enabling it would
/// actually hit.
///
/// The fixtures in `rfc822-san/` assert `keyCertSign` and `cRLSign`, so they
/// serve as the positive case.
#[test]
fn a_ca_asserting_crl_sign_validates_under_the_opt_in() {
    let mut p = ValidationPolicy::new(NOW);
    p.require_crl_sign_on_cas = true;
    run("rfc822-leaf-email", &p).expect("root and intermediate both assert cRLSign");
}
