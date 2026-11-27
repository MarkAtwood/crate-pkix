//! RFC 5280 §4.2: "A certificate MUST NOT include more than one instance of
//! a particular extension."
//!
//! `check_duplicate_extensions` enforces it, and had no test and no fixture.
//! A mutation sweep could delete the whole function, and could turn its
//! `exts.len() < 2` early return into `<= 2` or `== 2` — letting through a
//! certificate with exactly two extensions that are the same one twice —
//! with the suite still green.
//!
//! Fixtures: `tests/fixtures/dup-ext/` (see `gen.py`). `cryptography`
//! refuses to build such a certificate, correctly, so the TBSCertificate is
//! rebuilt at the DER level and re-signed: `chain_walk` verifies the
//! signature before it reads extensions, so an unsigned splice would be
//! rejected for the wrong reason and prove nothing.

use der::Decode as _;
use pkix_path::{validate_path, DefaultVerifier, Error, TrustAnchor, ValidationPolicy};
use x509_cert::Certificate;

const NOW: u64 = 1_800_000_000; // 2027-01-15

fn load(name: &str) -> Certificate {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/dup-ext")
        .join(format!("{name}.der"));
    Certificate::from_der(&std::fs::read(&p).expect("fixture present")).expect("parses")
}

fn run(leaf: &str) -> pkix_path::Result<pkix_path::ValidatedPath> {
    validate_path(
        &[load(leaf)],
        &[TrustAnchor::from_cert(load("dup-ext-root"))],
        &ValidationPolicy::new(NOW),
        &DefaultVerifier,
    )
}

/// Two instances of one extension make the certificate malformed.
///
/// The leaf carries `basicConstraints` twice and nothing else, so it has
/// exactly two extensions — the width at which the `< 2` early return's
/// mutations become visible. A cert with three would be caught even by
/// `<= 2`.
#[test]
fn a_duplicated_extension_is_malformed() {
    assert_eq!(
        run("dup-ext-leaf").err(),
        Some(Error::MalformedCertificate { index: 0 }),
        "basicConstraints appears twice"
    );
}

/// The same leaf without the duplicate validates.
///
/// This is what makes the test above about the duplicate rather than about
/// the hand-rebuilt DER or the re-signature: `dup-ext-ok` is the certificate
/// `dup-ext-leaf` was derived from.
#[test]
fn the_same_leaf_without_the_duplicate_validates() {
    run("dup-ext-ok").expect("one basicConstraints is fine");
}
