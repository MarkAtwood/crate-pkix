//! RFC 5280 §4.2.1.6: an issuer identified by its SAN rather than its DN.
//!
//! `cert_has_san_identity` decides this, and `check_issuer_linkage` skips the
//! §6.1.3(a)(2) DN comparison entirely when it holds. Four mutations of that
//! function survived the suite, so nothing distinguished "this issuer is
//! SAN-identified" from "it is not".
//!
//! The two chains here are different on purpose: the mutations need
//! different inputs. Chain A has an empty-subject issuer, which is the case
//! the accommodation exists for. Chain B has a *named* issuer that also
//! carries a critical SAN, which must still have its linkage checked —
//! without that case, deleting the `!` in the empty-subject guard would skip
//! linkage for every certificate with a critical SAN and nothing would
//! notice.
//!
//! Fixtures: `tests/fixtures/san-identity/` (see `gen.py`).

use der::Decode as _;
use pkix_path::{validate_path, DefaultVerifier, Error, TrustAnchor, ValidationPolicy};
use x509_cert::Certificate;

const NOW: u64 = 1_800_000_000; // 2027-01-15

fn load(name: &str) -> Certificate {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/san-identity")
        .join(format!("{name}.der"));
    Certificate::from_der(&std::fs::read(&p).expect("fixture present")).expect("parses")
}

fn run(leaf: &str, int_cert: &str) -> pkix_path::Result<pkix_path::ValidatedPath> {
    validate_path(
        &[load(leaf), load(int_cert)],
        &[TrustAnchor::from_cert(load("si-root"))],
        &ValidationPolicy::new(NOW),
        &DefaultVerifier,
    )
}

/// An empty-subject issuer with a critical SAN: linkage is skipped.
///
/// §4.2.1.6 makes the SAN the certificate's identity when the Subject is an
/// empty sequence, so comparing the child's issuer field against an empty DN
/// says nothing. The leaf here names `CN=si other` as its issuer, which is
/// not the (empty) subject of the certificate that signed it, and the chain
/// validates only because the comparison is skipped.
///
/// The signature still binds the leaf to that issuer's key — that is what
/// makes skipping the DN check safe rather than merely lenient.
#[test]
fn an_empty_subject_issuer_with_a_critical_san_skips_dn_linkage() {
    run("si-leaf-empty", "si-int-empty")
        .expect("the issuer is SAN-identified, so the DN comparison is skipped");
}

/// A *named* issuer with a critical SAN still has its linkage checked.
///
/// A critical SAN on a CA is unusual but legal, and it does not make the
/// Subject DN meaningless — only an empty Subject does. Deleting the `!` in
/// `if !subject.is_empty()` inverts exactly that, treating every
/// critical-SAN certificate as SAN-identified and skipping linkage for all
/// of them. This leaf names the same wrong issuer as the one above and must
/// be refused.
#[test]
fn a_named_issuer_with_a_critical_san_still_checks_dn_linkage() {
    assert_eq!(
        run("si-leaf-named", "si-int-named").err(),
        Some(Error::ChainBroken { index: 0 }),
        "the issuer has a Subject DN, so the leaf's issuer field must match it"
    );
}

/// An empty subject with a *non-critical* SAN is not SAN-identified.
///
/// §4.2.1.6 requires the SAN to be marked critical when the Subject is an
/// empty sequence, so this certificate is non-conformant and
/// `cert_has_san_identity` documents itself as rejecting it: "Returns
/// `false` for any cert that has a non-empty Subject or a non-critical SAN."
/// Linkage therefore runs, and this leaf's wrong issuer DN is caught.
///
/// This is the chain that distinguishes *which* extension the function looks
/// at. The issuers in the two chains above carry critical `basicConstraints`
/// and `keyUsage`, so flipping the OID comparison to `!=` — or the `&&` to
/// `||` — still reports SAN-identity from those, and both chains pass either
/// way. Here the only SAN is non-critical, so a mutation that accepts any
/// critical extension skips linkage and lets the wrong issuer through.
#[test]
fn an_empty_subject_with_a_non_critical_san_is_not_san_identified() {
    assert_eq!(
        run("si-leaf-noncrit", "si-int-noncrit").err(),
        Some(Error::ChainBroken { index: 0 }),
        "a non-critical SAN does not make the issuer SAN-identified"
    );
}
