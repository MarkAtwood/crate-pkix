//! RFC 5280 §6.3.3(b)(1): a distribution point says which DN issues its
//! CRLs, and matching distribution-point names are not enough.
//!
//! `check_dp_scope` walks a certificate's `cRLDistributionPoints` and asks
//! that question per distribution point. Two match guards decide it, and
//! both are reachable only when the names would otherwise agree -- so every
//! fixture where the names differ is refused by the name half of the rule
//! and proves nothing about either guard. The PKITS vectors in
//! `crl_dp_selection.rs` are all of that kind.
//!
//! The fixtures here name the same distribution point on both sides,
//! deliberately, so the issuer question is the only thing left to refuse
//! on. Fixture rationale: `tests/fixtures/dp-scope/gen.py`.

#![cfg(feature = "crl")]

use der::Decode as _;
use pkix_revocation::{crl_applies_to, Error, OutOfScopeReason};
use x509_cert::Certificate;

const DIR: &str = "tests/fixtures/dp-scope";

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(DIR)
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn load(name: &str) -> Certificate {
    Certificate::from_der(&fixture(name)).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

/// A distribution point with no `cRLIssuer` speaks for the certificate's own
/// issuer and for nobody else.
///
/// The CRL here is indirect, so `crl_applies_to`'s own issuer gate -- which
/// covers direct CRLs -- does not apply, and the distribution-point names
/// match. All that separates this CRL from being in scope is the guard
/// asking whether the CRL's issuer is the certificate's issuer. Without it,
/// any CA that publishes an indirect CRL naming a distribution point can
/// claim to speak about certificates it never issued.
///
/// The reason is the specific one: nothing matched on the *issuer* half, as
/// against the distribution-point half.
#[test]
fn an_indirect_crl_from_another_ca_is_out_of_scope() {
    let leaf = load("leaf-dp-no-crlissuer.der");
    let r = crl_applies_to(&leaf, &fixture("indirect-crl-from-b.der"));
    assert!(
        matches!(
            r,
            Err(Error::OutOfScope(
                OutOfScopeReason::CrlDistributionPointIssuerMismatch
            ))
        ),
        "a distribution point naming no cRLIssuer speaks only for the \
         certificate's issuer, got: {r:?}"
    );
}

/// The control: the same distribution point, and a CRL from the certificate's
/// own issuer, does apply.
///
/// Without it the test above would pass for a predicate that refused
/// everything.
#[test]
fn a_direct_crl_from_the_certificates_issuer_applies() {
    let leaf = load("leaf-dp-no-crlissuer.der");
    crl_applies_to(&leaf, &fixture("direct-crl-from-a.der"))
        .expect("the certificate's own issuer published this CRL at this distribution point");
}

/// A distribution point that names a `cRLIssuer` speaks only for an indirect
/// CRL.
///
/// RFC 5280 ties `cRLIssuer` to indirect CRLs: naming one is how a
/// certificate says "my revocation status is published by someone else".
/// Here the named `cRLIssuer` is the certificate's own issuer and the CRL
/// comes from that issuer with matching distribution-point names, so
/// everything agrees except that the CRL does not declare itself indirect
/// -- which is exactly what the guard tests.
#[test]
fn a_named_crl_issuer_does_not_admit_a_direct_crl() {
    let leaf = load("leaf-dp-with-crlissuer.der");
    let r = crl_applies_to(&leaf, &fixture("direct-crl-from-a.der"));
    assert!(
        matches!(
            r,
            Err(Error::OutOfScope(
                OutOfScopeReason::CrlDistributionPointIssuerMismatch
            ))
        ),
        "a distribution point naming a cRLIssuer applies only to an indirect \
         CRL, got: {r:?}"
    );
}

/// Satisfying the `indirectCRL` flag is not enough either: the named
/// `cRLIssuer` still has to be the CRL's issuer.
///
/// Both halves have to hold, and the test above moves only the flag. This
/// one moves only the issuer, so between them neither half can be dropped
/// while the other covers for it.
#[test]
fn a_named_crl_issuer_still_refuses_a_crl_from_someone_else() {
    let leaf = load("leaf-dp-with-crlissuer.der");
    // The named cRLIssuer is CA-A, so CA-B's indirect CRL is still out of
    // scope; what this asserts is that the refusal moved to the name half
    // once the indirect flag was satisfied.
    let r = crl_applies_to(&leaf, &fixture("indirect-crl-from-b.der"));
    assert!(
        matches!(
            r,
            Err(Error::OutOfScope(
                OutOfScopeReason::CrlDistributionPointIssuerMismatch
            ))
        ),
        "CA-B is not the named cRLIssuer, got: {r:?}"
    );
}
