//! How `check_revocation_against_anchor` picks the CRL's effective signer,
//! and the RFC 5280 §6.3.3 domain check that goes with it.
//!
//! The method branches on the pairing of a caller-supplied `cRLIssuer`
//! certificate with the CRL's own `indirectCRL` flag, and then applies three
//! name checks. Two of its four arms and the whole third name check had no
//! test: `crl_checker_tests.rs` drives this method only with a plain
//! `CrlChecker::new` over a direct CRL, which is one arm of the four.
//!
//! The third check is the one worth the trouble. Its comment in the source
//! says why it is not a restatement of the first two:
//!
//! > Without the discovery arm, (2a) and (2b) together imply this -- both
//! > sides reduce to the anchor's subject. Under discovery they do not:
//! > (2a) ties the CRL issuer to the *discovered* signer's subject while
//! > (2b) ties the cert to the anchor, leaving the two free to disagree.
//!
//! Which means every input that reaches it through a non-discovery checker
//! finds it already satisfied, and only a discovery-mode or separate-issuer
//! CRL tells the three conjuncts apart.
//!
//! Fixture rationale: `tests/fixtures/indirect-crl-crlsign/gen.py`.

#![cfg(feature = "crl")]

use der::Decode as _;
use pkix_path::{DefaultVerifier, TrustAnchor};
use pkix_revocation::{CrlChecker, Error, RevocationChecker as _};
use x509_cert::Certificate;

const NOW: u64 = 1_780_272_000;
const DIR: &str = "tests/fixtures/indirect-crl-crlsign";

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(DIR)
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn load(name: &str) -> Certificate {
    Certificate::from_der(&fixture(name)).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

fn anchor() -> TrustAnchor {
    TrustAnchor::from_cert(load("ca.der"))
}

/// An indirect CRL with a separate cRLIssuer, checked against the anchor
/// that issued the certificate.
///
/// Here the CRL's issuer and the certificate's issuer are different DNs by
/// design -- that is what "indirect" means -- so the third name check must
/// not be looking at the two of them. Require it unconditionally and the
/// whole indirect-CRL case stops working on the anchor path.
#[test]
fn an_indirect_crl_with_a_separate_issuer_is_usable_against_the_anchor() {
    let checker = CrlChecker::new_with_crl_issuer(
        fixture("indirect-crl.der"),
        load("crl-issuer-with-crlsign.der"),
        NOW,
        DefaultVerifier,
    )
    .expect("fixture is a valid DER-encoded CRL");

    checker
        .check_revocation_against_anchor(&load("leaf.der"), &anchor())
        .expect("an indirect CRL from the named cRLIssuer covers this certificate");
}

/// A caller-supplied cRLIssuer against a CRL that does not declare itself
/// indirect is a contradiction, and says so.
///
/// This is the arm the `signer_discovered` guard separates from the
/// discovery case. Treat a non-discovered issuer as discovered and the
/// contradiction is accepted instead: the supplied certificate becomes the
/// effective signer, and the refusal that follows blames the names rather
/// than the pairing.
#[test]
fn a_supplied_issuer_on_a_direct_crl_is_a_contradiction() {
    let checker = CrlChecker::new_with_crl_issuer(
        fixture("direct-crl.der"),
        load("crl-issuer-with-crlsign.der"),
        NOW,
        DefaultVerifier,
    )
    .expect("fixture is a valid DER-encoded CRL");

    let r = checker.check_revocation_against_anchor(&load("leaf.der"), &anchor());
    assert!(
        matches!(r, Err(Error::IndirectCrlIssuerUnexpected)),
        "a cRLIssuer supplied for a CRL that is not indirect must be \
         reported as such, got: {r:?}"
    );
}

/// Discovery mode on the anchor path, with a direct CRL.
///
/// The discovered signer is authoritative whatever the CRL's `indirectCRL`
/// flag says, which is what the `signer_discovered` guard admits. Without
/// it the same call reports `IndirectCrlIssuerUnexpected`, because a
/// discovered signer is held in the same field a caller-supplied one is.
///
/// This is also the input that tells the third name check's conjuncts
/// apart: discovery is on, the CRL is direct, and the two issuers do agree,
/// so the check must pass -- and it is the only combination where all three
/// conjuncts are individually load-bearing.
#[test]
fn a_discovered_signer_is_authoritative_against_the_anchor() {
    let ca = load("ca.der");
    let bundle = [ca.clone()];
    let checker = CrlChecker::new_with_signer_discovery(
        fixture("direct-crl.der"),
        &bundle,
        NOW,
        DefaultVerifier,
    )
    .expect("the CA signs its own CRL and is self-signed");

    checker
        .check_revocation_against_anchor(&load("leaf.der"), &anchor())
        .expect("the discovered signer is the anchor itself");
}

/// Discovery mode on the anchor path, with an indirect CRL whose issuer is
/// a different DN.
///
/// The combination the third name check must *not* fire on: discovery is
/// on, so its first conjunct holds, but the CRL declares itself indirect,
/// so the second refuses. Drop the negation there and this legitimate
/// pairing is reported as a mismatch.
#[test]
fn a_discovered_signer_on_an_indirect_crl_is_not_a_domain_violation() {
    let bundle = [load("crl-issuer-with-crlsign.der"), load("ca.der")];
    let checker = CrlChecker::new_with_signer_discovery(
        fixture("indirect-crl.der"),
        &bundle,
        NOW,
        DefaultVerifier,
    )
    .expect("the cRLIssuer is in the bundle and reaches a self-signed certificate");

    checker
        .check_revocation_against_anchor(&load("leaf.der"), &anchor())
        .expect("an indirect CRL's issuer is expected to differ from the certificate's");
}
