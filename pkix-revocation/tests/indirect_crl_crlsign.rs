//! RFC 5280 §6.3.3(f): a CRL issuer with a KeyUsage extension must assert
//! `cRLSign`.
//!
//! `check_crl_sign` enforces that, and it runs on one path only. The direct
//! case checks the certificate's own issuer, which is trusted to sign its
//! own CRL; the anchor case skips it, because an anchor is trusted by
//! construction. Only a separate cRLIssuer -- an indirect CRL -- reaches
//! it, and nothing in the suite built one with a non-conforming signer.
//! `Error::CrlSignMissing` had no test anywhere: the check could return
//! `Ok(())` for everything, and an indirect CRL signed by a certificate not
//! authorised to sign CRLs would have been accepted.
//!
//! Fixture rationale: `tests/fixtures/indirect-crl-crlsign/gen.py`. The two
//! candidate issuer certificates share a subject DN and a public key, so
//! the KeyUsage bit is the only difference between the accepting and the
//! refusing case.

#![cfg(feature = "crl")]

use der::Decode as _;
use pkix_path::DefaultVerifier;
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

fn check(issuer_cert: &str) -> pkix_revocation::Result<()> {
    let checker = CrlChecker::new_with_crl_issuer(
        fixture("indirect-crl.der"),
        load(issuer_cert),
        NOW,
        DefaultVerifier,
    )
    .expect("fixture is a valid DER-encoded CRL");
    checker.check_revocation(&load("leaf.der"), &load("ca.der"))
}

/// The control. With `cRLSign` asserted the indirect CRL is usable, so the
/// refusal below is attributable to the KeyUsage bit and not to the CRL,
/// the signature, the names or the window.
#[test]
fn an_indirect_crl_issuer_asserting_crl_sign_is_accepted() {
    check("crl-issuer-with-crlsign.der").expect("a cRLIssuer asserting cRLSign must be accepted");
}

/// The rule itself.
#[test]
fn an_indirect_crl_issuer_without_crl_sign_is_refused() {
    let r = check("crl-issuer-no-crlsign.der");
    assert!(
        matches!(r, Err(Error::CrlSignMissing)),
        "a cRLIssuer whose KeyUsage omits cRLSign must be refused with \
         CrlSignMissing, got: {r:?}"
    );
}

/// A discovered signer on an indirect CRL is not a domain violation on the
/// issuer path either.
///
/// `check_revocation` applies the same RFC 5280 §6.3.3 domain check the
/// anchor path does, under a condition that has to admit three situations
/// and refuse one:
///
///     crl_issuer_cert.is_none() || (signer_discovered && !indirect)
///
/// Loosen the inner conjunction to a disjunction and discovery mode alone
/// switches the check on, which refuses every indirect CRL found by
/// discovery -- their issuer DN differs from the certificate's by design,
/// which is what indirect means.
///
/// `anchor_path_signer.rs` covers the same rule against a `TrustAnchor`;
/// this is its twin on the entry point that takes an issuer certificate,
/// and the condition is written out separately in each.
#[test]
fn a_discovered_signer_on_an_indirect_crl_passes_the_domain_check() {
    let bundle = [load("crl-issuer-with-crlsign.der"), load("ca.der")];
    let checker = CrlChecker::new_with_signer_discovery(
        fixture("indirect-crl.der"),
        &bundle,
        NOW,
        DefaultVerifier,
    )
    .expect("the cRLIssuer is in the bundle and reaches a self-signed certificate");

    checker
        .check_revocation(&load("leaf.der"), &load("ca.der"))
        .expect("an indirect CRL's issuer is expected to differ from the certificate's");
}
