//! RFC 6960 §4.1.1: a `CertID` names the certificate asked about by two
//! hashes, and both have to match.
//!
//! `OcspChecker` recomputes the issuer-name hash and the issuer-key hash
//! from the issuer it was handed and refuses the response unless both
//! agree with the `CertID` -- a disjunction, so either mismatch alone is
//! fatal. Noticing a weakening of it needs a response that matches one
//! hash and not the other, and the existing cross-CA fixtures differ in
//! both, so either form of the test refuses them.
//!
//! `ca-case` is that response's one reachable counter-case: an issuer
//! whose subject is the same name under RFC 4518 case folding but a
//! different DER encoding, sharing the real issuer's key. It passes the
//! responder-id match and the signature check, and only the hash notices,
//! because `issuerNameHash` is over the DER. The response does not name
//! this certificate, and refusing it is what stops one response being
//! reused across two encodings of a single name.
//!
//! The mirror -- a matching name hash with a mismatched key -- is not
//! reachable, and no fixture makes it so. The response signature and the
//! delegated-responder validation both run before the CertID comparison
//! and both need the issuer's key, so an issuer whose key hash differs is
//! already refused: `OcspSignatureInvalid` for a DN twin with another key,
//! `OcspIssuerCertMismatch` for a differently named issuer. Only the
//! name-hash half of the disjunction is live, which is enough to pin it.
//!
//! Both comparisons appear twice in the crate, once per entry point, so
//! both are driven here.
//!
//! The `CertID` algorithm is SHA-1, which every deployed responder emits
//! and no other fixture here uses. It is identity matching, not a
//! signature: the hash says which certificate is being asked about. The
//! response signature is ECDSA with SHA-256.
//!
//! Fixture rationale: `tests/fixtures/ocsp-certid-binding/gen.py`.

#![cfg(feature = "ocsp")]

use der::Decode as _;
use pkix_path::{DefaultVerifier, TrustAnchor};
use pkix_revocation::{Error, OcspChecker, RevocationChecker as _};
use x509_cert::Certificate;
use x509_ocsp::{BasicOcspResponse, OcspResponse};

const DIR: &str = "tests/fixtures/ocsp-certid-binding";

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(DIR)
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn load(name: &str) -> Certificate {
    Certificate::from_der(&fixture(name)).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

/// `producedAt` of the fixture response, which is generation time. Using it
/// as `now` keeps the tests valid across a regeneration.
fn produced_at() -> u64 {
    let resp = OcspResponse::from_der(&fixture("response.der")).expect("fixture decodes");
    let bytes = resp
        .response_bytes
        .as_ref()
        .expect("fixture carries responseBytes");
    let basic =
        BasicOcspResponse::from_der(bytes.response.as_bytes()).expect("BasicOcspResponse decodes");
    basic
        .tbs_response_data
        .produced_at
        .as_ref()
        .to_unix_duration()
        .as_secs()
}

fn checker() -> OcspChecker<DefaultVerifier> {
    OcspChecker::new(fixture("response.der"), produced_at(), DefaultVerifier)
        .expect("fixture is a valid DER-encoded OcspResponse")
}

/// The control, and the only test in the crate that drives a SHA-1
/// `CertID`: against the issuer the response was produced for, both hashes
/// match and the status is reported.
#[test]
fn a_sha1_certid_matches_the_issuer_it_was_produced_for() {
    let leaf = load("leaf.der");
    let ca = load("ca-key1.der");
    checker()
        .check_revocation(&leaf, &ca)
        .expect("the response names this issuer");
    checker()
        .check_revocation_against_anchor(&leaf, &TrustAnchor::from(&ca))
        .expect("the response names this anchor");
}

/// An issuer whose subject folds to the same name but encodes to
/// different bytes.
///
/// Every check before the CertID comparison passes -- `names_match` folds
/// case, and the shared key verifies the signature -- so this is the one
/// shape that reaches the comparison with exactly one hash wrong.
#[test]
fn a_case_variant_issuer_name_does_not_bind_the_response() {
    let leaf = load("leaf.der");
    let variant = load("ca-case.der");
    let real = load("ca-key1.der");
    assert_ne!(
        variant.tbs_certificate().subject(),
        real.tbs_certificate().subject(),
        "fixture premise: the subjects differ as DER"
    );
    assert_eq!(
        variant.tbs_certificate().subject_public_key_info(),
        real.tbs_certificate().subject_public_key_info(),
        "fixture premise: the key is the same, so the signature still verifies"
    );

    for r in [
        checker().check_revocation(&leaf, &variant),
        checker().check_revocation_against_anchor(&leaf, &TrustAnchor::from(&variant)),
    ] {
        assert!(
            matches!(r, Err(Error::OcspCertIdMismatch)),
            "a CertID is a byte binding; an equivalent name that encodes \
             differently must not satisfy it, got: {r:?}"
        );
    }
}
