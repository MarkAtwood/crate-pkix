//! Validating attribute certificates: profile rules, validity,
//! signature, holder matching.
//!
//! Fixtures: `tests/fixtures/gen.py`, plus the Attribute Authority
//! certificate and holder certificate borrowed from `pkix-ct`'s oracle
//! fixtures so the AA has a real key and a chain `pkix-path` could
//! validate.

use der::Decode as _;
use pkix_ac::{AttributeCertificate, Error, ProfileViolation};
use pkix_path::DefaultVerifier;
use x509_cert::Certificate;

/// Inside the fixtures' window, which runs 2025-01-01 to 2026-01-01.
const NOW: u64 = 1_767_225_600; // 2026-01-01T00:00:00Z minus a day

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn ct_fixture(name: &str) -> Certificate {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../pkix-ct/tests/fixtures/sct-oracle")
        .join(name);
    let der = std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
    Certificate::from_der(&der).expect("fixture parses")
}

/// The Attribute Authority: the certificate whose key signed the ACs.
fn aa() -> Certificate {
    ct_fixture("precert-issuer.der")
}

/// The holder: the entity the ACs name in `entityName`.
fn holder() -> Certificate {
    ct_fixture("precert-leaf-final.der")
}

fn ac(name: &str) -> AttributeCertificate {
    AttributeCertificate::from_der(&fixture(name)).expect("parses")
}

/// The whole point: a real signature, made by a separate tool with a
/// real key, verifies.
///
/// This is what the parse tests cannot establish. They show the bytes
/// are read as the RFC lays them out; this shows the bytes handed to the
/// verifier are the ones `openssl dgst` signed.
#[test]
fn a_well_formed_attribute_certificate_verifies() {
    let ac = ac("ac-role-valid.der");
    ac.check_profile()
        .expect("conforms to the RFC 5755 profile");
    ac.verify(&aa(), NOW, &DefaultVerifier)
        .expect("the AA's own key must verify its signature");
}

/// One flipped byte in the signature must be refused. Without this the
/// test above would pass against a verifier that accepted anything.
#[test]
fn a_tampered_signature_is_refused() {
    let mut der = fixture("ac-role-valid.der");
    let last = der.len() - 1;
    der[last] ^= 0x01;
    let ac = AttributeCertificate::from_der(&der).expect("still parses");
    assert_eq!(
        ac.verify(&aa(), NOW, &DefaultVerifier),
        Err(Error::SignatureInvalid)
    );
}

/// A flipped byte inside `acinfo` must also be refused — the signature
/// covers it, so changing it invalidates the signature even though the
/// signature bytes themselves are untouched.
#[test]
fn tampering_with_the_signed_content_is_refused() {
    let der = fixture("ac-role-valid.der");
    let ac = AttributeCertificate::from_der(&der).expect("parses");
    let signed = ac.signed_bytes().to_vec();

    let offset = der
        .windows(signed.len())
        .position(|w| w == signed.as_slice())
        .expect("acinfo must appear in the certificate's own bytes");
    let mut tampered = der.clone();
    // Near the end of acinfo, inside the role URI. Deliberately not the
    // middle: that lands in the issuer name, and the issuer check runs
    // before the signature check, so the tamper would be refused as
    // IssuerMismatch and never exercise the signature at all. Picking
    // the wrong byte here is how this test would quietly stop testing
    // what it claims to.
    tampered[offset + signed.len() - 6] ^= 0x01;

    match AttributeCertificate::from_der(&tampered) {
        // Either the edit broke the DER, which is a fine outcome...
        Err(Error::ParseError) => {}
        // ...or it still parses, and then the signature must fail.
        Ok(ac) => assert_eq!(
            ac.verify(&aa(), NOW, &DefaultVerifier),
            Err(Error::SignatureInvalid),
            "a change inside acinfo must invalidate the signature, and must \
             reach the signature check rather than being refused earlier"
        ),
        Err(other) => panic!("unexpected error: {other:?}"),
    }
}

/// `signed_bytes` must be a slice of the original certificate, not a
/// re-encoding of the parsed structure. If it were re-encoded, an
/// encoder that did not reproduce its input would silently verify the
/// wrong bytes — the failure `pkix-ct` hit this morning.
#[test]
fn the_signed_bytes_come_from_the_original_der() {
    let der = fixture("ac-role-valid.der");
    let ac = AttributeCertificate::from_der(&der).expect("parses");
    let signed = ac.signed_bytes();
    assert_eq!(
        der.windows(signed.len()).filter(|w| *w == signed).count(),
        1,
        "acinfo must occur exactly once in the certificate's own bytes"
    );
    assert!(signed.len() < der.len(), "acinfo is a part, not the whole");
}

/// Verifying against the wrong authority must fail on the issuer name,
/// before any cryptography — the signature check alone would accept an
/// AC issued by one authority if the caller passed another's
/// certificate and the keys happened to match.
#[test]
fn the_wrong_authority_is_refused_by_name() {
    let ac = ac("ac-role-valid.der");
    // The holder's certificate is a real certificate with a real key,
    // and it is not the AA.
    assert_eq!(
        ac.verify(&holder(), NOW, &DefaultVerifier),
        Err(Error::IssuerMismatch)
    );
}

/// Expiry and the not-yet-valid case are distinct answers, as they are
/// for public-key certificates.
#[test]
fn the_validity_window_is_enforced_at_both_ends() {
    let expired = ac("ac-expired.der");
    assert_eq!(
        expired.verify(&aa(), NOW, &DefaultVerifier),
        Err(Error::Expired)
    );

    let valid = ac("ac-role-valid.der");
    // 2020-01-01, before the fixture's notBefore of 2025-01-01.
    assert_eq!(
        valid.verify(&aa(), 1_577_836_800, &DefaultVerifier),
        Err(Error::NotYetValid)
    );
}

/// The holder is named by `entityName` in these fixtures, and must match
/// the certificate of the entity presenting the AC.
#[test]
fn the_holder_is_matched_by_name() {
    let ac = ac("ac-role-valid.der");
    assert!(
        ac.matches_holder(&holder()),
        "the AC names this entity as its holder"
    );
    assert!(
        !ac.matches_holder(&aa()),
        "the authority is not the holder of its own attribute certificate"
    );
}

/// `attributes` is a `SEQUENCE OF`, so order is part of the value.
#[test]
fn attributes_are_returned_in_order() {
    let ac = ac("ac-two-roles.der");
    assert_eq!(ac.attributes().len(), 2);
    ac.check_profile().expect("two roles still conform");
    ac.verify(&aa(), NOW, &DefaultVerifier)
        .expect("the two-role certificate is signed too");
}

/// The profile checks must actually fire, and must say which rule broke.
///
/// Both fixtures parse — the §4.1 syntax permits what the §4.2 profile
/// forbids, which is exactly why parsing and profile checking are
/// separate steps. A test that only confirmed they parsed would be
/// testing the wrong half.
#[test]
fn a_v1form_issuer_parses_and_is_refused_by_the_profile() {
    let ac = ac("ac-issuer-v1form.der");
    assert_eq!(
        ac.check_profile(),
        Err(Error::ProfileViolation(ProfileViolation::IssuerV1Form))
    );
}

/// §4.2.2 requires exactly one holder form; this fixture gives two.
#[test]
fn a_holder_in_both_forms_parses_and_is_refused_by_the_profile() {
    let ac = ac("ac-holder-both.der");
    assert_eq!(
        ac.check_profile(),
        Err(Error::ProfileViolation(ProfileViolation::HolderAmbiguous))
    );
}

/// `verify` does not depend on `check_profile` having been called, so a
/// v1Form issuer must be refused there too rather than slipping through
/// to a signature check that cannot name an issuer.
#[test]
fn verify_refuses_a_v1form_issuer_on_its_own() {
    let ac = ac("ac-issuer-v1form.der");
    assert_eq!(
        ac.verify(&aa(), NOW, &DefaultVerifier),
        Err(Error::ProfileViolation(ProfileViolation::IssuerV1Form))
    );
}

/// Every violation must render a reason. A rule that is detected but
/// cannot be explained sends the reader to the spec with nothing to go
/// on.
#[test]
fn every_profile_violation_explains_itself() {
    for v in [
        ProfileViolation::IssuerV1Form,
        ProfileViolation::IssuerNameMissing,
        ProfileViolation::IssuerNameNotSingular,
        ProfileViolation::IssuerNameNotDirectoryName,
        ProfileViolation::IssuerExtraFields,
        ProfileViolation::HolderAmbiguous,
        ProfileViolation::HolderMissing,
        ProfileViolation::HolderNameNotSingular,
        ProfileViolation::HolderObjectDigestInfo,
        ProfileViolation::NoAttributes,
        ProfileViolation::AttributeWithoutValues,
    ] {
        let rendered = Error::ProfileViolation(v).to_string();
        assert!(
            rendered.starts_with("RFC 5755 profile violation: "),
            "{v:?} rendered as {rendered:?}"
        );
        assert!(
            rendered.len() > 45,
            "{v:?} must say which rule broke, got {rendered:?}"
        );
    }
}
