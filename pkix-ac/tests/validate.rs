//! Validating attribute certificates: profile rules, validity,
//! signature, holder matching.
//!
//! Fixtures: `tests/fixtures/gen.py`, plus the Attribute Authority
//! certificate and holder certificate borrowed from `pkix-ct`'s oracle
//! fixtures so the AA has a real key and a chain `pkix-path` could
//! validate.

use der::Decode as _;
use pkix_ac::{AttributeCertificate, Error, ProfileViolation, Targeting};
use x509_cert::ext::pkix::name::GeneralName;

/// A `GeneralName` dNSName, which is what the targeting fixtures use.
fn dns(host: &str) -> GeneralName {
    GeneralName::DnsName(der::asn1::Ia5String::new(host).expect("an IA5String host"))
}
use pkix_path::DefaultVerifier;
use x509_cert::Certificate;

/// Inside every fixture's window: the valid ACs run 2025-01-01 to
/// 2034-01-01, and the authority's certificate 2025-01-01 to 2035-01-01.
const NOW: u64 = 1_767_225_600; // 2025-12-31T12:00:00Z

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
///
/// Built by `tests/fixtures/make_aa.sh`, and deliberately not
/// `pkix-ct`'s `precert-issuer`: that is a CA, which RFC 5755 §4.5
/// forbids an AC issuer from being. See [`pkix_ac::check_issuer_profile`].
fn aa() -> Certificate {
    let der = fixture("aa-cert.der");
    Certificate::from_der(&der).expect("the authority certificate parses")
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
/// A targeted AC: the verifier it names matches, others do not.
///
/// Oracle: RFC 5755 §4.3.2 — "the targets check passes if the current
/// server is one of the targetName fields ... or if the current server
/// is a member of one of the targetGroup fields".
///
/// `Untargeted` is a third answer, not a synonym for either, which is
/// why the untargeted fixtures are checked alongside.
#[test]
fn targeting_matches_a_named_verifier_and_a_named_group() {
    let targeted = ac("ac-targeted.der");
    let me = dns("verifier.example.com");
    let group = dns("printers.example.com");
    let other = dns("elsewhere.example.com");

    assert_eq!(
        targeted.check_targeting(std::slice::from_ref(&me), &[]),
        Ok(Targeting::Matched)
    );
    assert_eq!(
        targeted.check_targeting(&[], std::slice::from_ref(&group)),
        Ok(Targeting::Matched)
    );
    assert_eq!(
        targeted.check_targeting(std::slice::from_ref(&other), std::slice::from_ref(&other)),
        Ok(Targeting::NotATarget),
        "a verifier the AC does not name is not a target"
    );
    // A name must not match as a group, nor a group as a name: the two
    // Target arms mean different things.
    assert_eq!(
        targeted.check_targeting(&[], std::slice::from_ref(&me)),
        Ok(Targeting::NotATarget)
    );
    assert_eq!(
        targeted.check_targeting(std::slice::from_ref(&group), &[]),
        Ok(Targeting::NotATarget)
    );

    // An untargeted AC answers Untargeted whatever the caller is called.
    let untargeted = ac("ac-role-valid.der");
    assert_eq!(
        untargeted.check_targeting(std::slice::from_ref(&other), &[]),
        Ok(Targeting::Untargeted)
    );
}

/// Several `Targets` elements are flattened into one.
///
/// Oracle: §4.3.2 — X.509-2000 defines the extension as a `SEQUENCE OF
/// Targets` while a conforming issuer emits one, and "if more than one
/// Targets element is found in an AC, the extension MUST be treated as
/// if all Target elements had been found within one Targets element".
#[test]
fn several_targets_elements_are_treated_as_one() {
    let split = ac("ac-targeted-split.der");
    assert_eq!(split.targets().expect("parses").expect("present").len(), 2);
    for host in ["first.example.com", "second.example.com"] {
        assert_eq!(
            split.check_targeting(std::slice::from_ref(&dns(host)), &[]),
            Ok(Targeting::Matched),
            "{host} is in the second Targets element and must still match"
        );
    }
}

/// `targetCert` parses and is refused — §4.3.2 says it MUST NOT be used.
#[test]
fn a_target_cert_is_refused() {
    let tc = ac("ac-target-cert.der");
    // It parses: the syntax permits what the profile forbids.
    assert_eq!(tc.targets().expect("parses").expect("present").len(), 1);
    assert_eq!(
        tc.check_targeting(&[], &[]),
        Err(Error::ProfileViolation(ProfileViolation::TargetCertUsed))
    );
}

/// RFC 5755 §5 rule 7: "If the AC contains an unsupported critical
/// extension, the AC MUST be rejected."
///
/// The non-critical twin is the control. Both fixtures carry the same
/// unknown OID and differ only in the criticality flag, so this cannot
/// pass by rejecting unknown extensions outright — which would break
/// every AC carrying an extension we have not heard of.
#[test]
fn an_unsupported_critical_extension_is_rejected_and_a_non_critical_one_is_not() {
    let critical = ac("ac-unsupported-critical.der");
    match critical.check_profile() {
        Err(Error::UnsupportedCriticalExtension(oid)) => {
            assert_eq!(oid.to_string(), "1.3.6.1.4.1.99999.1");
        }
        other => panic!("§5 rule 7 requires rejection, got {other:?}"),
    }

    ac("ac-unsupported-noncritical.der")
        .check_profile()
        .expect("an unknown non-critical extension must be ignored, not refused");
}

/// §4.3 fixes each profiled extension's criticality, so getting it
/// wrong is detectable.
#[test]
fn the_profiled_extensions_criticality_is_enforced() {
    // §4.3.6: noRevAvail MUST be non-critical.
    ac("ac-norevavail.der").check_profile().expect("conforming");
    assert_eq!(
        ac("ac-norevavail-critical.der").check_profile(),
        Err(Error::ProfileViolation(
            ProfileViolation::NoRevAvailCritical
        ))
    );

    // §4.3.1: auditIdentity MUST be critical, and 1..=20 octets.
    ac("ac-audit-identity.der")
        .check_profile()
        .expect("conforming");
    assert_eq!(
        ac("ac-audit-not-critical.der").check_profile(),
        Err(Error::ProfileViolation(
            ProfileViolation::AuditIdentityNotCritical
        ))
    );
    assert_eq!(
        ac("ac-audit-too-long.der").check_profile(),
        Err(Error::ProfileViolation(
            ProfileViolation::AuditIdentityLength
        ))
    );
}

/// The same extension twice is refused — §4.2.
///
/// Two instances let two implementations read one certificate
/// differently, which is the whole reason the rule exists.
#[test]
fn a_duplicate_extension_is_refused() {
    let dup = ac("ac-duplicate-ext.der");
    assert_eq!(
        dup.inner()
            .acinfo
            .extensions
            .as_ref()
            .map(std::vec::Vec::len),
        Some(2),
        "the fixture must really carry two"
    );
    assert_eq!(
        dup.check_profile(),
        Err(Error::ProfileViolation(
            ProfileViolation::DuplicateExtension
        ))
    );
}

/// The two accessors that exist to be read rather than enforced.
#[test]
fn no_rev_avail_and_audit_identity_are_readable() {
    let plain = ac("ac-role-valid.der");
    assert!(!plain.no_revocation_available());
    assert_eq!(plain.audit_identity(), None);

    assert!(ac("ac-norevavail.der").no_revocation_available());
    assert_eq!(
        ac("ac-audit-identity.der").audit_identity(),
        // The generator writes an OCTET STRING of 0..8 as the value, so
        // the extension value is that DER, header included.
        Some(&[0x04, 0x08, 0, 1, 2, 3, 4, 5, 6, 7][..])
    );
}

/// `check_extensions` works called on its own, not only through
/// `check_profile`.
///
/// It is public and reachable both ways. The §4.3 tests above go through
/// `check_profile`, which calls it, so this covers the standalone entry
/// point a caller might reasonably use to ask only about extensions —
/// for instance to report on a certificate whose §4.2 holder or issuer
/// form it has already decided to tolerate.
#[test]
fn check_extensions_stands_alone() {
    ac("ac-role-valid.der")
        .check_extensions()
        .expect("no extensions at all is not a violation");
    ac("ac-norevavail.der")
        .check_extensions()
        .expect("a conforming noRevAvail passes");
    assert_eq!(
        ac("ac-norevavail-critical.der").check_extensions(),
        Err(Error::ProfileViolation(
            ProfileViolation::NoRevAvailCritical
        ))
    );
    assert!(matches!(
        ac("ac-unsupported-critical.der").check_extensions(),
        Err(Error::UnsupportedCriticalExtension(_))
    ));
}

/// The §4.5 check on the authority's own certificate.
///
/// Oracle: §4.5 — "an AC issuer cannot be a CA as well", and keyUsage
/// "MUST NOT explicitly indicate that the AC issuer's public key cannot
/// be used to validate a digital signature". `pkix-ct`'s
/// `precert-issuer` is CA:TRUE with keyUsage "Certificate Sign, CRL
/// Sign" and so fails both; the purpose-built authority passes.
#[test]
fn a_ca_is_refused_as_an_attribute_authority() {
    pkix_ac::check_issuer_profile(&aa()).expect("the purpose-built authority conforms");

    let ca = ct_fixture("precert-issuer.der");
    match pkix_ac::check_issuer_profile(&ca) {
        Err(Error::ProfileViolation(
            ProfileViolation::IssuerIsACa | ProfileViolation::IssuerCannotSign,
        )) => {}
        other => panic!("a CA must be refused as an authority, got {other:?}"),
    }
}

/// Every §4.2 profile rule, driven by a fixture rather than asserted
/// about its own error message.
///
/// Each of these parses: §4.1's syntax permits what the §4.2 profile
/// forbids, which is why the two are separate steps. Before these
/// fixtures existed, eight of these rules were implemented and had only
/// a Display test behind them -- enough to prove the message read well,
/// nothing about whether the rule fired.
#[test]
fn each_profile_rule_is_driven_by_a_fixture() {
    use ProfileViolation as V;
    for (name, expected) in [
        // §4.2.3, which is four requirements in one sentence: one and
        // only one GeneralName, containing a non-empty distinguished
        // name, in the directoryName field.
        ("ac-issuer-no-name", V::IssuerNameMissing),
        ("ac-issuer-two-names", V::IssuerNameNotSingular),
        ("ac-issuer-dns-name", V::IssuerNameNotDirectoryName),
        ("ac-issuer-empty-dn", V::IssuerNameEmptyDn),
        ("ac-issuer-extra-fields", V::IssuerExtraFields),
        ("ac-issuer-v1form", V::IssuerV1Form),
        // §4.2.2 and §4.1 on the holder.
        ("ac-holder-two-names", V::HolderNameNotSingular),
        ("ac-holder-digest-info", V::HolderObjectDigestInfo),
        ("ac-holder-both", V::HolderAmbiguous),
        // §4.1 on the attributes.
        ("ac-no-attributes", V::NoAttributes),
        ("ac-attribute-no-values", V::AttributeWithoutValues),
    ] {
        let ac = ac(&format!("{name}.der"));
        assert_eq!(
            ac.check_profile(),
            Err(Error::ProfileViolation(expected)),
            "{name} must be refused as {expected:?}"
        );
    }
}

/// `issuerUniqueID` and `extensions` are told apart by tag alone.
///
/// Both are the trailing OPTIONAL fields of
/// `AttributeCertificateInfo` and neither is context-tagged, so the
/// only thing distinguishing them is that one is a `BIT STRING` and the
/// other a `SEQUENCE`. types.rs has said so since it was written and
/// nothing checked it: no fixture carried `issuerUniqueID` at all, so a
/// parser that mixed the two up would have passed every test.
///
/// This fixture carries both, which is the only arrangement that can
/// tell a working disambiguation from a lucky one.
#[test]
fn issuer_unique_id_and_extensions_are_both_read() {
    let ac = ac("ac-issuer-unique-id.der");
    let info = &ac.inner().acinfo;

    assert_eq!(
        info.issuer_unique_id.as_ref().and_then(|b| b.as_bytes()),
        Some(&[0x2a, 0x2b, 0x2c][..]),
        "the BIT STRING must land in issuerUniqueID"
    );
    assert_eq!(
        info.extensions.as_ref().map(std::vec::Vec::len),
        Some(1),
        "and the SEQUENCE in extensions"
    );
    assert!(
        ac.no_revocation_available(),
        "the extension must be readable, not merely counted"
    );
    ac.check_profile()
        .expect("carrying issuerUniqueID is conforming");
}

/// `otherObjectTypes` MUST NOT be used (§4.1), and cannot be reached.
///
/// There is no check for it, deliberately, because every position an
/// `ObjectDigestInfo` can occupy is already refused: the holder's by
/// [`ProfileViolation::HolderObjectDigestInfo`], the v2Form issuer's by
/// [`ProfileViolation::IssuerExtraFields`], and a `TargetCert`'s by
/// [`ProfileViolation::TargetCertUsed`] -- `targetCert` being forbidden
/// outright. So a profile-checked certificate can carry no
/// `ObjectDigestInfo` at all, and its `digestedObjectType` is
/// unreachable rather than unchecked.
///
/// This test pins the three refusals that argument rests on. If any of
/// them is relaxed, `otherObjectTypes` becomes reachable and needs its
/// own check, and this test is where that should be noticed.
#[test]
fn object_digest_info_is_unreachable_in_a_conforming_certificate() {
    assert_eq!(
        ac("ac-holder-digest-info.der").check_profile(),
        Err(Error::ProfileViolation(
            ProfileViolation::HolderObjectDigestInfo
        ))
    );
    assert_eq!(
        ac("ac-issuer-extra-fields.der").check_profile(),
        Err(Error::ProfileViolation(ProfileViolation::IssuerExtraFields))
    );
    let tc = ac("ac-target-cert.der");
    assert_eq!(
        tc.check_targeting(&[], &[]),
        Err(Error::ProfileViolation(ProfileViolation::TargetCertUsed))
    );
}
