//! Validating attribute certificates: profile rules, validity,
//! signature, holder matching.
//!
//! Fixtures: `tests/fixtures/gen.py`, plus the Attribute Authority
//! certificate and holder certificate borrowed from `pkix-ct`'s oracle
//! fixtures so the AA has a real key and a chain `pkix-path` could
//! validate.

use der::{Decode as _, Encode as _};
use pkix_ac::{AcRevocation, AttributeCertificate, Error, ProfileViolation, Targeting};
use x509_cert::ext::pkix::name::GeneralName;

/// A `GeneralName` dNSName, which is what the targeting fixtures use.
fn dns(host: &str) -> GeneralName {
    GeneralName::DnsName(der::asn1::Ia5String::new(host).expect("an IA5String host"))
}
use pkix_path::DefaultVerifier;
use x509_cert::Certificate;

/// Inside every fixture's window: the valid ACs run 2025-01-01 to
/// 2034-01-01, and the authority's certificate 2025-01-01 to 2035-01-01.
const NOW: u64 = 1_767_225_600; // 2026-01-01T00:00:00Z

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
    // One id-at-role attribute carrying two values, which is how §4.2.7
    // says to express several: "only one instance of each attribute can
    // occur in a single AC, but each instance can be multi-valued". This
    // fixture used to be two separate id-at-role attributes — a §4.2.7
    // violation that this test asserted conformed.
    let ac = ac("ac-two-roles.der");
    assert_eq!(ac.attributes().len(), 1, "one attribute type");
    assert_eq!(ac.attributes()[0].values.len(), 2, "carrying two values");
    ac.check_profile()
        .expect("a multi-valued attribute is the conforming shape");
    ac.verify(&aa(), NOW, &DefaultVerifier)
        .expect("the two-value certificate is signed too");
}

/// §4.2.7: two attributes of one type is a divergent-interpretation
/// hazard, not a convenience.
///
/// Given `Role=auditor` followed by `Role=admin`, a consumer reading the
/// first match sees auditor and one reading the last sees admin — the
/// same hazard this crate already refuses for duplicate extensions, and
/// here the consequence is a concrete privilege difference rather than a
/// theoretical one.
#[test]
fn two_attributes_of_one_type_are_refused() {
    assert_eq!(
        ac("ac-duplicate-attribute-type.der").check_profile(),
        Err(Error::ProfileViolation(
            ProfileViolation::DuplicateAttributeType
        ))
    );
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

    // The boundaries, which is where this was wrong. §4.3.1 bounds the
    // VALUE at 1..=20 octets; the length was taken from the extension
    // value's DER instead, which is two more for a short OCTET STRING.
    // So the real window was 1..=18 real octets, and the one length the
    // RFC forbids — zero — got through as a two-byte `04 00`.
    //
    // 21 octets, the only case tested before, is far enough over the
    // line to be refused under either reading, which is why nothing
    // caught it.
    ac("ac-audit-max.der")
        .check_profile()
        .expect("20 octets is the largest §4.3.1 permits");
    ac("ac-audit-near-max.der")
        .check_profile()
        .expect("19 octets is inside the window under any reading");
    for name in ["ac-audit-too-long.der", "ac-audit-empty.der"] {
        assert_eq!(
            ac(name).check_profile(),
            Err(Error::ProfileViolation(
                ProfileViolation::AuditIdentityLength
            )),
            "{name} is outside 1..=20 octets"
        );
    }

    // §4.3.1 gives auditIdentity the syntax OCTET STRING, and nothing
    // required the value to be one.
    assert_eq!(
        ac("ac-audit-not-octet-string.der").check_profile(),
        Err(Error::ProfileViolation(
            ProfileViolation::AuditIdentityNotOctetString
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
        // The OCTET STRING's contents, with no ASN.1 header. This
        // assertion previously pinned the header-included form, which is
        // how the wrong behaviour became load-bearing in the suite: the
        // test recorded what the code did rather than what the value is.
        Some(&[0, 1, 2, 3, 4, 5, 6, 7][..])
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
        ("ac-duplicate-attribute-type", V::DuplicateAttributeType),
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
    // Conforming *as a profile matter*: §4.2.8 makes issuerUniqueID
    // conditional on the AUTHORITY's certificate carrying one, and
    // check_profile has no authority certificate to consult. So this
    // says the field parsed and broke no rule check_profile can see —
    // not that the certificate is conforming overall.
    ac.check_profile()
        .expect("check_profile cannot judge §4.2.8 and must not try");

    // verify() does hold the authority's certificate, and refuses it:
    // the authority is a v3 certificate with no unique identifier, so
    // §4.2.8's "MUST NOT be used unless it is also used in the AC
    // issuer's PKC" is violated. This fixture is deliberately on the
    // wrong side of that rule, and an earlier version of this test
    // called it conforming.
    //
    // What this does NOT guard: the rule reads the authority's
    // `subjectUniqueID`, because the authority is its own certificate's
    // subject. It once read `issuerUniqueID`, which belongs to the
    // authority's CA — and this fixture has neither, so it satisfies
    // both readings and would pass if the field were reverted.
    // Distinguishing them needs an authority certificate carrying a
    // subjectUniqueID, which OpenSSL will not emit (RFC 5280 §4.1.2.8
    // deprecates the field), so the regression is unguarded and said so
    // rather than implied to be covered.
    assert_eq!(
        ac.verify(&aa(), NOW, &DefaultVerifier),
        Err(Error::ProfileViolation(
            ProfileViolation::IssuerUniqueIdMismatch
        )),
        "the authority has no unique identifier, so the AC must not carry one"
    );
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

/// Rewriting the outer `signatureAlgorithm` is refused.
///
/// This is the attack the check exists for, and the surgery is what an
/// on-path attacker can actually do: `acinfo` is the signed region, so
/// `acinfo.signature` cannot be touched without breaking the signature,
/// but the outer `signatureAlgorithm` sits outside it and can be
/// rewritten freely. Verifying under the rewritten copy would let the
/// attacker pick the algorithm the check runs with.
///
/// Oracle: RFC 5280 §4.1.1.2 — the outer field "MUST contain the same
/// algorithm identifier as the signature field in the sequence
/// tbsCertificate"; RFC 5755 §4.1 gives ACs the same shape.
#[test]
fn rewriting_the_unsigned_algorithm_identifier_is_refused() {
    let der = fixture("ac-role-valid.der");
    let ac = AttributeCertificate::from_der(&der).expect("parses");
    let signed = ac.signed_bytes().to_vec();

    // ecdsa-with-SHA256, which both copies carry.
    let sha256 = [0x06u8, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    // ecdsa-with-SHA384: same length, so no length fields shift and the
    // edit stays a pure substitution.
    let sha384 = [0x06u8, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];

    // The outer copy is the LAST occurrence: the inner one lives inside
    // acinfo, which comes first.
    let acinfo_end = der
        .windows(signed.len())
        .position(|w| w == signed.as_slice())
        .expect("acinfo is in the certificate")
        + signed.len();
    let outer = acinfo_end
        + der[acinfo_end..]
            .windows(sha256.len())
            .position(|w| w == sha256)
            .expect("the outer algorithm follows acinfo");

    let mut tampered = der.clone();
    tampered[outer..outer + sha384.len()].copy_from_slice(&sha384);

    // The signature bytes are untouched and acinfo is untouched, so
    // nothing but the mismatch can be refusing this.
    let tampered_ac = AttributeCertificate::from_der(&tampered).expect("still parses");
    assert_eq!(
        tampered_ac.signed_bytes(),
        signed.as_slice(),
        "the signed region must be identical; otherwise this tests the wrong thing"
    );
    assert_eq!(
        tampered_ac.verify(&aa(), NOW, &DefaultVerifier),
        Err(Error::SignatureAlgorithmMismatch)
    );
}

/// RFC 5755 §5 rule 5, the sentence that is easy to read past: "If the
/// evaluation time is equal to either notBeforeTime or notAfterTime,
/// then the AC is timely and this check succeeds."
///
/// The existing window test checks outside both bounds, which an
/// exclusive comparison would also pass. Only the bounds themselves
/// distinguish the two readings.
#[test]
fn the_validity_bounds_are_inclusive() {
    let ac = ac("ac-role-valid.der");
    let v = &ac.inner().acinfo.validity;
    let not_before = v.not_before_time.to_unix_duration().as_secs();
    let not_after = v.not_after_time.to_unix_duration().as_secs();

    ac.verify(&aa(), not_before, &DefaultVerifier)
        .expect("notBeforeTime itself is timely");
    ac.verify(&aa(), not_after, &DefaultVerifier)
        .expect("notAfterTime itself is timely");

    // One second outside each, to show the bound is where it claims.
    assert_eq!(
        ac.verify(&aa(), not_before - 1, &DefaultVerifier),
        Err(Error::NotYetValid)
    );
    assert_eq!(
        ac.verify(&aa(), not_after + 1, &DefaultVerifier),
        Err(Error::Expired)
    );
}

/// All six §4.4 attribute types parse, in order, uninterpreted.
///
/// The crate's position is "parse all, interpret none", and until now
/// every fixture carried `id-at-role` alone — so the claim was
/// untested against types with different shapes. These six differ
/// structurally: `Role` nests a `GeneralName`, `Clearance` is an OID
/// plus a `BIT STRING`, `Group` and `ChargingIdentity` use
/// `IetfAttrSyntax`, and `AccessIdentity` and
/// `ServiceAuthenticationInfo` use `SvceAuthInfo`.
///
/// Oracle: RFC 5755 §4.4 and Appendix B for the OIDs. Worth noting that
/// `id-aca` is `{ id-pkix 10 }`, so four of the six sit under
/// `1.3.6.1.5.5.7.10` while `role` and `clearance` are under `2.5.4` —
/// a distinction a crate that does not interpret attributes cannot
/// catch for itself, and which this test got wrong on the first attempt.
#[test]
fn all_six_profiled_attribute_types_parse_uninterpreted() {
    let ac = ac("ac-attribute-types.der");
    let got: Vec<String> = ac
        .attributes()
        .iter()
        .map(|a| a.r#type.to_string())
        .collect();

    assert_eq!(
        got,
        [
            "2.5.4.72",           // id-at-role
            "2.5.4.55",           // id-at-clearance
            "1.3.6.1.5.5.7.10.4", // id-aca-group
            "1.3.6.1.5.5.7.10.3", // id-aca-chargingIdentity
            "1.3.6.1.5.5.7.10.2", // id-aca-accessIdentity
            "1.3.6.1.5.5.7.10.1", // id-aca-authenticationInfo
        ],
        "all six parse, and `attributes` is a SEQUENCE OF so the order is preserved"
    );
    for a in ac.attributes() {
        assert_eq!(a.values.len(), 1, "each value is kept, whatever its shape");
    }

    ac.check_profile()
        .expect("six attribute types is conforming");
    ac.verify(&aa(), NOW, &DefaultVerifier)
        .expect("and the signature covers them all");
}

/// An attribute whose `SET OF` values are not in DER order verifies,
/// and re-encoding it would not.
///
/// This is the `pkix-ct` failure mode caught in the act and
/// neutralised. `values` is a `SET OF`; X.690 §11.6 requires members
/// sorted by their encodings, and a CA that does not sort emits bytes
/// that look well formed and are not canonical. `pkix-ct` verified SCTs
/// by re-encoding a parsed certificate, so an unsorted RDN was
/// re-sorted on the way out and the signature was checked over
/// different bytes than the log signed.
///
/// The fixture carries two values in descending order, and what the
/// test establishes is the chain of consequences:
///
/// 1. `SetOfVec` **re-sorts on decode**, so the parsed view is
///    canonical and is not the order the CA sent.
/// 2. Re-encoding `acinfo` therefore does **not** reproduce the signed
///    bytes — asserted here, against the same fixture.
/// 3. The signature verifies regardless, because
///    [`AttributeCertificate::signed_bytes`] is a slice of the original
///    DER rather than a re-encoding.
///
/// Together those say the slice is load-bearing rather than tidy. The
/// companion test in `parse.rs` shows re-encoding matching for a
/// canonical fixture, which is exactly how the old `pkix-ct` approach
/// passed its tests while being wrong.
#[test]
fn an_unsorted_set_of_verifies_though_re_encoding_would_not() {
    let ac = ac("ac-unsorted-set-of.der");
    let values = &ac.attributes()[0].values;
    assert_eq!(values.len(), 2, "both values survive");

    // 1. The parsed view is canonical, not the wire order. The
    //    generator emitted "zzz" first; DER order puts "aaa" first.
    let first = values.as_slice()[0].to_der().expect("re-encode a value");
    assert!(
        String::from_utf8_lossy(&first).contains("aaa"),
        "SetOfVec is expected to re-sort on decode; if this fails the \
         premise of this test changed and the rest of it needs re-reading"
    );

    // 2. So a re-encode does not reproduce what was signed.
    let reencoded = ac.inner().acinfo.to_der().expect("re-encode acinfo");
    assert_ne!(
        reencoded.as_slice(),
        ac.signed_bytes(),
        "re-encoding must differ here — that difference is the bug pkix-ct had"
    );

    // 3. And the signature still checks, because the signed bytes are
    //    taken from the original DER.
    ac.check_profile()
        .expect("non-canonical ordering is not a profile matter");
    ac.verify(&aa(), NOW, &DefaultVerifier)
        .expect("the signature covers the bytes as sent, sorted or not");
}

/// Distinguished names compare under RFC 5280 §7.1, not byte equality.
///
/// This was a real defect: all three name comparisons in this crate used
/// derived `PartialEq` on `Name`, which is byte-shaped. Two
/// distinguished names can hold the same content and differ in encoding
/// — `PrintableString` against `UTF8String`, letter case, insignificant
/// whitespace — and X.501 says they are one name.
///
/// The consequence was a workspace that contradicted itself.
/// `pkix-path` links issuer to subject with
/// [`pkix_path::names_match`], so a chain would validate and then the
/// attribute certificate riding on it would be refused for a name
/// `pkix-path` had just accepted. Fail-closed, and wrong.
///
/// The authority's certificate encodes its CN as `UTF8String`. These
/// fixtures name the same authority with a `PrintableString` and with
/// the case changed.
#[test]
fn an_equivalent_distinguished_name_is_not_a_mismatch() {
    for name in ["ac-issuer-printablestring.der", "ac-issuer-case.der"] {
        let ac = ac(name);
        ac.check_profile()
            .expect("a re-encoded DN is still conforming");
        ac.verify(&aa(), NOW, &DefaultVerifier)
            .unwrap_or_else(|e| panic!("{name} names the same authority under §7.1, got {e:?}"));
    }
}

/// The `baseCertificateID` holder form — §4.2.2's other option.
///
/// Every other fixture names the holder by `entityName`, so this branch
/// had never run against DER. It identifies the holder's certificate by
/// that certificate's **issuer** and serial, not by its subject, which
/// is the part easy to get backwards and impossible to notice while the
/// branch is untested.
///
/// Three fixtures, because two of them are what make the first mean
/// something: the issuer DN re-encoded, to show §7.1 applies on this
/// branch too, and the serial changed, to show a match is not coming
/// from the issuer name alone.
#[test]
fn a_holder_named_by_base_certificate_id_is_matched() {
    let holder = holder();

    let by_ref = ac("ac-holder-base-cert-id.der");
    by_ref
        .check_profile()
        .expect("baseCertificateID is a profiled form");
    assert!(
        by_ref.matches_holder(&holder),
        "the AC references this certificate by issuer and serial"
    );

    assert!(
        ac("ac-holder-base-cert-id-reencoded.der").matches_holder(&holder),
        "the issuer DN is re-encoded, and §7.1 makes it the same name"
    );

    assert!(
        !ac("ac-holder-base-cert-id-wrong-serial.der").matches_holder(&holder),
        "a different serial is a different certificate, whatever the issuer"
    );

    // And it must not match some other certificate that happens to
    // share the issuer: the authority's own certificate is issued by the
    // same root, so only the serial tells them apart.
    assert!(
        !by_ref.matches_holder(&aa()),
        "the authority shares the holder's issuer and must not match on it"
    );
}

/// `AttCertVersion ::= INTEGER { v2(1) }` — the only legal value.
///
/// types.rs says the version is "modelled as an enumeration rather than
/// an integer so that a wrong version is a parse failure at the type
/// level instead of a check someone can forget". Nothing tested that:
/// every fixture carried v2, so a type that silently accepted other
/// values would have passed.
///
/// These two carry 0 and 2 — v1 and the hypothetical v3 — and must fail
/// while parsing, before any profile rule gets a chance to opine.
#[test]
fn only_version_v2_parses() {
    for name in ["ac-version-v1.der", "ac-version-v3.der"] {
        let der = fixture(name);
        assert_eq!(
            AttributeCertificate::from_der(&der).err(),
            Some(Error::ParseError),
            "{name} must be refused by the parser, not by a later check"
        );
    }
}

/// The serial comparison in `matches_holder` treats DER INTEGER bytes as
/// the value.
///
/// That holds because DER gives each integer one encoding — minimal
/// length, and a leading zero octet only where it is needed to keep the
/// value positive. The comment in `matches_holder` asserts it; this
/// shows it, by reading the serial back out of a real certificate and
/// confirming the encoding is the canonical one for its value.
///
/// It matters because a non-minimal encoding of the same number would
/// compare unequal, so if `der` ever accepted one this comparison would
/// start answering "different certificate" for the same certificate.
#[test]
fn serial_numbers_compare_as_canonical_der_integers() {
    let holder = holder();
    let serial = holder.tbs_certificate().serial_number();
    let bytes = serial.as_bytes();

    assert!(!bytes.is_empty(), "an INTEGER is never zero-length in DER");
    // Minimal: a leading zero is only permitted to clear the sign bit.
    if bytes.len() > 1 {
        assert!(
            bytes[0] != 0x00 || bytes[1] & 0x80 != 0,
            "a leading zero octet is only canonical when the next has its \
             high bit set, got {bytes:02x?}"
        );
        assert!(
            bytes[0] != 0xFF || bytes[1] & 0x80 == 0,
            "and 0xff is only canonical when the next clears its high bit"
        );
    }

    // The holder's own AC matches it; a different serial does not. That
    // is the property the byte comparison is standing in for.
    assert!(ac("ac-holder-base-cert-id.der").matches_holder(&holder));
    assert!(!ac("ac-holder-base-cert-id-wrong-serial.der").matches_holder(&holder));
}

/// RFC 5755 §6's two revocation schemes, and §4.3.6's syntax.
///
/// §4.3.6 gives `noRevAvail` the syntax "NULL (i.e. `'0500'H` is the
/// DER encoding)". The value was never checked, so an AC asserting
/// "never revoke" with a body of junk satisfied
/// [`AttributeCertificate::no_revocation_available`] — and a caller
/// keyed on that accessor would skip revocation for an AC that never
/// made the assertion.
///
/// §6: "an AC MUST NOT contain both a noRevAvail extension and a
/// 'pointer in AC'". They are alternatives — one says no revocation
/// information exists, the other says where to find it — so an AC
/// asserting both has not chosen.
#[test]
fn the_revocation_schemes_are_mutually_exclusive_and_typed() {
    assert_eq!(
        ac("ac-norevavail-not-null.der").check_profile(),
        Err(Error::ProfileViolation(ProfileViolation::NoRevAvailNotNull))
    );
    assert_eq!(
        ac("ac-norevavail-with-pointer.der").check_profile(),
        Err(Error::ProfileViolation(
            ProfileViolation::NoRevAvailWithPointer
        ))
    );
    // The conforming one still passes, and still reads as the assertion.
    let ok = ac("ac-norevavail.der");
    ok.check_profile()
        .expect("a NULL-valued noRevAvail conforms");
    assert!(ok.no_revocation_available());

    // §6's "pointer in AC" points at REVOCATION status, so inside an
    // AIA it is `id-ad-ocsp`. An AIA holding only `id-ad-caIssuers`
    // points at the issuer's certificate — §4.3.4 treats that as a
    // separate, optional feature — so such an AC has chosen one scheme
    // and conforms. Treating any AIA as a pointer refused it.
    ac("ac-norevavail-with-caissuers.der")
        .check_profile()
        .expect("a caIssuers-only AIA is not a revocation pointer");
    assert_eq!(
        ac("ac-norevavail-with-ocsp.der").check_profile(),
        Err(Error::ProfileViolation(
            ProfileViolation::NoRevAvailWithPointer
        )),
        "an OCSP accessMethod is a revocation pointer, and §6 forbids the pair"
    );

    // An AIA the pointer test cannot decode must not read as "no
    // pointer": that let an AC carry noRevAvail beside a pointer.
    assert_eq!(
        ac("ac-norevavail-with-bad-aia.der").check_profile(),
        Err(Error::ProfileViolation(
            ProfileViolation::AuthorityInfoAccessMalformed
        )),
        "an undecodable AIA is refused rather than treated as absent"
    );
}

/// `targetCert` is refused by the profile check, not only by
/// `check_targeting`.
///
/// §5 defines support for an extension as being able to parse the value
/// AND honouring a rejection the value implies, so a crate claiming to
/// support a critical `targetInformation` has to refuse a `targetCert`
/// there. It previously only did so in `check_targeting`, which a
/// caller may never reach — `check_profile` and `verify` both returned
/// `Ok`.
///
/// This also restores the reachability argument for `otherObjectTypes`:
/// a `TargetCert` carries an `ObjectDigestInfo`, so that was the route
/// by which a profile-checked certificate could still hold one. This
/// fixture's `certDigestInfo` carries `digestedObjectType =
/// otherObjectTypes(2)`, the value §4.1 forbids.
#[test]
fn a_target_cert_is_refused_by_the_profile_check() {
    let ac = ac("ac-target-cert-other-object.der");
    assert_eq!(
        ac.check_profile(),
        Err(Error::ProfileViolation(ProfileViolation::TargetCertUsed))
    );
    // verify() does NOT run the profile rules — they are separate
    // calls, which is exactly the hazard `validate` exists to remove.
    // Asserting otherwise is a mistake this test made on its first
    // attempt, so it is recorded rather than quietly corrected.
    ac.verify(&aa(), NOW, &DefaultVerifier)
        .expect("verify checks the signature and validity, not the profile");

    // validate() runs both, so it refuses.
    assert_eq!(
        ac.validate(
            &aa(),
            &holder(),
            NOW,
            &[],
            &[],
            AcRevocation::CallerChecks,
            &DefaultVerifier
        ),
        Err(Error::ProfileViolation(ProfileViolation::TargetCertUsed))
    );
}

/// §4.2.5's serial-number rules, and §4.2.2's empty `entityName`.
///
/// §4.2.5: "AC issuers MUST force the serialNumber to be a positive
/// integer, that is, the sign bit in the DER encoding of the INTEGER
/// value MUST be zero", and "conformant ACs MUST NOT contain
/// serialNumber values longer than 20 octets". The first removes "a
/// potential ambiguity in mapping between a string of octets and an
/// integer value" — the mapping `matches_holder` relies on when it
/// compares serials as bytes.
///
/// The `entityName` case is a message fix as much as a rule: `A1 00`
/// used to be reported as `HolderNameNotSingular`, whose text reads
/// "holder carries more than one name" — the opposite of the truth.
#[test]
fn the_serial_number_and_empty_entity_name_rules_are_enforced() {
    for (name, expected) in [
        (
            "ac-serial-negative.der",
            ProfileViolation::SerialNotPositive,
        ),
        ("ac-serial-too-long.der", ProfileViolation::SerialTooLong),
        ("ac-holder-no-names.der", ProfileViolation::HolderNameEmpty),
    ] {
        assert_eq!(
            ac(name).check_profile(),
            Err(Error::ProfileViolation(expected)),
            "{name} must be refused as {expected:?}"
        );
    }
}

/// `validate` runs the whole of §5 that this crate can, in one call.
///
/// The hazard it removes: `check_profile` plus `verify` is the obvious
/// pair, and it silently skips rule 3 (§4.5 on the authority) and rule 6
/// (targeting). A consumer doing the obvious thing honoured an AC scoped
/// to somebody else's service, which §4.3.2 makes a MUST-reject.
#[test]
fn validate_runs_the_rules_the_obvious_pair_skips() {
    let holder = holder();

    // The conforming AC passes, and reports its targeting.
    assert_eq!(
        ac("ac-role-valid.der").validate(
            &aa(),
            &holder,
            NOW,
            &[],
            &[],
            AcRevocation::CallerChecks,
            &DefaultVerifier
        ),
        Ok(Targeting::Untargeted)
    );

    // Rule 6: targeted elsewhere. check_profile and verify both pass it.
    let targeted = ac("ac-targeted.der");
    targeted
        .check_profile()
        .expect("the obvious pair sees nothing wrong");
    targeted
        .verify(&aa(), NOW, &DefaultVerifier)
        .expect("nor does verify");
    assert_eq!(
        targeted.validate(
            &aa(),
            &holder,
            NOW,
            &[],
            &[],
            AcRevocation::CallerChecks,
            &DefaultVerifier
        ),
        Err(Error::NotATarget),
        "validate must catch what the pair misses"
    );

    // Rule 3: a CA as the authority. Again invisible to the pair, since
    // §4.5 is about the authority's certificate rather than the AC.
    let ca = ct_fixture("precert-issuer.der");
    assert!(matches!(
        ac("ac-role-valid.der").validate(
            &ca,
            &holder,
            NOW,
            &[],
            &[],
            AcRevocation::CallerChecks,
            &DefaultVerifier
        ),
        Err(Error::ProfileViolation(
            ProfileViolation::IssuerIsACa | ProfileViolation::IssuerCannotSign
        ))
    ));
}

/// §4.5 forbids a `keyUsage` that *excludes* signature validation, not
/// one that permits it by a different bit.
///
/// `nonRepudiation` (contentCommitment) denotes verifying signatures per
/// RFC 5280 §4.2.1.3, differing from `digitalSignature` in purpose
/// rather than capability, so an authority asserting only that bit is
/// permitted. Requiring `digitalSignature` specifically refused it.
///
/// The fixture carries `keyUsage = critical, nonRepudiation` and
/// nothing else. The first version of this test called
/// `check_issuer_profile` on a certificate asserting
/// `digitalSignature`, so `non_repudiation()` was never evaluated by
/// the short circuit — it passed identically before the change, while
/// its name claimed to cover it.
#[test]
fn an_authority_with_only_non_repudiation_is_permitted() {
    let der = fixture("aa-nonrep-cert.der");
    let aa = Certificate::from_der(&der).expect("the fixture parses");

    // Precondition: the fixture really does lack digitalSignature,
    // otherwise this test would pass for the old reason.
    let exts = aa
        .tbs_certificate()
        .extensions()
        .expect("the fixture has extensions");
    let ku_der = exts
        .iter()
        .find(|e| e.extn_id.to_string() == "2.5.29.15")
        .expect("and a keyUsage");
    let ku = x509_cert::ext::pkix::KeyUsage::from_der(ku_der.extn_value.as_bytes())
        .expect("which decodes");
    assert!(
        !ku.digital_signature() && ku.non_repudiation(),
        "the fixture must assert nonRepudiation and NOT digitalSignature"
    );

    pkix_ac::check_issuer_profile(&aa)
        .expect("§4.5 permits an authority whose keyUsage asserts nonRepudiation");
}

/// §4.5 refuses an authority whose `keyUsage` asserts neither
/// `digitalSignature` nor `nonRepudiation`.
///
/// This is the rule's negative side, and it had no coverage. Every
/// other test that mentions `IssuerCannotSign` alternates it with
/// `IssuerIsACa` against a CA fixture — and `check_issuer_profile`
/// tests `basicConstraints` before `keyUsage`, so those always return
/// `IssuerIsACa` and the keyUsage arm was never reached. Deleting the
/// §4.5 keyUsage rule outright left all 38 tests green.
///
/// The fixture is therefore deliberately NOT a CA: `CA:FALSE` with
/// `keyUsage = critical, keyEncipherment`.
#[test]
fn an_authority_that_cannot_sign_is_refused() {
    let der = fixture("aa-nosign-cert.der");
    let aa = Certificate::from_der(&der).expect("the fixture parses");

    // Precondition, so this cannot pass for the old reason: the
    // fixture must not be a CA, or IssuerIsACa would mask the rule.
    let exts = aa
        .tbs_certificate()
        .extensions()
        .expect("the fixture has extensions");
    let bc_der = exts
        .iter()
        .find(|e| e.extn_id.to_string() == "2.5.29.19")
        .expect("and basicConstraints");
    let bc = x509_cert::ext::pkix::BasicConstraints::from_der(bc_der.extn_value.as_bytes())
        .expect("which decodes");
    assert!(!bc.ca, "the fixture must not be a CA");

    assert_eq!(
        pkix_ac::check_issuer_profile(&aa),
        Err(Error::ProfileViolation(ProfileViolation::IssuerCannotSign)),
        "keyEncipherment alone excludes validating a signature"
    );
}

/// §4.2.5 requires "a positive integer", and zero is not one.
#[test]
fn a_zero_serial_is_not_positive() {
    assert_eq!(
        ac("ac-serial-zero.der").check_profile(),
        Err(Error::ProfileViolation(ProfileViolation::SerialNotPositive)),
        "DER content 00 is zero, which §4.2.5 does not permit"
    );

    // The minimal conforming case on the other side of the same rule:
    // +128, encoded with the leading 00 §4.2.5 prescribes.
    ac("ac-serial-positive-high-bit.der")
        .check_profile()
        .expect("a positive serial needing one pad octet conforms");
}

/// §6's MUST lives in this crate now, so this crate tests it.
///
/// The rule moved here precisely so the two entry points could not
/// disagree about it — and then only `pkix-chain` tested it, which
/// meant stubbing the check out left every `pkix-ac` test green and a
/// future split would have been caught in the wrong crate.
#[test]
fn never_revoke_only_refuses_an_ac_without_no_rev_avail() {
    let ac = ac("ac-role-valid.der");
    assert!(
        !ac.no_revocation_available(),
        "precondition: this fixture carries no noRevAvail"
    );

    assert_eq!(
        ac.validate(
            &aa(),
            &holder(),
            NOW,
            &[],
            &[],
            AcRevocation::NeverRevokeOnly,
            &DefaultVerifier
        ),
        Err(Error::RevocationUnsupported),
        "§6: a verifier supporting only 'never revoke' MUST reject it"
    );

    // And the same AC passes when the caller takes on §6's obligation.
    ac.validate(
        &aa(),
        &holder(),
        NOW,
        &[],
        &[],
        AcRevocation::CallerChecks,
        &DefaultVerifier,
    )
    .expect("CallerChecks accepts it");
}

/// §4.2.5's 20-octet cap is on the VALUE, not on its DER encoding.
///
/// §4.2.5 tells issuers to add "a leading (leftmost) '00'H octet if
/// necessary" to force the sign bit clear, then caps the value at 20
/// octets — so a conforming 20-octet serial whose top byte has its high
/// bit set occupies 21 DER content octets. Measuring those rejected it,
/// which is roughly half of all 20-octet serials.
#[test]
fn a_conforming_twenty_octet_serial_is_not_too_long() {
    // 20-octet magnitude, top byte 0xff, so DER carries a leading 00.
    let padded = ac("ac-serial-20-octet-high-bit.der");
    assert_eq!(
        padded.inner().acinfo.serial_number.as_bytes().len(),
        21,
        "precondition: the sign-padded encoding is 21 octets"
    );
    padded
        .check_profile()
        .expect("the value is 20 octets, which §4.2.5 permits");

    // A 21-octet magnitude is genuinely too long.
    assert_eq!(
        ac("ac-serial-too-long.der").check_profile(),
        Err(Error::ProfileViolation(ProfileViolation::SerialTooLong))
    );
}
