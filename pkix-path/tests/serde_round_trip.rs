//! Round-trip tests for `pkix-path`'s serde feature.
//!
//! Each test takes a value with non-trivial foreign-type fields (Name,
//! SerialNumber, SubjectPublicKeyInfo, ObjectIdentifier), serializes it
//! to JSON, deserializes the JSON back, and asserts both
//! [`PartialEq`]-equality and DER canonicality. The DER canonicality
//! check is the independent oracle: DER is a canonical encoding, so two
//! equivalent values MUST produce byte-identical DER. If round-trip
//! were to corrupt a field's structure without flipping its `PartialEq`
//! verdict (an unlikely failure mode), the DER-bytes assertion would
//! still catch it.
//!
//! Fixture: `gry-leaf.der`, a leaf certificate from the pkix-path test
//! corpus. The cert is openssl-produced; we use its fields as
//! convenient real-world values, not as a path-validation oracle.
//!
//! Run with: `cargo test -p pkix-path --features serde --test serde_round_trip`

#![cfg(feature = "serde")]

use der::{Decode, Encode};
use pkix_path::{
    validate_path, DefaultVerifier, DnAttrRule, Error, TrustAnchor, ValidatedPath, ValidationPolicy,
};
use x509_cert::Certificate;

const LEAF_DER: &[u8] = include_bytes!("fixtures/gry-leaf.der");
const INT_DER: &[u8] = include_bytes!("fixtures/gry-int.der");
const ROOT_DER: &[u8] = include_bytes!("fixtures/gry-root.der");

/// Unix time inside the gry fixture chain's validity window; matches the
/// in-tree `GRY_NOW = 1_780_272_000` (2026-06-01) used elsewhere in the
/// pkix-path test suite.
const GRY_NOW: u64 = 1_780_272_000;

/// OID `1.2.840.10045.4.3.2` (ecdsa-with-SHA256). Chosen as a stable,
/// short reference OID for the tests below; the value is unrelated to
/// the fixtures' actual algorithm.
const REF_OID: &str = "1.2.840.10045.4.3.2";

/// `TrustAnchor` round-trips through JSON: PartialEq holds AND each
/// foreign-type field re-encodes to the same DER bytes.
#[test]
fn trust_anchor_round_trips_through_json() {
    let cert = Certificate::from_der(ROOT_DER).expect("fixture decodes");
    let anchor = TrustAnchor::from_cert(cert);
    let original_subject_der = anchor.subject.to_der().expect("subject encodes");
    let original_spki_der = anchor
        .subject_public_key_info
        .to_der()
        .expect("SPKI encodes");

    let json = serde_json::to_string(&anchor).expect("anchor serializes");
    let back: TrustAnchor = serde_json::from_str(&json).expect("anchor deserializes");

    // Type-level PartialEq.
    assert_eq!(anchor, back);

    // DER canonicality oracle (independent of serde).
    let recovered_subject_der = back.subject.to_der().expect("recovered subject encodes");
    let recovered_spki_der = back
        .subject_public_key_info
        .to_der()
        .expect("recovered SPKI encodes");
    assert_eq!(recovered_subject_der, original_subject_der);
    assert_eq!(recovered_spki_der, original_spki_der);

    // name_constraints round-trips as Option<NameConstraints>. The
    // fixture's root has no NC extension; assert the Option shape is
    // preserved.
    assert_eq!(back.name_constraints, anchor.name_constraints);
}

/// `ValidationPolicy` with non-default OID-laden fields round-trips.
#[test]
fn validation_policy_round_trips_through_json() {
    let oid: der::asn1::ObjectIdentifier = REF_OID.parse().unwrap();
    let mut p = ValidationPolicy::new(1_700_000_000);
    p.initial_policy_set = vec![oid];
    p.required_leaf_eku = Some(vec![oid]);
    p.required_leaf_policy_oids = Some(vec![oid]);
    p.allowed_signature_algs = Some(vec![oid]);
    p.required_leaf_subject_dn_attrs = Some(DnAttrRule::AnyOf(vec![
        DnAttrRule::Field(oid),
        DnAttrRule::AllOf(vec![DnAttrRule::Field(oid)]),
    ]));
    p.max_validity_secs = Some(86_400);
    p.min_rsa_key_bits = Some(2048);
    p.require_subject_alt_name = true;
    p.require_rfc822_san = true;

    let json = serde_json::to_string(&p).expect("policy serializes");
    let back: ValidationPolicy = serde_json::from_str(&json).expect("policy deserializes");
    assert_eq!(p, back);
}

/// `DnAttrRule` round-trips both via direct serde and inside a
/// `ValidationPolicy`. The recursive `AllOf` / `AnyOf` shape exercises
/// the derive's handling of self-referential enums.
#[test]
fn dn_attr_rule_recursive_round_trips() {
    let oid_a: der::asn1::ObjectIdentifier = "2.5.4.65".parse().unwrap(); // pseudonym
    let oid_b: der::asn1::ObjectIdentifier = "2.5.4.42".parse().unwrap(); // givenName
    let oid_c: der::asn1::ObjectIdentifier = "2.5.4.4".parse().unwrap(); // surname
    let rule = DnAttrRule::AnyOf(vec![
        DnAttrRule::Field(oid_a),
        DnAttrRule::AllOf(vec![DnAttrRule::Field(oid_b), DnAttrRule::Field(oid_c)]),
    ]);
    let json = serde_json::to_string(&rule).expect("rule serializes");
    let back: DnAttrRule = serde_json::from_str(&json).expect("rule deserializes");
    assert_eq!(rule, back);
}

/// `ValidatedPath` produced by `validate_path` on the gry chain
/// round-trips through JSON. Both `PartialEq`-equality and per-field
/// DER canonicality hold.
///
/// `validate_path` is invoked only to obtain a `ValidatedPath` value
/// without poking at its `#[non_exhaustive]` struct literal — the
/// validation step is not part of the serde oracle. The serde oracle
/// for this test is "after serialize → deserialize, every DER-encodable
/// field re-encodes to bytes identical to the original."
#[test]
fn validated_path_round_trips_through_json() {
    let leaf = Certificate::from_der(LEAF_DER).expect("leaf decodes");
    let int_cert = Certificate::from_der(INT_DER).expect("int decodes");
    let root = Certificate::from_der(ROOT_DER).expect("root decodes");
    let anchors = [TrustAnchor::from_cert(root)];
    let vp = validate_path(
        &[leaf, int_cert],
        &anchors,
        &ValidationPolicy::new(GRY_NOW),
        &DefaultVerifier,
    )
    .expect("gry chain validates at GRY_NOW");

    let original_subj_der = vp.leaf_subject.to_der().unwrap();
    let original_issuer_der = vp.leaf_issuer.to_der().unwrap();
    let original_serial_der = vp.leaf_serial.to_der().unwrap();
    let original_spki_der = vp.leaf_spki.to_der().unwrap();

    let json = serde_json::to_string(&vp).expect("validated path serializes");
    let back: ValidatedPath = serde_json::from_str(&json).expect("validated path deserializes");
    assert_eq!(vp, back);

    // DER canonicality oracle for each foreign-type field.
    assert_eq!(back.leaf_subject.to_der().unwrap(), original_subj_der);
    assert_eq!(back.leaf_issuer.to_der().unwrap(), original_issuer_der);
    assert_eq!(back.leaf_serial.to_der().unwrap(), original_serial_der);
    assert_eq!(back.leaf_spki.to_der().unwrap(), original_spki_der);
}

/// `Error::Der(DerError)` round-trips with Display preservation. The
/// recovered `Error` deserializes from JSON; its `Display` output must
/// match the original (the DerError's `message` field carries the
/// rendered text verbatim).
#[test]
fn error_der_round_trips_preserving_display() {
    // Manufacture a DerError via the `From<der::Error> for Error`
    // shortcut. We use a real der::Error to get a meaningful Display
    // message, then assert round-trip preserves it.
    let synthetic: Error = der::Error::new(der::ErrorKind::Failed, der::Length::ZERO).into();
    let original_display = format!("{synthetic}");

    let json = serde_json::to_string(&synthetic).expect("error serializes");
    let back: Error = serde_json::from_str(&json).expect("error deserializes");
    assert_eq!(synthetic, back);
    assert_eq!(format!("{back}"), original_display);
}

/// Unit-variant `Error` round-trips. Sanity check that the most common
/// error shape (no payload, or `{ index: usize }`) serializes cleanly.
#[test]
fn error_unit_and_index_variants_round_trip() {
    let cases = vec![
        Error::NoTrustedPath,
        Error::PathTooLong,
        Error::MissingSan,
        Error::MissingRfc822San,
        Error::MissingEku,
        Error::SubjectDnAttrRuleUnmet,
        Error::SignatureInvalid { index: 3 },
        Error::ValidityPeriod { index: 0 },
        Error::DuplicateCertificate { first: 1, second: 4 },
    ];
    for err in &cases {
        let json = serde_json::to_string(err).expect("variant serializes");
        let back: Error = serde_json::from_str(&json).expect("variant deserializes");
        assert_eq!(err, &back, "round-trip mismatch for {err:?}");
    }
}
