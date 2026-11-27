//! Parsing RFC 5755 attribute certificates.
//!
//! Fixtures: `tests/fixtures/gen.py`. There is no independent tool that
//! builds attribute certificates — neither OpenSSL nor pyca/cryptography
//! models them, which is also why `pkix-ac` declares the ASN.1 itself —
//! so the fixtures are assembled from the productions in RFC 5755
//! Appendix A and signed by `openssl dgst`. The generator is therefore
//! not an independent oracle the way `pkix-ct`'s are, and the tests here
//! say so where it matters.

use der::asn1::ObjectIdentifier;
use der::{Decode as _, Encode as _};
use pkix_ac::types::{AttCertIssuer, AttCertVersion, AttributeCertificateInner};

/// `id-at-role` — RFC 5755 §4.4.5.
const ID_AT_ROLE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.72");

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

/// The shape RFC 5755 §4.1 describes, read back field by field.
#[test]
fn a_role_attribute_certificate_parses() {
    let der = fixture("ac-role-valid.der");
    let ac = AttributeCertificateInner::from_der(&der).expect("parses as an AC");

    assert_eq!(ac.acinfo.version, AttCertVersion::V2);

    // §4.2.2: the holder is named here by entityName, not by a
    // reference to its public-key certificate.
    assert!(ac.acinfo.holder.entity_name.is_some());
    assert!(ac.acinfo.holder.base_certificate_id.is_none());
    assert!(ac.acinfo.holder.object_digest_info.is_none());

    // §4.2.3: the issuer must be the v2 form, and v1Form must not
    // appear. The type can represent v1Form so that such a certificate
    // parses and can be refused with a reason rather than as malformed.
    let AttCertIssuer::V2Form(v2) = &ac.acinfo.issuer else {
        panic!("expected the v2 form, got v1Form");
    };
    assert!(v2.issuer_name.is_some(), "§4.2.3 requires issuerName");
    assert!(v2.base_certificate_id.is_none());
    assert!(v2.object_digest_info.is_none());

    assert_eq!(ac.acinfo.attributes.len(), 1);
    assert_eq!(ac.acinfo.attributes[0].r#type, ID_AT_ROLE);
    assert_eq!(
        ac.acinfo.attributes[0].values.len(),
        1,
        "RFC 5755 §4.1 requires at least one value"
    );

    // Neither optional trailing field is present, and they are
    // distinguishable only by tag — a BIT STRING against a SEQUENCE —
    // since neither is context-tagged.
    assert!(ac.acinfo.issuer_unique_id.is_none());
    assert!(ac.acinfo.extensions.is_none());
}

/// A multi-valued attribute keeps both values, and `attributes` is a
/// `SEQUENCE OF` so its order is part of the value.
///
/// The fixture is one `id-at-role` attribute with two values, which is
/// what §4.2.7 requires — "only one instance of each attribute can occur
/// in a single AC, but each instance can be multi-valued". It used to be
/// two separate `id-at-role` attributes, which that section forbids.
///
/// Note the values come back in DER `SET OF` order rather than the order
/// the generator wrote them, because `SetOfVec` sorts on decode. That is
/// the behaviour `validate.rs` leans on to show why the signed bytes
/// must be a slice of the original rather than a re-encoding.
#[test]
fn a_multi_valued_attribute_keeps_both_values() {
    let der = fixture("ac-two-roles.der");
    let ac = AttributeCertificateInner::from_der(&der).expect("parses");
    assert_eq!(ac.acinfo.attributes.len(), 1, "one attribute type");
    assert_eq!(ac.acinfo.attributes[0].r#type, ID_AT_ROLE);

    let values = &ac.acinfo.attributes[0].values;
    assert_eq!(values.len(), 2, "both values survive");

    let rendered: Vec<String> = values
        .as_slice()
        .iter()
        .map(|v| {
            let der = v.to_der().expect("re-encode a value");
            String::from_utf8_lossy(&der).to_string()
        })
        .collect();
    assert!(
        rendered.iter().any(|s| s.contains("auditor")),
        "the auditor role must be present, got {rendered:?}"
    );
    assert!(
        rendered.iter().any(|s| s.contains("approver")),
        "and the approver role, got {rendered:?}"
    );
}

/// The parser must not quietly accept trailing bytes after the
/// certificate, which is how a parser is made to disagree with its peers
/// about where a value ends.
#[test]
fn trailing_bytes_are_refused() {
    let mut der = fixture("ac-role-valid.der");
    der.push(0x00);
    assert!(
        AttributeCertificateInner::from_der(&der).is_err(),
        "a trailing byte must be an error, not ignored"
    );
}

/// Truncation anywhere must be an error rather than a partial value.
#[test]
fn truncation_is_refused_at_every_length() {
    let der = fixture("ac-role-valid.der");
    for cut in 1..der.len() {
        assert!(
            AttributeCertificateInner::from_der(&der[..cut]).is_err(),
            "truncating to {cut} of {} bytes parsed anyway",
            der.len()
        );
    }
}

/// The signature covers the DER of `acinfo`, so a consumer has to be able
/// to recover exactly those bytes. Re-encoding the parsed structure must
/// reproduce the slice that was signed, or signature verification built
/// on it would be checking different bytes than the AA signed.
#[test]
fn acinfo_re_encodes_to_the_bytes_that_were_signed() {
    let der = fixture("ac-role-valid.der");
    let ac = AttributeCertificateInner::from_der(&der).expect("parses");
    let reencoded = ac.acinfo.to_der().expect("re-encode acinfo");

    // Locate acinfo in the original: it is the first element inside the
    // outer SEQUENCE, so it starts after the outer header and runs for
    // its own full length.
    let outer_header = if der[1] < 0x80 {
        2
    } else {
        2 + (der[1] & 0x7F) as usize
    };
    let body = &der[outer_header..];
    let acinfo_header = if body[1] < 0x80 {
        2
    } else {
        2 + (body[1] & 0x7F) as usize
    };
    let acinfo_len = if body[1] < 0x80 {
        body[1] as usize
    } else {
        let n = (body[1] & 0x7F) as usize;
        body[2..2 + n]
            .iter()
            .fold(0usize, |a, &b| (a << 8) | b as usize)
    };
    let original = &body[..acinfo_header + acinfo_len];

    assert_eq!(
        reencoded, original,
        "re-encoded acinfo differs from the signed bytes"
    );
}
