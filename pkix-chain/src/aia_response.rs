//! Private decoding of AIA `caIssuers` response bodies.
//!
//! RFC 5280 §4.2.2.1: when caIssuers is published over HTTP the URI
//! "MUST point to either a single DER encoded certificate as specified in
//! [RFC2585] or a collection of certificates in a BER or DER encoded
//! 'certs-only' CMS message as specified in [RFC2797]". Both forms are
//! accepted here.
//!
//! The certs-only message is decoded by hand with `der` rather than with
//! the `cms` crate to keep `pkix-chain`'s dependency set unchanged; only
//! the path to `SignedData.certificates` is walked:
//!
//! ```text
//! ContentInfo ::= SEQUENCE {
//!   contentType  OBJECT IDENTIFIER (id-signedData),
//!   content  [0] EXPLICIT SignedData }
//! SignedData ::= SEQUENCE {
//!   version INTEGER, digestAlgorithms SET, encapContentInfo SEQUENCE,
//!   certificates [0] IMPLICIT SET OF CertificateChoices OPTIONAL,
//!   ... }
//! ```
//!
//! Limitation: `der` decodes definite-length encodings only, so a BER
//! message using indefinite lengths is rejected as
//! [`AiaError::MalformedCertificate`]. Certificates published by real CAs
//! as `.p7c` are DER in practice.

use der::asn1::{AnyRef, ObjectIdentifier};
use der::{Decode, Reader, SliceReader, Tag, TagNumber, Tagged as _};
use pkix_aia::AiaError;
use x509_cert::Certificate;

/// `id-signedData` — RFC 5652 §5.1.
const OID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

/// Decode a caIssuers response body into certificates.
///
/// A body that is a single DER `Certificate` yields one element. A
/// certs-only CMS `ContentInfo` yields the plain `Certificate` entries of
/// `SignedData.certificates` (other `CertificateChoices` alternatives are
/// skipped), at most `max_certs` of them; further entries are ignored so a
/// hostile bundle cannot flood the path-builder pool.
///
/// A body longer than `max_bytes` is refused before parsing, with
/// `AiaError::ResponseTooLarge`.
pub(crate) fn parse_ca_issuers_response(
    bytes: &[u8],
    max_certs: usize,
    max_bytes: usize,
) -> Result<Vec<Certificate>, AiaError> {
    // Before any parsing. The DER parser is bounded by its own length
    // encoding, but it still allocates in proportion to claimed lengths
    // and walks the whole structure, so handing it an arbitrarily large
    // body is an amplification step with nothing behind it.
    if bytes.len() > max_bytes {
        return Err(AiaError::ResponseTooLarge {
            limit: max_bytes,
            actual: bytes.len(),
        });
    }
    let single_err = match Certificate::from_der(bytes) {
        Ok(cert) => return Ok(vec![cert]),
        Err(e) => e,
    };
    match certs_only_cms(bytes, max_certs) {
        Ok(Some(certs)) => Ok(certs),
        // Not a SignedData ContentInfo: report the single-cert error,
        // which is the more useful diagnostic for a plain garbage body.
        Ok(None) => Err(AiaError::MalformedCertificate(single_err.to_string())),
        Err(e) => Err(AiaError::MalformedCertificate(format!(
            "certs-only CMS response: {e}"
        ))),
    }
}

/// `Ok(None)` when `bytes` is not a `SignedData` `ContentInfo`.
fn certs_only_cms(bytes: &[u8], max_certs: usize) -> der::Result<Option<Vec<Certificate>>> {
    let Ok(content_info) = AnyRef::from_der(bytes) else {
        return Ok(None);
    };
    if content_info.tag() != Tag::Sequence {
        return Ok(None);
    }
    let mut ci = SliceReader::new(content_info.value())?;
    let Ok(content_type) = ObjectIdentifier::decode(&mut ci) else {
        return Ok(None);
    };
    if content_type != OID_SIGNED_DATA {
        return Ok(None);
    }

    // content [0] EXPLICIT SignedData
    let explicit = AnyRef::decode(&mut ci)?;
    expect_context_tag(explicit.tag(), 0)?;
    let signed_data = AnyRef::from_der(explicit.value())?;
    if signed_data.tag() != Tag::Sequence {
        return Err(Tag::Sequence.value_error().into());
    }

    let mut sd = SliceReader::new(signed_data.value())?;
    AnyRef::decode(&mut sd)?; // version
    AnyRef::decode(&mut sd)?; // digestAlgorithms
    AnyRef::decode(&mut sd)?; // encapContentInfo

    let mut certs = Vec::new();
    if sd.is_finished() {
        return Ok(Some(certs));
    }
    let set = AnyRef::decode(&mut sd)?;
    if !is_context_tag(set.tag(), 0) {
        // `certificates` absent ([1] crls or signerInfos follows).
        return Ok(Some(certs));
    }
    let mut entries = SliceReader::new(set.value())?;
    while !entries.is_finished() && certs.len() < max_certs {
        if Tag::peek(&entries)? == Tag::Sequence {
            certs.push(Certificate::decode(&mut entries)?);
        } else {
            // extendedCertificate / v1 / v2 attribute certs / other.
            AnyRef::decode(&mut entries)?;
        }
    }
    Ok(Some(certs))
}

fn is_context_tag(tag: Tag, number: u32) -> bool {
    matches!(
        tag,
        Tag::ContextSpecific { constructed: true, number: n } if n == TagNumber(number)
    )
}

fn expect_context_tag(tag: Tag, number: u32) -> der::Result<()> {
    if is_context_tag(tag, number) {
        Ok(())
    } else {
        Err(tag.unexpected_error(None).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(number: u32, constructed: bool) -> Tag {
        Tag::ContextSpecific {
            constructed,
            number: TagNumber(number),
        }
    }

    /// All three parts of the tag have to agree.
    ///
    /// The CMS tests below feed well-formed input, so the predicate was only
    /// ever asked questions it answered yes to: it could have returned `true`
    /// unconditionally and the `certificates` branch would have been taken
    /// for a `[1] crls` or a `signerInfos` field, handing arbitrary SET
    /// content to the certificate decoder.
    #[test]
    fn a_context_tag_matches_only_on_class_number_and_construction() {
        assert!(is_context_tag(ctx(0, true), 0));
        assert!(is_context_tag(ctx(1, true), 1));

        assert!(!is_context_tag(ctx(1, true), 0), "wrong number");
        assert!(!is_context_tag(ctx(0, true), 1), "wrong number");
        assert!(
            !is_context_tag(ctx(0, false), 0),
            "primitive, not constructed"
        );
        assert!(!is_context_tag(Tag::Sequence, 0), "universal class");
        assert!(!is_context_tag(Tag::OctetString, 0), "universal class");
    }

    /// And the fallible wrapper refuses what the predicate rejects, rather
    /// than passing everything through.
    #[test]
    fn expect_context_tag_refuses_a_tag_it_did_not_want() {
        expect_context_tag(ctx(0, true), 0).expect("the matching tag is accepted");
        assert!(expect_context_tag(ctx(1, true), 0).is_err(), "wrong number");
        assert!(
            expect_context_tag(ctx(0, false), 0).is_err(),
            "primitive, not constructed"
        );
        assert!(
            expect_context_tag(Tag::Sequence, 0).is_err(),
            "universal class"
        );
    }

    const INT_DER: &[u8] = include_bytes!("../tests/fixtures/review/int.der");
    const INT_P7C: &[u8] = include_bytes!("../tests/fixtures/review/int.p7c");

    #[test]
    fn single_der_certificate() {
        assert_eq!(
            parse_ca_issuers_response(INT_DER, 4, usize::MAX)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn certs_only_cms_yields_embedded_certificate() {
        let certs = parse_ca_issuers_response(INT_P7C, 4, usize::MAX).unwrap();
        assert_eq!(certs, vec![Certificate::from_der(INT_DER).unwrap()]);
    }

    #[test]
    fn cert_cap_applies() {
        assert!(parse_ca_issuers_response(INT_P7C, 0, usize::MAX)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn garbage_is_malformed() {
        assert!(matches!(
            parse_ca_issuers_response(b"\x30\x03\x02\x01\x00", 4, usize::MAX),
            Err(AiaError::MalformedCertificate(_))
        ));
        let mut truncated = INT_P7C.to_vec();
        truncated.truncate(truncated.len() - 10);
        assert!(parse_ca_issuers_response(&truncated, 4, usize::MAX).is_err());
    }

    /// An oversize body is refused before the DER parser sees it.
    ///
    /// The byte cap is defence in depth behind the fetcher's own body
    /// cap. It is sized for a certs-only bundle rather than a single
    /// certificate, because this function decodes both.
    #[test]
    fn an_oversize_response_is_refused_before_parsing() {
        // A body one byte over the limit, and valid DER, so nothing but
        // the cap can be refusing it.
        let limit = INT_DER.len() - 1;
        assert_eq!(
            parse_ca_issuers_response(INT_DER, 4, limit),
            Err(AiaError::ResponseTooLarge {
                limit,
                actual: INT_DER.len(),
            }),
            "over the cap must be ResponseTooLarge, naming both numbers"
        );

        // Exactly at the limit is allowed: the check is `>`, not `>=`,
        // so a response of exactly the configured size still parses.
        assert_eq!(
            parse_ca_issuers_response(INT_DER, 4, INT_DER.len())
                .expect("a body exactly at the cap is within it")
                .len(),
            1
        );
    }

    /// The default must not sit on top of legitimate traffic.
    ///
    /// `max_certs_per_response` defaults to 16, and a certificate with
    /// many SANs reaches about 16 KiB, so a bundle at those limits is
    /// around 256 KiB. A cap sized for one certificate — the obvious
    /// reading of "how big is a certificate" — would reject valid
    /// bundles.
    #[test]
    fn the_default_cap_admits_a_full_legitimate_bundle() {
        let cfg = crate::AiaConfig::default();
        assert!(
            cfg.max_response_bytes >= cfg.max_certs_per_response * 16 * 1024,
            "default cap {} must admit {} certificates of 16 KiB",
            cfg.max_response_bytes,
            cfg.max_certs_per_response
        );
    }
}
