//! Integration tests for the TLS-handshake and OCSP-response SCT
//! extractors (PKIX-baac.6).
//!
//! # Fixtures
//!
//! * `tests/fixtures/resp-sct-extension.der` — a real-world OCSP
//!   response from SwissSign for `cryptography.io`, carrying four SCTs
//!   in the `SingleResponse.singleExtensions` extension (OID
//!   1.3.6.1.4.1.11129.2.4.5). Copied verbatim from
//!   `vectors/cryptography_vectors/x509/ocsp/resp-sct-extension.der` in
//!   the pyca/cryptography test-vectors repository (Apache-2.0 / BSD-3-Clause).
//!
//! * `tests/fixtures/ocsp-no-sct.der` — an OCSP response that decodes
//!   cleanly but carries no SCT extension. Copied verbatim from this
//!   workspace's `pkix-revocation/tests/fixtures/ocsp-ca-a-good.der`
//!   (workspace-internal fixture; same Apache-2.0 / MIT license as the
//!   rest of the crate).
//!
//! # Oracles
//!
//! Expected SCT counts and per-SCT field values for `resp-sct-extension.der`
//! come from pyca/cryptography's `cryptography.x509.ocsp.load_der_ocsp_response`
//! + `.single_extensions` traversal — independent of pkix-ct.
//!
//! For the TLS-extension test, the input bytes are constructed by
//! peeling the outer DER OCTET STRING from the cert fixture's SCT
//! extension (yielding the bare `SerializedSCTList` per RFC 6962 §3.3),
//! which is exactly what would arrive over the wire in TLS
//! extension 18 (`signed_certificate_timestamp`).

use std::fs;

use pkix_ct::{sct_list_from_tls_extension, SctList};
use x509_cert::der::{Decode, DecodePem};
use x509_cert::Certificate;

const CRYPTOGRAPHY_SCTS_PEM: &str = "tests/fixtures/cryptography-scts.pem";

/// SCT-list cert extension OID.
const SCT_LIST_OID: &str = "1.3.6.1.4.1.11129.2.4.2";

// --- TLS-extension path --------------------------------------------------

/// Build a TLS-extension-18 payload by stripping the outer OCTET STRING
/// wrap from the cert extension's value. This produces exactly the bytes
/// that arrive over TLS for `signed_certificate_timestamp` (RFC 6962 §3.3).
fn tls_ext_payload_from_cert(path: &str) -> Vec<u8> {
    let pem = fs::read_to_string(path).expect("read fixture");
    let cert = Certificate::from_pem(&pem).expect("parse PEM");
    let exts = cert.tbs_certificate().extensions().unwrap();
    let ext = exts
        .iter()
        .find(|e| e.extn_id.to_string() == SCT_LIST_OID)
        .expect("no SCT extension");
    let outer = ext.extn_value.as_bytes();
    // Peel one OCTET STRING wrap to get the SerializedSCTList bytes.
    let inner =
        x509_cert::der::asn1::OctetString::from_der(outer).expect("strip outer OCTET STRING");
    inner.as_bytes().to_vec()
}

#[test]
fn tls_extension_parses_serialized_sct_list() {
    let payload = tls_ext_payload_from_cert(CRYPTOGRAPHY_SCTS_PEM);
    let list = sct_list_from_tls_extension(&payload).expect("parse TLS payload");

    assert_eq!(list.scts().len(), 2);
    // Spot-check the first log_id — full vectors are validated in tests/parser.rs.
    assert_eq!(list.scts()[0].log_id[0..4], [0x29, 0x3c, 0x51, 0x96]);
    assert_eq!(list.scts()[1].log_id[0..4], [0x6f, 0x53, 0x76, 0xac]);
}

#[test]
fn tls_extension_consistent_with_extension_value_parse() {
    // The TLS-extension path and the cert-extension path must produce
    // identical SctList values for the same underlying SCT bytes.
    let pem = fs::read_to_string(CRYPTOGRAPHY_SCTS_PEM).unwrap();
    let cert = Certificate::from_pem(&pem).unwrap();
    let ext = cert
        .tbs_certificate()
        .extensions()
        .unwrap()
        .iter()
        .find(|e| e.extn_id.to_string() == SCT_LIST_OID)
        .unwrap();

    let via_cert_ext = SctList::from_extension_value(ext.extn_value.as_bytes()).unwrap();
    let payload = tls_ext_payload_from_cert(CRYPTOGRAPHY_SCTS_PEM);
    let via_tls_ext = sct_list_from_tls_extension(&payload).unwrap();

    assert_eq!(via_cert_ext, via_tls_ext);
}

#[test]
fn tls_extension_rejects_garbage() {
    // A single 0xff byte is not a valid u16 length prefix.
    let bad = [0xff];
    assert!(sct_list_from_tls_extension(&bad).is_err());
}

// --- OCSP path (gated behind the `ocsp` feature) -------------------------

#[cfg(feature = "ocsp")]
mod ocsp {
    use super::*;
    use pkix_ct::sct_list_from_ocsp_response;

    const OCSP_WITH_SCT: &str = "tests/fixtures/resp-sct-extension.der";
    const OCSP_NO_SCT: &str = "tests/fixtures/ocsp-no-sct.der";

    /// Independent oracle (pyca's `single_extensions` traversal):
    /// 4 SCTs, first log_id starts with 0x44 0x94 0x65 0x2e, signatures
    /// are 72 bytes each (DER ECDSA-Sig-Value with SEQUENCE-of-two-INTEGERs).
    const EXPECTED_LOG_ID_0_HEAD: [u8; 4] = [0x44, 0x94, 0x65, 0x2e];
    const EXPECTED_LOG_ID_1_HEAD: [u8; 4] = [0x6f, 0x53, 0x76, 0xac];
    const EXPECTED_LOG_ID_2_HEAD: [u8; 4] = [0xbb, 0xd9, 0xdf, 0xbc];
    const EXPECTED_LOG_ID_3_HEAD: [u8; 4] = [0xee, 0x4b, 0xbd, 0xb7];

    #[test]
    fn extracts_sct_list_from_ocsp_single_response() {
        let der = fs::read(OCSP_WITH_SCT).expect("read OCSP fixture");
        let result = sct_list_from_ocsp_response(&der).expect("parse OCSP");
        let list = result.expect("OCSP response contains SCT extension");

        assert_eq!(list.scts().len(), 4, "four SCTs expected");
        assert_eq!(list.scts()[0].log_id[0..4], EXPECTED_LOG_ID_0_HEAD);
        assert_eq!(list.scts()[1].log_id[0..4], EXPECTED_LOG_ID_1_HEAD);
        assert_eq!(list.scts()[2].log_id[0..4], EXPECTED_LOG_ID_2_HEAD);
        assert_eq!(list.scts()[3].log_id[0..4], EXPECTED_LOG_ID_3_HEAD);

        // All four are ECDSA-SHA256 signatures of 72 bytes.
        for sct in list.scts() {
            assert_eq!(sct.version, 0);
            assert_eq!(sct.hash_alg, 4); // SHA256
            assert_eq!(sct.sig_alg, 3); // ECDSA
            assert_eq!(sct.signature.len(), 72);
            assert!(sct.extensions.is_empty());
        }
    }

    #[test]
    fn ocsp_response_without_sct_returns_none() {
        let der = fs::read(OCSP_NO_SCT).expect("read OCSP no-SCT fixture");
        let result = sct_list_from_ocsp_response(&der).expect("parse OCSP");
        assert!(result.is_none(), "OCSP response had no SCT extension");
    }

    #[test]
    fn malformed_ocsp_returns_parse_error() {
        // Not a valid DER SEQUENCE.
        let bad = [0xff, 0xff, 0xff];
        let err = sct_list_from_ocsp_response(&bad).unwrap_err();
        assert_eq!(err, pkix_ct::Error::ParseError);
    }
}

/// A responder that refuses is not a responder that carried no SCTs.
///
/// `sct_list_from_ocsp_response` used to return `Ok(None)` for any
/// `responseStatus` other than `successful`, which is the same answer it
/// gives for a normal response with no SCT extension. A caller asking
/// "do I have SCTs from OCSP for this certificate?" could not tell
/// "no, the responder answered and embedded none" — settled — from "no,
/// the responder would not answer" — worth retrying or alerting on.
///
/// The input is built here rather than committed as a fixture because it
/// is three bytes of content and entirely determined by RFC 6960 §4.2.1:
/// `OCSPResponse ::= SEQUENCE { responseStatus OCSPResponseStatus,
/// responseBytes [0] EXPLICIT ResponseBytes OPTIONAL }`, so a bare
/// status with no `responseBytes` is exactly what a loaded responder
/// sends for `tryLater(3)`.
#[test]
#[cfg(feature = "ocsp")]
fn an_ocsp_refusal_is_reported_rather_than_read_as_no_scts() {
    for (status, name) in [
        (1u8, "malformedRequest"),
        (2, "internalError"),
        (3, "tryLater"),
        (5, "sigRequired"),
        (6, "unauthorized"),
    ] {
        // SEQUENCE { ENUMERATED status }
        let der = [0x30, 0x03, 0x0A, 0x01, status];
        let result = pkix_ct::sct_list_from_ocsp_response(&der);
        assert_eq!(
            result.err(),
            Some(pkix_ct::Error::OcspResponseNotSuccessful(status)),
            "{name}({status}) must be reported as a refusal, not as Ok(None)"
        );
    }
}

/// And `successful` with no SCT extension must still be `Ok(None)`, so
/// the fix did not turn a settled answer into an error.
#[test]
#[cfg(feature = "ocsp")]
fn a_successful_response_without_scts_is_still_ok_none() {
    let der = fs::read("tests/fixtures/ocsp-no-sct.der").expect("read OCSP no-SCT fixture");
    let result = pkix_ct::sct_list_from_ocsp_response(&der)
        .expect("a successful response must not be an error");
    assert!(
        result.is_none(),
        "this response carries no SCT extension, which is an answer"
    );
}

// --- the top-level responseExtensions branch -----------------------------

/// RFC 6960 §4.2.1 gives a response two places for an extension, and
/// RFC 6962 §3.3 does not say which to use.
///
/// `sct_list_from_ocsp_response` looks in each `SingleResponse`'s
/// `singleExtensions` first and then falls back to the top-level
/// `responseExtensions`. Every fixture here carried its SCTs in the
/// first, so the fallback had no test at all -- not merely its OID
/// comparison, the whole branch. A responder putting the list at the top
/// level would have its SCTs silently ignored, and the caller would see
/// a certificate with no CT evidence rather than one with an SCT.
///
/// The fixture carries a nonce *before* the SCT list, so a scan matching
/// the wrong OID finds something and tries to parse it as a list.
/// Oracle: `tests/fixtures/ocsp-response-extensions/gen.py`, which
/// asserts the placement it built.
#[test]
#[cfg(feature = "ocsp")]
fn extracts_sct_list_from_top_level_response_extensions() {
    let der = fs::read("tests/fixtures/ocsp-response-extensions/with-sct.der")
        .expect("read the top-level fixture");
    let list = pkix_ct::sct_list_from_ocsp_response(&der)
        .expect("the response parses")
        .expect("and its responseExtensions carry an SCT list");

    assert_eq!(list.scts().len(), 1, "one SCT, from the oracle fixture");
    let sct = &list.scts()[0];
    assert_eq!(sct.version, 0);
    assert_eq!(sct.hash_alg, 4, "SHA-256");
    assert_eq!(sct.sig_alg, 3, "ECDSA");
    assert_eq!(
        sct.timestamp_ms, 1_750_032_000_000,
        "the same SCT the sct-oracle tests pin"
    );
}

/// And a response with no SCT list in either place reports none.
///
/// The same response minus the SCT extension, so "no list anywhere" is
/// distinguishable from "looked in the wrong place". Without it, a
/// fallback that always answered `None` would be indistinguishable from
/// one that works.
#[test]
#[cfg(feature = "ocsp")]
fn a_top_level_response_without_an_sct_list_reports_none() {
    let der = fs::read("tests/fixtures/ocsp-response-extensions/without-sct.der")
        .expect("read the control fixture");
    assert!(
        pkix_ct::sct_list_from_ocsp_response(&der)
            .expect("the response parses")
            .is_none(),
        "no SCT extension in either place means no list"
    );
}
