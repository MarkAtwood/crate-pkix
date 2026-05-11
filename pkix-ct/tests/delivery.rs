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
    let exts = cert.tbs_certificate.extensions.as_ref().unwrap();
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

    assert_eq!(list.0.len(), 2);
    // Spot-check the first log_id — full vectors are validated in tests/parser.rs.
    assert_eq!(list.0[0].log_id[0..4], [0x29, 0x3c, 0x51, 0x96]);
    assert_eq!(list.0[1].log_id[0..4], [0x6f, 0x53, 0x76, 0xac]);
}

#[test]
fn tls_extension_consistent_with_extension_value_parse() {
    // The TLS-extension path and the cert-extension path must produce
    // identical SctList values for the same underlying SCT bytes.
    let pem = fs::read_to_string(CRYPTOGRAPHY_SCTS_PEM).unwrap();
    let cert = Certificate::from_pem(&pem).unwrap();
    let ext = cert
        .tbs_certificate
        .extensions
        .as_ref()
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

        assert_eq!(list.0.len(), 4, "four SCTs expected");
        assert_eq!(list.0[0].log_id[0..4], EXPECTED_LOG_ID_0_HEAD);
        assert_eq!(list.0[1].log_id[0..4], EXPECTED_LOG_ID_1_HEAD);
        assert_eq!(list.0[2].log_id[0..4], EXPECTED_LOG_ID_2_HEAD);
        assert_eq!(list.0[3].log_id[0..4], EXPECTED_LOG_ID_3_HEAD);

        // All four are ECDSA-SHA256 signatures of 72 bytes.
        for sct in &list.0 {
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
