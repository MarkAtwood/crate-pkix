//! Integration tests for the SCT binary-format parser.
//!
//! # Fixtures
//!
//! The test fixtures under `tests/fixtures/` are committed verbatim from
//! the pyca/cryptography test vectors repository
//! (<https://github.com/pyca/cryptography>), which is dual-licensed
//! Apache-2.0 / BSD-3-Clause. The specific files in use:
//!
//! * `cryptography-scts.pem` — a Let's Encrypt-issued certificate for
//!   `cryptography.io` (valid 2018-09-26 to 2018-12-25, since expired)
//!   carrying two embedded SCTs from Google's `Argon2018` and Cloudflare's
//!   `Nimbus 2018` logs. Path in upstream:
//!   `vectors/cryptography_vectors/x509/cryptography-scts.pem`.
//!
//! * `invalid-sct-version.der` — the same cert with the first SCT's
//!   version byte flipped from 0 to 1 (an unsupported version).
//!   Path in upstream:
//!   `vectors/cryptography_vectors/x509/custom/invalid-sct-version.der`.
//!
//! * `invalid-sct-length.der` — the same cert with the outer DER OCTET
//!   STRING shortened so the inner `SerializedSCTList` runs past its
//!   container. Path in upstream:
//!   `vectors/cryptography_vectors/x509/custom/invalid-sct-length.der`.
//!
//! # Oracles
//!
//! Test vector values (timestamps, log IDs, signature lengths) come from
//! three independent sources that all agree:
//!
//! 1. `openssl x509 -text -noout` rendering of the SCT extension.
//! 2. pyca/cryptography's `parse_scts()` (in `src/rust/src/x509/sct.rs`),
//!    which is a separate independent implementation.
//! 3. Direct extraction of the raw u64 big-endian timestamp bytes from
//!    `openssl asn1parse` of the cert's extension.
//!
//! Per the workspace test-discipline rule, no test uses this crate as its
//! own oracle. The expected hex values are typed in from openssl /
//! pyca / hand-decoded raw bytes, not from a previous run of
//! `pkix_ct::SctList::from_extension_value`.

use std::fs;

use pkix_ct::{Error, SctList};
use x509_cert::der::{Decode, DecodePem};
use x509_cert::Certificate;

const CRYPTOGRAPHY_SCTS_PEM: &str = "tests/fixtures/cryptography-scts.pem";
const INVALID_VERSION_DER: &str = "tests/fixtures/invalid-sct-version.der";
const INVALID_LENGTH_DER: &str = "tests/fixtures/invalid-sct-length.der";

/// OID for the SCT-list cert extension (RFC 6962 §3.3).
const SCT_LIST_OID: &str = "1.3.6.1.4.1.11129.2.4.2";

/// Pull the SCT-list extension value out of a cert.
fn extract_sct_extension(cert: &Certificate) -> Vec<u8> {
    let extensions = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .expect("cert has no extensions");
    for ext in extensions {
        if ext.extn_id.to_string() == SCT_LIST_OID {
            return ext.extn_value.as_bytes().to_vec();
        }
    }
    panic!("cert has no SCT-list extension");
}

fn load_pem_cert(path: &str) -> Certificate {
    let pem = fs::read_to_string(path).expect("read fixture");
    Certificate::from_pem(&pem).expect("parse PEM cert")
}

fn load_der_cert(path: &str) -> Certificate {
    let der = fs::read(path).expect("read fixture");
    Certificate::from_der(&der).expect("parse DER cert")
}

// ---- positive: a real cert with two SCTs --------------------------------

/// Independent oracle (openssl + pyca + raw u64 bytes all agree):
///
/// SCT 0: version=0, log_id = SHA-256 of Google Argon2018's pubkey =
///        29:3C:51:96:54:C8:39:65:BA:AA:50:FC:58:07:D4:B7:
///        6F:BF:58:7A:29:72:DC:A4:C3:0C:F4:E5:45:47:F4:78
/// SCT 1: version=0, log_id = SHA-256 of Cloudflare Nimbus 2018's pubkey =
///        6F:53:76:AC:31:F0:31:19:D8:99:00:A4:51:15:FF:77:
///        15:1C:11:D9:02:C1:00:29:06:8D:B2:08:9A:37:D9:13
const EXPECTED_LOG_ID_0: [u8; 32] = [
    0x29, 0x3c, 0x51, 0x96, 0x54, 0xc8, 0x39, 0x65, 0xba, 0xaa, 0x50, 0xfc, 0x58, 0x07, 0xd4, 0xb7,
    0x6f, 0xbf, 0x58, 0x7a, 0x29, 0x72, 0xdc, 0xa4, 0xc3, 0x0c, 0xf4, 0xe5, 0x45, 0x47, 0xf4, 0x78,
];
const EXPECTED_LOG_ID_1: [u8; 32] = [
    0x6f, 0x53, 0x76, 0xac, 0x31, 0xf0, 0x31, 0x19, 0xd8, 0x99, 0x00, 0xa4, 0x51, 0x15, 0xff, 0x77,
    0x15, 0x1c, 0x11, 0xd9, 0x02, 0xc1, 0x00, 0x29, 0x06, 0x8d, 0xb2, 0x08, 0x9a, 0x37, 0xd9, 0x13,
];

/// Timestamps decoded directly from the raw `u64::from_be_bytes` of the
/// 8-byte wire field (openssl asn1parse hex dump
/// `0000016617AB4AE9` and `0000016617AB4B70`). Equivalent UTC:
/// 2018-09-26 19:56:33.769 GMT and 2018-09-26 19:56:33.904 GMT, as
/// rendered by pyca's `parse_scts()`.
const EXPECTED_TS_0_MS: u64 = 1_537_995_393_769;
const EXPECTED_TS_1_MS: u64 = 1_537_995_393_904;

/// HashAlgorithm value 4 = SHA256 per RFC 5246 §7.4.1.4.1.
const SHA256_TAG: u8 = 4;
/// SignatureAlgorithm value 3 = ECDSA per RFC 5246 §7.4.1.4.1.
const ECDSA_TAG: u8 = 3;

/// First 16 bytes of SCT 0's signature, from openssl + pyca (the SCT's
/// signature is a 72-byte DER-encoded ECDSA-Sig-Value beginning with the
/// SEQUENCE tag 0x30, length 0x46 = 70 content bytes).
const EXPECTED_SIG_0_HEAD: [u8; 16] = [
    0x30, 0x46, 0x02, 0x21, 0x00, 0xa5, 0xce, 0xa8, 0x7c, 0x50, 0x6e, 0x71, 0x8c, 0x26, 0xe3, 0x48,
];

#[test]
fn parses_real_world_cert_with_two_scts() {
    let cert = load_pem_cert(CRYPTOGRAPHY_SCTS_PEM);
    let ext_value = extract_sct_extension(&cert);
    let list = SctList::from_extension_value(&ext_value).expect("parse SCT list");

    assert_eq!(list.0.len(), 2, "two SCTs expected");

    let sct0 = &list.0[0];
    assert_eq!(sct0.version, 0);
    assert_eq!(sct0.log_id, EXPECTED_LOG_ID_0);
    assert_eq!(sct0.timestamp_ms, EXPECTED_TS_0_MS);
    assert!(sct0.extensions.is_empty(), "no v1 extensions");
    assert_eq!(sct0.hash_alg, SHA256_TAG);
    assert_eq!(sct0.sig_alg, ECDSA_TAG);
    assert_eq!(sct0.signature.len(), 72);
    assert_eq!(&sct0.signature[..16], &EXPECTED_SIG_0_HEAD);

    let sct1 = &list.0[1];
    assert_eq!(sct1.version, 0);
    assert_eq!(sct1.log_id, EXPECTED_LOG_ID_1);
    assert_eq!(sct1.timestamp_ms, EXPECTED_TS_1_MS);
    assert!(sct1.extensions.is_empty());
    assert_eq!(sct1.hash_alg, SHA256_TAG);
    assert_eq!(sct1.sig_alg, ECDSA_TAG);
    assert_eq!(sct1.signature.len(), 72);
}

// ---- positive: round-trip through from_serialized_list ------------------

#[test]
fn from_serialized_list_matches_from_extension_value() {
    let cert = load_pem_cert(CRYPTOGRAPHY_SCTS_PEM);
    let ext_value = extract_sct_extension(&cert);

    let via_extension = SctList::from_extension_value(&ext_value).expect("parse");

    // Peel the outer DER OCTET STRING manually to get the
    // SerializedSCTList bytes, then parse those directly.
    let inner =
        x509_cert::der::asn1::OctetString::from_der(&ext_value).expect("strip outer OCTET STRING");
    let via_bare = SctList::from_serialized_list(inner.as_bytes()).expect("parse bare list");

    assert_eq!(via_extension, via_bare);
}

// ---- negative: invalid SCT version --------------------------------------

#[test]
fn rejects_invalid_sct_version() {
    let cert = load_der_cert(INVALID_VERSION_DER);
    let ext_value = extract_sct_extension(&cert);
    let err = SctList::from_extension_value(&ext_value).unwrap_err();
    // The pyca oracle rejects this fixture with "Invalid SCT version".
    // Our equivalent: Error::UnsupportedVersion(1).
    assert_eq!(err, Error::UnsupportedVersion(1));
}

// ---- negative: truncated OCTET STRING length ----------------------------

#[test]
fn rejects_truncated_outer_octet_string() {
    let cert = load_der_cert(INVALID_LENGTH_DER);
    let ext_value = extract_sct_extension(&cert);
    // The outer DER OCTET STRING declares length 0xB1 but the inner
    // SerializedSCTList length is 0xF2 — the SCT list's first SCT can't
    // fit. Depending on how the truncation lands, either the outer
    // OCTET STRING parse fails (ParseError) or the inner SCT body runs
    // off the end (TruncatedOrTrailing). Both indicate the fixture is
    // rejected.
    let err = SctList::from_extension_value(&ext_value).unwrap_err();
    assert!(
        matches!(err, Error::ParseError | Error::TruncatedOrTrailing),
        "expected ParseError or TruncatedOrTrailing, got {err:?}"
    );
}

// ---- negative: handwritten bad inputs -----------------------------------

#[test]
fn rejects_outer_octet_string_with_garbage() {
    // 0xff is not the OCTET STRING tag (0x04).
    let bad = [0xff, 0x00];
    assert_eq!(
        SctList::from_extension_value(&bad).unwrap_err(),
        Error::ParseError
    );
}

#[test]
fn rejects_sct_with_trailing_bytes() {
    // Build an outer OCTET STRING containing a SerializedSCTList where
    // the outer u16 length claims fewer bytes than the SCT actually has,
    // producing trailing bytes inside the SCT after its declared sub-fields.
    //
    // Construct a minimal valid SCT: version(1) + log_id(32) + ts(8) +
    // extensions_prefix(2) + hash_alg(1) + sig_alg(1) + sig_prefix(2) =
    // 47 bytes minimum. We prepend three length headers and one extra
    // trailing byte inside the SCT length to trip TruncatedOrTrailing.
    let mut sct = Vec::new();
    sct.push(0u8); // version
    sct.extend_from_slice(&[0xab; 32]); // log_id
    sct.extend_from_slice(&0x123456789abcdef0u64.to_be_bytes()); // ts
    sct.extend_from_slice(&[0x00, 0x00]); // extensions length = 0
    sct.push(SHA256_TAG); // hash
    sct.push(ECDSA_TAG); // sig
    sct.extend_from_slice(&[0x00, 0x00]); // signature length = 0

    // Wrap one extra byte at end of the SCT's u16-prefixed slot:
    let sct_len_correct = sct.len();
    let bogus_sct_len = sct_len_correct + 1; // declare 1 extra byte
    let mut padded_sct = sct.clone();
    padded_sct.push(0xff); // trailing byte inside the declared SCT length

    let mut inner_list = Vec::new();
    inner_list.extend_from_slice(&(bogus_sct_len as u16).to_be_bytes());
    inner_list.extend_from_slice(&padded_sct);

    let mut serialized = Vec::new();
    serialized.extend_from_slice(&(inner_list.len() as u16).to_be_bytes());
    serialized.extend_from_slice(&inner_list);

    // Wrap in DER OCTET STRING.
    let mut ext_value = Vec::new();
    ext_value.push(0x04); // OCTET STRING tag
    assert!(serialized.len() < 0x80);
    ext_value.push(serialized.len() as u8); // short-form length
    ext_value.extend_from_slice(&serialized);

    assert_eq!(
        SctList::from_extension_value(&ext_value).unwrap_err(),
        Error::TruncatedOrTrailing
    );
}
