//! Shared fixtures and helpers for the integration tests.
//!
//! Not every test file uses every helper, hence the blanket `dead_code`
//! allowance: each file that declares `mod support;` compiles the whole
//! module, so anything one file does not touch would otherwise warn.

#![allow(dead_code)]

use pkix_dane::{
    record::TlsaRecord, DnssecStatus, PresentedCert, TlsaMatchingType, TlsaResponse, TlsaSelector,
    TlsaUsage,
};
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

pub const LEAF_DER: &[u8] = include_bytes!("../fixtures/leaf.der");
pub const LEAF_SPKI_DER: &[u8] = include_bytes!("../fixtures/leaf.spki.der");
pub const OTHER_DER: &[u8] = include_bytes!("../fixtures/other.der");
pub const CA_DER: &[u8] = include_bytes!("../fixtures/ca.der");
pub const CA_SPKI_DER: &[u8] = include_bytes!("../fixtures/ca.spki.der");
pub const CHAIN_LEAF_DER: &[u8] = include_bytes!("../fixtures/chain-leaf.der");

/// The digest manifest written by `fixtures/gen.sh`.
///
/// Read at compile time rather than hardcoded in the test source so that
/// regenerating the fixtures — which generates fresh keys, and therefore
/// changes every digest — cannot leave a stale expectation behind.
const DIGESTS: &str = include_str!("../fixtures/digests.txt");

/// Looks up a digest from the manifest.
///
/// `fixture` is a fixture stem (`"leaf"`, `"ca"`, `"chain-leaf"`, …),
/// `selector` is `"Cert"` or `"Spki"`, `alg` is `"sha256"` or `"sha512"`.
///
/// # Panics
///
/// Panics if the manifest holds no such row, which means `gen.sh` and the
/// tests have diverged.
pub fn digest(fixture: &str, selector: &str, alg: &str) -> Vec<u8> {
    for line in DIGESTS.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let mut fields = line.split_whitespace();
        let (Some(f), Some(s), Some(a), Some(hex_digest)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            panic!("malformed digests.txt row: {line:?}");
        };
        if f == fixture && s == selector && a == alg {
            return hex(hex_digest);
        }
    }
    panic!("digests.txt should list {fixture}/{selector}/{alg}; rerun fixtures/gen.sh");
}

/// Decodes a hex string.
///
/// # Panics
///
/// Panics on a non-hex byte or an odd length, either of which means the
/// manifest is corrupt.
pub fn hex(s: &str) -> Vec<u8> {
    let nibbles: Vec<u8> = s
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            other => panic!("expected a hex digit, found {other:#x}"),
        })
        .collect();
    assert_eq!(nibbles.len() % 2, 0, "hex string should have even length");
    nibbles
        .chunks(2)
        .map(|pair| (pair[0] << 4) | pair[1])
        .collect()
}

/// Parses a fixture.
///
/// # Panics
///
/// Panics if the fixture does not parse, which means it is corrupt.
pub fn parse(der: &[u8]) -> Certificate {
    Certificate::from_der(der).expect("fixture should be a parseable certificate")
}

/// Pairs fixture bytes with their parsed form.
pub fn presented<'a>(der: &'a [u8], parsed: &'a Certificate) -> PresentedCert<'a> {
    PresentedCert::new(der, parsed)
}

/// Builds a TLSA record.
pub fn record(
    usage: TlsaUsage,
    selector: TlsaSelector,
    matching_type: TlsaMatchingType,
    data: Vec<u8>,
) -> TlsaRecord {
    TlsaRecord::new(usage, selector, matching_type, data)
}

/// Builds a record carrying the SHA-256 digest named in the manifest.
pub fn sha256_record(
    usage: TlsaUsage,
    selector: TlsaSelector,
    fixture: &str,
    selector_name: &str,
) -> TlsaRecord {
    record(
        usage,
        selector,
        TlsaMatchingType::Sha256,
        digest(fixture, selector_name, "sha256"),
    )
}

/// Wraps records in a DNSSEC-secure response.
pub fn secure(records: Vec<TlsaRecord>) -> TlsaResponse {
    TlsaResponse::new(records, DnssecStatus::Secure)
}
