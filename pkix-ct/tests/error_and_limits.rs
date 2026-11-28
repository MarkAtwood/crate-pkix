//! `Error`'s rendering, `CtLogList`'s emptiness, and the RFC 6962 §3.2
//! length ceiling.
//!
//! None of these has a caller inside the crate: an `Error` is returned
//! and rendering it is the consumer's business, `is_empty` is for a
//! caller deciding whether it has a log list worth consulting, and the
//! ceiling only matters for a certificate larger than any in the
//! fixtures.

use pkix_ct::{CtLog, CtLogList, Error, SignedCertificateTimestamp, UsableFrom};
use std::fs;

/// One of every `Error` variant.
///
/// Built directly rather than provoked, because several are reachable
/// only from inputs that would need their own fixtures, and what is
/// under test is the rendering rather than the route to it.
fn every_variant() -> Vec<(&'static str, Error)> {
    vec![
        ("NoScts", Error::NoScts),
        ("InvalidSignature", Error::InvalidSignature),
        ("ParseError", Error::ParseError),
        ("UnsupportedVersion", Error::UnsupportedVersion(7)),
        ("TruncatedOrTrailing", Error::TruncatedOrTrailing),
        ("UnknownLog", Error::UnknownLog),
        ("EntryTypeMismatch", Error::EntryTypeMismatch),
        ("EmptySctList", Error::EmptySctList),
        (
            "DuplicateSctListExtension",
            Error::DuplicateSctListExtension,
        ),
        (
            "UnsupportedSignatureAlgorithm",
            Error::UnsupportedSignatureAlgorithm {
                hash_alg: 2,
                sig_alg: 1,
            },
        ),
        ("LogKeyMalformed", Error::LogKeyMalformed),
    ]
}

/// Every variant renders something, and no two render the same thing.
///
/// A CT failure is a policy decision a caller reports: "no SCTs" and
/// "SCT signature invalid" lead somewhere different, and an empty or
/// shared message collapses them.
#[test]
fn every_error_variant_renders_a_distinct_message() {
    let variants = every_variant();
    let rendered: Vec<String> = variants.iter().map(|(_, e)| format!("{e}")).collect();
    for ((name, _), text) in variants.iter().zip(&rendered) {
        assert!(!text.is_empty(), "Error::{name} renders nothing");
    }
    for (i, a) in rendered.iter().enumerate() {
        for (j, b) in rendered.iter().enumerate().skip(i + 1) {
            assert_ne!(
                a, b,
                "Error::{} and Error::{} render the same message",
                variants[i].0, variants[j].0
            );
        }
    }
}

/// An empty log list says so, and one holding a log does not.
///
/// Both directions, because a caller uses this to decide whether it has
/// any basis for a CT policy at all: answering `true` always makes a
/// loaded list look unusable, and `false` always makes an unloaded one
/// look ready.
#[test]
fn a_log_list_reports_whether_it_holds_anything() {
    let empty = CtLogList::new();
    assert_eq!(empty.len(), 0);
    assert!(empty.is_empty(), "a list with no logs is empty");

    // `insert` requires the log_id to be SHA-256 of the SPKI, so the
    // oracle's committed pair is used rather than an invented id.
    let log_id: [u8; 32] = fs::read("tests/fixtures/sct-oracle/log-id.bin")
        .expect("read log id")
        .as_slice()
        .try_into()
        .expect("log-id.bin is 32 bytes");
    let mut one = CtLogList::new();
    one.insert(CtLog::new(
        log_id,
        fs::read("tests/fixtures/sct-oracle/log-spki.der").expect("read log spki"),
        "one".into(),
        "http://example.invalid/ct/".into(),
        UsableFrom::Unrecorded,
        None,
    ))
    .expect("insert");
    assert_eq!(one.len(), 1);
    assert!(!one.is_empty(), "a list holding a log is not empty");
}

/// A certificate of exactly `2^24 - 1` bytes is within `ASN.1Cert`.
///
/// RFC 6962 §3.2 types it `opaque ASN.1Cert<1..2^24-1>`, so 16777215 is
/// the largest representable and the check is `len > that`. Read as
/// `>=`, the largest legal certificate is refused -- and the MerkleTreeLeaf
/// builders take the DER as bytes without parsing it, so the boundary
/// can be exercised with a buffer rather than a 16 MiB fixture.
///
/// One byte more has no three-octet length and must be refused.
#[test]
fn the_asn1cert_ceiling_admits_its_own_maximum() {
    const MAX: usize = 0x00FF_FFFF;
    let sct = SignedCertificateTimestamp::from_bytes(
        &fs::read("tests/fixtures/sct-oracle/sct.bin").expect("read oracle sct"),
    )
    .expect("parse the oracle SCT");

    let at_limit = vec![0u8; MAX];
    let leaf = pkix_ct::merkle_tree_leaf_for_cert(&sct, &at_limit)
        .expect("2^24 - 1 is the largest ASN.1Cert, not the first refused");
    // version, leaf_type, 8 timestamp octets, 2 of entry_type, then the
    // u24 -- which at this length is 0xFF 0xFF 0xFF.
    assert_eq!(
        &leaf[12..15],
        &[0xFF, 0xFF, 0xFF],
        "the length is the maximum the three octets can carry"
    );

    let over_limit = vec![0u8; MAX + 1];
    assert!(
        matches!(
            pkix_ct::merkle_tree_leaf_for_cert(&sct, &over_limit),
            Err(Error::CertDerTooLong)
        ),
        "one byte more cannot be expressed in three octets"
    );

    // The signed-input builder has its own copy of the same check, and
    // it is reached through verification: the version, log, window and
    // algorithm checks all pass with the oracle's own SCT, so the
    // builder runs and then the signature fails. Which error comes back
    // is what separates the two readings -- at exactly the ceiling the
    // length is fine and the signature is not, so `InvalidSignature` is
    // the right answer and `CertDerTooLong` is the mutant's.
    let logs = oracle_log_list();
    let v = pkix_ct::SctVerifier::new(logs, pkix_path::DefaultVerifier);
    assert!(
        matches!(
            v.verify_sct_for_cert(&sct, &at_limit),
            Err(Error::InvalidSignature)
        ),
        "2^24 - 1 octets reaches the signature check; it does not fail the length check"
    );
    assert!(
        matches!(
            v.verify_sct_for_cert(&sct, &over_limit),
            Err(Error::CertDerTooLong)
        ),
        "and one byte more does not reach it"
    );
}

/// The oracle log, as `tests/verify.rs` builds it.
fn oracle_log_list() -> CtLogList {
    let log_id: [u8; 32] = fs::read("tests/fixtures/sct-oracle/log-id.bin")
        .expect("read log id")
        .as_slice()
        .try_into()
        .expect("log-id.bin is 32 bytes");
    let mut logs = CtLogList::new();
    logs.insert(CtLog::new(
        log_id,
        fs::read("tests/fixtures/sct-oracle/log-spki.der").expect("read log spki"),
        "oracle".into(),
        "http://example.invalid/ct/".into(),
        UsableFrom::Unrecorded,
        None,
    ))
    .expect("insert");
    logs
}
