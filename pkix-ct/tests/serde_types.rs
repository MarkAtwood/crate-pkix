//! serde round trips for the public CT result types.
//!
//! The crate's `serde` feature exists so a caller can cache what it has
//! already parsed and verified — an STH a TLS server has checked, an audit
//! path it wants to replay, a log list it trusts — instead of re-parsing
//! wire bytes on every lookup. These tests cover the round trip for each
//! type, and the one case where a round trip must be *refused*.
//!
//! Run: cargo test -p pkix-ct --features serde,log-list

#![cfg(all(feature = "serde", feature = "log-list"))]

use pkix_ct::{
    CtLog, CtLogList, MerkleAuditPath, SctList, SignedCertificateTimestamp, SignedTreeHead,
    UsableFrom,
};
use sha2::{Digest as _, Sha256};

/// A log whose `log_id` is consistent with its key, as RFC 6962 §3.2
/// requires.
fn consistent_log(key_der: &[u8], description: &str) -> CtLog {
    let log_id: [u8; 32] = Sha256::digest(key_der).into();
    CtLog::new(
        log_id,
        key_der.to_vec(),
        description.to_owned(),
        String::new(),
        UsableFrom::Unrecorded,
        None,
    )
}

fn round_trip<T>(value: &T) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let json = serde_json::to_string(value).expect("serialize");
    serde_json::from_str(&json).expect("deserialize")
}

#[test]
fn sct_round_trips() {
    let sct = SignedCertificateTimestamp::new(
        0,
        [7u8; 32],
        1_700_000_000_000,
        vec![1, 2, 3],
        4,
        3,
        vec![9; 64],
    );
    assert_eq!(round_trip(&sct), sct);
}

#[test]
fn sct_list_round_trips() {
    let list = SctList::new(vec![
        SignedCertificateTimestamp::new(0, [1u8; 32], 1, vec![], 4, 3, vec![1]),
        SignedCertificateTimestamp::new(0, [2u8; 32], 2, vec![], 4, 3, vec![2]),
    ])
    .expect("two SCTs are a legal list");
    assert_eq!(round_trip(&list), list);
}

#[test]
fn signed_tree_head_round_trips() {
    let sth = SignedTreeHead::new(42, 1_700_000_000_000, [3u8; 32], 4, 3, vec![8; 70]);
    assert_eq!(round_trip(&sth), sth);
}

#[test]
fn merkle_audit_path_round_trips() {
    let path = MerkleAuditPath::new(5, 11, vec![[1u8; 32], [2u8; 32], [3u8; 32]]);
    assert_eq!(round_trip(&path), path);
}

#[test]
fn ct_log_round_trips() {
    let log = consistent_log(b"key-material", "Example Log");
    assert_eq!(round_trip(&log), log);
}

// ---------------------------------------------------------------------------
// CtLogList: the round trip must re-run the RFC 6962 §3.2 check
// ---------------------------------------------------------------------------

/// A log list survives the round trip, and comes back as a usable map
/// rather than just a sequence.
#[test]
fn ct_log_list_round_trips_and_stays_indexed() {
    let a = consistent_log(b"key-a", "Log A");
    let b = consistent_log(b"key-b", "Log B");
    let mut list = CtLogList::new();
    list.insert(a.clone()).expect("a is consistent");
    list.insert(b.clone()).expect("b is consistent");

    let back = round_trip(&list);
    assert_eq!(back.len(), 2);
    // Indexed lookup still works, so the key was rebuilt rather than stored.
    assert_eq!(
        back.get(&a.log_id).map(|l| &l.description),
        Some(&a.description)
    );
    assert_eq!(
        back.get(&b.log_id).map(|l| &l.description),
        Some(&b.description)
    );
}

/// The map key is not written to the wire.
///
/// It is `SHA-256(key_der)` of the value it indexes, so storing it would
/// duplicate bytes already present and let the two copies disagree. The
/// serialized form is a bare sequence.
#[test]
fn ct_log_list_serializes_as_a_sequence_without_redundant_keys() {
    let mut list = CtLogList::new();
    list.insert(consistent_log(b"key-a", "Log A"))
        .expect("consistent");

    let json = serde_json::to_string(&list).expect("serialize");
    assert!(json.starts_with('['), "expected a JSON array, got {json}");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");
    assert_eq!(
        parsed.as_array().map(Vec::len),
        Some(1),
        "one entry, stored once"
    );
}

/// A tampered log list must be refused on the way in.
///
/// This is the reason `CtLogList` does not simply derive `Deserialize`.
/// `insert` enforces RFC 6962 §3.2 (`log_id == SHA-256(key_der)`) and
/// rejects a mismatch as a corrupted source; a derive would fill the
/// internal map directly and skip it. Since `get(log_id)` is how a caller
/// maps a parsed SCT back to a trusted log key, an entry filed under a key
/// that does not match it means verifying an SCT against the wrong key.
///
/// Persisting and reloading is exactly the path an attacker would reach by
/// editing a cache on disk, so the check has to run here and not only at
/// first parse.
#[test]
fn a_log_list_whose_log_id_does_not_match_its_key_is_rejected() {
    // Serialize a valid list, then corrupt the key material in the JSON so
    // the stored log_id no longer matches it.
    let mut list = CtLogList::new();
    list.insert(consistent_log(b"key-a", "Log A"))
        .expect("consistent");
    let json = serde_json::to_string(&list).expect("serialize");

    let mut doc: serde_json::Value = serde_json::from_str(&json).expect("valid json");
    let entry = &mut doc.as_array_mut().expect("array")[0];
    let original = entry["key_der"].clone();
    entry["key_der"] = serde_json::json!([0, 0, 0, 0]);
    assert_ne!(
        entry["key_der"], original,
        "the fixture must actually differ"
    );
    let tampered = serde_json::to_string(&doc).expect("re-serialize");

    let result: Result<CtLogList, _> = serde_json::from_str(&tampered);
    assert!(
        result.is_err(),
        "a log_id inconsistent with its key_der must be rejected, but the list loaded"
    );
}
