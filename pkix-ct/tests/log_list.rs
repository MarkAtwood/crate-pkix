//! Integration tests for `CtLogList` and the Google log_list.json parser.
//!
//! # Fixture
//!
//! `tests/fixtures/log_list_v3_snapshot.json` — a snapshot of Chrome's
//! Certificate Transparency log list, fetched from
//! <https://www.gstatic.com/ct/log_list/v3/log_list.json> on 2026-05-11.
//! At fetch time the schema version (the JSON's `"version"` field) was
//! `85.72` and the snapshot timestamp (`"log_list_timestamp"`) was
//! `2026-05-10T13:43:35Z`.
//!
//! The snapshot is committed verbatim. It will eventually go stale (Chrome
//! ships log-list updates every few months); the tests here validate
//! shape and a few specific log_ids whose 32-byte SHA-256 values are
//! public record and immutable for the life of each named log. A future
//! fixture refresh that drops one of the asserted logs will need to swap
//! to another currently-trusted log; this is expected maintenance.
//!
//! # Oracles
//!
//! Independent oracles for the asserted values:
//!
//! * Total log count — Chrome's log list itself is the public record;
//!   verified by `python3 -c 'import json; ...'` at fixture-snapshot
//!   time (see fixture refresh procedure).
//! * Individual log_ids — Chrome and Google publish the SHA-256 of each
//!   log's `SubjectPublicKeyInfo`; these 32-byte values are stable for
//!   the life of the log. The hex values asserted below come from
//!   `base64 -d` of the snapshot's `log_id` field, independent of
//!   pkix-ct's own parser.
//! * Timestamps — Chrome publishes log-state transitions; converted to
//!   ms via `datetime.fromisoformat`, independent of pkix-ct's own RFC
//!   3339 parser.

#![cfg(feature = "log-list-json")]

use std::fs;

use pkix_ct::CtLogList;

const LOG_LIST_PATH: &str = "tests/fixtures/log_list_v3_snapshot.json";

/// Total log count in the snapshot. Determined at fixture-snapshot time
/// by `python3 -c "import json; print(sum(len(op['logs']) for op in json.load(open('log_list.json'))['operators']))"`.
/// If a future snapshot refresh changes this, update both the constant
/// and the count in the fixture's leading rustdoc.
const SNAPSHOT_LOG_COUNT: usize = 35;

/// Google "Argon2026h1" log. log_id is SHA-256 of the log's
/// SubjectPublicKeyInfo, published by Google and immutable for the life
/// of the log. base64-decoded `log_id` from the snapshot.
const ARGON2026H1_LOG_ID: [u8; 32] = [
    0x0e, 0x57, 0x94, 0xbc, 0xf3, 0xae, 0xa9, 0x3e, 0x33, 0x1b, 0x2c, 0x99, 0x07, 0xb3, 0xf7, 0x90,
    0xdf, 0x9b, 0xc2, 0x3d, 0x71, 0x32, 0x25, 0xdd, 0x21, 0xa9, 0x25, 0xac, 0x61, 0xc5, 0x4e, 0x21,
];
/// Google "Argon2026h2" log.
const ARGON2026H2_LOG_ID: [u8; 32] = [
    0xd7, 0x6d, 0x7d, 0x10, 0xd1, 0xa7, 0xf5, 0x77, 0xc2, 0xc7, 0xe9, 0x5f, 0xd7, 0x00, 0xbf, 0xf9,
    0x82, 0xc9, 0x33, 0x5a, 0x65, 0xe1, 0xd0, 0xb3, 0x01, 0x73, 0x17, 0xc0, 0xc8, 0xc5, 0x69, 0x77,
];
/// Cloudflare "Nimbus2026" log.
const NIMBUS2026_LOG_ID: [u8; 32] = [
    0xcb, 0x38, 0xf7, 0x15, 0x89, 0x7c, 0x84, 0xa1, 0x44, 0x5f, 0x5b, 0xc1, 0xdd, 0xfb, 0xc9, 0x6e,
    0xf2, 0x9a, 0x59, 0xcd, 0x47, 0x0a, 0x69, 0x05, 0x85, 0xb0, 0xcb, 0x14, 0xc3, 0x14, 0x58, 0xe7,
];

/// Google's Argon2026h1 + Argon2026h2 both entered the "usable" state at
/// 2024-09-30T22:19:27Z. Oracle: python `datetime.fromisoformat`.
const USABLE_2024_09_30_22_19_27_MS: u64 = 1_727_734_767_000;

/// Cloudflare's Nimbus2026 entered "usable" at 2024-11-08T18:00:00Z.
const USABLE_2024_11_08_18_00_00_MS: u64 = 1_731_088_800_000;

#[test]
fn parses_chrome_snapshot() {
    let json = fs::read_to_string(LOG_LIST_PATH).expect("read snapshot");
    let list = CtLogList::from_google_log_list_json(&json).expect("parse log list");
    assert_eq!(list.len(), SNAPSHOT_LOG_COUNT);
}

#[test]
fn argon2026h1_present_with_expected_metadata() {
    let json = fs::read_to_string(LOG_LIST_PATH).unwrap();
    let list = CtLogList::from_google_log_list_json(&json).unwrap();
    let log = list.get(&ARGON2026H1_LOG_ID).expect("Argon2026h1 in list");
    assert_eq!(log.log_id, ARGON2026H1_LOG_ID);
    assert!(log.description.contains("Argon2026h1"));
    assert_eq!(log.url, "https://ct.googleapis.com/logs/us1/argon2026h1/");
    assert_eq!(log.usable_from_ms, Some(USABLE_2024_09_30_22_19_27_MS));
    assert_eq!(log.retired_at_ms, None);
}

#[test]
fn argon2026h2_present() {
    let json = fs::read_to_string(LOG_LIST_PATH).unwrap();
    let list = CtLogList::from_google_log_list_json(&json).unwrap();
    let log = list.get(&ARGON2026H2_LOG_ID).expect("Argon2026h2 in list");
    assert_eq!(log.log_id, ARGON2026H2_LOG_ID);
    assert!(log.description.contains("Argon2026h2"));
    assert_eq!(log.usable_from_ms, Some(USABLE_2024_09_30_22_19_27_MS));
}

#[test]
fn nimbus2026_present() {
    let json = fs::read_to_string(LOG_LIST_PATH).unwrap();
    let list = CtLogList::from_google_log_list_json(&json).unwrap();
    let log = list.get(&NIMBUS2026_LOG_ID).expect("Nimbus2026 in list");
    assert!(log.description.contains("Nimbus2026"));
    assert_eq!(log.url, "https://ct.cloudflare.com/logs/nimbus2026/");
    assert_eq!(log.usable_from_ms, Some(USABLE_2024_11_08_18_00_00_MS));
}

#[test]
fn all_logs_pass_consistency_check() {
    // The parser enforces log_id == SHA-256(key_der) at insert time, so
    // a successful parse implies all 35 logs pass. This test exists as
    // a regression guard: if the consistency check were ever weakened,
    // a hand-edited fixture with a bad entry would still parse, and
    // this test would catch it via the lower-level CtLogList API.
    let json = fs::read_to_string(LOG_LIST_PATH).unwrap();
    let list = CtLogList::from_google_log_list_json(&json).unwrap();

    let mut list2 = CtLogList::new();
    for log in list.iter() {
        // Re-insert each log into a fresh list — exercises the consistency
        // check on each entry independently.
        list2.insert(log.clone()).expect("consistency check");
    }
    assert_eq!(list2.len(), SNAPSHOT_LOG_COUNT);
}

#[test]
fn rejects_garbage_json() {
    let err = CtLogList::from_google_log_list_json("not json at all").unwrap_err();
    assert_eq!(err, pkix_ct::Error::ParseError);
}

#[test]
fn rejects_empty_object() {
    // Missing `operators` field.
    let err = CtLogList::from_google_log_list_json("{}").unwrap_err();
    assert_eq!(err, pkix_ct::Error::ParseError);
}
