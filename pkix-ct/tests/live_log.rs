//! Integration test against a real-world CT-log triple (PKIX-baac.8).
//!
//! # Fixture
//!
//! `tests/fixtures/live-log/` carries an SCT + inclusion proof + STH
//! triple captured one-off from a currently-running CT log shard.
//! `capture_live_log.py` in that directory documents the exact capture
//! procedure; `meta.json` records the log shard, source URL, capture
//! site, timestamp, and log-list version used. The fixture is fully
//! offline once committed — pkix-ct enforces no STH-freshness rule, so
//! it remains valid long after the log's current STH advances past the
//! captured `tree_size`.
//!
//! # Independent oracles
//!
//! Three independent paths agree on the captured bytes before this
//! test trusts them:
//!
//! 1. The capture script computes the [`merkle_leaf_hash`] from the
//!    final cert + issuer SPKI + SCT timestamp directly from RFC 6962
//!    §3.4 text — not by invoking pkix-ct. The CT log's
//!    `get-proof-by-hash` endpoint accepted that leaf hash and
//!    returned a proof for it, so the log itself confirms our
//!    [`MerkleTreeLeaf`] byte form matches what it computed when the
//!    cert was logged.
//! 2. A pure-Python RFC 9162 §2.1.3.2 verifier
//!    (`capture_live_log.py` re-runs this) confirms the captured
//!    inclusion proof reconstructs the captured STH's root_hash.
//! 3. `openssl dgst -verify` independently confirms the STH's ECDSA
//!    signature against the log's SPKI on the RFC 6962 §3.5
//!    `TreeHeadSignature` input bytes.
//!
//! pkix-ct's own verifier (this file) is therefore exercised against a
//! fixture whose every byte has been validated by at least one
//! independent code path.
//!
//! # Coverage
//!
//! This test exercises three pkix-ct entry points end-to-end against
//! the captured triple:
//!
//! - [`SctVerifier::verify_sct_for_precert`] — signature of the
//!   precert SCT, including the verifier's TBS-stripping and
//!   issuer-key-hash construction.
//! - [`SctVerifier::verify_sth`] — STH signature.
//! - [`SctVerifier::verify_inclusion`] — Merkle inclusion proof for
//!   the captured leaf against the STH-committed root.
//!
//! PKIX-baac.5 already covered all three against synthetic-but-shape-
//! correct fixtures; this test adds defense in depth via real-world
//! bytes from a deployed CT log.
//!
//! # Maintenance
//!
//! If the fixture ever needs to be re-captured (e.g., because the
//! Python script is updated and a new triple is desired), run
//! `pkix-difftest/python/.venv/bin/python
//! pkix-ct/tests/fixtures/live-log/capture_live_log.py`. Pick a
//! currently-running log via the Chromium CT log list and a
//! CT-enforcing TLS site (any major Cloudflare-fronted site, or
//! cloudflare.com itself, works).

#![cfg(feature = "log-list")]

use std::fs;

use pkix_ct::{
    merkle_leaf_hash, merkle_tree_leaf_for_precert, CtLog, CtLogList, MerkleAuditPath, SctList,
    SctVerifier, SignedCertificateTimestamp, SignedTreeHead,
};
use pkix_path::DefaultVerifier;

const FIXTURE_DIR: &str = "tests/fixtures/live-log";

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{FIXTURE_DIR}/{name}");
    fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

/// Build a `CtLogList` containing only the captured log, with an open
/// window (so the SCT's real-world timestamp falls inside).
/// `usable_from_ms = Some(0)` means "usable since epoch" — the widest
/// valid window. `None` would mean "never usable" per the `CtLog` doc.
fn captured_log_list() -> CtLogList {
    let log_id_bytes = fixture("log-id.bin");
    let log_id: [u8; 32] = log_id_bytes
        .as_slice()
        .try_into()
        .expect("log-id.bin is 32 bytes");
    let mut logs = CtLogList::new();
    logs.insert(CtLog::new(
        log_id,
        fixture("log-spki.der"),
        "live-log".into(),
        "http://example.invalid/ct/".into(),
        Some(0),
        None,
    ))
    .expect("captured log self-consistency");
    logs
}

/// Parse the single captured SCT from its wire form.
fn captured_sct() -> SignedCertificateTimestamp {
    let raw = fixture("sct.bin");
    // The wire form starts with a u16 length prefix when carried inside the
    // SignedCertificateTimestampList container; here we stored just the
    // SerializedSCT body, so we wrap it as a one-element list.
    let mut wrapped = Vec::with_capacity(2 + 2 + raw.len() + 2);
    let total = (raw.len() + 2) as u16;
    wrapped.extend_from_slice(&total.to_be_bytes());
    wrapped.extend_from_slice(&(raw.len() as u16).to_be_bytes());
    wrapped.extend_from_slice(&raw);
    let list = SctList::from_serialized_list(&wrapped).expect("parse captured SCT list");
    assert_eq!(list.0.len(), 1, "captured fixture has exactly one SCT");
    list.0.into_iter().next().unwrap()
}

/// Load the captured STH from `sth.bin`. Layout (big-endian):
/// `u64 timestamp_ms | u64 tree_size | 32 root | u8 hash | u8 sig | u32 sig_len | sig`.
fn captured_sth() -> ([u8; 32], SignedTreeHead) {
    let log_id_bytes = fixture("log-id.bin");
    let log_id: [u8; 32] = log_id_bytes.as_slice().try_into().unwrap();
    let buf = fixture("sth.bin");
    let timestamp_ms = u64::from_be_bytes(buf[0..8].try_into().unwrap());
    let tree_size = u64::from_be_bytes(buf[8..16].try_into().unwrap());
    let mut root_hash = [0u8; 32];
    root_hash.copy_from_slice(&buf[16..48]);
    let hash_alg = buf[48];
    let sig_alg = buf[49];
    let sig_len = u32::from_be_bytes(buf[50..54].try_into().unwrap()) as usize;
    let signature = buf[54..54 + sig_len].to_vec();
    assert_eq!(54 + sig_len, buf.len(), "sth.bin had trailing bytes");
    (
        log_id,
        SignedTreeHead::new(
            tree_size,
            timestamp_ms,
            root_hash,
            hash_alg,
            sig_alg,
            signature,
        ),
    )
}

/// Load the captured inclusion proof from `audit-path.bin`. Layout
/// (big-endian): `u32 tree_size | u32 leaf_index | u32 path_len | path_len*32 bytes`.
fn captured_audit_path() -> ([u8; 32], MerkleAuditPath) {
    let lh_bytes = fixture("leaf-hash.bin");
    let leaf_hash: [u8; 32] = lh_bytes
        .as_slice()
        .try_into()
        .expect("leaf-hash.bin is 32 bytes");
    let buf = fixture("audit-path.bin");
    let tree_size = u64::from(u32::from_be_bytes(buf[0..4].try_into().unwrap()));
    let leaf_index = u64::from(u32::from_be_bytes(buf[4..8].try_into().unwrap()));
    let path_len = u32::from_be_bytes(buf[8..12].try_into().unwrap()) as usize;
    let mut audit_path = Vec::with_capacity(path_len);
    let mut off = 12;
    for _ in 0..path_len {
        let mut h = [0u8; 32];
        h.copy_from_slice(&buf[off..off + 32]);
        audit_path.push(h);
        off += 32;
    }
    assert_eq!(off, buf.len(), "audit-path.bin had trailing bytes");
    (
        leaf_hash,
        MerkleAuditPath::new(leaf_index, tree_size, audit_path),
    )
}

/// PKIX-baac.8 acceptance: real-world-byte triple verifies end to end.
///
/// 1. The captured precert SCT's signature verifies against the
///    captured log SPKI for the leaf+issuer pair.
/// 2. The captured STH's signature verifies against the captured log
///    SPKI.
/// 3. The captured inclusion proof verifies the captured leaf hash
///    against the STH-committed root.
///
/// Together they prove the captured leaf was logged in the CT log and
/// the log committed to its presence in a publicly auditable Merkle
/// tree at some `tree_size`. This is the full RFC 6962 §2.1 + §3.2 +
/// §3.5 flow exercised against real bytes.
#[test]
fn live_log_triple_verifies_end_to_end() {
    let logs = captured_log_list();
    let v = SctVerifier::new(logs, DefaultVerifier);
    let sct = captured_sct();
    let leaf_der = fixture("leaf.der");
    let issuer_der = fixture("issuer.der");

    let log = v
        .verify_sct_for_precert(&sct, &leaf_der, &issuer_der)
        .expect("SCT signature verifies against captured log");
    assert_eq!(log.description, "live-log");

    let (log_id, sth) = captured_sth();
    let log = v.verify_sth(&log_id, &sth).expect("STH signature verifies");
    assert_eq!(log.description, "live-log");

    let (leaf_hash, proof) = captured_audit_path();
    assert_eq!(
        proof.tree_size, sth.tree_size,
        "audit-path tree_size matches the STH the proof is anchored to"
    );
    v.verify_inclusion(&leaf_hash, &proof, &sth.root_hash)
        .expect("inclusion proof reconstructs the STH root");
}

/// PKIX-yzb6 acceptance: the public `merkle_tree_leaf_for_precert`
/// helper produces a MerkleTreeLeaf byte string whose leaf hash
/// matches the one captured by the Python fixture-capture script.
///
/// Independent oracle: `leaf-hash.bin` is the value the
/// `capture_live_log.py` script computed from RFC 6962 §3.4 text in
/// Python; the CT log's `get-proof-by-hash` endpoint accepted that
/// value (meaning the log itself agreed it was a leaf in its tree).
/// So Python + CT-log-side both vouch for the bytes the Rust helper
/// must reproduce.
#[test]
fn merkle_tree_leaf_for_precert_matches_captured_leaf_hash() {
    let sct = captured_sct();
    let leaf_der = fixture("leaf.der");
    let issuer_der = fixture("issuer.der");

    let mtl = merkle_tree_leaf_for_precert(&sct, &leaf_der, &issuer_der)
        .expect("Rust MerkleTreeLeaf builder succeeds on real fixture");
    let derived_leaf_hash = merkle_leaf_hash(&mtl);

    let captured_leaf_hash: [u8; 32] = fixture("leaf-hash.bin")
        .as_slice()
        .try_into()
        .expect("leaf-hash.bin is 32 bytes");

    assert_eq!(
        derived_leaf_hash, captured_leaf_hash,
        "Rust-derived leaf hash must match the Python-captured one"
    );
}

/// PKIX-yzb6 follow-up: the leaf hash derived via the new helper
/// works as input to `verify_inclusion` against the captured STH —
/// end-to-end test that downstream consumers can do the full
/// "parse SCT → build MerkleTreeLeaf → hash → verify inclusion"
/// pipeline through pkix-ct's public API alone.
#[test]
fn merkle_tree_leaf_for_precert_feeds_verify_inclusion_end_to_end() {
    let logs = captured_log_list();
    let v = SctVerifier::new(logs, DefaultVerifier);
    let sct = captured_sct();
    let leaf_der = fixture("leaf.der");
    let issuer_der = fixture("issuer.der");

    let mtl = merkle_tree_leaf_for_precert(&sct, &leaf_der, &issuer_der)
        .expect("MerkleTreeLeaf builder succeeds");
    let derived_leaf_hash = merkle_leaf_hash(&mtl);

    let (_captured_leaf_hash, proof) = captured_audit_path();
    let (_log_id, sth) = captured_sth();

    v.verify_inclusion(&derived_leaf_hash, &proof, &sth.root_hash)
        .expect("inclusion proof verifies against the derived leaf hash");
}
