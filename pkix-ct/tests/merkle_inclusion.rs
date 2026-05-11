//! Integration tests for Merkle inclusion proof verification (PKIX-baac.5).
//!
//! # Fixtures
//!
//! Fixtures under `tests/fixtures/sct-oracle/merkle-tree-N*.{json,bin}`
//! are produced by `gen_merkle_inclusion.py` (in the same directory).
//! That script is the independent oracle: it builds left-leaning binary
//! Merkle trees from RFC 6962 §2.1 directly (recursive `MTH` definition
//! and `PATH` audit-path generator), never calling pkix-ct or any
//! third-party CT library.
//!
//! Two trees are committed:
//!
//! - **N=7**: odd-sized small tree; the last-leaf (m=6) audit path
//!   has length 2, exercising the RFC 6962 §2.1 left-leaning
//!   rebalance.
//! - **N=11**: odd-sized deeper tree; exercises several rebalances
//!   across multiple levels.
//!
//! A second independent cross-check inside the oracle script itself
//! re-verifies every emitted proof via RFC 9162 §2.1.3.2's verify
//! algorithm — a different code path from the generator. So the
//! fixtures' correctness is established by two independent algorithm
//! implementations (build-side + verify-side, both in Python) before
//! pkix-ct's Rust verify-side path is exercised against them.
//!
//! # Coverage
//!
//! - **Positive**: every leaf in both trees verifies cleanly.
//! - **Negative — wrong root**: any byte flipped in the expected root
//!   yields [`Error::MerkleProofInvalid`].
//! - **Negative — wrong index**: bumping `leaf_index` by 1 (still in
//!   range) yields [`Error::MerkleProofInvalid`].
//! - **Negative — out-of-range index**: `leaf_index >= tree_size` is
//!   [`Error::MerkleProofInvalid`].
//! - **Negative — tampered path**: any byte flipped in any audit-path
//!   hash yields [`Error::MerkleProofInvalid`].
//! - **Negative — tree_size = 0**: [`Error::MerkleProofMalformed`].
//! - **Negative — over-long audit path**: stuffing extra hashes
//!   beyond `ceil(log2(tree_size))` yields
//!   [`Error::MerkleProofMalformed`].
//!
//! Pre-cert / x509_entry / OCSP / STH-signature concerns are
//! deliberately out of scope for this test file — they live in
//! `tests/verify.rs`, `tests/verify_precert.rs`, and `tests/log_list.rs`.

#![cfg(feature = "log-list")]

use std::fs;

use pkix_ct::{CtLogList, Error, MerkleAuditPath, SctVerifier};
use pkix_path::DefaultVerifier;

const FIXTURE_DIR: &str = "tests/fixtures/sct-oracle";

/// Empty verifier — the verify_inclusion path uses neither the log
/// list nor the SignatureVerifier (it is hash-only).
fn empty_verifier() -> SctVerifier<DefaultVerifier> {
    SctVerifier::new(CtLogList::new(), DefaultVerifier)
}

/// Parsed form of `merkle-tree-N{N}.bin`.
struct MerkleFixture {
    tree_size: u64,
    root: [u8; 32],
    /// One entry per leaf: (leaf_index, leaf_bytes, audit_path).
    proofs: Vec<(u64, Vec<u8>, Vec<[u8; 32]>)>,
}

fn read_u32_be(buf: &[u8], off: &mut usize) -> u32 {
    let v = u32::from_be_bytes([buf[*off], buf[*off + 1], buf[*off + 2], buf[*off + 3]]);
    *off += 4;
    v
}

fn read_hash(buf: &[u8], off: &mut usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&buf[*off..*off + 32]);
    *off += 32;
    out
}

/// Load and parse the binary fixture file emitted by gen_merkle_inclusion.py.
fn load_fixture(n: u32) -> MerkleFixture {
    let path = format!("{FIXTURE_DIR}/merkle-tree-N{n}.bin");
    let buf = fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let mut off = 0usize;
    let tree_size = u64::from(read_u32_be(&buf, &mut off));
    let root_len = read_u32_be(&buf, &mut off);
    assert_eq!(root_len, 32, "fixture root is always sha-256");
    let root = read_hash(&buf, &mut off);
    let mut proofs = Vec::with_capacity(tree_size as usize);
    for _ in 0..tree_size {
        let leaf_index = u64::from(read_u32_be(&buf, &mut off));
        let leaf_len = read_u32_be(&buf, &mut off) as usize;
        let leaf_bytes = buf[off..off + leaf_len].to_vec();
        off += leaf_len;
        let path_count = read_u32_be(&buf, &mut off) as usize;
        let mut audit = Vec::with_capacity(path_count);
        for _ in 0..path_count {
            audit.push(read_hash(&buf, &mut off));
        }
        proofs.push((leaf_index, leaf_bytes, audit));
    }
    assert_eq!(off, buf.len(), "fixture file had trailing bytes");
    MerkleFixture {
        tree_size,
        root,
        proofs,
    }
}

// --- positive ------------------------------------------------------------

fn every_leaf_verifies(n: u32) {
    let fx = load_fixture(n);
    let v = empty_verifier();
    for (idx, leaf_bytes, audit) in &fx.proofs {
        let leaf_hash = pkix_ct::merkle_leaf_hash(leaf_bytes);
        let proof = MerkleAuditPath {
            leaf_index: *idx,
            tree_size: fx.tree_size,
            audit_path: audit.clone(),
        };
        v.verify_inclusion(&leaf_hash, &proof, &fx.root)
            .unwrap_or_else(|e| panic!("verify N={n} m={idx}: {e:?}"));
    }
}

#[test]
fn every_leaf_in_n7_verifies() {
    every_leaf_verifies(7);
}

#[test]
fn every_leaf_in_n11_verifies() {
    every_leaf_verifies(11);
}

// --- negative ------------------------------------------------------------

#[test]
fn rejects_tampered_root() {
    let fx = load_fixture(7);
    let v = empty_verifier();
    let (idx, leaf, audit) = &fx.proofs[3];
    let leaf_hash = pkix_ct::merkle_leaf_hash(leaf);
    let proof = MerkleAuditPath {
        leaf_index: *idx,
        tree_size: fx.tree_size,
        audit_path: audit.clone(),
    };
    let mut bad_root = fx.root;
    bad_root[7] ^= 0x01;
    assert_eq!(
        v.verify_inclusion(&leaf_hash, &proof, &bad_root),
        Err(Error::MerkleProofInvalid)
    );
}

#[test]
fn rejects_wrong_leaf_index_within_range() {
    let fx = load_fixture(7);
    let v = empty_verifier();
    let (idx, leaf, audit) = &fx.proofs[3];
    let leaf_hash = pkix_ct::merkle_leaf_hash(leaf);
    let mut proof = MerkleAuditPath {
        leaf_index: *idx,
        tree_size: fx.tree_size,
        audit_path: audit.clone(),
    };
    proof.leaf_index = (proof.leaf_index + 1) % fx.tree_size;
    assert_eq!(
        v.verify_inclusion(&leaf_hash, &proof, &fx.root),
        Err(Error::MerkleProofInvalid)
    );
}

#[test]
fn rejects_out_of_range_leaf_index() {
    let fx = load_fixture(7);
    let v = empty_verifier();
    let (_, leaf, audit) = &fx.proofs[0];
    let leaf_hash = pkix_ct::merkle_leaf_hash(leaf);
    let proof = MerkleAuditPath {
        leaf_index: fx.tree_size, // == tree_size: just past the end
        tree_size: fx.tree_size,
        audit_path: audit.clone(),
    };
    assert_eq!(
        v.verify_inclusion(&leaf_hash, &proof, &fx.root),
        Err(Error::MerkleProofInvalid)
    );
}

#[test]
fn rejects_tampered_audit_path_node() {
    let fx = load_fixture(11);
    let v = empty_verifier();
    let (idx, leaf, audit) = &fx.proofs[5];
    let leaf_hash = pkix_ct::merkle_leaf_hash(leaf);
    assert!(!audit.is_empty(), "fixture m=5 has at least one path elem");
    let mut tampered = audit.clone();
    tampered[0][0] ^= 0x80;
    let proof = MerkleAuditPath {
        leaf_index: *idx,
        tree_size: fx.tree_size,
        audit_path: tampered,
    };
    assert_eq!(
        v.verify_inclusion(&leaf_hash, &proof, &fx.root),
        Err(Error::MerkleProofInvalid)
    );
}

#[test]
fn rejects_empty_tree() {
    let v = empty_verifier();
    let leaf_hash = [0u8; 32];
    let proof = MerkleAuditPath {
        leaf_index: 0,
        tree_size: 0,
        audit_path: Vec::new(),
    };
    let root = [0u8; 32];
    assert_eq!(
        v.verify_inclusion(&leaf_hash, &proof, &root),
        Err(Error::MerkleProofMalformed)
    );
}

#[test]
fn rejects_overlong_audit_path() {
    let fx = load_fixture(7);
    let v = empty_verifier();
    let (idx, leaf, audit) = &fx.proofs[0];
    let leaf_hash = pkix_ct::merkle_leaf_hash(leaf);
    // Maximum legitimate audit-path length for N=7 is ceil(log2(7)) = 3.
    // Build a path of length 4 by appending an extra hash.
    let mut bloated = audit.clone();
    bloated.push([0xFFu8; 32]);
    let proof = MerkleAuditPath {
        leaf_index: *idx,
        tree_size: fx.tree_size,
        audit_path: bloated,
    };
    assert_eq!(
        v.verify_inclusion(&leaf_hash, &proof, &fx.root),
        Err(Error::MerkleProofMalformed)
    );
}

#[test]
fn rejects_short_audit_path() {
    // A non-trivial tree (N>1) needs at least one audit-path node to
    // verify ANY leaf. An audit path that's shorter than required
    // bubbles fn/sn to non-zero values, surfacing as
    // MerkleProofMalformed via the post-loop "sn != 0" check.
    let fx = load_fixture(7);
    let v = empty_verifier();
    let (idx, leaf, audit) = &fx.proofs[0];
    assert!(audit.len() > 1, "fixture m=0 has multiple path elements");
    let truncated = audit[..audit.len() - 1].to_vec();
    let leaf_hash = pkix_ct::merkle_leaf_hash(leaf);
    let proof = MerkleAuditPath {
        leaf_index: *idx,
        tree_size: fx.tree_size,
        audit_path: truncated,
    };
    assert_eq!(
        v.verify_inclusion(&leaf_hash, &proof, &fx.root),
        Err(Error::MerkleProofMalformed)
    );
}

// --- single-leaf edge case -----------------------------------------------

#[test]
fn single_leaf_tree_zero_path_verifies() {
    // RFC 6962 §2.1: MTH({d}) = SHA256(0x00 || d). The audit path
    // for the single leaf is empty. The verifier should accept the
    // empty path and return the leaf hash itself as the root.
    let v = empty_verifier();
    let leaf = b"single";
    let leaf_h = pkix_ct::merkle_leaf_hash(leaf);
    let proof = MerkleAuditPath {
        leaf_index: 0,
        tree_size: 1,
        audit_path: Vec::new(),
    };
    v.verify_inclusion(&leaf_h, &proof, &leaf_h)
        .expect("single-leaf inclusion proof verifies");
}

#[test]
fn single_leaf_tree_rejects_wrong_root() {
    let v = empty_verifier();
    let leaf = b"single";
    let leaf_h = pkix_ct::merkle_leaf_hash(leaf);
    let proof = MerkleAuditPath {
        leaf_index: 0,
        tree_size: 1,
        audit_path: Vec::new(),
    };
    let mut wrong_root = leaf_h;
    wrong_root[0] ^= 0x01;
    assert_eq!(
        v.verify_inclusion(&leaf_h, &proof, &wrong_root),
        Err(Error::MerkleProofInvalid)
    );
}

// --- STH verification (PKIX-baac.5 acceptance criteria 2 + 3) ----------

mod sth {
    //! Integration tests for [`SctVerifier::verify_sth`].
    //!
    //! Oracle: `tests/fixtures/sct-oracle/gen_sth_oracle.py` builds a
    //! synthetic Merkle tree of 7 leaves (same tree as N=7 from
    //! `gen_merkle_inclusion.py`), constructs an RFC 6962 §3.5
    //! `TreeHeadSignature` over the tree's root + timestamp + size,
    //! signs it with a fresh ECDSA-P256 key, and commits the input,
    //! output, and log SPKI. openssl `dgst -verify` independently
    //! validates the signature against the SPKI and signed-input
    //! bytes — recorded in the oracle script's commit log.

    use std::fs;

    use pkix_ct::{
        merkle_leaf_hash, CtLog, CtLogList, Error, MerkleAuditPath, SctVerifier, SignedTreeHead,
    };
    use pkix_path::DefaultVerifier;

    fn fixture(name: &str) -> Vec<u8> {
        let path = format!("{}/{name}", super::FIXTURE_DIR);
        fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
    }

    /// STH oracle constants — mirrored from gen_sth_oracle.py. The
    /// script writes the same values to sth-meta.json for human
    /// inspection; we hardcode them here to avoid pulling in a JSON
    /// parser as a dev-dependency just for two fields. If the oracle
    /// script changes these values, mirror the change here. The
    /// per-fixture root_hash is read from sth-tree.bin (the canonical
    /// binary form) rather than meta.json, so this constants block
    /// covers only the size/timestamp/algorithm metadata.
    const STH_TREE_SIZE: u64 = 7;
    const STH_TIMESTAMP_MS: u64 = 1_750_032_000_000;
    const STH_HASH_ALG: u8 = 4; // SHA-256
    const STH_SIG_ALG: u8 = 3; // ECDSA

    fn sth_log_list() -> CtLogList {
        let spki = fixture("sth-log-spki.der");
        let log_id_bytes = fixture("sth-log-id.bin");
        let log_id: [u8; 32] = log_id_bytes
            .as_slice()
            .try_into()
            .expect("sth-log-id.bin is 32 bytes");
        let mut logs = CtLogList::new();
        logs.insert(CtLog {
            log_id,
            key_der: spki,
            description: "sth-oracle".into(),
            url: "http://example.invalid/ct/".into(),
            usable_from_ms: None,
            retired_at_ms: None,
        })
        .unwrap();
        logs
    }

    /// Read the root hash from sth-tree.bin's header. Format: u32 N,
    /// u32 root_len, root_len bytes.
    fn read_root_from_tree() -> [u8; 32] {
        let buf = fixture("sth-tree.bin");
        let _n = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        let root_len = u32::from_be_bytes(buf[4..8].try_into().unwrap()) as usize;
        assert_eq!(root_len, 32);
        let mut root = [0u8; 32];
        root.copy_from_slice(&buf[8..8 + 32]);
        root
    }

    fn load_sth() -> ([u8; 32], SignedTreeHead) {
        let log_id_bytes = fixture("sth-log-id.bin");
        let log_id: [u8; 32] = log_id_bytes.as_slice().try_into().unwrap();
        let sth = SignedTreeHead {
            tree_size: STH_TREE_SIZE,
            timestamp_ms: STH_TIMESTAMP_MS,
            root_hash: read_root_from_tree(),
            hash_alg: STH_HASH_ALG,
            sig_alg: STH_SIG_ALG,
            signature: fixture("sth-signature.bin"),
        };
        (log_id, sth)
    }

    // --- positive: STH verifies ----------------------------------------

    #[test]
    fn verifies_real_world_shaped_sth() {
        let v = SctVerifier::new(sth_log_list(), DefaultVerifier);
        let (log_id, sth) = load_sth();
        let log = v.verify_sth(&log_id, &sth).expect("verify STH");
        assert_eq!(log.description, "sth-oracle");
    }

    // --- negative: tampered fields surface as InvalidSignature --------

    #[test]
    fn rejects_tampered_timestamp() {
        let v = SctVerifier::new(sth_log_list(), DefaultVerifier);
        let (log_id, mut sth) = load_sth();
        sth.timestamp_ms = sth.timestamp_ms.wrapping_add(1);
        assert_eq!(v.verify_sth(&log_id, &sth), Err(Error::InvalidSignature));
    }

    #[test]
    fn rejects_tampered_tree_size() {
        let v = SctVerifier::new(sth_log_list(), DefaultVerifier);
        let (log_id, mut sth) = load_sth();
        sth.tree_size = sth.tree_size.wrapping_add(1);
        assert_eq!(v.verify_sth(&log_id, &sth), Err(Error::InvalidSignature));
    }

    #[test]
    fn rejects_tampered_root_hash() {
        let v = SctVerifier::new(sth_log_list(), DefaultVerifier);
        let (log_id, mut sth) = load_sth();
        sth.root_hash[7] ^= 0x80;
        assert_eq!(v.verify_sth(&log_id, &sth), Err(Error::InvalidSignature));
    }

    #[test]
    fn rejects_tampered_signature() {
        let v = SctVerifier::new(sth_log_list(), DefaultVerifier);
        let (log_id, mut sth) = load_sth();
        let mid = sth.signature.len() / 2;
        sth.signature[mid] ^= 0xAA;
        assert_eq!(v.verify_sth(&log_id, &sth), Err(Error::InvalidSignature));
    }

    #[test]
    fn rejects_unknown_log_id() {
        let v = SctVerifier::new(CtLogList::new(), DefaultVerifier);
        let (log_id, sth) = load_sth();
        assert_eq!(v.verify_sth(&log_id, &sth), Err(Error::UnknownLog));
    }

    #[test]
    fn rejects_unsupported_signature_algorithm() {
        let v = SctVerifier::new(sth_log_list(), DefaultVerifier);
        let (log_id, mut sth) = load_sth();
        // sig_alg=2 (DSA) is excluded by project policy.
        sth.sig_alg = 2;
        assert_eq!(
            v.verify_sth(&log_id, &sth),
            Err(Error::UnsupportedSignatureAlgorithm {
                hash_alg: 4,
                sig_alg: 2,
            })
        );
    }

    // --- combined STH + inclusion-proof flow --------------------------

    /// Acceptance criterion 2 (PKIX-baac.5): "One real-world
    /// inclusion proof verifies against a real STH". The fixture is
    /// synthetic but the algorithm shape is identical to what real
    /// RFC 6962 logs emit. Real-world-byte defense in depth is added
    /// by `tests/live_log.rs` (PKIX-baac.8), which exercises the
    /// same flow against a triple captured from a deployed CT log.
    /// This test exercises the full STH-plus-inclusion flow against
    /// a hash- and signature-validated synthetic oracle.
    #[test]
    fn inclusion_proof_against_sth_verified_root() {
        let v = SctVerifier::new(sth_log_list(), DefaultVerifier);
        let (log_id, sth) = load_sth();

        // 1. Verify the STH signature.
        v.verify_sth(&log_id, &sth).expect("STH signature");

        // 2. Use the STH's committed root_hash to verify an
        // inclusion proof for an arbitrary leaf in the same tree.
        //    The sth-tree.bin file has the same layout as
        //    merkle-tree-N7.bin from the inclusion oracle.
        let tree_buf = fixture("sth-tree.bin");
        let mut off = 0usize;
        let n = u32::from_be_bytes(tree_buf[0..4].try_into().unwrap()) as usize;
        off += 4;
        let root_len = u32::from_be_bytes(tree_buf[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        let mut tree_root = [0u8; 32];
        tree_root.copy_from_slice(&tree_buf[off..off + root_len]);
        off += root_len;
        assert_eq!(
            tree_root, sth.root_hash,
            "the tree fixture and the STH agree on root_hash"
        );

        // Pick the last leaf (m=6 in N=7) — exercises the
        // left-leaning rebalance branch.
        let target_m = 6u64;
        for _ in 0..n {
            let m = u64::from(u32::from_be_bytes(
                tree_buf[off..off + 4].try_into().unwrap(),
            ));
            off += 4;
            let leaf_len = u32::from_be_bytes(tree_buf[off..off + 4].try_into().unwrap()) as usize;
            off += 4;
            let leaf_bytes = &tree_buf[off..off + leaf_len];
            off += leaf_len;
            let path_count =
                u32::from_be_bytes(tree_buf[off..off + 4].try_into().unwrap()) as usize;
            off += 4;
            let mut audit_path = Vec::with_capacity(path_count);
            for _ in 0..path_count {
                let mut h = [0u8; 32];
                h.copy_from_slice(&tree_buf[off..off + 32]);
                off += 32;
                audit_path.push(h);
            }
            if m == target_m {
                let leaf_h = merkle_leaf_hash(leaf_bytes);
                let proof = MerkleAuditPath {
                    leaf_index: m,
                    tree_size: sth.tree_size,
                    audit_path,
                };
                v.verify_inclusion(&leaf_h, &proof, &sth.root_hash)
                    .expect("inclusion proof against STH root");
                return;
            }
        }
        panic!("target leaf {target_m} not found in fixture");
    }
}
