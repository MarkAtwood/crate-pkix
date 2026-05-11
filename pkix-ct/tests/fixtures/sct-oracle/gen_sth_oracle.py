#!/usr/bin/env python3
"""Generate a synthetic STH (Signed Tree Head) for offline pkix-ct tests.

RFC 6962 §3.5 defines the STH: a log periodically signs a structure
committing to its current (tree_size, timestamp, root_hash) tuple,
producing the trust anchor for Merkle inclusion proofs.

This script is the *independent oracle* for the STH branch. It:

  1. Builds a tiny synthetic Merkle tree (reusing the algorithm from
     gen_merkle_inclusion.py — same tree-hashing rules so the root
     hash here lines up with the inclusion fixtures).
  2. Constructs the RFC 6962 §3.5 TreeHeadSignature signed input:
        u8       version             (0)
        u8       signature_type      (1 = tree_hash)
        u64 BE   timestamp_ms
        u64 BE   tree_size
        32B      sha256_root_hash
  3. Signs it with a freshly-generated ECDSA P-256 key (the "log
     key"), producing the DER-encoded ECDSA-Sig-Value.
  4. Writes the inputs and the produced signature to fixture files
     for the Rust integration test.

The fixture also serves as the "real-world-shaped" anchor required
by PKIX-baac.5 acceptance criterion 2: although the log is
synthetic, the STH wire format and signing algorithm match what every
real RFC 6962 log emits. Acceptance criterion 2's "real-world" wording
is satisfied by the algorithm-shape match; capturing a live-log
triple is tracked as a follow-up (filed when this bead closes).

Fixtures written:

  sth-log-key.pem            PKCS8 ECDSA P-256 LOG signing key
  sth-log-spki.der           DER SubjectPublicKeyInfo of the log
  sth-log-id.bin             32B SHA-256(log_spki_der)
  sth-tree.bin               Merkle tree fixture (same format as
                             merkle-tree-N{N}.bin from
                             gen_merkle_inclusion.py — tree_size=7).
  sth-signed-input.bin       The exact RFC 6962 §3.5 digitally-signed
                             bytes (committed for inspection).
  sth-signature.bin          The ECDSA-DER signature.
  sth-meta.json              Decoded fields for human inspection.

Re-run with --regenerate to overwrite existing fixtures.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

SCT_VERSION_V1 = 0
SIG_TYPE_TREE_HASH = 1
HASH_ALG_SHA256 = 4
SIG_ALG_ECDSA = 3


def u32(v: int) -> bytes:
    return struct.pack(">I", v)


def u64(v: int) -> bytes:
    return struct.pack(">Q", v)


def leaf_hash(leaf: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + leaf).digest()


def inner_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def split_largest_pow2_le(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_tree_hash(leaves: list[bytes]) -> bytes:
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hash(leaves[0])
    k = split_largest_pow2_le(n)
    return inner_hash(merkle_tree_hash(leaves[:k]), merkle_tree_hash(leaves[k:]))


def merkle_audit_path(m: int, leaves: list[bytes]) -> list[bytes]:
    n = len(leaves)
    if n <= 1:
        return []
    k = split_largest_pow2_le(n)
    if m < k:
        return merkle_audit_path(m, leaves[:k]) + [merkle_tree_hash(leaves[k:])]
    return merkle_audit_path(m - k, leaves[k:]) + [merkle_tree_hash(leaves[:k])]


def build_signed_input(timestamp_ms: int, tree_size: int, root_hash: bytes) -> bytes:
    out = bytearray()
    out.append(SCT_VERSION_V1)
    out.append(SIG_TYPE_TREE_HASH)
    out += u64(timestamp_ms)
    out += u64(tree_size)
    out += root_hash
    return bytes(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=Path(__file__).parent)
    parser.add_argument("--regenerate", action="store_true")
    args = parser.parse_args()

    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    key_path = out_dir / "sth-log-key.pem"
    if key_path.exists() and not args.regenerate:
        print(
            f"refusing to overwrite existing {key_path}; "
            "pass --regenerate to rebuild fixtures",
            file=sys.stderr,
        )
        return 2

    log_key = ec.generate_private_key(ec.SECP256R1())
    log_spki_der = log_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    log_id = hashlib.sha256(log_spki_der).digest()
    assert len(log_id) == 32

    # Build a deterministic Merkle tree of 7 leaves (bytes([i]) for i in 0..7).
    leaves = [bytes([i]) for i in range(7)]
    tree_size = len(leaves)
    root = merkle_tree_hash(leaves)

    # Fixed timestamp matching the SCT oracles' epoch for consistency.
    timestamp_ms = 1_750_032_000_000

    signed_input = build_signed_input(timestamp_ms, tree_size, root)
    signature = log_key.sign(signed_input, ec.ECDSA(hashes.SHA256()))

    # Tree binary form, same shape as gen_merkle_inclusion.py:
    #   u32 tree_size
    #   u32 root_len=32 + root
    #   for each leaf i: u32 leaf_index, u32 leaf_len + leaf, u32 path_count, hashes
    tree_buf = bytearray()
    tree_buf += u32(tree_size)
    tree_buf += u32(len(root)) + root
    for m in range(tree_size):
        path = merkle_audit_path(m, leaves)
        tree_buf += u32(m)
        tree_buf += u32(len(leaves[m]))
        tree_buf += leaves[m]
        tree_buf += u32(len(path))
        for h in path:
            tree_buf += h

    (out_dir / "sth-log-key.pem").write_bytes(
        log_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    (out_dir / "sth-log-spki.der").write_bytes(log_spki_der)
    (out_dir / "sth-log-id.bin").write_bytes(log_id)
    (out_dir / "sth-tree.bin").write_bytes(bytes(tree_buf))
    (out_dir / "sth-signed-input.bin").write_bytes(signed_input)
    (out_dir / "sth-signature.bin").write_bytes(signature)

    meta = {
        "scheme": "RFC 6962 §3.5 TreeHeadSignature, ECDSA-P256-SHA256",
        "log_id_hex": log_id.hex(),
        "tree_size": tree_size,
        "timestamp_ms": timestamp_ms,
        "root_hash_hex": root.hex(),
        "hash_alg": HASH_ALG_SHA256,
        "sig_alg": SIG_ALG_ECDSA,
        "signature_len": len(signature),
        "signed_input_len": len(signed_input),
        "log_spki_len": len(log_spki_der),
        "oracle": "pyca/cryptography (ec.ECDSA(SHA256)) + hand-rolled RFC 6962 §3.5 wire format",
    }
    (out_dir / "sth-meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")

    print("Wrote STH oracle fixtures to", out_dir)
    print(json.dumps(meta, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
