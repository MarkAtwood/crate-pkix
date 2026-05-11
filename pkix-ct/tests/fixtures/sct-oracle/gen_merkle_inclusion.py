#!/usr/bin/env python3
"""Generate Merkle inclusion proof test vectors for pkix-ct (PKIX-baac.5).

RFC 6962 §2.1 defines a left-leaning binary Merkle tree built over a
sequence of leaves. The tree-hashing rules are:

  - Leaf hash:        H(0x00 || leaf_bytes)
  - Inner node hash:  H(0x01 || left_hash || right_hash)

This script builds a synthetic tree of N leaves (one byte each, the
leaf index as a u8) and emits inclusion proofs for every leaf, plus
the root hash. The Rust implementation then verifies each proof using
RFC 9162 §2.1.3.2's algorithm and asserts the same root hash is
reached.

The script is the *independent oracle*: it implements the tree
construction directly from RFC 6962 §2.1, never calling pkix-ct or
any third-party CT library. pkix-ct's verification path is then
exercised against the committed fixtures.

Fixtures written to this directory:

  merkle-tree-N{N}.json    The full tree description for inspection.
                           Includes: tree_size, root_hash, leaves
                           (hex), and per-leaf inclusion proofs.
  merkle-tree-N{N}.bin     Binary form: BE u32 N, BE u32 root_len=32,
                           root, then N entries each of (BE u32 path_len,
                           BE u32 audit_path_count, audit_path[count] of
                           32 bytes each, BE u32 leaf_bytes_len,
                           leaf_bytes).

We emit two trees:
  - N=7  (odd, exercising left-leaning rebalance for the last leaf).
  - N=11 (odd, deeper, exercising several rebalances).

Re-run with --regenerate to overwrite existing fixtures.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path


def leaf_hash(leaf: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + leaf).digest()


def inner_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def split_largest_pow2_le(n: int) -> int:
    """Largest power of 2 strictly less than n, used by RFC 6962 §2.1
    tree decomposition.

        D[n] = SUBPROOF(m, D[n], true)
    where MTH(D[n]) is computed by splitting at index k = 2^(ceil(log2(n)) - 1),
    i.e. the largest power of 2 that is < n. For n a power of 2, k == n/2;
    otherwise k is the largest pow2 < n.
    """
    if n < 2:
        raise ValueError(f"split_largest_pow2_le requires n >= 2, got {n}")
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_tree_hash(leaves: list[bytes]) -> bytes:
    """RFC 6962 §2.1 MTH(D[n]).

    MTH({}) = SHA-256()  (only used by the empty-tree case)
    MTH({d}) = leaf_hash(d)
    MTH(D[n]) = inner_hash(MTH(D[0:k]), MTH(D[k:n]))
       where k = largest power of 2 < n
    """
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hash(leaves[0])
    k = split_largest_pow2_le(n)
    return inner_hash(merkle_tree_hash(leaves[:k]), merkle_tree_hash(leaves[k:]))


def merkle_audit_path(m: int, leaves: list[bytes]) -> list[bytes]:
    """RFC 6962 §2.1.1 PATH(m, D[n]).

    PATH(0, {d0}) = {}
    PATH(m, D[n]):
       k = split point (as in merkle_tree_hash)
       if m < k:
           return PATH(m, D[0:k]) ++ [MTH(D[k:n])]
       else:
           return PATH(m - k, D[k:n]) ++ [MTH(D[0:k])]
    """
    n = len(leaves)
    if n <= 1:
        return []
    k = split_largest_pow2_le(n)
    if m < k:
        return merkle_audit_path(m, leaves[:k]) + [merkle_tree_hash(leaves[k:])]
    return merkle_audit_path(m - k, leaves[k:]) + [merkle_tree_hash(leaves[:k])]


def build_tree(n: int) -> dict:
    """Build a tree of n leaves (leaf i = bytes([i])) and emit the
    full fixture description.
    """
    leaves = [bytes([i]) for i in range(n)]
    root = merkle_tree_hash(leaves)
    proofs = []
    for m in range(n):
        path = merkle_audit_path(m, leaves)
        proofs.append(
            {
                "leaf_index": m,
                "leaf_hex": leaves[m].hex(),
                "leaf_hash_hex": leaf_hash(leaves[m]).hex(),
                "audit_path_hex": [h.hex() for h in path],
            }
        )
    return {
        "tree_size": n,
        "root_hex": root.hex(),
        "leaves_hex": [leaf.hex() for leaf in leaves],
        "proofs": proofs,
    }


def write_tree_binary(out_path: Path, tree: dict) -> None:
    """Pack the fixture into a tight binary form that's easy to parse
    in the Rust integration test without pulling in a JSON dep there.

    Layout (all integers big-endian):
        u32 tree_size N
        u32 root_len = 32
        32B root_hash
        for each leaf i in 0..N:
            u32 leaf_index (= i)
            u32 leaf_bytes_len
            leaf_bytes
            u32 audit_path_count
            for each hash in audit_path:
                32B hash
    """
    buf = bytearray()
    n = tree["tree_size"]
    buf += struct.pack(">I", n)
    root = bytes.fromhex(tree["root_hex"])
    buf += struct.pack(">I", len(root)) + root
    for proof in tree["proofs"]:
        leaf = bytes.fromhex(proof["leaf_hex"])
        buf += struct.pack(">II", proof["leaf_index"], len(leaf))
        buf += leaf
        path = [bytes.fromhex(h) for h in proof["audit_path_hex"]]
        buf += struct.pack(">I", len(path))
        for h in path:
            buf += h
    out_path.write_bytes(bytes(buf))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=Path(__file__).parent)
    parser.add_argument("--regenerate", action="store_true")
    args = parser.parse_args()

    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    for n in (7, 11):
        json_path = out_dir / f"merkle-tree-N{n}.json"
        bin_path = out_dir / f"merkle-tree-N{n}.bin"
        if (json_path.exists() or bin_path.exists()) and not args.regenerate:
            print(
                f"refusing to overwrite existing {json_path} / {bin_path}; "
                "pass --regenerate to rebuild",
                file=sys.stderr,
            )
            return 2

    out = {}
    for n in (7, 11):
        tree = build_tree(n)
        out[f"N{n}"] = tree
        (out_dir / f"merkle-tree-N{n}.json").write_text(
            json.dumps(tree, indent=2, sort_keys=True) + "\n"
        )
        write_tree_binary(out_dir / f"merkle-tree-N{n}.bin", tree)
    print("Wrote merkle inclusion fixtures to", out_dir)
    for n, tree in out.items():
        print(f"  {n}: root={tree['root_hex'][:16]}…  proofs={len(tree['proofs'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
