#!/usr/bin/env python3
"""Rewrites a certificate's validity times as GeneralizedTime.

Why this exists
---------------
`pkix-dane` hashes certificates as the peer presented them, never a
re-encoding of a parsed certificate, because `x509-cert` 0.3 normalizes
validity times when it re-encodes: a date before 2050 is emitted as
`UTCTime` even when the issuer wrote `GeneralizedTime`. A TLSA record
published over such a certificate would not match a digest taken over
`to_der()` output.

OpenSSL will not produce such a certificate -- it follows RFC 5280
§4.1.2.5 and emits `UTCTime` for pre-2050 dates -- so the fixture that
exercises the hazard has to be assembled by hand. This script does that
by parsing the DER into a tag/length/value tree, rewriting the two
`UTCTime` values in the `Validity` sequence as `GeneralizedTime`, and
re-encoding. Enclosing lengths are recomputed by the re-encode, so the
2-octet growth of each time field propagates correctly.

The result is not a validly-signed certificate: the signature covers the
original `tbsCertificate` bytes. That is fine and deliberate. DANE
matching never inspects a signature, an issuer or a validity date -- it
compares octets -- so an unsigned fixture exercises exactly the code path
under test and nothing else.

Usage: gen_gentime.py <in.der> <out.der>
"""

from __future__ import annotations

import sys

TAG_UTC_TIME = 0x17
TAG_GENERALIZED_TIME = 0x18
CLASS_UNIVERSAL = 0x00
TAG_SEQUENCE = 0x30


class Node:
    """One DER TLV. `children` is None for a primitive, holding raw bytes."""

    def __init__(self, tag: int, value: bytes, children: list["Node"] | None):
        self.tag = tag
        self.value = value
        self.children = children

    def is_constructed(self) -> bool:
        return self.children is not None


def read_len(data: bytes, i: int) -> tuple[int, int]:
    """Returns (length, index after the length octets)."""
    first = data[i]
    i += 1
    if first < 0x80:
        return first, i
    if first == 0x80:
        raise ValueError("indefinite-length encoding is not valid DER")
    count = first & 0x7F
    if count > 4:
        raise ValueError(f"unreasonable length-of-length {count}")
    length = int.from_bytes(data[i : i + count], "big")
    return length, i + count


def encode_len(length: int) -> bytes:
    """Minimal-form DER length, as DER requires."""
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def parse(data: bytes, i: int = 0, end: int | None = None) -> list[Node]:
    """Parses TLVs in data[i:end] into Nodes, recursing into constructed ones."""
    if end is None:
        end = len(data)
    nodes: list[Node] = []
    while i < end:
        tag = data[i]
        length, j = read_len(data, i + 1)
        value = data[j : j + length]
        if len(value) != length:
            raise ValueError("truncated TLV")
        # Bit 0x20 marks a constructed encoding. Recurse into those only;
        # primitives keep their bytes verbatim so the round trip is exact.
        children = parse(value) if tag & 0x20 else None
        nodes.append(Node(tag, value, children))
        i = j + length
    return nodes


def encode(node: Node) -> bytes:
    if node.is_constructed():
        body = b"".join(encode(child) for child in node.children)
    else:
        body = node.value
    return bytes([node.tag]) + encode_len(len(body)) + body


def utc_to_generalized(value: bytes) -> bytes:
    """YYMMDDHHMMSSZ -> YYYYMMDDHHMMSSZ, per RFC 5280 §4.1.2.5.1.

    Two-digit years 50..99 mean 19xx; 00..49 mean 20xx.
    """
    text = value.decode("ascii")
    if len(text) != 13 or not text.endswith("Z"):
        raise ValueError(f"expected a 13-octet UTCTime, got {text!r}")
    yy = int(text[:2])
    century = 19 if yy >= 50 else 20
    return f"{century}{text[:2]}{text[2:]}".encode("ascii")


def rewrite_validity(node: Node) -> bool:
    """Finds the Validity sequence and converts its times. Returns whether
    anything changed."""
    if node.is_constructed():
        # Validity ::= SEQUENCE { notBefore Time, notAfter Time }
        if (
            node.tag == TAG_SEQUENCE
            and len(node.children) == 2
            and all(c.tag in (TAG_UTC_TIME, TAG_GENERALIZED_TIME) for c in node.children)
        ):
            changed = False
            for child in node.children:
                if child.tag == TAG_UTC_TIME:
                    child.value = utc_to_generalized(child.value)
                    child.tag = TAG_GENERALIZED_TIME
                    changed = True
            return changed
        return any(rewrite_validity(child) for child in node.children)
    return False


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    src, dst = sys.argv[1], sys.argv[2]

    original = open(src, "rb").read()
    roots = parse(original)
    if len(roots) != 1:
        raise SystemExit(f"{src}: expected one top-level TLV, found {len(roots)}")
    cert = roots[0]

    # Fidelity gate: an exact round trip before any edit proves the
    # parse/encode pair is faithful, so a byte difference afterwards can
    # only come from the intended rewrite.
    if encode(cert) != original:
        raise SystemExit(f"{src}: TLV round trip is not byte-exact; refusing to edit")

    if not rewrite_validity(cert):
        raise SystemExit(f"{src}: found no UTCTime validity field to rewrite")

    rewritten = encode(cert)
    if rewritten == original:
        raise SystemExit(f"{src}: rewrite produced identical bytes")

    with open(dst, "wb") as out:
        out.write(rewritten)
    print(f"{dst}: {len(original)} -> {len(rewritten)} octets (+{len(rewritten) - len(original)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
