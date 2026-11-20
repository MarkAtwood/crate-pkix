#!/usr/bin/env python3
"""Generate review fixtures for pkix-identity (stdlib only).

pkix-identity never verifies signatures, so the certificates carry a
fixed dummy ECDSA signature and a fixed P-256 SPKI. Each fixture is a leaf
whose only SAN is one otherName(SmtpUTF8Mailbox, UTF8String <mailbox>).

Run:  python3 -I gen.py
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, content):
    return bytes([tag]) + der_len(len(content)) + content


def seq(*items):
    return tlv(0x30, b"".join(items))


def oid(dotted):
    parts = [int(x) for x in dotted.split(".")]
    body = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        body += bytes(reversed(chunk))
    return tlv(0x06, body)


def name(cn):
    return seq(tlv(0x31, seq(oid("2.5.4.3"), tlv(0x0C, cn.encode()))))


ECDSA_SHA256 = seq(oid("1.2.840.10045.4.3.2"))
# Fixed uncompressed P-256 point (the generator G); never used to verify.
G = bytes.fromhex(
    "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
)
SPKI = seq(seq(oid("1.2.840.10045.2.1"), oid("1.2.840.10045.3.1.7")), tlv(0x03, b"\x00" + G))
VALIDITY = seq(tlv(0x17, b"000101000000Z"), tlv(0x18, b"20500101000000Z"))
DUMMY_SIG = seq(tlv(0x02, b"\x01"), tlv(0x02, b"\x01"))


def smtputf8_leaf(mailbox, serial):
    other = tlv(0xA0, oid("1.3.6.1.5.5.7.8.9") + tlv(0xA0, tlv(0x0C, mailbox.encode())))
    san = seq(oid("2.5.29.17"), tlv(0x04, seq(other)))
    tbs = seq(
        tlv(0xA0, tlv(0x02, b"\x02")),
        tlv(0x02, bytes([serial])),
        ECDSA_SHA256,
        name("Review Identity CA"),
        VALIDITY,
        name("review leaf"),
        SPKI,
        tlv(0xA3, seq(san)),
    )
    return seq(tbs, ECDSA_SHA256, tlv(0x03, b"\x00" + DUMMY_SIG))


for fname, mbox, serial in [
    # Non-conformant per RFC 8398 §3 (ASCII local-part in SmtpUTF8Mailbox).
    ("smtputf8_ascii_local_leaf.der", "alice@evil.com", 1),
    # Conformant: non-ASCII local-part, U-label domain.
    ("smtputf8_intl_ulabel_leaf.der", "用户@bücher.example", 2),
]:
    with open(os.path.join(HERE, fname), "wb") as f:
        f.write(smtputf8_leaf(mbox, serial))
print("ok")
