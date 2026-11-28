#!/usr/bin/env python3
"""
An x509_entry SCT over a certificate larger than 64 KiB.

WHAT THE RULE IS
----------------
RFC 6962 §3.2 carries the certificate as `ASN.1Cert`, which is
`opaque<1..2^24-1>` -- a three-byte big-endian length prefix. pkix-ct
emits it as

    out.push(((cert_len >> 16) & 0xFF) as u8);
    out.extend_from_slice(&(cert_len as u16).to_be_bytes());

and that top octet is zero for every certificate under 65536 bytes. So
`>> 16` read as `<< 16` -- which makes the low eight bits of any value
zero -- produces the same bytes for every fixture in this directory, and
four mutants of it survive across the MerkleTreeLeaf and signed-input
builders for both entry types.

A certificate over 64 KiB is what separates them. Its length needs all
three octets, so a wrong top octet is a wrong length prefix, the signed
input is a different message, and the SCT no longer verifies.

  cert.der          a self-signed certificate over 64 KiB
  sct.bin           a wire-format SCT over it, signed by log-key.pem
  signed-input.bin  the §3.2 digitally-signed input, for inspection
  log-spki.der      the log's SubjectPublicKeyInfo
  log-id.bin        SHA-256 of that SPKI, the RFC 6962 log_id
  meta.json         the decoded fields

The size comes from one large extension rather than many small ones, so
the certificate stays a certificate that `x509-cert` will parse: an
unrecognised non-critical extension whose value is a DER OCTET STRING of
padding. Nothing reads it; it is there to push the encoding past 65535
bytes.

This is the same independent-oracle arrangement as `../sct-oracle`: every
byte here is produced by this script from the RFC's own layout, and
pkix-ct plays no part in making the fixtures it is then asked to verify.
It reuses `../sct-oracle/log-key.pem` so there is one log signer across
the suite.

Usage: python3 gen.py   (run from this directory; needs `cryptography`)
"""

import datetime
import hashlib
import json
import struct
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

HERE = Path(__file__).resolve().parent
LOG_KEY = HERE / "../sct-oracle/log-key.pem"

# RFC 6962 §3.2 constants.
SCT_VERSION_V1 = 0
SIG_TYPE_CERTIFICATE_TIMESTAMP = 0
ENTRY_TYPE_X509 = 0
ENTRY_TYPE_PRECERT = 1
HASH_ALG_SHA256 = 4
SIG_ALG_ECDSA = 3

NOT_BEFORE = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
NOT_AFTER = datetime.datetime(2036, 1, 1, tzinfo=datetime.timezone.utc)
TIMESTAMP_MS = 1_767_225_600_000  # 2026-01-01T00:00:00Z
# An arc with no assigned meaning, so nothing is tempted to read it.
PADDING_OID = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1")
OID_SCT_LIST = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")


def u8(v):
    return struct.pack(">B", v)


def u16(v):
    return struct.pack(">H", v)


def u64(v):
    return struct.pack(">Q", v)


def u24(v):
    """Three-byte big-endian length: top octet, then the lower 16 bits."""
    if not 0 <= v <= 0xFFFFFF:
        raise ValueError(f"u24 out of range: {v}")
    return bytes([(v >> 16) & 0xFF]) + u16(v & 0xFFFF)


def build_signed_input_x509_entry(timestamp_ms, cert_der, extensions):
    """RFC 6962 §3.2 digitally-signed input, x509_entry branch."""
    out = bytearray()
    out += u8(SCT_VERSION_V1)
    out += u8(SIG_TYPE_CERTIFICATE_TIMESTAMP)
    out += u64(timestamp_ms)
    out += u16(ENTRY_TYPE_X509)
    out += u24(len(cert_der)) + cert_der
    out += u16(len(extensions)) + extensions
    return bytes(out)


def build_signed_input_precert_entry(
    timestamp_ms, issuer_key_hash, tbs_no_sct, extensions
):
    """RFC 6962 §3.2 digitally-signed input, precert_entry branch.

    The same preamble as the x509 branch, with entry_type 1 and the
    issuer's key hash before the TBS -- and the same u24 length, which is
    why this branch needs its own large fixture.
    """
    out = bytearray()
    out += u8(SCT_VERSION_V1)
    out += u8(SIG_TYPE_CERTIFICATE_TIMESTAMP)
    out += u64(timestamp_ms)
    out += u16(ENTRY_TYPE_PRECERT)
    out += issuer_key_hash
    out += u24(len(tbs_no_sct)) + tbs_no_sct
    out += u16(len(extensions)) + extensions
    return bytes(out)


def build_sct_wire(log_id, timestamp_ms, extensions, hash_alg, sig_alg, signature):
    out = bytearray()
    out += u8(SCT_VERSION_V1)
    out += log_id
    out += u64(timestamp_ms)
    out += u16(len(extensions)) + extensions
    out += u8(hash_alg)
    out += u8(sig_alg)
    out += u16(len(signature)) + signature
    return bytes(out)


def der_octet_string(body):
    """DER OCTET STRING, long-form length."""
    n = len(body)
    be = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x04, 0x80 | len(be)]) + be + body


def encode_sct_list_extension_value(scts_wire):
    """RFC 6962 §3.3 SignedCertificateTimestampList, DER-wrapped.

    `UnrecognizedExtension` takes the already-OCTET-STRING-wrapped
    payload; the builder adds the outer extnValue OCTET STRING itself.
    """
    inner = bytearray()
    for sct in scts_wire:
        inner += u16(len(sct)) + sct
    return der_octet_string(bytes(u16(len(inner)) + inner))


def make_large_cert(padding_len):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pkix-ct large leaf")])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(0x4C)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(
            x509.UnrecognizedExtension(
                PADDING_OID, der_octet_string(b"\xA5" * padding_len)
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )


def main():
    log_key = serialization.load_pem_private_key(LOG_KEY.read_bytes(), password=None)
    log_spki = log_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    log_id = hashlib.sha256(log_spki).digest()

    # Grow the padding until the encoding is comfortably over 65535, so the
    # top octet of the u24 length is non-zero.
    cert_der = make_large_cert(70_000)
    assert len(cert_der) > 0xFFFF, f"cert is {len(cert_der)} bytes, need > 65535"
    assert (len(cert_der) >> 16) & 0xFF != 0, "the top length octet must be non-zero"

    extensions = b""
    signed_input = build_signed_input_x509_entry(TIMESTAMP_MS, cert_der, extensions)
    signature = log_key.sign(signed_input, ec.ECDSA(hashes.SHA256()))
    sct_wire = build_sct_wire(
        log_id, TIMESTAMP_MS, extensions, HASH_ALG_SHA256, SIG_ALG_ECDSA, signature
    )

    # The oracle checks its own output before writing it.
    log_key.public_key().verify(signature, signed_input, ec.ECDSA(hashes.SHA256()))
    x509.load_der_x509_certificate(cert_der)

    for name, data in (
        ("cert.der", cert_der),
        ("sct.bin", sct_wire),
        ("signed-input.bin", signed_input),
        ("log-spki.der", log_spki),
        ("log-id.bin", log_id),
    ):
        (HERE / name).write_bytes(data)
        print(f"wrote {name} ({len(data)} bytes)")

    # ---------------------------------------------------------------
    # The precert_entry branch, which has its own copy of the u24.
    #
    # A CA issues a large leaf; the signed input is over that leaf's TBS
    # with no SCT-list extension, which is the TBS as issued here since
    # none was added. `pkix_ct::merkle_tree_leaf_for_precert` reconstructs
    # exactly this from the leaf and the issuer.
    # ---------------------------------------------------------------
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    issuer_dn = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "pkix-ct large issuer")]
    )
    issuer = (
        x509.CertificateBuilder()
        .subject_name(issuer_dn)
        .issuer_name(issuer_dn)
        .public_key(issuer_key.public_key())
        .serial_number(0x4D)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(issuer_key, hashes.SHA256())
    )
    issuer_der = issuer.public_bytes(serialization.Encoding.DER)
    issuer_key_hash = hashlib.sha256(
        issuer_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).digest()

    # The real CT flow, because pkix-ct verifies an *embedded* SCT and so
    # requires the final certificate to carry the SCT-list extension it
    # then strips back out. The log signs the TBS as it stands before the
    # extension exists; the CA re-issues the same certificate with the
    # SCT added; stripping it must reproduce the signed bytes exactly,
    # which holds because every other field is identical and the
    # extension is appended last.
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    padding_ext = x509.UnrecognizedExtension(
        PADDING_OID, der_octet_string(b"\x5A" * 70_000)
    )

    def leaf_builder():
        return (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(
                            NameOID.COMMON_NAME, "pkix-ct large precert leaf"
                        )
                    ]
                )
            )
            .issuer_name(issuer_dn)
            .public_key(leaf_key.public_key())
            .serial_number(0x4E)
            .not_valid_before(NOT_BEFORE)
            .not_valid_after(NOT_AFTER)
            .add_extension(padding_ext, critical=False)
        )

    pre_sct_leaf = leaf_builder().sign(issuer_key, hashes.SHA256())
    tbs_no_sct = pre_sct_leaf.tbs_certificate_bytes
    assert len(tbs_no_sct) > 0xFFFF, f"TBS is {len(tbs_no_sct)} bytes, need > 65535"
    assert (len(tbs_no_sct) >> 16) & 0xFF != 0, "the TBS top length octet must be non-zero"

    precert_signed_input = build_signed_input_precert_entry(
        TIMESTAMP_MS, issuer_key_hash, tbs_no_sct, extensions
    )
    precert_signature = log_key.sign(precert_signed_input, ec.ECDSA(hashes.SHA256()))
    precert_sct_wire = build_sct_wire(
        log_id,
        TIMESTAMP_MS,
        extensions,
        HASH_ALG_SHA256,
        SIG_ALG_ECDSA,
        precert_signature,
    )
    log_key.public_key().verify(
        precert_signature, precert_signed_input, ec.ECDSA(hashes.SHA256())
    )

    final_leaf = (
        leaf_builder()
        .add_extension(
            x509.UnrecognizedExtension(
                OID_SCT_LIST, encode_sct_list_extension_value([precert_sct_wire])
            ),
            critical=False,
        )
        .sign(issuer_key, hashes.SHA256())
    )
    leaf_der = final_leaf.public_bytes(serialization.Encoding.DER)
    # The invariant the verifier depends on: the final certificate's TBS
    # minus the SCT list is the TBS that was signed.
    assert len(final_leaf.tbs_certificate_bytes) > len(tbs_no_sct), "the SCT list was added"

    for name, data in (
        ("precert-issuer.der", issuer_der),
        ("precert-leaf.der", leaf_der),
        ("precert-sct.bin", precert_sct_wire),
        ("precert-signed-input.bin", precert_signed_input),
        ("precert-issuer-key-hash.bin", issuer_key_hash),
    ):
        (HERE / name).write_bytes(data)
        print(f"wrote {name} ({len(data)} bytes)")
    print(
        f"precert TBS is {len(tbs_no_sct)} bytes; u24 top octet = "
        f"{(len(tbs_no_sct) >> 16) & 0xFF}"
    )

    (HERE / "meta.json").write_text(
        json.dumps(
            {
                "cert_len": len(cert_der),
                "cert_len_u24_top_octet": (len(cert_der) >> 16) & 0xFF,
                "timestamp_ms": TIMESTAMP_MS,
                "log_id_hex": log_id.hex(),
                "signed_input_len": len(signed_input),
                "precert_tbs_len": len(tbs_no_sct),
                "precert_tbs_u24_top_octet": (len(tbs_no_sct) >> 16) & 0xFF,
            },
            indent=2,
        )
        + "\n"
    )
    print(
        f"cert is {len(cert_der)} bytes; u24 top octet = "
        f"{(len(cert_der) >> 16) & 0xFF}"
    )


if __name__ == "__main__":
    main()
