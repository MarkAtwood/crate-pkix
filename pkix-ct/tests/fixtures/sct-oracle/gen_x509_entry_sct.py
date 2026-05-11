#!/usr/bin/env python3
"""Generate a synthetic x509_entry SCT for offline pkix-ct verification tests.

This script is the *independent oracle*: it produces every byte that
pkix-ct will later verify. pkix-ct itself never participates in
producing these fixtures, so the verification test is genuinely
independent (oracle = pyca/cryptography + openssl wire-format encoding
hand-rolled from RFC 6962 §3.2).

The script is run once and its outputs are committed under this
directory:

  log-key.pem          PEM PKCS8 ECDSA P-256 private key (LOG signer)
  log-spki.der         DER SubjectPublicKeyInfo of the log
  log-id.bin           32-byte SHA-256(SPKI) = RFC 6962 log_id
  cert.der             DER of the certificate the SCT commits to
  sct.bin              The wire-format SignedCertificateTimestamp
                       (parseable by pkix_ct::SignedCertificateTimestamp::from_bytes)
  signed-input.bin     RFC 6962 §3.2 digitally-signed input (the bytes
                       that get hashed and signed). Committed for
                       independent inspection / cross-validation.
  meta.json            Decoded fields for human inspection / oracle.

The cert here is a generic CA-signed leaf-style cert. The SCT does NOT
need to be one a real CT log would issue (no chain validity rules at
the SCT signature layer); we only need:

  - a stable DER cert payload, and
  - a stable signing key with a known SPKI.

Re-running this script with the same `--seed` produces byte-identical
fixtures (modulo the cert's notBefore/notAfter, which we pin to a
fixed UTC instant).

Run with:

    python3 pkix-ct/tests/fixtures/sct-oracle/gen_x509_entry_sct.py

It prints the rust-friendly hex constants for the integration test
on stdout.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import secrets
import struct
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

# RFC 6962 §3.2 constants.
SCT_VERSION_V1 = 0
SIG_TYPE_CERTIFICATE_TIMESTAMP = 0
ENTRY_TYPE_X509 = 0

# RFC 5246 §7.4.1.4.1 tags. Log uses ECDSA-P256-SHA256, which is the
# RFC 6962 §2.1.4-recommended combo, so:
#   hash_alg = 4 (SHA-256)
#   sig_alg  = 3 (ECDSA)
HASH_ALG_SHA256 = 4
SIG_ALG_ECDSA = 3


def u8(v: int) -> bytes:
    return struct.pack(">B", v)


def u16(v: int) -> bytes:
    return struct.pack(">H", v)


def u24(v: int) -> bytes:
    # No native struct format for u24; emit (top byte, lower 16 BE).
    if not 0 <= v <= 0xFFFFFF:
        raise ValueError(f"u24 out of range: {v}")
    return bytes([(v >> 16) & 0xFF]) + u16(v & 0xFFFF)


def u64(v: int) -> bytes:
    return struct.pack(">Q", v)


def build_signed_input_x509_entry(
    timestamp_ms: int, cert_der: bytes, extensions: bytes
) -> bytes:
    """RFC 6962 §3.2 `digitally-signed` input (x509_entry branch).

    Layout:
        u8        sct_version            (0)
        u8        signature_type         (0 = certificate_timestamp)
        u64 BE    timestamp
        u16 BE    entry_type             (0 = x509_entry)
        u24 + N   cert_der               (ASN.1Cert: opaque<1..2^24-1>)
        u16 + M   extensions
    """
    out = bytearray()
    out += u8(SCT_VERSION_V1)
    out += u8(SIG_TYPE_CERTIFICATE_TIMESTAMP)
    out += u64(timestamp_ms)
    out += u16(ENTRY_TYPE_X509)
    out += u24(len(cert_der)) + cert_der
    out += u16(len(extensions)) + extensions
    return bytes(out)


def build_sct_wire(
    log_id: bytes,
    timestamp_ms: int,
    extensions: bytes,
    hash_alg: int,
    sig_alg: int,
    signature: bytes,
) -> bytes:
    """RFC 6962 §3.2 on-the-wire `SignedCertificateTimestamp`."""
    out = bytearray()
    out += u8(SCT_VERSION_V1)
    out += log_id  # 32 bytes
    out += u64(timestamp_ms)
    out += u16(len(extensions)) + extensions
    out += u8(hash_alg)
    out += u8(sig_alg)
    out += u16(len(signature)) + signature
    return bytes(out)


def make_cert(subject_cn: str, not_before: datetime.datetime) -> tuple[bytes, ec.EllipticCurvePrivateKey]:
    """Issue a self-signed P-256 cert with deterministic notBefore.

    The SCT we generate later does not need this cert's signature to be
    valid for any chain — the SCT layer is independent of cert
    validity. We use a self-signed cert to keep the fixture small and
    standalone.
    """
    subject_key = ec.generate_private_key(ec.SECP256R1())
    subj = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(subj)
        .public_key(subject_key.public_key())
        .serial_number(0x42)
        .not_valid_before(not_before)
        .not_valid_after(not_before + datetime.timedelta(days=365))
        .sign(subject_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER), subject_key


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path(__file__).parent,
        help="Where to write fixtures (defaults to this script's directory).",
    )
    parser.add_argument(
        "--regenerate",
        action="store_true",
        help="Regenerate even if fixtures already exist. Default refuses to overwrite.",
    )
    args = parser.parse_args()

    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    log_key_pem_path = out_dir / "log-key.pem"
    if log_key_pem_path.exists() and not args.regenerate:
        print(
            f"refusing to overwrite existing {log_key_pem_path}; "
            "pass --regenerate to rebuild fixtures",
            file=sys.stderr,
        )
        return 2

    # --- 1. Generate the LOG signing key (the CT log's identity).
    log_key = ec.generate_private_key(ec.SECP256R1())
    log_spki_der = log_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    log_id = hashlib.sha256(log_spki_der).digest()
    assert len(log_id) == 32

    # --- 2. Generate the cert the SCT commits to.
    fixed_not_before = datetime.datetime(2025, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc).replace(tzinfo=None)
    cert_der, _subject_key = make_cert("pkix-ct sct-oracle leaf", fixed_not_before)

    # --- 3. Pick a deterministic timestamp inside any plausible log window.
    # 2025-06-15T00:00:00Z = 1750032000000 ms.
    timestamp_ms = 1_750_032_000_000

    # --- 4. SCT extensions: empty in v1 deployments.
    extensions = b""

    # --- 5. Build the RFC 6962 §3.2 signed-input.
    signed_input = build_signed_input_x509_entry(timestamp_ms, cert_der, extensions)

    # --- 6. Sign with the log key (ECDSA-P256-SHA256, DER signature).
    signature = log_key.sign(signed_input, ec.ECDSA(hashes.SHA256()))

    # --- 7. Assemble the wire-format SCT.
    sct_wire = build_sct_wire(
        log_id=log_id,
        timestamp_ms=timestamp_ms,
        extensions=extensions,
        hash_alg=HASH_ALG_SHA256,
        sig_alg=SIG_ALG_ECDSA,
        signature=signature,
    )

    # --- 8. Write files.
    (out_dir / "log-key.pem").write_bytes(
        log_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    (out_dir / "log-spki.der").write_bytes(log_spki_der)
    (out_dir / "log-id.bin").write_bytes(log_id)
    (out_dir / "cert.der").write_bytes(cert_der)
    (out_dir / "sct.bin").write_bytes(sct_wire)
    (out_dir / "signed-input.bin").write_bytes(signed_input)

    meta = {
        "scheme": "RFC 6962 §3.2 x509_entry SCT, ECDSA-P256-SHA256",
        "log_id_hex": log_id.hex(),
        "timestamp_ms": timestamp_ms,
        "hash_alg": HASH_ALG_SHA256,
        "sig_alg": SIG_ALG_ECDSA,
        "extensions_len": len(extensions),
        "cert_len": len(cert_der),
        "signature_len": len(signature),
        "signed_input_len": len(signed_input),
        "sct_wire_len": len(sct_wire),
        "log_spki_len": len(log_spki_der),
        "oracle": "pyca/cryptography (ec.ECDSA(SHA256)) + hand-rolled RFC 6962 wire format",
    }
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")

    print("Wrote fixtures to", out_dir)
    print(json.dumps(meta, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
