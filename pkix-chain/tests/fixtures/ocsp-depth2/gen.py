#!/usr/bin/env python3
"""
Generate a depth-2 delegated OCSP responder chain for
`pkix-chain/tests/ocsp_responder_shim_depth.rs`.

WHY THIS IS SELF-CONTAINED
--------------------------
`../gen.py` regenerates every fixture in the parent directory from a fresh
random key on each run, so adding certificates there would rewrite files
that dozens of unrelated tests pin. This script writes only into its own
directory.

WHY A DEPTH-2 CHAIN
-------------------
`verify_ocsp_responder` wraps the caller's `RevocationChecker` in a shim
that skips the check for `chain[0]` when that certificate carries
`id-pkix-ocsp-nocheck` (RFC 6960 §4.2.2.2.1). The existing tests use a
single-certificate chain, which reaches the shim's
`check_revocation_against_anchor` only -- its `check_revocation` is never
called, so nothing proved that the shim still consults the caller for the
certificates it is not meant to bypass.

A three-certificate chain [responder, ca2, ca1] under `root` splits the
two methods: the responder and ca2 go through `check_revocation`, ca1
through `check_revocation_against_anchor`.

THE DELIBERATE SERIAL COLLISION
-------------------------------
`ca2` and both responder variants share serial 0x7777. Serial numbers are
unique per issuer, not globally (RFC 5280 §4.1.2.2), so this is
conformant -- and it is what distinguishes a shim that identifies the
bypassed certificate by issuer AND serial from one that accepts either.
With the conjunction weakened to a disjunction, ca2 is bypassed too, and
a revoked intermediate in a responder chain goes unreported.

Oracle: pyca/cryptography. The Rust verifier never participates.

Run from this directory:

    /home/mark/PROJECT/PKIX/pkix-difftest/python/.venv/bin/python3 gen.py
"""

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

# RFC 6960 §4.2.2.2.1 id-pkix-ocsp-nocheck.
OID_OCSP_NO_CHECK = ObjectIdentifier("1.3.6.1.5.5.7.48.1.5")

NOT_BEFORE = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
NOT_AFTER = datetime.datetime(2050, 1, 1, tzinfo=datetime.timezone.utc)

# ca2 and the responders share this on purpose. See the module docstring.
SHARED_SERIAL = 0x7777


def name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def ca_cert(subject_cn, serial, path_length, issuer_key, issuer_name, subject_key=None):
    key = subject_key or ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(name(subject_cn))
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(issuer_key, hashes.SHA256())
    )
    return key, cert


def responder_cert(serial, issuer_key, issuer_name, *, nocheck):
    key = ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateBuilder()
        .subject_name(name("OCSP Depth Responder"))
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), critical=False
        )
    )
    if nocheck:
        # id-pkix-ocsp-nocheck's value is an ASN.1 NULL (DER 05 00).
        builder = builder.add_extension(
            x509.UnrecognizedExtension(OID_OCSP_NO_CHECK, b"\x05\x00"),
            critical=False,
        )
    return key, builder.sign(issuer_key, hashes.SHA256())


def write(fname, cert):
    path = Path(__file__).resolve().parent / fname
    path.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    print(f"wrote {path.name} ({path.stat().st_size} bytes)")


def main():
    root_key = ec.generate_private_key(ec.SECP256R1())
    _, root = ca_cert(
        "OCSP Depth Root",
        0x7001,
        None,
        root_key,
        name("OCSP Depth Root"),
        subject_key=root_key,
    )
    ca1_key, ca1 = ca_cert("OCSP Depth CA1", 0x7002, 1, root_key, root.subject)
    ca2_key, ca2 = ca_cert("OCSP Depth CA2", SHARED_SERIAL, 0, ca1_key, ca1.subject)

    _, resp_nocheck = responder_cert(
        SHARED_SERIAL, ca2_key, ca2.subject, nocheck=True
    )
    _, resp_plain = responder_cert(SHARED_SERIAL, ca2_key, ca2.subject, nocheck=False)

    write("root.der", root)
    write("ca1.der", ca1)
    write("ca2.der", ca2)
    write("responder-nocheck.der", resp_nocheck)
    write("responder.der", resp_plain)


if __name__ == "__main__":
    main()
