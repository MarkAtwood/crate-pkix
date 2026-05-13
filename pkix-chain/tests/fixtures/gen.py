#!/usr/bin/env python3
"""
Generate DER fixtures for pkix-chain verify_tls_server integration tests.

Each test wants both a valid chain AND a leaf with (or without) a SAN
matching the target identity. pkix-identity's own fixtures are
self-signed, which is fine for that crate's pure-identity tests but
won't pass `verify_chain` here. So we generate a small two-cert chain:

  - root.der: self-signed CA (BasicConstraints CA=true, keyCertSign)
  - leaf-san-www-example.der: EE signed by root, SAN=DNS:www.example.com
  - leaf-no-san.der:          EE signed by root, no SAN extension

Validity 2000-01-01 to 2050-01-01. P-256 ECDSA throughout (matches
DefaultVerifier's P-256 support).

Oracle: pyca/cryptography. The Rust verifier under test never
participates in fixture creation.

Run from this directory:

    /home/mark/PROJECT/PKIX/pkix-difftest/python/.venv/bin/python3 gen.py

(or any other Python environment with cryptography installed).
"""

import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

OUT = Path(__file__).parent
NOT_BEFORE = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
NOT_AFTER = datetime.datetime(2050, 1, 1, tzinfo=datetime.timezone.utc)


def build_root():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pkix-chain test root")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
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
        .sign(key, hashes.SHA256())
    )
    return key, cert


def build_leaf(root_key, root_cert, *, sans, serial):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pkix-chain test leaf")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
    )
    if sans is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(sans),
            critical=False,
        )
    return builder.sign(root_key, hashes.SHA256())


def write_der(name, cert):
    path = OUT / name
    path.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    print(f"wrote {path.relative_to(OUT.parent.parent)}")


def main():
    root_key, root_cert = build_root()
    write_der("root.der", root_cert)

    leaf_san = build_leaf(
        root_key, root_cert,
        sans=[x509.DNSName("www.example.com")],
        serial=2,
    )
    write_der("leaf-san-www-example.der", leaf_san)

    leaf_no_san = build_leaf(
        root_key, root_cert,
        sans=None,
        serial=3,
    )
    write_der("leaf-no-san.der", leaf_no_san)


if __name__ == "__main__":
    main()
