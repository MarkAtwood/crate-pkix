#!/usr/bin/env python3
"""Generate trust-anchor fixtures with malformed NameConstraints extensions.

Oracle: pyca/cryptography (external to the Rust code under test).
Run once; output is committed as binary fixtures.

The generated certs:

  - anchor-malformed-nc.der: a self-signed CA cert whose NameConstraints
    extension (OID 2.5.29.30, critical=True) has an extnValue of four bytes
    0xFF 0xFE 0x00 0x01 — not a valid SEQUENCE, so any DER decoder
    attempting to parse it as NameConstraints will fail.

  - anchor-good-nc.der: a self-signed CA cert with a well-formed
    NameConstraints extension (permittedSubtrees = .example.com). Used as a
    positive control: pkix-truststore must accept this anchor cleanly.

These fixtures exercise the PKIX-tit4.1 fix: trust-anchor loaders now decode
via TrustAnchor::try_from rather than TrustAnchor::from_cert, so a malformed
critical NameConstraints extension produces Error::Der / Error::MalformedAnchor
rather than silently dropping the constraint at validation time.
"""

import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
UTC = datetime.timezone.utc

NOT_BEFORE = datetime.datetime(2026, 1, 1, tzinfo=UTC)
NOT_AFTER = datetime.datetime(2036, 1, 1, tzinfo=UTC)


def write(name: str, data: bytes) -> None:
    path = os.path.join(FIXTURES, name)
    with open(path, "wb") as f:
        f.write(data)
    print(f"{name}: {len(data)} bytes")


def write_der_and_pem(stem: str, der: bytes) -> None:
    write(f"{stem}.der", der)
    # PEM encoding is performed by pyca/cryptography (external to pkix-truststore).
    cert = x509.load_der_x509_certificate(der)
    pem = cert.public_bytes(serialization.Encoding.PEM)
    write(f"{stem}.pem", pem)


def build_ca(name_cn: str, nc_ext: x509.Extension, *, nc_critical: bool) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name_cn)])
    builder = (
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
        .add_extension(nc_ext.value, critical=nc_critical)
    )
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


# ---------------------------------------------------------------------------
# Malformed NameConstraints: four garbage bytes where a SEQUENCE is required.
# ---------------------------------------------------------------------------
NC_OID = x509.ObjectIdentifier("2.5.29.30")
GARBAGE_NC_VALUE = b"\xff\xfe\x00\x01"
malformed_nc = x509.Extension(
    oid=NC_OID,
    critical=True,
    value=x509.UnrecognizedExtension(NC_OID, GARBAGE_NC_VALUE),
)
write_der_and_pem("anchor-malformed-nc", build_ca(
    "Test Malformed NC Anchor", malformed_nc, nc_critical=True,
))

# ---------------------------------------------------------------------------
# Well-formed NameConstraints (positive control): permittedSubtrees=.example.com
# ---------------------------------------------------------------------------
good_nc = x509.Extension(
    oid=NC_OID,
    critical=True,
    value=x509.NameConstraints(
        permitted_subtrees=[x509.DNSName(".example.com")],
        excluded_subtrees=None,
    ),
)
write_der_and_pem("anchor-good-nc", build_ca(
    "Test Good NC Anchor", good_nc, nc_critical=True,
))

print("Done.")
