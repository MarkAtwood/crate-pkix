#!/usr/bin/env python3
"""Generate a CRL fixture with a present-but-malformed IssuingDistributionPoint extension.

Oracle: pyca/cryptography (external to the Rust code under test).
Run once; output is committed as a binary fixture.

The generated CRL:
  - Has a valid issuer, validity window, and signature (produced by a fresh CA key).
  - Contains the IssuingDistributionPoint extension (OID 2.5.29.28, critical=True)
    with an extnValue that is not valid DER for IssuingDistributionPoint: four bytes
    0xFF 0xFE 0x00 0x01, which cannot be parsed as the SEQUENCE required by
    RFC 5280 §5.2.5.
  - Is accompanied by the CA certificate (crl-malformed-idp-ca.der) needed to
    pass signature verification so that check_revocation reaches the IDP parse step.

This fixture exercises the error path in parse_issuing_dp() — specifically that a
present-but-unparseable IDP returns Err(Error::CrlParseError) rather than silently
returning None (the old fail-open behaviour fixed in PKIX-fy1b.3).
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
NOT_AFTER  = datetime.datetime(2030, 1, 1, tzinfo=UTC)
THIS_2026  = datetime.datetime(2026, 1, 1, tzinfo=UTC)
NEXT_2027  = datetime.datetime(2027, 1, 1, tzinfo=UTC)


def write(name: str, data: bytes) -> None:
    path = os.path.join(FIXTURES, name)
    with open(path, "wb") as f:
        f.write(data)
    print(f"{name}: {len(data)} bytes")


# ---------------------------------------------------------------------------
# Fresh CA key + certificate (dedicated to this fixture set)
# ---------------------------------------------------------------------------
ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Malformed IDP CRL CA")])

ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_name)
    .issuer_name(ca_name)
    .public_key(ca_key.public_key())
    .serial_number(300)
    .not_valid_before(NOT_BEFORE)
    .not_valid_after(NOT_AFTER)
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .add_extension(
        x509.KeyUsage(
            digital_signature=True,
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
    .sign(ca_key, hashes.SHA256())
)
write("crl-malformed-idp-ca.der", ca_cert.public_bytes(serialization.Encoding.DER))

# Leaf cert (serial=1, not revoked) — needed to call check_revocation.
leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
leaf_cert = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Malformed IDP Leaf")]))
    .issuer_name(ca_name)
    .public_key(leaf_key.public_key())
    .serial_number(1)
    .not_valid_before(NOT_BEFORE)
    .not_valid_after(NOT_AFTER)
    .sign(ca_key, hashes.SHA256())
)
write("crl-malformed-idp-leaf.der", leaf_cert.public_bytes(serialization.Encoding.DER))

# ---------------------------------------------------------------------------
# CRL with malformed IssuingDistributionPoint extension value
#
# The extnValue bytes 0xFF 0xFE 0x00 0x01 are not a valid SEQUENCE, so any
# DER decoder attempting to parse them as IssuingDistributionPoint will fail.
# The extension is marked critical=True (matching the MUST-critical requirement
# in RFC 5280 §5.2.5), though the CrlChecker does not enforce criticality — the
# important thing is that the value is unparseable.
# ---------------------------------------------------------------------------
IDP_OID = x509.ObjectIdentifier("2.5.29.28")
# Four garbage bytes: 0xFF starts an invalid tag, making this unparseable as any
# standard ASN.1 SEQUENCE.
GARBAGE_VALUE = b"\xff\xfe\x00\x01"

malformed_idp_ext = x509.UnrecognizedExtension(IDP_OID, GARBAGE_VALUE)

crl = (
    x509.CertificateRevocationListBuilder()
    .issuer_name(ca_name)
    .last_update(THIS_2026)
    .next_update(NEXT_2027)
    .add_extension(malformed_idp_ext, critical=True)
    .sign(ca_key, hashes.SHA256())
)
write("crl-malformed-idp.der", crl.public_bytes(serialization.Encoding.DER))

print("Done.")
