#!/usr/bin/env python3
"""Generate DER-encoded CRL test fixtures for pkix-revocation.

Oracle: pyca/cryptography (external to the Rust code under test).
Run once; outputs are committed as binary fixtures.
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


def gen_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def write(name: str, data: bytes) -> None:
    path = os.path.join(FIXTURES, name)
    with open(path, "wb") as f:
        f.write(data)
    print(f"{name}: {len(data)} bytes")


# ---------------------------------------------------------------------------
# CA key + certificate
# ---------------------------------------------------------------------------
ca_key = gen_rsa_key()

ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CRL CA")])

ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_name)
    .issuer_name(ca_name)
    .public_key(ca_key.public_key())
    .serial_number(100)
    .not_valid_before(NOT_BEFORE)
    .not_valid_after(NOT_AFTER)
    .add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    )
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
    .add_extension(
        x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
        critical=False,
    )
    .sign(ca_key, hashes.SHA256())
)

write("crl-ca.der", ca_cert.public_bytes(serialization.Encoding.DER))

# ---------------------------------------------------------------------------
# Leaf certificates
# ---------------------------------------------------------------------------
def make_leaf(serial: int, cn: str) -> bytes:
    key = gen_rsa_key()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .sign(ca_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


write("crl-leaf-good.der",    make_leaf(1, "Good Leaf"))
write("crl-leaf-revoked.der", make_leaf(2, "Revoked Leaf"))

# ---------------------------------------------------------------------------
# Helper: build a CRL
# ---------------------------------------------------------------------------
def make_crl(
    this_update: datetime.datetime,
    next_update: datetime.datetime,
    revoked: list,          # list of RevokedCertificate objects
) -> bytes:
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_name)
        .last_update(this_update)
        .next_update(next_update)
    )
    for r in revoked:
        builder = builder.add_revoked_certificate(r)
    crl = builder.sign(ca_key, hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.DER)


THIS_2026 = datetime.datetime(2026, 1, 1, tzinfo=UTC)
NEXT_2027 = datetime.datetime(2027, 1, 1, tzinfo=UTC)
THIS_2020 = datetime.datetime(2020, 1, 1, tzinfo=UTC)
NEXT_2021 = datetime.datetime(2021, 1, 1, tzinfo=UTC)
REVOKE_DATE = datetime.datetime(2026, 1, 1, tzinfo=UTC)

# crl-empty.der — no revocations
write("crl-empty.der", make_crl(THIS_2026, NEXT_2027, []))

# crl-with-revocation.der — serial 2 revoked, no reason code
revoked_no_reason = (
    x509.RevokedCertificateBuilder()
    .serial_number(2)
    .revocation_date(REVOKE_DATE)
    .build()
)
write("crl-with-revocation.der", make_crl(THIS_2026, NEXT_2027, [revoked_no_reason]))

# crl-with-reason.der — serial 2 revoked, CRLReason = keyCompromise (1)
revoked_with_reason = (
    x509.RevokedCertificateBuilder()
    .serial_number(2)
    .revocation_date(REVOKE_DATE)
    .add_extension(
        x509.CRLReason(x509.ReasonFlags.key_compromise),
        critical=False,
    )
    .build()
)
write("crl-with-reason.der", make_crl(THIS_2026, NEXT_2027, [revoked_with_reason]))

# crl-expired.der — thisUpdate=2020-01-01, nextUpdate=2021-01-01
write("crl-expired.der", make_crl(THIS_2020, NEXT_2021, []))

# crl-bad-sig.der — last byte of crl-empty.der XOR'd with 0xFF
empty_der = make_crl(THIS_2026, NEXT_2027, [])
bad_sig = bytearray(empty_der)
bad_sig[-1] ^= 0xFF
write("crl-bad-sig.der", bytes(bad_sig))
