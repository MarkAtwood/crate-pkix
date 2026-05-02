#!/usr/bin/env python3
"""Generate DER-encoded OCSP response test fixtures for pkix-revocation.

Oracle: pyca/cryptography (external to the Rust code under test).
Run once; outputs are committed as binary fixtures.

This script does NOT touch any existing CRL fixtures.
"""

import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
UTC = datetime.timezone.utc

NOT_BEFORE = datetime.datetime(2026, 1, 1, tzinfo=UTC)
NOT_AFTER  = datetime.datetime(2030, 1, 1, tzinfo=UTC)

PRODUCED_AT  = datetime.datetime(2026, 1, 1, tzinfo=UTC)
NEXT_UPDATE  = datetime.datetime(2027, 1, 1, tzinfo=UTC)
REVOKE_TIME  = datetime.datetime(2026, 1, 1, tzinfo=UTC)

PRODUCED_AT_EXPIRED = datetime.datetime(2020, 1, 1, tzinfo=UTC)
NEXT_UPDATE_EXPIRED = datetime.datetime(2021, 1, 1, tzinfo=UTC)


def gen_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def write(name: str, data: bytes) -> None:
    path = os.path.join(FIXTURES, name)
    with open(path, "wb") as f:
        f.write(data)
    print(f"{name}: {len(data)} bytes")


# ---------------------------------------------------------------------------
# CA key + certificate  (ocsp-ca.der)
# ---------------------------------------------------------------------------
ca_key = gen_rsa_key()

ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OCSP Test CA")])

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
            content_commitment=True,
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

write("ocsp-ca.der", ca_cert.public_bytes(serialization.Encoding.DER))

# ---------------------------------------------------------------------------
# Leaf certificates
# ---------------------------------------------------------------------------
def make_leaf(serial: int, cn: str) -> x509.Certificate:
    key = gen_rsa_key()
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .sign(ca_key, hashes.SHA256())
    )


leaf_good    = make_leaf(1, "OCSP Good Leaf")
leaf_revoked = make_leaf(2, "OCSP Revoked Leaf")

write("ocsp-leaf-good.der",    leaf_good.public_bytes(serialization.Encoding.DER))
write("ocsp-leaf-revoked.der", leaf_revoked.public_bytes(serialization.Encoding.DER))

# ---------------------------------------------------------------------------
# Helper: sign an OCSP response
# ---------------------------------------------------------------------------
def sign_ocsp(
    cert: x509.Certificate,
    cert_status: ocsp.OCSPCertStatus,
    produced_at: datetime.datetime,
    next_update: datetime.datetime,
    revocation_time=None,
    revocation_reason=None,
) -> bytes:
    builder = (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=cert,
            issuer=ca_cert,
            algorithm=hashes.SHA256(),
            cert_status=cert_status,
            this_update=produced_at,
            next_update=next_update,
            revocation_time=revocation_time,
            revocation_reason=revocation_reason,
        )
        .responder_id(ocsp.OCSPResponderEncoding.NAME, ca_cert)
    )
    response = builder.sign(ca_key, hashes.SHA256())
    return response.public_bytes(serialization.Encoding.DER)


# ---------------------------------------------------------------------------
# ocsp-good.der — certStatus=good for serial=1
# ---------------------------------------------------------------------------
good_der = sign_ocsp(
    cert=leaf_good,
    cert_status=ocsp.OCSPCertStatus.GOOD,
    produced_at=PRODUCED_AT,
    next_update=NEXT_UPDATE,
)
write("ocsp-good.der", good_der)

# ---------------------------------------------------------------------------
# ocsp-revoked.der — certStatus=revoked, reason=keyCompromise
# ---------------------------------------------------------------------------
write("ocsp-revoked.der", sign_ocsp(
    cert=leaf_revoked,
    cert_status=ocsp.OCSPCertStatus.REVOKED,
    produced_at=PRODUCED_AT,
    next_update=NEXT_UPDATE,
    revocation_time=REVOKE_TIME,
    revocation_reason=x509.ReasonFlags.key_compromise,
))

# ---------------------------------------------------------------------------
# ocsp-revoked-no-reason.der — certStatus=revoked, no reason extension
# ---------------------------------------------------------------------------
write("ocsp-revoked-no-reason.der", sign_ocsp(
    cert=leaf_revoked,
    cert_status=ocsp.OCSPCertStatus.REVOKED,
    produced_at=PRODUCED_AT,
    next_update=NEXT_UPDATE,
    revocation_time=REVOKE_TIME,
    revocation_reason=None,
))

# ---------------------------------------------------------------------------
# ocsp-unknown.der — certStatus=unknown for serial=1
# ---------------------------------------------------------------------------
write("ocsp-unknown.der", sign_ocsp(
    cert=leaf_good,
    cert_status=ocsp.OCSPCertStatus.UNKNOWN,
    produced_at=PRODUCED_AT,
    next_update=NEXT_UPDATE,
))

# ---------------------------------------------------------------------------
# ocsp-expired.der — good response with stale timestamps
# ---------------------------------------------------------------------------
write("ocsp-expired.der", sign_ocsp(
    cert=leaf_good,
    cert_status=ocsp.OCSPCertStatus.GOOD,
    produced_at=PRODUCED_AT_EXPIRED,
    next_update=NEXT_UPDATE_EXPIRED,
))

# ---------------------------------------------------------------------------
# ocsp-bad-sig.der — ocsp-good.der with last signature byte XOR'd 0xFF
# ---------------------------------------------------------------------------
bad_sig = bytearray(good_der)
bad_sig[-1] ^= 0xFF
write("ocsp-bad-sig.der", bytes(bad_sig))
