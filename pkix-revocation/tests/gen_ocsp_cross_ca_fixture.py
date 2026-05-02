#!/usr/bin/env python3
"""Generate cross-CA OCSP replay test fixtures for PKIX-8sh.4.

Scenario: CA-A and CA-B are independent CAs. CA-A's OCSP response for
serial=1 is signed by CA-A's key. CA-B also issues a leaf with serial=1.
Without issuer-hash verification an attacker could present CA-A's "good"
response for CA-B's serial=1 cert (same serial, valid signature from CA-A).
With issuer-hash verification the mismatch on issuerNameHash / issuerKeyHash
must be detected.

Outputs (in tests/fixtures/):
  ocsp-ca-a.der       — CA-A cert (RSA-2048, CN=OCSP CA-A, serial=100)
  ocsp-ca-b.der       — CA-B cert (RSA-2048, CN=OCSP CA-B, serial=100)
  ocsp-ca-a-leaf.der  — leaf issued by CA-A, serial=1
  ocsp-ca-b-leaf.der  — leaf issued by CA-B, serial=1
  ocsp-ca-a-good.der  — OCSP "good" response for CA-A / serial=1,
                         signed by CA-A's key (issuerNameHash and
                         issuerKeyHash are computed from CA-A)

Oracle: pyca/cryptography.
Run once; outputs committed as binary fixtures. Tests fully offline.
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

NOT_BEFORE  = datetime.datetime(2026, 1, 1, tzinfo=UTC)
NOT_AFTER   = datetime.datetime(2030, 1, 1, tzinfo=UTC)
PRODUCED_AT = datetime.datetime(2026, 1, 1, tzinfo=UTC)
NEXT_UPDATE = datetime.datetime(2027, 1, 1, tzinfo=UTC)


def gen_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def write(name: str, data: bytes) -> None:
    path = os.path.join(FIXTURES, name)
    with open(path, "wb") as f:
        f.write(data)
    print(f"{name}: {len(data)} bytes")


def make_ca(cn: str, key) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(100)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )


def make_leaf(serial: int, cn: str, issuer_cert, issuer_key) -> x509.Certificate:
    key = gen_rsa_key()
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .sign(issuer_key, hashes.SHA256())
    )


ca_a_key = gen_rsa_key()
ca_b_key = gen_rsa_key()

ca_a = make_ca("OCSP CA-A", ca_a_key)
ca_b = make_ca("OCSP CA-B", ca_b_key)

write("ocsp-ca-a.der", ca_a.public_bytes(serialization.Encoding.DER))
write("ocsp-ca-b.der", ca_b.public_bytes(serialization.Encoding.DER))

ca_a_leaf = make_leaf(1, "CA-A Leaf", ca_a, ca_a_key)
ca_b_leaf = make_leaf(1, "CA-B Leaf", ca_b, ca_b_key)

write("ocsp-ca-a-leaf.der", ca_a_leaf.public_bytes(serialization.Encoding.DER))
write("ocsp-ca-b-leaf.der", ca_b_leaf.public_bytes(serialization.Encoding.DER))

# OCSP "good" for CA-A/serial=1 — issuerNameHash and issuerKeyHash are for CA-A
response_der = (
    ocsp.OCSPResponseBuilder()
    .add_response(
        cert=ca_a_leaf,
        issuer=ca_a,
        algorithm=hashes.SHA256(),
        cert_status=ocsp.OCSPCertStatus.GOOD,
        this_update=PRODUCED_AT,
        next_update=NEXT_UPDATE,
        revocation_time=None,
        revocation_reason=None,
    )
    .responder_id(ocsp.OCSPResponderEncoding.NAME, ca_a)
    .sign(ca_a_key, hashes.SHA256())
    .public_bytes(serialization.Encoding.DER)
)
write("ocsp-ca-a-good.der", response_der)

print("Done. Commit the new fixtures in tests/fixtures/.")
