#!/usr/bin/env python3
"""Generate an indirect CRL fixture with a per-entry `certificateIssuer`
extension (RFC 5280 §5.3.3) for PKIX-8zxm.

Topology:
  - Two distinct CAs (CA-A and CA-B), self-signed.
  - One cRLIssuer cert (separate from both CAs), signed by CA-A.
  - An indirect CRL signed by cRLIssuer that contains:
    * one revoked entry for a cert from CA-A (effective issuer defaults to
      the CRL's own issuer = cRLIssuer.subject — which is wrong, but tests
      that the FALLBACK to CRL.issuer happens when no certificateIssuer
      extension is present);
    * one revoked entry for a cert from CA-B with `certificateIssuer`
      extension pointing at CA-B's subject DN.

Tests exercise:
  - "cert under CA-A, serial=1" against this CRL → not revoked, because the
    CRL's first entry's effective issuer is cRLIssuer.subject (≠ CA-A).
  - "cert under CA-B, serial=2" against this CRL → revoked, via the
    certificateIssuer extension.

Oracle: pyca/cryptography (external to the Rust code under test).
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
NOT_AFTER = datetime.datetime(2030, 1, 1, tzinfo=UTC)
THIS_UPDATE = datetime.datetime(2026, 1, 1, tzinfo=UTC)
NEXT_UPDATE = datetime.datetime(2027, 1, 1, tzinfo=UTC)
REVOKE_TIME = datetime.datetime(2026, 1, 1, tzinfo=UTC)


def gen_rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def write(name: str, data: bytes) -> None:
    path = os.path.join(FIXTURES, name)
    with open(path, "wb") as f:
        f.write(data)
    print(f"{name}: {len(data)} bytes")


def make_self_signed_ca(cn: str, key) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(100)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
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
        .sign(key, hashes.SHA256())
    )


def make_leaf(cn: str, serial: int, ca_name: x509.Name, ca_key) -> x509.Certificate:
    leaf_key = gen_rsa()
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(serial)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .sign(ca_key, hashes.SHA256())
    )


def make_crl_issuer_cert(cn: str, ca_name: x509.Name, ca_key) -> tuple[x509.Certificate, object]:
    key = gen_rsa()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(200)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return cert, key


# ===========================================================================
# Generate
# ===========================================================================
ca_a_key = gen_rsa()
ca_a = make_self_signed_ca("Indirect Per-Entry Test CA-A", ca_a_key)
write("indirect-per-entry-ca-a.der", ca_a.public_bytes(serialization.Encoding.DER))

ca_b_key = gen_rsa()
ca_b = make_self_signed_ca("Indirect Per-Entry Test CA-B", ca_b_key)
write("indirect-per-entry-ca-b.der", ca_b.public_bytes(serialization.Encoding.DER))

# cRLIssuer is signed by CA-A (the bd issue requires the cRLIssuer to chain
# back to a trusted anchor, but that validation is the caller's job in
# pkix-revocation; here we just ensure the cert is well-formed).
crl_issuer_cert, crl_issuer_key = make_crl_issuer_cert(
    "Indirect Per-Entry Test cRLIssuer", ca_a.subject, ca_a_key
)
write(
    "indirect-per-entry-crl-issuer.der",
    crl_issuer_cert.public_bytes(serialization.Encoding.DER),
)

# Leaves: one under CA-A (serial=1), one under CA-B (serial=2).
leaf_a = make_leaf("CA-A Leaf", 1, ca_a.subject, ca_a_key)
write("indirect-per-entry-leaf-a.der", leaf_a.public_bytes(serialization.Encoding.DER))

leaf_b = make_leaf("CA-B Leaf", 2, ca_b.subject, ca_b_key)
write("indirect-per-entry-leaf-b.der", leaf_b.public_bytes(serialization.Encoding.DER))

# Build the indirect CRL signed by cRLIssuer.
#
# Entries:
#   serial=99  — does NOT have certificateIssuer; effective issuer defaults
#                to the CRL's own issuer (cRLIssuer.subject). This entry
#                will not match either leaf — neither leaf has issuer DN
#                equal to cRLIssuer.subject.
#   serial=2   — HAS certificateIssuer pointing at CA-B's subject. This
#                entry should match leaf_b (CA-B, serial=2).
revoked_no_ce = (
    x509.RevokedCertificateBuilder()
    .serial_number(99)
    .revocation_date(REVOKE_TIME)
    .build()
)
revoked_with_ce = (
    x509.RevokedCertificateBuilder()
    .serial_number(2)
    .revocation_date(REVOKE_TIME)
    .add_extension(
        x509.CertificateIssuer([x509.DirectoryName(ca_b.subject)]),
        critical=True,
    )
    .build()
)

crl_builder = (
    x509.CertificateRevocationListBuilder()
    .issuer_name(crl_issuer_cert.subject)
    .last_update(THIS_UPDATE)
    .next_update(NEXT_UPDATE)
    .add_revoked_certificate(revoked_no_ce)
    .add_revoked_certificate(revoked_with_ce)
    .add_extension(
        x509.IssuingDistributionPoint(
            full_name=None,
            relative_name=None,
            only_contains_user_certs=False,
            only_contains_ca_certs=False,
            only_some_reasons=None,
            indirect_crl=True,
            only_contains_attribute_certs=False,
        ),
        critical=True,
    )
    .add_extension(x509.CRLNumber(1), critical=False)
)
crl = crl_builder.sign(crl_issuer_key, hashes.SHA256())
write("indirect-per-entry-crl.der", crl.public_bytes(serialization.Encoding.DER))
