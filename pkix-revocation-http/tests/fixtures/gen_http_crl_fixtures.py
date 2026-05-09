#!/usr/bin/env python3
"""Generate DER fixtures for HttpCrlFetcher / HttpOcspFetcher tests.

Oracle: pyca/cryptography (external to the Rust code under test). Mirrors
the gen_*.py scripts in pkix-revocation/tests/. Run once; outputs are
committed as binary fixtures and consumed offline by the test suite.

Outputs:
    http-ca.der                — RSA-2048 self-signed CA
    http-leaf-good.der         — leaf serial=1, CDP=http://crl.example.com/test.crl,
                                 OCSP=http://ocsp.example.com/
    http-leaf-revoked.der      — leaf serial=2, same CDP+OCSP extensions
    http-leaf-no-cdp.der       — leaf serial=3, NO CDP/AIA at all
    http-crl-revokes-2.der     — CRL listing serial=2 revoked
    http-crl-empty.der         — CRL with no revoked entries
"""

import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtensionOID,
    NameOID,
)

FIXTURES = os.path.dirname(os.path.abspath(__file__))
UTC = datetime.timezone.utc

NOT_BEFORE = datetime.datetime(2026, 1, 1, tzinfo=UTC)
NOT_AFTER = datetime.datetime(2126, 1, 1, tzinfo=UTC)
CRL_THIS = datetime.datetime(2026, 1, 1, tzinfo=UTC)
CRL_NEXT = datetime.datetime(2027, 1, 1, tzinfo=UTC)


def write(name: str, data: bytes) -> None:
    path = os.path.join(FIXTURES, name)
    with open(path, "wb") as f:
        f.write(data)
    print(f"{name}: {len(data)} bytes")


def gen_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


# ----- CA -----
ca_key = gen_rsa_key()
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test HTTP CRL CA")])
ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_name)
    .issuer_name(ca_name)
    .public_key(ca_key.public_key())
    .serial_number(100)
    .not_valid_before(NOT_BEFORE)
    .not_valid_after(NOT_AFTER)
    .add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
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
    .sign(ca_key, hashes.SHA256())
)
write("http-ca.der", ca_cert.public_bytes(serialization.Encoding.DER))


def make_leaf(*, serial: int, common_name: str, with_extensions: bool):
    """Build and sign a leaf cert.

    `with_extensions=True` adds CDP (HTTP CRL URL) and AIA (OCSP responder).
    These extensions are what HttpCrlFetcher / HttpOcspFetcher operate on.
    """
    leaf_key = gen_rsa_key()
    builder = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        )
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(serial)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
    )
    if with_extensions:
        builder = builder.add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[
                            x509.UniformResourceIdentifier(
                                "http://crl.example.com/test.crl"
                            )
                        ],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )
        builder = builder.add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier(
                            "http://ocsp.example.com/"
                        ),
                    )
                ]
            ),
            critical=False,
        )
    return builder.sign(ca_key, hashes.SHA256())


leaf_good = make_leaf(serial=1, common_name="Test HTTP Leaf Good", with_extensions=True)
write("http-leaf-good.der", leaf_good.public_bytes(serialization.Encoding.DER))

leaf_revoked = make_leaf(serial=2, common_name="Test HTTP Leaf Revoked", with_extensions=True)
write("http-leaf-revoked.der", leaf_revoked.public_bytes(serialization.Encoding.DER))

leaf_no_cdp = make_leaf(serial=3, common_name="Test HTTP Leaf No CDP", with_extensions=False)
write("http-leaf-no-cdp.der", leaf_no_cdp.public_bytes(serialization.Encoding.DER))


# ----- CRLs -----
def build_crl(*, revoked_serials: list[int]):
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_name)
        .last_update(CRL_THIS)
        .next_update(CRL_NEXT)
    )
    for s in revoked_serials:
        rc = (
            x509.RevokedCertificateBuilder()
            .serial_number(s)
            .revocation_date(CRL_THIS)
            .build()
        )
        builder = builder.add_revoked_certificate(rc)
    return builder.sign(ca_key, hashes.SHA256())


crl_revokes_2 = build_crl(revoked_serials=[2])
write("http-crl-revokes-2.der", crl_revokes_2.public_bytes(serialization.Encoding.DER))

crl_empty = build_crl(revoked_serials=[])
write("http-crl-empty.der", crl_empty.public_bytes(serialization.Encoding.DER))


# ----- OCSP responses (for PKIX-a1yc.6) -----
# Build a basic OCSP response signed directly by the CA. status=good for
# leaf-good (serial=1); status=revoked for leaf-revoked (serial=2).
from cryptography.x509 import ocsp

PRODUCED_AT = datetime.datetime(2026, 6, 1, tzinfo=UTC)
THIS_UPDATE = datetime.datetime(2026, 6, 1, tzinfo=UTC)
NEXT_UPDATE = datetime.datetime(2026, 7, 1, tzinfo=UTC)


def build_ocsp_response(*, leaf_cert, status):
    builder = ocsp.OCSPResponseBuilder()
    builder = builder.add_response(
        cert=leaf_cert,
        issuer=ca_cert,
        algorithm=hashes.SHA256(),
        cert_status=status,
        this_update=THIS_UPDATE,
        next_update=NEXT_UPDATE,
        revocation_time=THIS_UPDATE if isinstance(status, ocsp.OCSPCertStatus) and status == ocsp.OCSPCertStatus.REVOKED else None,
        revocation_reason=None,
    ).responder_id(ocsp.OCSPResponderEncoding.HASH, ca_cert)
    return builder.sign(ca_key, hashes.SHA256())


ocsp_good = build_ocsp_response(
    leaf_cert=leaf_good, status=ocsp.OCSPCertStatus.GOOD
)
write("http-ocsp-good.der", ocsp_good.public_bytes(serialization.Encoding.DER))

# Revoked needs a different builder shape: the helper above conflates good
# and revoked. Redo with explicit revocation_time for the revoked case.
revoked_builder = ocsp.OCSPResponseBuilder()
revoked_builder = revoked_builder.add_response(
    cert=leaf_revoked,
    issuer=ca_cert,
    algorithm=hashes.SHA256(),
    cert_status=ocsp.OCSPCertStatus.REVOKED,
    this_update=THIS_UPDATE,
    next_update=NEXT_UPDATE,
    revocation_time=THIS_UPDATE,
    revocation_reason=None,
).responder_id(ocsp.OCSPResponderEncoding.HASH, ca_cert)
ocsp_revoked = revoked_builder.sign(ca_key, hashes.SHA256())
write("http-ocsp-revoked.der", ocsp_revoked.public_bytes(serialization.Encoding.DER))
