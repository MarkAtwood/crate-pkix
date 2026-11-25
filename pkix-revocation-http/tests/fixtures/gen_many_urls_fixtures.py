#!/usr/bin/env python3
"""Generate the many-distribution-point fixtures for tests/url_cap.rs.

A certificate advertising far more revocation URLs than any real one
does, so the per-check URL cap can be observed. Written to this
directory as `manyurl-ca.der` and `manyurl-leaf.der`.

Run: python3 -I gen_many_urls_fixtures.py
(needs `cryptography`; the pkix-difftest venv has it)
"""
import datetime
import pathlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

HERE = pathlib.Path(__file__).resolve().parent

# How many of each to advertise. Comfortably above DEFAULT_MAX_URLS_PER_CHECK
# so a capped walk and an uncapped one are plainly distinguishable.
N_URLS = 20

NOT_BEFORE = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
NOT_AFTER = datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)

ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Many URL CA")])

ca = (
    x509.CertificateBuilder()
    .subject_name(ca_name)
    .issuer_name(ca_name)
    .public_key(ca_key.public_key())
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
    .sign(ca_key, hashes.SHA256())
)

leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Each distribution point carries one URI, so the extension lists N_URLS
# of them in order. The fetchers walk them in exactly this order.
cdps = x509.CRLDistributionPoints(
    [
        x509.DistributionPoint(
            full_name=[
                x509.UniformResourceIdentifier(f"http://crl{i:02d}.manyurl.test/ca.crl")
            ],
            relative_name=None,
            reasons=None,
            crl_issuer=None,
        )
        for i in range(N_URLS)
    ]
)

aia = x509.AuthorityInformationAccess(
    [
        x509.AccessDescription(
            access_method=AuthorityInformationAccessOID.OCSP,
            access_location=x509.UniformResourceIdentifier(
                f"http://ocsp{i:02d}.manyurl.test/"
            ),
        )
        for i in range(N_URLS)
    ]
)

leaf = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "many-url leaf")]))
    .issuer_name(ca_name)
    .public_key(leaf_key.public_key())
    .serial_number(2)
    .not_valid_before(NOT_BEFORE)
    .not_valid_after(NOT_AFTER)
    .add_extension(cdps, critical=False)
    .add_extension(aia, critical=False)
    .sign(ca_key, hashes.SHA256())
)

(HERE / "manyurl-ca.der").write_bytes(ca.public_bytes(serialization.Encoding.DER))
(HERE / "manyurl-leaf.der").write_bytes(leaf.public_bytes(serialization.Encoding.DER))
print(f"wrote manyurl-ca.der and manyurl-leaf.der with {N_URLS} CDP + {N_URLS} OCSP URLs")
