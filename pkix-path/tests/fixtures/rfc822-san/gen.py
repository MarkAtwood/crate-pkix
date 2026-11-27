#!/usr/bin/env python3
"""Fixtures for ValidationPolicy::require_rfc822_san.

That flag had no behavioural test -- only serde_round_trip.rs set it -- so a
mutation deleting the `!` in `if !has_rfc822` (accepting leaves WITHOUT an
rfc822 SAN and rejecting those with one) survived the whole suite.

Self-contained root/intermediate/leaf chain rather than additions to
policy-checks/, whose generator randomises every key on each run: adding a
fixture there rewrites the whole directory, and leaves signed by the new
intermediate key cannot be mixed with the committed one.

The flag is only consulted when require_subject_alt_name is also set, and the
EKU check runs first, so both leaves carry a serverAuth EKU.

  rfc822-root.der       self-signed CA
  rfc822-int.der        intermediate CA
  rfc822-leaf-email.der leaf, SAN = rfc822Name:user@example.com   -> passes
  rfc822-leaf-dns.der   leaf, SAN = dNSName:host.example.com      -> rejected
"""

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

OUT = Path(__file__).parent
NOT_BEFORE = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
NOT_AFTER = datetime.datetime(2036, 1, 1, tzinfo=datetime.timezone.utc)


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def ca(key, subject, issuer_name=None, issuer_key=None, serial=1):
    """Self-signed when issuer_key is None."""
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name if issuer_name is not None else subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(issuer_key if issuer_key is not None else key, hashes.SHA256())
    )


def leaf(key, issuer_cert, issuer_key, cn, san_entry, serial):
    return (
        x509.CertificateBuilder()
        .subject_name(name(cn))
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([san_entry]), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(issuer_key, hashes.SHA256())
    )


root_key = ec.generate_private_key(ec.SECP256R1())
int_key = ec.generate_private_key(ec.SECP256R1())
leaf_key = ec.generate_private_key(ec.SECP256R1())

root = ca(root_key, name("PKIX rfc822-san root"), serial=1)
intermediate = ca(
    int_key, name("PKIX rfc822-san int"), root.subject, root_key, serial=2
)
leaf_email = leaf(
    leaf_key, intermediate, int_key, "PKIX rfc822-san leaf email",
    x509.RFC822Name("user@example.com"), 3,
)
leaf_dns = leaf(
    leaf_key, intermediate, int_key, "PKIX rfc822-san leaf dns",
    x509.DNSName("host.example.com"), 4,
)

for fname, cert in {
    "rfc822-root.der": root,
    "rfc822-int.der": intermediate,
    "rfc822-leaf-email.der": leaf_email,
    "rfc822-leaf-dns.der": leaf_dns,
}.items():
    (OUT / fname).write_bytes(cert.public_bytes(serialization.Encoding.DER))
    print(f"  wrote {fname}")
