#!/usr/bin/env python3
"""Single-bit KeyUsage fixtures for the RFC 3161 TSA key-shape check.

`enforce_timestamping_ku_shape` rejects a TSA leaf whose KeyUsage asserts any
non-signing bit.  The check is one seven-way `||` chain, and a mutation sweep
found five of its six `||` operators unguarded.

Why five.  Mutating the i-th `||` to `&&` costs the i-th bit its standalone
power -- `A || B || C` becomes `A && B || C`, which is `(A && B) || C`, so a
certificate with only A set stops being rejected.  The existing
`leaf-timestamping-bad-ku.der` asserts digitalSignature + keyEncipherment, so
it kills the first operator and nothing else.  Each remaining operator needs a
certificate with exactly one bit set.

KeyUsage is assembled as raw DER rather than through `x509.KeyUsage`, because
`cryptography` refuses `encipher_only` without `key_agreement` -- correctly,
per RFC 5280 -- and that combination would trip the rule through
`key_agreement` and prove nothing about `encipher_only`.

Also here, because it shares the root: `tsa-eku-server-auth.der`, a leaf whose
critical EKU holds exactly one value and that value is not timeStamping. The
flat corpus has an EKU that is absent, non-critical, or holds several values,
but never that one -- which is the case RFC 3161 §2.3's "sole value" guard
decides.

Self-contained root and leaves: this directory's parent generator randomises
every key per run, so adding fixtures there rewrites all of them.
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
OID_KEY_USAGE = x509.ObjectIdentifier("2.5.29.15")


def bit_string(bit):
    """DER BIT STRING with exactly `bit` set, RFC 5280 KeyUsage numbering.

    Bit 0 is the MSB of the first content octet, so bit n lives in octet n//8
    at mask 0x80 >> (n % 8), and the unused-bit count is whatever pads the
    last octet after bit n.
    """
    nbytes = bit // 8 + 1
    data = bytearray(nbytes)
    data[bit // 8] = 0x80 >> (bit % 8)
    unused = nbytes * 8 - (bit + 1)
    return bytes([0x03, nbytes + 1, unused]) + bytes(data)


# RFC 5280 §4.2.1.3 bit numbering.
KU_BITS = {
    "digital-signature": 0,
    "data-encipherment": 3,
    "key-agreement": 4,
    "key-cert-sign": 5,
    "crl-sign": 6,
    "encipher-only": 7,
    "decipher-only": 8,
}


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


root_key = ec.generate_private_key(ec.SECP256R1())
root_name = name("PKIX tsa-ku root")
root = (
    x509.CertificateBuilder()
    .subject_name(root_name)
    .issuer_name(root_name)
    .public_key(root_key.public_key())
    .serial_number(1)
    .not_valid_before(NOT_BEFORE)
    .not_valid_after(NOT_AFTER)
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .add_extension(
        x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False,
        ),
        critical=True,
    )
    .sign(root_key, hashes.SHA256())
)

leaf_key = ec.generate_private_key(ec.SECP256R1())


def tsa_leaf(label, bit, serial):
    """A TSA leaf: critical sole id-kp-timeStamping EKU, one KeyUsage bit."""
    return (
        x509.CertificateBuilder()
        .subject_name(name(f"PKIX tsa-ku {label}"))
        .issuer_name(root_name)
        .public_key(leaf_key.public_key())
        .serial_number(serial)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True
        )
        .add_extension(
            x509.UnrecognizedExtension(OID_KEY_USAGE, bit_string(bit)), critical=True
        )
        .sign(root_key, hashes.SHA256())
    )


def tsa_leaf_with_eku(label, eku_oids, serial):
    """A leaf with a signing-only KeyUsage and the given critical EKU set.

    For the RFC 3161 §2.3 "timeStamping MUST be the sole EKU value" rule.
    The existing corpus covers an EKU that is absent, non-critical, or
    holds several values; what it has never held is exactly one value that
    is not timeStamping, which is the case the rule's guard decides. The
    KeyUsage is digitalSignature alone so that the key-shape check cannot
    fire first and mask the EKU verdict.
    """
    return (
        x509.CertificateBuilder()
        .subject_name(name(f"PKIX tsa-eku {label}"))
        .issuer_name(root_name)
        .public_key(leaf_key.public_key())
        .serial_number(serial)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage(eku_oids), critical=True)
        .add_extension(
            x509.UnrecognizedExtension(OID_KEY_USAGE, bit_string(0)), critical=True
        )
        .sign(root_key, hashes.SHA256())
    )


files = {"tsa-ku-root.der": root}
for i, (label, bit) in enumerate(KU_BITS.items(), start=2):
    files[f"tsa-ku-{label}.der"] = tsa_leaf(label, bit, i)

files["tsa-eku-server-auth.der"] = tsa_leaf_with_eku(
    "server-auth", [ExtendedKeyUsageOID.SERVER_AUTH], 90
)

for fname, cert in files.items():
    (OUT / fname).write_bytes(cert.public_bytes(serialization.Encoding.DER))
    print(f"  wrote {fname}")
