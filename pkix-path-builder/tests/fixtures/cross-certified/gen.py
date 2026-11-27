#!/usr/bin/env python3
"""
One CA, two certificates for it: a cross-certified CA.

WHY THIS EXISTS
---------------
`rank_candidates` sorts candidate issuers so that, in a
signature-checked search, one whose own issuer is a trust anchor is
tried before one that reaches the anchor only through further
certificates. The rustdoc's reason is that the common case should
terminate on its first candidate.

Nothing tested it, because no fixture gives a leaf two candidate issuers
to choose between. Every pool here has at most one certificate whose
subject matches the leaf's issuer, so the sort has a single element and
any ordering is the same ordering.

This is the ordinary shape that produces two: a CA cross-certified by a
second authority, which is how bridge PKIs are built. Both certificates
name the same CA and carry the same key, so both verify the leaf, and
both routes reach the anchor -- one directly, one through `other-ca`.

  root.der            the trust anchor
  other-ca.der        a second authority, issued by root
  ca-x-by-root.der    CA X, issued by root        -- reaches the anchor
  ca-x-by-other.der   CA X, issued by other-ca    -- reaches it via other-ca
  leaf.der            issued by CA X, signed with CA X's key

`ca-x-by-root` and `ca-x-by-other` share subject and key and differ only
in who issued them, so a builder that tries them in either order returns
a valid chain -- which is what makes this a test of the ordering and not
of validity. The chains differ in length, two certificates against
three, and that is what the ordering is observable through.

Usage: python3 gen.py   (run from this directory; needs `cryptography`)
"""

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

OUT = Path(__file__).resolve().parent
UTC = datetime.timezone.utc
NOT_BEFORE = datetime.datetime(2026, 1, 1, tzinfo=UTC)
NOT_AFTER = datetime.datetime(2036, 1, 1, tzinfo=UTC)

CA_KU = x509.KeyUsage(
    digital_signature=False,
    content_commitment=False,
    key_encipherment=False,
    data_encipherment=False,
    key_agreement=False,
    key_cert_sign=True,
    crl_sign=True,
    encipher_only=False,
    decipher_only=False,
)
LEAF_KU = x509.KeyUsage(
    digital_signature=True,
    content_commitment=False,
    key_encipherment=False,
    data_encipherment=False,
    key_agreement=False,
    key_cert_sign=False,
    crl_sign=False,
    encipher_only=False,
    decipher_only=False,
)


def dn(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def issue(subject, public_key, issuer_name, issuer_key, serial, *, ca):
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(
            x509.BasicConstraints(ca=ca, path_length=None if ca else None), critical=True
        )
        .add_extension(CA_KU if ca else LEAF_KU, critical=True)
    )
    return builder.sign(issuer_key, hashes.SHA256())


def write(name, cert):
    der = cert.public_bytes(serialization.Encoding.DER)
    (OUT / name).write_bytes(der)
    print(f"wrote {name} ({len(der)} bytes)")
    return cert


root_key = ec.generate_private_key(ec.SECP256R1())
other_key = ec.generate_private_key(ec.SECP256R1())
ca_x_key = ec.generate_private_key(ec.SECP256R1())
leaf_key = ec.generate_private_key(ec.SECP256R1())

root_dn = dn("cross-cert root")
other_dn = dn("cross-cert other authority")
ca_x_dn = dn("cross-cert CA X")

root = write(
    "root.der",
    issue(root_dn, root_key.public_key(), root_dn, root_key, 1, ca=True),
)
other = write(
    "other-ca.der",
    issue(other_dn, other_key.public_key(), root_dn, root_key, 2, ca=True),
)
# The same subject and the same key, issued twice.
by_root = write(
    "ca-x-by-root.der",
    issue(ca_x_dn, ca_x_key.public_key(), root_dn, root_key, 3, ca=True),
)
by_other = write(
    "ca-x-by-other.der",
    issue(ca_x_dn, ca_x_key.public_key(), other_dn, other_key, 4, ca=True),
)
leaf = write(
    "leaf.der",
    issue(dn("cross-cert leaf"), leaf_key.public_key(), ca_x_dn, ca_x_key, 5, ca=False),
)

# The properties the test turns on, asserted rather than assumed.
assert by_root.subject == by_other.subject == ca_x_dn, "one CA, two certificates"
assert (
    by_root.public_key().public_numbers() == by_other.public_key().public_numbers()
), "and one key, so either verifies the leaf"
assert by_root.issuer == root_dn, "one is issued by the anchor"
assert by_other.issuer == other_dn, "the other is not"
assert leaf.issuer == ca_x_dn, "the leaf names CA X, so both are candidates"
print("property checks passed")
