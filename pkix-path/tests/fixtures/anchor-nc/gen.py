#!/usr/bin/env python3
"""
Generate DER fixtures for trust anchor NameConstraints seeding tests.

Produces:
  anchor_permitted_dns.der  - Self-signed CA cert, permittedSubtrees: .example.com
  anchor_excluded_dns.der   - Self-signed CA cert, excludedSubtrees: evil.example.com
  leaf_good_dns.der         - Leaf cert (signed by anchor), SAN: www.example.com  [PASS with permitted anchor]
  leaf_bad_dns.der          - Leaf cert (signed by anchor), SAN: www.evil.com      [FAIL with permitted anchor]
  leaf_excluded_dns.der     - Leaf cert (signed by anchor), SAN: evil.example.com  [FAIL with excluded anchor]

All certs use P-256 ECDSA (SHA-256) to match the rustcrypto feature's supported algorithms.
Validity: 2000-01-01 to 2050-01-01 (far future, tests don't check time)
"""

import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# NOTE: keys and serials are random, so re-running this rewrites every file
# with equivalent-but-different bytes. When adding a fixture, run it and then
# `git checkout --` the ones you did not mean to touch; the committed bytes are
# what the tests reference.
OUT = Path(__file__).parent
NOT_BEFORE = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
NOT_AFTER  = datetime.datetime(2050, 1, 1, tzinfo=datetime.timezone.utc)


def make_subject(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_anchor_cert(key, subject_name, permitted=None, excluded=None):
    """Build a self-signed CA cert with optional NameConstraints."""
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(subject_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if permitted is not None or excluded is not None:
        builder = builder.add_extension(
            x509.NameConstraints(
                permitted_subtrees=permitted,
                excluded_subtrees=excluded,
            ),
            critical=True,
        )
    return builder.sign(key, hashes.SHA256())


def raw_name_constraints(minimum=None, maximum=None):
    """A nameConstraints extension value with a non-conformant GeneralSubtree.

    RFC 5280 4.2.1.10: "Within this profile, the minimum and maximum fields
    are not used with any name forms, thus minimum MUST be zero, and maximum
    MUST be absent."  `cryptography`'s NameConstraints type cannot encode
    either field -- correctly, since they are prohibited -- so the extension
    value is assembled by hand and attached as an UnrecognizedExtension.

    GeneralSubtree ::= SEQUENCE {
        base      GeneralName,
        minimum   [0] BaseDistance DEFAULT 0,
        maximum   [1] BaseDistance OPTIONAL }
    """

    def tlv(tag, value):
        assert len(value) < 128, "fixtures stay in the short-form length"
        return bytes([tag, len(value)]) + value

    # base = dNSName "example.com", context tag [2] IMPLICIT IA5String.
    base = tlv(0x82, b"example.com")
    subtree = base
    if minimum is not None:
        subtree += tlv(0x80, bytes([minimum]))      # [0] INTEGER
    if maximum is not None:
        subtree += tlv(0x81, bytes([maximum]))      # [1] INTEGER
    general_subtree = tlv(0x30, subtree)
    # permittedSubtrees [0] IMPLICIT GeneralSubtrees
    permitted = tlv(0xA0, general_subtree)
    return tlv(0x30, permitted)


def make_anchor_cert_raw_nc(key, subject_name, nc_value):
    """A self-signed CA whose nameConstraints value is supplied verbatim."""
    return (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(subject_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier("2.5.29.30"), nc_value
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )


def make_leaf_cert(anchor_key, anchor_cert, leaf_key, dns_name):
    """Build a leaf cert with a single DNS SAN, signed by anchor."""
    subject = make_subject(f"leaf-{dns_name}")
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(anchor_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(dns_name)]),
            critical=False,
        )
    )
    return builder.sign(anchor_key, hashes.SHA256())


# Generate keys
anchor_key_permitted = ec.generate_private_key(ec.SECP256R1())
anchor_key_excluded  = ec.generate_private_key(ec.SECP256R1())
leaf_key             = ec.generate_private_key(ec.SECP256R1())

# Anchor with permittedSubtrees: .example.com
anchor_permitted = make_anchor_cert(
    anchor_key_permitted,
    make_subject("Test Permitted NC Anchor"),
    permitted=[x509.DNSName(".example.com")],
)

# Anchor with excludedSubtrees: evil.example.com
anchor_excluded = make_anchor_cert(
    anchor_key_excluded,
    make_subject("Test Excluded NC Anchor"),
    excluded=[x509.DNSName("evil.example.com")],
)

# Leaf: www.example.com -- passes permittedSubtrees .example.com
leaf_good_dns = make_leaf_cert(anchor_key_permitted, anchor_permitted, leaf_key, "www.example.com")

# Leaf: www.evil.com -- violates permittedSubtrees .example.com
leaf_bad_dns = make_leaf_cert(anchor_key_permitted, anchor_permitted, leaf_key, "www.evil.com")

# Leaf: evil.example.com -- violates excludedSubtrees evil.example.com
leaf_excluded_dns = make_leaf_cert(anchor_key_excluded, anchor_excluded, leaf_key, "evil.example.com")

# Non-conformant GeneralSubtree fields. RFC 5280 4.2.1.10 requires minimum to
# be zero and maximum to be absent; cert_name_constraints rejects a certificate
# encoding either, rather than silently applying semantics it does not
# implement. Nothing tested that -- a mutation turning the `||` in that check
# into `&&` (so BOTH fields would have to be wrong) survived the whole suite.
anchor_key_minimum = ec.generate_private_key(ec.SECP256R1())
anchor_nc_minimum = make_anchor_cert_raw_nc(
    anchor_key_minimum,
    make_subject("PKIX anchor nc minimum"),
    raw_name_constraints(minimum=1),
)
anchor_key_maximum = ec.generate_private_key(ec.SECP256R1())
anchor_nc_maximum = make_anchor_cert_raw_nc(
    anchor_key_maximum,
    make_subject("PKIX anchor nc maximum"),
    raw_name_constraints(maximum=5),
)
# The same shape with both fields conformant, so a test can show the rejection
# comes from minimum/maximum and not from the hand-built encoding.
anchor_key_plain = ec.generate_private_key(ec.SECP256R1())
anchor_nc_plain = make_anchor_cert_raw_nc(
    anchor_key_plain,
    make_subject("PKIX anchor nc plain"),
    raw_name_constraints(),
)

# A CHAIN carrying the non-conformant subtree on an INTERMEDIATE, so the rule
# can be exercised through validate_path and not only through the trust-anchor
# constructors. Without this, deleting the check from cert_name_constraints
# leaves the whole suite green.
nci_root_key = ec.generate_private_key(ec.SECP256R1())
nci_root_subject = make_subject("PKIX nc-intermediate root")
nci_root = (
    x509.CertificateBuilder()
    .subject_name(nci_root_subject)
    .issuer_name(nci_root_subject)
    .public_key(nci_root_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(NOT_BEFORE)
    .not_valid_after(NOT_AFTER)
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(nci_root_key, hashes.SHA256())
)
nci_int_key = ec.generate_private_key(ec.SECP256R1())
nci_int_subject = make_subject("PKIX nc-intermediate ica")
nci_int = (
    x509.CertificateBuilder()
    .subject_name(nci_int_subject)
    .issuer_name(nci_root_subject)
    .public_key(nci_int_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(NOT_BEFORE)
    .not_valid_after(NOT_AFTER)
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .add_extension(
        x509.UnrecognizedExtension(
            x509.ObjectIdentifier("2.5.29.30"), raw_name_constraints(minimum=1)
        ),
        critical=True,
    )
    .sign(nci_root_key, hashes.SHA256())
)
nci_leaf_key = ec.generate_private_key(ec.SECP256R1())
nci_leaf = (
    x509.CertificateBuilder()
    .subject_name(make_subject("PKIX nc-intermediate leaf"))
    .issuer_name(nci_int_subject)
    .public_key(nci_leaf_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(NOT_BEFORE)
    .not_valid_after(NOT_AFTER)
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(
        x509.SubjectAlternativeName([x509.DNSName("host.example.com")]), critical=False
    )
    .sign(nci_int_key, hashes.SHA256())
)
# The same chain with a CONFORMANT intermediate constraint, so a test can show
# the rejection comes from minimum and not from the chain's shape.
nci_int_ok_key = ec.generate_private_key(ec.SECP256R1())
nci_int_ok_subject = make_subject("PKIX nc-intermediate ica ok")
nci_int_ok = (
    x509.CertificateBuilder()
    .subject_name(nci_int_ok_subject)
    .issuer_name(nci_root_subject)
    .public_key(nci_int_ok_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(NOT_BEFORE)
    .not_valid_after(NOT_AFTER)
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .add_extension(
        x509.UnrecognizedExtension(
            x509.ObjectIdentifier("2.5.29.30"), raw_name_constraints()
        ),
        critical=True,
    )
    .sign(nci_root_key, hashes.SHA256())
)
nci_leaf_ok = (
    x509.CertificateBuilder()
    .subject_name(make_subject("PKIX nc-intermediate leaf ok"))
    .issuer_name(nci_int_ok_subject)
    .public_key(nci_leaf_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(NOT_BEFORE)
    .not_valid_after(NOT_AFTER)
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(
        x509.SubjectAlternativeName([x509.DNSName("host.example.com")]), critical=False
    )
    .sign(nci_int_ok_key, hashes.SHA256())
)

# Write DER files
files = {
    "nc_int_root.der":     nci_root.public_bytes(serialization.Encoding.DER),
    "nc_int_bad.der":      nci_int.public_bytes(serialization.Encoding.DER),
    "nc_int_bad_leaf.der": nci_leaf.public_bytes(serialization.Encoding.DER),
    "nc_int_ok.der":       nci_int_ok.public_bytes(serialization.Encoding.DER),
    "nc_int_ok_leaf.der":  nci_leaf_ok.public_bytes(serialization.Encoding.DER),
    "anchor_nc_minimum.der": anchor_nc_minimum.public_bytes(serialization.Encoding.DER),
    "anchor_nc_maximum.der": anchor_nc_maximum.public_bytes(serialization.Encoding.DER),
    "anchor_nc_plain.der":   anchor_nc_plain.public_bytes(serialization.Encoding.DER),
    "anchor_permitted_dns.der": anchor_permitted.public_bytes(serialization.Encoding.DER),
    "anchor_excluded_dns.der":  anchor_excluded.public_bytes(serialization.Encoding.DER),
    "leaf_good_dns.der":        leaf_good_dns.public_bytes(serialization.Encoding.DER),
    "leaf_bad_dns.der":         leaf_bad_dns.public_bytes(serialization.Encoding.DER),
    "leaf_excluded_dns.der":    leaf_excluded_dns.public_bytes(serialization.Encoding.DER),
}

for name, data in files.items():
    path = OUT / name
    path.write_bytes(data)
    print(f"  wrote {path} ({len(data)} bytes)")

print("done")
