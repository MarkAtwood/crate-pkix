#!/usr/bin/env python3
"""
A chain whose leaf and intermediate differ in the two things checked only
on the leaf.

WHAT THE RULE IS
----------------
`ValidationPolicy::required_leaf_policy_oids` and
`required_leaf_subject_dn_attrs` are deployment-policy requirements on the
*leaf*, not on the path. `chain_walk` guards each with `if i == 0`.

Both guards survived mutation to `i != 0`, which applies each requirement
to every certificate except the leaf -- so a leaf that fails the
requirement is accepted as long as some intermediate happens to satisfy
it. That is the fail-open direction of a policy bypass: the caller asked
for a leaf asserting a particular policy OID, or carrying a particular
Subject attribute, and got neither.

Nothing noticed because the only chain those tests use is PKITS
AllCertificatesSamePoliciesTest10, and the name is the reason: every
certificate in it asserts the same policies, so it cannot tell apart
"check the leaf" from "check everything but the leaf". Its two Subject
DNs share the attributes the DN tests ask about.

  root   self-signed anchor
  int    certificatePolicies = [anyPolicy, P_INT]
         Subject: CN + O, and no C
  leaf   certificatePolicies = [P_LEAF]
         Subject: CN + C, and no O

Each property is present in exactly one of the two certificates, and in
opposite directions, so both guards are pinned from both sides: requiring
what the leaf has must pass, and requiring what only the intermediate has
must fail.

`int` also asserts anyPolicy so the §6.1.3 (d) valid_policy_tree does not
empty out on a policy the intermediate never named -- that would make the
chain fail for a reason other than the one under test. anyPolicy does not
satisfy a specific OID requirement (only explicit listing counts), so it
does not blunt the distinction.

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

# NIST test-policy OIDs, the same arc the PKITS policy tests use, so the
# values are recognisable and come from the spec rather than invented here.
P_LEAF = x509.ObjectIdentifier("2.16.840.1.101.3.2.1.48.1")
P_INT = x509.ObjectIdentifier("2.16.840.1.101.3.2.1.48.2")
ANY_POLICY = x509.ObjectIdentifier("2.5.29.32.0")


def policies(*oids):
    return x509.CertificatePolicies(
        [x509.PolicyInformation(policy_identifier=o, policy_qualifiers=None) for o in oids]
    )


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


def write(name, cert):
    der = cert.public_bytes(serialization.Encoding.DER)
    (OUT / name).write_bytes(der)
    print(f"  wrote {name} ({len(der)} bytes)")


root_key = ec.generate_private_key(ec.SECP256R1())
int_key = ec.generate_private_key(ec.SECP256R1())
leaf_key = ec.generate_private_key(ec.SECP256R1())

root_dn = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf-only root")])
# O present, C absent.
int_dn = x509.Name(
    [
        x509.NameAttribute(NameOID.COMMON_NAME, "leaf-only intermediate"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Intermediate Org"),
    ]
)
# C present, O absent -- the mirror image of the intermediate.
leaf_dn = x509.Name(
    [
        x509.NameAttribute(NameOID.COMMON_NAME, "leaf-only leaf"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ]
)

root = (
    x509.CertificateBuilder()
    .subject_name(root_dn)
    .issuer_name(root_dn)
    .public_key(root_key.public_key())
    .serial_number(1)
    .not_valid_before(NOT_BEFORE)
    .not_valid_after(NOT_AFTER)
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .add_extension(CA_KU, critical=True)
    .sign(root_key, hashes.SHA256())
)

intermediate = (
    x509.CertificateBuilder()
    .subject_name(int_dn)
    .issuer_name(root_dn)
    .public_key(int_key.public_key())
    .serial_number(2)
    .not_valid_before(NOT_BEFORE)
    .not_valid_after(NOT_AFTER)
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .add_extension(CA_KU, critical=True)
    .add_extension(policies(ANY_POLICY, P_INT), critical=False)
    .sign(root_key, hashes.SHA256())
)

leaf = (
    x509.CertificateBuilder()
    .subject_name(leaf_dn)
    .issuer_name(int_dn)
    .public_key(leaf_key.public_key())
    .serial_number(3)
    .not_valid_before(NOT_BEFORE)
    .not_valid_after(NOT_AFTER)
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    .add_extension(policies(P_LEAF), critical=False)
    .sign(int_key, hashes.SHA256())
)

write("root.der", root)
write("int.der", intermediate)
write("leaf.der", leaf)

# The asymmetry is the whole point, so assert it rather than trusting the
# builder calls above.
def oids(cert):
    ext = cert.extensions.get_extension_for_class(x509.CertificatePolicies).value
    return {p.policy_identifier for p in ext}


def attrs(cert):
    return {a.oid for a in cert.subject}


assert P_LEAF in oids(leaf) and P_LEAF not in oids(intermediate), "P_LEAF is leaf-only"
assert P_INT in oids(intermediate) and P_INT not in oids(leaf), "P_INT is intermediate-only"
assert NameOID.COUNTRY_NAME in attrs(leaf), "leaf carries C"
assert NameOID.COUNTRY_NAME not in attrs(intermediate), "intermediate does not"
assert NameOID.ORGANIZATION_NAME in attrs(intermediate), "intermediate carries O"
assert NameOID.ORGANIZATION_NAME not in attrs(leaf), "leaf does not"
print("  asymmetry checks passed")
