#!/usr/bin/env python3
"""
Public-key certificates for the holder-matching paths `gen.py` cannot
reach, and an attribute authority missing its `keyUsage`.

WHY THESE EXIST
---------------
RFC 5755 §4.2.2 lets an AC's `holder.entityName` match "the PKC subject
field OR ONE OF THE VALUES OF THE PKC subjectAltName field extension (if
present)". The holder certificate every existing fixture uses is
`pkix-ct`'s `precert-leaf-final.der`, which carries no subjectAltName at
all -- so holder matching has only ever been tried against a subject DN,
and `subject_alt_names` is dead code as far as the suite is concerned. An
AC issued against a holder's dNSName would silently fail to match the
holder it names.

  holder-san-cert.der   subject CN=pkix-ac SAN holder, and
                        subjectAltName dNSName ac-holder.example

§4.5 says an AC issuer's `keyUsage` "MUST NOT explicitly indicate that
the AC issuer's public key cannot be used to validate a digital
signature". An absent `keyUsage` indicates nothing, so it is permitted --
but every AA fixture carries one, which leaves the duplicate-extension
count in `check_issuer_profile` unable to tell `> 1` from `< 1`: with one
of each extension both read the same.

  aa-no-key-usage-cert.der   basicConstraints CA:FALSE and no keyUsage

Neither certificate's key is ever used. `matches_holder` compares names,
and `check_issuer_profile` reads extensions; the AC signature is made by
the attribute authority's key, not by either of these. So both are
self-signed and their keys are not kept.

These are generated separately from `make_aa.sh` on purpose: that script
regenerates every authority key from scratch, which would invalidate
every AC fixture signed with the committed `aa-key.pem`.

Usage: python3 make_holder_san.py   (run from this directory)
"""

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

OUT = Path(__file__).resolve().parent
UTC = datetime.timezone.utc
# The window the borrowed certificates and the AC fixtures share.
NOT_BEFORE = datetime.datetime(2025, 1, 1, tzinfo=UTC)
NOT_AFTER = datetime.datetime(2035, 1, 1, tzinfo=UTC)

HOLDER_DNS = "ac-holder.example"


def self_signed(cn, extensions):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
    )
    for ext, critical in extensions:
        builder = builder.add_extension(ext, critical=critical)
    return builder.sign(key, hashes.SHA256())


def write(fname, cert):
    der = cert.public_bytes(serialization.Encoding.DER)
    (OUT / fname).write_bytes(der)
    print(f"wrote {fname} ({len(der)} bytes)")
    return cert


holder = write(
    "holder-san-cert.der",
    self_signed(
        "pkix-ac SAN holder",
        [
            (x509.BasicConstraints(ca=False, path_length=None), True),
            (
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
                True,
            ),
            (x509.SubjectAlternativeName([x509.DNSName(HOLDER_DNS)]), False),
        ],
    ),
)

aa_no_ku = write(
    "aa-no-key-usage-cert.der",
    self_signed(
        "pkix-ac authority without keyUsage",
        [(x509.BasicConstraints(ca=False, path_length=None), True)],
    ),
)

# Assert the two properties the tests turn on, rather than trusting the
# builder calls above: a fixture that quietly lost either would go on
# passing for the wrong reason.
san = holder.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
assert san.get_values_for_type(x509.DNSName) == [HOLDER_DNS], "the holder's dNSName"
assert holder.subject.rfc4514_string() != HOLDER_DNS, "and it is not the subject DN"
assert [e.oid.dotted_string for e in aa_no_ku.extensions] == [
    "2.5.29.19"
], "the authority has basicConstraints and nothing else"
print("property checks passed")
