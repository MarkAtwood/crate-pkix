#!/usr/bin/env python3
"""Fixtures for RFC 5280 4.2.1.6 SAN-as-identity issuer handling.

`cert_has_san_identity` decides whether an issuer is identified by its
SubjectAltName rather than its Subject DN, and `check_issuer_linkage` skips
the 6.1.3(a)(2) DN comparison entirely when it is.  Four mutations of that
function survived the suite, including returning `false` always and deleting
the `!` in its empty-subject guard.

Two chains, because the two mutations need different inputs:

  A. empty-subject issuer, critical SAN -- the case the rule exists for.
     The leaf names a DIFFERENT issuer DN, which only validates because the
     linkage check is skipped.  Kills `-> false`.

  B. non-empty-subject issuer, critical SAN.  A critical SAN on a CA is
     unusual but legal, and such an issuer must STILL have its DN linkage
     checked.  The leaf names a different issuer DN and must be rejected.
     Kills `delete !`, which would otherwise skip linkage for every
     certificate carrying a critical SAN.

Both leaves are signed by the real issuer key, so the signature check passes
and the verdict turns on linkage alone.  RFC 5280 4.1.2.6 requires a CA
subject to be non-empty, so chain A is deliberately non-conformant -- it is
the shape the accommodation in `cert_has_san_identity` is written for.

  si-root.der          self-signed CA, anchor for both chains
  si-int-empty.der     intermediate, EMPTY subject, critical SAN
  si-leaf-empty.der    leaf under it, issuer DN = CN=si other
  si-int-named.der     intermediate, subject CN=si named, critical SAN
  si-leaf-named.der    leaf under it, issuer DN = CN=si other
"""

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

OUT = Path(__file__).parent
NOT_BEFORE = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
NOT_AFTER = datetime.datetime(2036, 1, 1, tzinfo=datetime.timezone.utc)

KU_CA = x509.KeyUsage(
    digital_signature=False, content_commitment=False, key_encipherment=False,
    data_encipherment=False, key_agreement=False, key_cert_sign=True,
    crl_sign=True, encipher_only=False, decipher_only=False,
)


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def ca(key, subject, issuer_name, issuer_key, serial, critical_san=None,
       noncritical_san=None):
    b = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(KU_CA, critical=True)
    )
    if critical_san is not None:
        b = b.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(critical_san)]), critical=True
        )
    if noncritical_san is not None:
        b = b.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(noncritical_san)]), critical=False
        )
    return b.sign(issuer_key, hashes.SHA256())


def leaf(key, issuer_dn, issuer_key, cn, serial):
    """A leaf whose issuer field is `issuer_dn`, signed by `issuer_key`."""
    return (
        x509.CertificateBuilder()
        .subject_name(name(cn))
        .issuer_name(issuer_dn)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(issuer_key, hashes.SHA256())
    )


root_key = ec.generate_private_key(ec.SECP256R1())
int_key = ec.generate_private_key(ec.SECP256R1())
leaf_key = ec.generate_private_key(ec.SECP256R1())
root_name = name("PKIX si root")
OTHER = name("si other")

root = ca(root_key, root_name, root_name, root_key, 1)

# A: empty subject + critical SAN.
int_empty = ca(int_key, x509.Name([]), root_name, root_key, 2, critical_san="a.example.com")
leaf_empty = leaf(leaf_key, OTHER, int_key, "PKIX si leaf empty", 3)

# B: non-empty subject + critical SAN.
int_named = ca(
    int_key, name("si named"), root_name, root_key, 4, critical_san="b.example.com"
)
leaf_named = leaf(leaf_key, OTHER, int_key, "PKIX si leaf named", 5)

# C: empty subject with a NON-CRITICAL SAN. RFC 5280 4.2.1.6 requires the SAN
# to be critical when the Subject is empty, so this is non-conformant, and
# `cert_has_san_identity` documents itself as returning false for it ("Returns
# false for any cert that has a non-empty Subject or a non-critical SAN").
#
# Needed because this issuer's OTHER extensions are critical: with the OID
# comparison flipped to `!=`, or the `&&` to `||`, critical basicConstraints
# alone makes the function report SAN-identity. Chains A and B cannot see
# either mutation; this one can.
int_noncrit = ca(
    int_key, x509.Name([]), root_name, root_key, 6, noncritical_san="c.example.com"
)
leaf_noncrit = leaf(leaf_key, OTHER, int_key, "PKIX si leaf noncrit", 7)

for fname, cert in {
    "si-int-noncrit.der": int_noncrit,
    "si-leaf-noncrit.der": leaf_noncrit,
    "si-root.der": root,
    "si-int-empty.der": int_empty,
    "si-leaf-empty.der": leaf_empty,
    "si-int-named.der": int_named,
    "si-leaf-named.der": leaf_named,
}.items():
    (OUT / fname).write_bytes(cert.public_bytes(serialization.Encoding.DER))
    print(f"  wrote {fname}")
