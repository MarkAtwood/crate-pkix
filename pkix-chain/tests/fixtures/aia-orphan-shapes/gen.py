#!/usr/bin/env python3
"""
Fixtures for the two pool shapes `orphans_on_paths` has to get right.

`Verifier::build_with_aia` only asks a certificate for its `caIssuers` URIs
when its issuer is not already available. Deciding that wrongly is not a
loud failure: the URI is simply never requested, and a chain AIA could have
completed reports "no path found" instead.

noca-*: AN ISSUER WITHOUT basicConstraints
------------------------------------------
`noca-int-ee` carries the same subject DN *and the same public key* as
`noca-int-ca`, so it verifies the leaf's signature -- but it has no
basicConstraints extension, so it is not a CA and RFC 5280 §6.1.4 forbids
using it as one. It is self-issued, which is what leaves the pool with no
complete path to the anchor and so routes the build into the AIA seam. Certificates like this exist: pre-RFC-3280 issuers predate
the extension being mandatory, and a CA key certified both ways is a known
misissuance. Such a certificate must neither serve as the issuer nor
suppress the fetch that would find a conformant replacement.

A different key is not enough to test this: the signature check already
rejects that, so basicConstraints never decides anything. Sharing the key is
what makes the CA bit load-bearing.

xsign-*: A SELF-SIGNED ROOT THAT IS NOT THE ANCHOR
--------------------------------------------------
`xsign-r-self` is a self-signed root that the relying party does not trust;
`xsign-r-cross` is the same subject and key certified by the anchor
`xsign-a`. This is how the Web PKI survives a root transition, and the
chain only completes if the self-signed root is recognised as still needing
its issuer. A self-signed certificate verifies its own signature and
matches its own subject to its own issuer, so an identity test that does not
exclude the certificate under consideration finds that it is its own issuer
and stops looking.

Oracle: pyca/cryptography. The Rust verifier never participates.

Run from this directory:

    /home/mark/PROJECT/PKIX/pkix-difftest/python/.venv/bin/python3 gen.py
"""

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

NOT_BEFORE = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
NOT_AFTER = datetime.datetime(2050, 1, 1, tzinfo=datetime.timezone.utc)

CA_KEY_USAGE = x509.KeyUsage(
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


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def ca_issuers(uri):
    return x509.AuthorityInformationAccess(
        [
            x509.AccessDescription(
                AuthorityInformationAccessOID.CA_ISSUERS,
                x509.UniformResourceIdentifier(uri),
            )
        ]
    )


def base(subject, issuer_name, pubkey, serial):
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(pubkey)
        .serial_number(serial)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
    )


def write(fname, cert):
    path = Path(__file__).resolve().parent / fname
    path.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    print(f"wrote {path.name} ({path.stat().st_size} bytes)")


def gen_noca():
    root_key = ec.generate_private_key(ec.SECP256R1())
    int_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())

    root_name = name("AIA NoCA Root")
    int_name = name("AIA NoCA Int")

    root = (
        base(root_name, root_name, root_key.public_key(), 0x8001)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(CA_KEY_USAGE, critical=True)
        .sign(root_key, hashes.SHA256())
    )

    int_ca = (
        base(int_name, root_name, int_key.public_key(), 0x8002)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(CA_KEY_USAGE, critical=True)
        .sign(root_key, hashes.SHA256())
    )

    # Same DN, same key, no basicConstraints at all -- and self-issued, so
    # the pool holding it offers no topologically complete path to the
    # anchor. That is what routes the build into the AIA seam; a copy
    # issued by the root would instead give the path builder a complete
    # candidate, and validation would reject it with "not a CA" before the
    # orphan predicate was ever consulted.
    int_ee = base(int_name, int_name, int_key.public_key(), 0x8003).sign(
        int_key, hashes.SHA256()
    )

    leaf = (
        base(name("AIA NoCA Leaf"), int_name, leaf_key.public_key(), 0x8004)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(ca_issuers("http://aia.test/noca-int-ca.der"), critical=False)
        .sign(int_key, hashes.SHA256())
    )

    write("noca-root.der", root)
    write("noca-int-ca.der", int_ca)
    write("noca-int-ee.der", int_ee)
    write("noca-leaf.der", leaf)


def gen_xsign():
    a_key = ec.generate_private_key(ec.SECP256R1())
    r_key = ec.generate_private_key(ec.SECP256R1())
    int_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())

    a_name = name("AIA Xsign Anchor A")
    r_name = name("AIA Xsign Root R")
    int_name = name("AIA Xsign Int")

    anchor_a = (
        base(a_name, a_name, a_key.public_key(), 0x9001)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(CA_KEY_USAGE, critical=True)
        .sign(a_key, hashes.SHA256())
    )

    # R, self-signed, pointing at its own cross-certificate.
    r_self = (
        base(r_name, r_name, r_key.public_key(), 0x9002)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(CA_KEY_USAGE, critical=True)
        .add_extension(ca_issuers("http://aia.test/xsign-r-cross.der"), critical=False)
        .sign(r_key, hashes.SHA256())
    )

    # The same subject and key, certified by A.
    r_cross = (
        base(r_name, a_name, r_key.public_key(), 0x9003)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(CA_KEY_USAGE, critical=True)
        .sign(a_key, hashes.SHA256())
    )

    intermediate = (
        base(int_name, r_name, int_key.public_key(), 0x9004)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(CA_KEY_USAGE, critical=True)
        .sign(r_key, hashes.SHA256())
    )

    leaf = (
        base(name("AIA Xsign Leaf"), int_name, leaf_key.public_key(), 0x9005)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(int_key, hashes.SHA256())
    )

    write("xsign-a.der", anchor_a)
    write("xsign-r-self.der", r_self)
    write("xsign-r-cross.der", r_cross)
    write("xsign-int.der", intermediate)
    write("xsign-leaf.der", leaf)


def gen_anchored():
    """anchored-*: an intermediate the anchor issued, carrying caIssuers.

    `orphans_on_paths` must not ask a certificate for its caIssuers URIs
    when its issuer is already a trust anchor: fetching there can only
    produce a certificate the anchor set already supersedes, so the request
    tells the CA's AIA endpoint which certificate is being validated and
    buys nothing.

    Showing that needs three things at once, and no existing fixture has
    all three: a complete topological path (so the orphan walk reaches the
    top of the chain), a validation that fails anyway (so the walk runs at
    all rather than the build simply succeeding), and a caIssuers URI on
    the anchor-issued certificate (so a wrongly-included orphan is
    visible as a fetch). `deep-i5.der`, the only anchor-issued intermediate
    in the corpus, carries no AIA extension.

    The leaf's validity ends in 2010, so the chain is complete and refused.
    """
    root_key = ec.generate_private_key(ec.SECP256R1())
    int_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())

    root_name = name("AIA Anchored Root")
    int_name = name("AIA Anchored Int")

    root = (
        base(root_name, root_name, root_key.public_key(), 0xA001)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(CA_KEY_USAGE, critical=True)
        .sign(root_key, hashes.SHA256())
    )

    intermediate = (
        base(int_name, root_name, int_key.public_key(), 0xA002)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(CA_KEY_USAGE, critical=True)
        .add_extension(ca_issuers("http://aia.test/anchored-root.der"), critical=False)
        .sign(root_key, hashes.SHA256())
    )

    leaf = (
        x509.CertificateBuilder()
        .subject_name(name("AIA Anchored Leaf"))
        .issuer_name(int_name)
        .public_key(leaf_key.public_key())
        .serial_number(0xA003)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(datetime.datetime(2010, 1, 1, tzinfo=datetime.timezone.utc))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(int_key, hashes.SHA256())
    )

    write("anchored-root.der", root)
    write("anchored-int.der", intermediate)
    write("anchored-leaf-expired.der", leaf)


if __name__ == "__main__":
    gen_noca()
    gen_xsign()
    gen_anchored()
