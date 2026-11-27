#!/usr/bin/env python3
"""
Bundles where a discovered CRL signer does not reach a self-signed
certificate.

WHAT THE RULE IS
----------------
`CrlChecker::new_with_signer_discovery` will not accept a signer it cannot
walk from the supplied bundle to a self-signed certificate --
`Error::CrlSignerNotTrusted`. The walk is `reaches_self_signed`, stepping
through `find_parent` and bounded by the bundle's own length.

Two of its parts had no test:

  * `find_parent` requires a candidate to be a different certificate AND to
    have the subject the certificate names as its issuer. Relax that to
    either and the walk picks whichever bundle entry is not the certificate
    in hand, so an unrelated self-signed certificate in the bundle makes
    `reaches_self_signed` answer yes for a signer that reaches nothing.

  * the step counter bounds the walk. The bound is what makes a cyclic
    bundle terminate; without it the walk follows the cycle forever, which
    turns a crafted bundle into a hang rather than a refusal.

  orphan                    subject O, issuer "Absent CA" -- nothing in
                            the bundle has that subject
  unrelated-root            a self-signed CA with nothing to do with the
                            orphan
  crl-from-orphan           a CRL whose issuer DN is O, so discovery picks
                            the orphan
  crl-from-unrelated-root   the control: a self-signed signer anchors itself

  cycle-a          subject A, issuer B
  cycle-b          subject B, issuer A
  crl-from-a       a CRL whose issuer DN is A

Neither cycle certificate is self-signed, so the walk A -> B -> A -> ...
only ends because the counter stops it. Mutual issuer references are what a
cross-certified pair looks like, so the shape is not merely adversarial.

No certificate here carries an AKI, which keeps `find_parent` on its
issuer-DN path -- the one being tested. The CRLs carry no AKI either, so
`discover_crl_signer` uses its own DN fallback.

Oracle: pyca/cryptography. The Rust checker never participates.

Run from this directory:

    /home/mark/PROJECT/PKIX/pkix-difftest/python/.venv/bin/python3 gen.py
"""

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

NOT_BEFORE = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
NOT_AFTER = datetime.datetime(2050, 1, 1, tzinfo=datetime.timezone.utc)
CRL_THIS = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
CRL_NEXT = datetime.datetime(2050, 1, 1, tzinfo=datetime.timezone.utc)

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


def cert(subject, issuer, pubkey, signing_key, serial):
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(pubkey)
        .serial_number(serial)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(CA_KEY_USAGE, critical=True)
        .sign(signing_key, hashes.SHA256())
    )


def crl(issuer, key):
    return (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer)
        .last_update(CRL_THIS)
        .next_update(CRL_NEXT)
        .sign(key, hashes.SHA256())
    )


def write(fname, der):
    path = Path(__file__).resolve().parent / fname
    path.write_bytes(der)
    print(f"wrote {path.name} ({path.stat().st_size} bytes)")


def main():
    orphan_key = ec.generate_private_key(ec.SECP256R1())
    absent_key = ec.generate_private_key(ec.SECP256R1())
    root_key = ec.generate_private_key(ec.SECP256R1())
    a_key = ec.generate_private_key(ec.SECP256R1())
    b_key = ec.generate_private_key(ec.SECP256R1())

    orphan_name = name("Anchoring Orphan")
    absent_name = name("Anchoring Absent CA")
    root_name = name("Anchoring Unrelated Root")
    a_name = name("Anchoring Cycle A")
    b_name = name("Anchoring Cycle B")

    # The orphan is signed by a CA that is deliberately not in any bundle.
    orphan = cert(orphan_name, absent_name, orphan_key.public_key(), absent_key, 0xF001)
    unrelated_root = cert(
        root_name, root_name, root_key.public_key(), root_key, 0xF002
    )

    # Mutual issuer references: A says B issued it, B says A did.
    cycle_a = cert(a_name, b_name, a_key.public_key(), b_key, 0xF003)
    cycle_b = cert(b_name, a_name, b_key.public_key(), a_key, 0xF004)

    write("orphan.der", orphan.public_bytes(serialization.Encoding.DER))
    write("unrelated-root.der", unrelated_root.public_bytes(serialization.Encoding.DER))
    write("cycle-a.der", cycle_a.public_bytes(serialization.Encoding.DER))
    write("cycle-b.der", cycle_b.public_bytes(serialization.Encoding.DER))
    write(
        "crl-from-orphan.der",
        crl(orphan_name, orphan_key).public_bytes(serialization.Encoding.DER),
    )
    write("crl-from-a.der", crl(a_name, a_key).public_bytes(serialization.Encoding.DER))
    # The control: a signer that is itself self-signed anchors itself, so a
    # refusal in the other cases is about reachability and not about the
    # constructor refusing every bundle.
    write(
        "crl-from-unrelated-root.der",
        crl(root_name, root_key).public_bytes(serialization.Encoding.DER),
    )


if __name__ == "__main__":
    main()
