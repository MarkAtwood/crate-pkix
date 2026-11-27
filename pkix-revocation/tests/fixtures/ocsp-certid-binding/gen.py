#!/usr/bin/env python3
"""
An OCSP response plus three candidate issuers that each break exactly one
half of the CertID binding.

WHAT THE RULE IS
----------------
RFC 6960 §4.1.1: a `CertID` names the certificate asked about by the hash
of its issuer's name *and* the hash of its issuer's public key, both under
one algorithm. `OcspChecker` recomputes both from the issuer it was handed
and refuses the response unless both match -- a disjunction, so either
mismatch is fatal.

Weakening that disjunction to a conjunction needs a response that matches
one hash and not the other to be noticed, and nothing in `../` is shaped
that way: the cross-CA fixtures differ in both name and key, so either
form of the test refuses them.

  ca-key1   DN "OCSP CertID CA", key K1 -- issued the leaf, signed the
                                           response
  ca-case   DN "ocsp certid ca", key K1 -- RFC 4518-equivalent name,
                                           byte-different DER

`ca-case` is the reachable case. It passes every check before the CertID
comparison: `names_match` folds case per RFC 4518, so the responder-id
match succeeds, and the shared key makes the response signature verify.
Only the hash notices, because `issuerNameHash` is over the DER of the
issuer's subject and that DER differs. The response genuinely does not
name this certificate, and refusing it is what stops a response being
reused across two encodings of one name.

The mirror -- a matching name hash with a different key -- is not
reachable, and no fixture can make it so: the response signature and the
delegated-responder validation both run first and both need the issuer's
key, so an issuer whose key hash differs is refused before the CertID
comparison. Only the name-hash half of that disjunction is live.

THE CertID ALGORITHM IS SHA-1
-----------------------------
Every response in `../` uses SHA-256, so `hash_certid_input`'s SHA-1 arm
had no test -- deleting it changed nothing. SHA-1 is what deployed
responders actually emit for CertID, and this is identity matching rather
than a signature: the hash names which certificate is being asked about.
The response signature here is ECDSA with SHA-256.

The validity window is deliberately wide and the tests take `now` from the
response's own `producedAt`, which is generation time.

Oracle: pyca/cryptography. The Rust checker never participates.

Run from this directory:

    /home/mark/PROJECT/PKIX/pkix-difftest/python/.venv/bin/python3 gen.py
"""

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID

NOT_BEFORE = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
NOT_AFTER = datetime.datetime(2050, 1, 1, tzinfo=datetime.timezone.utc)
THIS_UPDATE = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
NEXT_UPDATE = datetime.datetime(2050, 1, 1, tzinfo=datetime.timezone.utc)


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def ca(subject, key, serial):
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )


def write(fname, der):
    path = Path(__file__).resolve().parent / fname
    path.write_bytes(der)
    print(f"wrote {path.name} ({path.stat().st_size} bytes)")


def main():
    k1 = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())

    ca_name = name("OCSP CertID CA")
    # Same name under RFC 4518 case folding, different DER bytes.
    case_name = name("ocsp certid ca")

    ca_key1 = ca(ca_name, k1, 0xC101)
    ca_case = ca(case_name, k1, 0xC102)

    leaf = (
        x509.CertificateBuilder()
        .subject_name(name("OCSP CertID Leaf"))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(0xC104)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(k1, hashes.SHA256())
    )

    response = (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=leaf,
            issuer=ca_key1,
            algorithm=hashes.SHA1(),
            cert_status=ocsp.OCSPCertStatus.GOOD,
            this_update=THIS_UPDATE,
            next_update=NEXT_UPDATE,
            revocation_time=None,
            revocation_reason=None,
        )
        .responder_id(ocsp.OCSPResponderEncoding.NAME, ca_key1)
        .sign(k1, hashes.SHA256())
    )

    write("ca-key1.der", ca_key1.public_bytes(serialization.Encoding.DER))
    write("ca-case.der", ca_case.public_bytes(serialization.Encoding.DER))
    write("leaf.der", leaf.public_bytes(serialization.Encoding.DER))
    write("response.der", response.public_bytes(serialization.Encoding.DER))


if __name__ == "__main__":
    main()
