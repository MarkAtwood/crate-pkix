#!/usr/bin/env python3
"""Generate OCSP ResponderId test fixtures for PKIX-jd7.

Scenario: test that ResponderId (byName and byKey) is verified against the
issuer identity.  Four new fixtures are added:

  ocsp-good-bykey.der         — valid "good" response with ResponderId=byKey
                                 (SHA-1 of OCSP CA SPKI bits); uses same key
                                 as ocsp-ca.der so the signature passes.
  ocsp-good-byname-wrong.der  — "good" response with ResponderId=byName set to
                                 the wrong CA name (CN=Wrong CA); signature is
                                 still made with ocsp-ca.der's key so the sig
                                 check passes; only the name fails.
  ocsp-good-bykey-wrong.der   — "good" response with ResponderId=byKey set to
                                 SHA-1 of a *different* (throwaway) key, so the
                                 hash check fails.

Re-reads ocsp-ca.der and ocsp-leaf-good.der from the fixtures directory so
the CA key is regenerated once (this script must be re-run together with
gen_ocsp_fixtures.py if those fixtures change, or better: use the same CA key).

Because we cannot load a private key from the DER cert alone, this script
re-generates a fresh CA key and cert pair specifically for the ResponderId
fixtures, with a distinct CN so they don't collide.

Outputs (in tests/fixtures/):
  ocsp-rid-ca.der              — RSA-2048 CA used for ResponderId fixtures
  ocsp-rid-leaf-good.der       — leaf cert issued by ocsp-rid-ca.der, serial=1
  ocsp-rid-good-bykey.der      — valid response, ResponderId=byKey(SHA1(CA-SPKI))
  ocsp-rid-good-byname.der     — valid response, ResponderId=byName(correct name)
  ocsp-rid-bad-byname.der      — response with byName(wrong CA name), same key
  ocsp-rid-bad-bykey.der       — response with byKey(SHA1(wrong key)), same key

Oracle: pyca/cryptography.
Run once; outputs committed as binary fixtures. Tests fully offline.

Validation time: 2026-06-01 00:00:00 UTC = 1_780_272_000.
"""

import datetime
import hashlib
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
UTC = datetime.timezone.utc

NOT_BEFORE  = datetime.datetime(2026, 1, 1, tzinfo=UTC)
NOT_AFTER   = datetime.datetime(2030, 1, 1, tzinfo=UTC)
PRODUCED_AT = datetime.datetime(2026, 1, 1, tzinfo=UTC)
NEXT_UPDATE = datetime.datetime(2027, 1, 1, tzinfo=UTC)


def gen_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def write(name: str, data: bytes) -> None:
    path = os.path.join(FIXTURES, name)
    with open(path, "wb") as f:
        f.write(data)
    print(f"{name}: {len(data)} bytes")


# ---------------------------------------------------------------------------
# CA key + certificate for ResponderId fixtures
# ---------------------------------------------------------------------------
ca_key = gen_rsa_key()
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OCSP RID Test CA")])

ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_name)
    .issuer_name(ca_name)
    .public_key(ca_key.public_key())
    .serial_number(200)
    .not_valid_before(NOT_BEFORE)
    .not_valid_after(NOT_AFTER)
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=True,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    .sign(ca_key, hashes.SHA256())
)

write("ocsp-rid-ca.der", ca_cert.public_bytes(serialization.Encoding.DER))

# ---------------------------------------------------------------------------
# Leaf certificate
# ---------------------------------------------------------------------------
leaf_key = gen_rsa_key()
leaf_cert = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RID Good Leaf")]))
    .issuer_name(ca_name)
    .public_key(leaf_key.public_key())
    .serial_number(1)
    .not_valid_before(NOT_BEFORE)
    .not_valid_after(NOT_AFTER)
    .sign(ca_key, hashes.SHA256())
)

write("ocsp-rid-leaf-good.der", leaf_cert.public_bytes(serialization.Encoding.DER))


# ---------------------------------------------------------------------------
# Helper: build an OCSP response for leaf_cert / ca_cert with given responder
# ---------------------------------------------------------------------------
def make_ocsp_response(encoding: ocsp.OCSPResponderEncoding,
                       responder_cert: x509.Certificate,
                       signing_key=None) -> bytes:
    """Build a Good OCSP response for leaf_cert.

    encoding       — OCSPResponderEncoding.NAME or .HASH
    responder_cert — certificate whose identity fills the ResponderId
    signing_key    — key used to sign; defaults to ca_key
    """
    if signing_key is None:
        signing_key = ca_key

    builder = (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=leaf_cert,
            issuer=ca_cert,
            algorithm=hashes.SHA256(),
            cert_status=ocsp.OCSPCertStatus.GOOD,
            this_update=PRODUCED_AT,
            next_update=NEXT_UPDATE,
            revocation_time=None,
            revocation_reason=None,
        )
        .responder_id(encoding, responder_cert)
    )
    return builder.sign(signing_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


# ---------------------------------------------------------------------------
# ocsp-rid-good-byname.der — valid, ResponderId=byName(correct CA name)
# ---------------------------------------------------------------------------
write("ocsp-rid-good-byname.der",
      make_ocsp_response(ocsp.OCSPResponderEncoding.NAME, ca_cert))

# ---------------------------------------------------------------------------
# ocsp-rid-good-bykey.der — valid, ResponderId=byKey(SHA1 of CA SPKI bits)
# ---------------------------------------------------------------------------
write("ocsp-rid-good-bykey.der",
      make_ocsp_response(ocsp.OCSPResponderEncoding.HASH, ca_cert))

# ---------------------------------------------------------------------------
# ocsp-rid-bad-byname.der — byName with WRONG CA name, signed with correct key
#
# We build a fake CA cert with a different CN to supply as the responder_cert
# argument (pyca uses the cert's subject as the ResponderId Name value).
# The response is still signed with ca_key so the sig check passes; only the
# ResponderId name check should fail.
# ---------------------------------------------------------------------------
wrong_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Wrong CA")])
# Build a throwaway cert just to carry the wrong subject name.
# We use the real ca_key so the signature passes — we want to isolate the name check.
wrong_name_cert = (
    x509.CertificateBuilder()
    .subject_name(wrong_name)
    .issuer_name(wrong_name)
    .public_key(ca_key.public_key())   # same key → signature will verify
    .serial_number(999)
    .not_valid_before(NOT_BEFORE)
    .not_valid_after(NOT_AFTER)
    .sign(ca_key, hashes.SHA256())
)

write("ocsp-rid-bad-byname.der",
      make_ocsp_response(ocsp.OCSPResponderEncoding.NAME, wrong_name_cert))

# ---------------------------------------------------------------------------
# ocsp-rid-bad-bykey.der — byKey with hash of a DIFFERENT key's SPKI bits
#
# pyca requires that the responder cert's key matches the signing key when using
# HASH encoding, so we cannot supply a cert with a different public key.
# Workaround: generate a valid byKey response (correct SHA-1), then find the
# 20-byte SHA-1 KeyHash in the DER and XOR the first byte to corrupt it.
# The response is still signed with ca_key so the signature passes; only the
# ResponderId key hash check should fail.
# ---------------------------------------------------------------------------
good_bykey_der = bytearray(make_ocsp_response(ocsp.OCSPResponderEncoding.HASH, ca_cert))

# The byKey ResponderId in the BasicOCSPResponse is DER-encoded as:
#   [2] EXPLICIT OCTET STRING (20 bytes of SHA-1)
# Locate the OCTET STRING tag (0x04) followed by length 0x14 (20) followed by
# the 20-byte SHA-1 hash.  Find the first occurrence in the DER.
# We look for the context-specific [2] EXPLICIT wrapper: 0xa2 0x16 0x04 0x14
# (tag=0xa2, length=22, then OCTET STRING 0x04 0x14 then 20 bytes)
target = bytes([0xa2, 0x16, 0x04, 0x14])
idx = good_bykey_der.find(target)
if idx == -1:
    raise ValueError("Could not locate byKey ResponderId [2] EXPLICIT in DER")
# The SHA-1 bytes start 4 bytes after the tag sequence (past a2 16 04 14)
sha1_offset = idx + 4
# Corrupt the first byte of the SHA-1 hash
good_bykey_der[sha1_offset] ^= 0xFF

write("ocsp-rid-bad-bykey.der", bytes(good_bykey_der))

print("Done. Commit the new fixtures in tests/fixtures/.")
