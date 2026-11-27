#!/usr/bin/env python3
"""
Algorithm and key parameters the RSA-PSS and Ed25519 verifiers must read.

WHAT THE RULES ARE
------------------
These fixtures are not certificates. They are the four arguments of
`SignatureVerifier::verify_signature` -- an AlgorithmIdentifier, a
SubjectPublicKeyInfo, a message and a signature -- so a test can vary one
parameter at a time. A certificate cannot do that: changing the
signatureAlgorithm of a certificate invalidates its signature, and the
cases below are exactly the ones where a parameter disagrees with the
signature that was actually produced.

RFC 3279 §2.3.1: an `rsaEncryption` key's parameters MUST be NULL.
`rsa-spki-bogus-params` carries an INTEGER there. The key itself is
sound, so an implementation that ignores the parameters accepts a
signature it should have refused.

RFC 4055 §1.2: a key identified by `id-RSASSA-PSS` is restricted to PSS.
`pss-spki-bare` is the same modulus under that OID; offered to a PKCS#1
v1.5 verifier together with `sig-pkcs1v15-sha256`, which that key really
did produce, it must still be refused -- the refusal is about the key's
OID, not about the arithmetic.

RFC 4055 §3.1: the signature's PSS parameters must name one hash for both
the digest and MGF1, and `trailerField` 1. `alg-pss-mgf-sha384-hash-sha256`
names SHA-384 for MGF1 and SHA-256 for the digest, with
`sig-pss-sha256-salt32` -- a signature that really is SHA-256 with
MGF1-SHA-256. An implementation that does not compare the two hashes
verifies it, because the hash it verifies under is the one it read from
`hashAlgorithm`. The disagreement is the only thing wrong with this case,
which is what makes it a test of the comparison.

RFC 4055 §3.1 again: when the *key* carries PSS parameters, the signature
must use that same hash and a salt at least as long.

  pss-spki-sha256-salt32   key says SHA-256, salt >= 32
  pss-spki-sha256-salt48   key says SHA-256, salt >= 48
  pss-spki-sha384-salt48   key says SHA-384, salt >= 48

paired against signatures and parameters that are longer, shorter and of
the wrong hash. Every signature here is genuine for its own parameters,
so each verdict turns on the key-versus-signature comparison and on
nothing else.

RFC 8410 §3: id-Ed25519 takes absent parameters, in the signature
algorithm and in the key. `ed25519-spki-null-params` puts a NULL there
and is otherwise a working key, so an implementation that does not check
accepts `sig-ed25519`, which that key did produce.

SHA-384 is here because the sigalgs corpus has PSS with SHA-256 and
SHA-512 and nothing with SHA-384, which left the SHA-384 arm of the
RFC 4055 §2.1 hash table unreached.

Usage: python3 gen.py   (run from this directory; needs `cryptography`)
"""

import pathlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

HERE = pathlib.Path(__file__).resolve().parent

# --------------------------------------------------------------------------
# A minimal DER writer. The point of these fixtures is to encode shapes a
# certificate builder will not produce, so the encoding is done by hand.
# --------------------------------------------------------------------------


def _len(body: bytes) -> bytes:
    n = len(body)
    if n < 0x80:
        return bytes([n])
    be = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(be)]) + be


def tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _len(body) + body


def seq(*parts: bytes) -> bytes:
    return tlv(0x30, b"".join(parts))


def ctx(num: int, body: bytes) -> bytes:
    """An EXPLICIT context-specific tag; RFC 4055's module is EXPLICIT TAGS."""
    return tlv(0xA0 | num, body)


def integer(value: int) -> bytes:
    if value == 0:
        return tlv(0x02, b"\x00")
    be = value.to_bytes((value.bit_length() + 8) // 8, "big")
    return tlv(0x02, be)


def oid(dotted: str) -> bytes:
    arcs = [int(a) for a in dotted.split(".")]
    body = bytes([arcs[0] * 40 + arcs[1]])
    for arc in arcs[2:]:
        chunk = bytes([arc & 0x7F])
        arc >>= 7
        while arc:
            chunk = bytes([0x80 | (arc & 0x7F)]) + chunk
            arc >>= 7
        body += chunk
    return tlv(0x06, body)


NULL = b"\x05\x00"


def bit_string(body: bytes) -> bytes:
    return tlv(0x03, b"\x00" + body)


OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
OID_RSASSA_PSS = "1.2.840.113549.1.1.10"
OID_MGF1 = "1.2.840.113549.1.1.8"
OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_SHA384 = "2.16.840.1.101.3.4.2.2"
OID_ED25519 = "1.3.101.112"

HASH_OID = {"sha256": OID_SHA256, "sha384": OID_SHA384}
HASH_IMPL = {"sha256": hashes.SHA256(), "sha384": hashes.SHA384()}


def pss_params(digest: str, mgf_digest: str, salt_len: int) -> bytes:
    """RFC 4055 §3.1 RSASSA-PSS-params.

    `trailerField` is left out: 1 is its DEFAULT, and DER forbids encoding
    a value equal to the default. Salt lengths stay away from 20 for the
    same reason.
    """
    assert salt_len != 20, "20 is the DEFAULT saltLength and may not be encoded"
    hash_alg = seq(oid(HASH_OID[digest]), NULL)
    mgf_alg = seq(oid(OID_MGF1), seq(oid(HASH_OID[mgf_digest]), NULL))
    return seq(ctx(0, hash_alg), ctx(1, mgf_alg), ctx(2, integer(salt_len)))


def write(name: str, data: bytes) -> None:
    (HERE / name).write_bytes(data)
    print(f"{name}: {len(data)} bytes")


# --------------------------------------------------------------------------
# The message every signature below is over.
# --------------------------------------------------------------------------

MESSAGE = b"pkix-path algorithm parameter fixtures\n"
write("message.bin", MESSAGE)

# --------------------------------------------------------------------------
# One RSA key, many SubjectPublicKeyInfo wrappers around it.
# --------------------------------------------------------------------------

rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
rsa_pub = rsa_key.public_key()
rsa_pkcs1 = rsa_pub.public_bytes(
    serialization.Encoding.DER, serialization.PublicFormat.PKCS1
)

write("rsa-spki.der", seq(seq(oid(OID_RSA_ENCRYPTION), NULL), bit_string(rsa_pkcs1)))
write(
    "rsa-spki-bogus-params.der",
    seq(seq(oid(OID_RSA_ENCRYPTION), integer(1)), bit_string(rsa_pkcs1)),
)
write("pss-spki-bare.der", seq(seq(oid(OID_RSASSA_PSS)), bit_string(rsa_pkcs1)))
for digest, salt in (("sha256", 32), ("sha256", 48), ("sha384", 48)):
    write(
        f"pss-spki-{digest}-salt{salt}.der",
        seq(
            seq(oid(OID_RSASSA_PSS), pss_params(digest, digest, salt)),
            bit_string(rsa_pkcs1),
        ),
    )

# --------------------------------------------------------------------------
# AlgorithmIdentifiers, including ones that disagree with the signature.
# --------------------------------------------------------------------------

write("alg-sha256-rsa.der", seq(oid(OID_SHA256_WITH_RSA), NULL))
write("alg-pss-no-params.der", seq(oid(OID_RSASSA_PSS)))
for digest, salt in (("sha256", 32), ("sha256", 48), ("sha384", 48)):
    write(
        f"alg-pss-{digest}-salt{salt}.der",
        seq(oid(OID_RSASSA_PSS), pss_params(digest, digest, salt)),
    )
write(
    "alg-pss-mgf-sha384-hash-sha256.der",
    seq(oid(OID_RSASSA_PSS), pss_params("sha256", "sha384", 32)),
)

# --------------------------------------------------------------------------
# Signatures. Each one is genuine for the parameters it is named after.
# --------------------------------------------------------------------------

for digest, salt in (("sha256", 32), ("sha256", 48), ("sha384", 48)):
    write(
        f"sig-pss-{digest}-salt{salt}.bin",
        rsa_key.sign(
            MESSAGE,
            padding.PSS(mgf=padding.MGF1(HASH_IMPL[digest]), salt_length=salt),
            HASH_IMPL[digest],
        ),
    )
write(
    "sig-pkcs1v15-sha256.bin",
    rsa_key.sign(MESSAGE, padding.PKCS1v15(), hashes.SHA256()),
)

# --------------------------------------------------------------------------
# Ed25519: the same key with and without the parameters RFC 8410 forbids.
# --------------------------------------------------------------------------

ed_key = ed25519.Ed25519PrivateKey.generate()
ed_raw = ed_key.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)
write("ed25519-spki.der", seq(seq(oid(OID_ED25519)), bit_string(ed_raw)))
write(
    "ed25519-spki-null-params.der",
    seq(seq(oid(OID_ED25519), NULL), bit_string(ed_raw)),
)
write("alg-ed25519.der", seq(oid(OID_ED25519)))
write("sig-ed25519.bin", ed_key.sign(MESSAGE))
