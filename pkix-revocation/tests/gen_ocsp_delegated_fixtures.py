#!/usr/bin/env python3
"""Generate DER-encoded OCSP response fixtures for delegated-responder
testing (PKIX-53kt).

Oracle: pyca/cryptography (external to the Rust code under test).
Run once; outputs are committed as binary fixtures.

Generates a self-contained CA + leaf + responder-cert family of fixtures
distinct from gen_ocsp_fixtures.py's keys (CA keys are ephemeral so the
two scripts cannot share an issuer cert across runs).

Fixture set produced:

  ocsp-delegated-ca.der                — CA cert (issuer of leaf and delegate)
  ocsp-delegated-leaf.der              — leaf cert under check
  ocsp-delegated-good.der              — valid delegated OCSP response
                                         (responder cert in basic.certs has
                                         OCSPSigning EKU, signed by CA, valid)
  ocsp-delegated-no-eku.der            — responder cert lacks OCSPSigning EKU
  ocsp-delegated-wrong-ca.der          — responder cert signed by a different CA
                                         (rogue OCSP responder rejection)
  ocsp-delegated-expired-cert.der      — responder cert validity ends before
                                         producedAt
  ocsp-delegated-bad-sig.der           — issuer's signature on responder cert
                                         is corrupted (tampered DER)
"""

import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
UTC = datetime.timezone.utc

# Match the time anchors used by gen_ocsp_fixtures.py so a single NOW value
# in tests covers both fixture families.
NOT_BEFORE = datetime.datetime(2026, 1, 1, tzinfo=UTC)
NOT_AFTER = datetime.datetime(2030, 1, 1, tzinfo=UTC)
PRODUCED_AT = datetime.datetime(2026, 1, 1, tzinfo=UTC)
NEXT_UPDATE = datetime.datetime(2027, 1, 1, tzinfo=UTC)

# A responder cert that has expired before PRODUCED_AT — used to exercise
# the OcspResponderCertExpired error variant.
RESPONDER_EXPIRED_BEFORE = datetime.datetime(2024, 1, 1, tzinfo=UTC)
RESPONDER_EXPIRED_AFTER = datetime.datetime(2025, 6, 1, tzinfo=UTC)


def gen_rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def write(name: str, data: bytes) -> None:
    path = os.path.join(FIXTURES, name)
    with open(path, "wb") as f:
        f.write(data)
    print(f"{name}: {len(data)} bytes")


def make_ca(common_name: str, key) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(100)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
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
        .sign(key, hashes.SHA256())
    )


def make_leaf(serial: int, cn: str, ca_name: x509.Name, ca_key) -> x509.Certificate:
    leaf_key = gen_rsa()
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(serial)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .sign(ca_key, hashes.SHA256())
    )


def make_responder_cert(
    cn: str,
    issuer_name: x509.Name,
    issuer_key,
    serial: int,
    *,
    not_before: datetime.datetime = NOT_BEFORE,
    not_after: datetime.datetime = NOT_AFTER,
    include_ocsp_signing: bool = True,
    responder_key=None,
) -> tuple[x509.Certificate, object]:
    """Build a responder cert (and its keypair) signed by `issuer_key`.

    When `include_ocsp_signing=True`, the cert carries a critical
    ExtendedKeyUsage extension with the id-kp-OCSPSigning OID.
    """
    if responder_key is None:
        responder_key = gen_rsa()
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(issuer_name)
        .public_key(responder_key.public_key())
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if include_ocsp_signing:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),
            critical=False,
        )
    cert = builder.sign(issuer_key, hashes.SHA256())
    return cert, responder_key


def sign_ocsp_delegated(
    leaf: x509.Certificate,
    issuer: x509.Certificate,
    responder_cert: x509.Certificate,
    responder_key,
    *,
    produced_at: datetime.datetime = PRODUCED_AT,
    next_update: datetime.datetime = NEXT_UPDATE,
) -> bytes:
    """Build a delegated OCSP response.

    The response's `certs` field embeds `responder_cert` and the response
    signature is produced by `responder_key`. The ResponderId is set to
    the responder cert's name (byName encoding).
    """
    builder = (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=leaf,
            issuer=issuer,
            algorithm=hashes.SHA256(),
            cert_status=ocsp.OCSPCertStatus.GOOD,
            this_update=produced_at,
            next_update=next_update,
            revocation_time=None,
            revocation_reason=None,
        )
        .responder_id(ocsp.OCSPResponderEncoding.NAME, responder_cert)
        .certificates([responder_cert])
    )
    response = builder.sign(responder_key, hashes.SHA256())
    return response.public_bytes(serialization.Encoding.DER)


# ===========================================================================
# Main CA + leaf
# ===========================================================================
ca_key = gen_rsa()
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OCSP Delegated Test CA")])
ca_cert = make_ca("OCSP Delegated Test CA", ca_key)
write("ocsp-delegated-ca.der", ca_cert.public_bytes(serialization.Encoding.DER))

leaf = make_leaf(1, "OCSP Delegated Test Leaf", ca_name, ca_key)
write("ocsp-delegated-leaf.der", leaf.public_bytes(serialization.Encoding.DER))

# ===========================================================================
# Good delegated response
# ===========================================================================
responder_cert, responder_key = make_responder_cert(
    "OCSP Delegated Responder",
    ca_name,
    ca_key,
    serial=200,
    include_ocsp_signing=True,
)
write(
    "ocsp-delegated-good.der",
    sign_ocsp_delegated(leaf, ca_cert, responder_cert, responder_key),
)

# ===========================================================================
# No-EKU: responder cert lacks id-kp-OCSPSigning
# ===========================================================================
responder_no_eku, key_no_eku = make_responder_cert(
    "OCSP Responder No EKU",
    ca_name,
    ca_key,
    serial=201,
    include_ocsp_signing=False,
)
write(
    "ocsp-delegated-no-eku.der",
    sign_ocsp_delegated(leaf, ca_cert, responder_no_eku, key_no_eku),
)

# ===========================================================================
# Wrong-CA: responder cert signed by a DIFFERENT CA than `leaf`'s issuer
# ===========================================================================
rogue_ca_key = gen_rsa()
rogue_ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Rogue Other CA")])
rogue_ca_cert = make_ca("Rogue Other CA", rogue_ca_key)
# Note: the responder cert's issuer name is the rogue CA, NOT ca_name.
responder_rogue, key_rogue = make_responder_cert(
    "OCSP Responder Wrong CA",
    rogue_ca_name,
    rogue_ca_key,
    serial=202,
    include_ocsp_signing=True,
)
# Leaf is still signed by the legitimate CA; the response is for the legitimate
# leaf's CertID, but the responder cert is from a different CA family.
write(
    "ocsp-delegated-wrong-ca.der",
    sign_ocsp_delegated(leaf, ca_cert, responder_rogue, key_rogue),
)

# ===========================================================================
# Expired-cert: responder cert validity ends before producedAt
# ===========================================================================
responder_expired, key_expired = make_responder_cert(
    "OCSP Responder Expired",
    ca_name,
    ca_key,
    serial=203,
    not_before=RESPONDER_EXPIRED_BEFORE,
    not_after=RESPONDER_EXPIRED_AFTER,
    include_ocsp_signing=True,
)
write(
    "ocsp-delegated-expired-cert.der",
    sign_ocsp_delegated(leaf, ca_cert, responder_expired, key_expired),
)

# ===========================================================================
# Bad-sig: issuer's signature on responder cert is corrupted
#
# Build a valid delegated response, then locate the embedded responder cert
# in the final DER and flip a byte in its signature region. We use a tagged
# marker by setting a unique serial and finding it.
# ===========================================================================
# We can't easily flip just the responder cert's signature without re-
# encoding. Approach: build the response normally, then find the responder
# cert's signature byte range by re-encoding the responder cert and locating
# its signature suffix in the response DER.
responder_for_badsig, key_for_badsig = make_responder_cert(
    "OCSP Responder BadSig",
    ca_name,
    ca_key,
    serial=204,
    include_ocsp_signing=True,
)
good_response = sign_ocsp_delegated(
    leaf, ca_cert, responder_for_badsig, key_for_badsig
)

# The responder cert is embedded as DER in the response's `certs` field.
# Locate it by its full DER and tamper with the LAST byte of its signature
# (which is the last byte of the embedded cert's DER).
responder_der = responder_for_badsig.public_bytes(serialization.Encoding.DER)
idx = good_response.find(responder_der)
if idx < 0:
    raise SystemExit(
        "could not locate embedded responder cert DER in OCSP response — "
        "pyca embedding format may have changed"
    )
end = idx + len(responder_der)  # last byte of cert DER = last byte of signature
tampered = bytearray(good_response)
tampered[end - 1] ^= 0xFF
# Tampering the signature of the embedded responder cert leaves the OUTER
# OCSP response signature intact (because the OCSP signature only covers
# tbs_response_data, not the embedded certs). The only check that fires
# is the issuer-on-responder-cert signature check inside the delegated
# validation path.
write("ocsp-delegated-bad-sig.der", bytes(tampered))
