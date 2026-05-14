#!/usr/bin/env python3
"""Generate S/MIME tier-validated test fixtures for CA/B Forum S/MIME BR sub-profiles.

This is a sibling generator to `gen.py`, isolated so that adding a new tier
fixture does not regenerate the unrelated fixtures in `gen.py`'s output set.
Same convention as `gen-sc081-fixtures.py` (separate script for SC-081 cases).

Fixtures produced (PKIX-jbvb.3, Individual-validated tier):

  smime-individual-validated-self-signed-365d.der
    Self-signed P-256 cert with:
    - Subject DN: C=GB, givenName=Test, surname=Person,
                  serialNumber=ABCD1234, CN=Test Person
    - CertificatePolicies: 2.23.140.1.5.4.1 (Individual-validated)
    - rfc822Name SAN: individual@example.com
    - emailProtection EKU
    - 365-day validity (notBefore 2026-01-01)
    - cA=TRUE (self-signed anchor pattern matches existing smime-self-signed-365d.der)

  smime-individual-pseudonym-self-signed-365d.der
    Self-signed P-256 cert with:
    - Subject DN: C=GB, pseudonym=TestBox, serialNumber=EFGH5678, CN=TestBox
    - CertificatePolicies: 2.23.140.1.5.4.1 (Individual-validated)
    - rfc822Name SAN: testbox@example.com
    - emailProtection EKU
    - 365-day validity, cA=TRUE
    - Exercises the `AnyOf(pseudonym, AllOf(givenName, surname))` branch
      of `pkix_path::DnAttrRule` for the Individual-validated tier.

# Provenance

Modeled after zlint's `smime_leg1_iv_eff1.pem` (Individual-validated tier
marker: policy OID 2.23.140.1.5.4.1) but with the BR-mandated Subject DN
attributes that zlint's published fixture omits. zlint's published fixture
has only `C=GB, CN=Leon Mandrake`; no givenName/surname/pseudonym/serialNumber.
The workspace fixtures include the full DN attribute shape required by CA/B
Forum S/MIME BR §7.6 (Individual Validated) so that pkix-path's
`required_leaf_subject_dn_attrs` check has the attribute coverage it tests
for. pkilint's `tests/integration_certificates/cabf/smime/` was checked but
not cloned at fixture-authoring time; modeling-against parity is documented
on the assertion that pkilint classifies Individual-validated certs by the
same policy-OID + DN-attr criteria.

# Oracle

`openssl x509 -inform DER -text -noout < <file>.der` exposes:
  - Subject (multi-attribute DN)
  - X509v3 Subject Alternative Name: email:<addr>
  - X509v3 Extended Key Usage: E-mail Protection
  - X509v3 Certificate Policies: Policy: 2.23.140.1.5.4.1
  - X509v3 Basic Constraints: critical, CA:TRUE

# Re-running

Re-running this script generates new random keys; the existing fixture bytes
will change. Tests assert structural properties (cert.subject contains
expected OIDs, policy OID is asserted, EKU/SAN shape) so byte-level changes
are safe.
"""

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

OUT = Path(__file__).parent

# Match gen.py's time convention so GRY_NOW = 2026-06-01 is within window.
NOT_BEFORE = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
NOT_AFTER_365 = NOT_BEFORE + datetime.timedelta(days=365)

# Independent serial counter (does not interleave with gen.py's counter so the
# two scripts can run in either order without serial collisions).
_serial = 100


def next_serial():
    global _serial
    s = _serial
    _serial += 1
    return s


# CA/B Forum S/MIME BR reserved policy OIDs (§7.1.6.1 / Appendix A).
SMIME_INDIVIDUAL_VALIDATED_POLICY = x509.ObjectIdentifier("2.23.140.1.5.4.1")


def make_tier_cert(filename, subject_attrs, policy_oid, rfc822_san_email):
    """Build a self-signed S/MIME tier cert for use as both anchor and leaf.

    Uses the self-signed-anchor pattern from gen.py's smime_self_signed:
    cA=TRUE on the leaf so it can serve as its own trust anchor in tests
    without needing a separate CA chain.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(subject_attrs)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(next_serial())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER_365)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
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
        .add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name(rfc822_san_email)]),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=False,
        )
        .add_extension(
            x509.CertificatePolicies(
                [
                    x509.PolicyInformation(
                        policy_identifier=policy_oid, policy_qualifiers=None
                    ),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    path = OUT / filename
    path.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    print(f"  wrote {path} ({path.stat().st_size} bytes)")


# ---------------------------------------------------------------------------
# Individual-validated tier (PKIX-jbvb.3) — CA/B Forum S/MIME BR §7.6
#
# Subject DN rule:
#   AllOf:
#     AnyOf: pseudonym OR (givenName + surname)
#     serialNumber
# ---------------------------------------------------------------------------

# Form 1: givenName + surname + serialNumber (most common Individual-validated shape).
make_tier_cert(
    "smime-individual-validated-self-signed-365d.der",
    [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
        x509.NameAttribute(NameOID.GIVEN_NAME, "Test"),
        x509.NameAttribute(NameOID.SURNAME, "Person"),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, "ABCD1234"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Test Person"),
    ],
    SMIME_INDIVIDUAL_VALIDATED_POLICY,
    "individual@example.com",
)

# Form 2: pseudonym + serialNumber. Exercises the AnyOf branch.
make_tier_cert(
    "smime-individual-pseudonym-self-signed-365d.der",
    [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
        x509.NameAttribute(NameOID.PSEUDONYM, "TestBox"),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, "EFGH5678"),
        x509.NameAttribute(NameOID.COMMON_NAME, "TestBox"),
    ],
    SMIME_INDIVIDUAL_VALIDATED_POLICY,
    "testbox@example.com",
)

print("done")
