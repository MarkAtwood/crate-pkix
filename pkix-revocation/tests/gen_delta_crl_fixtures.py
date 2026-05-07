import datetime, os
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

FIXTURES = "/home/mark/PROJECT/PKIX/pkix-revocation/tests/fixtures"
UTC = datetime.timezone.utc
NOT_BEFORE = datetime.datetime(2026, 1, 1, tzinfo=UTC)
NOT_AFTER  = datetime.datetime(2030, 1, 1, tzinfo=UTC)
THIS_2026  = datetime.datetime(2026, 1, 1, tzinfo=UTC)
NEXT_2027  = datetime.datetime(2027, 1, 1, tzinfo=UTC)
REVOKE_DATE = datetime.datetime(2026, 1, 1, tzinfo=UTC)

def write(name, data):
    path = os.path.join(FIXTURES, name)
    with open(path, "wb") as f:
        f.write(data)
    print(f"{name}: {len(data)} bytes")

ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Delta CRL CA")])
ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_name).issuer_name(ca_name)
    .public_key(ca_key.public_key()).serial_number(200)
    .not_valid_before(NOT_BEFORE).not_valid_after(NOT_AFTER)
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .add_extension(x509.KeyUsage(
        digital_signature=True, content_commitment=False, key_encipherment=False,
        data_encipherment=False, key_agreement=False, key_cert_sign=True,
        crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
    .sign(ca_key, hashes.SHA256())
)
write("delta-crl-ca.der", ca_cert.public_bytes(serialization.Encoding.DER))

def make_leaf(serial, cn):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return (x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_name).public_key(key.public_key()).serial_number(serial)
        .not_valid_before(NOT_BEFORE).not_valid_after(NOT_AFTER)
        .sign(ca_key, hashes.SHA256())
    ).public_bytes(serialization.Encoding.DER)

write("delta-crl-leaf-2.der", make_leaf(2, "Delta Leaf serial=2"))
write("delta-crl-leaf-3.der", make_leaf(3, "Delta Leaf serial=3"))
write("delta-crl-leaf-4.der", make_leaf(4, "Delta Leaf serial=4"))

def make_base(serials, crl_num):
    b = (x509.CertificateRevocationListBuilder()
        .issuer_name(ca_name).last_update(THIS_2026).next_update(NEXT_2027)
        .add_extension(x509.CRLNumber(crl_num), critical=False))
    for s in serials:
        b = b.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(s).revocation_date(REVOKE_DATE).build())
    return b.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

def make_delta(entries, base_num, crl_num):
    b = (x509.CertificateRevocationListBuilder()
        .issuer_name(ca_name).last_update(THIS_2026).next_update(NEXT_2027)
        .add_extension(x509.CRLNumber(crl_num), critical=False)
        .add_extension(x509.DeltaCRLIndicator(base_num), critical=True))
    for serial, reason in entries:
        rb = x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(REVOKE_DATE)
        if reason is not None:
            rb = rb.add_extension(x509.CRLReason(reason), critical=False)
        b = b.add_revoked_certificate(rb.build())
    return b.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

write("delta-crl-base.der", make_base([2], 1))
write("delta-crl-delta-add.der", make_delta([(3, None)], base_num=1, crl_num=2))
write("delta-crl-remove.der", make_delta([(2, x509.ReasonFlags.remove_from_crl)], base_num=1, crl_num=2))
write("delta-crl-mixed.der", make_delta([(4, None), (2, x509.ReasonFlags.remove_from_crl)], base_num=1, crl_num=2))
print("Done.")
