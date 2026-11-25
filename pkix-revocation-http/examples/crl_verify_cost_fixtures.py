"""Generate CA + leaf + CRLs of several sizes, to measure how long
synchronous CRL verification takes inside an async fn."""
import datetime, sys, pathlib
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

out = pathlib.Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Bench CA")])
nb = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
na = datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)

ca = (x509.CertificateBuilder()
      .subject_name(name).issuer_name(name)
      .public_key(key.public_key()).serial_number(1)
      .not_valid_before(nb).not_valid_after(na)
      .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
      .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                   key_encipherment=False, data_encipherment=False,
                                   key_agreement=False, key_cert_sign=True,
                                   crl_sign=True, encipher_only=False,
                                   decipher_only=False), critical=True)
      .sign(key, hashes.SHA256()))
(out / "ca.der").write_bytes(ca.public_bytes(serialization.Encoding.DER))

leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
leaf = (x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")]))
        .issuer_name(name).public_key(leaf_key.public_key())
        .serial_number(999_999_999)
        .not_valid_before(nb).not_valid_after(na)
        .add_extension(x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier("http://crl.bench.test/ca.crl")],
                relative_name=None, reasons=None, crl_issuer=None)]), critical=False)
        .sign(key, hashes.SHA256()))
(out / "leaf.der").write_bytes(leaf.public_bytes(serialization.Encoding.DER))

for n in (int(x) for x in sys.argv[2:]):
    b = (x509.CertificateRevocationListBuilder()
         .issuer_name(name)
         .last_update(datetime.datetime(2026, 6, 1, tzinfo=datetime.timezone.utc))
         .next_update(datetime.datetime(2027, 6, 1, tzinfo=datetime.timezone.utc))
         .add_extension(x509.CRLNumber(1), critical=False))
    for i in range(2, n + 2):
        b = b.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(i)
            .revocation_date(datetime.datetime(2026, 5, 1, tzinfo=datetime.timezone.utc))
            .build())
    crl = b.sign(private_key=key, algorithm=hashes.SHA256())
    p = out / f"crl-{n}.der"
    p.write_bytes(crl.public_bytes(serialization.Encoding.DER))
    print(f"{n:>7} entries -> {p.stat().st_size:>9} bytes", flush=True)
