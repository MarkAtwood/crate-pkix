#!/usr/bin/env python3
"""Generate DER fixtures for the review_*.rs regression tests.

Dependencies: Python 3 stdlib + the `openssl` CLI (keys, certificates,
RSA/SHA-256 signing). CRLs and OCSP responses are assembled by hand with
the tiny DER encoder below so every field (times, extensions, criticality)
is pinned and reproducible apart from key material.

Usage:  python3 -I gen_review_fixtures.py
Writes: pkix-revocation/tests/fixtures/review/*
        pkix-revocation-http/tests/fixtures/review/* (copy of the same set)

Time model: CRLs thisUpdate 2026-01-01, nextUpdate 2027-01-01; OCSP
producedAt/thisUpdate 2026-05-31, nextUpdate 2026-06-07. Tests use
NOW = 2026-06-01T00:00:00Z = 1_780_272_000.
"""
import hashlib, os, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "fixtures", "review")
OUT_HTTP = os.path.join(HERE, "..", "..", "pkix-revocation-http", "tests", "fixtures", "review")

# ----------------------------------------------------------------- DER encode
def tlv(tag, body):
    n = len(body)
    if n < 0x80:
        l = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        l = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + l + body

def seq(*items): return tlv(0x30, b"".join(items))
def set_(*items): return tlv(0x31, b"".join(items))
def integer(v):
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=False) if v >= 0 else None
    # minimal encoding
    while len(b) > 1 and b[0] == 0 and b[1] < 0x80:
        b = b[1:]
    return tlv(0x02, b)
def enum(v): return tlv(0x0A, bytes([v]))
def octets(b): return tlv(0x04, b)
def bitstring(b): return tlv(0x03, b"\x00" + b)
def boolean(v): return tlv(0x01, b"\xff" if v else b"\x00")
def null(): return b"\x05\x00"
def oid(dotted):
    parts = [int(p) for p in dotted.split(".")]
    body = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        enc = [p & 0x7F]
        p >>= 7
        while p:
            enc.append(0x80 | (p & 0x7F))
            p >>= 7
        body += bytes(reversed(enc))
    return tlv(0x06, body)
def utctime(s): return tlv(0x17, s.encode())          # "YYMMDDHHMMSSZ"
def gentime(s): return tlv(0x18, s.encode())          # "YYYYMMDDHHMMSSZ"
def ctx(n, body, constructed=True): return tlv((0xA0 if constructed else 0x80) | n, body)
def ext(o, value, critical=False):
    return seq(oid(o), boolean(True) if critical else b"", octets(value))

SHA256_RSA = seq(oid("1.2.840.113549.1.1.11"), null())
SHA256 = seq(oid("2.16.840.1.101.3.4.2.1"), null())

# ----------------------------------------------------------------- DER decode
def parse_tlv(buf, off):
    tag = buf[off]; off += 1
    l = buf[off]; off += 1
    if l & 0x80:
        n = l & 0x7F
        l = int.from_bytes(buf[off:off + n], "big"); off += n
    return tag, buf[off:off + l], off + l, off  # tag, body, end, body_start

def children(body):
    out, off = [], 0
    while off < len(body):
        start = off
        tag, b, off, _ = parse_tlv(body, off)
        out.append((tag, b, body[start:off]))
    return out

def cert_parts(cert_der):
    _, cbody, _, _ = parse_tlv(cert_der, 0)
    tbs = children(cbody)[0]
    f = children(tbs[1])
    i = 1 if f[0][0] == 0xA0 else 0  # skip [0] version
    subject_full = f[i + 4][2]
    spki = children(f[i + 5][1])
    spk_bits = spki[1][1][1:]  # strip unused-bits octet
    return subject_full, spk_bits

# ----------------------------------------------------------------- openssl
TMP = tempfile.mkdtemp(prefix="review-fixtures-")
def run(*args, inp=None):
    return subprocess.run(args, input=inp, check=True, capture_output=True).stdout

def genkey(name):
    p = os.path.join(TMP, name + ".pem")
    run("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", p)
    return p

def sign(key, tbs):
    return run("openssl", "dgst", "-sha256", "-sign", key, inp=tbs)

def write(name, data):
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, name), "wb") as fh:
        fh.write(data)
    print(f"{name}: {len(data)} bytes")

ca_key = genkey("ca")
evil_key = genkey("evil")
leaf_key = genkey("leaf")

ext_ca = os.path.join(TMP, "ca.ext")
with open(ext_ca, "w") as fh:
    fh.write("basicConstraints=critical,CA:TRUE\n"
             "keyUsage=critical,keyCertSign,cRLSign\n"
             "subjectKeyIdentifier=hash\n")
ca_pem = os.path.join(TMP, "ca.crt")
csr = os.path.join(TMP, "ca.csr")
run("openssl", "req", "-new", "-key", ca_key, "-subj", "/CN=Review CA", "-out", csr)
run("openssl", "x509", "-req", "-in", csr, "-signkey", ca_key, "-days", "3650", "-sha256",
    "-set_serial", "1", "-extfile", ext_ca, "-out", ca_pem)
ca_der = run("openssl", "x509", "-in", ca_pem, "-outform", "DER")
write("ca.der", ca_der)

def leaf(serial, cn, extra=""):
    e = os.path.join(TMP, f"leaf{serial}.ext")
    with open(e, "w") as fh:
        fh.write("basicConstraints=critical,CA:FALSE\n"
                 "keyUsage=critical,digitalSignature\n"
                 "crlDistributionPoints=URI:http://crl.review.test/ca.crl\n"
                 "authorityInfoAccess=OCSP;URI:http://ocsp.review.test/\n" + extra)
    c = os.path.join(TMP, f"leaf{serial}.csr")
    run("openssl", "req", "-new", "-key", leaf_key, "-subj", f"/CN={cn}", "-out", c)
    p = os.path.join(TMP, f"leaf{serial}.crt")
    run("openssl", "x509", "-req", "-in", c, "-CA", ca_pem, "-CAkey", ca_key, "-days", "3650",
        "-sha256", "-set_serial", str(serial), "-extfile", e, "-out", p)
    return run("openssl", "x509", "-in", p, "-outform", "DER")

write("leaf-serial2.der", leaf(2, "Review Leaf serial=2 (revoked in base CRL)"))
write("leaf-serial3.der", leaf(3, "Review Leaf serial=3 (never revoked)"))

ca_subject, ca_spk = cert_parts(ca_der)

# ----------------------------------------------------------------- CRLs
THIS = utctime("260101000000Z")
NEXT = utctime("270101000000Z")
FAR = gentime("20990101000000Z")
REV_DATE = utctime("260101000000Z")
OID_CRL_NUMBER = "2.5.29.20"
OID_DELTA = "2.5.29.27"
OID_IDP = "2.5.29.28"
OID_REASON = "2.5.29.21"
OID_UNKNOWN = "1.3.6.1.4.1.55555.1.1"  # private-arc OID nobody recognises

def entry(serial, reason=None, extra_exts=()):
    exts = []
    if reason is not None:
        exts.append(ext(OID_REASON, enum(reason)))
    exts.extend(extra_exts)
    return seq(integer(serial), REV_DATE, seq(*exts) if exts else b"")

def crl(entries, crl_exts, key=ca_key, next_update=NEXT):
    tbs = seq(integer(1), SHA256_RSA, ca_subject, THIS, next_update,
              seq(*entries) if entries else b"",
              ctx(0, seq(*crl_exts)))
    return seq(tbs, SHA256_RSA, bitstring(sign(key, tbs)))

# Complete CRL #1: serial 2 revoked (keyCompromise).
write("base-crl.der", crl([entry(2, 1)], [ext(OID_CRL_NUMBER, integer(1))]))

# Delta CRL #2 against base #1: lists only serial 4. Legitimately signed by
# the CA. Used alone (CrlChecker::new) it hides serial 2's revocation.
write("delta-crl.der", crl([entry(4, 1)],
                           [ext(OID_CRL_NUMBER, integer(2)),
                            ext(OID_DELTA, integer(1), critical=True)]))

# Complete CRL whose entry for serial 99 carries an unrecognised CRITICAL
# entry extension (RFC 5280 §5.3: the CRL MUST NOT be used at all).
write("crl-unknown-critical-entry-ext.der",
      crl([entry(99, 1, [ext(OID_UNKNOWN, null(), critical=True)])],
          [ext(OID_CRL_NUMBER, integer(1))]))

# Delta CRL with an unrecognised CRITICAL CRL extension that "un-revokes"
# serial 2 (removeFromCRL). RFC 5280 §5.2: MUST NOT be used.
write("delta-crl-unknown-critical-ext.der",
      crl([entry(2, 8)],
          [ext(OID_CRL_NUMBER, integer(2)),
           ext(OID_DELTA, integer(1), critical=True),
           ext(OID_UNKNOWN, null(), critical=True)]))

# Delta CRL whose scope (IDP present) differs from the base (IDP absent),
# un-revoking serial 2. RFC 5280 §6.3.3(c)(3): delta must not be used.
idp_other = seq(ctx(0, ctx(0, tlv(0x86, b"http://other.review.test/partition7.crl"))))
write("delta-crl-scope-mismatch.der",
      crl([entry(2, 8)],
          [ext(OID_CRL_NUMBER, integer(2)),
           ext(OID_DELTA, integer(1), critical=True),
           ext(OID_IDP, idp_other, critical=True)]))

# Forged complete CRL: huge CRLNumber, nextUpdate 2099, signed by a key the
# CA never certified. Signature verification MUST fail; used to show that
# the cache stores it anyway.
write("forged-crl.der", crl([], [ext(OID_CRL_NUMBER, integer(1 << 62))],
                            key=evil_key, next_update=FAR))

# ----------------------------------------------------------------- OCSP
def ocsp(serial, status, key=ca_key, next_update="20260607000000Z"):
    name_hash = hashlib.sha256(ca_subject).digest()
    key_hash = hashlib.sha256(ca_spk).digest()
    cert_id = seq(SHA256, octets(name_hash), octets(key_hash), integer(serial))
    if status == "good":
        st = tlv(0x80, b"")
    else:  # revoked, keyCompromise
        st = ctx(1, gentime("20260101000000Z") + ctx(0, enum(1)))
    single = seq(cert_id, st, gentime("20260531000000Z"), ctx(0, gentime(next_update)))
    tbs = seq(ctx(1, ca_subject), gentime("20260531000000Z"), seq(single))
    basic = seq(tbs, SHA256_RSA, bitstring(sign(key, tbs)))
    return seq(enum(0), ctx(0, seq(oid("1.3.6.1.5.5.7.48.1.1"), octets(basic))))

write("ocsp-serial2-revoked.der", ocsp(2, "revoked"))
write("ocsp-forged-serial2-good.der", ocsp(2, "good", key=evil_key, next_update="20990101000000Z"))

shutil.rmtree(TMP)
os.makedirs(OUT_HTTP, exist_ok=True)
for f in os.listdir(OUT):
    shutil.copy(os.path.join(OUT, f), os.path.join(OUT_HTTP, f))
print("copied to", os.path.normpath(OUT_HTTP))
