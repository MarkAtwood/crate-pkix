#!/usr/bin/env python3
"""Prepend a raw DER Extension to a certificate's extension list and re-sign.

Stdlib only; signing is delegated to `openssl dgst -sha256 -sign`, so the
issuer key must be ECDSA or RSA-PKCS#1 v1.5 matching the cert's existing
signatureAlgorithm (which is preserved).

usage: prepend_ext.py IN.der ISSUER.key EXT_HEX OUT.der
"""
import subprocess, sys, tempfile, os

def tlv(buf, off):
    tag = buf[off]; off += 1
    n = buf[off]; off += 1
    if n & 0x80:
        k = n & 0x7f
        n = int.from_bytes(buf[off:off + k], "big"); off += k
    return tag, off, n  # tag, value offset, value length

def enc(tag, body):
    n = len(body)
    if n < 0x80:
        ln = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        ln = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + ln + body

def children(buf, off, end):
    out = []
    while off < end:
        t, v, n = tlv(buf, off)
        out.append(buf[off:v + n]); off = v + n
    return out

src, key, ext_hex, dst = sys.argv[1:]
cert = open(src, "rb").read()
_, cv, cn = tlv(cert, 0)
tbs, algid, sig = children(cert, cv, cv + cn)
_, tv, tn = tlv(tbs, 0)
fields = children(tbs, tv, tv + tn)
assert fields[-1][0] == 0xA3, "last TBS field must be [3] extensions"
_, ev, en = tlv(fields[-1], 0)
seq = fields[-1][ev:ev + en]
_, sv, sn = tlv(seq, 0)
exts = children(seq, sv, sv + sn)
exts.insert(0, bytes.fromhex(ext_hex))
fields[-1] = enc(0xA3, enc(0x30, b"".join(exts)))
new_tbs = enc(0x30, b"".join(fields))
with tempfile.TemporaryDirectory() as d:
    p = os.path.join(d, "tbs")
    open(p, "wb").write(new_tbs)
    s = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key, p],
                       check=True, capture_output=True).stdout
open(dst, "wb").write(enc(0x30, new_tbs + algid + enc(0x03, b"\x00" + s)))
