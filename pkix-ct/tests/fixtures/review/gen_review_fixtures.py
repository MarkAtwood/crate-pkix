#!/usr/bin/env python3
"""Generate review fixtures for pkix-ct (stdlib + `openssl` CLI only).

Inputs (existing, committed oracle fixtures in ../sct-oracle/):
  precert-leaf-final.der   final leaf with one embedded precert SCT
  precert-issuer-key.pem   issuer ECDSA P-256 key (re-signs the leaf)
  precert-log-spki.der     log SPKI that signed the SCT
  precert-sct.bin          wire-format SCT (timestamp 2025-06-16T00:00:00Z)

Outputs (this directory):
  leaf-dup-sct.der   The same leaf, but its SCT-list extension carries
                     the *same* SCT twice. TBS-minus-SCT-list is byte-
                     identical to the original, so both copies verify;
                     the cert is re-signed by the real issuer key with
                     `openssl dgst -sha256 -sign` so it is a validly
                     issued certificate, not a tampered one.
  log-list-retired.json / log-list-readonly.json
                     Google v3 log_list.json with the oracle log in the
                     `retired` / `readonly` state at 2025-09-01T00:00:00Z
                     (after the SCT timestamp).

Run:  python3 gen_review_fixtures.py
"""
import base64, hashlib, json, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ORACLE = HERE.parent / "sct-oracle"
SCT_LIST_OID = bytes.fromhex("060a2b06010401d679020402")


def read_tlv(b, i):
    tag = b[i]; i += 1
    l = b[i]; i += 1
    if l & 0x80:
        n = l & 0x7F
        l = int.from_bytes(b[i:i + n], "big"); i += n
    return tag, i, l  # tag, content start, content length


def children(b):
    out, i = [], 0
    while i < len(b):
        tag, s, l = read_tlv(b, i)
        out.append((tag, b[i:s + l], b[s:s + l]))
        i = s + l
    return out


def enc_len(n):
    if n < 0x80:
        return bytes([n])
    nb = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(nb)]) + nb


def tlv(tag, content):
    return bytes([tag]) + enc_len(len(content)) + content


def u16(n):
    return n.to_bytes(2, "big")


def make_dup_leaf():
    leaf = (ORACLE / "precert-leaf-final.der").read_bytes()
    sct = (ORACLE / "precert-sct.bin").read_bytes()
    _, s, l = read_tlv(leaf, 0)
    tbs_full, sigalg_full, _ = [c[1] for c in children(leaf[s:s + l])]
    _, ts, tl = read_tlv(tbs_full, 0)
    tbs_kids = children(tbs_full[ts:ts + tl])
    new_kids = []
    for tag, full, content in tbs_kids:
        if tag == 0xA3:
            (_, _, exts_content), = children(content)
            new_exts = []
            for _, ext_full, ext_content in children(exts_content):
                if ext_content.startswith(SCT_LIST_OID):
                    one = u16(len(sct)) + sct
                    body = one + one  # the SAME SCT twice
                    sct_list = u16(len(body)) + body
                    ext_full = tlv(0x30, SCT_LIST_OID + tlv(0x04, tlv(0x04, sct_list)))
                new_exts.append(ext_full)
            full = tlv(0xA3, tlv(0x30, b"".join(new_exts)))
        new_kids.append(full)
    new_tbs = tlv(0x30, b"".join(new_kids))
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "tbs.der"
        p.write_bytes(new_tbs)
        sig = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(ORACLE / "precert-issuer-key.pem"), str(p)],
            check=True, capture_output=True).stdout
    cert = tlv(0x30, new_tbs + sigalg_full + tlv(0x03, b"\x00" + sig))
    (HERE / "leaf-dup-sct.der").write_bytes(cert)


def make_log_lists():
    spki = (ORACLE / "precert-log-spki.der").read_bytes()
    for state in ("retired", "readonly"):
        doc = {
            "version": "review",
            "log_list_timestamp": "2025-10-01T00:00:00Z",
            "operators": [{
                "name": "review-operator",
                "email": [],
                "logs": [{
                    "description": f"precert-oracle ({state})",
                    "log_id": base64.b64encode(hashlib.sha256(spki).digest()).decode(),
                    "key": base64.b64encode(spki).decode(),
                    "url": "https://example.invalid/ct/",
                    "mmd": 86400,
                    "state": {state: {"timestamp": "2025-09-01T00:00:00Z"}},
                }],
            }],
        }
        (HERE / f"log-list-{state}.json").write_text(json.dumps(doc, indent=2) + "\n")


if __name__ == "__main__":
    make_dup_leaf()
    make_log_lists()
    sys.exit(0)
