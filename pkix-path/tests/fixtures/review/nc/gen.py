#!/usr/bin/env python3
"""Generate review fixtures for pkix-path NameConstraints / DN tests.

Stdlib-only DER builder; signatures come from the `openssl` CLI
(ECDSA P-256 / SHA-256). Keys are generated on first run and kept next
to the certs (`*.key.pem`) so reruns are reproducible apart from ECDSA
nonce randomness. Validity: 2000-01-01 .. 2050-01-01.

Run:  python3 -I gen.py   (from any directory; writes next to this file)

Every chain is  root (anchor, no NC)  ->  int1 [-> int2]  ->  leaf.
See README.md for the scenario table.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------- DER
def der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, content):
    return bytes([tag]) + der_len(len(content)) + content


def seq(*items):
    return tlv(0x30, b"".join(items))


def set_of(items):
    return tlv(0x31, b"".join(sorted(items)))


def integer(v):
    b = v.to_bytes((v.bit_length() + 8) // 8 or 1, "big")
    return tlv(0x02, b)


def oid(dotted):
    parts = [int(x) for x in dotted.split(".")]
    body = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        body += bytes(reversed(chunk))
    return tlv(0x06, body)


def boolean(v):
    return tlv(0x01, b"\xff" if v else b"\x00")


def octet(b):
    return tlv(0x04, b)


def bitstring(b, unused=0):
    return tlv(0x03, bytes([unused]) + b)


UTF8, PRINTABLE, IA5, BMP = 0x0C, 0x13, 0x16, 0x1E

OID_CN = "2.5.4.3"
OID_O = "2.5.4.10"
OID_C = "2.5.4.6"
OID_EMAIL = "1.2.840.113549.1.9.1"


def ava(o, tag, value):
    if isinstance(value, str):
        value = value.encode("utf-16-be" if tag == BMP else "utf-8")
    return seq(oid(o), tlv(tag, value))


def name(rdns):
    """rdns: list of lists of (oid, tag, value)."""
    return seq(*[set_of([ava(*a) for a in rdn]) for rdn in rdns])


def simple_name(cn, o="Review"):
    return name([[(OID_C, PRINTABLE, "US")], [(OID_O, UTF8, o)], [(OID_CN, UTF8, cn)]])


# GeneralName encoders (implicit context tags)
def gn_dns(s):
    return tlv(0x82, s.encode())


def gn_email(s):
    return tlv(0x81, s.encode())


def gn_uri(s):
    return tlv(0x86, s.encode())


def gn_ip(b):
    return tlv(0x87, b)


def gn_dirname(n):
    return tlv(0xA4, n)


def gn_other(type_oid, inner):
    # OtherName ::= SEQUENCE { type-id OID, value [0] EXPLICIT ANY }
    return tlv(0xA0, oid(type_oid) + tlv(0xA0, inner))


def ext(o, critical, value):
    parts = [oid(o)]
    if critical:
        parts.append(boolean(True))
    parts.append(octet(value))
    return seq(*parts)


def ext_bc(ca):
    return ext("2.5.29.19", True, seq(boolean(True)) if ca else seq())


def ext_ku(ca):
    # keyCertSign|cRLSign (bits 5,6) for CA; digitalSignature (bit 0) for leaf
    return ext("2.5.29.15", True, bitstring(b"\x06", 1) if ca else bitstring(b"\x80", 7))


def ext_san(names, critical=False):
    return ext("2.5.29.17", critical, seq(*names))


def ext_nc(permitted=None, excluded=None):
    body = b""
    if permitted is not None:
        body += tlv(0xA0, b"".join(seq(g) for g in permitted))
    if excluded is not None:
        body += tlv(0xA1, b"".join(seq(g) for g in excluded))
    return ext("2.5.29.30", True, seq(body))


ECDSA_SHA256 = seq(oid("1.2.840.10045.4.3.2"))
VALIDITY = seq(tlv(0x17, b"000101000000Z"), tlv(0x18, b"20500101000000Z"))


# ---------------------------------------------------------------- keys
def key(label):
    path = os.path.join(HERE, f"{label}.key.pem")
    if not os.path.exists(path):
        subprocess.run(
            ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", path],
            check=True,
        )
    spki = subprocess.run(
        ["openssl", "pkey", "-in", path, "-pubout", "-outform", "DER"],
        check=True,
        capture_output=True,
    ).stdout
    return path, spki


def sign(key_path, data):
    return subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", key_path],
        input=data,
        check=True,
        capture_output=True,
    ).stdout


_serial = [1000]


def cert(subject, issuer, spki, issuer_key, exts):
    _serial[0] += 1
    tbs = seq(
        tlv(0xA0, integer(2)),
        integer(_serial[0]),
        ECDSA_SHA256,
        issuer,
        VALIDITY,
        subject,
        spki,
        tlv(0xA3, seq(*exts)),
    )
    sig = sign(issuer_key, tbs)
    return seq(tbs, ECDSA_SHA256, bitstring(sig))


def write(fname, der):
    with open(os.path.join(HERE, fname), "wb") as f:
        f.write(der)


# ---------------------------------------------------------------- PKI
ROOT_KEY, ROOT_SPKI = key("root")
ROOT_NAME = simple_name("Review Root")
write("root.der", cert(ROOT_NAME, ROOT_NAME, ROOT_SPKI, ROOT_KEY, [ext_bc(True), ext_ku(True)]))

INT1_KEY, INT1_SPKI = key("int1")
INT2_KEY, INT2_SPKI = key("int2")
LEAF_KEY, LEAF_SPKI = key("leaf")


def scenario(tag, nc1, leaf_exts, nc2=None, leaf_subject=None):
    """Write <tag>_int1.der [<tag>_int2.der] <tag>_leaf.der."""
    n1 = simple_name(f"{tag} int1")
    write(
        f"{tag}_int1.der",
        cert(n1, ROOT_NAME, INT1_SPKI, ROOT_KEY, [ext_bc(True), ext_ku(True), nc1]),
    )
    issuer_name, issuer_key = n1, INT1_KEY
    if nc2 is not None:
        n2 = simple_name(f"{tag} int2")
        write(
            f"{tag}_int2.der",
            cert(n2, n1, INT2_SPKI, INT1_KEY, [ext_bc(True), ext_ku(True), nc2]),
        )
        issuer_name, issuer_key = n2, INT2_KEY
    subj = leaf_subject if leaf_subject is not None else simple_name(f"{tag} leaf")
    write(
        f"{tag}_leaf.der",
        cert(subj, issuer_name, LEAF_SPKI, issuer_key, [ext_bc(False), ext_ku(False)] + leaf_exts),
    )


UPN = "1.3.6.1.4.1.311.20.2.3"
SMTP_UTF8 = "1.3.6.1.5.5.7.8.9"

# --- controls (must already be rejected / accepted today)
scenario("ctl_dns_excl", ext_nc(excluded=[gn_dns("evil.com")]), [ext_san([gn_dns("www.evil.com")])])
scenario("ctl_uri_perm", ext_nc(permitted=[gn_uri("good.com")]), [ext_san([gn_uri("https://good.com/x")])])
scenario("ctl_uri_bad", ext_nc(permitted=[gn_uri("good.com")]), [ext_san([gn_uri("https://evil.com/x")])])
scenario("ctl_ip_single", ext_nc(permitted=[gn_ip(bytes([10, 0, 0, 0, 255, 0, 0, 0]))]),
         [ext_san([gn_ip(bytes([10, 1, 2, 3]))])])
scenario("ctl_rfc822_perm", ext_nc(permitted=[gn_email("example.com")]),
         [ext_san([gn_email("alice@evil.com")])])

# --- B: trailing-dot dNSName escapes an excluded subtree
scenario("dns_trailing_dot", ext_nc(excluded=[gn_dns("evil.com")]), [ext_san([gn_dns("www.evil.com.")])])
# --- B: empty excluded dNSName ("exclude every DNS name") is ignored
scenario("dns_empty_excluded", ext_nc(excluded=[gn_dns("")]), [ext_san([gn_dns("www.example.com")])])
# --- B: URI host taken from text after an '@' in the *path*
scenario("uri_at_in_path_perm", ext_nc(permitted=[gn_uri("good.com")]),
         [ext_san([gn_uri("https://evil.com/@good.com")])])
scenario("uri_at_in_path_excl", ext_nc(excluded=[gn_uri("evil.com")]),
         [ext_san([gn_uri("https://evil.com/a@b.example")])])
# --- B: URI with no authority / IP host must be rejected when URI constraints exist
scenario("uri_no_authority", ext_nc(excluded=[gn_uri(".evil.com")]), [ext_san([gn_uri("urn:example:evil")])])
scenario("uri_ip_host", ext_nc(excluded=[gn_uri(".evil.com")]), [ext_san([gn_uri("https://192.0.2.1/")])])
# --- B: SmtpUTF8Mailbox otherName escapes an rfc822Name permitted subtree (RFC 8398 s6)
scenario("smtputf8_vs_rfc822", ext_nc(permitted=[gn_email("example.com")]),
         [ext_san([gn_other(SMTP_UTF8, tlv(UTF8, b"alice@evil.com"))])])
# --- B: critical NC with an otherName form is silently ignored
scenario("othername_excluded", ext_nc(excluded=[gn_other(UPN, tlv(UTF8, b"admin@corp.example"))]),
         [ext_san([gn_other(UPN, tlv(UTF8, b"admin@corp.example"))])])
scenario("othername_permitted", ext_nc(permitted=[gn_other(UPN, tlv(UTF8, b"user@corp.example"))]),
         [ext_san([gn_other(UPN, tlv(UTF8, b"admin@other.example"))])])
# --- B: quoted local-part containing '@' hides the real domain from rfc822 exclusion
scenario("rfc822_quoted_at", ext_nc(excluded=[gn_email("evil.com")]),
         [ext_san([gn_email('"x@good.com"@evil.com')])])
# --- B: emailAddress AVA not encoded as IA5String skips the rfc822 check
scenario("dn_email_utf8", ext_nc(permitted=[gn_email("example.com")]), [],
         leaf_subject=name([[(OID_C, PRINTABLE, "US")], [(OID_CN, UTF8, "leaf")],
                            [(OID_EMAIL, UTF8, "alice@evil.com")]]))
# --- B: permitted-subtree intersection empties IP / URI / rfc822 host forms
ip10 = gn_ip(bytes([10, 0, 0, 0, 255, 0, 0, 0]))
scenario("ip_intersect", ext_nc(permitted=[ip10]), [ext_san([gn_ip(bytes([10, 1, 2, 3]))])],
         nc2=ext_nc(permitted=[ip10]))
scenario("uri_intersect", ext_nc(permitted=[gn_uri("example.com")]),
         [ext_san([gn_uri("https://example.com/x")])], nc2=ext_nc(permitted=[gn_uri("example.com")]))
scenario("rfc822_intersect", ext_nc(permitted=[gn_email(".example.com")]),
         [ext_san([gn_email("a@host.example.com")])], nc2=ext_nc(permitted=[gn_email("host.example.com")]))

# --- positive / negative companions for the fixes
scenario("smtputf8_ok", ext_nc(permitted=[gn_email("example.com")]),
         [ext_san([gn_other(SMTP_UTF8, tlv(UTF8, "\u00fc@example.com".encode()))])])
scenario("smtputf8_excluded", ext_nc(excluded=[gn_email("evil.com")]),
         [ext_san([gn_other(SMTP_UTF8, tlv(UTF8, "\u00fc@evil.com".encode()))])])
scenario("smtputf8_idn_domain", ext_nc(permitted=[gn_email("example.com")]),
         [ext_san([gn_other(SMTP_UTF8, tlv(UTF8, "\u00fc@b\u00fccher.example".encode()))])])
scenario("othername_unconstrained", ext_nc(permitted=[gn_dns("example.com")]),
         [ext_san([gn_dns("www.example.com"), gn_other(UPN, tlv(UTF8, b"admin@corp.example"))])])
scenario("uri_userinfo_ok", ext_nc(permitted=[gn_uri("good.com")]),
         [ext_san([gn_uri("https://user:pw@good.com:8443/p@q?x=@y#@z")])])
scenario("uri_ipv6_host", ext_nc(excluded=[gn_uri(".evil.com")]), [ext_san([gn_uri("https://[2001:db8::1]/")])])
scenario("uri_trailing_dot", ext_nc(excluded=[gn_uri("evil.com")]), [ext_san([gn_uri("https://evil.com./")])])
scenario("dns_trailing_dot_permitted", ext_nc(permitted=[gn_dns("good.com")]), [ext_san([gn_dns("www.good.com.")])])
scenario("dns_wildcard_trailing_dot", ext_nc(excluded=[gn_dns("evil.com")]), [ext_san([gn_dns("*.evil.com.")])])
scenario("rfc822_quoted_at_ok", ext_nc(permitted=[gn_email("good.com")]),
         [ext_san([gn_email('"x@evil.com"@good.com')])])
scenario("dns_dot_intersect", ext_nc(permitted=[gn_dns("example.com")]),
         [ext_san([gn_dns("www.example.com")])], nc2=ext_nc(permitted=[gn_dns(".example.com")]))
scenario("ip_intersect_narrow_out", ext_nc(permitted=[ip10]), [ext_san([gn_ip(bytes([10, 2, 0, 1]))])],
         nc2=ext_nc(permitted=[gn_ip(bytes([10, 1, 0, 0, 255, 255, 0, 0]))]))
scenario("ip_intersect_narrow_in", ext_nc(permitted=[ip10]), [ext_san([gn_ip(bytes([10, 1, 9, 9]))])],
         nc2=ext_nc(permitted=[gn_ip(bytes([10, 1, 0, 0, 255, 255, 0, 0]))]))
scenario("uri_intersect_disjoint", ext_nc(permitted=[gn_uri("a.example.com")]),
         [ext_san([gn_uri("https://a.example.com/")])], nc2=ext_nc(permitted=[gn_uri("b.example.com")]))
scenario("rfc822_intersect_mailbox", ext_nc(permitted=[gn_email(".example.com")]),
         [ext_san([gn_email("bob@host.example.com")])], nc2=ext_nc(permitted=[gn_email("alice@host.example.com")]))

print("ok", file=sys.stderr)
