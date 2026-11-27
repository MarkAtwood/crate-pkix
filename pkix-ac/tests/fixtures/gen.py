#!/usr/bin/env python3
"""Build RFC 5755 attribute certificates.

Why this is hand-rolled DER
---------------------------
Neither OpenSSL nor pyca/cryptography can create an attribute
certificate — they model public-key certificates, CRLs and requests, and
so does `x509-cert`, which is why `pkix-ac` declares the ASN.1 itself.
That leaves no independent tool to generate fixtures with, so they are
assembled here from the productions in RFC 5755 Appendix A and signed
with a real key by `openssl dgst`.

The consequence is worth stating plainly: this generator is not an
independent oracle the way `pkix-ct`'s pyca-based ones are. It and the
Rust parser could in principle share a misreading of the spec. What it
does establish is that the parser reads bytes laid out the way the RFC
says, and that signature verification works over a signature a separate
tool produced. The ASN.1 here was transcribed from rfc5755.txt, whose
module is DEFINITIONS IMPLICIT TAGS — so every context tag below is
implicit, and a reader checking this against RFC 5280 habits will think
some of them are wrong.

Key and names are borrowed from the pkix-ct oracle fixtures rather than
generated, so the AA has a certificate that `pkix-path` can validate.

Run:  python3 gen.py
"""
import pathlib
import subprocess
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
CT = HERE.parent.parent.parent / "pkix-ct" / "tests" / "fixtures" / "sct-oracle"
# The Attribute Authority, built by make_aa.sh. NOT pkix-ct's
# precert-issuer: that is CA:TRUE with keyUsage "Certificate Sign, CRL
# Sign", and RFC 5755 §4.5 forbids both for an AC issuer ("an AC issuer
# cannot be a CA as well", and keyUsage must not exclude
# digitalSignature). ACs signed by it verify arithmetically and can
# never pass a conforming end-to-end validation, which is what the
# pkix-chain wrapper exposed.
AA_CERT = HERE / "aa-cert.der"
AA_KEY = HERE / "aa-key.pem"
# The root that issued the authority, and the holder. Shared with
# pkix-ct so the same self-signed root is the single trust anchor.
ROOT_CERT = CT / "precert-issuer.der"
LEAF_CERT = CT / "precert-leaf-final.der"

# ---------------------------------------------------------------- DER ---


def tlv(tag: int, body: bytes) -> bytes:
    if len(body) < 0x80:
        return bytes([tag, len(body)]) + body
    n = (len(body).bit_length() + 7) // 8
    return bytes([tag, 0x80 | n]) + len(body).to_bytes(n, "big") + body


def seq(*parts: bytes) -> bytes:
    return tlv(0x30, b"".join(parts))


def integer(n: int) -> bytes:
    if n == 0:
        return tlv(0x02, b"\x00")
    b = n.to_bytes((n.bit_length() + 8) // 8, "big")
    return tlv(0x02, b)


def oid(dotted: str) -> bytes:
    parts = [int(x) for x in dotted.split(".")]
    out = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append((p & 0x7F) | 0x80)
            p >>= 7
        out += bytes(reversed(chunk))
    return tlv(0x06, out)


def gen_time(s: str) -> bytes:
    """GeneralizedTime. RFC 5755 §4.1 requires seconds and Z."""
    assert len(s) == 15 and s.endswith("Z"), s
    return tlv(0x18, s.encode())


def bitstring(b: bytes) -> bytes:
    return tlv(0x03, b"\x00" + b)


def read_len(b: bytes, i: int):
    first = b[i + 1]
    if first < 0x80:
        return first, 2
    n = first & 0x7F
    return int.from_bytes(b[i + 2 : i + 2 + n], "big"), 2 + n


def tbs_field(cert: bytes, index: int) -> bytes:
    """The index-th field of a TBSCertificate, as bytes.

    0 = version, 1 = serial, 2 = sigalg, 3 = issuer, 4 = validity,
    5 = subject, 6 = spki. Used to lift real X.501 Names out of the
    borrowed certificates instead of constructing new ones.
    """
    cv, ch = read_len(cert, 0)
    body = cert[ch : ch + cv]
    tv, th = read_len(body, 0)
    tbs = body[th : th + tv]
    off, out = 0, []
    while off < len(tbs):
        vlen, hlen = read_len(tbs, off)
        out.append(tbs[off : off + hlen + vlen])
        off += hlen + vlen
    return out[index]


# ------------------------------------------------------- RFC 5755 ------

# ecdsa-with-SHA256, matching the borrowed P-256 AA key.
ECDSA_SHA256 = seq(oid("1.2.840.10045.4.3.2"))
# id-at-role, RFC 5755 §4.4.5.
ID_AT_ROLE = "2.5.4.72"


def general_name_directory(name_der: bytes) -> bytes:
    """GeneralName directoryName [4]. EXPLICIT because Name is a CHOICE."""
    return tlv(0xA4, name_der)


def general_names(*names: bytes) -> bytes:
    return seq(*names)


def role_attribute(role_uri: str) -> bytes:
    """A Role attribute — RFC 5755 §4.4.5.

    Role ::= SEQUENCE { roleAuthority [0] GeneralNames OPTIONAL,
                        roleName      [1] GeneralName }
    roleName is a uniformResourceIdentifier [6], which §4.4.5 says
    SHOULD be used.
    """
    role_name = tlv(0x86, role_uri.encode())  # [6] IMPLICIT IA5String
    role = seq(tlv(0xA1, role_name))  # [1] holding the GeneralName
    return seq(oid(ID_AT_ROLE), tlv(0x31, role))  # SET OF AttributeValue


# RFC 5755 §4.3 extension OIDs.
ID_PE_AC_AUDIT_IDENTITY = "1.3.6.1.5.5.7.1.4"
ID_CE_TARGET_INFORMATION = "2.5.29.55"
ID_CE_NO_REV_AVAIL = "2.5.29.56"


def extension(oid_dotted: str, critical: bool, value: bytes) -> bytes:
    """Extension ::= SEQUENCE { extnID, critical DEFAULT FALSE, extnValue }

    `critical` is DEFAULT FALSE, so DER requires it to be ABSENT when
    false -- emitting an explicit FALSE would be a non-canonical encoding
    the parser is entitled to reject.
    """
    parts = [oid(oid_dotted)]
    if critical:
        parts.append(tlv(0x01, b"\xff"))
    parts.append(tlv(0x04, value))
    return seq(*parts)


def general_name_dns(host: str) -> bytes:
    """GeneralName dNSName [2] IA5String. IMPLICIT, so [2] replaces the
    IA5String tag."""
    return tlv(0x82, host.encode())


def target_name(gn: bytes) -> bytes:
    """Target targetName [0] GeneralName -- RFC 5755 §4.3.2.

    EXPLICIT despite the module being DEFINITIONS IMPLICIT TAGS. X.680
    makes a tag on an untagged CHOICE explicit, because a CHOICE has no
    single tag of its own for an implicit tag to replace, and GeneralName
    is an untagged CHOICE. So [0] is constructed and WRAPS the
    GeneralName's own tag rather than replacing it.

    This is the opposite of Holder.entityName [1] GeneralNames, where the
    inner type is a SEQUENCE OF and the implicit tag does replace its
    tag. Both appear in the same module.
    """
    return tlv(0xA0, gn)


def target_group(gn: bytes) -> bytes:
    """Target targetGroup [1] GeneralName. EXPLICIT, as targetName."""
    return tlv(0xA1, gn)


def target_cert(name_der: bytes, serial: int) -> bytes:
    """Target targetCert [2] TargetCert -- which §4.3.2 says MUST NOT be
    used. Emitted so the refusal can be tested.

    TargetCert is a SEQUENCE, a tagged type, so here the implicit tag
    DOES replace it -- [2] stands in for TargetCert's own SEQUENCE tag.
    Its first field, targetCertificate, is an IssuerSerial, which is a
    SEQUENCE in its own right and still needs its own wrapper. Omitting
    that made the parser read the GeneralNames as the IssuerSerial and
    then find a [4] where it wanted a SEQUENCE.
    """
    return tlv(0xA2, seq(issuer_serial_contents(name_der, serial)))


def targets(*ts: bytes) -> bytes:
    """Targets ::= SEQUENCE OF Target."""
    return seq(*ts)


def target_information(*targets_elements: bytes) -> bytes:
    """The extension value: SEQUENCE OF Targets.

    X.509-2000 defines it as a SEQUENCE OF Targets while §4.3.2 says a
    conforming issuer emits exactly one; users must accept several and
    treat them as one. Both shapes are generated.
    """
    return seq(*targets_elements)


def issuer_serial_contents(name_der: bytes, serial: int) -> bytes:
    """The contents of an IssuerSerial — RFC 5755 §4.1.

    Returned unwrapped so a caller can apply an IMPLICIT context tag,
    which replaces the SEQUENCE tag rather than adding a layer.
    """
    return general_names(general_name_directory(name_der)) + integer(serial)


def enumerated(n: int) -> bytes:
    return tlv(0x0A, bytes([n]))


SHA256_ALGID = seq(oid("2.16.840.1.101.3.4.2.1"))


def object_digest_info_contents(digested_object_type: int = 0) -> bytes:
    """ObjectDigestInfo contents -- RFC 5755 §4.1.

    Unwrapped so a caller can apply an IMPLICIT context tag, which
    replaces the SEQUENCE tag. `digestedObjectType` 2 is otherObjectTypes,
    which §4.1 says MUST NOT be used.
    """
    return (enumerated(digested_object_type) + SHA256_ALGID
            + bitstring(bytes(32)))


def acinfo(holder_name: bytes, issuer_name: bytes, serial: int,
           not_before: str, not_after: str, attrs: bytes,
           issuer_v1_form: bool = False,
           holder_both_forms: bool = False,
           exts: bytes = b"",
           holder_override: bytes = b"",
           issuer_override: bytes = b"") -> bytes:
    version = integer(1)  # AttCertVersion v2
    # IMPLICIT tagging: [1] REPLACES the SEQUENCE OF tag of GeneralNames,
    # so the GeneralName sits directly inside [1] with no inner SEQUENCE.
    # Wrapping one in — the explicit reading, and the RFC 5280 habit —
    # produces a structure one level too deep that no conforming parser
    # will read.
    if holder_both_forms:
        # §4.2.2 requires exactly one of baseCertificateID and
        # entityName. This gives both, so which one identifies the
        # holder is ambiguous.
        holder = seq(
            tlv(0xA0, issuer_serial_contents(holder_name, 0x99)),
            tlv(0xA1, general_name_directory(holder_name)),
        )
    else:
        holder = seq(tlv(0xA1, general_name_directory(holder_name)))
    # Likewise [0] replaces V2Form's own SEQUENCE tag. What remains
    # inside is V2Form's first field, issuerName, which is untagged and
    # so keeps its SEQUENCE OF tag.
    if issuer_v1_form:
        # AttCertIssuer's first CHOICE arm: GeneralNames with no context
        # tag. §4.2.3 forbids it, and a conforming parser must still be
        # able to read it in order to say so.
        issuer = general_names(general_name_directory(issuer_name))
    else:
        issuer = tlv(0xA0, general_names(general_name_directory(issuer_name)))
    if holder_override:
        holder = holder_override
    if issuer_override:
        issuer = issuer_override
    validity = seq(gen_time(not_before), gen_time(not_after))
    # `extensions` is the last field of AttributeCertificateInfo, after
    # the optional issuerUniqueID, and is itself OPTIONAL -- so an empty
    # extension list is omitted rather than encoded as an empty SEQUENCE.
    tail = seq(exts) if exts else b""
    return seq(version, holder, issuer, ECDSA_SHA256, integer(serial),
               validity, attrs, tail)


def sign(data: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as td:
        p = pathlib.Path(td) / "acinfo.der"
        p.write_bytes(data)
        return subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(AA_KEY), str(p)],
            check=True, capture_output=True).stdout


def attribute_certificate(info: bytes) -> bytes:
    return seq(info, ECDSA_SHA256, bitstring(sign(info)))


def main() -> None:
    aa = AA_CERT.read_bytes()
    leaf = LEAF_CERT.read_bytes()
    aa_subject = tbs_field(aa, 5)
    leaf_subject = tbs_field(leaf, 5)

    # The ordinary case: one Role attribute, holder named by
    # entityName, issuer in v2Form with a directoryName. Valid for the
    # same window the borrowed certificates use.
    info = acinfo(leaf_subject, aa_subject, 0x2A,
                  "20250101000000Z", "20340101000000Z",
                  seq(role_attribute("urn:example:role:auditor")))
    (HERE / "ac-role-valid.der").write_bytes(attribute_certificate(info))

    # Two attributes, to pin that `attributes` is a SEQUENCE OF and the
    # parser keeps the order.
    info = acinfo(leaf_subject, aa_subject, 0x2B,
                  "20250101000000Z", "20340101000000Z",
                  seq(role_attribute("urn:example:role:auditor"),
                      role_attribute("urn:example:role:approver")))
    (HERE / "ac-two-roles.der").write_bytes(attribute_certificate(info))

    # Expired: notAfter in the past, everything else identical. For the
    # validity check, not the parser.
    info = acinfo(leaf_subject, aa_subject, 0x2C,
                  "20200101000000Z", "20210101000000Z",
                  seq(role_attribute("urn:example:role:auditor")))
    (HERE / "ac-expired.der").write_bytes(attribute_certificate(info))

    # Non-conforming on purpose, to give the profile checks something
    # to reject. Both parse: the syntax permits what the profile does
    # not, which is why parsing and profile checking are separate.
    info = acinfo(leaf_subject, aa_subject, 0x2D,
                  "20250101000000Z", "20340101000000Z",
                  seq(role_attribute("urn:example:role:auditor")),
                  issuer_v1_form=True)
    (HERE / "ac-issuer-v1form.der").write_bytes(attribute_certificate(info))

    info = acinfo(leaf_subject, aa_subject, 0x2E,
                  "20250101000000Z", "20340101000000Z",
                  seq(role_attribute("urn:example:role:auditor")),
                  holder_both_forms=True)
    (HERE / "ac-holder-both.der").write_bytes(attribute_certificate(info))

    # ---- §4.3 extensions -------------------------------------------
    #
    # None of the fixtures above carry extensions, which left every §4.3
    # rule and the §5 rule 7 critical-extension refusal unexercised.

    role = seq(role_attribute("urn:example:role:auditor"))
    window = ("20250101000000Z", "20340101000000Z")

    def with_exts(serial, exts):
        return acinfo(leaf_subject, aa_subject, serial, *window, role, exts=exts)

    # Targeted at one name and one group. targetInformation MUST be
    # critical (§4.3.2).
    info = with_exts(0x30, extension(
        ID_CE_TARGET_INFORMATION, True,
        target_information(targets(
            target_name(general_name_dns("verifier.example.com")),
            target_group(general_name_dns("printers.example.com")),
        ))))
    (HERE / "ac-targeted.der").write_bytes(attribute_certificate(info))

    # Two Targets elements, which X.509-2000 permits and §4.3.2 requires
    # a user to flatten into one.
    info = with_exts(0x31, extension(
        ID_CE_TARGET_INFORMATION, True,
        target_information(
            targets(target_name(general_name_dns("first.example.com"))),
            targets(target_name(general_name_dns("second.example.com"))),
        )))
    (HERE / "ac-targeted-split.der").write_bytes(attribute_certificate(info))

    # targetCert, which §4.3.2 says MUST NOT be used.
    info = with_exts(0x32, extension(
        ID_CE_TARGET_INFORMATION, True,
        target_information(targets(target_cert(leaf_subject, 0x77)))))
    (HERE / "ac-target-cert.der").write_bytes(attribute_certificate(info))

    # An unknown OID marked critical: RFC 5755 §5 rule 7 says reject.
    info = with_exts(0x33, extension("1.3.6.1.4.1.99999.1", True, b"\x05\x00"))
    (HERE / "ac-unsupported-critical.der").write_bytes(attribute_certificate(info))

    # The same unknown OID, NOT critical: must be ignored, not rejected.
    info = with_exts(0x34, extension("1.3.6.1.4.1.99999.1", False, b"\x05\x00"))
    (HERE / "ac-unsupported-noncritical.der").write_bytes(attribute_certificate(info))

    # noRevAvail: criticality MUST be FALSE (§4.3.6), value is NULL.
    null = b"\x05\x00"
    info = with_exts(0x35, extension(ID_CE_NO_REV_AVAIL, False, null))
    (HERE / "ac-norevavail.der").write_bytes(attribute_certificate(info))
    info = with_exts(0x36, extension(ID_CE_NO_REV_AVAIL, True, null))
    (HERE / "ac-norevavail-critical.der").write_bytes(attribute_certificate(info))

    # The same extension twice: §4.2 forbids it, and two instances let
    # two implementations read one certificate differently.
    dup = extension(ID_CE_NO_REV_AVAIL, False, null)
    info = with_exts(0x37, dup + dup)
    (HERE / "ac-duplicate-ext.der").write_bytes(attribute_certificate(info))

    # auditIdentity: criticality MUST be TRUE, value 1..=20 octets
    # (§4.3.1).
    audit = tlv(0x04, bytes(range(8)))
    info = with_exts(0x38, extension(ID_PE_AC_AUDIT_IDENTITY, True, audit))
    (HERE / "ac-audit-identity.der").write_bytes(attribute_certificate(info))
    info = with_exts(0x39, extension(ID_PE_AC_AUDIT_IDENTITY, False, audit))
    (HERE / "ac-audit-not-critical.der").write_bytes(attribute_certificate(info))
    too_long = tlv(0x04, bytes(21))
    info = with_exts(0x3A, extension(ID_PE_AC_AUDIT_IDENTITY, True, too_long))
    (HERE / "ac-audit-too-long.der").write_bytes(attribute_certificate(info))

    # ---- §4.2 profile rules, one fixture each -----------------------
    #
    # Each of these was an implemented rule with nothing but a Display
    # test behind it. All of them parse: §4.1's syntax permits what the
    # §4.2 profile forbids, which is why parsing and profile checking
    # are separate steps.

    def info_with(serial, **kw):
        return acinfo(leaf_subject, aa_subject, serial, *window, role, **kw)

    # §4.2.3: issuerName is required. A v2Form with none at all.
    (HERE / "ac-issuer-no-name.der").write_bytes(attribute_certificate(
        info_with(0x40, issuer_override=tlv(0xA0, b""))))

    # §4.2.3: and it must carry one and only one name.
    two_names = general_names(general_name_directory(aa_subject),
                              general_name_directory(leaf_subject))
    (HERE / "ac-issuer-two-names.der").write_bytes(attribute_certificate(
        info_with(0x41, issuer_override=tlv(0xA0, two_names))))

    # §4.2.3: a non-directoryName issuerName cannot be compared against
    # a certificate subject.
    (HERE / "ac-issuer-dns-name.der").write_bytes(attribute_certificate(
        info_with(0x42, issuer_override=tlv(
            0xA0, general_names(general_name_dns("aa.example.com"))))))

    # §4.2.3: v2Form must carry neither baseCertificateID nor
    # objectDigestInfo. [0] IssuerSerial, implicit.
    (HERE / "ac-issuer-extra-fields.der").write_bytes(attribute_certificate(
        info_with(0x43, issuer_override=tlv(
            0xA0,
            general_names(general_name_directory(aa_subject))
            + tlv(0xA0, issuer_serial_contents(aa_subject, 0x11))))))

    # §4.2.2: entityName must be a single name. [1] is IMPLICIT, so it
    # replaces the SEQUENCE OF tag and both names sit directly inside.
    (HERE / "ac-holder-two-names.der").write_bytes(attribute_certificate(
        info_with(0x44, holder_override=seq(tlv(
            0xA1,
            general_name_directory(leaf_subject)
            + general_name_directory(aa_subject))))))

    # §4.1/§4.2.2: objectDigestInfo is not profiled for the holder.
    (HERE / "ac-holder-digest-info.der").write_bytes(attribute_certificate(
        info_with(0x45, holder_override=seq(
            tlv(0xA2, object_digest_info_contents())))))

    # §4.1: at least one attribute is required.
    (HERE / "ac-no-attributes.der").write_bytes(attribute_certificate(
        acinfo(leaf_subject, aa_subject, 0x46, *window, seq())))

    # §4.1: and each attribute needs at least one value.
    empty_attr = seq(oid(ID_AT_ROLE), tlv(0x31, b""))
    (HERE / "ac-attribute-no-values.der").write_bytes(attribute_certificate(
        acinfo(leaf_subject, aa_subject, 0x47, *window, seq(empty_attr))))

    # §4.2.3: "all AC issuers MUST have non-empty distinguished names".
    # A directoryName wrapping an empty RDNSequence satisfies every
    # count-based check and none of the content-based one.
    (HERE / "ac-issuer-empty-dn.der").write_bytes(attribute_certificate(
        info_with(0x49, issuer_override=tlv(
            0xA0, general_names(general_name_directory(seq()))))))

    # The other optional trailing field. issuerUniqueID and extensions
    # are both OPTIONAL and neither is context-tagged, so they are
    # distinguishable only because one is a BIT STRING and the other a
    # SEQUENCE. This fixture carries BOTH, which is the only way to show
    # the disambiguation actually works.
    info = seq(integer(1),
               seq(tlv(0xA1, general_name_directory(leaf_subject))),
               tlv(0xA0, general_names(general_name_directory(aa_subject))),
               ECDSA_SHA256, integer(0x48),
               seq(gen_time(window[0]), gen_time(window[1])),
               role,
               bitstring(b"\x2a\x2b\x2c"),
               seq(extension(ID_CE_NO_REV_AVAIL, False, b"\x05\x00")))
    (HERE / "ac-issuer-unique-id.der").write_bytes(attribute_certificate(info))

    for f in sorted(HERE.glob("ac-*.der")):
        print(f"{f.name}: {f.stat().st_size} bytes")


if __name__ == "__main__":
    main()
