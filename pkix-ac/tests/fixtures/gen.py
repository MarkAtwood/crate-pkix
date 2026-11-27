#!/usr/bin/env python3
"""Build RFC 5755 attribute certificates.

Why this is hand-rolled DER
---------------------------
Neither OpenSSL nor pyca/cryptography can create an attribute
certificate — they model public-key certificates, CRLs and requests, and
so does `x509-cert`, which is why `pkix-ac` declares the ASN.1 itself.
That leaves no independent tool to generate fixtures with, so they are
assembled here from the productions in RFC 5755 Appendix B and signed
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
    return seq(oid(ID_AT_ROLE), tlv(0x31, role_value(role_uri)))


def role_value(role_uri: str) -> bytes:
    """One Role AttributeValue, without the enclosing SET OF."""
    role_name = tlv(0x86, role_uri.encode())  # [6] IMPLICIT IA5String
    return seq(tlv(0xA1, role_name))  # [1] holding the GeneralName


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


def sign(data: bytes, key: pathlib.Path = None) -> bytes:
    with tempfile.TemporaryDirectory() as td:
        p = pathlib.Path(td) / "acinfo.der"
        p.write_bytes(data)
        return subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(key or AA_KEY), str(p)],
            check=True, capture_output=True).stdout


def attribute_certificate(info: bytes, key: pathlib.Path = None) -> bytes:
    return seq(info, ECDSA_SHA256, bitstring(sign(info, key)))


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
    # ONE id-at-role attribute carrying TWO values, which is how §4.2.7
    # says to express several: "only one instance of each attribute can
    # occur in a single AC, but each instance can be multi-valued".
    #
    # This fixture used to be two separate id-at-role attributes, which
    # §4.2.7 forbids -- and a test asserted it conformed.
    two_roles = seq(oid(ID_AT_ROLE), tlv(0x31,
        role_value("urn:example:role:auditor")
        + role_value("urn:example:role:approver")))
    info = acinfo(leaf_subject, aa_subject, 0x2B,
                  "20250101000000Z", "20340101000000Z", seq(two_roles))
    (HERE / "ac-two-roles.der").write_bytes(attribute_certificate(info))

    # And the violation, so the new rule has a fixture.
    info = acinfo(leaf_subject, aa_subject, 0x2F,
                  "20250101000000Z", "20340101000000Z",
                  seq(role_attribute("urn:example:role:auditor"),
                      role_attribute("urn:example:role:admin")))
    (HERE / "ac-duplicate-attribute-type.der").write_bytes(
        attribute_certificate(info))

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
    # The boundaries, which is where this rule was wrong. §4.3.1: the
    # VALUE must be 1..=20 octets. Measuring the extension value's DER
    # instead put the real window at 1..=18 and let a zero-length value
    # through as a two-byte `04 00`. 21 octets was far enough over the
    # line to be refused under either reading, which is why the original
    # fixture caught nothing.
    for serial, n, label in (
        (0x3A, 21, "too-long"),   # over by one
        (0x3B, 20, "max"),        # the largest permitted
        (0x3C, 19, "near-max"),   # inside under both readings
        (0x3D, 0, "empty"),       # the one length the RFC forbids
    ):
        value = tlv(0x04, bytes(range(n)) if n else b"")
        info = with_exts(serial, extension(ID_PE_AC_AUDIT_IDENTITY, True, value))
        (HERE / f"ac-audit-{label}.der").write_bytes(attribute_certificate(info))

    # And a value that is not an OCTET STRING at all -- §4.3.1 gives the
    # syntax, and nothing checked it.
    info = with_exts(0x3E, extension(ID_PE_AC_AUDIT_IDENTITY, True, integer(0x2A)))
    (HERE / "ac-audit-not-octet-string.der").write_bytes(
        attribute_certificate(info))

    # AttCertVersion ::= INTEGER { v2(1) }. The profile permits exactly
    # one value, and it is modelled as an enumeration so a wrong version
    # is a parse failure rather than a check that can be forgotten --
    # a claim nothing tested, because no fixture carried another value.
    for serial, version, label in ((0x80, 0, "v1"), (0x81, 2, "v3")):
        info = seq(integer(version),
                   seq(tlv(0xA1, general_name_directory(leaf_subject))),
                   tlv(0xA0, general_names(general_name_directory(aa_subject))),
                   ECDSA_SHA256, integer(serial),
                   seq(gen_time(window[0]), gen_time(window[1])),
                   role)
        (HERE / f"ac-version-{label}.der").write_bytes(
            attribute_certificate(info))

    # ---- §6 revocation, §4.2.5 serials, and an empty entityName -----

    # §4.3.6 gives noRevAvail the syntax NULL. The value was never
    # checked, so an AC asserting "never revoke" with a body of junk
    # satisfied no_revocation_available().
    info = with_exts(0x90, extension(ID_CE_NO_REV_AVAIL, False, tlv(0x04, b"junk")))
    (HERE / "ac-norevavail-not-null.der").write_bytes(attribute_certificate(info))

    # §6: "an AC MUST NOT contain both a noRevAvail extension and a
    # 'pointer in AC'". The two schemes are alternatives.
    cdp = extension("2.5.29.31", False, seq(seq(tlv(0xA0, tlv(0xA0,
        tlv(0x86, b"http://crl.example.com/ac.crl"))))))
    info = with_exts(0x91, extension(ID_CE_NO_REV_AVAIL, False, b"\x05\x00") + cdp)
    (HERE / "ac-norevavail-with-pointer.der").write_bytes(
        attribute_certificate(info))

    # A targetCert as the ONLY target, which §4.3.2 forbids -- and whose
    # certDigestInfo carries otherObjectTypes(2), the value §4.1 forbids.
    # This was the route by which a profile-checked AC could still hold
    # an ObjectDigestInfo.
    # TargetCert ::= SEQUENCE { targetCertificate IssuerSerial,
    #   targetName GeneralName OPTIONAL,
    #   certDigestInfo ObjectDigestInfo OPTIONAL }
    #
    # [2] is IMPLICIT and replaces TargetCert's own SEQUENCE tag, so its
    # fields sit directly inside: the IssuerSerial keeps its SEQUENCE,
    # targetName is omitted, and certDigestInfo keeps its own.
    tc_with_odi = tlv(0xA2,
        seq(issuer_serial_contents(leaf_subject, 0x77))
        + seq(object_digest_info_contents(2)))
    info = with_exts(0x92, extension(
        ID_CE_TARGET_INFORMATION, True, target_information(targets(tc_with_odi))))
    (HERE / "ac-target-cert-other-object.der").write_bytes(
        attribute_certificate(info))

    # §4.2.5: the serial's sign bit MUST be zero. `02 01 80` is -128.
    def acinfo_raw_serial(serial_der, exts=b""):
        tail = seq(exts) if exts else b""
        return seq(integer(1),
                   seq(tlv(0xA1, general_name_directory(leaf_subject))),
                   tlv(0xA0, general_names(general_name_directory(aa_subject))),
                   ECDSA_SHA256, serial_der,
                   seq(gen_time(window[0]), gen_time(window[1])), role, tail)
    (HERE / "ac-serial-negative.der").write_bytes(attribute_certificate(
        acinfo_raw_serial(tlv(0x02, b"\x80"))))
    # And longer than the 20 octets §4.2.5 permits.
    (HERE / "ac-serial-too-long.der").write_bytes(attribute_certificate(
        acinfo_raw_serial(tlv(0x02, b"\x01" + bytes(20)))))

    # §4.2.2: an entityName present but carrying no names. `A1 00`.
    (HERE / "ac-holder-no-names.der").write_bytes(attribute_certificate(
        acinfo(b"", aa_subject, 0x93, *window, role,
               holder_override=seq(tlv(0xA1, b"")))))

    # ---- a chain with depth -----------------------------------------
    #
    # root -> intermediate -> {authority, holder}, all from
    # make_aa.sh. Every pkix-chain wrapper test used one-element chains,
    # so the composition had never walked a chain even though every real
    # deployment has intermediates.
    deep_aa = (HERE / "aa-deep-cert.der").read_bytes()
    deep_holder = (HERE / "holder-deep-cert.der").read_bytes()
    info = acinfo(tbs_field(deep_holder, 5), tbs_field(deep_aa, 5), 0x70,
                  *window, role)
    (HERE / "ac-deep.der").write_bytes(
        attribute_certificate(info, HERE / "aa-deep-key.pem"))

    # ---- holder binding and DN comparison ---------------------------

    def dn_cn(text: str, string_tag: int = 0x0C) -> bytes:
        """A Name holding a single CN, encoded with a chosen string type.

        RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
        RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
        AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }

        0x0C is UTF8String, 0x13 PrintableString. Both hold the same
        characters and RFC 5280 §7.1 says the names are equal, so this is
        how a cosmetic re-encoding is expressed.
        """
        ava = seq(oid("2.5.4.3"), tlv(string_tag, text.encode()))
        return seq(tlv(0x31, ava))

    AA_CN = "pkix-ac attribute authority"
    ROOT_CN = "pkix-ct precert-oracle issuer CA"
    LEAF_SERIAL = 0x9A9A

    # The authority's certificate encodes its CN as UTF8String. This AC
    # names the same authority with a PrintableString, which is the same
    # distinguished name under §7.1 and different bytes.
    (HERE / "ac-issuer-printablestring.der").write_bytes(attribute_certificate(
        acinfo(leaf_subject, b"", 0x60, *window, role,
               issuer_override=tlv(0xA0, general_names(
                   general_name_directory(dn_cn(AA_CN, 0x13)))))))

    # And the same authority with the case changed, which RFC 4518
    # case-folds.
    (HERE / "ac-issuer-case.der").write_bytes(attribute_certificate(
        acinfo(leaf_subject, b"", 0x61, *window, role,
               issuer_override=tlv(0xA0, general_names(
                   general_name_directory(dn_cn(AA_CN.upper())))))))

    # The holder named by baseCertificateID rather than entityName --
    # §4.2.2's other form, which every fixture so far skipped. It
    # references the holder's certificate by its ISSUER and serial, not
    # by its own subject.
    (HERE / "ac-holder-base-cert-id.der").write_bytes(attribute_certificate(
        acinfo(b"", aa_subject, 0x62, *window, role,
               holder_override=seq(tlv(0xA0, issuer_serial_contents(
                   dn_cn(ROOT_CN), LEAF_SERIAL))))))

    # The same form with the issuer DN re-encoded, so the §7.1
    # comparison is exercised on this branch too.
    (HERE / "ac-holder-base-cert-id-reencoded.der").write_bytes(
        attribute_certificate(
            acinfo(b"", aa_subject, 0x63, *window, role,
                   holder_override=seq(tlv(0xA0, issuer_serial_contents(
                       dn_cn(ROOT_CN, 0x13), LEAF_SERIAL))))))

    # And with the wrong serial, so a match cannot be coming from the
    # issuer name alone.
    (HERE / "ac-holder-base-cert-id-wrong-serial.der").write_bytes(
        attribute_certificate(
            acinfo(b"", aa_subject, 0x64, *window, role,
                   holder_override=seq(tlv(0xA0, issuer_serial_contents(
                       dn_cn(ROOT_CN), LEAF_SERIAL + 1))))))

    # ---- §4.4 attribute types, uninterpreted ------------------------
    #
    # The crate's stated position is "parse all, interpret none". Every
    # other fixture carries id-at-role only, so nothing showed the claim
    # holds for types with different shapes.
    #
    # OIDs from RFC 5755 §4.4 and Appendix B. id-aca is { id-pkix 10 },
    # so the four id-aca attributes are 1.3.6.1.5.5.7.10.n -- NOT under
    # 2.5.4 like role and clearance, which is easy to get wrong and
    # invisible in a crate that does not interpret them.
    ID_ACA_AUTHENTICATION_INFO = "1.3.6.1.5.5.7.10.1"
    ID_ACA_ACCESS_IDENTITY = "1.3.6.1.5.5.7.10.2"
    ID_ACA_CHARGING_IDENTITY = "1.3.6.1.5.5.7.10.3"
    ID_ACA_GROUP = "1.3.6.1.5.5.7.10.4"
    ID_AT_ROLE_OID = "2.5.4.72"
    ID_AT_CLEARANCE = "2.5.4.55"

    def attr(oid_dotted, *values):
        return seq(oid(oid_dotted), tlv(0x31, b"".join(values)))

    def utf8(s):
        return tlv(0x0C, s.encode())

    # SvceAuthInfo ::= SEQUENCE { service GeneralName, ident GeneralName,
    #                             authInfo OCTET STRING OPTIONAL }
    def svce_auth_info(service, ident):
        return seq(general_name_dns(service), general_name_dns(ident))

    # IetfAttrSyntax ::= SEQUENCE { policyAuthority [0] GeneralNames
    #   OPTIONAL, values SEQUENCE OF CHOICE { OCTET STRING, OID,
    #   UTF8String } }
    def ietf_attr(*values):
        return seq(seq(*values))

    # Clearance ::= SEQUENCE { policyId OID, classList BIT STRING
    #   DEFAULT {unclassified}, securityCategories SET OF ... OPTIONAL }
    #
    # classList is a named bit list, so X.690 §11.2.2 requires trailing
    # zero bits to be removed: restricted(2) is `03 02 05 20`, not
    # `03 02 00 20`. `bitstring()` writes a plain BIT STRING with zero
    # unused bits, which is wrong for this type -- and the fixture passed
    # anyway because the value rides inside `Any` and is never decoded,
    # so the test presenting it as a §4.4 Clearance could not notice.
    clearance = seq(oid("1.3.6.1.4.1.99.7"), tlv(0x03, b"\x05\x20"))

    # All six §4.4 types in one certificate.
    info = acinfo(leaf_subject, aa_subject, 0x50, *window, seq(
        attr(ID_AT_ROLE_OID, seq(tlv(0xA1, tlv(0x86, b"urn:example:role:auditor")))),
        attr(ID_AT_CLEARANCE, clearance),
        attr(ID_ACA_GROUP, ietf_attr(utf8("auditors"))),
        attr(ID_ACA_CHARGING_IDENTITY, ietf_attr(utf8("cost-centre-7"))),
        attr(ID_ACA_ACCESS_IDENTITY,
             svce_auth_info("svc.example.com", "user.example.com")),
        attr(ID_ACA_AUTHENTICATION_INFO,
             svce_auth_info("auth.example.com", "user.example.com")),
    ))
    (HERE / "ac-attribute-types.der").write_bytes(attribute_certificate(info))

    # Two values under ONE attribute type, in descending DER order.
    #
    # `values` is a SET OF, and DER requires members sorted by their
    # encodings (X.690 §11.6). A CA that does not sort emits
    # well-formed-looking bytes in the wrong order -- the exact shape
    # that broke pkix-ct's SCT verification, where re-encoding re-sorted
    # an unsorted RDN and so changed the bytes the signature covered.
    # This asks whether such an AC is readable at all, and whether its
    # signature still checks.
    hi = seq(tlv(0xA1, tlv(0x86, b"zzz:example:role:second")))
    lo = seq(tlv(0xA1, tlv(0x86, b"aaa:example:role:first")))
    info = acinfo(leaf_subject, aa_subject, 0x51, *window,
                  seq(attr(ID_AT_ROLE_OID, hi, lo)))
    (HERE / "ac-unsorted-set-of.der").write_bytes(attribute_certificate(info))

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
