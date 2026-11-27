//! RFC 5280 §7.1 DN comparison where an attribute value is NOT a string.
//!
//! `ava_values_match`'s string path (UTF8String, PrintableString, IA5String,
//! VisibleString, BMPString) is exercised all over this suite by real
//! certificates. Its other branch — "neither value is a string type" —
//! compares the raw DER, tag and content, and had no test at all: a
//! mutation sweep flipped its `&&` to `||` and both its `==` to `!=`, and
//! all three survived.
//!
//! That branch is not decorative. With `||` in place of `&&`, two
//! certificates whose DNs carry the same attribute OID with *different*
//! non-string values compare as equal, because the tags match. DN equality
//! is what links a certificate to its issuer, so a weakened comparison here
//! links chains that should not link.
//!
//! The Names are built as DER rather than from fixtures because no
//! certificate generator will emit an OID-valued commonName: that is the
//! point, and a fixture nobody can regenerate is worse than bytes with the
//! encoding written out beside them.

use der::Decode as _;
use pkix_path::names_match;
use x509_cert::name::Name;

// Name ::= SEQUENCE OF RelativeDistinguishedName
//   30 0d
//     31 0b                      SET (one RDN)
//       30 09                    SEQUENCE (AttributeTypeAndValue)
//         06 03 55 04 03         type = OID 2.5.4.3 (commonName)
//         <value>                a deliberately non-string value
//
// `commonName` is declared as a DirectoryString, so an OID-valued one is
// schema-invalid — and `der::Any` carries it regardless, which is exactly
// the input this branch exists to handle.

/// value = OID 1.2.3 (`06 02 2a 03`).
const OID_123: &[u8] = &[
    0x30, 0x0d, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x06, 0x02, 0x2a, 0x03,
];

/// value = OID 1.2.4 (`06 02 2a 04`) — same tag as `OID_123`, different
/// content.
const OID_124: &[u8] = &[
    0x30, 0x0d, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x06, 0x02, 0x2a, 0x04,
];

/// value = OCTET STRING `2a 03` (`04 02 2a 03`) — different tag from
/// `OID_123`, identical content bytes.
const OCTETS_123: &[u8] = &[
    0x30, 0x0d, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x04, 0x02, 0x2a, 0x03,
];

fn name(der: &[u8]) -> Name {
    Name::from_der(der).expect("hand-built Name parses")
}

/// Identical non-string values match.
///
/// Without this the three negative cases below could all pass on a
/// comparison that never returns `true`.
#[test]
fn the_same_non_string_value_matches_itself() {
    assert!(names_match(&name(OID_123), &name(OID_123)));
}

/// Same tag, different content: not equal.
///
/// Kills the `a.value() == b.value()` → `!=` mutation, and the `&&` → `||`
/// one: under `||` the matching tags alone would carry this to `true`.
#[test]
fn the_same_tag_with_different_content_does_not_match() {
    assert!(
        !names_match(&name(OID_123), &name(OID_124)),
        "OID 1.2.3 and OID 1.2.4 are different names"
    );
}

/// Different tag, identical content: not equal.
///
/// Kills the `a.tag() == b.tag()` → `!=` mutation, and `&&` → `||` again
/// from the other side. The comment on this branch gives the reason —
/// comparing content alone would call two different encodings of the same
/// bytes the same name.
#[test]
fn a_different_tag_with_the_same_content_does_not_match() {
    assert!(
        !names_match(&name(OID_123), &name(OCTETS_123)),
        "an OID and an OCTET STRING are different types, whatever their bytes"
    );
}

/// A string value and a non-string value never match, whatever the bytes.
///
/// The `_ => false` arm. A legitimate chain will not encode one attribute
/// as a string in one certificate and as something else in another, so this
/// is fail-closed rather than a comparison.
#[test]
fn a_string_value_does_not_match_a_non_string_value() {
    // value = PrintableString "*" (`13 01 2a`), whose single content byte
    // is the first content byte of OID 1.2.3.
    const PRINTABLE: &[u8] = &[
        0x30, 0x0c, 0x31, 0x0a, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x01, 0x2a,
    ];
    assert!(!names_match(&name(PRINTABLE), &name(OID_123)));
    assert!(
        !names_match(&name(OID_123), &name(PRINTABLE)),
        "and the same in the other argument order"
    );
}
