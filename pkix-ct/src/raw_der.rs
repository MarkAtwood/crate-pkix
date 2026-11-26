//! Byte-preserving DER navigation, for reconstructing the RFC 6962
//! signed inputs out of a certificate's original bytes.
//!
//! # Why this exists rather than using the parsed structures
//!
//! RFC 6962 §3.2 signatures are over bytes the log saw at submission
//! time. Reconstructing those bytes by parsing a certificate into
//! `x509-cert` types and re-encoding them is only correct if the
//! encoder reproduces its input exactly, and an encoder is under no
//! obligation to: it may normalise a `GeneralizedTime` that could have
//! been a `UTCTime`, re-sort a `SET OF` whose original order was not
//! canonical, choose a different string type for an equivalent value,
//! or emit a length in a different number of bytes.
//!
//! Where that happens the reconstructed input differs from the signed
//! one by a byte or two, the signature check fails, and the caller is
//! told their valid certificate has an invalid SCT. The failure is
//! indistinguishable from forgery and lands nowhere near its cause.
//!
//! So this module does not re-encode anything. It locates the bytes
//! that are already there and copies them. The only bytes it writes
//! are the length fields of the structures it has to resize, and the
//! tag bytes it copies verbatim from the input.
//!
//! # Strictness
//!
//! The reader rejects any length field that is not in DER's minimal
//! form, and any length spanning more than four bytes. A certificate
//! that violates either would also be rejected by the `der` crate's
//! parser, which every other part of this workspace runs on, so
//! accepting it here would only produce bytes no log ever signed.

use alloc::vec::Vec;

/// DER tag byte for `SEQUENCE` (universal 16, constructed).
pub(crate) const TAG_SEQUENCE: u8 = 0x30;

/// DER tag byte for `INTEGER` (universal 2, primitive).
pub(crate) const TAG_INTEGER: u8 = 0x02;

/// DER tag byte for `OBJECT IDENTIFIER` (universal 6, primitive).
pub(crate) const TAG_OID: u8 = 0x06;

/// DER tag byte for `[0] EXPLICIT` — the `TBSCertificate` `version`
/// field, the only optional field before `subjectPublicKeyInfo`.
pub(crate) const TAG_VERSION: u8 = 0xA0;

/// DER tag byte for `[3] EXPLICIT` — the `TBSCertificate`
/// `extensions` field.
pub(crate) const TAG_EXTENSIONS: u8 = 0xA3;

/// One tag-length-value triple, located at the start of a slice.
///
/// Holds no borrow of its own: the caller keeps the slice the offsets
/// refer to, which is what lets the same `Tlv` describe a position in
/// a parent buffer and in a sub-slice of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Tlv {
    /// The identifier octet, to be copied verbatim when re-emitting.
    pub(crate) tag: u8,
    /// Length of the tag and length octets together.
    pub(crate) header_len: usize,
    /// Length of the value octets.
    pub(crate) value_len: usize,
}

impl Tlv {
    /// Total size of the triple: header plus value.
    pub(crate) fn total_len(self) -> usize {
        self.header_len + self.value_len
    }

    /// The value octets, from the slice this was read from.
    pub(crate) fn value<'a>(self, input: &'a [u8]) -> &'a [u8] {
        &input[self.header_len..self.total_len()]
    }
}

/// Read the triple at the start of `input`.
///
/// Returns `None` if `input` is truncated, if the length octets are
/// not in DER's minimal form, if the length spans more than four
/// octets, or if the value runs past the end of `input`.
pub(crate) fn read_tlv(input: &[u8]) -> Option<Tlv> {
    let (&tag, after_tag) = input.split_first()?;
    let (&first, after_first) = after_tag.split_first()?;

    let (value_len, header_len) = if first < 0x80 {
        // Short form: the length is this octet.
        (first as usize, 2)
    } else {
        // Long form: the low seven bits count the length octets.
        let count = (first & 0x7F) as usize;
        if count == 0 || count > 4 || after_first.len() < count {
            // Zero means indefinite length, which DER forbids; more
            // than four octets means a value larger than any
            // certificate; fewer octets than claimed is truncation.
            return None;
        }
        let octets = &after_first[..count];
        if octets[0] == 0 {
            // A leading zero octet is a non-minimal encoding.
            return None;
        }
        let mut len = 0usize;
        for &b in octets {
            len = (len << 8) | b as usize;
        }
        if len < 0x80 {
            // Representable in the short form, so the long form is
            // non-minimal.
            return None;
        }
        (len, 2 + count)
    };

    if input.len() - header_len < value_len {
        return None;
    }
    Some(Tlv {
        tag,
        header_len,
        value_len,
    })
}

/// Read the triple at the start of `input` and require `tag`.
pub(crate) fn read_tagged(input: &[u8], tag: u8) -> Option<Tlv> {
    read_tlv(input).filter(|tlv| tlv.tag == tag)
}

/// Append a tag and a minimally-encoded DER length to `out`.
///
/// `tag` is copied from the input rather than reconstructed, so this
/// writes the only bytes in a spliced structure that did not come from
/// the original certificate.
pub(crate) fn push_header(out: &mut Vec<u8>, tag: u8, value_len: usize) {
    out.push(tag);
    if value_len < 0x80 {
        out.push(value_len as u8);
        return;
    }
    let be = value_len.to_be_bytes();
    // Index of the most significant non-zero octet. `value_len >=
    // 0x80` here, so one exists.
    let start = be
        .iter()
        .position(|&b| b != 0)
        .expect("value_len >= 0x80 has a non-zero octet");
    let significant = &be[start..];
    // At most `size_of::<usize>()` octets, far below the 0x7F the
    // count field can hold.
    out.push(0x80 | significant.len() as u8);
    out.extend_from_slice(significant);
}

/// Walk `input` as a sequence of triples, yielding each one's offset.
///
/// Stops at the end of `input`. Returns `None` if any triple is
/// malformed, so a caller gets one answer for "this is not DER"
/// rather than a partial walk.
pub(crate) fn tlvs(input: &[u8]) -> Option<Vec<(usize, Tlv)>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < input.len() {
        let tlv = read_tlv(&input[off..])?;
        out.push((off, tlv));
        off += tlv.total_len();
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn short_form_length() {
        let tlv = read_tlv(&[0x30, 0x03, 0xAA, 0xBB, 0xCC]).expect("valid");
        assert_eq!(tlv.tag, TAG_SEQUENCE);
        assert_eq!(tlv.header_len, 2);
        assert_eq!(tlv.value_len, 3);
        assert_eq!(
            tlv.value(&[0x30, 0x03, 0xAA, 0xBB, 0xCC]),
            &[0xAA, 0xBB, 0xCC]
        );
    }

    #[test]
    fn long_form_length() {
        let mut der = vec![0x30, 0x82, 0x01, 0x00];
        der.extend(core::iter::repeat_n(0u8, 256));
        let tlv = read_tlv(&der).expect("valid");
        assert_eq!(tlv.header_len, 4);
        assert_eq!(tlv.value_len, 256);
    }

    /// A length that fits the short form must not be written long.
    /// Accepting it would let two encodings of one certificate both
    /// parse, and only one of them is what a log signed.
    #[test]
    fn non_minimal_long_form_is_rejected() {
        assert!(read_tlv(&[0x30, 0x81, 0x03, 0xAA, 0xBB, 0xCC]).is_none());
    }

    #[test]
    fn leading_zero_length_octet_is_rejected() {
        let mut der = vec![0x30, 0x83, 0x00, 0x01, 0x00];
        der.extend(core::iter::repeat_n(0u8, 256));
        assert!(read_tlv(&der).is_none());
    }

    #[test]
    fn indefinite_length_is_rejected() {
        assert!(read_tlv(&[0x30, 0x80, 0x00, 0x00]).is_none());
    }

    #[test]
    fn truncated_value_is_rejected() {
        assert!(read_tlv(&[0x30, 0x05, 0xAA]).is_none());
    }

    #[test]
    fn oversized_length_field_is_rejected() {
        assert!(read_tlv(&[0x30, 0x85, 0x01, 0x02, 0x03, 0x04, 0x05]).is_none());
    }

    /// Every length this writes must read back as the same number,
    /// and must be the form `read_tlv` accepts — the two have to
    /// agree or a splice produces bytes this crate cannot re-read.
    #[test]
    fn headers_round_trip_at_every_length_boundary() {
        for len in [
            0usize, 1, 0x7E, 0x7F, 0x80, 0x81, 0xFF, 0x100, 0x101, 0xFFFF, 0x1_0000, 0x12_3456,
        ] {
            let mut out = Vec::new();
            push_header(&mut out, TAG_SEQUENCE, len);
            out.extend(core::iter::repeat_n(0u8, len));
            let tlv = read_tlv(&out).unwrap_or_else(|| panic!("length {len} did not read back"));
            assert_eq!(tlv.value_len, len, "length {len} round-tripped wrong");
            assert_eq!(tlv.total_len(), out.len());
        }
    }

    #[test]
    fn walking_a_sequence_of_triples() {
        // Three triples back to back.
        let der = [0x02, 0x01, 0x05, 0x06, 0x02, 0x2A, 0x03, 0x30, 0x00];
        let found = tlvs(&der).expect("valid");
        assert_eq!(found.len(), 3);
        assert_eq!(found[0].0, 0);
        assert_eq!(found[0].1.tag, TAG_INTEGER);
        assert_eq!(found[1].0, 3);
        assert_eq!(found[1].1.tag, TAG_OID);
        // 3 octets for the INTEGER, then 4 for the OID.
        assert_eq!(found[2].0, 7);
        assert_eq!(found[2].1.tag, TAG_SEQUENCE);
    }

    #[test]
    fn walking_stops_on_a_malformed_triple() {
        assert!(tlvs(&[0x02, 0x01, 0x05, 0x30, 0x7F]).is_none());
    }
}
