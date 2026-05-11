//! SCT binary-format parser (RFC 6962 §3.2 / §3.3).
//!
//! This module parses the wire form of Signed Certificate Timestamps; it
//! does not verify signatures. Signature verification, log-list lookup, and
//! Merkle inclusion proofs are tracked separately (see PKIX-baac children).
//!
//! # Encoding (RFC 6962 §3.2)
//!
//! A `SignedCertificateTimestamp` is encoded as follows (all multi-byte
//! integers are network byte order):
//!
//! ```text
//! struct {
//!     Version sct_version;           // 1 byte; v1 == 0
//!     LogID id;                      // 32 bytes: SHA-256(log_pubkey_DER)
//!     uint64 timestamp;              // 8 bytes: ms since Unix epoch
//!     CtExtensions extensions;       // u16 length-prefixed bytes
//!     digitally-signed struct {
//!         HashAlgorithm hash;        // 1 byte (RFC 5246 §7.4.1.4.1)
//!         SignatureAlgorithm sig;    // 1 byte
//!         opaque signature<0..2^16-1>;
//!     } signature;
//! } SignedCertificateTimestamp;
//! ```
//!
//! A `SignedCertificateTimestampList` (RFC 6962 §3.3) wraps a sequence:
//!
//! ```text
//! opaque SerializedSCT<1..2^16-1>;
//! struct {
//!     SerializedSCT sct_list<1..2^16-1>;
//! } SignedCertificateTimestampList;
//! ```
//!
//! When the list is carried in a certificate extension (OID
//! 1.3.6.1.4.1.11129.2.4.2), the extension's `extnValue` (an ASN.1 OCTET
//! STRING) contains another DER-encoded OCTET STRING whose contents are
//! the `SignedCertificateTimestampList` bytes. [`SctList::from_extension_value`]
//! peels this inner OCTET STRING; [`SctList::from_serialized_list`] takes
//! the unwrapped bytes directly (useful for the TLS handshake extension,
//! which is not double-wrapped).

use alloc::vec::Vec;
use der::asn1::OctetString;
use der::Decode;

use crate::{Error, Result};

/// A parsed Signed Certificate Timestamp (RFC 6962 §3.2).
///
/// Field types preserve the on-the-wire representation: `hash_alg` and
/// `sig_alg` are the raw 1-byte tags from RFC 5246 §7.4.1.4.1 rather than
/// typed enums, so future TLS revisions adding new algorithms do not
/// require changes here. Signature interpretation lives one layer up
/// (see [`crate::verify_scts`] and PKIX-baac.3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SignedCertificateTimestamp {
    /// SCT version. Always 0 for the v1 protocol defined in RFC 6962. v2
    /// (RFC 9162) is not yet deployed and parsing rejects non-zero
    /// versions with [`Error::UnsupportedVersion`].
    pub version: u8,
    /// Log identifier — SHA-256 of the log's public key DER encoding
    /// (RFC 6962 §3.2). Used to look up the log's verifying key in a
    /// [`crate::CtLogList`].
    pub log_id: [u8; 32],
    /// Timestamp the log committed to, in milliseconds since the Unix
    /// epoch. Decoded from the 8-byte big-endian wire field.
    pub timestamp_ms: u64,
    /// CT extensions byte string. Usually empty in deployed v1 SCTs (no
    /// extensions are currently defined by RFC 6962); preserved verbatim
    /// for forward compatibility and inclusion in the signed structure.
    pub extensions: Vec<u8>,
    /// `HashAlgorithm` value (RFC 5246 §7.4.1.4.1). For typical
    /// CT-enforced TLS deployments this is 4 (SHA-256).
    pub hash_alg: u8,
    /// `SignatureAlgorithm` value (RFC 5246 §7.4.1.4.1). For typical
    /// CT-enforced TLS deployments this is 3 (ECDSA).
    pub sig_alg: u8,
    /// Raw signature bytes (a DER-encoded ECDSA-Sig-Value for ECDSA, or
    /// the RSA signature octet string for RSA). Length matches the
    /// `signature` field's u16 length prefix on the wire.
    pub signature: Vec<u8>,
}

impl SignedCertificateTimestamp {
    /// Parse a single `SignedCertificateTimestamp` from `input`.
    ///
    /// `input` must contain exactly one SCT — trailing bytes cause
    /// [`Error::TruncatedOrTrailing`]. This entry point is used by
    /// [`SctList`]'s list parser; callers handling a single SCT from the
    /// TLS handshake's `signed_certificate_timestamp` form (a single SCT
    /// wrapped in a u16 length prefix) should first strip that prefix.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedVersion`] if the first byte is not 0,
    /// or [`Error::TruncatedOrTrailing`] / [`Error::ParseError`] for
    /// length/format problems.
    pub fn from_bytes(input: &[u8]) -> Result<Self> {
        let mut cur = Cursor::new(input);
        let sct = Self::read(&mut cur)?;
        if !cur.is_empty() {
            return Err(Error::TruncatedOrTrailing);
        }
        Ok(sct)
    }

    fn read(cur: &mut Cursor<'_>) -> Result<Self> {
        let version = cur.read_u8()?;
        if version != 0 {
            return Err(Error::UnsupportedVersion(version));
        }
        let log_id = {
            let bytes = cur.read_bytes(32)?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            arr
        };
        let timestamp_ms = cur.read_u64_be()?;
        let extensions = cur.read_u16_prefixed()?.to_vec();
        let hash_alg = cur.read_u8()?;
        let sig_alg = cur.read_u8()?;
        let signature = cur.read_u16_prefixed()?.to_vec();
        Ok(Self {
            version,
            log_id,
            timestamp_ms,
            extensions,
            hash_alg,
            sig_alg,
            signature,
        })
    }
}

/// A parsed `SignedCertificateTimestampList` (RFC 6962 §3.3).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct SctList(pub Vec<SignedCertificateTimestamp>);

impl SctList {
    /// Parse the value of a cert's SCT-list extension
    /// (OID 1.3.6.1.4.1.11129.2.4.2).
    ///
    /// The certificate extension framework already strips the outer
    /// OCTET STRING that wraps the extension value (typically via
    /// `x509_cert::ext::Extension::extn_value.as_bytes()`). RFC 6962
    /// §3.3 then wraps the `SignedCertificateTimestampList` in a
    /// second DER OCTET STRING; this function peels that second layer
    /// and parses the inner bytes.
    ///
    /// For OCSP-response and TLS-handshake delivery paths, which are
    /// not double-wrapped, use [`Self::from_serialized_list`] instead.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ParseError`] if the input is not a valid DER
    /// OCTET STRING, or any error from [`Self::from_serialized_list`].
    pub fn from_extension_value(ext_value: &[u8]) -> Result<Self> {
        let inner = OctetString::from_der(ext_value).map_err(|_| Error::ParseError)?;
        Self::from_serialized_list(inner.as_bytes())
    }

    /// Parse a bare `SignedCertificateTimestampList` (RFC 6962 §3.3).
    ///
    /// The expected layout is:
    ///
    /// ```text
    /// u16 total_length
    /// (u16 sct_length, sct_length bytes of SCT) ...
    /// ```
    ///
    /// repeated until `total_length` bytes have been consumed. RFC 6962
    /// requires the list to contain at least one SCT
    /// (`SerializedSCT sct_list<1..2^16-1>`), so an empty list is rejected
    /// as a parse error.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TruncatedOrTrailing`] or [`Error::ParseError`]
    /// on malformed input.
    pub fn from_serialized_list(bytes: &[u8]) -> Result<Self> {
        let mut outer = Cursor::new(bytes);
        let body = outer.read_u16_prefixed()?;
        if !outer.is_empty() {
            return Err(Error::TruncatedOrTrailing);
        }
        if body.is_empty() {
            // RFC 6962 §3.3: sct_list<1..2^16-1> — empty list is not legal.
            return Err(Error::ParseError);
        }
        let mut inner = Cursor::new(body);
        let mut scts = Vec::new();
        while !inner.is_empty() {
            let sct_bytes = inner.read_u16_prefixed()?;
            let mut sct_cur = Cursor::new(sct_bytes);
            let sct = SignedCertificateTimestamp::read(&mut sct_cur)?;
            if !sct_cur.is_empty() {
                return Err(Error::TruncatedOrTrailing);
            }
            scts.push(sct);
        }
        Ok(Self(scts))
    }
}

// --- internal cursor helpers ---------------------------------------------

struct Cursor<'a> {
    data: &'a [u8],
}

impl<'a> Cursor<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.data.len() < n {
            return Err(Error::TruncatedOrTrailing);
        }
        let (head, tail) = self.data.split_at(n);
        self.data = tail;
        Ok(head)
    }

    fn read_u8(&mut self) -> Result<u8> {
        Ok(self.read_bytes(1)?[0])
    }

    fn read_u16_be(&mut self) -> Result<u16> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u64_be(&mut self) -> Result<u64> {
        let bytes = self.read_bytes(8)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(bytes);
        Ok(u64::from_be_bytes(arr))
    }

    fn read_u16_prefixed(&mut self) -> Result<&'a [u8]> {
        let len = self.read_u16_be()? as usize;
        self.read_bytes(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Cursor unit tests — these test the parser plumbing only; the
    // independent oracle for the wire format is in tests/parser.rs.

    #[test]
    fn cursor_reads_and_advances() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05];
        let mut c = Cursor::new(&data);
        assert_eq!(c.read_u8().unwrap(), 0x01);
        assert_eq!(c.read_u16_be().unwrap(), 0x0203);
        assert_eq!(c.read_bytes(2).unwrap(), &[0x04, 0x05]);
        assert!(c.is_empty());
    }

    #[test]
    fn cursor_rejects_short_read() {
        let data = [0x01];
        let mut c = Cursor::new(&data);
        assert_eq!(c.read_u16_be(), Err(Error::TruncatedOrTrailing));
    }

    #[test]
    fn cursor_reads_u16_prefixed() {
        let data = [0x00, 0x03, 0xaa, 0xbb, 0xcc, 0xff];
        let mut c = Cursor::new(&data);
        assert_eq!(c.read_u16_prefixed().unwrap(), &[0xaa, 0xbb, 0xcc]);
        assert_eq!(c.read_u8().unwrap(), 0xff);
    }

    #[test]
    fn cursor_rejects_u16_prefix_overflow() {
        // prefix says 5 bytes follow, but only 2 are available
        let data = [0x00, 0x05, 0xaa, 0xbb];
        let mut c = Cursor::new(&data);
        assert_eq!(c.read_u16_prefixed(), Err(Error::TruncatedOrTrailing));
    }

    #[test]
    fn empty_list_rejected() {
        // u16=0 outer length, no body
        let data = [0x00, 0x00];
        assert_eq!(SctList::from_serialized_list(&data), Err(Error::ParseError));
    }

    #[test]
    fn version_must_be_zero() {
        // outer u16=1, one byte SCT (only the version byte = 1)
        // u16=3 outer, u16=1 inner, then 1 byte version=1
        let data = [0x00, 0x03, 0x00, 0x01, 0x01];
        assert_eq!(
            SctList::from_serialized_list(&data),
            Err(Error::UnsupportedVersion(1))
        );
    }
}
