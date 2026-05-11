//! SCT signature verification (RFC 6962 §3.2).
//!
//! Given a parsed [`SignedCertificateTimestamp`], a final certificate, and
//! a [`CtLogList`], reconstruct the structure the log signed and verify
//! the SCT's signature against the log's verifying key. Algorithm
//! dispatch is delegated to a caller-supplied [`SignatureVerifier`] from
//! `pkix-path`, so the same algorithm backends (ECDSA P-256, RSA
//! PKCS#1 v1.5, etc.) used for path validation also serve SCT
//! verification.
//!
//! # The signed structure (RFC 6962 §3.2)
//!
//! ```text
//! digitally-signed struct {
//!     Version sct_version;             // 1 byte; v1 = 0
//!     SignatureType signature_type;    // 1 byte; certificate_timestamp = 0
//!     uint64 timestamp;                // 8 bytes, big-endian
//!     LogEntryType entry_type;         // 2 bytes, big-endian;
//!                                      // x509_entry = 0, precert_entry = 1
//!     select(entry_type) {
//!         case x509_entry:    ASN.1Cert certificate;       // u24-prefixed
//!         case precert_entry: PreCert precert;             // see RFC 6962 §3.2
//!     };
//!     CtExtensions extensions;         // u16-prefixed opaque
//! } signed_input;
//! ```
//!
//! This module implements the `x509_entry` branch. The `precert_entry`
//! branch is stubbed with [`Error::PrecertEntryNotImplemented`] (tracked
//! as PKIX-baac.4).
//!
//! # Algorithm mapping
//!
//! The SCT carries a `(hash_alg, sig_alg)` pair drawn from RFC 5246
//! §7.4.1.4.1's `HashAlgorithm` / `SignatureAlgorithm` tables.
//! `pkix-path::SignatureVerifier` expects an X.509-style
//! [`AlgorithmIdentifierRef`] OID. [`tls_alg_to_x509_oid`] maps the TLS
//! tags to the corresponding X.509 signature-algorithm OIDs. Currently
//! supported combinations:
//!
//! | hash_alg | sig_alg | X.509 OID                       | Name                       |
//! |---------:|--------:|--------------------------------|----------------------------|
//! | 4 (SHA-256) | 3 (ECDSA) | 1.2.840.10045.4.3.2            | `ecdsa-with-SHA256`        |
//! | 5 (SHA-384) | 3 (ECDSA) | 1.2.840.10045.4.3.3            | `ecdsa-with-SHA384`        |
//! | 4 (SHA-256) | 1 (RSA)   | 1.2.840.113549.1.1.11          | `sha256WithRSAEncryption`  |
//! | 5 (SHA-384) | 1 (RSA)   | 1.2.840.113549.1.1.12          | `sha384WithRSAEncryption`  |
//! | 6 (SHA-512) | 1 (RSA)   | 1.2.840.113549.1.1.13          | `sha512WithRSAEncryption`  |
//!
//! RFC 6962 §2.1.4 says CT logs MUST use ECDSA P-256 (with SHA-256) or
//! RSA (2048+, SHA-256); the table above intentionally covers the
//! superset the workspace's `SignatureVerifier` backends can verify.
//! Unsupported combinations return [`Error::UnsupportedSignatureAlgorithm`].

use alloc::vec::Vec;
use der::asn1::ObjectIdentifier;
use der::Decode as _;
use x509_cert::spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};

use pkix_path::SignatureVerifier;

use crate::sct::SignedCertificateTimestamp;
use crate::{CtLog, CtLogList, Error, Result};

/// `LogEntryType::x509_entry` — RFC 6962 §3.1.
const ENTRY_TYPE_X509: u16 = 0;
// `LogEntryType::precert_entry` (= 1) is defined by RFC 6962 §3.1 but
// is not used in this module yet — the precert_entry branch is
// PKIX-baac.4. The constant will return when that branch lands.
/// `SignatureType::certificate_timestamp` — RFC 6962 §3.2.
const SIG_TYPE_CERTIFICATE_TIMESTAMP: u8 = 0;
/// `Version::v1` — RFC 6962 §3.2.
const SCT_VERSION_V1: u8 = 0;

// X.509 signature-algorithm OIDs. Duplicated here (rather than re-exported
// from pkix-path) because pkix-path's copies are private and feature-gated;
// these are needed unconditionally for the TLS-alg-tag → X.509-OID map.

/// `ecdsa-with-SHA256` (ANSI X9.62 / RFC 5758 §3.2): 1.2.840.10045.4.3.2.
const OID_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
/// `ecdsa-with-SHA384` (RFC 5758 §3.2): 1.2.840.10045.4.3.3.
const OID_ECDSA_WITH_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
/// `sha256WithRSAEncryption` (RFC 8017 / PKCS#1): 1.2.840.113549.1.1.11.
const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
/// `sha384WithRSAEncryption` (RFC 8017 / PKCS#1): 1.2.840.113549.1.1.12.
const OID_SHA384_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
/// `sha512WithRSAEncryption` (RFC 8017 / PKCS#1): 1.2.840.113549.1.1.13.
const OID_SHA512_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

/// Map a TLS `(hash_alg, sig_alg)` pair to the matching X.509 signature
/// algorithm OID. Returns `None` for combinations not recognised by
/// `pkix-path`'s built-in [`SignatureVerifier`] backends.
///
/// See the module-level table for the recognised combinations.
fn tls_alg_to_x509_oid(hash_alg: u8, sig_alg: u8) -> Option<ObjectIdentifier> {
    // RFC 5246 §7.4.1.4.1 HashAlgorithm: 4=SHA256, 5=SHA384, 6=SHA512.
    // SignatureAlgorithm: 1=RSA, 3=ECDSA.
    match (hash_alg, sig_alg) {
        (4, 3) => Some(OID_ECDSA_WITH_SHA256),
        (5, 3) => Some(OID_ECDSA_WITH_SHA384),
        (4, 1) => Some(OID_SHA256_WITH_RSA),
        (5, 1) => Some(OID_SHA384_WITH_RSA),
        (6, 1) => Some(OID_SHA512_WITH_RSA),
        _ => None,
    }
}

/// Verify SCTs against a trusted CT log list using a pluggable
/// [`SignatureVerifier`] for algorithm dispatch.
///
/// `SctVerifier` wraps a `CtLogList` (the trust anchor set, populated by
/// the caller from a source it trusts — see [`CtLogList`]) and a
/// `SignatureVerifier` implementation. The verifier is responsible for
/// the actual cryptography; this type handles the RFC 6962 framing
/// (signed-input reconstruction, log lookup, algorithm-tag mapping).
///
/// # Example
///
/// ```no_run
/// # #[cfg(all(feature = "log-list", feature = "log-list-json"))]
/// # fn example() -> Result<(), pkix_ct::Error> {
/// use pkix_ct::{CtLogList, SctVerifier, SctList};
/// use pkix_path::DefaultVerifier;
///
/// // Caller-supplied log list (from a trusted source — pkix-ct ships none).
/// let log_list_json = "..."; // read from disk, embed, etc.
/// let logs = CtLogList::from_google_log_list_json(log_list_json)?;
///
/// // Caller-supplied cert (final cert, DER-encoded).
/// let cert_der: &[u8] = &[];
///
/// // Parse the SCTs out of the cert and verify each one.
/// let sct_list = SctList(vec![]);
/// let v = SctVerifier::new(logs, DefaultVerifier);
/// for sct in &sct_list.0 {
///     let _log = v.verify_sct_for_cert(sct, cert_der)?;
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct SctVerifier<V: SignatureVerifier> {
    logs: CtLogList,
    verifier: V,
}

impl<V: SignatureVerifier> SctVerifier<V> {
    /// Create an `SctVerifier` from a log list and a signature backend.
    pub const fn new(logs: CtLogList, verifier: V) -> Self {
        Self { logs, verifier }
    }

    /// Access the underlying log list.
    #[must_use]
    pub const fn logs(&self) -> &CtLogList {
        &self.logs
    }

    /// Verify one SCT against a final certificate (RFC 6962 `x509_entry`).
    ///
    /// `cert_der` must be the DER encoding of the final (issued)
    /// certificate the SCT commits to. For `precert_entry` SCTs (embedded
    /// in pre-certificates and re-published in the issued cert via the
    /// cert extension), use the future `verify_sct_for_precert` API
    /// (PKIX-baac.4); this function returns
    /// [`Error::PrecertEntryNotImplemented`] if the SCT carries a
    /// non-x509 entry type.
    ///
    /// Note: `pkix-ct`'s `SignedCertificateTimestamp` does not carry an
    /// explicit `entry_type` field (it is implied by the
    /// delivery channel — cert extension ⇒ precert_entry, OCSP /
    /// TLS-handshake ⇒ x509_entry). This function unconditionally treats
    /// the SCT as `x509_entry`; the caller is responsible for picking
    /// the right entry point based on delivery channel.
    ///
    /// On success the matching [`CtLog`] is returned so the caller can
    /// surface which log signed the SCT.
    ///
    /// # Errors
    ///
    /// - [`Error::UnsupportedVersion`] — SCT version is not 0 (v1).
    /// - [`Error::UnknownLog`] — `sct.log_id` is not present in the log list.
    /// - [`Error::SctTimestampOutsideLogWindow`] — `sct.timestamp_ms` is
    ///   outside `[log.usable_from_ms, log.retired_at_ms]`.
    /// - [`Error::UnsupportedSignatureAlgorithm`] — `(hash_alg, sig_alg)`
    ///   is not a recognised combination.
    /// - [`Error::LogKeyMalformed`] — the log's `key_der` does not parse
    ///   as a valid `SubjectPublicKeyInfo`.
    /// - [`Error::CertDerTooLong`] — the cert DER exceeds the 2^24 - 1
    ///   octet limit of the `ASN.1Cert` u24 length prefix.
    /// - [`Error::InvalidSignature`] — the underlying verifier rejected
    ///   the signature.
    pub fn verify_sct_for_cert(
        &self,
        sct: &SignedCertificateTimestamp,
        cert_der: &[u8],
    ) -> Result<&CtLog> {
        if sct.version != SCT_VERSION_V1 {
            return Err(Error::UnsupportedVersion(sct.version));
        }

        let log = self.logs.get(&sct.log_id).ok_or(Error::UnknownLog)?;

        if !log_window_contains(log, sct.timestamp_ms) {
            return Err(Error::SctTimestampOutsideLogWindow);
        }

        let oid = tls_alg_to_x509_oid(sct.hash_alg, sct.sig_alg).ok_or(
            Error::UnsupportedSignatureAlgorithm {
                hash_alg: sct.hash_alg,
                sig_alg: sct.sig_alg,
            },
        )?;

        let signed_input = build_signed_input_x509_entry(sct, cert_der)?;

        let spki =
            SubjectPublicKeyInfoRef::from_der(&log.key_der).map_err(|_| Error::LogKeyMalformed)?;

        let alg_id = AlgorithmIdentifierRef {
            oid,
            parameters: None,
        };

        self.verifier
            .verify_signature(alg_id, spki, &signed_input, &sct.signature)
            .map_err(|_| Error::InvalidSignature)?;

        Ok(log)
    }
}

/// Check whether `timestamp_ms` falls inside the log's usable window.
///
/// RFC 6962 §3.5 / §6.2 (and CT log lifecycle documentation) describe
/// `usable_from`/`retired_at` as inclusive lower and upper bounds: SCTs
/// timestamped at or after `usable_from` and strictly before
/// `retired_at` are trustworthy. `None` on either bound is treated as
/// "unbounded" on that side, matching the Chrome log_list.json schema
/// semantics ("never usable" is encoded by `usable_from_ms = None`).
fn log_window_contains(log: &CtLog, timestamp_ms: u64) -> bool {
    if let Some(lo) = log.usable_from_ms {
        if timestamp_ms < lo {
            return false;
        }
    }
    if let Some(hi) = log.retired_at_ms {
        if timestamp_ms >= hi {
            return false;
        }
    }
    true
}

/// Reconstruct the RFC 6962 §3.2 `digitally-signed` input for an
/// `x509_entry` SCT.
///
/// Layout (all multi-byte fields are network byte order):
///
/// ```text
/// u8       version              (0)
/// u8       signature_type       (0 = certificate_timestamp)
/// u64      timestamp_ms
/// u16      entry_type           (0 = x509_entry)
/// u24, len cert_der             (ASN.1Cert: opaque<1..2^24-1>)
/// u16, len extensions
/// ```
fn build_signed_input_x509_entry(
    sct: &SignedCertificateTimestamp,
    cert_der: &[u8],
) -> Result<Vec<u8>> {
    // ASN.1Cert is opaque<1..2^24-1>, a 3-byte big-endian length prefix.
    if cert_der.len() > 0x00FF_FFFF {
        return Err(Error::CertDerTooLong);
    }
    // The parser already enforces u16-bounded extensions on input (the
    // wire field's length prefix is u16). Defensively cap here to keep
    // build_signed_input total in the unsigned-range it advertises.
    debug_assert!(sct.extensions.len() <= u16::MAX as usize);

    let cert_len = cert_der.len();
    let cap = 1 + 1 + 8 + 2 + 3 + cert_len + 2 + sct.extensions.len();
    let mut out = Vec::with_capacity(cap);
    out.push(SCT_VERSION_V1);
    out.push(SIG_TYPE_CERTIFICATE_TIMESTAMP);
    out.extend_from_slice(&sct.timestamp_ms.to_be_bytes());
    out.extend_from_slice(&ENTRY_TYPE_X509.to_be_bytes());
    // u24 length prefix: top byte, then u16.
    out.push(((cert_len >> 16) & 0xFF) as u8);
    out.extend_from_slice(&(cert_len as u16).to_be_bytes());
    out.extend_from_slice(cert_der);
    out.extend_from_slice(&(sct.extensions.len() as u16).to_be_bytes());
    out.extend_from_slice(&sct.extensions);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sct::SignedCertificateTimestamp;
    use alloc::vec;
    use alloc::vec::Vec;

    fn empty_sct(hash_alg: u8, sig_alg: u8) -> SignedCertificateTimestamp {
        SignedCertificateTimestamp {
            version: 0,
            log_id: [0u8; 32],
            timestamp_ms: 0,
            extensions: Vec::new(),
            hash_alg,
            sig_alg,
            signature: Vec::new(),
        }
    }

    #[test]
    fn tls_alg_map_known_combinations() {
        assert_eq!(tls_alg_to_x509_oid(4, 3), Some(OID_ECDSA_WITH_SHA256));
        assert_eq!(tls_alg_to_x509_oid(5, 3), Some(OID_ECDSA_WITH_SHA384));
        assert_eq!(tls_alg_to_x509_oid(4, 1), Some(OID_SHA256_WITH_RSA));
        assert_eq!(tls_alg_to_x509_oid(5, 1), Some(OID_SHA384_WITH_RSA));
        assert_eq!(tls_alg_to_x509_oid(6, 1), Some(OID_SHA512_WITH_RSA));
    }

    #[test]
    fn tls_alg_map_rejects_unknown() {
        // hash=2 (SHA-1) is RFC 5246-defined but not in our supported set
        // (and pkix-path does not ship a SHA-1 backend).
        assert_eq!(tls_alg_to_x509_oid(2, 3), None);
        // sig=2 (DSA) is RFC 5246-defined; project policy excludes DSA.
        assert_eq!(tls_alg_to_x509_oid(4, 2), None);
        // Garbage values.
        assert_eq!(tls_alg_to_x509_oid(0xFF, 0xFF), None);
    }

    #[test]
    fn log_window_unbounded() {
        let log = CtLog {
            log_id: [0u8; 32],
            key_der: Vec::new(),
            description: "test".into(),
            url: "http://example.com/".into(),
            usable_from_ms: None,
            retired_at_ms: None,
        };
        assert!(log_window_contains(&log, 0));
        assert!(log_window_contains(&log, u64::MAX));
    }

    #[test]
    fn log_window_lower_bound_inclusive() {
        let log = CtLog {
            log_id: [0u8; 32],
            key_der: Vec::new(),
            description: "test".into(),
            url: "http://example.com/".into(),
            usable_from_ms: Some(1_000),
            retired_at_ms: None,
        };
        assert!(!log_window_contains(&log, 999));
        assert!(log_window_contains(&log, 1_000));
        assert!(log_window_contains(&log, 1_001));
    }

    #[test]
    fn log_window_upper_bound_exclusive() {
        let log = CtLog {
            log_id: [0u8; 32],
            key_der: Vec::new(),
            description: "test".into(),
            url: "http://example.com/".into(),
            usable_from_ms: None,
            retired_at_ms: Some(2_000),
        };
        assert!(log_window_contains(&log, 1_999));
        assert!(!log_window_contains(&log, 2_000));
        assert!(!log_window_contains(&log, 2_001));
    }

    /// Independent oracle for the signed-input layout: byte-for-byte
    /// hand-decoded values against RFC 6962 §3.2.
    #[test]
    fn signed_input_layout() {
        let mut sct = empty_sct(4, 3);
        sct.timestamp_ms = 0x0123_4567_89AB_CDEF;
        sct.extensions = vec![0xAA, 0xBB];
        let cert = b"hello";
        let out = build_signed_input_x509_entry(&sct, cert).unwrap();
        // Expected bytes:
        //   00                          version = 0
        //   00                          signature_type = certificate_timestamp
        //   01 23 45 67 89 AB CD EF     timestamp_ms (BE)
        //   00 00                       entry_type = x509_entry
        //   00 00 05                    u24 cert_len = 5
        //   68 65 6C 6C 6F              "hello"
        //   00 02                       ext_len = 2
        //   AA BB                       extensions
        let expected: &[u8] = &[
            0x00, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x00, 0x00, 0x00, 0x00,
            0x05, b'h', b'e', b'l', b'l', b'o', 0x00, 0x02, 0xAA, 0xBB,
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn signed_input_zero_length_cert_and_ext() {
        let sct = empty_sct(4, 3);
        let out = build_signed_input_x509_entry(&sct, &[]).unwrap();
        // Expected:
        //   00                  version = 0
        //   00                  signature_type
        //   00 00 00 00 00 00 00 00  timestamp_ms = 0
        //   00 00               entry_type
        //   00 00 00            cert_len = 0
        //   (no cert bytes)
        //   00 00               ext_len = 0
        let expected: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00,
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn signed_input_rejects_oversize_cert() {
        let sct = empty_sct(4, 3);
        // 2^24 bytes triggers the u24-length-prefix guard.
        let huge = vec![0u8; 0x0100_0000];
        assert_eq!(
            build_signed_input_x509_entry(&sct, &huge),
            Err(Error::CertDerTooLong)
        );
    }
}
