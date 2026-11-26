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
//! This module implements both the `x509_entry` and `precert_entry`
//! branches. See [`SctVerifier::verify_sct_for_cert`] (x509_entry, used
//! by SCTs delivered via OCSP or the TLS handshake) and
//! [`SctVerifier::verify_sct_for_precert`] (precert_entry, used by SCTs
//! embedded directly in the issued certificate via the SCT-list
//! extension).
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
use sha2::{Digest, Sha256};
use x509_cert::spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};
use x509_cert::Certificate;

use pkix_path::SignatureVerifier;

use crate::raw_der;
use crate::sct::SignedCertificateTimestamp;
use crate::{CtLog, CtLogList, Error, Result, UsableFrom};

/// `LogEntryType::x509_entry` — RFC 6962 §3.1.
const ENTRY_TYPE_X509: u16 = 0;
/// `LogEntryType::precert_entry` — RFC 6962 §3.1.
const ENTRY_TYPE_PRECERT: u16 = 1;
/// `SignatureType::certificate_timestamp` — RFC 6962 §3.2.
const SIG_TYPE_CERTIFICATE_TIMESTAMP: u8 = 0;
/// `MerkleLeafType::timestamped_entry` — RFC 6962 §3.4.
const MERKLE_LEAF_TYPE_TIMESTAMPED_ENTRY: u8 = 0;
/// `Version::v1` — RFC 6962 §3.2.
const SCT_VERSION_V1: u8 = 0;

/// RFC 6962 §3.3 SCT-list certificate extension OID
/// (`google.experimental.ct.sct`). The verifier strips this extension
/// from the final cert's TBS when reconstructing the bytes the log
/// signed over for a `precert_entry` SCT.
const OID_SCT_LIST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.4.2");

/// The DER content octets of [`OID_SCT_LIST`], for matching an
/// `extnID` in the certificate's own bytes without decoding it.
///
/// Derived from the same constant rather than written out, so the two
/// cannot drift apart.
const OID_SCT_LIST_BYTES: &[u8] = OID_SCT_LIST.as_bytes();

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

/// One embedded SCT that verified, as returned by
/// [`SctVerifier::verify_embedded_scts`].
///
/// Carries the identity of the log that vouched for the certificate
/// and the time it did so, which is what CT policies (log / operator
/// diversity, SCT age) are evaluated over. Look the log up with
/// [`CtLogList::get`] for its key and metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct VerifiedSct {
    /// The verifying log's `log_id` (SHA-256 of its SPKI, RFC 6962 §3.2).
    pub log_id: [u8; 32],
    /// The SCT's timestamp, in milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
}

/// Which RFC 6962 §3.1 log entry an SCT's signature covers.
///
/// Not carried on the transmitted SCT. RFC 6962 §3.2 puts `entry_type`
/// inside the `digitally-signed` structure, so it is an *input* to
/// verification that the caller supplies, not a field that can be
/// parsed out of an SCT.
///
/// Only one case is determined by how the SCT arrived: an SCT embedded
/// in a certificate must be [`LogEntryType::Precert`], because the log
/// signed it before the certificate that now carries it existed. For
/// SCTs delivered over the TLS handshake or OCSP, RFC 6962 §3.3 names
/// no entry type — a server may staple either kind — which is why
/// [`SctVerifier::diagnose_entry_type`] exists rather than a field on
/// the SCT claiming to know.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum LogEntryType {
    /// `x509_entry` (0) — the log signed the final certificate.
    X509,
    /// `precert_entry` (1) — the log signed a pre-certificate.
    Precert,
}

/// One embedded SCT that did **not** verify, with the reason, as
/// returned by [`SctVerifier::verify_embedded_scts_with_report`].
///
/// Exists because the reasons are not interchangeable. An SCT rejected
/// as [`Error::InvalidSignature`] is a forged or tampered SCT, or a log
/// signing key gone bad; one rejected as [`Error::UnknownLog`] is a
/// stale log list on this host. The first is an alarm and the second is
/// configuration, and a verifier that reports both as "zero valid SCTs"
/// leaves its caller unable to tell which happened.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct RejectedSct {
    /// The `log_id` the SCT claimed, which for an
    /// [`Error::UnknownLog`] rejection is the log to go and look up.
    ///
    /// Claimed, not verified: on an [`Error::InvalidSignature`]
    /// rejection nothing in this struct has been authenticated, so
    /// treat it as a lead rather than as fact.
    pub log_id: [u8; 32],
    /// The timestamp the SCT claimed, in milliseconds since the Unix
    /// epoch. Unauthenticated, for the same reason as `log_id`.
    pub timestamp_ms: u64,
    /// Why this SCT was rejected.
    pub reason: Error,
}

/// The full outcome of verifying a certificate's embedded SCTs, as
/// returned by [`SctVerifier::verify_embedded_scts_with_report`].
///
/// `verified` is what [`SctVerifier::verify_embedded_scts`] returns on
/// its own; `rejected` is what that method discards. Both can be
/// non-empty at once — three good SCTs and one with a bad signature is
/// a certificate worth a second look, and a caller that only counts the
/// good ones will not notice.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct EmbeddedSctReport {
    /// One entry per distinct log that vouched for the certificate,
    /// deduplicated by `log_id` as described on
    /// [`SctVerifier::verify_embedded_scts`].
    pub verified: Vec<VerifiedSct>,
    /// One entry per SCT that failed, in the order the SCT list gave
    /// them, each with its reason.
    ///
    /// An SCT skipped because an earlier SCT from the same log already
    /// verified is not here: it is a duplicate, not a failure.
    pub rejected: Vec<RejectedSct>,
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
/// use pkix_ct::{CtLogList, SctVerifier};
/// use pkix_path::DefaultVerifier;
///
/// // Caller-supplied log list (from a trusted source — pkix-ct ships none).
/// let log_list_json = "..."; // read from disk, embed, etc.
/// let logs = CtLogList::from_google_log_list_json(log_list_json)?;
///
/// // The certificate exactly as it arrived, and its issuer. These are
/// // the bytes the log signed, so they are what gets passed: a
/// // certificate parsed and encoded again is not guaranteed to be the
/// // same certificate.
/// let cert_der: &[u8] = &[];
/// let issuer_der: &[u8] = &[];
///
/// let v = SctVerifier::new(logs, DefaultVerifier);
/// let report = v.verify_embedded_scts_with_report(cert_der, issuer_der)?;
///
/// // One entry per log that vouched for the certificate, and for each
/// // SCT that did not verify, why.
/// for ok in &report.verified {
///     let _log_id = ok.log_id;
/// }
/// for bad in &report.rejected {
///     let _reason = &bad.reason;
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
    /// directly in the issued cert via the SCT-list extension), use
    /// [`Self::verify_sct_for_precert`] instead.
    ///
    /// This function always treats the SCT as `x509_entry`, because
    /// RFC 6962 §3.2 carries `entry_type` inside the `digitally-signed`
    /// structure rather than on the transmitted SCT: it is an input to
    /// verification, not something an SCT can be asked.
    ///
    /// Which input is right is only settled for embedded SCTs, which
    /// are necessarily `precert_entry` — the log signed them before the
    /// certificate carrying them existed. RFC 6962 §3.3 names no entry
    /// type for the TLS-handshake and OCSP channels, and a server may
    /// staple either kind, so a caller holding one of those cannot
    /// derive the answer and should not assume it.
    ///
    /// If this returns [`Error::InvalidSignature`] on an SCT that might
    /// have been `precert_entry`, [`Self::diagnose_entry_type`] will
    /// say which entry type does verify. This method cannot determine
    /// that itself: the `precert_entry` form signs over the issuer's
    /// key hash, and no issuer is passed here.
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
    /// - [`Error::SctExtensionsTooLong`] — `sct.extensions` exceeds the
    ///   2^16 - 1 octet `CtExtensions` limit (only reachable for SCTs
    ///   built through the public constructor or fields).
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

    /// Verify one SCT against a pre-cert (RFC 6962 `precert_entry`).
    ///
    /// SCTs embedded in an issued ("final") certificate via the
    /// SCT-list extension (OID 1.3.6.1.4.1.11129.2.4.2) are
    /// `precert_entry` SCTs: the log signed them over a structure
    /// derived from the pre-certificate the CA submitted, not over the
    /// final cert. To verify, the caller supplies:
    ///
    /// - `leaf_cert_der`: the DER of the **final** (issued)
    ///   certificate carrying the SCT-list extension. The verifier
    ///   strips that extension from the leaf's `TBSCertificate` to
    ///   reconstruct the TBS bytes the log signed over.
    /// - `issuer_cert_der`: the DER of the certificate that signed the
    ///   pre-cert submission and that signs the final cert. The
    ///   verifier hashes its `SubjectPublicKeyInfo` to produce the
    ///   `issuer_key_hash` field of the RFC 6962 §3.2 `PreCert`
    ///   structure.
    ///
    /// On success the matching [`CtLog`] is returned.
    ///
    /// # Caveats
    ///
    /// - This entry point assumes the issuer cert IS the cert whose
    ///   SubjectPublicKeyInfo the log committed to via
    ///   `issuer_key_hash`. RFC 6962 §3.1 also allows "Precertificate
    ///   Signing Certificates" (an intermediate with the CT EKU
    ///   delegated to sign pre-cert submissions). When such an
    ///   intermediate is in play, the caller must pass the Precert
    ///   Signing Certificate's issuer, not the immediate signer.
    ///   Detecting the delegated case is the caller's responsibility.
    /// - The verifier does NOT validate that `issuer_cert_der`
    ///   actually issued `leaf_cert_der`. Callers wanting that
    ///   guarantee compose this with `pkix-path` chain validation
    ///   first (or use `pkix-chain`).
    /// - The leaf's TBS is not re-encoded. The SCT-list extension is
    ///   spliced out of `leaf_cert_der` at the byte level, so the
    ///   signed input is the certificate's own bytes rather than an
    ///   encoder's rendering of them. This used to go through
    ///   [`der::Encode`] and was bit-exact only for
    ///   canonically-encoded certificates; a certificate whose
    ///   `SET OF` ordering or time encoding the encoder normalised
    ///   verified as [`Error::InvalidSignature`] despite carrying a
    ///   good SCT.
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
    /// - [`Error::ParseError`] — `leaf_cert_der` or `issuer_cert_der`
    ///   could not be parsed as an X.509 certificate.
    /// - [`Error::LeafMissingSctList`] — `leaf_cert_der` does not
    ///   contain an SCT-list extension; verifying a `precert_entry`
    ///   SCT against such a cert is meaningless (the caller likely
    ///   wants `verify_sct_for_cert` instead).
    /// - [`Error::CertDerTooLong`] — the reconstructed TBS exceeds the
    ///   2^24 - 1 octet limit of the RFC 6962 `TBSCertificate`
    ///   opaque-length-prefixed field.
    /// - [`Error::SctExtensionsTooLong`] — `sct.extensions` exceeds the
    ///   2^16 - 1 octet `CtExtensions` limit (only reachable for SCTs
    ///   built through the public constructor or fields).
    /// - [`Error::InvalidSignature`] — the underlying verifier rejected
    ///   the signature.
    pub fn verify_sct_for_precert(
        &self,
        sct: &SignedCertificateTimestamp,
        leaf_cert_der: &[u8],
        issuer_cert_der: &[u8],
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

        let tbs_no_sct = tbs_without_sct_list(leaf_cert_der)?;
        let issuer_key_hash = issuer_key_hash_from_cert(issuer_cert_der)?;
        let signed_input = build_signed_input_precert_entry(sct, &issuer_key_hash, &tbs_no_sct)?;

        let spki =
            SubjectPublicKeyInfoRef::from_der(&log.key_der).map_err(|_| Error::LogKeyMalformed)?;

        let alg_id = AlgorithmIdentifierRef {
            oid,
            parameters: None,
        };

        if self
            .verifier
            .verify_signature(alg_id, spki, &signed_input, &sct.signature)
            .is_err()
        {
            // Before calling it a bad signature, check whether this is
            // simply an x509_entry SCT asked the precert question. Only
            // reachable here, and only on the failure path: this method
            // holds the leaf DER that the x509_entry form signs over,
            // whereas verify_sct_for_cert has no issuer and so cannot
            // run the reverse check. The SCT is rejected either way;
            // the point is to not call a caller's wiring mistake an
            // attack.
            if self.verify_sct_for_cert(sct, leaf_cert_der).is_ok() {
                return Err(Error::EntryTypeMismatch);
            }
            return Err(Error::InvalidSignature);
        }

        Ok(log)
    }

    /// Which entry type, if either, this SCT's signature verifies
    /// under — the way out of an [`Error::InvalidSignature`] that might
    /// really be a wrong-entry-point mistake.
    ///
    /// RFC 6962 §3.2 keeps `entry_type` inside the `digitally-signed`
    /// structure, so it never arrives with the SCT and the caller has
    /// to assume one. For an embedded SCT the answer is always
    /// [`LogEntryType::Precert`]; for one delivered over the TLS
    /// handshake or OCSP, RFC 6962 §3.3 names no entry type and a
    /// server may staple either kind, so the only way to find out is to
    /// try. That is what this does.
    ///
    /// Both entry types are attempted, `x509_entry` first. A success
    /// says the SCT is genuine and names which question to ask; the
    /// answer is a diagnosis, not an acceptance — nothing here decides
    /// whether the SCT satisfies a CT policy.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidSignature`] — neither entry type verifies, so
    ///   the SCT really is bad rather than misrouted.
    /// - Any error either verification raises before reaching the
    ///   signature check, such as [`Error::UnknownLog`].
    pub fn diagnose_entry_type(
        &self,
        sct: &SignedCertificateTimestamp,
        leaf_cert_der: &[u8],
        issuer_cert_der: &[u8],
    ) -> Result<LogEntryType> {
        if self.verify_sct_for_cert(sct, leaf_cert_der).is_ok() {
            return Ok(LogEntryType::X509);
        }
        match self.verify_sct_for_precert(sct, leaf_cert_der, issuer_cert_der) {
            Ok(_) => Ok(LogEntryType::Precert),
            // EntryTypeMismatch cannot surface here: the x509 case is
            // tried first and returns above. Anything else is the
            // genuine reason neither form worked.
            Err(e) => Err(e),
        }
    }

    /// Verify the SCTs embedded in `leaf_cert`'s SCT-list extension
    /// against this verifier's [`CtLogList`], reporting both the logs
    /// that vouched for the cert and the SCTs that failed, with why.
    ///
    /// Prefer this over [`Self::verify_embedded_scts`] anywhere the
    /// answer might be acted on or logged: that method returns only the
    /// successes, so "no valid SCTs" arrives with no way to tell a
    /// forged SCT from a log list nobody has updated.
    ///
    /// Cert-embedded SCTs are always `precert_entry` (RFC 6962 §3.1):
    /// the log signed the pre-cert before the CA glued the SCT list
    /// into the final cert. This method dispatches every SCT through
    /// [`Self::verify_sct_for_precert`].
    ///
    /// For SCTs delivered via OCSP or the TLS handshake — which are
    /// `x509_entry` — callers should extract the SCT list themselves
    /// via [`crate::sct_list_from_ocsp_response`] /
    /// [`crate::sct_list_from_tls_extension`] and call
    /// [`Self::verify_sct_for_cert`] in a loop.
    ///
    /// An SCT lands in `verified` only if it fully verified (signature
    /// OK, log known, timestamp inside the log's usable window). SCTs
    /// that don't verify — wrong signature, unknown log, retired log,
    /// unsupported algorithm — are NOT errors: they land in
    /// [`EmbeddedSctReport::rejected`] with their reason, and an
    /// all-rejected list is still a successful result.
    ///
    /// Each reason matters separately. [`Error::InvalidSignature`] on
    /// every SCT means a forged SCT list or a log key gone bad;
    /// [`Error::UnknownLog`] on every SCT means this host's log list is
    /// stale. Alarm and misconfiguration, told apart.
    ///
    /// The result is **deduplicated by `log_id`**: at most one entry
    /// per log, keeping the first verified SCT in list order. An SCT
    /// list that repeats the same SCT, or carries several SCTs from
    /// one log, therefore cannot inflate the result. CT policies
    /// count independent logs, not list entries (e.g., CA/Browser
    /// Forum TLS BR §3.2.2.9 and browser CT policies require SCTs
    /// "from logs operated by two different log operators"), so the
    /// caller applies that policy to the returned `log_id`s — mapping
    /// them to operators from its own log-list source. For a plain
    /// distinct-log count, use [`Self::count_embedded_sct_logs`].
    ///
    /// `issuer_cert` is the certificate whose `SubjectPublicKeyInfo`
    /// the CT logs hashed when generating `issuer_key_hash` for the
    /// `PreCert` structure (typically the immediate issuer — see
    /// [`Self::verify_sct_for_precert`] for caveats about Precert
    /// Signing Certificates).
    ///
    /// # Errors
    ///
    /// - [`Error::NoScts`] — the cert has no SCT-list extension or
    ///   the extension's serialized list is empty.
    /// - [`Error::ParseError`] — the SCT-list extension is present
    ///   but malformed, or either cert fails to parse.
    /// - [`Error::DuplicateSctListExtension`] — the leaf carries the
    ///   extension more than once, which RFC 5280 §4.2 forbids and
    ///   which leaves no way to know which copy the log was given.
    /// - [`Error::TruncatedOrTrailing`] — the SCT-list extension is
    ///   present but the wire bytes are truncated or have trailing
    ///   garbage.
    /// - [`Error::UnsupportedVersion`] — an SCT in the list carries
    ///   an unsupported SCT version (propagated from
    ///   [`crate::SctList::from_extension_value`]).
    pub fn verify_embedded_scts_with_report(
        &self,
        leaf_cert_der: &[u8],
        issuer_cert_der: &[u8],
    ) -> Result<EmbeddedSctReport> {
        // Parsed only to find the extension. The signed input is built
        // from `leaf_cert_der` itself, which is why these take DER and
        // not `&Certificate`: re-encoding a parsed certificate to
        // recover its bytes reintroduces exactly the divergence
        // `tbs_without_sct_list` was rewritten to avoid.
        let leaf_cert = Certificate::from_der(leaf_cert_der).map_err(|_| Error::ParseError)?;
        let exts = leaf_cert
            .tbs_certificate()
            .extensions()
            .ok_or(Error::NoScts)?;
        // Counted, not found. `find` would silently take the first of
        // several, and which instance a verifier reads is exactly what
        // an attacker exploits when two implementations choose
        // differently — the same reason `pkix-identity` counts SAN
        // extensions and `pkix-path::check_duplicate_extensions`
        // rejects the certificate outright.
        let mut matching = exts.iter().filter(|e| e.extn_id == OID_SCT_LIST);
        let ext = matching.next().ok_or(Error::NoScts)?;
        if matching.next().is_some() {
            return Err(Error::DuplicateSctListExtension);
        }

        // `SctList` cannot be empty, so an empty list arrives as a
        // parse error rather than as a list; `NoScts` is reserved for
        // a certificate that carries no extension at all.
        let scts = crate::sct::SctList::from_extension_value(ext.extn_value.as_bytes())?;

        let mut report = EmbeddedSctReport::default();
        for sct in scts.scts() {
            // One entry per log: a repeated SCT, or a second SCT from
            // a log already counted, adds no independent evidence.
            // Checked before verifying so duplicates cost no signature
            // verification. SCT lists are tiny (u16-bounded), so the
            // linear scan is fine.
            if report.verified.iter().any(|v| v.log_id == sct.log_id) {
                continue;
            }
            // The reason is kept, not dropped. This was `.is_ok()`,
            // which collapsed a forged signature and a stale log list
            // into the same empty result.
            match self.verify_sct_for_precert(sct, leaf_cert_der, issuer_cert_der) {
                Ok(_) => report.verified.push(VerifiedSct {
                    log_id: sct.log_id,
                    timestamp_ms: sct.timestamp_ms,
                }),
                Err(reason) => report.rejected.push(RejectedSct {
                    log_id: sct.log_id,
                    timestamp_ms: sct.timestamp_ms,
                    reason,
                }),
            }
        }
        Ok(report)
    }

    /// The logs that vouched for `leaf_cert`, discarding why any other
    /// SCT failed.
    ///
    /// Equivalent to
    /// `verify_embedded_scts_with_report(..)?.verified`. Use it where
    /// the rejections genuinely do not matter — a policy check that
    /// only counts distinct logs, say. Where the zero case will be
    /// surfaced to an operator or a log, use
    /// [`Self::verify_embedded_scts_with_report`] instead: an empty
    /// result here cannot distinguish a forged SCT list from a log list
    /// this host has not refreshed.
    ///
    /// # Errors
    ///
    /// As for [`Self::verify_embedded_scts_with_report`].
    pub fn verify_embedded_scts(
        &self,
        leaf_cert_der: &[u8],
        issuer_cert_der: &[u8],
    ) -> Result<Vec<VerifiedSct>> {
        Ok(self
            .verify_embedded_scts_with_report(leaf_cert_der, issuer_cert_der)?
            .verified)
    }

    /// Number of distinct logs with a verified SCT embedded in
    /// `leaf_cert` — `verify_embedded_scts(..)?.len()`.
    ///
    /// Convenience for callers whose policy is a plain log count.
    /// Policies that require operator diversity need the `log_id`s
    /// from [`Self::verify_embedded_scts`] instead.
    ///
    /// A returned `0` says only that nothing verified. To act on that,
    /// or to log it, use [`Self::verify_embedded_scts_with_report`],
    /// which says whether the SCTs failed their signatures or merely
    /// named logs this host does not know.
    ///
    /// # Errors
    ///
    /// As for [`Self::verify_embedded_scts`].
    pub fn count_embedded_sct_logs(
        &self,
        leaf_cert_der: &[u8],
        issuer_cert_der: &[u8],
    ) -> Result<usize> {
        self.verify_embedded_scts(leaf_cert_der, issuer_cert_der)
            .map(|v| v.len())
    }

    /// Verify a Merkle inclusion proof (RFC 6962 §2.1.1 / RFC 9162 §2.1.3.2).
    ///
    /// An inclusion proof demonstrates that a particular leaf is in
    /// the CT log's append-only Merkle tree at the position the log
    /// claims. Verifying the proof reconstructs the tree's root hash
    /// from the leaf hash and the audit-path siblings; if the
    /// reconstructed root equals the `root_hash` the consumer trusts
    /// (typically from a [`SignedTreeHead`] signed by the log), the
    /// leaf is provably in the tree.
    ///
    /// `leaf_hash` is the RFC 6962 §2.1 leaf hash:
    /// `SHA256(0x00 || MerkleTreeLeaf-bytes)`. Compute it from an
    /// SCT plus the cert it commits to via
    /// [`merkle_tree_leaf_for_cert`] (x509_entry) or
    /// [`merkle_tree_leaf_for_precert`] (precert_entry) followed by
    /// [`merkle_leaf_hash`].
    ///
    /// # Errors
    ///
    /// - [`Error::MerkleProofMalformed`] — `tree_size` is 0, or the
    ///   audit path is longer than the maximum height for the tree
    ///   size (`ceil(log2(tree_size))` hashes), indicating either a
    ///   buggy proof source or a tampered proof.
    /// - [`Error::MerkleProofInvalid`] — `leaf_index >= tree_size`,
    ///   or the reconstructed root hash does not match `root_hash`.
    ///   Tampered proofs (any single byte changed in any audit-path
    ///   hash, the leaf hash, the leaf index, the tree size, or the
    ///   expected root) all surface as this variant.
    ///
    /// This method does not use `self.logs` or `self.verifier` — it is
    /// hash-only, and is kept here for discoverability: callers
    /// verifying SCTs are the same ones who will want inclusion proofs,
    /// and RFC 6962 §2 groups the "log behavior" operations together.
    ///
    /// It delegates to [`verify_inclusion_proof`], which takes no
    /// verifier. Prefer that function when inclusion proofs are all you
    /// need — a CT monitor with a captured STH should not have to build
    /// an `SctVerifier` whose log list and signature verifier are never
    /// consulted.
    pub fn verify_inclusion(
        &self,
        leaf_hash: &[u8; 32],
        proof: &MerkleAuditPath,
        root_hash: &[u8; 32],
    ) -> Result<()> {
        verify_inclusion_proof(leaf_hash, proof, root_hash)
    }

    /// Verify a Signed Tree Head's signature against the log's
    /// public key (RFC 6962 §3.5).
    ///
    /// `log_id` identifies which log signed the STH (a SHA-256 hash
    /// of the log's `SubjectPublicKeyInfo` DER, per RFC 6962 §3.2).
    /// The verifier looks up the matching [`CtLog`] in its
    /// [`CtLogList`] and dispatches signature verification through
    /// the configured [`SignatureVerifier`].
    ///
    /// The signed structure (RFC 6962 §3.5) is:
    ///
    /// ```text
    /// digitally-signed struct {
    ///     Version version;            // 1 byte; v1 = 0
    ///     SignatureType signature_type;  // 1 byte; tree_hash = 1
    ///     uint64 timestamp;           // 8 bytes BE
    ///     uint64 tree_size;           // 8 bytes BE
    ///     opaque sha256_root_hash[32];
    /// } TreeHeadSignature;
    /// ```
    ///
    /// On success the matching [`CtLog`] is returned so the caller
    /// can correlate the STH with the log entry it came from.
    ///
    /// # Errors
    ///
    /// - [`Error::UnknownLog`] — `log_id` is not present in the log list.
    /// - [`Error::UnsupportedSignatureAlgorithm`] — `(hash_alg, sig_alg)`
    ///   is not a recognised combination.
    /// - [`Error::LogKeyMalformed`] — the log's `key_der` does not
    ///   parse as a valid `SubjectPublicKeyInfo`.
    /// - [`Error::InvalidSignature`] — the underlying verifier
    ///   rejected the signature. Tampered timestamp, tree_size, or
    ///   root_hash bytes all surface as this variant.
    pub fn verify_sth(&self, log_id: &[u8; 32], sth: &SignedTreeHead) -> Result<&CtLog> {
        let log = self.logs.get(log_id).ok_or(Error::UnknownLog)?;

        let oid = tls_alg_to_x509_oid(sth.hash_alg, sth.sig_alg).ok_or(
            Error::UnsupportedSignatureAlgorithm {
                hash_alg: sth.hash_alg,
                sig_alg: sth.sig_alg,
            },
        )?;

        let signed_input = build_signed_input_tree_head(sth);

        let spki =
            SubjectPublicKeyInfoRef::from_der(&log.key_der).map_err(|_| Error::LogKeyMalformed)?;

        let alg_id = AlgorithmIdentifierRef {
            oid,
            parameters: None,
        };

        self.verifier
            .verify_signature(alg_id, spki, &signed_input, &sth.signature)
            .map_err(|_| Error::InvalidSignature)?;

        Ok(log)
    }
}

/// Reconstruct the RFC 6962 §3.5 `digitally-signed` input for an STH.
///
/// Layout (all multi-byte fields are network byte order):
///
/// ```text
/// u8       version             (0)
/// u8       signature_type      (1 = tree_hash)
/// u64      timestamp_ms
/// u64      tree_size
/// 32B      sha256_root_hash
/// ```
fn build_signed_input_tree_head(sth: &SignedTreeHead) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::with_capacity(1 + 1 + 8 + 8 + 32);
    out.push(SCT_VERSION_V1);
    out.push(SIG_TYPE_TREE_HASH);
    out.extend_from_slice(&sth.timestamp_ms.to_be_bytes());
    out.extend_from_slice(&sth.tree_size.to_be_bytes());
    out.extend_from_slice(&sth.root_hash);
    out
}

/// `SignatureType::tree_hash` — RFC 6962 §3.5 (used by STH signatures).
const SIG_TYPE_TREE_HASH: u8 = 1;

/// A Signed Tree Head: the log's signed commitment to a tree state
/// (RFC 6962 §3.5).
///
/// An STH is the trust anchor for Merkle inclusion proofs: the log
/// periodically publishes an STH committing to its current tree size,
/// root hash, and timestamp. Consumers cache STHs from logs they
/// trust, and any inclusion proof against `root_hash` is only as
/// trustworthy as the STH it was checked against.
///
/// `pkix-ct` does not parse STHs from log responses (the JSON
/// `get-sth` API is log-specific transport); the caller constructs
/// this struct from whichever source they fetch STHs from.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct SignedTreeHead {
    /// Tree size at the time the STH was signed.
    pub tree_size: u64,
    /// Timestamp the log committed to, milliseconds since Unix epoch.
    pub timestamp_ms: u64,
    /// Merkle root hash for the tree at `tree_size`.
    pub root_hash: [u8; 32],
    /// `HashAlgorithm` (RFC 5246 §7.4.1.4.1).
    pub hash_alg: u8,
    /// `SignatureAlgorithm` (RFC 5246 §7.4.1.4.1).
    pub sig_alg: u8,
    /// Raw signature bytes (DER-encoded ECDSA-Sig-Value for ECDSA, or
    /// raw RSA signature octet string for RSA).
    pub signature: alloc::vec::Vec<u8>,
}

impl SignedTreeHead {
    /// Construct a `SignedTreeHead` from its constituent fields.
    #[must_use]
    pub fn new(
        tree_size: u64,
        timestamp_ms: u64,
        root_hash: [u8; 32],
        hash_alg: u8,
        sig_alg: u8,
        signature: alloc::vec::Vec<u8>,
    ) -> Self {
        Self {
            tree_size,
            timestamp_ms,
            root_hash,
            hash_alg,
            sig_alg,
            signature,
        }
    }
}

/// An audit path proving a single leaf's inclusion in an RFC 6962 §2
/// Merkle tree at some `tree_size`.
///
/// Built either from a CT log's `get-proof-by-hash` response (parsed
/// out of the response JSON by the caller) or programmatically. The
/// type does not currently carry parser methods — `pkix-ct` is
/// transport-agnostic.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct MerkleAuditPath {
    /// 0-based index of the leaf in the tree.
    pub leaf_index: u64,
    /// Total number of leaves in the tree at the time the proof was
    /// generated. Must equal the `tree_size` of the
    /// [`SignedTreeHead`] whose `root_hash` is being checked against.
    pub tree_size: u64,
    /// Sibling hashes from leaf-to-root, ordered RFC 6962 §2.1.1-style
    /// (innermost sibling first, root's-direct-child sibling last).
    pub audit_path: alloc::vec::Vec<[u8; 32]>,
}

impl MerkleAuditPath {
    /// Construct a `MerkleAuditPath` from its constituent fields.
    #[must_use]
    pub fn new(leaf_index: u64, tree_size: u64, audit_path: alloc::vec::Vec<[u8; 32]>) -> Self {
        Self {
            leaf_index,
            tree_size,
            audit_path,
        }
    }
}

/// Hash-only worker for [`SctVerifier::verify_inclusion`].
///
/// Implements RFC 9162 §2.1.3.2 (the verification-side restatement of
/// RFC 6962 §2.1.1). This is the iterative form used by every shipped
/// open-source CT implementation (certificate-transparency-go,
/// Trillian, etc.) — chosen over the recursive RFC 6962 §2.1.1
/// statement because the iterative form avoids stack allocations and
/// terminates exactly when the audit path is exhausted.
/// Verify a Merkle audit path against an expected root hash
/// (RFC 6962 §2.1).
///
/// Hash-only: no log list, no signature verifier, no certificate. A CT
/// monitor holding an STH it has already verified can check proofs in a
/// loop with nothing else.
///
/// The same check is available as
/// [`SctVerifier::verify_inclusion`](SctVerifier::verify_inclusion) for
/// callers who already hold a verifier. That method delegates here; it
/// exists for discoverability, since callers verifying SCTs are usually
/// the ones who will want inclusion proofs too. This function exists
/// because requiring an `SctVerifier` — which means inventing a
/// [`CtLogList`](crate::CtLogList) and a
/// [`SignatureVerifier`](pkix_path::SignatureVerifier) that are never
/// consulted — is a steep price for a hash comparison.
///
/// It sits alongside [`merkle_leaf_hash`] and
/// [`merkle_tree_leaf_for_cert`], which are free functions for the same
/// reason: computing a leaf hash needs no verifier either.
///
/// # Errors
///
/// - [`Error::MerkleProofMalformed`] — `tree_size` is 0, or the audit
///   path is longer than the maximum height for the tree size
///   (`ceil(log2(tree_size))` hashes), indicating a buggy proof source
///   or a tampered proof.
/// - [`Error::MerkleProofInvalid`] — `leaf_index >= tree_size`, or the
///   reconstructed root does not match `expected_root`. A single changed
///   byte anywhere — an audit-path hash, the leaf hash, the index, the
///   tree size, the expected root — surfaces as this variant.
pub fn verify_inclusion_proof(
    leaf_hash: &[u8; 32],
    proof: &MerkleAuditPath,
    expected_root: &[u8; 32],
) -> Result<()> {
    if proof.tree_size == 0 {
        return Err(Error::MerkleProofMalformed);
    }
    if proof.leaf_index >= proof.tree_size {
        return Err(Error::MerkleProofInvalid);
    }
    // Maximum audit path length for a tree of N leaves is ceil(log2(N))
    // (no path elements for N=1). Any longer is malformed.
    let max_path_len = if proof.tree_size <= 1 {
        0
    } else {
        // `64 - leading_zeros(N - 1)` = ceil(log2(N)) for N >= 2.
        64 - (proof.tree_size - 1).leading_zeros() as usize
    };
    if proof.audit_path.len() > max_path_len {
        return Err(Error::MerkleProofMalformed);
    }

    let mut fn_ = proof.leaf_index;
    let mut sn = proof.tree_size - 1;
    let mut r: [u8; 32] = *leaf_hash;

    for p in &proof.audit_path {
        if sn == 0 {
            // Audit path has more elements than the tree size
            // justifies — proof is over-long.
            return Err(Error::MerkleProofMalformed);
        }
        if (fn_ & 1) == 1 || fn_ == sn {
            // The leaf is on the right of this internal node, or it
            // is the rightmost leaf in an odd-sized subtree (the
            // left-leaning rebalance from RFC 6962 §2.1).
            r = inner_hash(p, &r);
            // Bubble both fn_ and sn up until LSB(fn_) == 1 again
            // (or fn_ == 0, meaning we've processed all the
            // rebalance shifts).
            while (fn_ & 1) == 0 && fn_ != 0 {
                fn_ >>= 1;
                sn >>= 1;
            }
        } else {
            // Standard left-child case: sibling is on the right.
            r = inner_hash(&r, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }

    if sn != 0 {
        // The audit path was shorter than the tree size required —
        // the proof never bubbled all the way to the root.
        return Err(Error::MerkleProofMalformed);
    }
    if r != *expected_root {
        return Err(Error::MerkleProofInvalid);
    }
    Ok(())
}

/// RFC 6962 §2.1 inner-node hash: `SHA256(0x01 || left || right)`.
fn inner_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01u8]);
    h.update(left);
    h.update(right);
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// RFC 6962 §2.1 leaf hash: `SHA256(0x00 || leaf_bytes)`.
///
/// Computes the leaf hash of a `MerkleTreeLeaf` byte string. Callers
/// that have parsed an SCT and want to feed it through
/// [`SctVerifier::verify_inclusion`] use this helper to derive the
/// 32-byte leaf hash from the `MerkleTreeLeaf` bytes the log
/// committed to.
#[must_use]
pub fn merkle_leaf_hash(leaf_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00u8]);
    h.update(leaf_bytes);
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Build the RFC 6962 §3.4 `MerkleTreeLeaf` byte string for an
/// `x509_entry` SCT.
///
/// Layout (all multi-byte fields are network byte order):
///
/// ```text
/// u8       version              (0 = v1)
/// u8       leaf_type            (0 = timestamped_entry)
/// u64      timestamp_ms         (from the SCT)
/// u16      entry_type           (0 = x509_entry)
/// u24, len cert_der             (ASN.1Cert: opaque<1..2^24-1>)
/// u16, len extensions           (from the SCT)
/// ```
///
/// The resulting byte string is what the log committed to in its
/// Merkle tree. Feed it through [`merkle_leaf_hash`] to get the
/// 32-byte leaf hash that [`SctVerifier::verify_inclusion`] expects.
///
/// Errors with [`Error::CertDerTooLong`] if `cert_der` exceeds the RFC
/// 6962 §3.2 u24 length prefix, or [`Error::SctExtensionsTooLong`] if
/// `sct.extensions` exceeds the u16 `CtExtensions` length prefix.
///
/// For `precert_entry` SCTs (the common case for SCTs embedded in
/// final certs — RFC 6962 §3.1), use
/// [`merkle_tree_leaf_for_precert`] instead.
pub fn merkle_tree_leaf_for_cert(
    sct: &SignedCertificateTimestamp,
    cert_der: &[u8],
) -> Result<Vec<u8>> {
    build_merkle_tree_leaf_x509_entry(sct, cert_der)
}

/// Build the RFC 6962 §3.4 `MerkleTreeLeaf` byte string for a
/// `precert_entry` SCT.
///
/// Layout (all multi-byte fields are network byte order):
///
/// ```text
/// u8       version              (0 = v1)
/// u8       leaf_type            (0 = timestamped_entry)
/// u64      timestamp_ms         (from the SCT)
/// u16      entry_type           (1 = precert_entry)
/// 32B      issuer_key_hash      (SHA256 of issuer SPKI DER)
/// u24, len tbs_no_sct           (TBSCertificate with SCT-list
///                                extension removed, opaque<1..2^24-1>)
/// u16, len extensions           (from the SCT)
/// ```
///
/// `leaf_cert_der` is the FINAL (issued) cert carrying the embedded
/// SCT extension; the helper strips OID 1.3.6.1.4.1.11129.2.4.2 from
/// its TBSCertificate to reconstruct the bytes the log saw at
/// pre-cert submission time. `issuer_cert_der` is the issuing CA
/// cert; its SubjectPublicKeyInfo is hashed to produce
/// `issuer_key_hash`.
///
/// Feed the returned bytes through [`merkle_leaf_hash`] to get the
/// 32-byte leaf hash that [`SctVerifier::verify_inclusion`] expects.
///
/// Errors with [`Error::LeafMissingSctList`] if `leaf_cert_der` does
/// not carry the SCT-list extension; [`Error::ParseError`] if either
/// cert fails to parse; [`Error::CertDerTooLong`] if the re-encoded
/// TBS exceeds the u24 length prefix; [`Error::SctExtensionsTooLong`]
/// if `sct.extensions` exceeds the u16 `CtExtensions` length prefix.
pub fn merkle_tree_leaf_for_precert(
    sct: &SignedCertificateTimestamp,
    leaf_cert_der: &[u8],
    issuer_cert_der: &[u8],
) -> Result<Vec<u8>> {
    let tbs_no_sct = tbs_without_sct_list(leaf_cert_der)?;
    let issuer_key_hash = issuer_key_hash_from_cert(issuer_cert_der)?;
    build_merkle_tree_leaf_precert_entry(sct, &issuer_key_hash, &tbs_no_sct)
}

/// Length of `sct.extensions` as the RFC 6962 §3.2 `CtExtensions`
/// u16 length prefix (`opaque extensions<0..2^16-1>`).
///
/// The wire parser can never produce a longer field, but
/// [`SignedCertificateTimestamp`] has public fields and a public
/// constructor, so the bound is re-checked here instead of truncating
/// the prefix with `as u16` (which would misframe the signed input).
fn sct_extensions_len(sct: &SignedCertificateTimestamp) -> Result<u16> {
    u16::try_from(sct.extensions.len()).map_err(|_| Error::SctExtensionsTooLong)
}

/// MerkleTreeLeaf builder for the x509_entry case. Shares the wire
/// layout from byte index 2 onward with [`build_signed_input_x509_entry`];
/// the difference is the byte at index 1
/// (`leaf_type=timestamped_entry` here vs `signature_type=certificate_timestamp`
/// there — both happen to be the u8 value `0`, but the semantic
/// distinction is documented by the constant name).
fn build_merkle_tree_leaf_x509_entry(
    sct: &SignedCertificateTimestamp,
    cert_der: &[u8],
) -> Result<Vec<u8>> {
    if cert_der.len() > 0x00FF_FFFF {
        return Err(Error::CertDerTooLong);
    }
    let ext_len = sct_extensions_len(sct)?;

    let cert_len = cert_der.len();
    let cap = 1 + 1 + 8 + 2 + 3 + cert_len + 2 + sct.extensions.len();
    let mut out = Vec::with_capacity(cap);
    out.push(SCT_VERSION_V1);
    out.push(MERKLE_LEAF_TYPE_TIMESTAMPED_ENTRY);
    out.extend_from_slice(&sct.timestamp_ms.to_be_bytes());
    out.extend_from_slice(&ENTRY_TYPE_X509.to_be_bytes());
    out.push(((cert_len >> 16) & 0xFF) as u8);
    out.extend_from_slice(&(cert_len as u16).to_be_bytes());
    out.extend_from_slice(cert_der);
    out.extend_from_slice(&ext_len.to_be_bytes());
    out.extend_from_slice(&sct.extensions);
    Ok(out)
}

/// MerkleTreeLeaf builder for the precert_entry case. See
/// [`build_merkle_tree_leaf_x509_entry`] for the byte-index-1 distinction
/// versus [`build_signed_input_precert_entry`].
fn build_merkle_tree_leaf_precert_entry(
    sct: &SignedCertificateTimestamp,
    issuer_key_hash: &[u8; 32],
    tbs_no_sct: &[u8],
) -> Result<Vec<u8>> {
    if tbs_no_sct.len() > 0x00FF_FFFF {
        return Err(Error::CertDerTooLong);
    }
    let ext_len = sct_extensions_len(sct)?;

    let tbs_len = tbs_no_sct.len();
    let cap = 1 + 1 + 8 + 2 + 32 + 3 + tbs_len + 2 + sct.extensions.len();
    let mut out = Vec::with_capacity(cap);
    out.push(SCT_VERSION_V1);
    out.push(MERKLE_LEAF_TYPE_TIMESTAMPED_ENTRY);
    out.extend_from_slice(&sct.timestamp_ms.to_be_bytes());
    out.extend_from_slice(&ENTRY_TYPE_PRECERT.to_be_bytes());
    out.extend_from_slice(issuer_key_hash);
    out.push(((tbs_len >> 16) & 0xFF) as u8);
    out.extend_from_slice(&(tbs_len as u16).to_be_bytes());
    out.extend_from_slice(tbs_no_sct);
    out.extend_from_slice(&ext_len.to_be_bytes());
    out.extend_from_slice(&sct.extensions);
    Ok(out)
}

/// Check whether `timestamp_ms` falls inside the log's usable window.
///
/// RFC 6962 §3.5 / §6.2 (and CT log lifecycle documentation) describe
/// `usable_from`/`retired_at` as inclusive lower and upper bounds: SCTs
/// timestamped at or after `usable_from` and strictly before
/// `retired_at` are trustworthy. `usable_from_ms = None` means the log
/// has never reached the usable state, so the check always fails.
/// `retired_at_ms = None` means the log has not been retired, so the
/// upper bound is unbounded.
fn log_window_contains(log: &CtLog, timestamp_ms: u64) -> bool {
    match log.usable_from {
        UsableFrom::At(lo) if timestamp_ms < lo => return false,
        UsableFrom::At(_) | UsableFrom::Unrecorded => {}
        // Nothing this log signed is trusted, so no timestamp is
        // inside its window.
        UsableFrom::Never => return false,
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
    // The wire parser bounds extensions to u16, but `sct` may have been
    // built via the public constructor / fields; check rather than trust.
    let ext_len = sct_extensions_len(sct)?;

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
    out.extend_from_slice(&ext_len.to_be_bytes());
    out.extend_from_slice(&sct.extensions);
    Ok(out)
}

/// Reconstruct the RFC 6962 §3.2 `digitally-signed` input for a
/// `precert_entry` SCT.
///
/// Layout (all multi-byte fields are network byte order):
///
/// ```text
/// u8       version              (0)
/// u8       signature_type       (0 = certificate_timestamp)
/// u64      timestamp_ms
/// u16      entry_type           (1 = precert_entry)
/// 32B      issuer_key_hash
/// u24, len tbs_no_sct           (TBSCertificate with SCT-list extension
///                                removed, opaque<1..2^24-1>)
/// u16, len extensions
/// ```
fn build_signed_input_precert_entry(
    sct: &SignedCertificateTimestamp,
    issuer_key_hash: &[u8; 32],
    tbs_no_sct: &[u8],
) -> Result<Vec<u8>> {
    if tbs_no_sct.len() > 0x00FF_FFFF {
        return Err(Error::CertDerTooLong);
    }
    let ext_len = sct_extensions_len(sct)?;

    let tbs_len = tbs_no_sct.len();
    let cap = 1 + 1 + 8 + 2 + 32 + 3 + tbs_len + 2 + sct.extensions.len();
    let mut out = Vec::with_capacity(cap);
    out.push(SCT_VERSION_V1);
    out.push(SIG_TYPE_CERTIFICATE_TIMESTAMP);
    out.extend_from_slice(&sct.timestamp_ms.to_be_bytes());
    out.extend_from_slice(&ENTRY_TYPE_PRECERT.to_be_bytes());
    out.extend_from_slice(issuer_key_hash);
    out.push(((tbs_len >> 16) & 0xFF) as u8);
    out.extend_from_slice(&(tbs_len as u16).to_be_bytes());
    out.extend_from_slice(tbs_no_sct);
    out.extend_from_slice(&ext_len.to_be_bytes());
    out.extend_from_slice(&sct.extensions);
    Ok(out)
}

/// Remove the SCT-list extension (OID 1.3.6.1.4.1.11129.2.4.2) from
/// `leaf_cert_der`'s TBSCertificate and return the resulting TBS DER.
///
/// # What this does not do
///
/// It does not re-encode the certificate. RFC 6962 §3.2 signs the
/// bytes the log was given, so the reconstruction has to reproduce
/// them, and nothing obliges an encoder to reproduce its own input:
/// `x509-cert` may normalise a `GeneralizedTime` that could have been
/// a `UTCTime`, re-sort a `SET OF` the original CA left unsorted, or
/// pick a different string type for an equivalent value. Any of those
/// shifts a byte, the signature check fails, and the caller is told a
/// valid certificate carries an invalid SCT — a report that looks
/// exactly like forgery and points nowhere near the encoder.
///
/// So every byte here is copied from `leaf_cert_der`. The only bytes
/// written are the three length fields that have to shrink: the
/// extensions `SEQUENCE`, its `[3] EXPLICIT` wrapper, and the
/// TBSCertificate `SEQUENCE`. Tag octets are copied too, not
/// reconstructed.
///
/// This replaced a parse-and-re-encode implementation that was correct
/// for canonically-encoded certificates and silently wrong for any
/// other. `pkix-ct/tests/fixtures/sct-oracle/gen_precert_entry_sct.py`
/// strips the extension independently in Python and commits the result,
/// which `tbs_without_sct_list_matches_oracle_bytes` compares against.
///
/// # Errors
///
/// - [`Error::LeafMissingSctList`] — no extensions, or no SCT-list
///   extension among them.
/// - [`Error::DuplicateSctListExtension`] — more than one. RFC 5280
///   §4.2 forbids it, and which one the log saw is unknowable.
/// - [`Error::ParseError`] — the certificate is not well-formed DER to
///   the depth this needs to walk.
/// - [`Error::CertDerTooLong`] — the TBS does not fit the RFC 6962
///   §3.2 `u24` length prefix.
fn tbs_without_sct_list(leaf_cert_der: &[u8]) -> Result<Vec<u8>> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
    // signatureValue }, so the first triple inside is the TBS.
    let cert =
        raw_der::read_tagged(leaf_cert_der, raw_der::TAG_SEQUENCE).ok_or(Error::ParseError)?;
    let cert_body = cert.value(leaf_cert_der);
    let tbs = raw_der::read_tagged(cert_body, raw_der::TAG_SEQUENCE).ok_or(Error::ParseError)?;
    let tbs_tag = tbs.tag;
    let tbs_body = tbs.value(cert_body);

    // `extensions` is `[3] EXPLICIT`, which no other TBSCertificate
    // field can be mistaken for, so find it by tag rather than by
    // position.
    let (ext_off, ext_wrapper) = raw_der::tlvs(tbs_body)
        .ok_or(Error::ParseError)?
        .into_iter()
        .find(|(_, tlv)| tlv.tag == raw_der::TAG_EXTENSIONS)
        .ok_or(Error::LeafMissingSctList)?;
    let wrapper_body =
        &tbs_body[ext_off + ext_wrapper.header_len..ext_off + ext_wrapper.total_len()];

    // Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
    let exts =
        raw_der::read_tagged(wrapper_body, raw_der::TAG_SEQUENCE).ok_or(Error::ParseError)?;
    let exts_body = exts.value(wrapper_body);

    // Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER, ... }, so the
    // first triple inside each one is the OID to match on.
    let mut target: Option<(usize, usize)> = None;
    for (off, ext) in raw_der::tlvs(exts_body).ok_or(Error::ParseError)? {
        if ext.tag != raw_der::TAG_SEQUENCE {
            return Err(Error::ParseError);
        }
        let body = &exts_body[off + ext.header_len..off + ext.total_len()];
        let oid = raw_der::read_tagged(body, raw_der::TAG_OID).ok_or(Error::ParseError)?;
        if oid.value(body) == OID_SCT_LIST_BYTES {
            if target.is_some() {
                return Err(Error::DuplicateSctListExtension);
            }
            target = Some((off, ext.total_len()));
        }
    }
    let (target_off, target_len) = target.ok_or(Error::LeafMissingSctList)?;

    // The extensions SEQUENCE without that one Extension's octets.
    let mut new_exts_body = Vec::with_capacity(exts_body.len() - target_len);
    new_exts_body.extend_from_slice(&exts_body[..target_off]);
    new_exts_body.extend_from_slice(&exts_body[target_off + target_len..]);

    let mut new_tbs_body = Vec::with_capacity(tbs_body.len());
    new_tbs_body.extend_from_slice(&tbs_body[..ext_off]);
    if !new_exts_body.is_empty() {
        let mut new_exts = Vec::with_capacity(new_exts_body.len() + 6);
        raw_der::push_header(&mut new_exts, exts.tag, new_exts_body.len());
        new_exts.extend_from_slice(&new_exts_body);
        raw_der::push_header(&mut new_tbs_body, ext_wrapper.tag, new_exts.len());
        new_tbs_body.extend_from_slice(&new_exts);
    }
    // When the SCT-list was the only extension the whole `[3]` field is
    // dropped: RFC 5280 §4.1.2.9 requires an absent field rather than
    // an empty SEQUENCE, and that is also what the log signed.
    new_tbs_body.extend_from_slice(&tbs_body[ext_off + ext_wrapper.total_len()..]);

    let mut out = Vec::with_capacity(new_tbs_body.len() + 6);
    raw_der::push_header(&mut out, tbs_tag, new_tbs_body.len());
    out.extend_from_slice(&new_tbs_body);
    if out.len() > 0x00FF_FFFF {
        return Err(Error::CertDerTooLong);
    }
    Ok(out)
}

/// Parse `issuer_cert_der` and return SHA-256 of its
/// `SubjectPublicKeyInfo` DER bytes.
///
/// This is the `issuer_key_hash` field of the RFC 6962 §3.2 `PreCert`
/// structure. The hash is computed over the canonical DER encoding of
/// the issuer's `SubjectPublicKeyInfo` (the same form used by every
/// X.509 verifier when working with the issuer's public key). For
/// every real-world CT-logged issuer cert this matches the bytes a CT
/// log would have hashed at submission time, because real issuer
/// certs use canonical DER for their SPKI.
///
/// Returns [`Error::ParseError`] if the cert or its SPKI cannot be
/// parsed.
fn issuer_key_hash_from_cert(issuer_cert_der: &[u8]) -> Result<[u8; 32]> {
    let spki = spki_bytes(issuer_cert_der)?;
    let digest = Sha256::digest(spki);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

/// The `subjectPublicKeyInfo` octets of `cert_der`, as they appear in
/// `cert_der`.
///
/// Returned by reference into the input rather than re-encoded, for
/// the reason given on [`tbs_without_sct_list`]: this hash goes into a
/// signed input, so a byte the encoder chose differently from the CA
/// is a verification failure blamed on the signature.
///
/// Located positionally, because unlike `extensions` the field carries
/// no distinguishing tag — it is a `SEQUENCE`, as are four of the
/// fields before it. RFC 5280 §4.1 fixes that order:
///
/// ```text
/// TBSCertificate ::= SEQUENCE {
///     version         [0] EXPLICIT Version DEFAULT v1,  -- optional
///     serialNumber        CertificateSerialNumber,
///     signature           AlgorithmIdentifier,
///     issuer              Name,
///     validity            Validity,
///     subject             Name,
///     subjectPublicKeyInfo SubjectPublicKeyInfo,
///     ...
/// }
/// ```
///
/// Only `version` is optional, and it is `[0] EXPLICIT`, so skipping
/// it when present and then counting five mandatory fields lands on
/// the key. A v1 certificate omits it and the count starts at
/// `serialNumber`, which is checked rather than assumed.
///
/// # Errors
///
/// [`Error::ParseError`] if the certificate is not well-formed DER to
/// that depth, or if the fields are not in the order RFC 5280 fixes.
fn spki_bytes(cert_der: &[u8]) -> Result<&[u8]> {
    let cert = raw_der::read_tagged(cert_der, raw_der::TAG_SEQUENCE).ok_or(Error::ParseError)?;
    let cert_body = cert.value(cert_der);
    let tbs = raw_der::read_tagged(cert_body, raw_der::TAG_SEQUENCE).ok_or(Error::ParseError)?;
    let tbs_body = tbs.value(cert_body);

    let fields = raw_der::tlvs(tbs_body).ok_or(Error::ParseError)?;
    let mut fields = fields.into_iter();
    let mut next = fields.next().ok_or(Error::ParseError)?;
    if next.1.tag == raw_der::TAG_VERSION {
        next = fields.next().ok_or(Error::ParseError)?;
    }
    // serialNumber, then signature / issuer / validity / subject.
    if next.1.tag != raw_der::TAG_INTEGER {
        return Err(Error::ParseError);
    }
    for _ in 0..4 {
        next = fields.next().ok_or(Error::ParseError)?;
        if next.1.tag != raw_der::TAG_SEQUENCE {
            return Err(Error::ParseError);
        }
    }
    let (off, spki) = fields.next().ok_or(Error::ParseError)?;
    if spki.tag != raw_der::TAG_SEQUENCE {
        return Err(Error::ParseError);
    }
    Ok(&tbs_body[off..off + spki.total_len()])
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
    fn log_window_never_usable() {
        // The log never reached the usable state, so the window
        // check must always fail.
        let log = CtLog {
            log_id: [0u8; 32],
            key_der: Vec::new(),
            description: "test".into(),
            url: "http://example.com/".into(),
            usable_from: UsableFrom::Never,
            retired_at_ms: None,
        };
        assert!(!log_window_contains(&log, 0));
        assert!(!log_window_contains(&log, u64::MAX));
    }

    #[test]
    /// The two states that `Option<u64>` could not tell apart must
    /// give opposite answers.
    ///
    /// `usable_from_ms: Option<u64>` had `None` meaning "never became
    /// usable, reject everything" while the log-list importer needed a
    /// value for "usable, but the list does not say since when" and
    /// used `Some(0)` — relying on nothing predating the Unix epoch.
    /// Two states, one of them a sentinel. They are now named, and
    /// this is the assertion that was not previously expressible
    /// without encoding that convention into the test.
    #[test]
    fn an_unrecorded_start_is_not_the_same_as_never_usable() {
        let log = |usable_from| CtLog {
            log_id: [0u8; 32],
            key_der: Vec::new(),
            description: "test".into(),
            url: "http://example.com/".into(),
            usable_from,
            retired_at_ms: None,
        };
        for ts in [0, 1, 1_700_000_000_000, u64::MAX] {
            assert!(
                log_window_contains(&log(UsableFrom::Unrecorded), ts),
                "an unrecorded start imposes no lower bound, so {ts} is inside"
            );
            assert!(
                !log_window_contains(&log(UsableFrom::Never), ts),
                "a log that never became usable vouches for nothing, so {ts} is outside"
            );
        }
    }

    #[test]
    fn log_window_unbounded_upper() {
        // No recorded lower bound and no retirement: the window is
        // open at both ends, accepting any timestamp.
        let log = CtLog {
            log_id: [0u8; 32],
            key_der: Vec::new(),
            description: "test".into(),
            url: "http://example.com/".into(),
            usable_from: UsableFrom::Unrecorded,
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
            usable_from: UsableFrom::At(1_000),
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
            usable_from: UsableFrom::Unrecorded,
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

    /// Independent oracle for the precert_entry signed-input layout:
    /// byte-for-byte hand-decoded values against RFC 6962 §3.2.
    #[test]
    fn precert_signed_input_layout() {
        let mut sct = empty_sct(4, 3);
        sct.timestamp_ms = 0x0123_4567_89AB_CDEF;
        sct.extensions = vec![0xAA, 0xBB];
        let issuer_key_hash = [0x11u8; 32];
        let tbs = b"hello";
        let out = build_signed_input_precert_entry(&sct, &issuer_key_hash, tbs).unwrap();
        // Expected bytes:
        //   00                          version = 0
        //   00                          signature_type = certificate_timestamp
        //   01 23 45 67 89 AB CD EF     timestamp_ms (BE)
        //   00 01                       entry_type = precert_entry
        //   11 * 32                     issuer_key_hash
        //   00 00 05                    u24 tbs_len = 5
        //   68 65 6C 6C 6F              "hello"
        //   00 02                       ext_len = 2
        //   AA BB                       extensions
        let mut expected = Vec::with_capacity(1 + 1 + 8 + 2 + 32 + 3 + 5 + 2 + 2);
        expected.extend_from_slice(&[0x00, 0x00]);
        expected.extend_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
        expected.extend_from_slice(&[0x00, 0x01]);
        expected.extend_from_slice(&[0x11; 32]);
        expected.extend_from_slice(&[0x00, 0x00, 0x05]);
        expected.extend_from_slice(b"hello");
        expected.extend_from_slice(&[0x00, 0x02, 0xAA, 0xBB]);
        assert_eq!(out, expected);
    }

    #[test]
    fn precert_signed_input_rejects_oversize_tbs() {
        let sct = empty_sct(4, 3);
        let issuer_key_hash = [0u8; 32];
        let huge = vec![0u8; 0x0100_0000];
        assert_eq!(
            build_signed_input_precert_entry(&sct, &issuer_key_hash, &huge),
            Err(Error::CertDerTooLong)
        );
    }

    /// PKIX-yzb6 acceptance — byte-layout oracle for the x509_entry
    /// MerkleTreeLeaf builder. Hand-decoded against RFC 6962 §3.4.
    ///
    /// The byte pattern is byte-equal to the corresponding
    /// `build_signed_input_x509_entry` output because both
    /// `MerkleLeafType::timestamped_entry` and
    /// `SignatureType::certificate_timestamp` are encoded as the u8
    /// value `0`. The test still asserts the literal expected bytes so
    /// any future divergence (e.g. RFC 9162 v2 raising one of the
    /// values to a non-zero variant) is caught.
    #[test]
    fn merkle_tree_leaf_x509_entry_layout() {
        let mut sct = empty_sct(4, 3);
        sct.timestamp_ms = 0x0123_4567_89AB_CDEF;
        sct.extensions = vec![0xAA, 0xBB];
        let cert = b"hello";
        let out = build_merkle_tree_leaf_x509_entry(&sct, cert).unwrap();
        // Expected bytes (compare with signed_input_layout above):
        //   00                          version = 0
        //   00                          leaf_type = timestamped_entry
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

    /// PKIX-yzb6 acceptance — byte-layout oracle for the
    /// precert_entry MerkleTreeLeaf builder. Hand-decoded against RFC
    /// 6962 §3.4.
    #[test]
    fn merkle_tree_leaf_precert_entry_layout() {
        let mut sct = empty_sct(4, 3);
        sct.timestamp_ms = 0x0123_4567_89AB_CDEF;
        sct.extensions = vec![0xAA, 0xBB];
        let issuer_key_hash = [0x11u8; 32];
        let tbs = b"hello";
        let out = build_merkle_tree_leaf_precert_entry(&sct, &issuer_key_hash, tbs).unwrap();
        let mut expected = Vec::with_capacity(1 + 1 + 8 + 2 + 32 + 3 + 5 + 2 + 2);
        expected.extend_from_slice(&[0x00, 0x00]); // version=0, leaf_type=0
        expected.extend_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
        expected.extend_from_slice(&[0x00, 0x01]); // entry_type=precert
        expected.extend_from_slice(&[0x11; 32]);
        expected.extend_from_slice(&[0x00, 0x00, 0x05]); // u24 tbs_len=5
        expected.extend_from_slice(b"hello");
        expected.extend_from_slice(&[0x00, 0x02, 0xAA, 0xBB]);
        assert_eq!(out, expected);
    }

    #[test]
    fn merkle_tree_leaf_x509_entry_rejects_oversize_cert() {
        let sct = empty_sct(4, 3);
        let huge = vec![0u8; 0x0100_0000];
        assert_eq!(
            build_merkle_tree_leaf_x509_entry(&sct, &huge),
            Err(Error::CertDerTooLong)
        );
    }

    #[test]
    fn merkle_tree_leaf_precert_entry_rejects_oversize_tbs() {
        let sct = empty_sct(4, 3);
        let issuer_key_hash = [0u8; 32];
        let huge = vec![0u8; 0x0100_0000];
        assert_eq!(
            build_merkle_tree_leaf_precert_entry(&sct, &issuer_key_hash, &huge),
            Err(Error::CertDerTooLong)
        );
    }

    /// PKIX-yzb6: byte index 1 of the MerkleTreeLeaf is named
    /// `leaf_type`, not `signature_type`. Currently both happen to be
    /// the u8 value 0, but the constants document the semantic
    /// distinction. This test pins the convention: if a future
    /// refactor pulls in a non-zero MerkleLeafType variant (RFC 9162
    /// CTv2 has yet to introduce one, but might) the test surfaces
    /// the change.
    #[test]
    fn merkle_tree_leaf_second_byte_is_leaf_type_not_signature_type() {
        let sct = empty_sct(4, 3);
        let mtl = build_merkle_tree_leaf_x509_entry(&sct, b"x").unwrap();
        assert_eq!(
            mtl[1], MERKLE_LEAF_TYPE_TIMESTAMPED_ENTRY,
            "byte 1 must be MerkleLeafType (timestamped_entry = 0), \
             NOT SignatureType (certificate_timestamp = 0)"
        );
    }

    /// Acceptance criterion 2 (PKIX-baac.4): the bytes produced by
    /// [`tbs_without_sct_list`] for the precert-oracle fixture's
    /// `precert-leaf-final.der` must match the oracle's committed
    /// `precert-tbs-no-sct.bin` (the TBS bytes the log signed over)
    /// byte-for-byte.
    ///
    /// The oracle generates `precert-tbs-no-sct.bin` independently of
    /// pkix-ct: it builds two cert objects via cryptography's
    /// `CertificateBuilder` (one with the SCT-list extension, one
    /// without) and takes the without-extension cert's
    /// `tbs_certificate_bytes` as the canonical "what the log signed"
    /// blob. The script's own self-test (in
    /// gen_precert_entry_sct.py) cross-checks this by ALSO running a
    /// hand-rolled DER walker that strips the SCT-list extension from
    /// the with-extension cert's TBS and asserts the result equals
    /// the without-extension cert's TBS.
    ///
    /// This test then asserts pkix-ct's reconstruction matches the
    /// oracle bytes, completing the bit-exactness chain:
    /// pkix-ct ↔ cryptography ↔ hand-rolled DER walker.
    ///
    /// Gated on `std` because it reads fixture files from disk; the
    /// integration test in `tests/verify_precert.rs` exercises the
    /// same path end-to-end for `no_std` builds via cargo's normal
    /// `std`-only integration-test machinery.
    #[cfg(feature = "std")]
    #[test]
    fn tbs_without_sct_list_matches_oracle_bytes() {
        let leaf_der = std::fs::read("tests/fixtures/sct-oracle/precert-leaf-final.der")
            .expect("read precert-leaf-final.der");
        let expected = std::fs::read("tests/fixtures/sct-oracle/precert-tbs-no-sct.bin")
            .expect("read precert-tbs-no-sct.bin");
        let actual = tbs_without_sct_list(&leaf_der).expect("strip SCT-list");
        assert_eq!(
            actual.len(),
            expected.len(),
            "reconstructed TBS length {} != oracle length {}",
            actual.len(),
            expected.len(),
        );
        assert_eq!(
            actual, expected,
            "reconstructed TBS bytes do not match the oracle's \
             precert-tbs-no-sct.bin; x509-cert's re-encoder may have \
             canonicalized something the cryptography emitter did \
             differently. Compare with `xxd` to diagnose.",
        );
    }

    /// Every certificate in this crate's fixtures that carries an
    /// SCT-list extension.
    ///
    /// Six certificates is not the "millions of CT-logged certs in
    /// deployment" that the old parse-and-re-encode implementation
    /// needed to be right about. It does not have to be: the property
    /// asserted below is that bytes are copied rather than re-encoded,
    /// and a copy cannot diverge on a certificate nobody tested.
    #[cfg(feature = "std")]
    pub(super) fn sct_bearing_fixtures() -> Vec<(&'static str, Vec<u8>)> {
        let der_files = [
            "tests/fixtures/sct-oracle/precert-leaf-final.der",
            "tests/fixtures/live-log/leaf.der",
            "tests/fixtures/invalid-sct-version.der",
            "tests/fixtures/invalid-sct-length.der",
            "tests/fixtures/review/leaf-dup-sct.der",
        ];
        let mut out: Vec<(&'static str, Vec<u8>)> = der_files
            .iter()
            .map(|p| {
                (
                    *p,
                    std::fs::read(p).unwrap_or_else(|e| panic!("read {p}: {e}")),
                )
            })
            .collect();

        // The Let's Encrypt leaf from pyca/cryptography's vectors, the
        // only PEM among them and the one issued by a real CA.
        let pem = std::fs::read_to_string("tests/fixtures/cryptography-scts.pem")
            .expect("read cryptography-scts.pem");
        let b64: String = pem
            .lines()
            .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE"))
            .skip(1)
            .take_while(|l| !l.starts_with("-----END CERTIFICATE"))
            .collect();
        let der = base64_decode(&b64).expect("decode cryptography-scts.pem");
        out.push(("tests/fixtures/cryptography-scts.pem", der));
        out
    }

    /// Minimal standard-alphabet base64, to read the one PEM fixture
    /// without a dependency for six lines of test support.
    #[cfg(feature = "std")]
    fn base64_decode(s: &str) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        let mut acc: u32 = 0;
        let mut bits = 0u32;
        for c in s.bytes() {
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' => break,
                b'\r' | b'\n' | b' ' | b'\t' => continue,
                _ => return None,
            };
            acc = (acc << 6) | u32::from(v);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push(((acc >> bits) & 0xFF) as u8);
            }
        }
        Some(out)
    }

    /// The reconstructed TBS must be the original TBS with one
    /// extension's octets removed — not a re-encoding of it.
    ///
    /// This is the property that retires the old implementation's
    /// correctness assumption. The old code parsed the certificate and
    /// asked `x509-cert` to emit it again, which is only faithful if
    /// the encoder reproduces its input byte for byte; where it did
    /// not, a valid SCT failed as `InvalidSignature` with nothing to
    /// point at the encoder. Copying cannot fail that way, and this
    /// asserts the copy really is one: every octet before the
    /// extensions field, and every octet after it, identical to the
    /// certificate as it arrived.
    #[cfg(feature = "std")]
    #[test]
    fn tbs_without_sct_list_copies_rather_than_re_encodes() {
        for (name, der) in sct_bearing_fixtures() {
            let out = tbs_without_sct_list(&der)
                .unwrap_or_else(|e| panic!("{name}: strip failed: {e:?}"));

            // Locate the same structures in the original.
            let cert = raw_der::read_tagged(&der, raw_der::TAG_SEQUENCE).expect("cert");
            let cert_body = cert.value(&der);
            let tbs = raw_der::read_tagged(cert_body, raw_der::TAG_SEQUENCE).expect("tbs");
            let tbs_body = tbs.value(cert_body);
            let (ext_off, wrapper) = raw_der::tlvs(tbs_body)
                .expect("tbs fields")
                .into_iter()
                .find(|(_, t)| t.tag == raw_der::TAG_EXTENSIONS)
                .expect("extensions field");

            let out_tbs = raw_der::read_tagged(&out, raw_der::TAG_SEQUENCE)
                .unwrap_or_else(|| panic!("{name}: output is not a SEQUENCE"));
            assert_eq!(
                out_tbs.total_len(),
                out.len(),
                "{name}: output has trailing bytes"
            );
            let out_body = out_tbs.value(&out);

            assert_eq!(
                &out_body[..ext_off],
                &tbs_body[..ext_off],
                "{name}: the octets before the extensions field changed — version, \
                 serial, signature algorithm, issuer, validity, subject, public key \
                 and any earlier extension must be copied verbatim"
            );
            let tail = &tbs_body[ext_off + wrapper.total_len()..];
            assert!(
                out_body.ends_with(tail),
                "{name}: the octets after the extensions field changed"
            );

            // The SCT-list extension's own octets are gone, and every
            // other extension's are still there untouched.
            let wrapper_body =
                &tbs_body[ext_off + wrapper.header_len..ext_off + wrapper.total_len()];
            let exts = raw_der::read_tagged(wrapper_body, raw_der::TAG_SEQUENCE).expect("exts");
            let exts_body = exts.value(wrapper_body);
            let mut saw_sct_list = 0;
            for (off, ext) in raw_der::tlvs(exts_body).expect("extensions") {
                let bytes = &exts_body[off..off + ext.total_len()];
                let body = &exts_body[off + ext.header_len..off + ext.total_len()];
                let oid = raw_der::read_tagged(body, raw_der::TAG_OID).expect("extnID");
                if oid.value(body) == OID_SCT_LIST_BYTES {
                    saw_sct_list += 1;
                    assert!(
                        !contains(out_body, bytes),
                        "{name}: the SCT-list extension survived the strip"
                    );
                } else {
                    assert!(
                        contains(out_body, bytes),
                        "{name}: an unrelated extension was not copied verbatim"
                    );
                }
            }
            assert_eq!(saw_sct_list, 1, "{name}: expected one SCT-list extension");
        }
    }

    #[cfg(feature = "std")]
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// A certificate the re-encoder does not reproduce must still be
    /// reconstructed exactly.
    ///
    /// This is the test the old implementation could not pass.
    /// `tests/fixtures/reencode/` holds two certificates that are
    /// well-formed DER, that a CA could emit, and that a log would
    /// sign — and that `x509-cert` re-encodes differently:
    ///
    /// - `leaf-generalizedtime-notbefore.der` puts a `GeneralizedTime`
    ///   before 2050 in `notBefore`, which x509-cert normalises.
    ///   `pkix_path::encode_tbs_certificate` was hand-written to patch
    ///   around this one case and does preserve it.
    /// - `leaf-unsorted-rdn.der` has a subject RDN whose `SET OF`
    ///   members are not in the order X.690 §11.6 requires. x509-cert
    ///   parses it and re-sorts on encode, and nothing patches around
    ///   that: measured against this fixture,
    ///   `encode_tbs_certificate` produced bytes that differ from the
    ///   original. So the old implementation reconstructed the wrong
    ///   signed input and a genuinely valid SCT came back as
    ///   [`Error::InvalidSignature`] — the exact failure this crate
    ///   now cannot produce, because it copies the bytes instead.
    ///
    /// The expected bytes are stripped independently in
    /// `gen_reencode_fixtures.py`, so a shared mistake between the
    /// generator and this crate would have to be made twice, in two
    /// languages.
    #[cfg(feature = "std")]
    #[test]
    fn a_cert_the_re_encoder_alters_is_still_reconstructed_exactly() {
        for stem in ["leaf-generalizedtime-notbefore", "leaf-unsorted-rdn"] {
            let der = std::fs::read(format!("tests/fixtures/reencode/{stem}.der"))
                .unwrap_or_else(|e| panic!("read {stem}.der: {e}"));
            let expected = std::fs::read(format!("tests/fixtures/reencode/{stem}-tbs-no-sct.bin"))
                .unwrap_or_else(|e| panic!("read {stem}-tbs-no-sct.bin: {e}"));

            let actual = tbs_without_sct_list(&der)
                .unwrap_or_else(|e| panic!("{stem}: strip failed: {e:?}"));
            assert_eq!(
                actual, expected,
                "{stem}: reconstructed TBS does not match the Python oracle; \
                 a byte that came from the certificate was not copied"
            );
        }
    }

    /// Mirror test for `issuer_key_hash_from_cert`: the SHA-256 of
    /// the issuer cert's SubjectPublicKeyInfo DER must match the
    /// oracle's committed `precert-issuer-key-hash.bin`.
    ///
    /// `std`-gated for the same reason as
    /// [`tbs_without_sct_list_matches_oracle_bytes`].
    #[cfg(feature = "std")]
    #[test]
    fn issuer_key_hash_matches_oracle_bytes() {
        let issuer_der = std::fs::read("tests/fixtures/sct-oracle/precert-issuer.der")
            .expect("read precert-issuer.der");
        let expected = std::fs::read("tests/fixtures/sct-oracle/precert-issuer-key-hash.bin")
            .expect("read precert-issuer-key-hash.bin");
        let actual = issuer_key_hash_from_cert(&issuer_der).expect("hash issuer SPKI");
        assert_eq!(actual.len(), expected.len(), "32-byte sha-256 mismatch");
        assert_eq!(&actual[..], expected.as_slice());
    }
}
