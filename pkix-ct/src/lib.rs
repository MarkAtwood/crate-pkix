#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! Certificate Transparency SCT verification for `pkix-chain` (RFC 6962).
//!
//! Verifies Signed Certificate Timestamps (SCTs) embedded in X.509
//! certificates, OCSP responses, or TLS handshake extensions against a
//! set of trusted CT log public keys.
//!
//! # Spec references
//!
//! - RFC 6962 — Certificate Transparency
//! - RFC 9162 — Certificate Transparency Version 2.0
//! - CA/Browser Forum TLS Baseline Requirements §3.2.2.9 — SCT requirements
//!
//! # Limitations
//!
//! SCT binary-format parsing (RFC 6962 §3.2 / §3.3) is implemented; see
//! [`SignedCertificateTimestamp`] and [`SctList`]. Delivery-channel
//! adapters for the TLS handshake extension and OCSP responses are also
//! implemented; see [`sct_list_from_tls_extension`] and (behind the
//! `ocsp` feature) `sct_list_from_ocsp_response`. CT log list management
//! is implemented behind the `log-list` and `log-list-json` features;
//! see [`CtLog`], [`CtLogList`], and `CtLogList::from_google_log_list_json`.
//! SCT signature verification for both the `x509_entry` and
//! `precert_entry` log entry types is implemented; see
//! [`SctVerifier::verify_sct_for_cert`] (used when SCTs are delivered
//! via OCSP or the TLS handshake) and
//! [`SctVerifier::verify_sct_for_precert`] (used when SCTs are
//! embedded directly in the issued certificate via the SCT-list
//! extension). Merkle inclusion proof verification is not yet
//! implemented; see the project tracker (PKIX-baac.5) for status.

extern crate alloc;

mod delivery;
#[cfg(feature = "log-list")]
mod log_list;
mod sct;
#[cfg(feature = "log-list")]
mod verify;

#[cfg(feature = "ocsp")]
#[cfg_attr(docsrs, doc(cfg(feature = "ocsp")))]
pub use delivery::sct_list_from_ocsp_response;
pub use delivery::sct_list_from_tls_extension;
#[cfg(feature = "log-list")]
#[cfg_attr(docsrs, doc(cfg(feature = "log-list")))]
pub use log_list::{CtLog, CtLogList};
pub use sct::{SctList, SignedCertificateTimestamp};
#[cfg(feature = "log-list")]
#[cfg_attr(docsrs, doc(cfg(feature = "log-list")))]
pub use verify::SctVerifier;

/// Errors returned by SCT parsing and verification.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// The certificate contains no SCT extension.
    NoScts,
    /// An SCT signature was invalid.
    InvalidSignature,
    /// DER parsing of the SCT list extension failed.
    ParseError,
    /// The SCT version byte was not 0 (v1). RFC 6962 §3.2 defines only
    /// version 1; RFC 9162 introduces v2 but is not yet deployed.
    UnsupportedVersion(u8),
    /// A length prefix in the SCT or SCT list ran past the available input,
    /// or trailing bytes remained after the declared length was consumed.
    TruncatedOrTrailing,
    /// The SCT's `log_id` does not appear in the [`CtLogList`] used to
    /// construct the [`SctVerifier`].
    UnknownLog,
    /// The SCT carries `(hash_alg, sig_alg)` tags that
    /// [`SctVerifier`] does not know how to map to an X.509 signature
    /// algorithm. See the [`SctVerifier`] module documentation for the
    /// supported combinations.
    UnsupportedSignatureAlgorithm {
        /// RFC 5246 §7.4.1.4.1 `HashAlgorithm` tag carried by the SCT.
        hash_alg: u8,
        /// RFC 5246 §7.4.1.4.1 `SignatureAlgorithm` tag carried by the SCT.
        sig_alg: u8,
    },
    /// The [`CtLog::key_der`] bytes did not parse as a valid
    /// `SubjectPublicKeyInfo`. Indicates a corrupted log list.
    LogKeyMalformed,
    /// The SCT timestamp falls outside the log's
    /// `[usable_from_ms, retired_at_ms)` window.
    SctTimestampOutsideLogWindow,
    /// The supplied certificate DER exceeds the 2^24 - 1 octet limit of
    /// the RFC 6962 §3.2 `ASN.1Cert` (or `PreCert.tbs_certificate`)
    /// opaque-length-prefixed field.
    CertDerTooLong,
    /// The final leaf certificate passed to
    /// [`SctVerifier::verify_sct_for_precert`] does not contain an
    /// SCT-list extension (OID 1.3.6.1.4.1.11129.2.4.2). Verifying a
    /// `precert_entry` SCT against a cert that never carried the
    /// embedded list is nonsensical — the SCT must have come from a
    /// different delivery channel (OCSP / TLS handshake), for which
    /// callers should use [`SctVerifier::verify_sct_for_cert`].
    LeafMissingSctList,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoScts => f.write_str("certificate contains no SCTs"),
            Self::InvalidSignature => f.write_str("SCT signature invalid"),
            Self::ParseError => f.write_str("SCT list parse error"),
            Self::UnsupportedVersion(v) => {
                write!(
                    f,
                    "unsupported SCT version: {v} (only v1 / version=0 is supported)"
                )
            }
            Self::TruncatedOrTrailing => {
                f.write_str("SCT or SCT list bytes were truncated or had trailing data")
            }
            Self::UnknownLog => f.write_str("SCT log_id not present in the log list"),
            Self::UnsupportedSignatureAlgorithm { hash_alg, sig_alg } => {
                write!(
                    f,
                    "SCT signature algorithm not supported: hash_alg={hash_alg}, sig_alg={sig_alg}"
                )
            }
            Self::LogKeyMalformed => {
                f.write_str("CT log key_der is not a valid SubjectPublicKeyInfo")
            }
            Self::SctTimestampOutsideLogWindow => {
                f.write_str("SCT timestamp falls outside the log's usable window")
            }
            Self::CertDerTooLong => {
                f.write_str("certificate DER exceeds the 2^24 - 1 octet ASN.1Cert limit")
            }
            Self::LeafMissingSctList => {
                f.write_str("leaf certificate does not contain the SCT-list extension")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;
