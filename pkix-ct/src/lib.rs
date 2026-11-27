#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
// `CtLog`, `CtLogList`, `SctVerifier` and the MerkleTreeLeaf builders
// only exist behind `log-list`, and the crate docs link to them. With the
// feature off those items are gone, so the links cannot resolve and
// `cargo doc` on a default feature selection reports an error.
//
// Allowed only in that configuration, which loses no signal: a mistyped
// link is broken with the feature on too, and the quality gate's
// all-features doc build runs under RUSTDOCFLAGS=-D warnings. Demoting
// them to code spans instead would cost every docs.rs reader a working
// link — docs.rs builds all features — to spare a configuration nobody
// publishes documentation from. Same reasoning, and same shape, as the
// attribute at the top of `pkix-path`.
// Also `ocsp`, which gates `sct_list_from_ocsp_response`: a build with
// `log-list` on and `ocsp` off resolves the first group of links and not
// that one, so conditioning on `log-list` alone left it unresolved.
#![cfg_attr(
    any(not(feature = "log-list"), not(feature = "ocsp")),
    allow(rustdoc::broken_intra_doc_links)
)]

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
//! # What is implemented
//!
//! - SCT binary-format parsing, RFC 6962 §3.2 / §3.3:
//!   [`SignedCertificateTimestamp`], [`SctList`].
//! - Delivery-channel adapters: [`sct_list_from_tls_extension`] for the
//!   TLS handshake extension and, behind the `ocsp` feature,
//!   `sct_list_from_ocsp_response`.
//! - CT log list management, behind the `log-list` and `log-list-json`
//!   features: [`CtLog`], [`CtLogList`],
//!   `CtLogList::from_google_log_list_json`.
//! - SCT signature verification for both log entry types:
//!   [`SctVerifier::verify_sct_for_cert`] for `x509_entry` (SCTs delivered
//!   via OCSP or the TLS handshake) and
//!   [`SctVerifier::verify_sct_for_precert`] for `precert_entry` (SCTs
//!   embedded in the issued certificate via the SCT-list extension).
//! - Merkle inclusion proof verification (RFC 6962 §2.1.1) and Signed Tree
//!   Head signature verification (RFC 6962 §3.5):
//!   [`SctVerifier::verify_inclusion`] and [`SctVerifier::verify_sth`],
//!   with the `MerkleTreeLeaf` builders [`merkle_tree_leaf_for_cert`] and
//!   [`merkle_tree_leaf_for_precert`] plus [`merkle_leaf_hash`] completing
//!   the "parse SCT → build leaf → hash → verify inclusion" path.
//!
//! # Limitations
//!
//! - Only RFC 6962 v1 SCTs are accepted; a non-zero version byte is
//!   rejected with [`Error::UnsupportedVersion`]. RFC 9162 is cited above
//!   for context, not as implemented.
//! - Everything past parsing — signature, inclusion-proof and STH
//!   verification — needs the issuing log's public key, so it sits behind
//!   the `log-list` feature. A default build parses SCTs and no more.

extern crate alloc;

mod delivery;
#[cfg(feature = "log-list")]
mod log_list;
// Byte-preserving DER navigation for the RFC 6962 signed inputs. Only
// `verify` needs it, so it carries the same gate; without one it would
// be dead code in a default build.
#[cfg(feature = "log-list")]
mod raw_der;
mod sct;
#[cfg(feature = "log-list")]
mod verify;

#[cfg(feature = "ocsp")]
#[cfg_attr(docsrs, doc(cfg(feature = "ocsp")))]
pub use delivery::sct_list_from_ocsp_response;
pub use delivery::sct_list_from_tls_extension;
#[cfg(feature = "log-list")]
#[cfg_attr(docsrs, doc(cfg(feature = "log-list")))]
pub use log_list::{CtLog, CtLogList, UsableFrom};
pub use sct::{SctList, SignedCertificateTimestamp};
#[cfg(feature = "log-list")]
#[cfg_attr(docsrs, doc(cfg(feature = "log-list")))]
pub use verify::{
    merkle_leaf_hash, merkle_tree_leaf_for_cert, merkle_tree_leaf_for_precert,
    verify_inclusion_proof, EmbeddedSctReport, LogEntryType, MerkleAuditPath, RejectedSct,
    SctVerifier, SignedTreeHead, VerifiedSct,
};

/// Errors returned by SCT parsing and verification.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    /// The SCT's signature did not verify as asked, but does verify
    /// under the *other* RFC 6962 §3.1 log entry type.
    ///
    /// Reported instead of [`Error::InvalidSignature`] so that calling
    /// the wrong entry point is distinguishable from a forged or
    /// tampered SCT. RFC 6962 puts `entry_type` inside the
    /// `digitally-signed` structure rather than on the transmitted SCT,
    /// so the verifier has to be told which one to assume, and being
    /// told wrong used to look exactly like an attack.
    ///
    /// The SCT is still rejected. This names the likely cause; it does
    /// not accept the signature.
    EntryTypeMismatch,
    /// An SCT list held no SCTs.
    ///
    /// RFC 6962 §3.3 declares the list as
    /// `SerializedSCT sct_list<1..2^16-1>`, so zero entries is not a
    /// short list but a malformed one. Returned both by the parsers
    /// and by [`SctList::new`], which is the whole point of the latter
    /// existing.
    EmptySctList,
    /// The leaf certificate carries more than one SCT-list extension.
    ///
    /// RFC 5280 §4.2 forbids a certificate from repeating an
    /// extension. Reconstructing the `precert_entry` signed input
    /// means removing that extension, and with two of them there is no
    /// way to know which one the log was given — so this is refused
    /// rather than guessed, in agreement with
    /// `pkix-path::check_duplicate_extensions`, which rejects such a
    /// certificate during path validation.
    DuplicateSctListExtension,
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
    /// The SCT timestamp falls outside the log's usable window —
    /// before [`CtLog::usable_from`], at or after
    /// `CtLog::retired_at_ms`, or signed by a log that never became
    /// usable at all.
    SctTimestampOutsideLogWindow,
    /// The supplied certificate DER exceeds the 2^24 - 1 octet limit of
    /// the RFC 6962 §3.2 `ASN.1Cert` (or `PreCert.tbs_certificate()`)
    /// opaque-length-prefixed field.
    CertDerTooLong,
    /// The SCT's `extensions` field exceeds the 2^16 - 1 octet limit
    /// of the RFC 6962 §3.2 `CtExtensions` (`opaque<0..2^16-1>`) field.
    /// The wire parser cannot produce such an SCT; this is reachable
    /// only through [`SignedCertificateTimestamp::new`] or by setting
    /// the public `extensions` field directly.
    SctExtensionsTooLong,
    /// The OCSP response carried a `responseStatus` other than
    /// `successful(0)`, so it is a refusal rather than an answer about
    /// the certificate.
    ///
    /// The value is the RFC 6960 §4.2.1 `OCSPResponseStatus`:
    /// `malformedRequest(1)`, `internalError(2)`, `tryLater(3)`,
    /// `sigRequired(5)`, `unauthorized(6)`.
    ///
    /// Carried as a number rather than `x509_ocsp`'s enum so that this
    /// variant does not drag an optional dependency's type into the
    /// error type of every build.
    ///
    /// This used to be reported as `Ok(None)` — the same answer as a
    /// responder that replied normally and simply embedded no SCTs.
    /// "The responder refused" and "there are no SCTs here" call for
    /// different actions: the first is worth retrying or alerting on,
    /// the second is settled.
    OcspResponseNotSuccessful(u8),
    /// The final leaf certificate passed to
    /// [`SctVerifier::verify_sct_for_precert`] does not contain an
    /// SCT-list extension (OID 1.3.6.1.4.1.11129.2.4.2). Verifying a
    /// `precert_entry` SCT against a cert that never carried the
    /// embedded list is nonsensical — the SCT must have come from a
    /// different delivery channel (OCSP / TLS handshake), for which
    /// callers should use [`SctVerifier::verify_sct_for_cert`].
    LeafMissingSctList,
    /// Merkle inclusion proof verification failed: the reconstructed
    /// root hash does not match the supplied root, or the proof's
    /// `leaf_index` is outside `[0, tree_size)`, or the audit path's
    /// length is inconsistent with the tree size. Tampered proofs
    /// (flipped node, wrong index, wrong tree size) all surface as
    /// this variant.
    MerkleProofInvalid,
    /// Merkle inclusion proof has an invalid shape: `tree_size` is 0
    /// (the empty tree contains nothing), or the audit path is
    /// indefinitely long for the claimed tree size.
    MerkleProofMalformed,
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
            Self::EntryTypeMismatch => f.write_str(
                "SCT signature verifies under the other RFC 6962 log entry type \
                 (wrong verification entry point for how this SCT was delivered)",
            ),
            Self::EmptySctList => {
                f.write_str("SCT list contains no SCTs (RFC 6962 §3.3 requires at least one)")
            }
            Self::DuplicateSctListExtension => {
                f.write_str("leaf certificate carries more than one SCT-list extension")
            }
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
            Self::OcspResponseNotSuccessful(status) => {
                write!(f, "OCSP responder returned status {status}, not successful")
            }
            Self::SctExtensionsTooLong => {
                f.write_str("SCT extensions exceed the 2^16 - 1 octet CtExtensions limit")
            }
            Self::LeafMissingSctList => {
                f.write_str("leaf certificate does not contain the SCT-list extension")
            }
            Self::MerkleProofInvalid => f.write_str("Merkle inclusion proof failed verification"),
            Self::MerkleProofMalformed => f.write_str("Merkle inclusion proof has invalid shape"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

const _: fn() = || {
    fn _assert_send_sync<T: Send + Sync>() {}
    _assert_send_sync::<Error>();
};

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;
