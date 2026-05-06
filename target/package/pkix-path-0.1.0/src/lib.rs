#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! RFC 5280 X.509 certificate path validation — pure Rust, `no_std`.
//!
//! Implements certificate path building and validation per
//! [RFC 5280 §6](https://www.rfc-editor.org/rfc/rfc5280#section-6).
//!
//! # Architecture
//!
//! Cryptographic signature verification is pluggable via [`SignatureVerifier`].
//! The default feature set (`rustcrypto`) wires in RustCrypto backends for
//! RSA-PKCS1v15, P-256 ECDSA, and (with optional features) RSA-PSS, P-384,
//! Ed25519. For FIPS-validated crypto, implement [`SignatureVerifier`] against
//! `wolfcrypt-rustcrypto` and disable the `rustcrypto` feature.
//!
//! Revocation checking is handled by `pkix-revocation`. This crate never
//! touches the network — use [`pkix_chain::verify_chain`] for the combined API.
//!
//! # Limitations
//!
//! v0.1 does **not** implement:
//! - NameConstraints (RFC 5280 §4.2.1.10)
//! - PolicyConstraints / certificate policy validation (§4.2.1.9, §6.1.5)
//! - Revocation (use `pkix-revocation`)
//! - Cross-certificate path building (RFC 4158)
//!
//! These are tracked for v0.2+.

use spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};
use x509_cert::Certificate;

/// Errors returned by path validation.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Certificate signature verification failed at the given chain index.
    SignatureInvalid {
        /// Zero-based index into the `chain` slice of the failing certificate.
        index: usize,
    },
    /// Certificate validity period check failed (expired or not yet valid).
    ValidityPeriod {
        /// Zero-based index into the `chain` slice of the failing certificate.
        index: usize,
    },
    /// Issuer/subject name linkage is broken at the given chain index.
    ChainBroken {
        /// Zero-based index into the `chain` slice where the break was found.
        index: usize,
    },
    /// No path from the subject certificate to any trust anchor was found.
    NoTrustedPath,
    /// Path length exceeds [`ValidationPolicy::max_path_len`].
    PathTooLong,
    /// An intermediate certificate is missing BasicConstraints cA=TRUE.
    NotCA {
        /// Zero-based index into the `chain` slice of the failing certificate.
        index: usize,
    },
    /// An intermediate certificate is missing KeyUsage keyCertSign.
    KeyUsageMissing {
        /// Zero-based index into the `chain` slice of the failing certificate.
        index: usize,
    },
    /// A critical extension is present that this implementation does not handle.
    UnhandledCriticalExtension {
        /// Zero-based index into the `chain` slice of the failing certificate.
        index: usize,
    },
    /// ASN.1 / DER decoding error.
    Der(der::Error),
}

impl From<der::Error> for Error {
    fn from(e: der::Error) -> Self {
        Error::Der(e)
    }
}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Pluggable signature verification backend.
///
/// Implement this trait to provide algorithm-specific signature verification.
/// The trait is OID-dispatched: the `algorithm` argument carries the OID and
/// any parameters from the certificate's `signatureAlgorithm` field.
///
/// # Implementing a custom backend
///
/// ```rust,ignore
/// struct MyVerifier;
///
/// impl pkix_path::SignatureVerifier for MyVerifier {
///     fn verify_signature(
///         &self,
///         algorithm: spki::AlgorithmIdentifierRef<'_>,
///         issuer_spki: spki::SubjectPublicKeyInfoRef<'_>,
///         message: &[u8],
///         signature: &[u8],
///     ) -> pkix_path::Result<()> {
///         match algorithm.oid {
///             MY_RSA_OID => { /* ... */ }
///             MY_ECDSA_OID => { /* ... */ }
///             _ => Err(pkix_path::Error::SignatureInvalid { index: 0 }),
///         }
///     }
/// }
/// ```
pub trait SignatureVerifier {
    /// Verify `signature` over `message`.
    ///
    /// - `algorithm`    — from the subject cert's `signatureAlgorithm` field
    /// - `issuer_spki`  — SPKI extracted from the issuer or trust anchor cert
    /// - `message`      — DER-encoded TBSCertificate (the bytes that were signed)
    /// - `signature`    — raw signature bytes (BitString content, not the wrapper)
    fn verify_signature(
        &self,
        algorithm: AlgorithmIdentifierRef<'_>,
        issuer_spki: SubjectPublicKeyInfoRef<'_>,
        message: &[u8],
        signature: &[u8],
    ) -> Result<()>;
}

/// A trust anchor used to terminate path validation.
///
/// A trust anchor is typically either a self-signed root CA certificate
/// or a raw (name, SPKI) pair extracted from a platform trust store.
/// The trust anchor itself is **not** signature-verified — it is trusted
/// by definition.
pub struct TrustAnchor {
    /// The trusted certificate. Its subject name and SPKI are used to
    /// anchor the chain; its own signature is not checked.
    pub certificate: Certificate,
}

impl TrustAnchor {
    /// Wrap a certificate as a trust anchor.
    pub fn new(certificate: Certificate) -> Self {
        Self { certificate }
    }
}

/// Policy parameters controlling path validation.
///
/// # Limitations
///
/// v0.1 does not enforce NameConstraints, CertificatePolicies, or
/// PolicyMappings. Fields for these will be added in v0.2.
pub struct ValidationPolicy {
    /// Maximum chain depth, not counting the trust anchor. Default: 10.
    ///
    /// A chain of [leaf] is depth 0. [leaf, intermediate, root] is depth 1
    /// (one intermediate). Validation fails if depth exceeds this value.
    pub max_path_len: u8,

    /// Current time as seconds since the Unix epoch (1970-01-01T00:00:00Z).
    ///
    /// Used to check `notBefore` ≤ `now` ≤ `notAfter` on every certificate.
    /// **Must be set by the caller** — there is no platform clock in `no_std`.
    pub current_time_unix: u64,

    /// Enforce the KeyUsage extension when present. Default: `true`.
    ///
    /// When `true`, an intermediate certificate missing `keyCertSign` in its
    /// KeyUsage will be rejected even if BasicConstraints cA=TRUE.
    pub enforce_key_usage: bool,
}

impl Default for ValidationPolicy {
    fn default() -> Self {
        Self {
            max_path_len: 10,
            current_time_unix: 0, // caller must set to avoid silent clock skew
            enforce_key_usage: true,
        }
    }
}

/// The result of a successful certificate path validation.
#[non_exhaustive]
pub struct ValidatedPath {
    /// Index into the `anchors` slice of the trust anchor that terminated the path.
    pub anchor_index: usize,
    /// Depth of the validated chain (number of intermediates, excluding trust anchor).
    pub depth: usize,
}

/// Validate a certificate chain from subject to a trust anchor.
///
/// `chain` must be ordered leaf-first:
/// - `chain[0]` is the subject (end-entity) certificate
/// - `chain[1..]` are intermediates in issuer order
/// - The last element of `chain` must be issued by one of `anchors`
///
/// Validation follows RFC 5280 §6.1. Each certificate's signature is verified
/// using `verifier`, with the signing key taken from the next certificate in
/// the chain (or the matching trust anchor for the last cert).
///
/// # Errors
///
/// Returns `Err` on the first RFC 5280 §6.1 check failure. The error variant
/// includes the chain index of the failing certificate where applicable.
///
/// # Limitations
///
/// See crate-level documentation for v0.1 scope limits.
pub fn validate_path<V>(
    chain: &[Certificate],
    anchors: &[TrustAnchor],
    policy: &ValidationPolicy,
    verifier: &V,
) -> Result<ValidatedPath>
where
    V: SignatureVerifier,
{
    let _ = (chain, anchors, policy, verifier);
    todo!("RFC 5280 §6.1 state machine — tracked in pkix-path v0.1 issue")
}
