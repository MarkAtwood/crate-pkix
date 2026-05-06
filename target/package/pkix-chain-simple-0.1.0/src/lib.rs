#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! Strict, opinionated X.509 chain verifier for the common happy-path case.
//!
//! This crate accepts **only** the narrow subset of certificate configurations
//! found in the overwhelming majority of TLS and code-signing chains. Any
//! deviation — an unusual extension, a long chain, a non-whitelisted algorithm
//! — returns an error rather than attempting to handle it.
//!
//! # When to use this crate
//!
//! Use `pkix-chain-simple` when:
//! - You control (or fully trust) the CA hierarchy you validate against
//! - Chains are short: one leaf + at most [`MAX_INTERMEDIATES`] intermediates
//! - Certs use RSA-PKCS1v15-SHA-256 or ECDSA-P-256-SHA-256
//! - You want strict, auditable validation with no silent fallbacks
//!
//! Use [`pkix_chain`] (or [`pkix_path`] directly) when:
//! - You need NameConstraints, policy validation, or revocation checking
//! - You need a custom signature backend (FIPS, HSM, wolfCrypt)
//! - You need to accept a broader set of algorithms or extension profiles
//!
//! # Simplicity contract
//!
//! A chain passes the simplicity gate if and only if all of the following hold:
//!
//! **Chain shape**
//! - At least 1 certificate (the end-entity / leaf)
//! - At most `1 + `[`MAX_INTERMEDIATES`]` ` certificates (leaf + intermediates;
//!   the trust anchor is supplied separately and not counted)
//!
//! **Signature algorithms** — only [`ALLOWED_SIG_ALGS`]:
//! - `sha256WithRSAEncryption` (OID 1.2.840.113549.1.1.11)
//! - `ecdsa-with-SHA256` (OID 1.2.840.10045.4.3.2)
//!
//! **Extensions — end-entity cert** (`chain[0]`):
//! - `BasicConstraints` (cA MUST be FALSE or absent)
//! - `KeyUsage`
//! - `ExtendedKeyUsage`
//! - `SubjectAltName`
//! - `SubjectKeyIdentifier`
//! - `AuthorityKeyIdentifier`
//! - No other extensions permitted (critical or non-critical)
//!
//! **Extensions — intermediate certs** (`chain[1..]`):
//! - `BasicConstraints` (cA MUST be TRUE) — required
//! - `KeyUsage` (must include `keyCertSign`) — required
//! - `SubjectKeyIdentifier`
//! - `AuthorityKeyIdentifier`
//! - No other extensions permitted (critical or non-critical)
//!
//! # Limitations
//!
//! - No revocation checking (CRL / OCSP). Use `pkix-revocation` if required.
//! - No NameConstraints or certificate policy validation.
//! - No cross-certificate path building (RFC 4158).
//! - Signature backend is always RustCrypto; for a custom backend use `pkix_path` directly.

use der::asn1::ObjectIdentifier;
use pkix_path::{Error as PathError, TrustAnchor, ValidatedPath, ValidationPolicy};
use x509_cert::Certificate;

// ---------------------------------------------------------------------------
// Allowed signature algorithm OIDs
// ---------------------------------------------------------------------------

/// OID for `sha256WithRSAEncryption` (RSA-PKCS1v15 with SHA-256).
///
/// Source: RFC 3279 §2.2.1 / PKCS #1.
pub const OID_RSA_PKCS1V15_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

/// OID for `ecdsa-with-SHA256` (ECDSA over P-256 with SHA-256).
///
/// Source: RFC 5758 §3.2.
pub const OID_ECDSA_P256_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// The complete set of signature algorithms accepted by [`verify_simple`].
///
/// Any certificate whose `signatureAlgorithm` field carries an OID not in this
/// slice is rejected with [`Error::AlgorithmNotAllowed`].
pub const ALLOWED_SIG_ALGS: &[ObjectIdentifier] =
    &[OID_RSA_PKCS1V15_SHA256, OID_ECDSA_P256_SHA256];

// ---------------------------------------------------------------------------
// Allowed extension OIDs
// ---------------------------------------------------------------------------

/// OID for the `BasicConstraints` extension (RFC 5280 §4.2.1.9).
pub const OID_EXT_BASIC_CONSTRAINTS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.5.29.19");

/// OID for the `KeyUsage` extension (RFC 5280 §4.2.1.3).
pub const OID_EXT_KEY_USAGE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.5.29.15");

/// OID for the `ExtendedKeyUsage` extension (RFC 5280 §4.2.1.12).
pub const OID_EXT_EXTENDED_KEY_USAGE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.5.29.37");

/// OID for the `SubjectAltName` extension (RFC 5280 §4.2.1.6).
pub const OID_EXT_SUBJECT_ALT_NAME: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.5.29.17");

/// OID for the `SubjectKeyIdentifier` extension (RFC 5280 §4.2.1.2).
pub const OID_EXT_SUBJECT_KEY_ID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.5.29.14");

/// OID for the `AuthorityKeyIdentifier` extension (RFC 5280 §4.2.1.1).
pub const OID_EXT_AUTHORITY_KEY_ID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.5.29.35");

/// Extensions permitted on the end-entity (leaf) certificate.
///
/// Any extension OID not in this slice causes [`Error::UnexpectedExtension`].
pub const ALLOWED_LEAF_EXTENSIONS: &[ObjectIdentifier] = &[
    OID_EXT_BASIC_CONSTRAINTS,
    OID_EXT_KEY_USAGE,
    OID_EXT_EXTENDED_KEY_USAGE,
    OID_EXT_SUBJECT_ALT_NAME,
    OID_EXT_SUBJECT_KEY_ID,
    OID_EXT_AUTHORITY_KEY_ID,
];

/// Extensions permitted on intermediate CA certificates.
///
/// Any extension OID not in this slice causes [`Error::UnexpectedExtension`].
pub const ALLOWED_INTERMEDIATE_EXTENSIONS: &[ObjectIdentifier] = &[
    OID_EXT_BASIC_CONSTRAINTS,
    OID_EXT_KEY_USAGE,
    OID_EXT_SUBJECT_KEY_ID,
    OID_EXT_AUTHORITY_KEY_ID,
];

// ---------------------------------------------------------------------------
// Chain shape limit
// ---------------------------------------------------------------------------

/// Maximum number of intermediate CA certificates between the leaf and the
/// trust anchor. Chains with more intermediates are rejected with
/// [`Error::ChainTooLong`].
///
/// This covers every real-world PKI the author is aware of at the time of
/// writing. If you need deeper chains, use [`pkix_chain`] directly.
pub const MAX_INTERMEDIATES: usize = 2;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by [`verify_simple`].
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// `chain` slice is empty; there is no certificate to validate.
    EmptyChain,

    /// Chain has more certificates than `1 + `[`MAX_INTERMEDIATES`].
    ///
    /// `len` is the number of certificates supplied (excluding the trust anchor).
    /// Use [`pkix_chain`] for longer chains.
    ChainTooLong {
        /// Number of certificates in the chain that was rejected.
        len: usize,
    },

    /// No trust anchors were provided.
    NoTrustAnchors,

    /// The `signatureAlgorithm` field of a certificate uses an OID not in
    /// [`ALLOWED_SIG_ALGS`].
    AlgorithmNotAllowed {
        /// Zero-based index into `chain` of the certificate with the
        /// disallowed algorithm.
        index: usize,
    },

    /// A certificate carries a critical extension whose OID is not in the
    /// allowed set for its chain position.
    UnhandledCriticalExtension {
        /// Zero-based index into `chain` of the non-conforming certificate.
        index: usize,
    },

    /// A certificate carries a non-critical extension whose OID is not in the
    /// allowed set for its chain position.
    ///
    /// `verify_simple` applies a whitelist even to non-critical extensions,
    /// treating any unknown extension as a signal that this chain is not
    /// "simple". Use [`pkix_chain`] if you need to accept such certs.
    UnexpectedExtension {
        /// Zero-based index into `chain` of the non-conforming certificate.
        index: usize,
    },

    /// An intermediate certificate is missing `BasicConstraints` (cA=TRUE)
    /// or `KeyUsage` (keyCertSign), both of which are required by this crate's
    /// simplicity contract even when they would otherwise be optional.
    MissingRequiredExtension {
        /// Zero-based index into `chain` of the non-conforming intermediate.
        index: usize,
    },

    /// The end-entity certificate has `BasicConstraints` cA=TRUE, which means
    /// it is a CA certificate, not a leaf. This crate does not validate chains
    /// where the subject is itself a CA.
    LeafIsCA,

    /// Underlying RFC 5280 path validation error from [`pkix_path`].
    Path(PathError),
}

impl From<PathError> for Error {
    fn from(e: PathError) -> Self {
        Error::Path(e)
    }
}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Verify a certificate chain using strict, simple validation rules.
///
/// Applies the simplicity gate (see [crate-level docs](crate)) before
/// delegating to [`pkix_path::validate_path`] with the built-in RustCrypto
/// signature backends (RSA-PKCS1v15-SHA-256, ECDSA-P-256-SHA-256) and no
/// revocation checking.
///
/// # Arguments
///
/// - `chain`    — leaf-first; `chain[0]` is the end-entity certificate,
///   `chain[1..]` are intermediates in issuer order.
/// - `anchors`  — trusted root CA certificates. The chain must terminate at
///   one of these. The trust anchor's own signature is not checked.
/// - `now_unix` — current time as seconds since the Unix epoch
///   (1970-01-01T00:00:00Z). Used to check `notBefore`/`notAfter`.
///
/// # Returns
///
/// [`ValidatedPath`] on success, identifying which trust anchor terminated
/// the chain and the validated depth.
///
/// # Errors
///
/// - [`Error::EmptyChain`] / [`Error::ChainTooLong`] — chain shape violations
/// - [`Error::AlgorithmNotAllowed`] — non-whitelisted signature algorithm
/// - [`Error::UnhandledCriticalExtension`] / [`Error::UnexpectedExtension`] /
///   [`Error::MissingRequiredExtension`] — extension profile violations
/// - [`Error::LeafIsCA`] — end-entity cert has cA=TRUE
/// - [`Error::Path`] — underlying RFC 5280 validation failure
///
/// # Example
///
/// ```rust,no_run
/// use pkix_chain_simple::verify_simple;
/// use pkix_path::TrustAnchor;
/// use x509_cert::Certificate;
/// use der::Decode;
///
/// # let leaf_der: &[u8] = &[];
/// # let root_der: &[u8] = &[];
/// let leaf   = Certificate::from_der(leaf_der).unwrap();
/// let anchor = TrustAnchor::new(Certificate::from_der(root_der).unwrap());
///
/// verify_simple(&[leaf], &[anchor], 1_700_000_000)?;
/// # Ok::<(), pkix_chain_simple::Error>(())
/// ```
pub fn verify_simple(
    chain: &[Certificate],
    anchors: &[TrustAnchor],
    now_unix: u64,
) -> Result<ValidatedPath> {
    // --- Shape checks -------------------------------------------------------
    if chain.is_empty() {
        return Err(Error::EmptyChain);
    }
    if chain.len() > 1 + MAX_INTERMEDIATES {
        return Err(Error::ChainTooLong { len: chain.len() });
    }
    if anchors.is_empty() {
        return Err(Error::NoTrustAnchors);
    }

    // --- Simplicity gate ----------------------------------------------------
    // Walk every certificate before touching pkix-path. This ensures that any
    // rejection for non-standard structure is reported as a typed Error variant
    // rather than a generic PathError.
    for (i, cert) in chain.iter().enumerate() {
        let is_leaf = i == 0;
        check_algorithm(i, cert)?;
        check_extensions(i, cert, is_leaf)?;
    }

    // --- Delegate to pkix-path ----------------------------------------------
    let policy = ValidationPolicy {
        current_time_unix: now_unix,
        max_path_len: (1 + MAX_INTERMEDIATES) as u8,
        ..Default::default()
    };

    pkix_path::validate_path(chain, anchors, &policy, &RustCryptoVerifier).map_err(Error::Path)
}

// ---------------------------------------------------------------------------
// Gate helpers (stubs — implementation tracked in pkix-chain-simple v0.1)
// ---------------------------------------------------------------------------

/// Reject the certificate if its `signatureAlgorithm` OID is not in
/// [`ALLOWED_SIG_ALGS`].
///
/// Both the outer `signatureAlgorithm` field and the inner
/// `TBSCertificate.signature` field are checked; RFC 5280 §4.1.1.2 requires
/// them to be identical.
fn check_algorithm(_index: usize, _cert: &Certificate) -> Result<()> {
    todo!(
        "check cert.signature_algorithm.oid against ALLOWED_SIG_ALGS; \
         also verify outer == inner per RFC 5280 §4.1.1.2"
    )
}

/// Reject the certificate if any extension OID falls outside the allowed set
/// for its chain position, or if required extensions are absent.
///
/// - `is_leaf = true`  → whitelist is [`ALLOWED_LEAF_EXTENSIONS`]; also checks
///   `BasicConstraints` cA is FALSE (or absent).
/// - `is_leaf = false` → whitelist is [`ALLOWED_INTERMEDIATE_EXTENSIONS`]; also
///   checks `BasicConstraints` cA=TRUE and `KeyUsage` keyCertSign are present.
fn check_extensions(_index: usize, _cert: &Certificate, _is_leaf: bool) -> Result<()> {
    todo!(
        "walk cert TBSCertificate.extensions; for each extension OID check \
         against allowed set for is_leaf; enforce required extensions on \
         intermediates; check BasicConstraints cA value"
    )
}

// ---------------------------------------------------------------------------
// Internal RustCrypto verifier
// ---------------------------------------------------------------------------

/// Zero-sized RustCrypto-backed [`SignatureVerifier`] used internally.
///
/// Not exported — callers who need a different backend should use
/// [`pkix_path::validate_path`] or [`pkix_chain::verify_chain`] directly.
struct RustCryptoVerifier;

impl pkix_path::SignatureVerifier for RustCryptoVerifier {
    fn verify_signature(
        &self,
        _algorithm: spki::AlgorithmIdentifierRef<'_>,
        _issuer_spki: spki::SubjectPublicKeyInfoRef<'_>,
        _message: &[u8],
        _signature: &[u8],
    ) -> pkix_path::Result<()> {
        todo!(
            "dispatch to RustCrypto p256::ecdsa or rsa::pkcs1v15 based on \
             algorithm.oid; tracked in pkix-chain-simple v0.1 implementation issue"
        )
    }
}
