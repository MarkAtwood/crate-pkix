#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! Strict, opinionated X.509 chain verifier for the common happy-path case.
//!
//! This crate accepts **only** the narrow subset of certificate configurations
//! found in short, simple chains issued by a CA hierarchy you control or fully
//! trust. Any deviation — an unusual extension, a long chain, a non-whitelisted
//! algorithm — returns an error rather than attempting to handle it.
//!
//! # When to use this crate
//!
//! Use `pkix-chain-simple` when:
//! - You control (or fully trust) the CA hierarchy you validate against
//! - Chains are short: one leaf + at most [`MAX_INTERMEDIATES`] intermediates
//! - Certs use RSA-PKCS1v15-SHA-256 or ECDSA-P-256-SHA-256
//! - You want strict, auditable validation with no silent fallbacks
//!
//! Use `pkix_chain` (or [`pkix_path`] directly) when:
//! - You are validating certs from a public CA (CA/B Forum TLS, code-signing)
//!   that may carry extensions not in this crate's allowlist
//! - You need `NameConstraints`, policy validation, or revocation checking
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
//! - `CRLDistributionPoints` (informational; content not inspected)
//! - `AuthorityInfoAccess` (informational; content not inspected)
//! - No other extensions permitted (critical or non-critical)
//!
//! **Extensions — intermediate certs** (`chain[1..]`):
//! - `BasicConstraints` (cA MUST be TRUE) — required
//! - `KeyUsage` (must include `keyCertSign`) — required
//! - `SubjectKeyIdentifier`
//! - `AuthorityKeyIdentifier`
//! - `CRLDistributionPoints` (informational; content not inspected)
//! - `AuthorityInfoAccess` (informational; content not inspected)
//! - `CertificatePolicies`, `PolicyMappings`, `NameConstraints`, `PolicyConstraints`,
//!   `InhibitAnyPolicy`, `ExtendedKeyUsage`, `SubjectAltName`, `IssuerAltName`
//!   (content not inspected by this crate)
//! - No other extensions permitted (critical or non-critical)
//!
//! # Limitations
//!
//! - No revocation checking (CRL / OCSP). Use `pkix-revocation` if required.
//! - No `NameConstraints` or certificate policy validation.
//! - No cross-certificate path building (RFC 4158).
//! - Signature backend is always `RustCrypto`; for a custom backend use `pkix_path` directly.

use der::asn1::ObjectIdentifier;
use der::Decode;
use pkix_path::{
    DefaultVerifier, Error as PathError, TrustAnchor, ValidatedPath, ValidationPolicy,
};
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};
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
pub const ALLOWED_SIG_ALGS: &[ObjectIdentifier] = &[OID_RSA_PKCS1V15_SHA256, OID_ECDSA_P256_SHA256];

// ---------------------------------------------------------------------------
// Allowed extension OIDs
// ---------------------------------------------------------------------------

/// OID for the `BasicConstraints` extension (RFC 5280 §4.2.1.9).
pub const OID_EXT_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");

/// OID for the `KeyUsage` extension (RFC 5280 §4.2.1.3).
pub const OID_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");

/// OID for the `ExtendedKeyUsage` extension (RFC 5280 §4.2.1.12).
pub const OID_EXT_EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");

/// OID for the `SubjectAltName` extension (RFC 5280 §4.2.1.6).
pub const OID_EXT_SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");

/// OID for the `SubjectKeyIdentifier` extension (RFC 5280 §4.2.1.2).
pub const OID_EXT_SUBJECT_KEY_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");

/// OID for the `AuthorityKeyIdentifier` extension (RFC 5280 §4.2.1.1).
pub const OID_EXT_AUTHORITY_KEY_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");

/// OID for the `CRLDistributionPoints` extension (RFC 5280 §4.2.1.13).
pub const OID_EXT_CRL_DISTRIBUTION_POINTS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.5.29.31");

/// OID for the `AuthorityInfoAccess` extension (RFC 5280 §4.2.2.1).
pub const OID_EXT_AUTHORITY_INFO_ACCESS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1");

/// OID for the `CertificatePolicies` extension (RFC 5280 §4.2.1.4).
pub const OID_EXT_CERTIFICATE_POLICIES: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.5.29.32");

/// OID for the `PolicyMappings` extension (RFC 5280 §4.2.1.5).
pub const OID_EXT_POLICY_MAPPINGS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.33");

/// OID for the `NameConstraints` extension (RFC 5280 §4.2.1.10).
pub const OID_EXT_NAME_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.30");

/// OID for the `PolicyConstraints` extension (RFC 5280 §4.2.1.11).
pub const OID_EXT_POLICY_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.36");

/// OID for the `InhibitAnyPolicy` extension (RFC 5280 §4.2.1.14).
pub const OID_EXT_INHIBIT_ANY_POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.54");

/// OID for the `IssuerAltName` extension (RFC 5280 §4.2.1.7).
pub const OID_EXT_ISSUER_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.18");

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
    OID_EXT_CRL_DISTRIBUTION_POINTS,
    OID_EXT_AUTHORITY_INFO_ACCESS,
];

/// Extensions permitted on intermediate CA certificates.
///
/// Any extension OID not in this slice causes [`Error::UnexpectedExtension`]
/// (non-critical) or [`Error::UnhandledCriticalExtension`] (critical).
///
/// Permitted extensions:
/// - `BasicConstraints` (cA MUST be TRUE) — required
/// - `KeyUsage` (must include `keyCertSign`) — required
/// - `SubjectKeyIdentifier`
/// - `AuthorityKeyIdentifier`
/// - `CRLDistributionPoints` (informational; content not inspected)
/// - `AuthorityInfoAccess` (informational; content not inspected)
/// - `CertificatePolicies` (content not inspected by this crate)
/// - `PolicyMappings` (content not inspected by this crate)
/// - `NameConstraints` (content not inspected by this crate)
/// - `PolicyConstraints` (content not inspected by this crate)
/// - `InhibitAnyPolicy` (content not inspected by this crate)
/// - `ExtendedKeyUsage` (content not inspected by this crate)
/// - `SubjectAltName` (content not inspected by this crate)
/// - `IssuerAltName` (content not inspected by this crate)
pub const ALLOWED_INTERMEDIATE_EXTENSIONS: &[ObjectIdentifier] = &[
    OID_EXT_BASIC_CONSTRAINTS,
    OID_EXT_KEY_USAGE,
    OID_EXT_SUBJECT_KEY_ID,
    OID_EXT_AUTHORITY_KEY_ID,
    OID_EXT_CRL_DISTRIBUTION_POINTS,
    OID_EXT_AUTHORITY_INFO_ACCESS,
    OID_EXT_CERTIFICATE_POLICIES,
    OID_EXT_POLICY_MAPPINGS,
    OID_EXT_NAME_CONSTRAINTS,
    OID_EXT_POLICY_CONSTRAINTS,
    OID_EXT_INHIBIT_ANY_POLICY,
    OID_EXT_EXTENDED_KEY_USAGE,
    OID_EXT_SUBJECT_ALT_NAME,
    OID_EXT_ISSUER_ALT_NAME,
];

/// Extension OIDs that may appear as **critical** on the end-entity (leaf) certificate.
///
/// This is a strict subset of [`ALLOWED_LEAF_EXTENSIONS`]: every OID here is
/// one that `pkix-path` accepts when the extension is critical.
/// A leaf cert whose critical extension is in [`ALLOWED_LEAF_EXTENSIONS`] but
/// **not** in this slice is rejected with [`Error::UnhandledCriticalExtension`].
///
/// - `BasicConstraints`, `KeyUsage`, `SubjectAltName`, `ExtendedKeyUsage` are
///   accepted as critical by `pkix-path` (EKU content is not inspected; RFC 5280
///   §6.1 path validation does not require it).
/// - `SubjectKeyIdentifier`, `AuthorityKeyIdentifier` are not accepted as critical.
pub const CRITICAL_OK_LEAF_EXTENSIONS: &[ObjectIdentifier] = &[
    OID_EXT_BASIC_CONSTRAINTS,
    OID_EXT_KEY_USAGE,
    OID_EXT_SUBJECT_ALT_NAME,
    OID_EXT_EXTENDED_KEY_USAGE,
];

/// Extension OIDs that may appear as **critical** on intermediate CA certificates.
///
/// Strict subset of [`ALLOWED_INTERMEDIATE_EXTENSIONS`]; same rationale as
/// [`CRITICAL_OK_LEAF_EXTENSIONS`].
///
/// Several entries are required here because RFC 5280 mandates critical marking:
/// - `NameConstraints` — RFC 5280 §4.2.1.10: **MUST** be critical
/// - `PolicyConstraints` — RFC 5280 §4.2.1.11: SHOULD be critical
/// - `InhibitAnyPolicy` — RFC 5280 §4.2.1.14: **MUST** be critical
pub const CRITICAL_OK_INTERMEDIATE_EXTENSIONS: &[ObjectIdentifier] = &[
    OID_EXT_BASIC_CONSTRAINTS,
    OID_EXT_KEY_USAGE,
    OID_EXT_CERTIFICATE_POLICIES,
    OID_EXT_NAME_CONSTRAINTS,
    OID_EXT_POLICY_CONSTRAINTS,
    OID_EXT_INHIBIT_ANY_POLICY,
    OID_EXT_POLICY_MAPPINGS,
    OID_EXT_EXTENDED_KEY_USAGE,
    OID_EXT_SUBJECT_ALT_NAME,
];

// ---------------------------------------------------------------------------
// Chain shape limit
// ---------------------------------------------------------------------------

/// Maximum number of intermediate CA certificates between the leaf and the
/// trust anchor. Chains with more intermediates are rejected with
/// [`Error::ChainTooLong`].
///
/// This covers every real-world PKI the author is aware of at the time of
/// writing. If you need deeper chains, use `pkix_chain` directly.
///
/// **Note**: `chain[0]` is the end-entity (leaf) certificate. `chain[0]` is
/// checked against [`ALLOWED_LEAF_EXTENSIONS`] — if it has
/// `BasicConstraints cA=TRUE`, [`Error::LeafIsCA`] is returned regardless of
/// `MAX_INTERMEDIATES`. Pass a non-CA end-entity as `chain[0]`.
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
    /// Use `pkix_chain` for longer chains.
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
    /// "simple". Use `pkix_chain` if you need to accept such certs.
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
    ///
    /// **Edge case**: if you want to validate a 1-cert "chain" where `chain[0]`
    /// is a self-signed root CA that is also listed in `anchors`, this error
    /// will fire. Use [`pkix_path::validate_path`] directly for that case.
    LeafIsCA,

    /// Underlying RFC 5280 path validation error from [`pkix_path`].
    Path(PathError),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyChain => write!(f, "chain is empty"),
            Self::ChainTooLong { len } => {
                write!(
                    f,
                    "chain has {len} certificates; maximum is {}",
                    1 + MAX_INTERMEDIATES
                )
            }
            Self::NoTrustAnchors => write!(f, "no trust anchors provided"),
            Self::AlgorithmNotAllowed { index } => {
                write!(
                    f,
                    "certificate at index {index} uses a disallowed signature algorithm"
                )
            }
            Self::UnhandledCriticalExtension { index } => {
                write!(
                    f,
                    "certificate at index {index} has an unhandled critical extension"
                )
            }
            Self::UnexpectedExtension { index } => {
                write!(
                    f,
                    "certificate at index {index} has an unexpected extension"
                )
            }
            Self::MissingRequiredExtension { index } => {
                write!(
                    f,
                    "intermediate at index {index} is missing a required extension \
                     (BasicConstraints cA=TRUE or KeyUsage keyCertSign)"
                )
            }
            Self::LeafIsCA => write!(f, "end-entity certificate has BasicConstraints cA=TRUE"),
            Self::Path(e) => write!(f, "path validation: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Path(e) => Some(e),
            _ => None,
        }
    }
}

impl From<PathError> for Error {
    fn from(e: PathError) -> Self {
        Self::Path(e)
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
/// delegating to [`pkix_path::validate_path`] with the built-in `RustCrypto`
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
/// Checks are applied in this order; the first failure is returned:
///
/// 1. Shape: [`Error::EmptyChain`], [`Error::ChainTooLong`], [`Error::NoTrustAnchors`]
/// 2. Per-cert simplicity gate (leaf-first): [`Error::AlgorithmNotAllowed`],
///    [`Error::UnhandledCriticalExtension`] (unknown or unhandleable critical ext),
///    [`Error::UnexpectedExtension`] (unknown non-critical ext),
///    [`Error::MissingRequiredExtension`], [`Error::LeafIsCA`]
/// 3. Path validation: [`Error::Path`] — signature, validity, chain linkage
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
/// let anchor = TrustAnchor::from_cert(Certificate::from_der(root_der).unwrap());
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
    const _: () = assert!(
        MAX_INTERMEDIATES <= u8::MAX as usize,
        "MAX_INTERMEDIATES must fit in u8"
    );
    let mut policy = ValidationPolicy::new(now_unix);
    #[allow(clippy::cast_possible_truncation)] // assert above guarantees this fits
    let max_path_len = MAX_INTERMEDIATES as u8;
    policy.max_path_len = max_path_len;

    pkix_path::validate_path(chain, anchors, &policy, &DefaultVerifier).map_err(Error::Path)
}

// ---------------------------------------------------------------------------
// Gate helpers (stubs — implementation tracked in pkix-chain-simple v0.1)
// ---------------------------------------------------------------------------

/// Reject the certificate if its `signatureAlgorithm` OID is not in
/// [`ALLOWED_SIG_ALGS`].
///
/// The RFC 5280 §4.1.1.2 outer/inner OID consistency check is **not**
/// duplicated here; `validate_path` handles it via `check_oid_consistency`
/// and returns `Error::Path(MalformedCertificate { index })` for that case.
fn check_algorithm(index: usize, cert: &Certificate) -> Result<()> {
    let oid = cert.signature_algorithm.oid;
    if !ALLOWED_SIG_ALGS.contains(&oid) {
        return Err(Error::AlgorithmNotAllowed { index });
    }
    Ok(())
}

/// Reject the certificate if any extension OID falls outside the allowed set
/// for its chain position, or if required extensions are absent.
///
/// - `is_leaf = true`  → whitelist is [`ALLOWED_LEAF_EXTENSIONS`]; critical
///   extensions must be in [`CRITICAL_OK_LEAF_EXTENSIONS`]; also checks
///   `BasicConstraints` cA is FALSE (or absent).
/// - `is_leaf = false` → whitelist is [`ALLOWED_INTERMEDIATE_EXTENSIONS`];
///   critical extensions must be in [`CRITICAL_OK_INTERMEDIATE_EXTENSIONS`];
///   also checks `BasicConstraints` cA=TRUE and `KeyUsage` keyCertSign are present.
fn check_extensions(index: usize, cert: &Certificate, is_leaf: bool) -> Result<()> {
    let allowed = if is_leaf {
        ALLOWED_LEAF_EXTENSIONS
    } else {
        ALLOWED_INTERMEDIATE_EXTENSIONS
    };
    let critical_ok = if is_leaf {
        CRITICAL_OK_LEAF_EXTENSIONS
    } else {
        CRITICAL_OK_INTERMEDIATE_EXTENSIONS
    };

    let extensions = match &cert.tbs_certificate.extensions {
        Some(exts) => exts,
        None if is_leaf => return Ok(()),
        None => return Err(Error::MissingRequiredExtension { index }),
    };

    // Whitelist check: every extension OID must be in the allowed set.
    // Critical extensions must additionally be in the critical-OK set (those
    // that pkix-path handles when the extension is marked critical).
    //
    // Scan all extensions before reporting an error so that the most severe
    // violation wins: an unhandled critical extension takes priority over a
    // mere unexpected non-critical extension.
    let mut unexpected = false;
    let mut unhandled_critical = false;
    for ext in extensions {
        if !allowed.contains(&ext.extn_id) {
            if ext.critical {
                unhandled_critical = true;
            } else {
                unexpected = true;
            }
        } else if ext.critical && !critical_ok.contains(&ext.extn_id) {
            unhandled_critical = true;
        }
    }
    if unhandled_critical {
        return Err(Error::UnhandledCriticalExtension { index });
    }
    if unexpected {
        return Err(Error::UnexpectedExtension { index });
    }

    if is_leaf {
        // Check BasicConstraints if present: cA MUST be false.
        if let Some(ext) = extensions
            .iter()
            .find(|e| e.extn_id == OID_EXT_BASIC_CONSTRAINTS)
        {
            let bc = BasicConstraints::from_der(ext.extn_value.as_bytes())
                .map_err(|e| Error::Path(pkix_path::Error::from(e)))?;
            if bc.ca {
                return Err(Error::LeafIsCA);
            }
        }
    } else {
        // BasicConstraints required, cA must be true.
        let bc_ext = extensions
            .iter()
            .find(|e| e.extn_id == OID_EXT_BASIC_CONSTRAINTS)
            .ok_or(Error::MissingRequiredExtension { index })?;
        let bc = BasicConstraints::from_der(bc_ext.extn_value.as_bytes())
            .map_err(|e| Error::Path(pkix_path::Error::from(e)))?;
        if !bc.ca {
            return Err(Error::MissingRequiredExtension { index });
        }

        // KeyUsage required, keyCertSign must be set.
        let ku_ext = extensions
            .iter()
            .find(|e| e.extn_id == OID_EXT_KEY_USAGE)
            .ok_or(Error::MissingRequiredExtension { index })?;
        let ku = KeyUsage::from_der(ku_ext.extn_value.as_bytes())
            .map_err(|e| Error::Path(pkix_path::Error::from(e)))?;
        if !ku.key_cert_sign() {
            return Err(Error::MissingRequiredExtension { index });
        }
    }

    Ok(())
}
