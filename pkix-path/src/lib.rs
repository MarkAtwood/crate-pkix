#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
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
//! RSA-PKCS1v15-SHA-256 (`rsa` feature) and ECDSA-P-256-SHA-256 (`p256` feature).
//! P-384 and Ed25519 are planned for v0.2.
//! For FIPS-validated crypto, implement [`SignatureVerifier`] against
//! `wolfcrypt-rustcrypto` and disable the `rustcrypto` feature.
//!
//! Revocation checking is handled by `pkix-revocation`. This crate never
//! touches the network — use `pkix_chain::verify_chain` for the combined API.
//!
//! # Limitations
//!
//! v0.1 does **not** implement:
//! - Revocation (use `pkix-revocation`)
//! - Cross-certificate path building (RFC 4158)
//! - RFC 4518 full Unicode NFKC DN normalization (BMPString/UniversalString)
//!
//! These are tracked for v0.2+.

// For no_std builds, pull in the alloc crate explicitly so `alloc::` paths
// and the `vec!` macro resolve. `#[macro_use]` re-exports alloc macros
// (vec!, format!, etc.) into the crate root, making them available everywhere
// without qualifying them as `alloc::vec!(...)`.
#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

// Unified Vec import: alloc::vec::Vec in no_std, std::vec::Vec under std.
// Both map to the same concrete type; this alias lets the rest of the file
// write `Vec<_>` without cfg-gating every use site.
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

use der::Tagged;
use signature::Error as SignatureError;
use spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};
use x509_cert::Certificate;

/// Re-exported for use with [`TrustAnchor::name_constraints`].
pub use x509_cert::ext::pkix::constraints::name::NameConstraints;

/// Errors returned by path validation.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Certificate signature verification failed at the given chain index.
    SignatureInvalid {
        /// Zero-based index into the `chain` slice of the failing certificate.
        index: usize,
    },
    /// A structural encoding error was found in a certificate.
    ///
    /// Currently returned when the outer `signatureAlgorithm` OID differs from
    /// the inner `TBSCertificate.signature` OID (RFC 5280 §4.1.1.2).
    /// Parameters are not compared; see `check_oid_consistency` for rationale.
    MalformedCertificate {
        /// Zero-based index into the `chain` slice of the malformed certificate.
        ///
        /// The underlying `der::Error` is intentionally not stored here to keep
        /// this variant `no_std`-compatible and to preserve the stable API shape.
        /// Callers that need the root-cause parse error should validate the
        /// DER certificate independently before calling [`validate_path`].
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
    /// An intermediate certificate is missing `BasicConstraints` `cA=TRUE`.
    NotCA {
        /// Zero-based index into the `chain` slice of the failing certificate.
        index: usize,
    },
    /// An intermediate certificate has a `KeyUsage` extension with `keyCertSign` not set.
    ///
    /// This error is only returned when a `KeyUsage` extension is **present** and the
    /// `keyCertSign` bit is explicitly absent or zero (RFC 5280 §6.1.4(n): "If a KeyUsage
    /// extension is present, verify that the keyCertSign bit is set.").
    ///
    /// Certificates with **no** `KeyUsage` extension are not rejected by this check;
    /// RFC 5280 does not require the extension to be present on CA certificates.
    KeyUsageMissing {
        /// Zero-based index into the `chain` slice of the failing certificate.
        index: usize,
    },
    /// A critical extension is present that this implementation does not handle.
    UnhandledCriticalExtension {
        /// Zero-based index into the `chain` slice of the failing certificate.
        index: usize,
    },
    /// Certificate name constraints violated (RFC 5280 §4.2.1.10); `index` is the 0-based chain position.
    NameConstraintViolation {
        /// Zero-based index into the `chain` slice of the failing certificate.
        index: usize,
    },
    /// Certificate policy validation failed (RFC 5280 §6.1.5(g)).
    ///
    /// Returned when `explicit_policy` reaches zero and the valid policy tree
    /// is empty, meaning no acceptable certificate policy exists for the chain.
    PolicyViolation {
        /// Zero-based index of the certificate where the violation was detected.
        index: usize,
    },
    /// ASN.1 / DER encoding or decoding error.
    ///
    /// Most commonly returned when the internal 8 KiB stack buffer used to
    /// re-encode `TBSCertificate` for signature verification is too small.
    /// This is an **implementation limit**, not a certificate defect — the
    /// certificate may be perfectly valid. Certificates with `TBSCertificate`
    /// exceeding 8 KiB (large government / enterprise / HSM attestation certs) will
    /// trigger this error. This is tracked for v0.2 (heap-backed encoding).
    ///
    /// Callers that want a stable match target should check for `Error::Der(_)`
    /// without inspecting the inner value; the specific `der::Error` variants
    /// are not part of the stable API contract.
    Der(der::Error),
    /// A certificate's validity period (notAfter − notBefore) exceeds
    /// [`ValidationPolicy::max_validity_secs`].
    ///
    /// This check fires for every certificate in the chain, not just the leaf.
    ValidityPeriodExceedsMax {
        /// Zero-based index into the `chain` slice of the failing certificate.
        index: usize,
    },
    /// A certificate's signature algorithm OID is not in
    /// [`ValidationPolicy::allowed_signature_algs`].
    ///
    /// The check fires before signature verification so the error is diagnostic
    /// rather than a confusing `SignatureInvalid`.
    AlgorithmNotAllowed {
        /// Zero-based index into the `chain` slice of the failing certificate.
        index: usize,
    },
    /// An RSA public key's modulus is smaller than
    /// [`ValidationPolicy::min_rsa_key_bits`] bits.
    ///
    /// Non-RSA keys (EC, Ed25519, …) are not affected by this check.
    KeyTooSmall {
        /// Zero-based index into the `chain` slice of the failing certificate.
        index: usize,
    },
    /// The leaf certificate (chain index 0) has no `SubjectAltName` extension,
    /// or the extension is present but empty.
    ///
    /// Only checked when [`ValidationPolicy::require_subject_alt_name`] is `true`.
    /// Intermediate CA certificates are not subject to this check.
    MissingSan,
    /// The leaf certificate (chain index 0) does not assert all OIDs required
    /// by [`ValidationPolicy::required_leaf_eku`].
    ///
    /// `anyExtendedKeyUsage` (2.5.29.37.0) does not satisfy a specific OID
    /// requirement — each required OID must be listed explicitly.
    MissingEku,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SignatureInvalid { index } => {
                write!(f, "signature invalid at chain index {index}")
            }
            Self::ValidityPeriod { index } => {
                write!(f, "validity period check failed at chain index {index}")
            }
            Self::MalformedCertificate { index } => {
                write!(f, "malformed certificate at chain index {index}")
            }
            Self::ChainBroken { index } => {
                write!(f, "issuer/subject linkage broken at chain index {index}")
            }
            Self::NoTrustedPath => write!(f, "no path to a trusted anchor"),
            Self::PathTooLong => write!(f, "path length exceeds maximum"),
            Self::NotCA { index } => write!(f, "certificate at index {index} is not a CA"),
            Self::KeyUsageMissing { index } => {
                write!(f, "keyCertSign missing at chain index {index}")
            }
            Self::UnhandledCriticalExtension { index } => {
                write!(f, "unhandled critical extension at chain index {index}")
            }
            Self::NameConstraintViolation { index } => {
                write!(f, "name constraints violated at certificate index {index}")
            }
            Self::PolicyViolation { index } => {
                write!(f, "certificate policy violation at chain index {index}")
            }
            Self::Der(e) => write!(f, "DER error: {e}"),
            Self::ValidityPeriodExceedsMax { index } => {
                write!(f, "validity period exceeds maximum at chain index {index}")
            }
            Self::AlgorithmNotAllowed { index } => {
                write!(f, "signature algorithm not allowed at chain index {index}")
            }
            Self::KeyTooSmall { index } => {
                write!(f, "RSA key too small at chain index {index}")
            }
            Self::MissingSan => write!(f, "leaf certificate is missing SubjectAltName"),
            Self::MissingEku => {
                write!(
                    f,
                    "leaf certificate is missing required ExtendedKeyUsage OID(s)"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Der(e) => Some(e),
            Self::SignatureInvalid { .. }
            | Self::MalformedCertificate { .. }
            | Self::ValidityPeriod { .. }
            | Self::ChainBroken { .. }
            | Self::NoTrustedPath
            | Self::PathTooLong
            | Self::NotCA { .. }
            | Self::KeyUsageMissing { .. }
            | Self::UnhandledCriticalExtension { .. }
            | Self::NameConstraintViolation { .. }
            | Self::PolicyViolation { .. }
            | Self::ValidityPeriodExceedsMax { .. }
            | Self::AlgorithmNotAllowed { .. }
            | Self::KeyTooSmall { .. }
            | Self::MissingSan
            | Self::MissingEku => None,
        }
    }
}

impl From<der::Error> for Error {
    fn from(e: der::Error) -> Self {
        Self::Der(e)
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
/// This trait is object-safe and can be used as `dyn SignatureVerifier`.
/// All method arguments are either `&self` or borrows, so no `Sized` bound
/// is implied.
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
///     ) -> core::result::Result<(), signature::Error> {
///         match algorithm.oid {
///             MY_RSA_OID => { /* ... */ }
///             MY_ECDSA_OID => { /* ... */ }
///             _ => Err(signature::Error::new()),
///         }
///     }
/// }
/// ```
pub trait SignatureVerifier {
    /// Verify `signature` over `message`.
    ///
    /// - `algorithm`    — from the subject cert's `signatureAlgorithm` field
    /// - `issuer_spki`  — SPKI extracted from the issuer or trust anchor cert
    /// - `message`      — DER-encoded `TBSCertificate` (the bytes that were signed)
    /// - `signature`    — raw signature bytes (`BitString` content, not the wrapper)
    ///
    /// Returns `Ok(())` on success or `Err(signature::Error)` on failure.
    /// The caller ([`validate_path`]) maps the error to [`Error::SignatureInvalid`]
    /// with the correct chain index — the verifier does not need to know it.
    fn verify_signature(
        &self,
        algorithm: AlgorithmIdentifierRef<'_>,
        issuer_spki: SubjectPublicKeyInfoRef<'_>,
        message: &[u8],
        signature: &[u8],
    ) -> core::result::Result<(), SignatureError>;
}

/// A trust anchor used to terminate path validation.
///
/// A trust anchor is typically either a self-signed root CA certificate
/// or a raw (name, SPKI) pair extracted from a platform trust store.
/// The trust anchor itself is **not** signature-verified — it is trusted
/// by definition (RFC 5280 §6.1.1(c)).
///
/// **Validity period**: RFC 5280 §6.1.1(c) explicitly excludes the trust
/// anchor's notBefore/notAfter from path validation. An expired root CA
/// certificate used as a trust anchor will still anchor valid paths — this
/// is intentional behavior, not a bug. Callers are responsible for ensuring
/// their trust store contains the anchors they intend to trust.
///
/// **`PartialEq` is byte-level, not semantic**: The derived `PartialEq`
/// compares fields verbatim. Two anchors representing the same CA may compare
/// unequal if their DER encodings differ — for example, one `AlgorithmIdentifier`
/// with explicit `NULL` parameters and another with absent parameters are both
/// valid for RSA (RFC 3279 §2.3.1) but will not be equal under `==`. Do not use
/// `==` to deduplicate a trust store; use [`names_match`] and compare
/// `algorithm.oid` plus `subject_public_key` bytes directly. Path validation
/// already handles this internally, so it is not affected by this encoding difference.
///
/// # Stability
///
/// `TrustAnchor` is `#[non_exhaustive]`: new fields may be added in minor
/// versions. Construct via [`TrustAnchor::new`], [`TrustAnchor::from_cert`],
/// or `TrustAnchor::from`/`try_from`. Do not use struct literal syntax.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct TrustAnchor {
    /// The subject distinguished name of the trust anchor.
    pub subject: x509_cert::name::Name,
    /// The subject public key info of the trust anchor.
    ///
    /// Must be a valid SPKI for the chosen signature algorithm. An empty or
    /// malformed SPKI will cause signature verification to fail with
    /// `Error::NoTrustedPath` (no anchor matched), not a panic.
    pub subject_public_key_info: spki::SubjectPublicKeyInfoOwned,
    /// NameConstraints from the trust anchor certificate, if present.
    ///
    /// When set, `chain_walk` seeds the initial `permitted_subtrees` and
    /// `excluded_subtrees` state from this value before walking the chain.
    /// Populated automatically by `from_cert`; `None` for programmatically
    /// constructed anchors unless explicitly set.
    pub name_constraints: Option<x509_cert::ext::pkix::constraints::name::NameConstraints>,
}

impl TrustAnchor {
    /// Create a trust anchor from raw subject name and SPKI.
    #[must_use]
    pub fn new(
        subject: x509_cert::name::Name,
        subject_public_key_info: spki::SubjectPublicKeyInfoOwned,
    ) -> Self {
        Self {
            subject,
            subject_public_key_info,
            name_constraints: None,
        }
    }

    /// Extract subject name and SPKI from a certificate to create a trust anchor.
    ///
    /// This is the typical constructor when your trust store contains full
    /// self-signed root CA certificates.
    ///
    /// Prefer [`TrustAnchor::from`] (i.e. `TrustAnchor::from(&cert)`) when you
    /// need to keep `cert` alive after building the anchor.
    ///
    /// # NameConstraints and malformed extensions
    ///
    /// If the anchor certificate contains a malformed or unparseable
    /// `NameConstraints` extension, `from_cert` silently sets
    /// `name_constraints = None` and continues. The resulting anchor
    /// will not enforce NC constraints from that extension.
    ///
    /// For strict RFC 5280 §4.2 compliance — where a critical extension
    /// that cannot be parsed MUST cause rejection — use
    /// [`TrustAnchor::try_from`] instead. That path propagates the
    /// `der::Error` to the caller.
    #[must_use]
    pub fn from_cert(cert: Certificate) -> Self {
        let name_constraints = find_cert_ext(&cert, OID_NAME_CONSTRAINTS);
        Self {
            subject: cert.tbs_certificate.subject,
            subject_public_key_info: cert.tbs_certificate.subject_public_key_info,
            name_constraints,
        }
    }
}

impl From<&Certificate> for TrustAnchor {
    fn from(cert: &Certificate) -> Self {
        Self {
            subject: cert.tbs_certificate.subject.clone(),
            subject_public_key_info: cert.tbs_certificate.subject_public_key_info.clone(),
            name_constraints: find_cert_ext(cert, OID_NAME_CONSTRAINTS),
        }
    }
}

/// Fail-closed construction from an owned certificate.
///
/// Returns `Err(der::Error)` if the certificate contains a `NameConstraints`
/// extension with malformed DER. Use this when building a trust store that
/// must reject certificates with unparseable critical extensions per
/// RFC 5280 §4.2.
///
/// # Why only `TryFrom<Certificate>` and not `TryFrom<&Certificate>`
///
/// `TryFrom<&Certificate>` would conflict with the blanket impl
/// `impl<T, U: Into<T>> TryFrom<U>` provided by Rust core, because
/// `From<&Certificate>` is already implemented (and `From` implies `Into`).
/// Use `TrustAnchor::try_from(cert.clone())` if you need to keep `cert`.
impl TryFrom<Certificate> for TrustAnchor {
    type Error = der::Error;

    fn try_from(cert: Certificate) -> core::result::Result<Self, Self::Error> {
        let name_constraints = try_find_cert_ext(&cert, OID_NAME_CONSTRAINTS)?;
        Ok(TrustAnchor {
            subject: cert.tbs_certificate.subject,
            subject_public_key_info: cert.tbs_certificate.subject_public_key_info,
            name_constraints,
        })
    }
}

/// Policy parameters controlling path validation.
///
/// # Stability
///
/// `ValidationPolicy` is `#[non_exhaustive]`.
/// Construct via [`ValidationPolicy::new`] or [`Default`] + field assignment.
/// Do not use struct literal syntax.
///
/// # Performance note
///
/// Policy objects are intended to be constructed once (e.g., at server startup)
/// and reused for the lifetime of the application. Repeated construction is
/// unnecessary.
///
/// Policy enforcement (CertificatePolicies, PolicyMappings, PolicyConstraints,
/// InhibitAnyPolicy) is implemented per RFC 5280 §6.1. Use the
/// `initial_explicit_policy`, `initial_any_policy_inhibit`,
/// `initial_policy_mapping_inhibit`, and `initial_policy_set` fields to
/// configure the initial policy state.
///
/// # Limitations
///
/// Path-building (RFC 4158 — cross-signed certificates, multiple candidate
/// issuers) is **out of scope for v0.1**. The caller must supply the complete,
/// ordered chain.
///
/// Revocation checking (CRL / OCSP) is out of scope for `pkix-path`; see
/// `pkix-revocation` for that functionality.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationPolicy {
    /// Maximum chain depth, not counting the trust anchor. Default: 10.
    ///
    /// A chain of `[leaf]` is depth 0. `[leaf, intermediate, root]` is depth 1
    /// (one intermediate). Validation fails if depth exceeds this value.
    pub max_path_len: u8,

    /// Current time as seconds since the Unix epoch (1970-01-01T00:00:00Z).
    ///
    /// Used to check `notBefore` ≤ `now` ≤ `notAfter` on every certificate.
    /// **Must be set by the caller** — there is no platform clock in `no_std`.
    ///
    /// **Warning — the default is 0 (1970-01-01):** Any certificate issued
    /// after 1970 has `notBefore > 0` and will fail the validity check with
    /// [`Error::ValidityPeriod`]. If you see unexpected `ValidityPeriod`
    /// errors, check that `current_time_unix` is set to the current time.
    ///
    /// **Warning**: passing `u64::MAX` causes all `notAfter` checks to pass.
    /// This effectively disables expiry checking — only use it in contexts
    /// where you explicitly want permissive (clock-free) validation.
    pub current_time_unix: u64,

    /// Enforce the KeyUsage extension when present. Default: `true`.
    ///
    /// When `true`, an intermediate certificate whose `KeyUsage` extension is
    /// **present** but does not include `keyCertSign` will be rejected with
    /// [`Error::KeyUsageMissing`], per RFC 5280 §6.1.4(n).
    ///
    /// Certificates with **no** `KeyUsage` extension are not affected; RFC 5280
    /// only mandates the check when the extension is present.
    pub enforce_key_usage: bool,

    /// Initial explicit-policy indicator (RFC 5280 §6.1.1).
    ///
    /// When `true`, path validation requires that at least one valid policy exists
    /// from the initial policy set. When `false` (the default), any valid path is
    /// accepted even if no certificate policy is asserted.
    pub initial_explicit_policy: bool,

    /// Initial any-policy inhibit indicator (RFC 5280 §6.1.1).
    ///
    /// When `true`, the `anyPolicy` OID is not considered a match for any other
    /// policy at the start of the path. When `false` (the default), `anyPolicy`
    /// is accepted as a wildcard unless later inhibited by a CA certificate.
    pub initial_any_policy_inhibit: bool,

    /// Initial policy-mapping inhibit indicator (RFC 5280 §6.1.1).
    ///
    /// When `true`, policy mappings are not permitted in any certificate in the
    /// chain. When `false` (the default), policy mappings are allowed.
    pub initial_policy_mapping_inhibit: bool,

    /// Initial user-requested policy set (RFC 5280 §6.1.1).
    ///
    /// The set of certificate policies acceptable to the relying party. An empty
    /// vec is treated as `{anyPolicy}` — all policies are acceptable. Set this
    /// to restrict which policies are recognized in the output.
    ///
    /// Note: this is `pub` but clones the OID set, so prefer constructing once
    /// and reusing the `ValidationPolicy`.
    pub initial_policy_set: Vec<der::asn1::ObjectIdentifier>,

    /// If `Some(n)`, reject any certificate whose (notAfter − notBefore) exceeds
    /// `n` seconds. `None` means unconstrained (the default).
    ///
    /// Applied to every certificate in the chain, not just the leaf.
    /// Violations produce [`Error::ValidityPeriodExceedsMax`].
    pub max_validity_secs: Option<u64>,

    /// If `Some(list)`, reject any certificate whose signature algorithm OID is
    /// not in `list`. `None` means any algorithm is accepted (the default).
    ///
    /// Applied to every certificate in the chain. The check fires **before**
    /// signature verification so the error is diagnostic rather than a confusing
    /// [`Error::SignatureInvalid`].
    /// Violations produce [`Error::AlgorithmNotAllowed`].
    pub allowed_signature_algs: Option<Vec<der::asn1::ObjectIdentifier>>,

    /// If `Some(bits)`, reject any certificate carrying an RSA public key whose
    /// modulus is fewer than `bits` bits. Non-RSA keys are not affected.
    /// `None` means unconstrained (the default).
    ///
    /// Applied to every certificate in the chain.
    /// Violations produce [`Error::KeyTooSmall`].
    pub min_rsa_key_bits: Option<u32>,

    /// If `true`, the leaf certificate (chain index 0) must have a non-empty
    /// SubjectAltName extension. `false` means no SAN requirement (the default).
    ///
    /// Intermediate CA certificates are not checked by this field.
    /// Violations produce [`Error::MissingSan`].
    pub require_subject_alt_name: bool,

    /// If `Some(oids)`, the leaf certificate must explicitly assert every OID in
    /// `oids` via its ExtendedKeyUsage extension. `None` means no EKU requirement
    /// (the default).
    ///
    /// `anyExtendedKeyUsage` (2.5.29.37.0) does **not** satisfy a specific OID
    /// check — each required OID must be listed in the cert's EKU extension.
    /// Violations produce [`Error::MissingEku`].
    pub required_leaf_eku: Option<Vec<der::asn1::ObjectIdentifier>>,
}

impl ValidationPolicy {
    /// Construct a policy with the given time and sensible defaults.
    ///
    /// Equivalent to `ValidationPolicy { current_time_unix: now_unix, ..Default::default() }`.
    /// This is the preferred constructor: it forces the caller to supply a timestamp,
    /// preventing the silent validity failures caused by `Default`'s `current_time_unix = 0`.
    #[must_use]
    pub fn new(now_unix: u64) -> Self {
        Self {
            current_time_unix: now_unix,
            ..Default::default()
        }
    }
}

impl Default for ValidationPolicy {
    fn default() -> Self {
        Self {
            max_path_len: 10,
            current_time_unix: 0, // caller must set to avoid silent clock skew
            enforce_key_usage: true,
            initial_explicit_policy: false,
            initial_any_policy_inhibit: false,
            initial_policy_mapping_inhibit: false,
            initial_policy_set: Vec::new(),
            // New profile-enforcement fields: all disabled by default so that
            // existing callers get unconstrained behavior (backward compatible).
            max_validity_secs: None,
            allowed_signature_algs: None,
            min_rsa_key_bits: None,
            require_subject_alt_name: false,
            required_leaf_eku: None,
        }
    }
}

/// The result of a successful certificate path validation.
///
/// Fields are `pub` for direct read access. `#[non_exhaustive]` prevents external
/// code from constructing `ValidatedPath` directly and from pattern-matching
/// exhaustively, preserving the ability to add fields in future minor versions
/// without a breaking change.
///
/// # Copy stability
///
/// `ValidatedPath` derives `Copy` and is committed to remain `Copy` in all v0.1.x
/// releases. Any future field additions that are non-`Copy` will be added in a new
/// minor version (v0.2+) with an explicit removal of the `Copy` derive, constituting
/// a breaking change per semantic versioning. Callers may depend on `Copy` within
/// the v0.1 series.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ValidatedPath {
    /// Index into the `anchors` slice of the trust anchor that terminated the path.
    pub anchor_index: usize,
    /// Number of certificates in the validated chain minus one (`chain.len() - 1`).
    ///
    /// For a single self-signed certificate, `depth == 0`. For a leaf + one
    /// intermediate, `depth == 1`. This equals `chain.len().saturating_sub(1)`.
    ///
    /// Note: this counts all certificates except the trust anchor — including
    /// self-issued intermediates that RFC 5280 §4.2.1.9 excludes from the
    /// `pathLenConstraint` count. For chains with self-issued intermediates the
    /// `depth` field may be larger than the RFC 5280 path length.
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
///
/// **8 KiB `TBSCertificate` limit**: signature verification re-encodes each
/// `TBSCertificate` into a fixed 8 KiB stack buffer. Certificates whose
/// `TBSCertificate` DER encoding exceeds 8 KiB return [`Error::Der`].
/// This is an implementation limit, not a certificate defect. Large
/// government, enterprise, or HSM attestation certificates may trigger this.
/// A heap-backed encoding path is planned for v0.2.
///
/// Duplicate certificates in `chain` (same cert appearing at two indices) are
/// not detected. They will fail signature verification or name linkage with a
/// `SignatureInvalid` or `ChainBroken` error rather than a dedicated diagnostic.
#[must_use = "path validation result must be checked"]
pub fn validate_path<V>(
    chain: &[Certificate],
    anchors: &[TrustAnchor],
    policy: &ValidationPolicy,
    verifier: &V,
) -> Result<ValidatedPath>
where
    V: SignatureVerifier,
{
    // (1) Input guards: reject empty chain or anchors, check OID consistency.
    check_inputs(chain, anchors)?;
    check_oid_consistency(chain)?;

    // (2) Path-length check (anchor-independent).
    // RFC 5280 §4.2.1.9: pathLen counts non-self-issued intermediates only.
    let num_non_si_intermediates = chain[1..]
        .iter()
        .filter(|c| !is_self_issued_cert(c))
        .count();
    if num_non_si_intermediates > policy.max_path_len as usize {
        return Err(Error::PathTooLong);
    }

    // (3) Try each name-matching anchor. Iterating all candidates handles key
    //     rollover: multiple anchors may share a DN but have different keys
    //     (e.g., during a root CA rotation). The first anchor that passes the
    //     full chain walk is used; the last error is returned if none succeed.
    //
    //     Complexity: O(A × N) where A = number of anchors, N = chain length.
    //     For the common case of O(1) matching anchors this is effectively O(N).
    let last_cert = chain.last().ok_or(Error::NoTrustedPath)?;
    let is_self_issued = names_match(
        &last_cert.tbs_certificate.issuer,
        &last_cert.tbs_certificate.subject,
    );
    let mut last_err = Error::NoTrustedPath;
    for (anchor_index, anchor) in anchors.iter().enumerate() {
        if !names_match(&anchor.subject, &last_cert.tbs_certificate.issuer) {
            continue;
        }
        // For self-issued certs the cert and anchor are the same entity; their
        // keys must match (RFC 5280 §3.2 name-collision guard).
        if is_self_issued
            && !spki_key_matches(
                &anchor.subject_public_key_info,
                &last_cert.tbs_certificate.subject_public_key_info,
            )
        {
            continue;
        }
        match chain_walk(chain, anchor, policy, verifier) {
            Ok(()) => {
                return Ok(ValidatedPath {
                    anchor_index,
                    depth: chain.len().saturating_sub(1),
                });
            }
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

// ---------------------------------------------------------------------------
// validate_path helpers — input guards and OID consistency (PKIX-6vu)
// ---------------------------------------------------------------------------

/// Compare two SPKIs for the purpose of the self-issued anchor guard.
///
/// Compares algorithm OID and key bytes only — not the parameters field.
/// This is intentional: for RSA, explicit NULL parameters and absent
/// parameters are both valid encodings of the same algorithm (RFC 3279
/// §2.3.1); comparing the full `AlgorithmIdentifier` would wrongly reject
/// a valid anchor whose SPKI parameter encoding differs from the cert's.
/// For ECDSA, the parameters carry the curve OID, but two keys on different
/// curves also differ in their raw key bytes, so OID + key comparison is
/// still sufficient to distinguish them.
fn spki_key_matches(
    a: &spki::SubjectPublicKeyInfoOwned,
    b: &spki::SubjectPublicKeyInfoOwned,
) -> bool {
    a.algorithm.oid == b.algorithm.oid && a.subject_public_key == b.subject_public_key
}

fn check_inputs(chain: &[Certificate], anchors: &[TrustAnchor]) -> Result<()> {
    if chain.is_empty() || anchors.is_empty() {
        return Err(Error::NoTrustedPath);
    }
    Ok(())
}

/// RFC 5280 §4.1.1.2: outer signatureAlgorithm OID must equal inner TBSCertificate.signature OID.
///
/// Only OIDs are compared, not parameters.  RFC 5280 says the two
/// AlgorithmIdentifiers MUST be identical, but many production CAs
/// generate certs where one field has explicit NULL parameters and the other
/// omits them — a mismatch that OpenSSL and other validators accept in
/// practice.  OID-only comparison preserves the security intent (the same
/// algorithm must be named in both places) without rejecting otherwise-valid
/// certs from common PKI deployments.
fn check_oid_consistency(chain: &[Certificate]) -> Result<()> {
    for (index, cert) in chain.iter().enumerate() {
        if cert.signature_algorithm.oid != cert.tbs_certificate.signature.oid {
            return Err(Error::MalformedCertificate { index });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Critical extension guard (PKIX-ad6)
// ---------------------------------------------------------------------------

const OID_KEY_USAGE: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.15");

const OID_BASIC_CONSTRAINTS: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.19");

const OID_SUBJECT_ALT_NAME: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.17");

const OID_EXTENDED_KEY_USAGE: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.37");

const OID_NAME_CONSTRAINTS: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.30");

const OID_CERTIFICATE_POLICIES: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.32");

const OID_POLICY_MAPPINGS: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.33");

const OID_POLICY_CONSTRAINTS: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.36");

const OID_INHIBIT_ANY_POLICY: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.54");

/// OID for the `anyPolicy` wildcard (2.5.29.32.0 — a child of id-ce-certificatePolicies).
const OID_ANY_POLICY: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.32.0");

/// OID for the emailAddress attribute in Distinguished Names (PKCS #9 §5.2.1).
/// Used when enforcing RFC 5280 §4.2.1.10 rfc822Name constraints against DN attributes.
const OID_EMAIL_ADDRESS: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.1");

/// OIDs of extensions that this implementation handles; all others, if critical, cause rejection.
///
/// `OID_SUBJECT_ALT_NAME` is listed here so that certs with critical SAN extensions
/// (e.g. TLS server certs) do not fail with `UnhandledCriticalExtension`. However,
/// the SAN *value* is not inspected by path validation — name matching still uses the
/// Subject DN. **v0.1 limitation**: a cert with an empty Subject and critical SAN
/// will pass this check but fail name linkage since `names_match` compares against
/// the empty Subject. This is tracked for v0.2 (RFC 5280 §4.2.1.6).
///
/// `OID_EXTENDED_KEY_USAGE` is listed here so that certs with critical EKU
/// (common in CA/B Forum TLS and code-signing certificates) do not fail with
/// `UnhandledCriticalExtension`. RFC 5280 §6.1 path validation does not require
/// inspecting EKU values; the extension is accepted and its content is not verified.
const HANDLED_CRITICAL_OIDS: &[der::asn1::ObjectIdentifier] = &[
    OID_KEY_USAGE,
    OID_BASIC_CONSTRAINTS,
    OID_SUBJECT_ALT_NAME,
    OID_EXTENDED_KEY_USAGE,
    OID_NAME_CONSTRAINTS,
    OID_CERTIFICATE_POLICIES,
    OID_POLICY_MAPPINGS,
    OID_POLICY_CONSTRAINTS,
    OID_INHIBIT_ANY_POLICY,
];

/// RFC 5280 §6.1.3(a)(3): reject any critical extension not in the handled set.
fn check_critical_extensions(cert: &Certificate, index: usize) -> Result<()> {
    if let Some(exts) = cert.tbs_certificate.extensions.as_ref() {
        for ext in exts {
            if ext.critical && !HANDLED_CRITICAL_OIDS.contains(&ext.extn_id) {
                return Err(Error::UnhandledCriticalExtension { index });
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Policy tree (RFC 5280 §6.1) — PKIX-mi3.2
// ---------------------------------------------------------------------------

/// A node in the certificate policy tree (RFC 5280 §6.1.2(a)).
///
/// Stored as a flat `Vec<PolicyNode>`.  Depth 0 is the synthetic anyPolicy
/// root (initialized before any cert is processed).  Depth `d` corresponds
/// to the d-th certificate from the trust-anchor end (depth 1 = CA adjacent
/// to trust anchor, depth n = leaf).
///
/// # Limitations (v0.1)
///
/// Policy qualifiers (`qualifier_set` per RFC 5280 §6.1.2(a)) are not stored
/// or enforced. They are discarded on ingestion. Application-specific qualifier
/// processing is deferred to v0.2.
#[derive(Clone, Debug)]
struct PolicyNode {
    /// Certificate depth at which this node was added (0 = root sentinel).
    depth: usize,
    /// The policy OID this node represents.
    valid_policy: der::asn1::ObjectIdentifier,
    /// Policies in the NEXT certificate that are consistent with this node.
    /// Initialized to `{valid_policy}`; updated by PolicyMappings.
    expected_policy_set: Vec<der::asn1::ObjectIdentifier>,
}

/// Initialise the policy tree with the anyPolicy root node (RFC 5280 §6.1.2(a)).
fn init_policy_tree() -> Vec<PolicyNode> {
    vec![PolicyNode {
        depth: 0,
        valid_policy: OID_ANY_POLICY,
        expected_policy_set: vec![OID_ANY_POLICY],
    }]
}

/// Prune nodes at depth < `cert_depth` that have no children at depth+1.
///
/// After processing certificate at depth `d`, any ancestor node with no
/// surviving child must be deleted (RFC 5280 §6.1.3(d)(3)): "If there is a
/// node in the valid_policy_tree of depth i-1 or less without any child
/// nodes, delete that node.  Repeat this step until there are no nodes of
/// depth i-1 or less without children."
///
/// Starts by pruning depth `cert_depth - 1` (checking against children at
/// `cert_depth`), then walks upward toward depth 1.  The depth-0 root is
/// left in place (it is only removed when `policy_tree` is set to `None`).
fn prune_policy_tree(tree: &mut Vec<PolicyNode>, cert_depth: usize) {
    // Walk upward from cert_depth-1 down to depth 1 (inclusive), pruning nodes
    // that have no surviving child at depth d+1.  Depth 0 (the anyPolicy root
    // sentinel) is never pruned here — the caller clears policy_tree entirely
    // when it becomes effectively NULL (no nodes at depth ≥ 1).
    //
    // RFC 5280 §6.1.3(d)(3): "If there is a node in the valid_policy_tree of
    // depth i-1 or less without any child nodes, delete that node. Repeat this
    // step until there are no nodes of depth i-1 or less without children."
    //
    // Iteration: d starts at cert_depth, decrements to 1.  At each step we
    // prune depth d-1 against children at depth d, then continue upward.
    // We stop at d==1 because depth 0 is the root sentinel and is excluded.
    let mut d = cert_depth;
    loop {
        if d == 0 {
            break; // depth-0 root sentinel — never prune it
        }
        let prune_depth = d - 1; // depth to prune (children are at d)
        if prune_depth == 0 {
            break; // depth-0 root sentinel — never prune it
        }
        let child_policies: Vec<der::asn1::ObjectIdentifier> = tree
            .iter()
            .filter(|n| n.depth == d)
            .map(|n| n.valid_policy)
            .collect();
        // Remove nodes at prune_depth that have no surviving child at depth d.
        // A node has a child if some child's valid_policy appears in its
        // expected_policy_set (policy mappings may have changed those).
        // anyPolicy nodes are not exempt — they get pruned the same way.
        tree.retain(|n| {
            if n.depth != prune_depth {
                return true; // leave nodes at other depths untouched
            }
            child_policies
                .iter()
                .any(|cp| n.expected_policy_set.contains(cp))
        });
        d -= 1;
        // Continue upward even if prune_depth became empty — the level above
        // may now also be childless and needs pruning.
    }
}

// ---------------------------------------------------------------------------
// KeyUsage extraction (PKIX-8ae)
// ---------------------------------------------------------------------------

/// Returns whether the `keyCertSign` bit is set in the KeyUsage extension.
///
/// - `None`         — KeyUsage extension absent (no constraint)
/// - `Some(true)`   — keyCertSign is set
/// - `Some(false)`  — KeyUsage present, keyCertSign NOT set
fn has_key_cert_sign(cert: &Certificate) -> Option<bool> {
    use der::Decode;
    use x509_cert::ext::pkix::KeyUsage;

    cert.tbs_certificate
        .extensions
        .as_ref()?
        .iter()
        .find(|ext| ext.extn_id == OID_KEY_USAGE)
        .and_then(|ext| KeyUsage::from_der(ext.extn_value.as_bytes()).ok())
        .map(|ku| ku.key_cert_sign())
}

// ---------------------------------------------------------------------------
// Extension extraction helpers
// ---------------------------------------------------------------------------

/// Find and decode an X.509 extension from `cert` by OID.
///
/// **Fail-open**: returns `None` if the extension is absent *or* if its DER
/// value cannot be decoded. Decoding errors are silently discarded.
///
/// Use this for extensions where a parse failure is tolerable (e.g., optional
/// informational extensions). For security-critical extensions where a parse
/// failure must be propagated, use [`try_find_cert_ext`] instead.
fn find_cert_ext<T: der::DecodeOwned>(
    cert: &Certificate,
    oid: der::asn1::ObjectIdentifier,
) -> Option<T> {
    cert.tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find(|e| e.extn_id == oid)
        .and_then(|e| T::from_der(e.extn_value.as_bytes()).ok())
}

/// Look up and decode an X.509 extension from `cert` by OID.
///
/// **Fail-closed**: propagates DER decoding errors to the caller rather than
/// discarding them. This is appropriate for security-critical extensions where
/// a malformed value must not be silently ignored.
///
/// Returns:
/// - `Ok(None)` — extension absent.
/// - `Ok(Some(T))` — extension present and decoded successfully.
/// - `Err(der::Error)` — extension present but DER decoding failed.
///
/// For non-critical extensions where a parse failure should be treated as
/// absent, use [`find_cert_ext`] (fail-open) instead.
fn try_find_cert_ext<T: der::DecodeOwned>(
    cert: &Certificate,
    oid: der::asn1::ObjectIdentifier,
) -> der::Result<Option<T>> {
    match cert
        .tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find(|e| e.extn_id == oid)
    {
        None => Ok(None),
        Some(e) => T::from_der(e.extn_value.as_bytes()).map(Some),
    }
}

// NOTE: uses fail-open (find_cert_ext): a malformed BasicConstraints extension
// is treated as absent, not as an error. This is intentional — a malformed but
// non-critical BC extension should not block validation; chain_walk separately
// enforces cA=TRUE which will return NotCA if BC is absent or malformed. For
// the NC extension, fail-closed is required (see cert_name_constraints) because
// a silently-ignored NC constraint is a security bypass.
fn cert_basic_constraints(cert: &Certificate) -> Option<x509_cert::ext::pkix::BasicConstraints> {
    find_cert_ext(cert, OID_BASIC_CONSTRAINTS)
}

fn cert_subject_alt_names(cert: &Certificate) -> Option<x509_cert::ext::pkix::SubjectAltName> {
    find_cert_ext(cert, OID_SUBJECT_ALT_NAME)
}

/// Decode the NameConstraints extension from `cert`.
///
/// Returns `Err(MalformedCertificate)` if the extension is present but:
/// - its DER cannot be decoded (vjc.7: fail-closed on security-critical extension), or
/// - any GeneralSubtree has a non-zero `minimum` or a present `maximum` field
///   (vjc.8: RFC 5280 §4.2.1.10 MUST require minimum=0, maximum=absent).
///
/// Returns `Ok(None)` if the extension is absent.
fn cert_name_constraints(
    cert: &Certificate,
    index: usize,
) -> crate::Result<Option<NameConstraints>> {
    let nc = try_find_cert_ext::<NameConstraints>(cert, OID_NAME_CONSTRAINTS)
        .map_err(|_| Error::MalformedCertificate { index })?;

    if let Some(ref nc) = nc {
        // RFC 5280 §4.2.1.10: "the minimum and maximum fields are not used with
        // any name forms, thus minimum MUST be zero, maximum MUST be absent."
        // Reject certs that encode non-conformant subtrees rather than silently
        // applying potentially unexpected constraint semantics.
        let subtrees_iter = nc
            .permitted_subtrees
            .iter()
            .flatten()
            .chain(nc.excluded_subtrees.iter().flatten());
        for st in subtrees_iter {
            if st.minimum != 0 || st.maximum.is_some() {
                return Err(Error::MalformedCertificate { index });
            }
        }
    }

    Ok(nc)
}

// ---------------------------------------------------------------------------
// Validity period checker (PKIX-047)
// ---------------------------------------------------------------------------

/// Convert an `x509_cert::time::Time` to seconds since the Unix epoch.
fn time_to_unix_secs(t: &x509_cert::time::Time) -> u64 {
    t.to_unix_duration().as_secs()
}

/// RFC 5280 §6.1.3(a)(2): check notBefore ≤ now ≤ notAfter.
fn check_validity(cert: &Certificate, now_unix: u64, index: usize) -> Result<()> {
    let not_before = time_to_unix_secs(&cert.tbs_certificate.validity.not_before);
    let not_after = time_to_unix_secs(&cert.tbs_certificate.validity.not_after);
    if now_unix >= not_before && now_unix <= not_after {
        Ok(())
    } else {
        Err(Error::ValidityPeriod { index })
    }
}

// ---------------------------------------------------------------------------
// Name comparison — RFC 4518 string prep (PKIX-drv)
// ---------------------------------------------------------------------------

/// Compare two distinguished names per RFC 4518 string prep rules.
///
/// For v0.1: implements case-fold and whitespace normalization for ASCII
/// characters. Full Unicode NFKD normalization is deferred to v0.2.
///
/// Returns `true` if the names are equivalent.
///
/// # Ordering
///
/// RFC 5280 §4.1.2.4 defines `Name` as `SEQUENCE OF RDN`, so RDNs are
/// compared positionally (index 0 with index 0, etc.). Within each RDN —
/// which is a `SET OF AttributeTypeAndValue` — comparison is order-independent:
/// each AVA in one RDN is matched against any AVA in the other.
///
/// # Limitations
///
/// TeletexString and BMPString attribute values are not normalized — matching
/// falls back to raw DER byte comparison. Certificates from legacy PKIs using
/// these string types may fail name matching even when the names are
/// semantically equivalent. Full support is deferred to v0.2.
#[must_use]
pub fn names_match(a: &x509_cert::name::Name, b: &x509_cert::name::Name) -> bool {
    let a_rdns = a.0.as_slice();
    let b_rdns = b.0.as_slice();

    if a_rdns.len() != b_rdns.len() {
        return false;
    }

    for (a_rdn, b_rdn) in a_rdns.iter().zip(b_rdns.iter()) {
        let a_avas = a_rdn.0.as_slice();
        let b_avas = b_rdn.0.as_slice();
        if a_avas.len() != b_avas.len() {
            return false;
        }
        // Bijective AVA matching: every AVA in a_rdn must match some AVA in b_rdn,
        // AND every AVA in b_rdn must match some AVA in a_rdn (both directions).
        //
        // The bidirectional check is equivalent to set equality for well-formed RDNs
        // (RFC 5280 §5.1.2.4 SHOULD NOT contain duplicate OIDs), and also correctly
        // handles the malformed-cert case where an RDN has duplicate OIDs:
        //   a={CN=Alice, CN=Alice}, b={CN=Bob, CN=Alice} → both len=2, forward pass
        //   finds CN=Alice for each a_ava, but the reverse pass finds no match for
        //   CN=Bob → returns false (correct).
        // The reverse pass is O(n²) on AVA count; n is 1–5 in practice.
        for a_ava in a_avas.iter() {
            let found = b_avas.iter().any(|b_ava| {
                b_ava.oid == a_ava.oid && ava_values_match(&a_ava.value, &b_ava.value)
            });
            if !found {
                return false;
            }
        }
        for b_ava in b_avas.iter() {
            let found = a_avas.iter().any(|a_ava| {
                a_ava.oid == b_ava.oid && ava_values_match(&a_ava.value, &b_ava.value)
            });
            if !found {
                return false;
            }
        }
    }
    true
}

/// RFC 5280 §3.3: a certificate is self-issued if subject == issuer and neither is empty.
fn is_self_issued_cert(cert: &Certificate) -> bool {
    !cert.tbs_certificate.subject.is_empty()
        && names_match(&cert.tbs_certificate.subject, &cert.tbs_certificate.issuer)
}

/// Compare two AttributeTypeAndValue values after RFC 4518 normalization.
fn ava_values_match(a: &der::Any, b: &der::Any) -> bool {
    let a_str = any_to_str_bytes(a);
    let b_str = any_to_str_bytes(b);

    match (a_str, b_str) {
        (Some(a_bytes), Some(b_bytes)) => normalized_eq(a_bytes, b_bytes),
        // Both values are non-string types (e.g. OID, INTEGER) or unhandled string
        // types: compare tag AND content bytes (raw DER). Tag comparison ensures
        // TeletexString and BMPString with coincidentally identical bytes are not
        // considered equal.
        (None, None) => a.tag() == b.tag() && a.value() == b.value(),
        // One value is a string type and the other is not. Return false (fail-closed).
        // A legitimate certificate chain will never encode the same attribute OID as a
        // string type in one cert and a non-string type in another, so this mismatch
        // indicates a malformed or suspicious certificate.
        _ => false,
    }
}

/// Extract the string content bytes from a DirectoryString Any value,
/// returning `None` for types that require special pre-processing before
/// normalization (see `ava_values_match` for the dispatch logic).
///
/// # Normalization strategy by string type
///
/// **Currently handled (v0.1 partial normalization):**
/// `UTF8String`, `PrintableString`, `IA5String`, `VisibleString` — raw
/// content bytes are passed directly to `NormalizedIter`, which applies
/// ASCII case-folding and insignificant-space handling (RFC 4518 §2.4 step
/// 6 subset). Full Unicode NFKC normalization (RFC 4518 §2.3) is deferred
/// to v0.2 along with the types below.
///
/// **v0.2 planned — decode then normalize:**
/// - `BMPString` (UCS-2 BE, BMP only): decode UTF-16BE → apply full RFC
///   4518 six-step preparation (Map → NFKC → Prohibit → CheckBidi →
///   insignificant-space). RFC 4518 §2.1 classifies BMPString as "a subset
///   of Unicode" — no custom transcoding required.
/// - `UniversalString` (UCS-4 BE): decode UCS-4 BE → apply the same RFC
///   4518 six-step preparation as BMPString.
///
/// v0.2 will also upgrade the currently-handled types to full RFC 4518
/// six-step normalization (adding NFKC). All types except `TeletexString`
/// will be normalized identically.
///
/// **Permanent exception — `TeletexString` (T61String):**
/// Raw DER byte comparison only; decode-and-normalize will never be added.
/// RFC 4518 §2.1 states: "As there is no standard for mapping TeletexString
/// values to Unicode, the mapping is left a local matter." RFC 5280 §7.1
/// classifies TeletexString support as OPTIONAL. No canonical T.61→Unicode
/// table exists (OpenSSL, NSS, and GnuTLS each use incompatible vendor
/// extensions). Introducing any mapping would silently accept mismatches
/// that other validators reject.
fn any_to_str_bytes(a: &der::Any) -> Option<&[u8]> {
    use der::Tag;
    match a.tag() {
        Tag::Utf8String | Tag::PrintableString | Tag::Ia5String | Tag::VisibleString => {
            Some(a.value())
        }
        _ => None,
    }
}

/// Compare two byte slices after RFC 4518 whitespace normalization and case-folding.
///
/// Rules applied (per RFC 4518 §2):
/// 1. ASCII letters (0x41–0x5A): case-fold to lowercase. Non-ASCII bytes are
///    passed through unchanged; full Unicode case-folding (NFKC + case-fold)
///    is deferred to v0.2.
/// 2. Leading/trailing spaces: ignored
/// 3. Internal multiple spaces: collapsed to single space
fn normalized_eq(a: &[u8], b: &[u8]) -> bool {
    NormalizedIter::new(a).eq(NormalizedIter::new(b))
}

/// Iterator that yields bytes after ASCII case-fold and whitespace normalization.
struct NormalizedIter<'a> {
    bytes: &'a [u8],
    pos: usize,
    pending_space: bool,
}

impl<'a> NormalizedIter<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        // Skip leading spaces.
        let start = bytes.iter().position(|&b| b != b' ').unwrap_or(bytes.len());
        // Find end (skip trailing spaces).
        let end = bytes[start..]
            .iter()
            .rposition(|&b| b != b' ')
            .map_or(start, |i| start + i + 1);
        Self {
            bytes: &bytes[start..end],
            pos: 0,
            pending_space: false,
        }
    }
}

impl<'a> Iterator for NormalizedIter<'a> {
    type Item = u8;
    fn next(&mut self) -> Option<u8> {
        // Invariant: `pending_space = true` means we emitted a space on the previous
        // call but have not yet consumed the consecutive space run that follows it.
        // On the next call we skip the entire run and resume with the next non-space
        // byte. This ensures:
        //   (a) internal space runs collapse to exactly one space, and
        //   (b) trailing space runs do not emit a trailing space, because the run
        //       ends at the trim boundary established in `new()` (trailing spaces
        //       are excluded from `self.bytes` before iteration begins).
        if self.pending_space {
            self.pending_space = false;
            while self.pos < self.bytes.len() && self.bytes[self.pos] == b' ' {
                self.pos += 1;
            }
            // Fall through: process the next non-space byte (or return None if at end).
        }
        if self.pos >= self.bytes.len() {
            return None;
        }
        let b = self.bytes[self.pos];
        self.pos += 1;
        if b == b' ' {
            // Emit one space; next call will skip any further consecutive spaces.
            self.pending_space = true;
            Some(b' ')
        } else {
            Some(b.to_ascii_lowercase())
        }
    }
}

// ---------------------------------------------------------------------------
// NameConstraints matching (PKIX-mew)
// ---------------------------------------------------------------------------

/// Newtype wrapping a bitmask of `GeneralName` name types for NameConstraints.
///
/// Used by `nc_constrained_types` to track which types have been constrained
/// by at least one CA certificate in the path, even if the intersection later
/// empties the permitted set for that type.
///
/// Bare `u32` constants would allow silent misuse (e.g., confusing a count
/// with a mask). The newtype makes the intent explicit at every operation site.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct NcTypeMask(u32);

impl NcTypeMask {
    const EMPTY: NcTypeMask = NcTypeMask(0);
    const RFC822: NcTypeMask = NcTypeMask(1 << 0);
    const DNS: NcTypeMask = NcTypeMask(1 << 1);
    const DIRECTORY_NAME: NcTypeMask = NcTypeMask(1 << 2);
    const URI: NcTypeMask = NcTypeMask(1 << 3);
    const IP_ADDRESS: NcTypeMask = NcTypeMask(1 << 4);

    /// Returns `true` if `self` and `other` share at least one bit (non-empty intersection).
    ///
    /// Named `intersects` rather than `contains` because this is a bitmask test,
    /// not a set-membership check — `a.intersects(b)` is symmetric, while `contains`
    /// implies `a ⊇ b`.
    fn intersects(self, other: NcTypeMask) -> bool {
        self.0 & other.0 != 0
    }
}

impl core::ops::BitOr for NcTypeMask {
    type Output = NcTypeMask;
    fn bitor(self, rhs: NcTypeMask) -> NcTypeMask {
        NcTypeMask(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for NcTypeMask {
    fn bitor_assign(&mut self, rhs: NcTypeMask) {
        self.0 |= rhs.0;
    }
}

/// Return the `NcTypeMask` bit for the name type of `name`, or `EMPTY` for
/// unrecognized types.
fn name_type_bit(name: &x509_cert::ext::pkix::name::GeneralName) -> NcTypeMask {
    use x509_cert::ext::pkix::name::GeneralName;
    match name {
        GeneralName::Rfc822Name(_) => NcTypeMask::RFC822,
        GeneralName::DnsName(_) => NcTypeMask::DNS,
        GeneralName::DirectoryName(_) => NcTypeMask::DIRECTORY_NAME,
        GeneralName::UniformResourceIdentifier(_) => NcTypeMask::URI,
        GeneralName::IpAddress(_) => NcTypeMask::IP_ADDRESS,
        _ => NcTypeMask::EMPTY,
    }
}

/// Returns true if `subject` DN is within the subtree rooted at `constraint`.
///
/// RFC 5280 §4.2.1.10: a DirectoryName constraint is satisfied when the subject's
/// DN has the constraint DN as a prefix (most-general to most-specific order).
/// E.g., constraint `{C=US, O=Test}` matches subject `{C=US, O=Test, CN=Alice}`.
fn dn_within_subtree(subject: &x509_cert::name::Name, constraint: &x509_cert::name::Name) -> bool {
    let c_rdns = &constraint.0;
    let s_rdns = &subject.0;
    if c_rdns.len() > s_rdns.len() {
        return false;
    }
    c_rdns.iter().zip(s_rdns.iter()).all(|(c_rdn, s_rdn)| {
        // Each pair of RDNs must have matching attribute-value pairs.
        if c_rdn.0.len() != s_rdn.0.len() {
            return false;
        }
        c_rdn.0.iter().all(|c_ava| {
            s_rdn
                .0
                .iter()
                .any(|s_ava| c_ava.oid == s_ava.oid && ava_values_match(&c_ava.value, &s_ava.value))
        })
    })
}

/// Returns true if `a` and `b` are the same handled `GeneralName` variant.
///
/// Uses `name_type_bit` as the single source of truth so that adding a new
/// handled type to `name_type_bit` automatically extends this check with no
/// separate update required.
fn same_nc_variant(
    a: &x509_cert::ext::pkix::name::GeneralName,
    b: &x509_cert::ext::pkix::name::GeneralName,
) -> bool {
    name_type_bit(a) != NcTypeMask::EMPTY && name_type_bit(a) == name_type_bit(b)
}

/// Returns true if `name` satisfies the `subtree` constraint.
fn name_matches_subtree(
    name: &x509_cert::ext::pkix::name::GeneralName,
    subtree: &x509_cert::ext::pkix::constraints::name::GeneralSubtree,
) -> bool {
    use x509_cert::ext::pkix::name::GeneralName;
    match (name, &subtree.base) {
        (GeneralName::DnsName(subj), GeneralName::DnsName(constr)) => {
            matches_dns_name(subj.as_str(), constr.as_str())
        }
        (GeneralName::DirectoryName(subj), GeneralName::DirectoryName(constr)) => {
            dn_within_subtree(subj, constr)
        }
        (GeneralName::Rfc822Name(subj), GeneralName::Rfc822Name(constr)) => {
            matches_rfc822_name(subj.as_str(), constr.as_str())
        }
        (
            GeneralName::UniformResourceIdentifier(subj),
            GeneralName::UniformResourceIdentifier(constr),
        ) => matches_uri(subj.as_str(), constr.as_str()),
        (GeneralName::IpAddress(subj), GeneralName::IpAddress(constr)) => {
            matches_ip_address(subj.as_bytes(), constr.as_bytes())
        }
        // Mismatched variants or unhandled types: no match.
        _ => false,
    }
}

/// DNS name constraint matching (RFC 5280 §4.2.1.10).
///
/// If `constraint` starts with '.', `subject` must be a subdomain of it
/// (label-aware suffix check). Otherwise exact match (case-insensitive).
fn matches_dns_name(subject: &str, constraint: &str) -> bool {
    if constraint.is_empty() {
        return false;
    }
    if let Some(suffix) = constraint.strip_prefix('.') {
        // Subdomain match: subject must end with ".suffix" (not just "suffix").
        if subject.eq_ignore_ascii_case(suffix) {
            // The constraint is ".example.com"; subject "example.com" is the
            // apex — RFC 5280 §4.2.1.10 excludes the apex from subdomain constraints.
            return false;
        }
        let dot_suffix = constraint; // already starts with '.'
        subject.len() > dot_suffix.len()
            && subject[subject.len() - dot_suffix.len()..].eq_ignore_ascii_case(dot_suffix)
    } else {
        // RFC 5280 §4.2.1.10: a constraint without a leading period matches
        // the hostname exactly AND any subdomain (labels added to the left).
        // E.g., "example.com" matches "example.com" and "host.example.com".
        subject.eq_ignore_ascii_case(constraint)
            || (subject.len() > constraint.len() + 1
                && subject.as_bytes()[subject.len() - constraint.len() - 1] == b'.'
                && subject[subject.len() - constraint.len()..].eq_ignore_ascii_case(constraint))
    }
}

/// RFC 822 (email) name constraint matching (RFC 5280 §4.2.1.10).
fn matches_rfc822_name(subject: &str, constraint: &str) -> bool {
    if constraint.contains('@') {
        // Constraint is a specific mailbox address: exact match required.
        return subject.eq_ignore_ascii_case(constraint);
    }
    // Constraint is a domain (or .domain); extract the domain part of subject.
    let domain = match subject.split_once('@') {
        Some((_, d)) => d,
        None => return false, // malformed subject
    };
    if let Some(suffix) = constraint.strip_prefix('.') {
        // Domain must end with .suffix.
        if domain.eq_ignore_ascii_case(suffix) {
            return false; // apex excluded
        }
        let dot_suffix = constraint;
        domain.len() > dot_suffix.len()
            && domain[domain.len() - dot_suffix.len()..].eq_ignore_ascii_case(dot_suffix)
    } else {
        // Domain must equal the constraint exactly.
        domain.eq_ignore_ascii_case(constraint)
    }
}

/// URI host name constraint matching (RFC 5280 §4.2.1.10).
///
/// URI constraints use different semantics from DNS constraints:
/// - Leading period: subdomains only (same as DNS).
/// - No leading period: **exact host only** (unlike DNS, which also matches subdomains).
fn matches_uri_host(host: &str, constraint: &str) -> bool {
    if constraint.is_empty() {
        return false;
    }
    if let Some(suffix) = constraint.strip_prefix('.') {
        // Leading dot: subdomains only, apex excluded (same rule as DNS).
        if host.eq_ignore_ascii_case(suffix) {
            return false;
        }
        let dot_suffix = constraint;
        host.len() > dot_suffix.len()
            && host[host.len() - dot_suffix.len()..].eq_ignore_ascii_case(dot_suffix)
    } else {
        // RFC 5280 §4.2.1.10: URI constraint without leading period matches
        // the exact host only — subdomains are NOT included.
        host.eq_ignore_ascii_case(constraint)
    }
}

/// URI name constraint matching (RFC 5280 §4.2.1.10).
///
/// Extracts the host from the URI and applies URI host matching rules.
fn matches_uri(subject_uri: &str, constraint: &str) -> bool {
    // Extract host: everything between "://" and the next '/' or '?' or '#' or end.
    let host = if let Some(after_scheme) = subject_uri.find("://") {
        let rest = &subject_uri[after_scheme + 3..];
        // Strip userinfo if present (user:pass@host).
        let rest = rest.split_once('@').map_or(rest, |(_, h)| h);
        // Strip port and path.
        let host_end = rest.find(['/', '?', '#', ':']).unwrap_or(rest.len());
        &rest[..host_end]
    } else {
        return false; // not a URI with scheme
    };
    matches_uri_host(host, constraint)
}

/// IP address name constraint matching (RFC 5280 §4.2.1.10).
///
/// `constraint_bytes` must be 8 bytes (IPv4: addr + mask) or 32 bytes (IPv6).
/// `subject_bytes` must be 4 bytes (IPv4) or 16 bytes (IPv6).
fn matches_ip_address(subject_bytes: &[u8], constraint_bytes: &[u8]) -> bool {
    let (expected_subj_len, half) = match constraint_bytes.len() {
        8 => (4usize, 4usize),
        32 => (16usize, 16usize),
        _ => return false,
    };
    if subject_bytes.len() != expected_subj_len {
        return false;
    }
    let (addr, mask) = constraint_bytes.split_at(half);
    subject_bytes
        .iter()
        .zip(addr.iter().zip(mask.iter()))
        .all(|(s, (a, m))| s & m == a & m)
}

// ---------------------------------------------------------------------------
// ECDSA P-256 SHA-256 backend (PKIX-evy)
// ---------------------------------------------------------------------------

/// OID for `ecdsa-with-SHA256` (1.2.840.10045.4.3.2).
#[cfg(feature = "p256")]
const OID_ECDSA_P256_SHA256: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// ECDSA P-256 with SHA-256 signature verifier.
///
/// Handles OID `ecdsa-with-SHA256` (1.2.840.10045.4.3.2).
/// Feature-gated behind `p256`.
#[cfg(feature = "p256")]
#[derive(Clone, Copy, Debug, Default)]
pub struct EcdsaP256Verifier;

#[cfg(feature = "p256")]
impl SignatureVerifier for EcdsaP256Verifier {
    fn verify_signature(
        &self,
        algorithm: spki::AlgorithmIdentifierRef<'_>,
        issuer_spki: spki::SubjectPublicKeyInfoRef<'_>,
        message: &[u8],
        signature: &[u8],
    ) -> core::result::Result<(), SignatureError> {
        use p256::ecdsa::{signature::Verifier as _, DerSignature, VerifyingKey};

        // Reject any OID other than ecdsa-with-SHA256.
        if algorithm.oid != OID_ECDSA_P256_SHA256 {
            return Err(SignatureError::new());
        }

        let vk = VerifyingKey::try_from(issuer_spki).map_err(|_| SignatureError::new())?;

        let sig = DerSignature::try_from(signature).map_err(|_| SignatureError::new())?;

        vk.verify(message, &sig).map_err(|_| SignatureError::new())
    }
}

// ---------------------------------------------------------------------------
// RSA PKCS#1 v1.5 SHA-256 backend (PKIX-gmv)
// ---------------------------------------------------------------------------

/// OID for `sha256WithRSAEncryption` (1.2.840.113549.1.1.11).
#[cfg(feature = "rsa")]
const OID_SHA256_WITH_RSA: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

/// RSA with PKCS#1 v1.5 padding and SHA-256 signature verifier.
///
/// Handles OID `sha256WithRSAEncryption` (1.2.840.113549.1.1.11).
/// Feature-gated behind `rsa`.
#[cfg(feature = "rsa")]
#[derive(Clone, Copy, Debug, Default)]
pub struct RsaPkcs1v15Sha256Verifier;

#[cfg(feature = "rsa")]
impl SignatureVerifier for RsaPkcs1v15Sha256Verifier {
    fn verify_signature(
        &self,
        algorithm: spki::AlgorithmIdentifierRef<'_>,
        issuer_spki: spki::SubjectPublicKeyInfoRef<'_>,
        message: &[u8],
        signature: &[u8],
    ) -> core::result::Result<(), SignatureError> {
        use rsa::pkcs1v15::{Signature, VerifyingKey};
        use rsa::signature::Verifier as _;
        use sha2::Sha256;

        // Reject any OID other than sha256WithRSAEncryption.
        if algorithm.oid != OID_SHA256_WITH_RSA {
            return Err(SignatureError::new());
        }

        let vk =
            VerifyingKey::<Sha256>::try_from(issuer_spki).map_err(|_| SignatureError::new())?;

        let sig = Signature::try_from(signature).map_err(|_| SignatureError::new())?;

        vk.verify(message, &sig).map_err(|_| SignatureError::new())
    }
}

// ---------------------------------------------------------------------------
// RSA key size helper (PKIX-ken.1.5)
// ---------------------------------------------------------------------------

/// rsaEncryption OID: 1.2.840.113549.1.1.1 (RFC 3279 §2.3.1)
const OID_RSA_ENCRYPTION: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// Decode the RSA modulus from an SPKI and return its bit length.
///
/// Returns `None` when:
/// - the key algorithm OID is not `rsaEncryption` (non-RSA key; check does not apply), or
/// - the SPKI bytes cannot be decoded (malformed; signature verification will also fail).
///
/// Uses `der::SliceReader` and `der::asn1::UintRef` from the existing `der`
/// dependency — no additional crate required.
///
/// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }` (RFC 3279 §2.3.1).
/// `UintRef::as_bytes()` strips the leading 0x00 sign byte from a DER unsigned INTEGER,
/// returning only the magnitude. Bit length is derived as `magnitude_bytes * 8`, which
/// over-counts by at most 7 bits for keys whose high magnitude byte has leading zero bits —
/// this lenient rounding is acceptable for a minimum-floor check: a real 2040-bit key
/// would measure as 2048 bits and pass a 2048-bit floor. Key-generation tools always
/// produce keys whose top bit is set, so the practical impact is zero.
fn rsa_public_key_bits(spki: &spki::SubjectPublicKeyInfoOwned) -> Option<u32> {
    use der::{asn1::UintRef, Reader};

    if spki.algorithm.oid != OID_RSA_ENCRYPTION {
        return None; // Non-RSA key: check does not apply.
    }
    // BitString::as_bytes() returns None when unused_bits != 0.
    // RSA SPKI subject_public_key is always octet-aligned (unused_bits = 0).
    let raw = spki.subject_public_key.as_bytes()?;

    // raw is a DER-encoded RSAPublicKey SEQUENCE.
    // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    //
    // We decode the modulus INTEGER and then skip the publicExponent so the
    // sequence reader does not complain about trailing data (der 0.7 requires
    // the closure to consume the entire SEQUENCE content).
    //
    // Skip strategy: read the modulus, then call tlv_bytes() to consume the
    // exponent TLV as a raw byte slice (no allocation, no decode required).
    let modulus_byte_len: usize = der::SliceReader::new(raw)
        .ok()?
        .sequence(|r| {
            // UintRef strips the leading 0x00 sign byte; as_bytes() returns magnitude only.
            let modulus: UintRef<'_> = r.decode()?;
            let modulus_len = modulus.as_bytes().len();
            // Consume the publicExponent TLV so the nested reader has no trailing data.
            let _ = r.tlv_bytes()?;
            Ok(modulus_len)
        })
        .ok()?;

    // saturating_mul guards against overflow on a hypothetical absurdly large modulus.
    // The result fits in u32: the largest practical RSA key is 16384 bits (2048 bytes),
    // well within u32::MAX. u32::try_from is used to make the bound explicit.
    u32::try_from(modulus_byte_len.saturating_mul(8)).ok()
}

// ---------------------------------------------------------------------------
// Chain walk loop — signature verification and name linkage (PKIX-vxf)
// ---------------------------------------------------------------------------

/// Walk the chain from issuer to leaf, applying all RFC 5280 §6.1 per-cert checks.
///
/// Path-length and anchor-matching are handled by the caller (`validate_path`).
/// This function walks `chain` in reverse (issuer-to-leaf) against `anchor`:
///
///    a. Verify signature with the current issuer's SPKI.
///    b. Verify issuer/subject name linkage.
///    c. Check validity period against `policy.current_time_unix`.
///    d. Reject any unhandled critical extensions.
///    e. Check cert names (subject DN + SAN) against accumulated NC state.
///    f. For all certs except the leaf (i > 0): require `BasicConstraints` cA=TRUE.
///    g. For all certs except the leaf (i > 0): if `policy.enforce_key_usage`, require `keyCertSign`.
///    h. For all certs except the leaf (i > 0): enforce `pathLenConstraint` if present.
///    i. For all certs except the leaf (i > 0): accumulate NameConstraints state
///       (INTERSECTION for permittedSubtrees, UNION for excludedSubtrees).
///
/// RFC 5280 §4.2.1.9 note on pathLenConstraint: for the cert at position `i`
/// (leaf at 0, root-adjacent at chain.len()-1), there are exactly `i-1`
/// intermediate certs below it. The constraint requires `i-1 ≤ pathLenConstraint`.
fn chain_walk<V: SignatureVerifier>(
    chain: &[Certificate],
    anchor: &TrustAnchor,
    policy: &ValidationPolicy,
    verifier: &V,
) -> Result<()> {
    use der::Encode;
    use spki::der::referenced::OwnedToRef as _;
    use x509_cert::ext::pkix::{InhibitAnyPolicy, PolicyConstraints, PolicyMappings};

    let mut working_spki = &anchor.subject_public_key_info;
    let mut working_issuer_name = &anchor.subject;

    // RFC 5280 §6.1.2 (b)+(c): seed the initial permitted/excluded subtrees
    // from the trust anchor. These initial constraints apply to ALL certs in
    // the chain (including intermediates), not just to leaves — the chain walk
    // enforces them from the first certificate onward.
    let (mut nc_permitted, mut nc_excluded) = match &anchor.name_constraints {
        None => (
            None,
            x509_cert::ext::pkix::constraints::name::GeneralSubtrees::default(),
        ),
        Some(nc) => (
            // Clone necessary: nc_permitted and nc_excluded are mutated during the walk.
            nc.permitted_subtrees.clone(),
            nc.excluded_subtrees.clone().unwrap_or_default(),
        ),
    };
    // Bitmask of NcTypeMask bits for name types that have been explicitly
    // constrained by at least one permittedSubtrees entry in any CA cert seen so far.
    // Needed to detect violations when intersection empties the permitted set
    // for a type (e.g., two incompatible DN constraints → empty, but DN still forbidden).
    //
    // INVARIANT: bits are ORed in and never cleared. Once a type bit is set,
    // nc_permitted must contain zero entries of that type to represent "empty
    // intersection" (all names of that type are forbidden). Do NOT derive
    // "is type constrained?" from nc_permitted contents alone — that would
    // silently allow names of a type whose permitted set was emptied by
    // conflicting CA constraints.
    let mut nc_constrained_types: NcTypeMask = match &nc_permitted {
        None => NcTypeMask::EMPTY,
        Some(permitted) => {
            let mut bits = NcTypeMask::EMPTY;
            for st in permitted {
                bits |= name_type_bit(&st.base);
            }
            bits
        }
    };

    // RFC 5280 §6.1.2: initialise policy state variables (PKIX-mi3.3).
    //
    // The counters represent "skip N more non-self-issued certificates before
    // the constraint activates".  Setting a counter to `n + 1` means the
    // constraint never triggers unless a CA certificate forces it lower.
    let n = chain.len();
    // Convert n (usize) to u32 safely. Chains with >4 billion certs are not
    // realistic, but a truncating cast would produce a wrong counter value.
    // u32::MAX is safe: counters are only decremented (saturating), so u32::MAX
    // behaves identically to any value > the chain length for these semantics.
    let n_u32 = u32::try_from(n).unwrap_or(u32::MAX);
    let mut explicit_policy: u32 = if policy.initial_explicit_policy {
        0
    } else {
        n_u32.saturating_add(1)
    };
    let mut inhibit_any: u32 = if policy.initial_any_policy_inhibit {
        0
    } else {
        n_u32.saturating_add(1)
    };
    let mut policy_mapping: u32 = if policy.initial_policy_mapping_inhibit {
        0
    } else {
        n_u32.saturating_add(1)
    };
    // §6.1.2(a): initial valid_policy_tree — single anyPolicy root node.
    let mut policy_tree: Option<Vec<PolicyNode>> = Some(init_policy_tree());

    for i in (0..chain.len()).rev() {
        let cert = &chain[i];

        // (a0) Signature algorithm allowlist check.
        //      Fires BEFORE signature verification to give a diagnostic error
        //      (AlgorithmNotAllowed) rather than a confusing SignatureInvalid.
        //      Uses the outer signatureAlgorithm field, which RFC 5280 §4.1.1.2
        //      requires to be identical to the inner TBSCertificate.signature OID.
        //      Applies to every cert in the chain (no i == 0 guard), matching
        //      CA/B Forum profile intent.
        if let Some(ref allowed) = policy.allowed_signature_algs {
            // O(n) over a typically 2–6 element list; acceptable for the common case.
            if !allowed.contains(&cert.signature_algorithm.oid) {
                return Err(Error::AlgorithmNotAllowed { index: i });
            }
        }

        // (a) Verify signature with the current issuer's SPKI.
        //     8 KiB covers typical TLS and code-signing certs (1–3 KiB), but
        //     NOT large government / HSM certs. Certificates exceeding this limit
        //     return Error::Der — an implementation limit, not a malformed cert.
        //     Tracked for v0.2 with heap-backed encoding.
        let mut tbs_buf = [0u8; 8192];
        let tbs_bytes = cert
            .tbs_certificate
            .encode_to_slice(&mut tbs_buf)
            .map_err(Error::Der)?;
        verifier
            .verify_signature(
                cert.signature_algorithm.owned_to_ref(),
                working_spki.owned_to_ref(),
                tbs_bytes,
                cert.signature.raw_bytes(),
            )
            .map_err(|_| Error::SignatureInvalid { index: i })?;

        // (b) Issuer/subject name linkage.
        if !names_match(working_issuer_name, &cert.tbs_certificate.issuer) {
            return Err(Error::ChainBroken { index: i });
        }

        // (c) Validity period.
        check_validity(cert, policy.current_time_unix, i)?;

        // (c2) Max validity period length check.
        //      saturating_sub avoids wrap on a malformed cert where notAfter < notBefore;
        //      a duration of 0 trivially passes the > max_secs test (safe, not a bypass).
        //      Applies to every cert in the chain per the epic intent.
        if let Some(max_secs) = policy.max_validity_secs {
            let not_before = cert
                .tbs_certificate
                .validity
                .not_before
                .to_unix_duration()
                .as_secs();
            let not_after = cert
                .tbs_certificate
                .validity
                .not_after
                .to_unix_duration()
                .as_secs();
            if not_after.saturating_sub(not_before) > max_secs {
                return Err(Error::ValidityPeriodExceedsMax { index: i });
            }
        }

        // (c3) Minimum RSA key size check.
        //      Non-RSA keys produce None from rsa_public_key_bits and are silently skipped.
        //      Applies to every cert in the chain per the epic intent.
        if let Some(min_bits) = policy.min_rsa_key_bits {
            if let Some(actual_bits) =
                rsa_public_key_bits(&cert.tbs_certificate.subject_public_key_info)
            {
                if actual_bits < min_bits {
                    return Err(Error::KeyTooSmall { index: i });
                }
            }
            // Non-RSA keys: rsa_public_key_bits returns None → check silently skipped.
        }

        // (d) Critical extension guard.
        check_critical_extensions(cert, i)?;

        // Cert depth in the RFC 5280 §6.1 sense: 1 = root-adjacent, n = leaf.
        let cert_depth = n - i;

        // Decode the cert's CertificatePolicies extension once per cert.
        // Used in both step (d) (policy tree update) and step (a/b) (PolicyMappings
        // anyPolicy qualifier lookup).  Decoding here avoids a second parse inside
        // the mapping loop (b5r.12).
        let cert_cp: Option<x509_cert::ext::pkix::certpolicy::CertificatePolicies> =
            find_cert_ext(cert, OID_CERTIFICATE_POLICIES);

        // (policy-d) CertificatePolicies extension (RFC 5280 §6.1.3(d)).
        // Only processed when the policy tree is still alive.
        if let Some(ref mut tree) = policy_tree {
            if let Some(ref cp_ext) = cert_cp {
                let mut new_nodes: Vec<PolicyNode> = Vec::new();
                let mut has_any_policy = false;

                // Step (d)(1): process each specific policy P ≠ anyPolicy.
                for policy_info in cp_ext.0.iter() {
                    let p_oid = &policy_info.policy_identifier;
                    if p_oid == &OID_ANY_POLICY {
                        // Defer anyPolicy processing to step (d)(2).
                        has_any_policy = true;
                        continue;
                    }

                    // (d)(1)(i): for each parent at depth i-1 whose
                    // expected_policy_set contains p_oid, create a child.
                    let mut matched_via_i = false;
                    let match_count = tree
                        .iter()
                        .filter(|parent| {
                            parent.depth == cert_depth - 1
                                && parent.expected_policy_set.contains(p_oid)
                        })
                        .count();

                    for _ in 0..match_count {
                        matched_via_i = true;
                        new_nodes.push(PolicyNode {
                            depth: cert_depth,
                            valid_policy: *p_oid,
                            expected_policy_set: vec![*p_oid],
                        });
                    }

                    // (d)(1)(ii): if no match in (i), check for an anyPolicy
                    // parent at depth i-1.
                    if !matched_via_i {
                        let has_any_parent = tree.iter().any(|parent| {
                            parent.depth == cert_depth - 1 && parent.valid_policy == OID_ANY_POLICY
                        });
                        if has_any_parent {
                            new_nodes.push(PolicyNode {
                                depth: cert_depth,
                                valid_policy: *p_oid,
                                expected_policy_set: vec![*p_oid],
                            });
                        }
                    }
                }

                // Step (d)(2): if cert has anyPolicy and (inhibit_any > 0 or
                // self-issued non-leaf), expand for each unmatched expected
                // policy from parent nodes.
                if has_any_policy {
                    let may_expand = inhibit_any > 0 || (i > 0 && is_self_issued_cert(cert));
                    if may_expand {
                        // Already-covered valid_policies at this depth.
                        let already_covered: Vec<der::asn1::ObjectIdentifier> =
                            new_nodes.iter().map(|nd| nd.valid_policy).collect();
                        for parent in tree.iter().filter(|nd| nd.depth == cert_depth - 1) {
                            for ep in parent.expected_policy_set.iter() {
                                if !already_covered.contains(ep) {
                                    new_nodes.push(PolicyNode {
                                        depth: cert_depth,
                                        valid_policy: *ep,
                                        expected_policy_set: vec![*ep],
                                    });
                                }
                            }
                        }
                    }
                }

                tree.extend(new_nodes);

                // Step (d)(3): prune ancestors with no children.
                if cert_depth > 1 {
                    prune_policy_tree(tree, cert_depth);
                }
                // If no nodes at depth >= 1 remain, tree is effectively NULL.
                if !tree.iter().any(|nd| nd.depth >= 1) {
                    policy_tree = None;
                }
            } else {
                // §6.1.3(e): CertificatePolicies absent → tree becomes NULL.
                policy_tree = None;
            }
        }

        // (policy-f) RFC 5280 §6.1.3(f): explicit_policy == 0 and tree NULL
        // → policy violation.
        if explicit_policy == 0 && policy_tree.is_none() {
            return Err(Error::PolicyViolation { index: i });
        }

        // Decode SAN once per cert: used in both the NC name check (e) and
        // potentially cached for the NC state update (i). Avoids scanning the
        // extension list twice per cert when both checks are active (vjc.13).
        let san = cert_subject_alt_names(cert);

        // (e) NameConstraints: check this cert's names against accumulated state.
        // RFC 5280 §6.1.3(b): self-issued non-leaf certs are exempt from NC name checking.
        // The NC state is still updated from their extensions in step (i).
        if i == 0 || !is_self_issued_cert(cert) {
            check_name_constraints(
                cert,
                san.as_ref(),
                nc_permitted.as_ref(),
                &nc_excluded,
                nc_constrained_types,
                i,
            )?;
        }

        // (e2) Require non-empty SubjectAltName on leaf cert.
        //      Only when require_subject_alt_name is set; intermediate CA certs
        //      are NOT checked (i == 0 guard). The `san` variable is decoded above
        //      and is already available — no second extension scan needed.
        if i == 0 && policy.require_subject_alt_name {
            // san is None if the extension is absent; Some(v) where v.0 may be empty.
            let san_is_nonempty = san.as_ref().is_some_and(|s| !s.0.is_empty());
            if !san_is_nonempty {
                return Err(Error::MissingSan);
            }
        }

        // (e3) Required leaf EKU OID check.
        //      Only when required_leaf_eku is Some; only on the leaf (i == 0).
        //      Uses try_find_cert_ext (fail-closed): malformed EKU DER on the leaf
        //      is mapped to MalformedCertificate rather than silently ignored.
        //      anyExtendedKeyUsage (OID 2.5.29.37.0) does NOT satisfy a specific
        //      OID requirement — only explicit listing in the cert's EKU counts.
        if i == 0 {
            if let Some(ref required_ekus) = policy.required_leaf_eku {
                use x509_cert::ext::pkix::ExtendedKeyUsage;
                match try_find_cert_ext::<ExtendedKeyUsage>(cert, OID_EXTENDED_KEY_USAGE)
                    .map_err(|_| Error::MalformedCertificate { index: 0 })?
                {
                    None => {
                        // EKU extension absent; any non-empty requirement fails.
                        if !required_ekus.is_empty() {
                            return Err(Error::MissingEku);
                        }
                    }
                    Some(eku) => {
                        for req_oid in required_ekus {
                            if !eku.0.iter().any(|e| e == req_oid) {
                                return Err(Error::MissingEku);
                            }
                        }
                    }
                }
            }
        }

        // (f–h) CA-only checks: apply to every cert except the leaf (chain[0]).
        //        This includes any intermediate CAs and the root CA cert if it
        //        is included in the chain rather than supplied only as an anchor.
        if i > 0 {
            // (f) BasicConstraints cA=TRUE required; (h) pathLenConstraint.
            // Decode BasicConstraints once for both checks.
            let bc = cert_basic_constraints(cert);
            if !bc.as_ref().is_some_and(|b| b.ca) {
                return Err(Error::NotCA { index: i });
            }

            // (g) KeyUsage keyCertSign required (when policy demands it).
            // RFC 5280 §6.1.4(n): "If a KeyUsage extension is present, verify that the
            // keyCertSign bit is set."  Only reject when KeyUsage IS present (Some(_)) and
            // keyCertSign is NOT set (== Some(false)).  Absent KeyUsage (None) is allowed.
            if policy.enforce_key_usage && has_key_cert_sign(cert) == Some(false) {
                return Err(Error::KeyUsageMissing { index: i });
            }

            // (h) pathLenConstraint: count only non-self-issued intermediates below position i
            // (RFC 5280 §4.2.1.9: "non-self-issued intermediate certificates").
            // chain[1..i] = the intermediate positions between the leaf (0) and this cert (i).
            if let Some(path_len) = bc.and_then(|b| b.path_len_constraint) {
                let effective_depth = chain[1..i]
                    .iter()
                    .filter(|c| !is_self_issued_cert(c))
                    .count();
                if effective_depth > path_len as usize {
                    return Err(Error::PathTooLong);
                }
            }

            // (policy-a) PolicyMappings (RFC 5280 §6.1.4(a)): anyPolicy must
            // not appear on either side of a mapping.
            // (policy-b) Apply mappings to the tree or delete mapped nodes.
            // NOTE: Policy mappings use the current policy_mapping counter value
            // (before decrement); the decrement happens in §6.1.4(h) below.
            // try_find_cert_ext (fail-closed): a malformed PolicyMappings extension
            // must cause rejection rather than silent ignore; a silently-discarded
            // mapping could allow a policy bypass (e.g., inhibit_policy_mapping bypass).
            if let Some(pm) = try_find_cert_ext::<PolicyMappings>(cert, OID_POLICY_MAPPINGS)
                .map_err(|_| Error::MalformedCertificate { index: i })?
            {
                // §6.1.4(a): reject anyPolicy as issuer or subject domain.
                for mapping in pm.0.iter() {
                    if mapping.issuer_domain_policy == OID_ANY_POLICY
                        || mapping.subject_domain_policy == OID_ANY_POLICY
                    {
                        return Err(Error::PolicyViolation { index: i });
                    }
                }

                // §6.1.4(b)(1): if policy_mapping > 0, update expected_policy_set.
                // §6.1.4(b)(2): if policy_mapping == 0, delete mapped nodes.
                if let Some(ref mut tree) = policy_tree {
                    if policy_mapping > 0 {
                        // For each issuerDomainPolicy ID-P in the mappings,
                        // update expected_policy_set of matching nodes.
                        for mapping in pm.0.iter() {
                            let idp = &mapping.issuer_domain_policy;
                            let sdp = &mapping.subject_domain_policy;
                            let mut found = false;
                            for node in tree.iter_mut() {
                                if node.depth == cert_depth && &node.valid_policy == idp {
                                    found = true;
                                    node.expected_policy_set.retain(|p| p != idp);
                                    if !node.expected_policy_set.contains(sdp) {
                                        node.expected_policy_set.push(*sdp);
                                    }
                                }
                            }
                            // If no node at cert_depth has valid_policy = ID-P
                            // but there is an anyPolicy node, generate a new
                            // child of the depth-(i-1) anyPolicy node.
                            if !found {
                                let has_any = tree.iter().any(|nd| {
                                    nd.depth == cert_depth && nd.valid_policy == OID_ANY_POLICY
                                });
                                if has_any {
                                    tree.push(PolicyNode {
                                        depth: cert_depth,
                                        valid_policy: *idp,
                                        expected_policy_set: vec![*sdp],
                                    });
                                }
                            }
                        }
                    } else {
                        // policy_mapping == 0: delete nodes whose valid_policy
                        // is an issuer_domain_policy in a mapping.
                        let mapped_policies: Vec<der::asn1::ObjectIdentifier> =
                            pm.0.iter().map(|m| m.issuer_domain_policy).collect();
                        tree.retain(|nd| {
                            nd.depth != cert_depth || !mapped_policies.contains(&nd.valid_policy)
                        });
                        if cert_depth > 0 {
                            prune_policy_tree(tree, cert_depth);
                        }
                    }
                }
            }
            // Check if tree became effectively NULL after mapping operations.
            if let Some(ref t) = policy_tree {
                if !t.iter().any(|nd| nd.depth >= 1) {
                    policy_tree = None;
                }
            }

            // (policy-h) RFC 5280 §6.1.4(h): decrement policy counters for
            // non-self-issued intermediate certificates.
            // This happens AFTER policy mappings processing (§6.1.4(b)) and
            // BEFORE clamping from extensions (§6.1.4(i)/(j)).
            if !is_self_issued_cert(cert) {
                explicit_policy = explicit_policy.saturating_sub(1);
                policy_mapping = policy_mapping.saturating_sub(1);
                inhibit_any = inhibit_any.saturating_sub(1);
            }

            // (policy-i) PolicyConstraints (RFC 5280 §6.1.4(c)): clamp
            // explicit_policy and policy_mapping from the extension.
            // try_find_cert_ext (fail-closed): malformed PolicyConstraints must reject;
            // silently ignoring it could allow explicit_policy bypass.
            if let Some(pc) =
                try_find_cert_ext::<PolicyConstraints>(cert, OID_POLICY_CONSTRAINTS)
                    .map_err(|_| Error::MalformedCertificate { index: i })?
            {
                if let Some(req) = pc.require_explicit_policy {
                    explicit_policy = explicit_policy.min(req);
                }
                if let Some(ipm) = pc.inhibit_policy_mapping {
                    policy_mapping = policy_mapping.min(ipm);
                }
            }

            // (policy-j) InhibitAnyPolicy (RFC 5280 §6.1.4(d)): clamp inhibit_any.
            // try_find_cert_ext (fail-closed): malformed InhibitAnyPolicy must reject;
            // silently ignoring it could allow anyPolicy through when it should be inhibited.
            if let Some(iap) =
                try_find_cert_ext::<InhibitAnyPolicy>(cert, OID_INHIBIT_ANY_POLICY)
                    .map_err(|_| Error::MalformedCertificate { index: i })?
            {
                inhibit_any = inhibit_any.min(iap.0);
            }

            // (i) NC update: NameConstraints state update (RFC 5280 §6.1.4(b)).
            //     INTERSECTION for permitted, UNION for excluded.
            //     cert_name_constraints is fail-closed: a malformed or non-conformant
            //     NC extension (e.g., non-zero minimum/maximum) returns MalformedCertificate
            //     rather than silently ignoring the constraints (vjc.7, vjc.8).
            if let Some(nc) = cert_name_constraints(cert, i)? {
                // permittedSubtrees: intersect with current state.
                if let Some(new_permitted) = nc.permitted_subtrees {
                    // Track which types this CA is constraining.
                    for entry in new_permitted.iter() {
                        nc_constrained_types |= name_type_bit(&entry.base);
                    }
                    match nc_permitted.as_mut() {
                        None => {
                            // First constraint seen; adopt it directly.
                            nc_permitted = Some(new_permitted);
                        }
                        Some(current) => {
                            // Type-aware intersection of two permitted-subtrees sets.
                            //
                            // RFC 5280 §6.1.4(b): intersect entry-by-entry, but only
                            // compare entries of the SAME name type. Entries of types
                            // not present in new_permitted are unchanged (new doesn't
                            // constrain that type). Entries of types not in current
                            // are added directly (new adds a fresh constraint).
                            //
                            // For entries of matching type, keep:
                            //   1. new entries within (⊆) some same-type current entry.
                            //   2. current entries within (⊆) some same-type new entry.
                            // (If neither is within the other the intersection for that
                            // type is empty — tracked via nc_constrained_types.)
                            let mut result =
                                x509_cert::ext::pkix::constraints::name::GeneralSubtrees::default();

                            // For each new entry, pre-filter current entries of the
                            // same type to avoid calling same_nc_variant twice per
                            // pair (vjc.16: duplicated guard + containment check).
                            for n in new_permitted.iter() {
                                let same_type_in_current: x509_cert::ext::pkix::constraints::name::GeneralSubtrees =
                                    current
                                        .iter()
                                        .filter(|c| same_nc_variant(&c.base, &n.base))
                                        .cloned()
                                        .collect();
                                if same_type_in_current.is_empty() {
                                    // Type not previously constrained → add directly.
                                    result.push(n.clone());
                                } else if same_type_in_current
                                    .iter()
                                    .any(|c| name_matches_subtree(&n.base, c))
                                {
                                    // n is within some same-type current entry → keep.
                                    result.push(n.clone());
                                }
                                // else: n is not within any current entry of same type → drop.
                            }

                            for c in current.iter() {
                                let same_type_in_new: x509_cert::ext::pkix::constraints::name::GeneralSubtrees =
                                    new_permitted
                                        .iter()
                                        .filter(|n| same_nc_variant(&n.base, &c.base))
                                        .cloned()
                                        .collect();
                                if same_type_in_new.is_empty() {
                                    // Type not in new_permitted → keep unchanged.
                                    result.push(c.clone());
                                } else if same_type_in_new
                                    .iter()
                                    .any(|n| name_matches_subtree(&c.base, n))
                                {
                                    // c is more specific than some new entry; keep unless
                                    // an equivalent entry is already in result (dedup
                                    // within the result set for this type).
                                    let same_type_in_result: &[_] = result.as_slice();
                                    let already_in_result = same_type_in_result.iter().any(|e| {
                                        same_nc_variant(&e.base, &c.base)
                                            && name_matches_subtree(&e.base, c)
                                            && name_matches_subtree(&c.base, e)
                                    });
                                    if !already_in_result {
                                        result.push(c.clone());
                                    }
                                }
                                // else: c is not within any new entry of same type → drop.
                            }

                            *current = result;
                        }
                    }
                }
                // excludedSubtrees: union — append only entries not already present,
                // avoiding monotonic growth that would make per-cert NC checks O(chain²)
                // when the same excluded subtrees are repeated across multiple CAs (vjc.12).
                if let Some(new_excluded) = nc.excluded_subtrees {
                    for new_entry in new_excluded.iter() {
                        // Deduplication uses name_matches_subtree as a two-way equality
                        // check: two entries are considered the same subtree when each
                        // matches the other (i.e., they are semantically equivalent, not
                        // just byte-equal).
                        let already_present = nc_excluded.iter().any(|existing| {
                            same_nc_variant(&existing.base, &new_entry.base)
                                && name_matches_subtree(&existing.base, new_entry)
                                && name_matches_subtree(&new_entry.base, existing)
                        });
                        if !already_present {
                            nc_excluded.push(new_entry.clone());
                        }
                    }
                }
            }
        }

        // Update state for next iteration.
        working_spki = &cert.tbs_certificate.subject_public_key_info;
        working_issuer_name = &cert.tbs_certificate.subject;
    }

    // RFC 5280 §6.1.5(a-b): post-loop leaf policy finalisation.
    //
    // §6.1.5 is a post-loop step in the RFC.  These operations apply only to
    // the leaf certificate (chain[0]), which was the last iteration (i == 0).
    // Placing them here rather than inside the loop at i == 0 matches the RFC
    // section numbering and makes clear that they happen after all per-cert
    // §6.1.3/§6.1.4 steps have completed.
    {
        let leaf = &chain[0];
        // §6.1.5(a): if the leaf is not self-issued, decrement counters.
        // inhibit_any and policy_mapping are decremented per RFC 5280 §6.1.5(a)
        // but are not used after this point in the algorithm — only explicit_policy
        // is tested in §6.1.5(g) and the final check.
        if !is_self_issued_cert(leaf) {
            explicit_policy = explicit_policy.saturating_sub(1);
            // Per §6.1.5(a): RFC also decrements inhibit_any and policy_mapping here,
            // but neither is read after §6.1.5(a) in our implementation.
        }
        // §6.1.5(b): if PolicyConstraints requireExplicitPolicy == 0,
        // force explicit_policy to 0.
        // try_find_cert_ext (fail-closed): consistent with per-loop treatment of
        // PolicyConstraints; a malformed extension on the leaf must also reject.
        if let Some(pc) =
            try_find_cert_ext::<PolicyConstraints>(leaf, OID_POLICY_CONSTRAINTS)
                .map_err(|_| Error::MalformedCertificate { index: 0 })?
        {
            if pc.require_explicit_policy == Some(0) {
                explicit_policy = 0;
            }
        }
    }

    // RFC 5280 §6.1.5(g): intersect the valid_policy_tree with the
    // user-initial-policy-set (PKIX-mi3.5).
    //
    // An empty initial_policy_set means {anyPolicy} — no trimming needed.
    //
    // When the set is non-empty:
    //   §6.1.5(g)(iii)(1): valid_policy_node_set = nodes whose parent
    //     has valid_policy = anyPolicy.
    //   §6.1.5(g)(iii)(2): delete nodes in that set not in initial_policy_set
    //     (and not anyPolicy themselves) along with their descendants.
    //   §6.1.5(g)(iii)(3): if a leaf anyPolicy node exists, materialise
    //     nodes for each P-OID in initial_policy_set not already present.
    //   §6.1.5(g)(iii)(4): prune childless ancestors.
    if !policy.initial_policy_set.is_empty() {
        if let Some(ref mut tree) = policy_tree {
            let leaf_depth = n;

            // §6.1.5(g)(iii): intersect the valid_policy_tree with
            // user-initial-policy-set.
            //
            // The RFC defines valid_policy_node_set (vpns) as nodes in the tree
            // whose PARENT has valid_policy == anyPolicy.  Because the depth-0 root
            // is always anyPolicy, this includes ALL depth-1 nodes.  For deeper trees,
            // it also includes nodes at any depth whose immediate parent is anyPolicy.
            //
            // Step (iii)(2): delete every vpns node whose valid_policy is not anyPolicy
            // AND not in the user-initial-policy-set.  Then prune ancestors that
            // become childless.
            //
            // Implementation: collect vpns_policies (the valid_policies of vpns nodes)
            // for step (iii)(3) dedup, then delete out-of-set nodes.
            let vpns_indices: Vec<usize> = tree
                .iter()
                .enumerate()
                .filter(|(_, nd)| {
                    nd.depth >= 1
                        && tree
                            .iter()
                            .any(|p| p.depth == nd.depth - 1 && p.valid_policy == OID_ANY_POLICY)
                })
                .map(|(idx, _)| idx)
                .collect();

            // Collect valid_policies already in vpns (for step (iii)(3) dedup).
            let vpns_policies: Vec<der::asn1::ObjectIdentifier> = vpns_indices
                .iter()
                .map(|&idx| tree[idx].valid_policy)
                .collect();

            // Identify vpns nodes to delete: not anyPolicy and not in initial_policy_set.
            let to_delete_vpns: Vec<(usize, der::asn1::ObjectIdentifier)> = vpns_indices
                .iter()
                .filter(|&&idx| {
                    tree[idx].valid_policy != OID_ANY_POLICY
                        && !policy.initial_policy_set.contains(&tree[idx].valid_policy)
                })
                .map(|&idx| (tree[idx].depth, tree[idx].valid_policy))
                .collect();

            if !to_delete_vpns.is_empty() {
                // Delete the out-of-set vpns nodes.
                tree.retain(|nd| {
                    !to_delete_vpns
                        .iter()
                        .any(|(d, vp)| nd.depth == *d && &nd.valid_policy == vp)
                });
                // Cascade deletion downward: remove any node that is no longer
                // reachable from a living parent node.
                for d in 2..=leaf_depth {
                    let parent_depth = d - 1;
                    let reachable: Vec<der::asn1::ObjectIdentifier> = tree
                        .iter()
                        .filter(|nd| nd.depth == parent_depth)
                        .flat_map(|nd| nd.expected_policy_set.iter().copied())
                        .collect();
                    let any_parent = tree
                        .iter()
                        .any(|nd| nd.depth == parent_depth && nd.valid_policy == OID_ANY_POLICY);
                    tree.retain(|nd| {
                        if nd.depth != d {
                            return true;
                        }
                        reachable.contains(&nd.valid_policy) || any_parent
                    });
                }
            }

            // Step (iii)(3): materialise nodes for initial_policy_set members
            // not yet present, if there's an anyPolicy node at leaf depth.
            let has_leaf_any = tree
                .iter()
                .any(|nd| nd.depth == leaf_depth && nd.valid_policy == OID_ANY_POLICY);
            if has_leaf_any {
                let mut additions = Vec::new();
                for p_oid in &policy.initial_policy_set {
                    if !vpns_policies.contains(p_oid) {
                        additions.push(PolicyNode {
                            depth: leaf_depth,
                            valid_policy: *p_oid,
                            expected_policy_set: vec![*p_oid],
                        });
                    }
                }
                tree.extend(additions);
                // Delete the leaf anyPolicy node.
                tree.retain(|nd| !(nd.depth == leaf_depth && nd.valid_policy == OID_ANY_POLICY));
            }

            // Step (iii)(4): prune childless ancestors.
            if n > 0 {
                prune_policy_tree(tree, leaf_depth);
            }
            // The tree is effectively NULL if no nodes exist at depth >= 1
            // (only the synthetic depth-0 anyPolicy root is left, which
            // does not represent any actual valid policy).
            if !tree.iter().any(|nd| nd.depth >= 1) {
                policy_tree = None;
            }
        }
    }

    // §6.1.5 final check: path is valid iff explicit_policy > 0 OR tree
    // is non-NULL.
    if explicit_policy == 0 && policy_tree.is_none() {
        return Err(Error::PolicyViolation { index: 0 });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// NameConstraints enforcement (PKIX-xji)
// ---------------------------------------------------------------------------

/// Whether a name-constraint check requires a match (permitted) or forbids a
/// match (excluded).
///
/// Using an explicit enum instead of a bare `bool` makes call sites
/// self-documenting: `CheckMode::Excluded` / `CheckMode::Permitted` vs
/// opaque `false` / `true` (vjc.25).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CheckMode {
    /// Excluded subtrees: any name that matches is a violation.
    Excluded,
    /// Permitted subtrees: a constrained name type that matches *no* entry is a violation.
    Permitted,
}

/// Check that all names in `cert` satisfy the current NameConstraints state.
///
/// Called once per certificate during chain_walk, BEFORE updating the NC
/// state from that certificate's own NameConstraints extension.
///
/// `san` is the pre-decoded SubjectAltName for this cert (pass `None` if the
/// extension is absent). Decoding it before the call avoids a second scan of
/// the extension list when both NC check and NC update are needed (vjc.13).
///
/// RFC 5280 §6.1.4(b)(1)–(2): check excluded subtrees first, then
/// permitted subtrees.
fn check_name_constraints(
    cert: &x509_cert::Certificate,
    san: Option<&x509_cert::ext::pkix::SubjectAltName>,
    nc_permitted: Option<&x509_cert::ext::pkix::constraints::name::GeneralSubtrees>,
    nc_excluded: &x509_cert::ext::pkix::constraints::name::GeneralSubtrees,
    nc_constrained_types: NcTypeMask,
    index: usize,
) -> crate::Result<()> {
    use x509_cert::ext::pkix::name::GeneralName;

    let subject = &cert.tbs_certificate.subject;
    let subject_is_empty = subject.0.is_empty();

    // Helper: check all cert names (subject DN + SAN) against `subtrees`.
    //
    // CheckMode::Excluded → any match is a violation.
    // CheckMode::Permitted → a name type is constrained if any CA in the path
    // ever added a permittedSubtrees entry of that type (tracked in
    // nc_constrained_types). Constrained types must match at least one permitted
    // subtree entry; unconstrained types are always accepted.
    let check_names = |subtrees: &[x509_cert::ext::pkix::constraints::name::GeneralSubtree],
                       mode: CheckMode|
     -> crate::Result<()> {
        let type_constrained =
            |name: &GeneralName| -> bool { nc_constrained_types.intersects(name_type_bit(name)) };

        // subject DN — skipped when empty per RFC 5280 §6.1.3(b).
        // Avoid constructing a GeneralName::DirectoryName (which requires a clone)
        // by handling DirectoryName constraints inline: pull DirectoryName entries
        // from `subtrees` and test directly against the subject Name (vjc.24).
        if !subject_is_empty {
            let subject_constrained = nc_constrained_types.intersects(NcTypeMask::DIRECTORY_NAME);
            let dn_matches_any = subtrees.iter().any(|st| {
                if let GeneralName::DirectoryName(constr) = &st.base {
                    dn_within_subtree(subject, constr)
                } else {
                    false
                }
            });
            match mode {
                CheckMode::Excluded => {
                    if dn_matches_any {
                        return Err(Error::NameConstraintViolation { index });
                    }
                }
                CheckMode::Permitted => {
                    if subject_constrained && !dn_matches_any {
                        return Err(Error::NameConstraintViolation { index });
                    }
                }
            }
        }

        // SAN entries.
        if let Some(san_ext) = san {
            for name in san_ext.0.iter() {
                match mode {
                    CheckMode::Excluded => {
                        if subtrees.iter().any(|st| name_matches_subtree(name, st)) {
                            return Err(Error::NameConstraintViolation { index });
                        }
                    }
                    CheckMode::Permitted => {
                        if type_constrained(name)
                            && !subtrees.iter().any(|st| name_matches_subtree(name, st))
                        {
                            return Err(Error::NameConstraintViolation { index });
                        }
                    }
                }
            }
        }
        Ok(())
    };

    // (1) Excluded check: any excluded subtree match → violation.
    check_names(nc_excluded.as_slice(), CheckMode::Excluded)?;

    // (2) Permitted check: if permitted set is constrained, every name must
    //     match at least one permitted subtree.
    if let Some(permitted) = nc_permitted {
        check_names(permitted.as_slice(), CheckMode::Permitted)?;
    }

    // (3) RFC 5280 §4.2.1.10: emailAddress attributes in the subject DN MUST
    //     be checked against the rfc822Name constraint.
    //     Guard: only enter the RDN walk if RFC822 constraints are actually
    //     present — either a permitted-subtrees entry for RFC822 exists, OR at
    //     least one excluded entry is an Rfc822Name.  Checking !nc_excluded.is_empty()
    //     without filtering by type would cause the walk whenever ANY excluded
    //     name type exists, even if none are Rfc822Name (vjc.11).
    let has_rfc822_excluded = nc_excluded
        .iter()
        .any(|st| matches!(st.base, GeneralName::Rfc822Name(_)));
    let has_rfc822_constraint =
        nc_constrained_types.intersects(NcTypeMask::RFC822) || has_rfc822_excluded;

    if has_rfc822_constraint && !subject_is_empty {
        // Collect the RFC822 permitted subtrees once, outside the RDN loop,
        // to avoid re-checking the Option and iterating nc_permitted on every
        // emailAddress AVA found (vjc.26). `None` means the permitted check is
        // inactive (only an excluded check may apply); the NcTypeMask::RFC822
        // condition is evaluated once here and the result carried forward via
        // `permitted_rfc822`. `permitted_rfc822_storage` holds the allocation
        // when the check is active; `Option` avoids a dummy assignment that
        // would trigger an unused-assignment warning.
        let permitted_rfc822_storage: Option<
            x509_cert::ext::pkix::constraints::name::GeneralSubtrees,
        > = if nc_constrained_types.intersects(NcTypeMask::RFC822) {
            Some(
                nc_permitted
                    .map(|p| {
                        p.iter()
                            .filter(|st| matches!(st.base, GeneralName::Rfc822Name(_)))
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default(),
            )
        } else {
            None
        };
        let permitted_rfc822: Option<&[x509_cert::ext::pkix::constraints::name::GeneralSubtree]> =
            permitted_rfc822_storage.as_deref();

        for rdn in subject.0.iter() {
            for ava in rdn.0.iter() {
                if ava.oid != OID_EMAIL_ADDRESS {
                    continue;
                }
                let Ok(email_ia5) = ava.value.decode_as::<der::asn1::Ia5StringRef<'_>>() else {
                    continue;
                };
                let email_str = email_ia5.as_str();
                // Excluded check — walk only Rfc822Name excluded entries.
                for st in nc_excluded.iter() {
                    if let GeneralName::Rfc822Name(constraint) = &st.base {
                        if matches_rfc822_name(email_str, constraint.as_str()) {
                            return Err(Error::NameConstraintViolation { index });
                        }
                    }
                }
                // Permitted check (only when RFC822 has been constrained).
                if let Some(permitted) = permitted_rfc822 {
                    if !permitted.iter().any(|st| {
                        if let GeneralName::Rfc822Name(constraint) = &st.base {
                            matches_rfc822_name(email_str, constraint.as_str())
                        } else {
                            false
                        }
                    }) {
                        return Err(Error::NameConstraintViolation { index });
                    }
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// DefaultVerifier — OID-dispatching RustCrypto backend (PKIX-8wg)
// ---------------------------------------------------------------------------

/// A [`SignatureVerifier`] that dispatches to available RustCrypto backends by OID.
///
/// This is the recommended out-of-the-box verifier for applications that use
/// the default RustCrypto feature set. It supports:
///
/// - `ecdsa-with-SHA256` (1.2.840.10045.4.3.2) — via the `p256` feature
/// - `sha256WithRSAEncryption` (1.2.840.113549.1.1.11) — via the `rsa` feature
///
/// Any OID not in the above set returns `Err(signature::Error::new())`.
///
/// To support additional algorithms, implement [`SignatureVerifier`] directly
/// and dispatch your own OID table.
#[cfg(any(feature = "p256", feature = "rsa"))]
#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultVerifier;

#[cfg(any(feature = "p256", feature = "rsa"))]
impl SignatureVerifier for DefaultVerifier {
    fn verify_signature(
        &self,
        algorithm: AlgorithmIdentifierRef<'_>,
        issuer_spki: SubjectPublicKeyInfoRef<'_>,
        message: &[u8],
        signature: &[u8],
    ) -> core::result::Result<(), SignatureError> {
        let oid = algorithm.oid;
        #[cfg(feature = "p256")]
        if oid == OID_ECDSA_P256_SHA256 {
            return EcdsaP256Verifier.verify_signature(algorithm, issuer_spki, message, signature);
        }
        #[cfg(feature = "rsa")]
        if oid == OID_SHA256_WITH_RSA {
            return RsaPkcs1v15Sha256Verifier.verify_signature(
                algorithm,
                issuer_spki,
                message,
                signature,
            );
        }
        Err(SignatureError::new())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "p256"))]
mod tests_ecdsa_p256 {
    use super::*;
    use der::Decode;

    /// Test vector: a real P-256/SHA-256 self-signed cert generated by OpenSSL.
    /// Oracle: `openssl verify -CAfile ec.pem ec.pem` returns OK.
    #[test]
    fn verify_p256_self_signed() {
        let der = include_bytes!("../tests/fixtures/ec-p256-sha256.der");
        let cert = Certificate::from_der(der).expect("parse cert");

        use der::Encode as _;
        let tbs_der = cert.tbs_certificate.to_der().expect("encode tbs");
        let sig_bytes = cert.signature.raw_bytes();

        // Self-signed cert: signer SPKI is the cert's own SPKI.
        use spki::der::referenced::OwnedToRef as _;
        let spki_ref = cert.tbs_certificate.subject_public_key_info.owned_to_ref();

        let verifier = EcdsaP256Verifier;
        assert!(
            verifier
                .verify_signature(
                    cert.signature_algorithm.owned_to_ref(),
                    spki_ref,
                    &tbs_der,
                    sig_bytes,
                )
                .is_ok(),
            "self-signed P-256 cert should verify"
        );
    }
}

#[cfg(all(test, feature = "rsa"))]
mod tests_rsa {
    use super::*;
    use der::Decode;

    /// Test vector: a real RSA-2048/SHA-256 self-signed cert generated by OpenSSL.
    /// Oracle: `openssl verify -CAfile rsa.pem rsa.pem` returns OK.
    #[test]
    fn verify_rsa_pkcs1v15_sha256_self_signed() {
        let der = include_bytes!("../tests/fixtures/rsa-pkcs1v15-sha256.der");
        let cert = Certificate::from_der(der).expect("parse cert");

        use der::Encode as _;
        let tbs_der = cert.tbs_certificate.to_der().expect("encode tbs");
        let sig_bytes = cert.signature.raw_bytes();

        // Self-signed cert: signer SPKI is the cert's own SPKI.
        use spki::der::referenced::OwnedToRef as _;
        let spki_ref = cert.tbs_certificate.subject_public_key_info.owned_to_ref();

        let verifier = RsaPkcs1v15Sha256Verifier;
        assert!(
            verifier
                .verify_signature(
                    cert.signature_algorithm.owned_to_ref(),
                    spki_ref,
                    &tbs_der,
                    sig_bytes,
                )
                .is_ok(),
            "self-signed RSA cert should verify"
        );
    }

    /// Regression (PKIX-5u0): `spki_key_matches` ignores the NULL-vs-absent
    /// parameter encoding difference that exists for RSA SPKIs.
    ///
    /// RFC 3279 §2.3.1 allows both explicit NULL parameters and absent
    /// parameters for `rsaEncryption`. The derived `PartialEq` in the `spki`
    /// crate treats `Some(NULL) ≠ None`, so using `==` in the self-issued
    /// anchor guard would wrongly reject a valid anchor.
    #[test]
    fn spki_key_matches_ignores_null_vs_absent_params() {
        let der_bytes = include_bytes!("../tests/fixtures/rsa-pkcs1v15-sha256.der");
        let cert = Certificate::from_der(der_bytes).expect("parse cert");
        let cert_spki = &cert.tbs_certificate.subject_public_key_info;

        // Same OID and key bytes, but parameters: None instead of Some(NULL).
        let spki_no_params: spki::SubjectPublicKeyInfoOwned = spki::SubjectPublicKeyInfoOwned {
            algorithm: spki::AlgorithmIdentifier {
                oid: cert_spki.algorithm.oid,
                parameters: None,
            },
            subject_public_key: cert_spki.subject_public_key.clone(),
        };

        // PartialEq distinguishes Some(NULL) from None — document this behavior.
        assert_ne!(cert_spki, &spki_no_params);

        // spki_key_matches must return true: same OID + same key bytes.
        assert!(super::spki_key_matches(cert_spki, &spki_no_params));
    }

    /// Integration regression (PKIX-5u0): the self-issued anchor guard must not
    /// return `NoTrustedPath` when an anchor has absent parameters (None) and the
    /// cert in the chain has explicit NULL parameters — both are valid per RFC 3279
    /// §2.3.1 for rsaEncryption.
    ///
    /// The guard compares anchor and cert SPKIs with `spki_key_matches` (OID + key
    /// bytes only). Before the fix, using `==` caused `NoTrustedPath` because
    /// `Some(NULL) != None` under derived `PartialEq`.
    ///
    /// Note: the anchor with `parameters: None` will fail signature verification
    /// (the `rsa` crate rejects absent params during key parsing), so the result
    /// is `Err(SignatureInvalid)`, not `Ok`. What this test verifies is that the
    /// guard does NOT skip the anchor and return `NoTrustedPath`. The anchor is
    /// tried; the failure is at a later stage, not the guard.
    #[test]
    fn self_issued_rsa_anchor_absent_params_not_no_trusted_path() {
        // 2026-06-01 — within rsa-pkcs1v15-sha256.der validity window
        // (notBefore=2026-05-02, notAfter=2036-04-29).
        const NOW: u64 = 1_780_272_000;

        let der_bytes = include_bytes!("../tests/fixtures/rsa-pkcs1v15-sha256.der");
        let cert = Certificate::from_der(der_bytes).expect("parse cert");
        let cert_spki = &cert.tbs_certificate.subject_public_key_info;

        // Construct an anchor from the same cert but with parameters: None.
        // Simulates a trust store that was populated from a source omitting the
        // explicit NULL — a common DER encoding variation for rsaEncryption.
        let anchor = TrustAnchor::new(
            cert.tbs_certificate.subject.clone(),
            spki::SubjectPublicKeyInfoOwned {
                algorithm: spki::AlgorithmIdentifier {
                    oid: cert_spki.algorithm.oid,
                    parameters: None,
                },
                subject_public_key: cert_spki.subject_public_key.clone(),
            },
        );

        let policy = ValidationPolicy {
            current_time_unix: NOW,
            ..Default::default()
        };
        let result = validate_path(&[cert], &[anchor], &policy, &RsaPkcs1v15Sha256Verifier);
        // The guard must not skip the anchor (which would return NoTrustedPath).
        // SignatureInvalid is expected: the anchor was tried but the rsa crate
        // rejects absent params during key parsing.
        assert!(
            !matches!(result, Err(Error::NoTrustedPath)),
            "guard must not return NoTrustedPath for same key with different param encoding; got: {result:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// NormalizedIter / names_match unit tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests_normalized_iter {
    use super::normalized_eq;

    /// Identical ASCII strings must compare equal.
    #[test]
    fn identical_strings_equal() {
        assert!(normalized_eq(b"hello", b"hello"));
    }

    /// Case is folded to lowercase.
    #[test]
    fn case_folding() {
        assert!(normalized_eq(b"Hello", b"hello"));
        assert!(normalized_eq(b"HELLO WORLD", b"hello world"));
    }

    /// Leading spaces are stripped.
    #[test]
    fn leading_spaces_stripped() {
        assert!(normalized_eq(b"  hello", b"hello"));
    }

    /// Trailing spaces are stripped.
    ///
    /// Regression test: NormalizedIter must not emit a trailing space for
    /// input that ends with a space sequence.
    #[test]
    fn trailing_spaces_stripped() {
        assert!(normalized_eq(b"hello  ", b"hello"));
        assert!(normalized_eq(b"hello ", b"hello"));
    }

    /// Multiple consecutive internal spaces are collapsed to a single space.
    ///
    /// Regression test for the double-space bug: `pending_space` must not
    /// cause two spaces to be emitted for a single space in the input.
    #[test]
    fn internal_spaces_collapsed() {
        assert!(normalized_eq(b"hello  world", b"hello world"));
        assert!(normalized_eq(b"hello   world", b"hello world"));
    }

    /// Combined: leading + trailing + internal spaces, case folding.
    #[test]
    fn combined_normalization() {
        assert!(normalized_eq(b"  Hello   World  ", b"hello world"));
    }

    /// Empty string and all-spaces string must both yield zero bytes.
    #[test]
    fn empty_and_whitespace_only() {
        assert!(normalized_eq(b"", b""));
        assert!(normalized_eq(b"   ", b""));
        assert!(normalized_eq(b"   ", b"   "));
    }

    /// Different strings must NOT compare equal after normalization.
    #[test]
    fn different_strings_not_equal() {
        assert!(!normalized_eq(b"hello", b"world"));
        assert!(!normalized_eq(b"ab", b"abc"));
    }

    /// NormalizedIter: input ending with an internal space sequence followed by
    /// trailing spaces must emit the space and then stop (no double space, no
    /// trailing space).
    #[test]
    fn internal_then_trailing_space_no_trailing_emit() {
        assert!(
            normalized_eq(b"ab  ", b"ab"),
            "trailing spaces must not be emitted"
        );
        assert!(
            normalized_eq(b"ab  cd  ", b"ab cd"),
            "internal double-space collapses; trailing spaces stripped"
        );
    }
}

// PKIX-h6z: validate_path public API tests.
#[cfg(all(test, feature = "p256"))]
mod tests_validate_path {
    use super::*;
    use der::Decode;

    // Fixtures and time constants reused from tests_chain_walk.
    const GRY_NOW: u64 = 1_780_272_000; // 2026-06-01

    fn load(bytes: &[u8]) -> Certificate {
        Certificate::from_der(bytes).expect("parse cert")
    }

    fn policy_at(t: u64) -> ValidationPolicy {
        ValidationPolicy {
            current_time_unix: t,
            ..Default::default()
        }
    }

    /// Happy-path 1-cert chain: self-signed cert is both chain and anchor.
    ///
    /// Expected: Ok(ValidatedPath { anchor_index: 0, depth: 0 })
    #[test]
    fn one_cert_chain_ok() {
        let cert = load(include_bytes!("../tests/fixtures/ec-p256-sha256.der"));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        let result = validate_path(&[cert], &anchors, &policy_at(GRY_NOW), &EcdsaP256Verifier)
            .expect("1-cert chain must validate");
        assert_eq!(result.anchor_index, 0);
        assert_eq!(result.depth, 0);
    }

    /// Happy-path 2-cert chain: leaf + intermediate, with root anchor.
    ///
    /// Oracle: openssl verify -CAfile gry-root.pem -untrusted gry-int.pem gry-leaf.pem → OK
    /// Expected: Ok(ValidatedPath { anchor_index: 0, depth: 1 })
    #[test]
    fn two_cert_chain_ok() {
        let root = load(include_bytes!("../tests/fixtures/gry-root.der"));
        let int_cert = load(include_bytes!("../tests/fixtures/gry-int.der"));
        let leaf = load(include_bytes!("../tests/fixtures/gry-leaf.der"));
        let anchors = [TrustAnchor::from_cert(root)];
        let result = validate_path(
            &[leaf, int_cert],
            &anchors,
            &policy_at(GRY_NOW),
            &EcdsaP256Verifier,
        )
        .expect("2-cert chain must validate");
        assert_eq!(result.anchor_index, 0);
        assert_eq!(result.depth, 1);
    }

    /// Multiple anchors: correct anchor is second in the slice.
    ///
    /// Expected: Ok(ValidatedPath { anchor_index: 1, depth: 0 })
    #[test]
    fn correct_anchor_index_when_multiple_anchors() {
        let p256 = load(include_bytes!("../tests/fixtures/ec-p256-sha256.der"));
        let rsa = load(include_bytes!("../tests/fixtures/rsa-pkcs1v15-sha256.der"));
        // First anchor is the RSA cert (wrong name and SPKI for the P-256 chain).
        // Second anchor matches.
        let anchors = [
            TrustAnchor::from_cert(rsa),
            TrustAnchor::from_cert(p256.clone()),
        ];
        let result = validate_path(&[p256], &anchors, &policy_at(GRY_NOW), &EcdsaP256Verifier)
            .expect("must find second anchor");
        assert_eq!(result.anchor_index, 1);
        assert_eq!(result.depth, 0);
    }

    /// Empty chain returns NoTrustedPath.
    #[test]
    fn empty_chain_returns_error() {
        let anchors = [TrustAnchor::from_cert(load(include_bytes!(
            "../tests/fixtures/ec-p256-sha256.der"
        )))];
        assert!(
            matches!(
                validate_path(&[], &anchors, &policy_at(GRY_NOW), &EcdsaP256Verifier),
                Err(Error::NoTrustedPath)
            ),
            "empty chain must fail"
        );
    }

    /// path_too_long: vxf chain [leaf, int] with max_path_len = 0.
    ///
    /// chain.len()=2 → 1 intermediate. 1 > max_path_len(0) → PathTooLong.
    #[test]
    fn path_too_long_returns_error() {
        let root = load(include_bytes!("../tests/fixtures/vxf-root.der"));
        let int_cert = load(include_bytes!("../tests/fixtures/vxf-int.der"));
        let leaf = load(include_bytes!("../tests/fixtures/vxf-leaf.der"));
        let anchors = [TrustAnchor::from_cert(root)];
        let policy = ValidationPolicy {
            current_time_unix: GRY_NOW,
            max_path_len: 0,
            ..Default::default()
        };
        assert!(
            matches!(
                validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier),
                Err(Error::PathTooLong)
            ),
            "1 intermediate with max_path_len=0 must return PathTooLong"
        );
    }

    /// no_trusted_path: vxf chain presented to an unrelated anchor (gry-root).
    ///
    /// vxf's last cert issuer name does not match gry-root's subject name.
    #[test]
    fn no_trusted_path_unrelated_anchor_returns_error() {
        let gry_root = load(include_bytes!("../tests/fixtures/gry-root.der"));
        let vxf_int = load(include_bytes!("../tests/fixtures/vxf-int.der"));
        let vxf_leaf = load(include_bytes!("../tests/fixtures/vxf-leaf.der"));
        let anchors = [TrustAnchor::from_cert(gry_root)];
        assert!(
            matches!(
                validate_path(
                    &[vxf_leaf, vxf_int],
                    &anchors,
                    &policy_at(GRY_NOW),
                    &EcdsaP256Verifier
                ),
                Err(Error::NoTrustedPath)
            ),
            "vxf chain with gry anchor must return NoTrustedPath"
        );
    }

    /// oid_mismatch: outer signatureAlgorithm OID differs from inner TBS signature OID.
    ///
    /// Patch the SECOND occurrence of the ECDSA-with-SHA256 OID bytes in vxf-leaf.der
    /// to ECDSA-with-SHA384. The inner TBS.signature remains SHA256.
    /// check_oid_consistency detects this → MalformedCertificate { index: 0 }.
    ///
    /// Oracle: RFC 5280 §4.1.1.2 requires outer and inner AlgorithmIdentifiers to be identical.
    #[test]
    fn oid_mismatch_outer_returns_malformed_certificate() {
        let mut leaf_der = include_bytes!("../tests/fixtures/vxf-leaf.der").to_vec();
        // ECDSA-with-SHA256 OID content bytes: 1.2.840.10045.4.3.2
        let oid_sha256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
        // ECDSA-with-SHA384 OID content bytes: 1.2.840.10045.4.3.3 (same length, last byte differs)
        let oid_sha384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
        // In Certificate DER the inner TBS.signature OID appears FIRST (inside TBSCertificate)
        // and the outer signatureAlgorithm OID appears SECOND (after TBSCertificate). Patching
        // only the second occurrence changes the outer OID while leaving the inner intact.
        let first = leaf_der
            .windows(8)
            .position(|w| w == oid_sha256)
            .expect("inner SHA256 OID must be present in vxf-leaf.der");
        let second = leaf_der[first + 8..]
            .windows(8)
            .position(|w| w == oid_sha256)
            .map(|p| first + 8 + p)
            .expect("outer SHA256 OID must be present in vxf-leaf.der");
        leaf_der[second..second + 8].copy_from_slice(oid_sha384);
        let leaf = Certificate::from_der(&leaf_der).expect("patched DER must parse");
        assert_ne!(
            leaf.signature_algorithm, leaf.tbs_certificate.signature,
            "outer/inner OIDs must differ after patch"
        );
        let int_cert = load(include_bytes!("../tests/fixtures/vxf-int.der"));
        let root = load(include_bytes!("../tests/fixtures/vxf-root.der"));
        let anchors = [TrustAnchor::from_cert(root)];
        assert!(
            matches!(
                validate_path(
                    &[leaf, int_cert],
                    &anchors,
                    &policy_at(GRY_NOW),
                    &EcdsaP256Verifier
                ),
                Err(Error::MalformedCertificate { index: 0 })
            ),
            "outer/inner OID mismatch must return MalformedCertificate {{ index: 0 }}"
        );
    }

    /// intermediate_not_ca: nca-int has no BasicConstraints extension.
    ///
    /// Oracle: pyca/cryptography — nca-int built without any extensions.
    /// cert_is_ca(nca-int) returns None → NotCA { index: 1 }.
    #[test]
    fn intermediate_not_ca_returns_not_ca() {
        let root = load(include_bytes!("../tests/fixtures/nca-root.der"));
        let int_cert = load(include_bytes!("../tests/fixtures/nca-int.der"));
        let leaf = load(include_bytes!("../tests/fixtures/nca-leaf.der"));
        let anchors = [TrustAnchor::from_cert(root)];
        assert!(
            matches!(
                validate_path(
                    &[leaf, int_cert],
                    &anchors,
                    &policy_at(GRY_NOW),
                    &EcdsaP256Verifier
                ),
                Err(Error::NotCA { index: 1 })
            ),
            "intermediate without BasicConstraints CA flag must return NotCA {{ index: 1 }}"
        );
    }

    /// key_usage_missing_cert_sign: kuf-int has KeyUsage with digitalSignature only.
    ///
    /// Oracle: pyca/cryptography — kuf-int KeyUsage.keyCertSign = False.
    /// Default policy has enforce_key_usage = true; chain_walk checks at i=1.
    #[test]
    fn key_usage_missing_cert_sign_returns_error() {
        let root = load(include_bytes!("../tests/fixtures/kuf-root.der"));
        let int_cert = load(include_bytes!("../tests/fixtures/kuf-int.der"));
        let leaf = load(include_bytes!("../tests/fixtures/kuf-leaf.der"));
        let anchors = [TrustAnchor::from_cert(root)];
        assert!(
            matches!(
                validate_path(&[leaf, int_cert], &anchors, &policy_at(GRY_NOW), &EcdsaP256Verifier),
                Err(Error::KeyUsageMissing { index: 1 })
            ),
            "intermediate with KeyUsage but no keyCertSign must return KeyUsageMissing {{ index: 1 }}"
        );
    }

    /// absent_key_usage_intermediate_accepted: nku-int has NO KeyUsage extension at all.
    ///
    /// RFC 5280 §6.1.4(n): "If a KeyUsage extension is **present**, verify that the
    /// keyCertSign bit is set." Absent KeyUsage must not be rejected by enforce_key_usage.
    ///
    /// Oracle: pyca/cryptography — nku-int has only BasicConstraints (OID 2.5.29.19),
    /// no KeyUsage extension.
    #[test]
    fn absent_key_usage_intermediate_accepted() {
        let root = load(include_bytes!("../tests/fixtures/nku-root.der"));
        let int_cert = load(include_bytes!("../tests/fixtures/nku-int.der"));
        let leaf = load(include_bytes!("../tests/fixtures/nku-leaf.der"));
        let anchors = [TrustAnchor::from_cert(root)];
        // Default policy has enforce_key_usage = true.
        // nku-int has no KeyUsage — must NOT trigger KeyUsageMissing per RFC 5280 §6.1.4(n).
        let now: u64 = 1_720_000_000; // 2024-07-03, within nku-int validity (2024-2030)
        let mut policy = ValidationPolicy::default();
        policy.current_time_unix = now;
        validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier)
            .expect("intermediate with absent KeyUsage must be accepted when enforce_key_usage=true");
    }

    /// Leaf with critical ExtendedKeyUsage → validate_path must accept it.
    ///
    /// EKU is in HANDLED_CRITICAL_OIDS; its value is not inspected.
    /// Oracle: pyca/cryptography — eku-critical-self-signed.der, critical=True, serverAuth.
    #[test]
    fn critical_eku_accepted() {
        let cert = load(include_bytes!(
            "../tests/fixtures/eku-critical-self-signed.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        validate_path(&[cert], &anchors, &policy_at(GRY_NOW), &EcdsaP256Verifier)
            .expect("cert with critical EKU must be accepted");
    }

    /// Security test: anchor with matching name but wrong SPKI must be rejected.
    ///
    /// Guards against a name-collision attack: an attacker who creates a root cert
    /// with the same DN as a trusted anchor but a different key must not be accepted.
    /// The self-issued SPKI guard in validate_path catches this.
    #[test]
    fn forged_anchor_name_match_spki_mismatch_rejected() {
        use der::Decode as _;
        let p256 = Certificate::from_der(include_bytes!("../tests/fixtures/ec-p256-sha256.der"))
            .expect("parse P-256 cert");
        let rsa =
            Certificate::from_der(include_bytes!("../tests/fixtures/rsa-pkcs1v15-sha256.der"))
                .expect("parse RSA cert");
        // Forged anchor: P-256 cert's subject name + RSA cert's SPKI.
        let forged = TrustAnchor::new(
            p256.tbs_certificate.subject.clone(),
            rsa.tbs_certificate.subject_public_key_info.clone(),
        );
        let anchors = [forged];
        assert!(
            matches!(
                validate_path(&[p256], &anchors, &policy_at(GRY_NOW), &EcdsaP256Verifier),
                Err(Error::NoTrustedPath)
            ),
            "anchor with matching name but wrong SPKI must return NoTrustedPath"
        );
    }
}

// PKIX-vxf + PKIX-gry: chain_walk tests require the p256 feature.
#[cfg(all(test, feature = "p256"))]
mod tests_chain_walk {
    use super::*;
    use der::Decode;

    // Fixtures (PKIX-vxf):
    //   vxf-root.der — self-signed root CA, CN=PKIX-vxf-root  (P-256)
    //   vxf-int.der  — intermediate CA, CN=PKIX-vxf-int, signed by vxf-root
    //   vxf-leaf.der — leaf cert, CN=PKIX-vxf-leaf, signed by vxf-int
    //   chk-root.der / chk-int.der / chk-leaf-wrong-issuer.der — ChainBroken test chain
    //
    // Fixtures (PKIX-gry):
    //   gry-root.der                  — root CA, CN=PKIX-gry-root (P-256)
    //   gry-int.der                   — intermediate CA, CN=PKIX-gry-int, valid 2026-2036
    //   gry-leaf.der                  — leaf, CN=PKIX-gry-leaf, valid 2026-2027 (short-lived)
    //   gry-leaf-unknown-crit.der     — leaf with unknown critical extension
    //
    // Unix timestamp constants for gry validity tests:
    //   GRY_NOW     = 1780272000  (2026-06-01, all gry certs valid)
    //   GRY_EXPIRED = 1830384000  (2028-01-02, gry-leaf expired; gry-int still valid)
    //   GRY_NOTYET  = 0           (1970-01-01, all gry certs not-yet-valid)
    //
    // Oracle:
    //   vxf chain: openssl verify -CAfile vxf-root.pem -untrusted vxf-int.pem vxf-leaf.pem → OK
    //   gry chain: pyca/cryptography; chain verifies at GRY_NOW
    //   chk-leaf-wrong-issuer: signature valid under chk-int key (pyca); issuer = PKIX-WRONG-ISSUER by design

    const GRY_NOW: u64 = 1_780_272_000;
    const GRY_EXPIRED: u64 = 1_830_384_000;
    const GRY_NOTYET: u64 = 0;

    fn load(bytes: &[u8]) -> Certificate {
        Certificate::from_der(bytes).expect("parse cert")
    }

    fn policy_at(t: u64) -> ValidationPolicy {
        ValidationPolicy {
            current_time_unix: t,
            ..Default::default()
        }
    }

    /// 1-cert chain: self-signed P-256 cert as both chain and anchor.
    #[test]
    fn single_cert_chain_ok() {
        let p256 = load(include_bytes!("../tests/fixtures/ec-p256-sha256.der"));
        let policy = policy_at(GRY_NOW);
        let anchor = TrustAnchor::from_cert(p256.clone());
        chain_walk(&[p256], &anchor, &policy, &EcdsaP256Verifier)
            .expect("1-cert chain must pass chain_walk");
    }

    /// 2-cert chain (leaf + intermediate) with root as anchor.
    ///
    /// Oracle: openssl verify -CAfile vxf-root.pem -untrusted vxf-int.pem vxf-leaf.pem → OK
    #[test]
    fn two_cert_chain_ok() {
        let root = load(include_bytes!("../tests/fixtures/vxf-root.der"));
        let int_cert = load(include_bytes!("../tests/fixtures/vxf-int.der"));
        let leaf = load(include_bytes!("../tests/fixtures/vxf-leaf.der"));
        let policy = policy_at(GRY_NOW);
        let anchor = TrustAnchor::from_cert(root);
        chain_walk(&[leaf, int_cert], &anchor, &policy, &EcdsaP256Verifier)
            .expect("2-cert chain must pass chain_walk");
    }

    /// Leaf with corrupted signature — last byte flipped.
    ///
    /// The DER structure remains valid; only the BIT STRING content is wrong.
    /// Expect SignatureInvalid at chain index 0.
    #[test]
    fn corrupted_signature_returns_signature_invalid() {
        let mut leaf_der = include_bytes!("../tests/fixtures/vxf-leaf.der").to_vec();
        *leaf_der.last_mut().unwrap() ^= 0xFF;
        let leaf = Certificate::from_der(&leaf_der).expect("parse still succeeds after bit flip");
        let int_cert = load(include_bytes!("../tests/fixtures/vxf-int.der"));
        let anchor = TrustAnchor::from_cert(load(include_bytes!("../tests/fixtures/vxf-root.der")));
        let policy = policy_at(GRY_NOW);
        assert!(
            matches!(
                chain_walk(&[leaf, int_cert], &anchor, &policy, &EcdsaP256Verifier),
                Err(Error::SignatureInvalid { index: 0 })
            ),
            "corrupted leaf signature must return SignatureInvalid {{ index: 0 }}"
        );
    }

    /// Chain where the leaf's issuer field does not match the intermediate's subject.
    ///
    /// Oracle: chk-leaf-wrong-issuer was signed by chk-int's private key
    /// (signature IS valid), but its issuer field = "PKIX-WRONG-ISSUER" by design.
    #[test]
    fn wrong_issuer_name_returns_chain_broken() {
        let root = load(include_bytes!("../tests/fixtures/chk-root.der"));
        let int_cert = load(include_bytes!("../tests/fixtures/chk-int.der"));
        let leaf_wrong = load(include_bytes!(
            "../tests/fixtures/chk-leaf-wrong-issuer.der"
        ));
        let policy = policy_at(GRY_NOW);
        let anchor = TrustAnchor::from_cert(root);
        assert!(
            matches!(
                chain_walk(
                    &[leaf_wrong, int_cert],
                    &anchor,
                    &policy,
                    &EcdsaP256Verifier
                ),
                Err(Error::ChainBroken { index: 0 })
            ),
            "leaf with wrong issuer must return ChainBroken {{ index: 0 }}"
        );
    }

    // --- PKIX-gry per-cert check tests ---

    /// Expired leaf cert → ValidityPeriod at index 0.
    ///
    /// Oracle: gry-leaf.der has notAfter=2027-01-01; GRY_EXPIRED=2028-01-02.
    /// gry-int.der has notAfter=2036-01-01, which is still valid at GRY_EXPIRED.
    /// Reverse walk: i=1 (gry-int) passes validity, then i=0 (gry-leaf) fails.
    #[test]
    fn expired_leaf_returns_validity_period() {
        let root = load(include_bytes!("../tests/fixtures/gry-root.der"));
        let int_cert = load(include_bytes!("../tests/fixtures/gry-int.der"));
        let leaf = load(include_bytes!("../tests/fixtures/gry-leaf.der"));
        let policy = policy_at(GRY_EXPIRED);
        let anchor = TrustAnchor::from_cert(root);
        assert!(
            matches!(
                chain_walk(&[leaf, int_cert], &anchor, &policy, &EcdsaP256Verifier),
                Err(Error::ValidityPeriod { index: 0 })
            ),
            "expired leaf must return ValidityPeriod {{ index: 0 }}"
        );
    }

    /// Not-yet-valid intermediate → ValidityPeriod at index 1.
    ///
    /// Oracle: gry-int.der has notBefore=2026-01-01; GRY_NOTYET=0 (1970-01-01).
    /// Reverse walk processes chain[1] (gry-int) first; it is not yet valid at time 0.
    #[test]
    fn notyet_valid_intermediate_returns_validity_period() {
        let root = load(include_bytes!("../tests/fixtures/gry-root.der"));
        let int_cert = load(include_bytes!("../tests/fixtures/gry-int.der"));
        let leaf = load(include_bytes!("../tests/fixtures/gry-leaf.der"));
        let policy = policy_at(GRY_NOTYET);
        let anchor = TrustAnchor::from_cert(root);
        assert!(
            matches!(
                chain_walk(&[leaf, int_cert], &anchor, &policy, &EcdsaP256Verifier),
                Err(Error::ValidityPeriod { index: 1 })
            ),
            "not-yet-valid intermediate must return ValidityPeriod {{ index: 1 }}"
        );
    }

    /// Leaf with unknown critical extension → UnhandledCriticalExtension at index 0.
    ///
    /// Oracle: gry-leaf-unknown-crit.der was generated with OID 1.3.6.1.5.5.7.99.99 critical=true
    /// (not in HANDLED_CRITICAL_OIDS) using pyca/cryptography.
    #[test]
    fn unknown_critical_extension_returns_unhandled() {
        let root = load(include_bytes!("../tests/fixtures/gry-root.der"));
        let int_cert = load(include_bytes!("../tests/fixtures/gry-int.der"));
        let leaf_unk = load(include_bytes!(
            "../tests/fixtures/gry-leaf-unknown-crit.der"
        ));
        let policy = policy_at(GRY_NOW);
        let anchor = TrustAnchor::from_cert(root);
        assert!(
            matches!(
                chain_walk(&[leaf_unk, int_cert], &anchor, &policy, &EcdsaP256Verifier),
                Err(Error::UnhandledCriticalExtension { index: 0 })
            ),
            "unknown critical ext must return UnhandledCriticalExtension {{ index: 0 }}"
        );
    }
}

// ---------------------------------------------------------------------------
// Tests: ValidationPolicy profile-enforcement fields (PKIX-ken.1.9–1.13)
// ---------------------------------------------------------------------------
//
// Fixtures: pkix-path/tests/fixtures/policy-checks/
//   root-p256.der, int-p256.der — P-256 CA chain (ecdsa-sha256)
//   leaf-p256-365d-san-eku.der  — 365-day leaf, SAN=DNS:test.example.com, EKU=serverAuth
//   leaf-p256-400d-san-eku.der  — 400-day leaf, SAN, EKU=serverAuth
//   leaf-p256-365d-no-san.der   — 365-day leaf, no SAN extension
//   leaf-p256-365d-no-eku.der   — 365-day leaf, SAN, no EKU extension
//   leaf-p256-365d-wrong-eku.der— 365-day leaf, SAN, EKU=emailProtection only
//   root-rsa2048.der, int-rsa2048.der — RSA-2048 CA chain (sha256WithRSAEncryption)
//   leaf-rsa2048-365d-san-eku.der — RSA-2048 leaf, SAN, EKU=serverAuth
//   leaf-rsa1024-365d-san-eku.der — RSA-1024 leaf, SAN, EKU=serverAuth
//
// Oracle: pkix-path/tests/fixtures/policy-checks/gen.py (pyca/cryptography)
// Chain verification: openssl verify passed for P-256 and RSA-2048 happy paths.
// Time constant: PC_NOW = 2026-06-01T00:00:00Z = 1_780_272_000 (unix)
//   All fixtures have NOT_BEFORE=2026-01-01, valid at PC_NOW.
//
// All tests require the p256 feature for P-256 chain tests, and rsa for RSA chain tests.
//
// The P-256 chain uses the module-level const directly; RSA chain tests live inside
// a separate rsa-feature-gated block so clippy does not warn about unused imports.

#[cfg(all(test, feature = "p256"))]
mod tests_policy_fields {
    use super::*;
    use der::Decode;

    // GRY_NOW is also the test time for these fixtures (2026-06-01T00:00:00Z).
    const PC_NOW: u64 = 1_780_272_000;

    // OID constants — values from const_oid spec, NOT derived from the code under test.
    // ecdsa-with-SHA256: 1.2.840.10045.4.3.2  (RFC 5912 §6)
    const ECDSA_SHA256_OID: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
    // sha256WithRSAEncryption: 1.2.840.113549.1.1.11  (RFC 5912 §2)
    const RSA_SHA256_OID: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
    // id-kp-serverAuth: 1.3.6.1.5.5.7.3.1  (RFC 5280 §4.2.1.12)
    const ID_KP_SERVER_AUTH: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
    // id-kp-emailProtection: 1.3.6.1.5.5.7.3.4  (RFC 5280 §4.2.1.12)
    const ID_KP_EMAIL_PROTECTION: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.4");

    fn load(bytes: &[u8]) -> Certificate {
        Certificate::from_der(bytes).expect("valid DER fixture")
    }

    // -----------------------------------------------------------------------
    // max_validity_secs (PKIX-ken.1.9)
    // -----------------------------------------------------------------------

    /// Oracle: all certs in the chain have validity ≤ 3652 days (10-year root/int,
    /// 365-day leaf). A cap of 4000 days allows all of them through.
    #[test]
    fn max_validity_passes_when_cert_within_limit() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        // 4000-day cap: root/int have ~3652 days, leaf has 365 days — all within limit.
        policy.max_validity_secs = Some(4_000 * 86_400);
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier)
            .expect("all certs within 4000-day cap should validate");
    }

    /// Oracle: root-p256.der and int-p256.der each have ~3652-day validity
    /// (NOT_BEFORE=2026-01-01, NOT_AFTER=2036-01-01 from gen.py).
    /// A cap of 400 days forces `ValidityPeriodExceedsMax` on the root (checked first
    /// by chain_walk which iterates from high index to low).
    ///
    /// Note: the check applies to every cert in the chain, not just the leaf.
    /// The root cert (highest index) is checked first and produces the error.
    #[test]
    fn max_validity_fails_when_cert_exceeds_limit() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        // 400-day cap: root/int have 3652-day validity → ValidityPeriodExceedsMax.
        // Wildcard index because the root (highest-index cert) is checked first.
        policy.max_validity_secs = Some(400 * 86_400);
        let anchors = [TrustAnchor::from_cert(root)];
        assert!(
            matches!(
                validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier),
                Err(Error::ValidityPeriodExceedsMax { .. })
            ),
            "certs with 3652-day validity over 400-day cap must return ValidityPeriodExceedsMax"
        );
    }

    /// Isolates the leaf-only failure: use a 1-cert self-issued chain where
    /// the cert acts as both leaf and anchor. The 400-day cert fails a 398-day cap.
    ///
    /// Oracle: leaf-p256-400d-san-eku.der has notAfter-notBefore = 400 days = 34,560,000 s.
    /// 400 days > 398 days → ValidityPeriodExceedsMax { index: 0 }.
    #[test]
    fn max_validity_fails_at_leaf_index_zero() {
        // Use a single self-signed cert as both chain[0] and anchor so there is only
        // one cert in the chain, making index 0 the only possible failure point.
        // leaf-p256-400d-san-eku.der is NOT self-signed, so we use a known self-signed
        // cert from the existing fixture set (ec-p256-sha256.der) which has a long
        // validity, then set max to 1 day to force failure at index 0.
        let cert = Certificate::from_der(include_bytes!("../tests/fixtures/ec-p256-sha256.der"))
            .expect("parse ec-p256-sha256.der");
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        let mut policy = ValidationPolicy::new(1_780_272_000); // PC_NOW: 2026-06-01
                                                               // 1-day cap: the cert has multi-year validity → fails at index 0.
        policy.max_validity_secs = Some(86_400);
        assert!(
            matches!(
                validate_path(&[cert], &anchors, &policy, &EcdsaP256Verifier),
                Err(Error::ValidityPeriodExceedsMax { index: 0 })
            ),
            "1-cert chain: long-validity cert with 1-day cap must return ValidityPeriodExceedsMax {{ index: 0 }}"
        );
    }

    /// Oracle: None = unconstrained, any validity length is accepted.
    #[test]
    fn max_validity_none_is_unconstrained() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-400d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.max_validity_secs = None; // default, but explicit for documentation
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier)
            .expect("None cap must accept any validity length");
    }

    // -----------------------------------------------------------------------
    // allowed_signature_algs (PKIX-ken.1.10)
    // -----------------------------------------------------------------------

    /// Oracle: P-256 chain uses ecdsa-with-SHA256; allowlist contains that OID.
    #[test]
    fn alg_allowlist_passes_when_oid_in_list() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.allowed_signature_algs = Some(vec![ECDSA_SHA256_OID]);
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier)
            .expect("ECDSA-SHA256 chain with ECDSA-SHA256 allowlist should pass");
    }

    /// Oracle: P-256 chain uses ecdsa-sha256; allowlist contains only RSA-sha256.
    /// chain_walk walks highest index first: leaf=[0], int=[1], root=[2].
    /// For a 3-cert chain, the root-adjacent cert is at index 2 in the slice.
    /// chain_walk iterates i from (chain.len()-1) down to 0, so i=2 (root) is checked
    /// first and fails with AlgorithmNotAllowed { index: 2 }.
    #[test]
    fn alg_allowlist_fails_when_oid_not_in_list() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        // Only RSA allowed, but chain uses ECDSA.
        policy.allowed_signature_algs = Some(vec![RSA_SHA256_OID]);
        let anchors = [TrustAnchor::from_cert(root)];
        assert!(
            matches!(
                validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier),
                Err(Error::AlgorithmNotAllowed { .. })
            ),
            "ECDSA chain with RSA-only allowlist must return AlgorithmNotAllowed"
        );
    }

    /// Oracle: None = unconstrained, any algorithm is accepted.
    #[test]
    fn alg_allowlist_none_is_unconstrained() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.allowed_signature_algs = None; // default
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier)
            .expect("None allowlist must accept any algorithm");
    }

    // -----------------------------------------------------------------------
    // require_subject_alt_name (PKIX-ken.1.12)
    // -----------------------------------------------------------------------

    /// Oracle: leaf-p256-365d-san-eku.der has SAN=DNS:test.example.com.
    #[test]
    fn require_san_passes_when_san_present() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.require_subject_alt_name = true;
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier)
            .expect("leaf with SAN must pass require_subject_alt_name=true");
    }

    /// Oracle: leaf-p256-365d-no-san.der has no SAN extension.
    #[test]
    fn require_san_fails_when_san_absent() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-no-san.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.require_subject_alt_name = true;
        let anchors = [TrustAnchor::from_cert(root)];
        assert!(
            matches!(
                validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier),
                Err(Error::MissingSan)
            ),
            "leaf without SAN must return MissingSan when require_subject_alt_name=true"
        );
    }

    /// Oracle: false = default = no SAN requirement; missing SAN is not an error.
    #[test]
    fn require_san_false_does_not_fail_on_missing_san() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-no-san.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.require_subject_alt_name = false; // default, explicit for documentation
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier)
            .expect("require_subject_alt_name=false must not fail on missing SAN");
    }

    /// Regression guard for the i == 0 guard in chain_walk.
    ///
    /// int-p256.der has no SAN extension. With require_subject_alt_name=true,
    /// the check MUST NOT fail on the intermediate (i == 1). Only the leaf
    /// (i == 0) is checked.
    ///
    /// Oracle: openssl x509 -inform DER -in int-p256.der -text -noout | grep -i alt
    /// → empty output; int-p256.der has no SAN. Confirmed during fixture generation.
    #[test]
    fn require_san_only_checks_leaf_not_intermediates() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        // The leaf HAS a SAN; the intermediate does NOT.
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.require_subject_alt_name = true;
        let anchors = [TrustAnchor::from_cert(root)];
        // Must pass: the SAN-less intermediate is not checked, only the leaf.
        validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier)
            .expect("i==0 guard must ensure only the leaf is checked for SAN presence");
    }

    // -----------------------------------------------------------------------
    // required_leaf_eku (PKIX-ken.1.13)
    // -----------------------------------------------------------------------

    /// Oracle: leaf-p256-365d-san-eku.der has EKU=serverAuth (1.3.6.1.5.5.7.3.1).
    #[test]
    fn required_eku_passes_when_all_oids_present() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.required_leaf_eku = Some(vec![ID_KP_SERVER_AUTH]);
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier)
            .expect("leaf with serverAuth EKU must pass required_leaf_eku=[serverAuth]");
    }

    /// Oracle: leaf-p256-365d-no-eku.der has no EKU extension.
    /// required_leaf_eku=Some([serverAuth]) with absent EKU → MissingEku.
    #[test]
    fn required_eku_fails_when_eku_extension_absent() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-no-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.required_leaf_eku = Some(vec![ID_KP_SERVER_AUTH]);
        let anchors = [TrustAnchor::from_cert(root)];
        assert!(
            matches!(
                validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier),
                Err(Error::MissingEku)
            ),
            "leaf without EKU extension must return MissingEku when an EKU OID is required"
        );
    }

    /// Oracle: leaf-p256-365d-wrong-eku.der has EKU=emailProtection only, not serverAuth.
    #[test]
    fn required_eku_fails_when_required_oid_not_in_list() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-wrong-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        // Requires serverAuth; leaf only has emailProtection.
        policy.required_leaf_eku = Some(vec![ID_KP_SERVER_AUTH]);
        let anchors = [TrustAnchor::from_cert(root)];
        assert!(
            matches!(
                validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier),
                Err(Error::MissingEku)
            ),
            "leaf with wrong EKU must return MissingEku when required OID is absent"
        );
    }

    /// Oracle: None = no EKU requirement; missing EKU is not an error.
    #[test]
    fn required_eku_none_is_unconstrained() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-no-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.required_leaf_eku = None; // default
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier)
            .expect("None required_leaf_eku must accept leaf with no EKU");
    }

    /// Oracle: Some([]) = require zero OIDs → trivially passes regardless of EKU content.
    #[test]
    fn required_eku_empty_vec_is_unconstrained() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-no-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        // Empty vec: Some([]) requires zero OIDs → always passes.
        policy.required_leaf_eku = Some(vec![]);
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier)
            .expect("Some([]) required_leaf_eku (empty) must accept any EKU configuration");
    }

    /// Verify that emailProtection in required_leaf_eku does NOT match serverAuth in the cert.
    /// This guards against a hypothetical relaxed OID comparison bug.
    #[test]
    fn required_eku_emailprotection_does_not_match_serverauth() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        // Require emailProtection; leaf only has serverAuth.
        policy.required_leaf_eku = Some(vec![ID_KP_EMAIL_PROTECTION]);
        let anchors = [TrustAnchor::from_cert(root)];
        assert!(
            matches!(
                validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier),
                Err(Error::MissingEku)
            ),
            "OID comparison must be exact; emailProtection must not match serverAuth"
        );
    }
}

// RSA-specific policy field tests — gated on the rsa feature.
#[cfg(all(test, feature = "p256", feature = "rsa"))]
mod tests_policy_fields_rsa {
    use super::*;
    use der::Decode;

    const PC_NOW: u64 = 1_780_272_000;

    // sha256WithRSAEncryption: 1.2.840.113549.1.1.11  (RFC 5912 §2)
    const RSA_SHA256_OID: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
    // ecdsa-with-SHA256: 1.2.840.10045.4.3.2  (RFC 5912 §6)
    const ECDSA_SHA256_OID: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
    // id-kp-serverAuth: 1.3.6.1.5.5.7.3.1
    const ID_KP_SERVER_AUTH: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");

    fn load(bytes: &[u8]) -> Certificate {
        Certificate::from_der(bytes).expect("valid DER fixture")
    }

    // -----------------------------------------------------------------------
    // min_rsa_key_bits helper unit tests (PKIX-ken.1.11)
    // -----------------------------------------------------------------------

    /// Direct unit test of rsa_public_key_bits helper.
    /// Oracle: openssl x509 -inform DER -in leaf-rsa2048.der -text -noout | grep 'Public-Key'
    /// → Public-Key: (2048 bit)
    #[test]
    fn rsa_key_bits_correct_for_2048_key() {
        let cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-rsa2048-365d-san-eku.der"
        ));
        let result = rsa_public_key_bits(&cert.tbs_certificate.subject_public_key_info);
        assert_eq!(
            result,
            Some(2048),
            "RSA-2048 key must return Some(2048) from rsa_public_key_bits"
        );
    }

    /// Direct unit test of rsa_public_key_bits helper.
    /// Oracle: openssl x509 -inform DER -in leaf-rsa1024.der -text -noout | grep 'Public-Key'
    /// → Public-Key: (1024 bit)
    #[test]
    fn rsa_key_bits_correct_for_1024_key() {
        let cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-rsa1024-365d-san-eku.der"
        ));
        let result = rsa_public_key_bits(&cert.tbs_certificate.subject_public_key_info);
        assert_eq!(
            result,
            Some(1024),
            "RSA-1024 key must return Some(1024) from rsa_public_key_bits"
        );
    }

    /// Direct unit test of rsa_public_key_bits helper.
    /// P-256 key is not RSA; must return None.
    #[test]
    fn rsa_key_bits_none_for_ec_key() {
        let cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-san-eku.der"
        ));
        let result = rsa_public_key_bits(&cert.tbs_certificate.subject_public_key_info);
        assert_eq!(
            result, None,
            "EC key must return None from rsa_public_key_bits (not RSA)"
        );
    }

    // -----------------------------------------------------------------------
    // min_rsa_key_bits validate_path tests (PKIX-ken.1.11)
    // -----------------------------------------------------------------------

    /// Oracle: leaf-rsa2048-365d-san-eku.der has RSA-2048 leaf.
    /// 2048 >= 2048 → passes.
    #[test]
    fn min_rsa_key_bits_passes_when_key_meets_limit() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-rsa2048.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-rsa2048.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-rsa2048-365d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.min_rsa_key_bits = Some(2048);
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(
            &[leaf, int_cert],
            &anchors,
            &policy,
            &RsaPkcs1v15Sha256Verifier,
        )
        .expect("RSA-2048 leaf with min=2048 should pass");
    }

    /// Oracle: leaf-rsa1024-365d-san-eku.der has RSA-1024 leaf.
    /// 1024 < 2048 → KeyTooSmall { index: 0 }.
    #[test]
    fn min_rsa_key_bits_fails_when_key_too_small() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-rsa2048.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-rsa2048.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-rsa1024-365d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.min_rsa_key_bits = Some(2048);
        let anchors = [TrustAnchor::from_cert(root)];
        assert!(
            matches!(
                validate_path(
                    &[leaf, int_cert],
                    &anchors,
                    &policy,
                    &RsaPkcs1v15Sha256Verifier
                ),
                Err(Error::KeyTooSmall { index: 0 })
            ),
            "RSA-1024 leaf with min=2048 must return KeyTooSmall {{ index: 0 }}"
        );
    }

    /// Oracle: None = unconstrained; RSA-1024 leaf passes with no key size restriction.
    #[test]
    fn min_rsa_key_bits_none_is_unconstrained() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-rsa2048.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-rsa2048.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-rsa1024-365d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.min_rsa_key_bits = None; // default
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(
            &[leaf, int_cert],
            &anchors,
            &policy,
            &RsaPkcs1v15Sha256Verifier,
        )
        .expect("None min_rsa_key_bits must accept RSA-1024 leaf");
    }

    /// EC key must not be affected by min_rsa_key_bits regardless of the value.
    /// Oracle: P-256 key is not RSA; rsa_public_key_bits returns None → check skipped.
    #[test]
    fn min_rsa_key_bits_ec_key_passes_unconditionally() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        // Extremely high floor — would reject any RSA key, but P-256 is not RSA.
        policy.min_rsa_key_bits = Some(16384);
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier)
            .expect("EC key must not be affected by min_rsa_key_bits");
    }

    // -----------------------------------------------------------------------
    // allowed_signature_algs: RSA chain test (PKIX-ken.1.10)
    // -----------------------------------------------------------------------

    /// Oracle: RSA chain uses sha256WithRSAEncryption; ECDSA-only allowlist must reject it.
    #[test]
    fn alg_allowlist_fails_on_rsa_chain_when_only_ecdsa_allowed() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-rsa2048.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-rsa2048.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-rsa2048-365d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        // Only ECDSA allowed; RSA chain must fail.
        policy.allowed_signature_algs = Some(vec![ECDSA_SHA256_OID]);
        let anchors = [TrustAnchor::from_cert(root)];
        assert!(
            matches!(
                validate_path(
                    &[leaf, int_cert],
                    &anchors,
                    &policy,
                    &RsaPkcs1v15Sha256Verifier
                ),
                Err(Error::AlgorithmNotAllowed { .. })
            ),
            "RSA chain with ECDSA-only allowlist must return AlgorithmNotAllowed"
        );
    }

    /// Oracle: RSA chain with RSA in allowlist must pass.
    #[test]
    fn alg_allowlist_passes_for_rsa_chain() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-rsa2048.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-rsa2048.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-rsa2048-365d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.allowed_signature_algs = Some(vec![RSA_SHA256_OID]);
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(
            &[leaf, int_cert],
            &anchors,
            &policy,
            &RsaPkcs1v15Sha256Verifier,
        )
        .expect("RSA chain with RSA-SHA256 in allowlist should pass");
    }

    /// EKU tests for RSA chain are structurally identical to P-256; spot-check one.
    ///
    /// Oracle: leaf-rsa2048-365d-san-eku.der has EKU=serverAuth.
    #[test]
    fn required_eku_passes_for_rsa_chain() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-rsa2048.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-rsa2048.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-rsa2048-365d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.required_leaf_eku = Some(vec![ID_KP_SERVER_AUTH]);
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(
            &[leaf, int_cert],
            &anchors,
            &policy,
            &RsaPkcs1v15Sha256Verifier,
        )
        .expect("RSA leaf with serverAuth EKU must pass required_leaf_eku=[serverAuth]");
    }
}
