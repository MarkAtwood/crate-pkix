#![cfg_attr(not(feature = "std"), no_std)]
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

use der::Tagged;
use signature::Error as SignatureError;
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

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::SignatureInvalid { index } => {
                write!(f, "signature invalid at chain index {index}")
            }
            Error::ValidityPeriod { index } => {
                write!(f, "validity period check failed at chain index {index}")
            }
            Error::ChainBroken { index } => {
                write!(f, "issuer/subject linkage broken at chain index {index}")
            }
            Error::NoTrustedPath => write!(f, "no path to a trusted anchor"),
            Error::PathTooLong => write!(f, "path length exceeds maximum"),
            Error::NotCA { index } => write!(f, "certificate at index {index} is not a CA"),
            Error::KeyUsageMissing { index } => {
                write!(f, "keyCertSign missing at chain index {index}")
            }
            Error::UnhandledCriticalExtension { index } => {
                write!(f, "unhandled critical extension at chain index {index}")
            }
            Error::Der(e) => write!(f, "DER error: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Der(e) => Some(e),
            _ => None,
        }
    }
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
    /// - `message`      — DER-encoded TBSCertificate (the bytes that were signed)
    /// - `signature`    — raw signature bytes (BitString content, not the wrapper)
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
/// by definition.
pub struct TrustAnchor {
    /// The subject distinguished name of the trust anchor.
    pub subject: x509_cert::name::Name,
    /// The subject public key info of the trust anchor.
    pub subject_public_key_info: spki::SubjectPublicKeyInfoOwned,
}

impl TrustAnchor {
    /// Create a trust anchor from raw subject name and SPKI.
    pub fn new(
        subject: x509_cert::name::Name,
        subject_public_key_info: spki::SubjectPublicKeyInfoOwned,
    ) -> Self {
        Self {
            subject,
            subject_public_key_info,
        }
    }

    /// Extract subject name and SPKI from a certificate to create a trust anchor.
    ///
    /// This is the typical constructor when your trust store contains full
    /// self-signed root CA certificates.
    pub fn from_cert(cert: Certificate) -> Self {
        Self {
            subject: cert.tbs_certificate.subject,
            subject_public_key_info: cert.tbs_certificate.subject_public_key_info,
        }
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
    ///
    /// **Warning**: passing `u64::MAX` causes all `notAfter` checks to pass.
    /// This effectively disables expiry checking — only use it in contexts
    /// where you explicitly want permissive (clock-free) validation.
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
    // (1) Input guards: reject empty chain or anchors, check OID consistency.
    check_inputs(chain, anchors)?;
    check_oid_consistency(chain)?;

    // (2–5) Full per-cert walk: anchor matching, signatures, name linkage,
    //        validity, critical extensions, intermediate CA enforcement.
    let anchor_index = chain_walk(chain, anchors, policy, verifier)?;

    // (6) Return validated path descriptor.
    Ok(ValidatedPath {
        anchor_index,
        depth: chain.len().saturating_sub(1),
    })
}

// ---------------------------------------------------------------------------
// validate_path helpers — input guards and OID consistency (PKIX-6vu)
// ---------------------------------------------------------------------------


fn check_inputs(chain: &[Certificate], anchors: &[TrustAnchor]) -> Result<()> {
    if chain.is_empty() || anchors.is_empty() {
        return Err(Error::NoTrustedPath);
    }
    Ok(())
}

/// RFC 5280 §4.1.1.2: outer signatureAlgorithm must equal inner TBSCertificate.signature.
fn check_oid_consistency(chain: &[Certificate]) -> Result<()> {
    for (index, cert) in chain.iter().enumerate() {
        if cert.signature_algorithm != cert.tbs_certificate.signature {
            return Err(Error::SignatureInvalid { index });
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

/// OIDs of extensions that this implementation handles; all others, if critical, cause rejection.
const HANDLED_CRITICAL_OIDS: &[der::asn1::ObjectIdentifier] = &[
    OID_KEY_USAGE,
    OID_BASIC_CONSTRAINTS,
    OID_SUBJECT_ALT_NAME, // recognized but application-level; path validator ignores value
];

/// RFC 5280 §6.1.3(a)(3): reject any critical extension not in the handled set.
///
/// Returns `Ok(())` on success, or `Err(())` to signal the *type* of error —
/// the caller must inject the correct `index` when constructing `Error::UnhandledCriticalExtension`.
fn check_critical_extensions(cert: &Certificate) -> core::result::Result<(), ()> {
    if let Some(exts) = cert.tbs_certificate.extensions.as_ref() {
        for ext in exts.iter() {
            if ext.critical && !HANDLED_CRITICAL_OIDS.contains(&ext.extn_id) {
                return Err(());
            }
        }
    }
    Ok(())
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

    let exts = cert.tbs_certificate.extensions.as_ref()?;
    for ext in exts.iter() {
        if ext.extn_id == OID_KEY_USAGE {
            let ku = KeyUsage::from_der(ext.extn_value.as_bytes()).ok()?;
            return Some(ku.key_cert_sign());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// BasicConstraints extraction (PKIX-0q5)
// ---------------------------------------------------------------------------

/// Returns whether the certificate is a CA cert per BasicConstraints.
///
/// - `None`         — BasicConstraints absent (treated as cA=FALSE per RFC 5280)
/// - `Some(true)`   — BasicConstraints present and cA=TRUE
/// - `Some(false)`  — BasicConstraints present and cA=FALSE
fn cert_is_ca(cert: &Certificate) -> Option<bool> {
    use der::Decode;
    use x509_cert::ext::pkix::BasicConstraints;

    let exts = cert.tbs_certificate.extensions.as_ref()?;
    for ext in exts.iter() {
        if ext.extn_id == OID_BASIC_CONSTRAINTS {
            let bc = BasicConstraints::from_der(ext.extn_value.as_bytes()).ok()?;
            return Some(bc.ca);
        }
    }
    None
}

/// Returns the pathLenConstraint if present in BasicConstraints.
fn cert_path_len_constraint(cert: &Certificate) -> Option<u8> {
    use der::Decode;
    use x509_cert::ext::pkix::BasicConstraints;

    let exts = cert.tbs_certificate.extensions.as_ref()?;
    for ext in exts.iter() {
        if ext.extn_id == OID_BASIC_CONSTRAINTS {
            let bc = BasicConstraints::from_der(ext.extn_value.as_bytes()).ok()?;
            return bc.path_len_constraint;
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Validity period checker (PKIX-047)
// ---------------------------------------------------------------------------

/// Convert an `x509_cert::time::Time` to seconds since the Unix epoch.
fn time_to_unix_secs(t: &x509_cert::time::Time) -> u64 {
    t.to_unix_duration().as_secs()
}

/// RFC 5280 §6.1.3(a)(2): check notBefore ≤ now ≤ notAfter.
///
/// Returns `Ok(())` or `Err(())` — caller injects the chain index.
fn check_validity(cert: &Certificate, now_unix: u64) -> core::result::Result<(), ()> {
    let not_before = time_to_unix_secs(&cert.tbs_certificate.validity.not_before);
    let not_after = time_to_unix_secs(&cert.tbs_certificate.validity.not_after);
    if now_unix < not_before || now_unix > not_after {
        Err(())
    } else {
        Ok(())
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
        // For each AVA in a_rdn, find matching AVA in b_rdn (same OID, equal normalized value).
        for a_ava in a_avas.iter() {
            let found = b_avas.iter().any(|b_ava| {
                b_ava.oid == a_ava.oid && ava_values_match(&a_ava.value, &b_ava.value)
            });
            if !found {
                return false;
            }
        }
    }
    true
}

/// Compare two AttributeTypeAndValue values after RFC 4518 normalization.
fn ava_values_match(a: &der::Any, b: &der::Any) -> bool {
    let a_str = any_to_str_bytes(a);
    let b_str = any_to_str_bytes(b);

    match (a_str, b_str) {
        (Some(a_bytes), Some(b_bytes)) => normalized_eq(a_bytes, b_bytes),
        // Fall back to raw DER byte comparison if we can't decode as a string type.
        (None, None) => a.value() == b.value(),
        _ => false,
    }
}

/// Extract the string content bytes from a DirectoryString Any value.
/// Returns None if the tag is not a string type we handle.
fn any_to_str_bytes(a: &der::Any) -> Option<&[u8]> {
    use der::Tag;
    match a.tag() {
        Tag::Utf8String | Tag::PrintableString | Tag::Ia5String | Tag::VisibleString => {
            Some(a.value())
        }
        _ => None,
    }
}

/// Compare two ASCII byte slices after RFC 4518 whitespace normalization and case-folding.
///
/// Rules applied:
/// 1. ASCII letters: case-fold to lowercase
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
        let start = bytes
            .iter()
            .position(|&b| b != b' ')
            .unwrap_or(bytes.len());
        // Find end (skip trailing spaces).
        let end = bytes[start..]
            .iter()
            .rposition(|&b| b != b' ')
            .map(|i| start + i + 1)
            .unwrap_or(start);
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
        if self.pending_space {
            self.pending_space = false;
            // Skip past all additional spaces in input.
            while self.pos < self.bytes.len() && self.bytes[self.pos] == b' ' {
                self.pos += 1;
            }
            if self.pos < self.bytes.len() {
                return Some(b' ');
            }
            return None;
        }
        if self.pos >= self.bytes.len() {
            return None;
        }
        let b = self.bytes[self.pos];
        self.pos += 1;
        if b == b' ' {
            // Emit one space, then consume additional spaces next call.
            self.pending_space = true;
            Some(b' ')
        } else {
            Some(b.to_ascii_lowercase())
        }
    }
}

// ---------------------------------------------------------------------------
// Trust anchor matching (PKIX-1tb)
// ---------------------------------------------------------------------------

/// Find the index of the trust anchor that issued the last cert in the chain.
///
/// Matching rules (both must hold):
/// 1. `anchor.subject` == `last_cert.tbs_certificate.issuer` per RFC 4518 string prep.
/// 2. For self-issued certificates (issuer == subject), a direct SPKI comparison is
///    also performed to prevent name-collision attacks: an attacker who creates a
///    different root cert with the same DN but a different key is rejected here.
///
/// The anchor's own signature is NOT verified — trust anchors are trusted by definition.
///
/// Returns `Ok(i)` for the first matching anchor, or `Err(Error::NoTrustedPath)` if none.
fn find_trust_anchor(last_cert: &Certificate, anchors: &[TrustAnchor]) -> Result<usize> {
    let is_self_issued = names_match(
        &last_cert.tbs_certificate.issuer,
        &last_cert.tbs_certificate.subject,
    );

    for (i, anchor) in anchors.iter().enumerate() {
        if !names_match(&anchor.subject, &last_cert.tbs_certificate.issuer) {
            continue;
        }
        // For self-issued certs, also compare SPKIs directly to prevent
        // name-collision attacks (RFC 5280 §3.2).
        if is_self_issued
            && anchor.subject_public_key_info
                != last_cert.tbs_certificate.subject_public_key_info
        {
            continue;
        }
        return Ok(i);
    }
    Err(Error::NoTrustedPath)
}

// ---------------------------------------------------------------------------
// ECDSA P-256 SHA-256 backend (PKIX-evy)
// ---------------------------------------------------------------------------

/// ECDSA P-256 with SHA-256 signature verifier.
///
/// Handles OID `ecdsa-with-SHA256` (1.2.840.10045.4.3.2).
/// Feature-gated behind `p256`.
#[cfg(feature = "p256")]
pub struct EcdsaP256Verifier;

#[cfg(feature = "p256")]
impl SignatureVerifier for EcdsaP256Verifier {
    fn verify_signature(
        &self,
        _algorithm: spki::AlgorithmIdentifierRef<'_>,
        issuer_spki: spki::SubjectPublicKeyInfoRef<'_>,
        message: &[u8],
        signature: &[u8],
    ) -> core::result::Result<(), SignatureError> {
        use p256::ecdsa::{signature::Verifier as _, DerSignature, VerifyingKey};

        let vk = VerifyingKey::try_from(issuer_spki).map_err(|_| SignatureError::new())?;

        let sig = DerSignature::try_from(signature).map_err(|_| SignatureError::new())?;

        vk.verify(message, &sig).map_err(|_| SignatureError::new())
    }
}

// ---------------------------------------------------------------------------
// RSA PKCS#1 v1.5 SHA-256 backend (PKIX-gmv)
// ---------------------------------------------------------------------------

/// RSA with PKCS#1 v1.5 padding and SHA-256 signature verifier.
///
/// Handles OID `sha256WithRSAEncryption` (1.2.840.113549.1.1.11).
/// Feature-gated behind `rsa`.
#[cfg(feature = "rsa")]
pub struct RsaPkcs1v15Sha256Verifier;

#[cfg(feature = "rsa")]
impl SignatureVerifier for RsaPkcs1v15Sha256Verifier {
    fn verify_signature(
        &self,
        _algorithm: spki::AlgorithmIdentifierRef<'_>,
        issuer_spki: spki::SubjectPublicKeyInfoRef<'_>,
        message: &[u8],
        signature: &[u8],
    ) -> core::result::Result<(), SignatureError> {
        use rsa::pkcs1v15::{Signature, VerifyingKey};
        use rsa::signature::Verifier as _;
        use sha2::Sha256;

        let vk = VerifyingKey::<Sha256>::try_from(issuer_spki)
            .map_err(|_| SignatureError::new())?;

        let sig = Signature::try_from(signature).map_err(|_| SignatureError::new())?;

        vk.verify(message, &sig).map_err(|_| SignatureError::new())
    }
}

// ---------------------------------------------------------------------------
// Chain walk loop — signature verification and name linkage (PKIX-vxf)
// ---------------------------------------------------------------------------

/// Walk the chain from issuer to leaf, applying all RFC 5280 §6.1 per-cert checks.
///
/// ## Algorithm
///
/// 1. Reject early if the chain is too long per `policy.max_path_len`.
/// 2. Match a trust anchor for the last cert in the chain.
/// 3. Walk `chain` in reverse (issuer-to-leaf):
///    a. Verify signature with the current issuer's SPKI.
///    b. Verify issuer/subject name linkage.
///    c. Check validity period against `policy.current_time_unix`.
///    d. Reject any unhandled critical extensions.
///    e. For intermediates (i > 0): require `BasicConstraints` cA=TRUE.
///    f. For intermediates (i > 0): if `policy.enforce_key_usage`, require `keyCertSign`.
///    g. For intermediates (i > 0): enforce `pathLenConstraint` if present.
///    h. Update working SPKI and issuer name for the next iteration.
///
/// Returns the trust anchor index on success.
fn chain_walk<V: SignatureVerifier>(
    chain: &[Certificate],
    anchors: &[TrustAnchor],
    policy: &ValidationPolicy,
    verifier: &V,
) -> Result<usize> {
    use der::Encode;
    use spki::der::referenced::OwnedToRef as _;

    // Early-out: number of intermediates is chain.len()-1 (chain[0] is the leaf).
    let num_intermediates = chain.len().saturating_sub(1);
    if num_intermediates > policy.max_path_len as usize {
        return Err(Error::PathTooLong);
    }

    let anchor_index =
        find_trust_anchor(chain.last().ok_or(Error::NoTrustedPath)?, anchors)?;
    let anchor = &anchors[anchor_index];

    let mut working_spki = &anchor.subject_public_key_info;
    let mut working_issuer_name = &anchor.subject;

    for i in (0..chain.len()).rev() {
        let cert = &chain[i];

        // (a) Verify signature with the current issuer's SPKI.
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
        check_validity(cert, policy.current_time_unix)
            .map_err(|()| Error::ValidityPeriod { index: i })?;

        // (d) Critical extension guard.
        check_critical_extensions(cert)
            .map_err(|()| Error::UnhandledCriticalExtension { index: i })?;

        // (e–g) Intermediate-only checks.
        if i > 0 {
            // (e) BasicConstraints cA=TRUE required.
            if cert_is_ca(cert) != Some(true) {
                return Err(Error::NotCA { index: i });
            }

            // (f) KeyUsage keyCertSign required (when policy demands it).
            if policy.enforce_key_usage {
                match has_key_cert_sign(cert) {
                    Some(true) => {}
                    _ => return Err(Error::KeyUsageMissing { index: i }),
                }
            }

            // (g) pathLenConstraint: the cert at position i has i-1 intermediates
            // below it in the chain. Enforce the constraint.
            if let Some(path_len) = cert_path_len_constraint(cert) {
                if (i - 1) > path_len as usize {
                    return Err(Error::PathTooLong);
                }
            }
        }

        // Update state for next iteration.
        working_spki = &cert.tbs_certificate.subject_public_key_info;
        working_issuer_name = &cert.tbs_certificate.subject;
    }

    Ok(anchor_index)
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
            return RsaPkcs1v15Sha256Verifier
                .verify_signature(algorithm, issuer_spki, message, signature);
        }
        Err(SignatureError::new())
    }
}

/// OID for `ecdsa-with-SHA256` — used by `DefaultVerifier` dispatch.
#[cfg(any(feature = "p256", feature = "rsa"))]
const OID_ECDSA_P256_SHA256: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// OID for `sha256WithRSAEncryption` — used by `DefaultVerifier` dispatch.
#[cfg(any(feature = "p256", feature = "rsa"))]
const OID_SHA256_WITH_RSA: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

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
}

#[cfg(test)]
mod tests_find_trust_anchor {
    use super::*;
    use der::Decode;

    // Fixtures used across tests:
    //   ec-p256-sha256.der   — self-signed, CN=PKIX-evy-test  (P-256 key)
    //   rsa-pkcs1v15-sha256.der — self-signed, CN=PKIX-gmv-test (RSA-2048 key)
    //
    // Oracle: both certs were verified OK by `openssl verify -CAfile <cert> <cert>`.

    fn load_p256_cert() -> Certificate {
        let der = include_bytes!("../tests/fixtures/ec-p256-sha256.der");
        Certificate::from_der(der).expect("parse P-256 cert")
    }

    fn load_rsa_cert() -> Certificate {
        let der = include_bytes!("../tests/fixtures/rsa-pkcs1v15-sha256.der");
        Certificate::from_der(der).expect("parse RSA cert")
    }

    /// Single matching anchor — name and SPKI both match the self-signed cert.
    #[test]
    fn single_anchor_matches() {
        let cert = load_p256_cert();
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        assert_eq!(find_trust_anchor(&cert, &anchors).unwrap(), 0);
    }

    /// Two anchors; only the second matches. Tests iteration order.
    #[test]
    fn second_anchor_matches() {
        let p256 = load_p256_cert();
        let rsa = load_rsa_cert();
        // First anchor has RSA name + RSA SPKI (won't match the P-256 cert).
        // Second anchor has P-256 name + P-256 SPKI (will match).
        let anchors = [TrustAnchor::from_cert(rsa), TrustAnchor::from_cert(p256.clone())];
        assert_eq!(find_trust_anchor(&p256, &anchors).unwrap(), 1);
    }

    /// Security test: anchor name matches but SPKI is different — must reject.
    ///
    /// This guards against an attacker who publishes a different root cert with
    /// the same DN as a trusted anchor. Name-only matching would wrongly accept it.
    #[test]
    fn name_match_spki_mismatch_rejected() {
        let p256 = load_p256_cert();
        let rsa = load_rsa_cert();
        // Forge an anchor: P-256 cert's subject name, but RSA cert's SPKI.
        let forged = TrustAnchor::new(
            p256.tbs_certificate.subject.clone(),
            rsa.tbs_certificate.subject_public_key_info.clone(),
        );
        let anchors = [forged];
        assert!(
            matches!(find_trust_anchor(&p256, &anchors), Err(Error::NoTrustedPath)),
            "name match with wrong SPKI must return NoTrustedPath"
        );
    }

    /// Anchor name does not match — must reject.
    #[test]
    fn name_mismatch_rejected() {
        let p256 = load_p256_cert();
        let rsa = load_rsa_cert();
        // RSA anchor has a different CN — no name match with the P-256 cert.
        let anchors = [TrustAnchor::from_cert(rsa)];
        assert!(
            matches!(find_trust_anchor(&p256, &anchors), Err(Error::NoTrustedPath)),
            "anchor with different name must return NoTrustedPath"
        );
    }
}

// PKIX-h6z: validate_path public API tests.
#[cfg(all(test, feature = "p256"))]
mod tests_validate_path {
    use super::*;
    use der::Decode;

    // Fixtures and time constants reused from tests_chain_walk.
    const GRY_NOW: u64 = 1_780_272_000;   // 2026-06-01

    fn load(bytes: &[u8]) -> Certificate {
        Certificate::from_der(bytes).expect("parse cert")
    }

    fn policy_at(t: u64) -> ValidationPolicy {
        ValidationPolicy { current_time_unix: t, ..Default::default() }
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
        let anchors = [TrustAnchor::from_cert(rsa), TrustAnchor::from_cert(p256.clone())];
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
    /// check_oid_consistency detects this → SignatureInvalid { index: 0 }.
    ///
    /// Oracle: RFC 5280 §4.1.1.2 requires outer and inner AlgorithmIdentifiers to be identical.
    #[test]
    fn oid_mismatch_outer_returns_signature_invalid() {
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
            leaf.signature_algorithm,
            leaf.tbs_certificate.signature,
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
                Err(Error::SignatureInvalid { index: 0 })
            ),
            "outer/inner OID mismatch must return SignatureInvalid {{ index: 0 }}"
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
                validate_path(&[leaf, int_cert], &anchors, &policy_at(GRY_NOW), &EcdsaP256Verifier),
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
        // The self-signed cert's notBefore is in the past (generated in 2026).
        // Use a current time of 2026 to ensure it's valid.
        let policy = policy_at(GRY_NOW);
        let anchors = [TrustAnchor::from_cert(p256.clone())];
        assert_eq!(
            chain_walk(&[p256], &anchors, &policy, &EcdsaP256Verifier).unwrap(),
            0
        );
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
        let anchors = [TrustAnchor::from_cert(root)];
        assert_eq!(
            chain_walk(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier).unwrap(),
            0
        );
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
        let anchors = [TrustAnchor::from_cert(load(include_bytes!(
            "../tests/fixtures/vxf-root.der"
        )))];
        let policy = policy_at(GRY_NOW);
        assert!(
            matches!(
                chain_walk(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier),
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
        let anchors = [TrustAnchor::from_cert(root)];
        assert!(
            matches!(
                chain_walk(&[leaf_wrong, int_cert], &anchors, &policy, &EcdsaP256Verifier),
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
        let anchors = [TrustAnchor::from_cert(root)];
        assert!(
            matches!(
                chain_walk(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier),
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
        let anchors = [TrustAnchor::from_cert(root)];
        assert!(
            matches!(
                chain_walk(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier),
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
        let leaf_unk = load(include_bytes!("../tests/fixtures/gry-leaf-unknown-crit.der"));
        let policy = policy_at(GRY_NOW);
        let anchors = [TrustAnchor::from_cert(root)];
        assert!(
            matches!(
                chain_walk(
                    &[leaf_unk, int_cert],
                    &anchors,
                    &policy,
                    &EcdsaP256Verifier
                ),
                Err(Error::UnhandledCriticalExtension { index: 0 })
            ),
            "unknown critical ext must return UnhandledCriticalExtension {{ index: 0 }}"
        );
    }
}
