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

// ---------------------------------------------------------------------------
// validate_path helpers — input guards and OID consistency (PKIX-6vu)
// ---------------------------------------------------------------------------

#[allow(dead_code)]
fn check_inputs(chain: &[Certificate], anchors: &[TrustAnchor]) -> Result<()> {
    if chain.is_empty() || anchors.is_empty() {
        return Err(Error::NoTrustedPath);
    }
    Ok(())
}

/// RFC 5280 §4.1.1.2: outer signatureAlgorithm must equal inner TBSCertificate.signature.
#[allow(dead_code)]
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

#[allow(dead_code)]
const OID_KEY_USAGE: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.15");
#[allow(dead_code)]
const OID_BASIC_CONSTRAINTS: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.19");
#[allow(dead_code)]
const OID_SUBJECT_ALT_NAME: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.17");

/// OIDs of extensions that this implementation handles; all others, if critical, cause rejection.
#[allow(dead_code)]
const HANDLED_CRITICAL_OIDS: &[der::asn1::ObjectIdentifier] = &[
    OID_KEY_USAGE,
    OID_BASIC_CONSTRAINTS,
    OID_SUBJECT_ALT_NAME, // recognized but application-level; path validator ignores value
];

/// RFC 5280 §6.1.3(a)(3): reject any critical extension not in the handled set.
///
/// Returns `Ok(())` on success, or `Err(())` to signal the *type* of error —
/// the caller must inject the correct `index` when constructing `Error::UnhandledCriticalExtension`.
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
fn time_to_unix_secs(t: &x509_cert::time::Time) -> u64 {
    t.to_unix_duration().as_secs()
}

/// RFC 5280 §6.1.3(a)(2): check notBefore ≤ now ≤ notAfter.
///
/// Returns `Ok(())` or `Err(())` — caller injects the chain index.
#[allow(dead_code)]
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
/// Matching rule: `anchor.subject` must equal `last_cert.tbs_certificate.issuer`
/// per RFC 4518 string prep (see [`names_match`]).
///
/// The anchor's signature is NOT verified — trust anchors are trusted by definition.
///
/// Returns `Some(i)` for the first matching anchor, or `None` if no anchor matched.
#[allow(dead_code)]
fn find_trust_anchor(last_cert: &Certificate, anchors: &[TrustAnchor]) -> Option<usize> {
    for (i, anchor) in anchors.iter().enumerate() {
        if names_match(&anchor.subject, &last_cert.tbs_certificate.issuer) {
            return Some(i);
        }
    }
    None
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
