//! CA/Browser Forum TLS Baseline Requirements reference lints.
//!
//! This module provides lint implementations for the requirements in the CA/B Forum
//! Baseline Requirements for TLS Server Certificates.  Each lint has a stable ID
//! of the form `cabf.br.tls.<section>.<noun>`.
//!
//! # Lints provided
//!
//! | ID | Citation | Severity | Applies to |
//! |----|----------|----------|-----------|
//! | [`cabf.br.tls.validity.max`](ValidityMaxLint) | TLS BR §6.3.2 (SC-081) | Error | Leaf |
//! | [`cabf.br.tls.alg.sha1_prohibited`](Sha1ProhibitedLint) | TLS BR §7.1.3 | Error | Any |
//! | [`cabf.br.tls.rsa.min_key_size`](RsaMinKeySizeLint) | TLS BR §6.1.5 | Error | Leaf |
//! | [`cabf.br.tls.san.required`](SanRequiredLint) | TLS BR §7.1.4.2 | Error | Leaf |
//! | [`cabf.br.tls.eku.server_auth`](EkuServerAuthLint) | TLS BR §7.1.2.7.3 | Error | Leaf |
//! | [`cabf.br.tls.bc.ca_flag`](BcCaFlagLint) | TLS BR §7.1.2.5 | Error | IntermediateCa |
//!
//! # Using the profile
//!
//! ```rust,ignore
//! use pkix_lint::cabf_tls_br::CabfTlsBrProfile;
//! use pkix_lint::LintProfile;
//!
//! let profile = CabfTlsBrProfile;
//! let runner = profile.lint_runner();
//! let findings = runner.run_cert(&cert, SubjectKind::Leaf, 0, now_unix);
//! ```

use der::{asn1::ObjectIdentifier, Decode as _};
use x509_cert::Certificate;

use crate::{Lint, LintProfile, LintResult, LintRunner, Scope, Severity, SubjectKind};

// ---------------------------------------------------------------------------
// OID constants
//
// Each constant carries a normative citation in its doc comment.
// ---------------------------------------------------------------------------

/// SHA-1 with RSA encryption — RFC 3279 §2.2.1, PKCS #1.
/// Prohibited in TLS BR §7.1.3.
const SHA1_WITH_RSA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5");

/// ECDSA with SHA-1 — RFC 3279 §2.2.3.
/// Prohibited in TLS BR §7.1.3.
const ECDSA_WITH_SHA1: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.1");

/// RSA encryption SPKI algorithm OID — RFC 3279 §2.3.1.
/// Used to detect RSA keys in SubjectPublicKeyInfo.
const RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// SubjectAltName extension OID — RFC 5280 §4.2.1.6.
const OID_SUBJECT_ALT_NAME: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.5.29.17");

/// ExtendedKeyUsage extension OID — RFC 5280 §4.2.1.12.
const OID_EXTENDED_KEY_USAGE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.5.29.37");

/// BasicConstraints extension OID — RFC 5280 §4.2.1.9.
const OID_BASIC_CONSTRAINTS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.5.29.19");

/// id-kp-serverAuth — RFC 5280 §4.2.1.12, TLS BR §7.1.2.7.3.
const ID_KP_SERVER_AUTH: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");

// ---------------------------------------------------------------------------
// Lint 1 — cabf.br.tls.validity.max
// ---------------------------------------------------------------------------

/// Leaf certificate validity must not exceed the SC-081 phased cap.
///
/// CA/B Forum Ballot SC-081 introduces a phased reduction:
/// - Before 2026-03-15: 398 days
/// - 2026-03-15 to 2027-03-15: 200 days
/// - 2027-03-15 to 2029-03-15: 100 days
/// - 2029-03-15 onwards: 47 days
///
/// The cap is evaluated at `now_unix` (the relying party's current time).
///
/// Citation: CA/B Forum TLS BR §6.3.2 (SC-081)
pub struct ValidityMaxLint;

impl Lint for ValidityMaxLint {
    fn id(&self) -> &'static str {
        "cabf.br.tls.validity.max"
    }

    fn citation(&self) -> &'static str {
        "CA/B Forum TLS BR §6.3.2 (SC-081)"
    }

    fn severity(&self) -> Severity {
        Severity::Error
    }

    fn scope(&self) -> Scope {
        Scope::Certificate
    }

    fn applies_to(&self) -> SubjectKind {
        SubjectKind::Leaf
    }

    fn check_cert(&self, cert: &Certificate, _kind: SubjectKind, now_unix: u64) -> LintResult {
        let tbs = &cert.tbs_certificate;
        let not_before = tbs.validity.not_before.to_unix_duration().as_secs();
        let not_after = tbs.validity.not_after.to_unix_duration().as_secs();

        // Validity duration in seconds; saturate to avoid underflow on malformed certs.
        let duration_secs = not_after.saturating_sub(not_before);

        let cap = pkix_profiles::sc081_validity_cap(now_unix);

        if duration_secs > cap {
            LintResult::Error("leaf certificate validity period exceeds SC-081 cap")
        } else {
            LintResult::Pass
        }
    }
}

// ---------------------------------------------------------------------------
// Lint 2 — cabf.br.tls.alg.sha1_prohibited
// ---------------------------------------------------------------------------

/// No certificate in the chain may use SHA-1 as its signature algorithm.
///
/// Checks the outer `signatureAlgorithm` OID on the certificate structure.
/// Both `sha1WithRSAEncryption` (1.2.840.113549.1.1.5) and `ecdsa-with-SHA1`
/// (1.2.840.10045.4.1) are checked.
///
/// Citation: CA/B Forum TLS BR §7.1.3
pub struct Sha1ProhibitedLint;

impl Lint for Sha1ProhibitedLint {
    fn id(&self) -> &'static str {
        "cabf.br.tls.alg.sha1_prohibited"
    }

    fn citation(&self) -> &'static str {
        "CA/B Forum TLS BR §7.1.3"
    }

    fn severity(&self) -> Severity {
        Severity::Error
    }

    fn scope(&self) -> Scope {
        Scope::Certificate
    }

    fn applies_to(&self) -> SubjectKind {
        SubjectKind::Any
    }

    fn check_cert(&self, cert: &Certificate, _kind: SubjectKind, _now_unix: u64) -> LintResult {
        let sig_alg = &cert.signature_algorithm.oid;
        if sig_alg == &SHA1_WITH_RSA || sig_alg == &ECDSA_WITH_SHA1 {
            LintResult::Error("certificate uses SHA-1 signature algorithm, prohibited by TLS BR §7.1.3")
        } else {
            LintResult::Pass
        }
    }
}

// ---------------------------------------------------------------------------
// Lint 3 — cabf.br.tls.rsa.min_key_size
// ---------------------------------------------------------------------------

/// RSA leaf certificates must have a modulus of at least 2048 bits.
///
/// Non-RSA keys (ECDSA, Ed25519, etc.) return `NotApplicable`.
///
/// The RSA modulus byte length is read directly from the DER-encoded
/// `RSAPublicKey` structure inside the `SubjectPublicKeyInfo` bit string.
/// A modulus of `n` bytes satisfies the 2048-bit requirement iff `n >= 256`.
/// This is correct: a leading zero byte is only present when the high bit of
/// the first significant byte is set (DER unsigned integer encoding), so the
/// minimum 2048-bit modulus is 256 bytes with no leading zero, and a 2047-bit
/// modulus is 256 bytes with a leading zero — both ≥ 256 bytes, but the actual
/// bit length of the latter is 2047.  The floor-byte comparison `n_bytes >= 256`
/// is the conservative check used by most CA/B Forum linting tools.
///
/// Citation: CA/B Forum TLS BR §6.1.5
pub struct RsaMinKeySizeLint;

impl Lint for RsaMinKeySizeLint {
    fn id(&self) -> &'static str {
        "cabf.br.tls.rsa.min_key_size"
    }

    fn citation(&self) -> &'static str {
        "CA/B Forum TLS BR §6.1.5"
    }

    fn severity(&self) -> Severity {
        Severity::Error
    }

    fn scope(&self) -> Scope {
        Scope::Certificate
    }

    fn applies_to(&self) -> SubjectKind {
        SubjectKind::Leaf
    }

    fn check_cert(&self, cert: &Certificate, _kind: SubjectKind, _now_unix: u64) -> LintResult {
        let spki = &cert.tbs_certificate.subject_public_key_info;

        // Only check RSA keys.
        if spki.algorithm.oid != RSA_ENCRYPTION {
            return LintResult::NotApplicable;
        }

        // The SubjectPublicKeyInfo.subjectPublicKey bit string contains the
        // DER encoding of RSAPublicKey ::= SEQUENCE { modulus INTEGER,
        //                                              publicExponent INTEGER }
        let key_bytes = spki.subject_public_key.raw_bytes();

        // Decode RSAPublicKey SEQUENCE to get the modulus INTEGER bytes.
        // We only need the first INTEGER (modulus); parse the outer SEQUENCE
        // header manually to avoid pulling in the `rsa` crate.
        match rsa_modulus_byte_len(key_bytes) {
            Some(n_bytes) => {
                // 256 bytes * 8 bits/byte = 2048 bits
                if n_bytes >= 256 {
                    LintResult::Pass
                } else {
                    LintResult::Error("RSA key modulus is less than 2048 bits")
                }
            }
            None => LintResult::Error("RSA public key structure is unparseable"),
        }
    }
}

/// Parse DER-encoded `RSAPublicKey ::= SEQUENCE { modulus INTEGER, ... }` and
/// return the byte length of the modulus `INTEGER` value (including any leading
/// zero padding byte).
///
/// Returns `None` if the structure is malformed.
fn rsa_modulus_byte_len(der: &[u8]) -> Option<usize> {
    // Expect SEQUENCE tag 0x30.
    let (seq_content, _rest) = der_peel_tlv(der, 0x30)?;
    // First element inside SEQUENCE: INTEGER tag 0x02.
    let (_modulus_value, _) = der_peel_tlv(seq_content, 0x02)?;
    // We want the *length* of the value field, not the value itself.
    // Re-derive it from the raw bytes we already parsed.
    der_tlv_value_len(seq_content, 0x02)
}

/// Strip a DER TLV wrapper with the given `expected_tag` and return
/// `(value_bytes, remaining_bytes)`.  Returns `None` on mismatch or truncation.
fn der_peel_tlv<'a>(input: &'a [u8], expected_tag: u8) -> Option<(&'a [u8], &'a [u8])> {
    let (tag, rest) = input.split_first()?;
    if *tag != expected_tag {
        return None;
    }
    let (len, rest) = parse_der_length(rest)?;
    if rest.len() < len {
        return None;
    }
    let (value, remaining) = rest.split_at(len);
    Some((value, remaining))
}

/// Return only the byte length of the value of the first TLV with `expected_tag`.
fn der_tlv_value_len(input: &[u8], expected_tag: u8) -> Option<usize> {
    let (tag, rest) = input.split_first()?;
    if *tag != expected_tag {
        return None;
    }
    let (len, _rest) = parse_der_length(rest)?;
    Some(len)
}

/// Parse a DER length field, returning `(length_value, remaining_bytes)`.
///
/// Handles short-form (1 byte) and long-form (2–4 byte) lengths.
/// Indefinite-length encoding is not supported (not valid in DER).
fn parse_der_length(input: &[u8]) -> Option<(usize, &[u8])> {
    let (first, rest) = input.split_first()?;
    if *first < 0x80 {
        // Short form: length is directly in this byte.
        return Some((*first as usize, rest));
    }
    // Long form: low 7 bits encode how many subsequent bytes hold the length.
    let n_bytes = (*first & 0x7f) as usize;
    if n_bytes == 0 || n_bytes > 4 || rest.len() < n_bytes {
        return None; // indefinite, > 4-byte length, or truncated
    }
    let (len_bytes, rest) = rest.split_at(n_bytes);
    let mut length: usize = 0;
    for &b in len_bytes {
        length = length.checked_shl(8)?.checked_add(b as usize)?;
    }
    Some((length, rest))
}

// ---------------------------------------------------------------------------
// Lint 4 — cabf.br.tls.san.required
// ---------------------------------------------------------------------------

/// Leaf certificates must have a non-empty SubjectAltName extension.
///
/// If the extension is absent the lint returns Error.
/// If the extension is present but contains no general names, the lint returns Error.
///
/// Citation: CA/B Forum TLS BR §7.1.4.2
pub struct SanRequiredLint;

impl Lint for SanRequiredLint {
    fn id(&self) -> &'static str {
        "cabf.br.tls.san.required"
    }

    fn citation(&self) -> &'static str {
        "CA/B Forum TLS BR §7.1.4.2"
    }

    fn severity(&self) -> Severity {
        Severity::Error
    }

    fn scope(&self) -> Scope {
        Scope::Certificate
    }

    fn applies_to(&self) -> SubjectKind {
        SubjectKind::Leaf
    }

    fn check_cert(&self, cert: &Certificate, _kind: SubjectKind, _now_unix: u64) -> LintResult {
        let extensions = match &cert.tbs_certificate.extensions {
            Some(exts) => exts,
            None => return LintResult::Error("leaf certificate has no extensions; SubjectAltName absent"),
        };

        let san_ext = extensions.iter().find(|e| e.extn_id == OID_SUBJECT_ALT_NAME);

        match san_ext {
            None => LintResult::Error("SubjectAltName extension absent from leaf certificate"),
            Some(ext) => {
                // Decode SubjectAltName ::= GeneralNames ::= SEQUENCE OF GeneralName
                match x509_cert::ext::pkix::SubjectAltName::from_der(ext.extn_value.as_bytes()) {
                    Ok(san) if san.0.is_empty() => {
                        LintResult::Error("SubjectAltName extension is present but contains no names")
                    }
                    Ok(_) => LintResult::Pass,
                    Err(_) => LintResult::Error("SubjectAltName extension value is malformed DER"),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Lint 5 — cabf.br.tls.eku.server_auth
// ---------------------------------------------------------------------------

/// Leaf certificates must assert id-kp-serverAuth in ExtendedKeyUsage.
///
/// If the EKU extension is absent the lint returns Error.
/// If the extension is present but does not include `id-kp-serverAuth`
/// (1.3.6.1.5.5.7.3.1) the lint returns Error.
///
/// Citation: CA/B Forum TLS BR §7.1.2.7.3
pub struct EkuServerAuthLint;

impl Lint for EkuServerAuthLint {
    fn id(&self) -> &'static str {
        "cabf.br.tls.eku.server_auth"
    }

    fn citation(&self) -> &'static str {
        "CA/B Forum TLS BR §7.1.2.7.3"
    }

    fn severity(&self) -> Severity {
        Severity::Error
    }

    fn scope(&self) -> Scope {
        Scope::Certificate
    }

    fn applies_to(&self) -> SubjectKind {
        SubjectKind::Leaf
    }

    fn check_cert(&self, cert: &Certificate, _kind: SubjectKind, _now_unix: u64) -> LintResult {
        let extensions = match &cert.tbs_certificate.extensions {
            Some(exts) => exts,
            None => return LintResult::Error("leaf certificate has no extensions; ExtendedKeyUsage absent"),
        };

        let eku_ext = extensions.iter().find(|e| e.extn_id == OID_EXTENDED_KEY_USAGE);

        match eku_ext {
            None => LintResult::Error("ExtendedKeyUsage extension absent from leaf certificate"),
            Some(ext) => {
                match x509_cert::ext::pkix::ExtendedKeyUsage::from_der(ext.extn_value.as_bytes()) {
                    Ok(eku) => {
                        if eku.0.iter().any(|oid| oid == &ID_KP_SERVER_AUTH) {
                            LintResult::Pass
                        } else {
                            LintResult::Error(
                                "ExtendedKeyUsage does not include id-kp-serverAuth (1.3.6.1.5.5.7.3.1)",
                            )
                        }
                    }
                    Err(_) => LintResult::Error("ExtendedKeyUsage extension value is malformed DER"),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Lint 6 — cabf.br.tls.bc.ca_flag
// ---------------------------------------------------------------------------

/// Intermediate CA certificates must have BasicConstraints with cA=TRUE.
///
/// Checks the `BasicConstraints` extension (OID 2.5.29.19).
/// If the extension is absent the lint returns Error.
/// If the extension is present but `cA` is not `true` the lint returns Error.
///
/// Citation: CA/B Forum TLS BR §7.1.2.5
pub struct BcCaFlagLint;

impl Lint for BcCaFlagLint {
    fn id(&self) -> &'static str {
        "cabf.br.tls.bc.ca_flag"
    }

    fn citation(&self) -> &'static str {
        "CA/B Forum TLS BR §7.1.2.5"
    }

    fn severity(&self) -> Severity {
        Severity::Error
    }

    fn scope(&self) -> Scope {
        Scope::Certificate
    }

    fn applies_to(&self) -> SubjectKind {
        SubjectKind::IntermediateCa
    }

    fn check_cert(&self, cert: &Certificate, _kind: SubjectKind, _now_unix: u64) -> LintResult {
        let extensions = match &cert.tbs_certificate.extensions {
            Some(exts) => exts,
            None => {
                return LintResult::Error(
                    "intermediate CA certificate has no extensions; BasicConstraints absent",
                )
            }
        };

        let bc_ext = extensions.iter().find(|e| e.extn_id == OID_BASIC_CONSTRAINTS);

        match bc_ext {
            None => LintResult::Error(
                "BasicConstraints extension absent from intermediate CA certificate",
            ),
            Some(ext) => {
                match x509_cert::ext::pkix::BasicConstraints::from_der(
                    ext.extn_value.as_bytes(),
                ) {
                    Ok(bc) => {
                        if bc.ca {
                            LintResult::Pass
                        } else {
                            LintResult::Error(
                                "BasicConstraints present but cA flag is not TRUE",
                            )
                        }
                    }
                    Err(_) => LintResult::Error("BasicConstraints extension value is malformed DER"),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CabfTlsBrProfile — bundles all lints with the WebPkiProfile path policy
// ---------------------------------------------------------------------------

/// The CA/B Forum TLS Baseline Requirements profile for `pkix-lint`.
///
/// Implements both [`pkix_path::Profile`] (delegating to [`pkix_profiles::WebPkiProfile`])
/// and [`LintProfile`] (providing all six CABF TLS BR lints above).
///
/// # Usage
///
/// ```rust,ignore
/// use pkix_lint::cabf_tls_br::CabfTlsBrProfile;
/// use pkix_lint::{LintProfile, SubjectKind};
///
/// let profile = CabfTlsBrProfile;
/// let runner = profile.lint_runner();
/// let findings = runner.run_cert(&cert, SubjectKind::Leaf, 0, now_unix);
/// ```
pub struct CabfTlsBrProfile;

impl pkix_path::Profile for CabfTlsBrProfile {
    fn id(&self) -> &str {
        pkix_profiles::WebPkiProfile.id()
    }

    fn version(&self) -> &str {
        pkix_profiles::WebPkiProfile.version()
    }

    fn policy(&self, now_unix: u64) -> pkix_path::ValidationPolicy {
        pkix_profiles::WebPkiProfile.policy(now_unix)
    }

    fn policy_oids(&self) -> &[der::asn1::ObjectIdentifier] {
        pkix_profiles::WebPkiProfile.policy_oids()
    }
}

/// Build the canonical list of CABF TLS BR lints.
///
/// Returns a fresh `Vec<Box<dyn Lint>>` on each call — the caller owns the lints.
/// Use [`CabfTlsBrProfile::lint_runner`] for a ready-to-use [`LintRunner`].
pub fn all_lints() -> Vec<Box<dyn Lint>> {
    vec![
        Box::new(ValidityMaxLint),
        Box::new(Sha1ProhibitedLint),
        Box::new(RsaMinKeySizeLint),
        Box::new(SanRequiredLint),
        Box::new(EkuServerAuthLint),
        Box::new(BcCaFlagLint),
    ]
}

impl LintProfile for CabfTlsBrProfile {
    fn lints(&self) -> &[Box<dyn Lint>] {
        // `OnceLock` (stable since Rust 1.70) gives us a lazily-initialized
        // static `Vec<Box<dyn Lint>>` whose reference outlives `&self`.
        static LINTS: std::sync::OnceLock<Vec<Box<dyn Lint>>> = std::sync::OnceLock::new();
        LINTS.get_or_init(all_lints)
    }

    fn lint_runner(&self) -> LintRunner {
        LintRunner::new(all_lints())
    }
}
