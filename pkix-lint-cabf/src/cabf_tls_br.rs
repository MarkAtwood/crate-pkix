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
//! | [`cabf.br.tls.rsa.min_key_size`](RsaMinKeySizeLint) | TLS BR §6.1.5 | Error | Any |
//! | [`cabf.br.tls.san.required`](SanRequiredLint) | TLS BR §7.1.4.2 | Error | Leaf |
//! | [`cabf.br.tls.eku.server_auth`](EkuServerAuthLint) | TLS BR §7.1.2.7.3 | Error | Leaf |
//! | [`cabf.br.tls.bc.ca_flag`](BcCaFlagLint) | TLS BR §7.1.2.5 | Error | `IntermediateCa` |
//!
//! # Using the profile
//!
//! ```rust,no_run
//! // `cert` and `now_unix` are obtained from the calling context.
//! use pkix_lint_cabf::cabf_tls_br::CabfTlsBrProfile;
//! use pkix_lint::{LintProfile, SubjectKind};
//! use x509_cert::Certificate;
//!
//! let cert: Certificate = unimplemented!("load from DER");
//! let now_unix: u64 = unimplemented!("current Unix epoch seconds");
//! let profile = CabfTlsBrProfile;
//! let runner = profile.lint_runner();
//! let findings = runner.run_cert(&cert, SubjectKind::Leaf, 0, now_unix);
//! ```

use der::{asn1::ObjectIdentifier, Decode as _};
use x509_cert::Certificate;

use pkix_lint::{
    Lint, LintProfile, LintResult, LintRunner, Profile, Scope, Severity, SubjectKind,
    ValidationPolicy,
};

// ---------------------------------------------------------------------------
// OID constants
//
// Each constant carries a normative citation in its doc comment.
// ---------------------------------------------------------------------------

/// SHA-1 with RSA encryption — RFC 3279 §2.2.1, PKCS #1.
/// Prohibited in TLS BR §7.1.3.
const SHA1_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5");

/// ECDSA with SHA-1 — RFC 3279 §2.2.3.
/// Prohibited in TLS BR §7.1.3.
const ECDSA_WITH_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.1");

/// RSA encryption SPKI algorithm OID — RFC 3279 §2.3.1.
/// Used to detect RSA keys in `SubjectPublicKeyInfo`.
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// `SubjectAltName` extension OID — RFC 5280 §4.2.1.6.
const OID_SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");

/// `ExtendedKeyUsage` extension OID — RFC 5280 §4.2.1.12.
const OID_EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");

/// `BasicConstraints` extension OID — RFC 5280 §4.2.1.9.
const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");

/// id-kp-serverAuth — RFC 5280 §4.2.1.12, TLS BR §7.1.2.7.3.
const ID_KP_SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");

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
/// The cap phase is evaluated at the certificate's `notBefore` (issuance time),
/// not at the relying party's current time. This matches the SC-081 requirement:
/// the validity period cap that applied when the cert was issued governs that
/// cert for its lifetime.
///
/// Citation: CA/B Forum TLS BR §6.3.2 (SC-081)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
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

    fn title(&self) -> &str {
        "Leaf certificate validity must not exceed SC-081 cap"
    }

    fn rfc_section_id(&self) -> Option<&str> {
        Some("cabf-tls-br-6.3.2")
    }

    fn check_cert(&self, cert: &Certificate, _kind: SubjectKind, _now_unix: u64) -> LintResult {
        // SC-081: cap is determined by issuance time (notBefore), not validation time.
        // `_now_unix` is intentionally ignored — it is the relying-party's current time,
        // which must not affect whether a certificate's validity period was compliant at
        // issuance.  A cert issued before 2026-03-15 under the 398-day cap remains valid
        // even when a relying party validates it after 2026-03-15 (the 200-day epoch).
        let tbs = &cert.tbs_certificate;
        let not_before = tbs.validity.not_before.to_unix_duration().as_secs();
        let not_after = tbs.validity.not_after.to_unix_duration().as_secs();

        // Structurally invalid cert: notAfter precedes notBefore.
        // No separate validity-range lint exists that catches this case, so we
        // return Error here rather than silently passing (duration = 0 via
        // saturating_sub would always pass the cap check, masking the defect).
        if not_after < not_before {
            return LintResult::error(
                "leaf certificate notAfter precedes notBefore (inverted validity period)",
            );
        }

        let duration_secs = not_after - not_before;
        let cap = pkix_profiles_cabf::sc081_validity_cap(not_before);

        if duration_secs > cap {
            // Dynamic detail (Cow::Owned): report the actual non-conforming
            // duration vs the cap in effect for this issuance date. The cap
            // varies with issuance time (SC-081 has multiple effective dates),
            // so a static "exceeds cap" message would lose audit context.
            // Demonstrates Cow::Owned usage post-PKIX-ua6q migration.
            let duration_days = duration_secs / 86_400;
            let cap_days = cap / 86_400;
            LintResult::error(format!(
                "leaf certificate validity period {duration_days} days exceeds SC-081 cap of {cap_days} days at issuance"
            ))
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
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
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

    fn title(&self) -> &str {
        "SHA-1 signature algorithm prohibited"
    }

    fn rfc_section_id(&self) -> Option<&str> {
        Some("cabf-tls-br-7.1.3")
    }

    fn check_cert(&self, cert: &Certificate, _kind: SubjectKind, _now_unix: u64) -> LintResult {
        let sig_alg = cert.signature_algorithm.oid;
        if matches!(sig_alg, SHA1_WITH_RSA | ECDSA_WITH_SHA1) {
            LintResult::error(
                "certificate uses SHA-1 signature algorithm, prohibited by TLS BR §7.1.3",
            )
        } else {
            LintResult::Pass
        }
    }
}

// ---------------------------------------------------------------------------
// Lint 3 — cabf.br.tls.rsa.min_key_size
// ---------------------------------------------------------------------------

/// RSA certificates (leaf and intermediate CA) must have a modulus of at least 2048 bits.
///
/// Non-RSA keys (ECDSA, Ed25519, etc.) return `NotApplicable`.
///
/// The RSA modulus bit length is computed from the DER-encoded `RSAPublicKey`
/// structure inside the `SubjectPublicKeyInfo` bit string and compared against
/// the 2048-bit floor.
///
/// # Why bit-length, not byte-length
///
/// DER INTEGER encoding of unsigned values prepends a leading 0x00 byte when
/// the high bit of the first content byte would be 1 (to distinguish a
/// non-negative integer from a negative one). For a true 2048-bit modulus,
/// bit 2047 (0-indexed) is set — that is bit 7 of the first byte — so DER
/// prepends a 0x00, yielding 257 bytes in the INTEGER value field. A 2047-bit
/// modulus has its highest bit at position 2046 (bit 6 of the first byte,
/// bit 7 = 0), so no leading 0x00 is added and the value is 256 bytes.
///
/// A naive `n_bytes >= 256` check therefore accepts 2047-bit keys, which
/// violates the BR floor. This lint computes the actual bit length:
///
/// 1. Strip any leading 0x00 padding byte from the modulus INTEGER.
/// 2. Compute `(remaining_byte_len - 1) * 8 + (8 - leading_zero_bits)`,
///    i.e. the position (1-indexed) of the most-significant set bit.
/// 3. Reject if the result is less than 2048.
///
/// Citation: CA/B Forum TLS BR §6.1.5
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
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
        SubjectKind::Any
    }

    fn title(&self) -> &str {
        "RSA modulus must be at least 2048 bits"
    }

    fn rfc_section_id(&self) -> Option<&str> {
        Some("cabf-tls-br-6.1.5")
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

        rsa_modulus_bit_len(key_bytes).map_or(
            LintResult::error("RSA public key structure is unparseable"),
            |n_bits| {
                if n_bits >= 2048 {
                    LintResult::Pass
                } else {
                    LintResult::error("RSA key modulus is less than 2048 bits")
                }
            },
        )
    }
}

/// Parse DER-encoded `RSAPublicKey ::= SEQUENCE { modulus INTEGER, ... }` and
/// return the bit length of the modulus (i.e. the position of its
/// most-significant set bit, counted from 1).
///
/// The DER encoding of a non-negative INTEGER prepends a 0x00 padding byte
/// when the high bit of the first content byte would be set. This function
/// strips the optional padding before measuring, then counts leading zero
/// bits in the remaining first byte, so a 2047-bit modulus reports 2047
/// and a 2048-bit modulus reports 2048.
///
/// Returns `None` if the structure is malformed or the modulus is zero.
fn rsa_modulus_bit_len(der: &[u8]) -> Option<usize> {
    // Expect SEQUENCE tag 0x30.
    let (seq_content, _rest) = der_peel_tlv(der, 0x30)?;
    // First element inside SEQUENCE must be the modulus INTEGER (tag 0x02).
    let (mut int_value, _rest) = der_peel_tlv(seq_content, 0x02)?;

    // Strip a single leading 0x00 padding byte if it is purely a sign byte
    // (i.e. the next byte has its high bit set). DER forbids extra padding
    // bytes beyond this single sign byte.
    if int_value.len() >= 2 && int_value[0] == 0x00 && int_value[1] & 0x80 != 0 {
        int_value = &int_value[1..];
    }

    // Skip any all-zero leading bytes (they would indicate an over-encoded
    // value; under strict DER this should not occur, but we guard against it
    // rather than over-counting bits).
    while let Some((&first, rest)) = int_value.split_first() {
        if first == 0 {
            int_value = rest;
        } else {
            break;
        }
    }

    let (&high, _) = int_value.split_first()?;
    if high == 0 {
        return None; // modulus is zero — malformed
    }
    let leading_zeros = high.leading_zeros() as usize;
    Some((int_value.len() - 1) * 8 + (8 - leading_zeros))
}

/// Strip a DER TLV wrapper with the given `expected_tag` and return
/// `(value_bytes, remaining_bytes)`.  Returns `None` on mismatch or truncation.
fn der_peel_tlv(input: &[u8], expected_tag: u8) -> Option<(&[u8], &[u8])> {
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

/// Leaf certificates must have a non-empty `SubjectAltName` extension.
///
/// If the extension is absent the lint returns Error.
/// If the extension is present but contains no general names, the lint returns Error.
///
/// Citation: CA/B Forum TLS BR §7.1.4.2
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
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

    fn title(&self) -> &str {
        "Leaf certificate must include subjectAltName"
    }

    fn rfc_section_id(&self) -> Option<&str> {
        Some("cabf-tls-br-7.1.4.2")
    }

    fn check_cert(&self, cert: &Certificate, _kind: SubjectKind, _now_unix: u64) -> LintResult {
        let Some(extensions) = &cert.tbs_certificate.extensions else {
            return LintResult::error("leaf certificate has no extensions; SubjectAltName absent");
        };

        let Some(san_ext) = extensions
            .iter()
            .find(|e| e.extn_id == OID_SUBJECT_ALT_NAME)
        else {
            return LintResult::error("SubjectAltName extension absent from leaf certificate");
        };

        // Decode SubjectAltName ::= GeneralNames ::= SEQUENCE OF GeneralName
        match x509_cert::ext::pkix::SubjectAltName::from_der(san_ext.extn_value.as_bytes()) {
            Ok(san) if san.0.is_empty() => {
                LintResult::error("SubjectAltName extension is present but contains no names")
            }
            Ok(_) => LintResult::Pass,
            Err(_) => LintResult::error("SubjectAltName extension value is malformed DER"),
        }
    }
}

// ---------------------------------------------------------------------------
// Lint 5 — cabf.br.tls.eku.server_auth
// ---------------------------------------------------------------------------

/// Leaf certificates must assert id-kp-serverAuth in `ExtendedKeyUsage`.
///
/// If the EKU extension is absent the lint returns Error.
/// If the extension is present but does not include `id-kp-serverAuth`
/// (1.3.6.1.5.5.7.3.1) the lint returns Error.
///
/// Citation: CA/B Forum TLS BR §7.1.2.7.3
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
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

    fn title(&self) -> &str {
        "Leaf certificate must include id-kp-serverAuth EKU"
    }

    fn rfc_section_id(&self) -> Option<&str> {
        Some("cabf-tls-br-7.1.2.7.3")
    }

    fn check_cert(&self, cert: &Certificate, _kind: SubjectKind, _now_unix: u64) -> LintResult {
        let Some(extensions) = &cert.tbs_certificate.extensions else {
            return LintResult::error(
                "leaf certificate has no extensions; ExtendedKeyUsage absent",
            );
        };

        let Some(eku_ext) = extensions
            .iter()
            .find(|e| e.extn_id == OID_EXTENDED_KEY_USAGE)
        else {
            return LintResult::error("ExtendedKeyUsage extension absent from leaf certificate");
        };

        match x509_cert::ext::pkix::ExtendedKeyUsage::from_der(eku_ext.extn_value.as_bytes()) {
            Ok(eku) => {
                if eku.0.contains(&ID_KP_SERVER_AUTH) {
                    LintResult::Pass
                } else {
                    LintResult::error(
                        "ExtendedKeyUsage does not include id-kp-serverAuth (1.3.6.1.5.5.7.3.1)",
                    )
                }
            }
            Err(_) => LintResult::error("ExtendedKeyUsage extension value is malformed DER"),
        }
    }
}

// ---------------------------------------------------------------------------
// Lint 6 — cabf.br.tls.bc.ca_flag
// ---------------------------------------------------------------------------

/// Intermediate CA certificates must have `BasicConstraints` with cA=TRUE.
///
/// Checks the `BasicConstraints` extension (OID 2.5.29.19).
/// If the extension is absent the lint returns Error.
/// If the extension is present but `cA` is not `true` the lint returns Error.
///
/// Citation: CA/B Forum TLS BR §7.1.2.5
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
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

    fn title(&self) -> &str {
        "CA certificates must set BasicConstraints.cA=TRUE"
    }

    fn rfc_section_id(&self) -> Option<&str> {
        Some("cabf-tls-br-7.1.2.5")
    }

    fn check_cert(&self, cert: &Certificate, _kind: SubjectKind, _now_unix: u64) -> LintResult {
        let Some(extensions) = &cert.tbs_certificate.extensions else {
            return LintResult::error(
                "intermediate CA certificate has no extensions; BasicConstraints absent",
            );
        };

        let Some(bc_ext) = extensions
            .iter()
            .find(|e| e.extn_id == OID_BASIC_CONSTRAINTS)
        else {
            return LintResult::error(
                "BasicConstraints extension absent from intermediate CA certificate",
            );
        };

        x509_cert::ext::pkix::BasicConstraints::from_der(bc_ext.extn_value.as_bytes()).map_or(
            LintResult::error("BasicConstraints extension value is malformed DER"),
            |bc| {
                if bc.ca {
                    LintResult::Pass
                } else {
                    LintResult::error("BasicConstraints present but cA flag is not TRUE")
                }
            },
        )
    }
}

// ---------------------------------------------------------------------------
// CabfTlsBrProfile — bundles all lints with the WebPkiProfile path policy
// ---------------------------------------------------------------------------

/// The CA/B Forum TLS Baseline Requirements profile for `pkix-lint`.
///
/// Implements both [`pkix_path::Profile`] (delegating to [`pkix_profiles_cabf::WebPkiProfile`])
/// and [`LintProfile`] (providing all six CABF TLS BR lints above).
///
/// # Usage
///
/// ```rust,no_run
/// // `cert` and `now_unix` are obtained from the calling context.
/// use pkix_lint_cabf::cabf_tls_br::CabfTlsBrProfile;
/// use pkix_lint::{LintProfile, SubjectKind};
/// use x509_cert::Certificate;
///
/// let cert: Certificate = unimplemented!("load from DER");
/// let now_unix: u64 = unimplemented!("current Unix epoch seconds");
/// let profile = CabfTlsBrProfile;
/// let runner = profile.lint_runner();
/// let findings = runner.run_cert(&cert, SubjectKind::Leaf, 0, now_unix);
/// ```
pub struct CabfTlsBrProfile;

impl Profile for CabfTlsBrProfile {
    fn id(&self) -> &'static str {
        pkix_profiles_cabf::WebPkiProfile.id()
    }

    fn version(&self) -> &'static str {
        pkix_profiles_cabf::WebPkiProfile.version()
    }

    fn policy(&self, now_unix: u64) -> ValidationPolicy {
        pkix_profiles_cabf::WebPkiProfile.policy(now_unix)
    }

    fn policy_oids(&self) -> &[der::asn1::ObjectIdentifier] {
        pkix_profiles_cabf::WebPkiProfile.policy_oids()
    }
}

/// Build the canonical list of CABF TLS BR lints.
///
/// Returns a fresh `Vec<Box<dyn Lint>>` on each call — the caller owns the lints.
/// Use [`CabfTlsBrProfile::lint_runner`] for a ready-to-use [`LintRunner`].
#[must_use]
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
    /// Return the shared lint list for this profile.
    ///
    /// The returned slice is backed by a lazily-initialized `static OnceLock`.
    /// The lint instances returned here are different objects from those used
    /// inside a `LintRunner` produced by [`lint_runner`][Self::lint_runner]:
    /// each call to `lint_runner()` constructs a fresh set of instances via
    /// [`all_lints()`]. Both use the same lint types and IDs, but the instances
    /// are not shared.
    ///
    /// Note: if `Lint` implementations ever become stateful, callers should
    /// prefer [`lint_runner`][Self::lint_runner] for a self-contained runner
    /// rather than mixing a call to `lints()` with a separately constructed
    /// runner.
    fn lints(&self) -> &[Box<dyn Lint>] {
        // `OnceLock` (stable since Rust 1.70) gives us a lazily-initialized
        // static `Vec<Box<dyn Lint>>` whose reference outlives `&self`.
        static LINTS: std::sync::OnceLock<Vec<Box<dyn Lint>>> = std::sync::OnceLock::new();
        LINTS.get_or_init(all_lints)
    }

    /// Allocates a fresh [`LintRunner`] backed by a new set of lint instances
    /// on each call.
    ///
    /// The lint instances inside the returned runner are independent from those
    /// returned by [`lints()`][Self::lints]: both source their lint types from
    /// [`all_lints()`], but the objects are distinct allocations. The set of
    /// lint IDs is identical.
    ///
    /// For repeated use, cache the returned [`LintRunner`] at the call site
    /// rather than calling this method on every evaluation.
    fn lint_runner(&self) -> LintRunner {
        LintRunner::new(all_lints())
    }
}
