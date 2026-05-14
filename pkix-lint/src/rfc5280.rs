//! RFC 5280 conformance lints.
//!
//! This module ships [`Lint`] implementations that enforce structural and
//! semantic rules from [RFC 5280][rfc5280]. Each lint is keyed by an OSCAL
//! Control-id-shaped identifier (`rfc5280-<section>`) and cites the
//! relevant section in its rustdoc.
//!
//! The lints here are intentionally lean and parameterless except where
//! the underlying RFC explicitly admits an operator-tunable threshold;
//! see [`Rfc5280MaxSerialLengthLint`] for the first such case.
//!
//! [rfc5280]: https://www.rfc-editor.org/rfc/rfc5280
//!
//! # Provenance
//!
//! Added in PKIX-9vnx.6.4 as the demonstration vehicle for the
//! [`Lint::parameters`] / [`Lint::set_parameter`] OSCAL Parameter
//! mechanism. CABF-shaped lints now live in the `pkix-lint-cabf`
//! crate ([`cabf_tls_br`][cabf_tls_br]); project policy (see workspace
//! `AGENTS.md` and the PKIX-amgn / PKIX-9vnx alignment epics) is that
//! RFC-conformance lints stay in `pkix-lint` while CA/B Forum policy
//! lints live in `pkix-lint-cabf`.
//!
//! [cabf_tls_br]: https://docs.rs/pkix-lint-cabf/latest/pkix_lint_cabf/cabf_tls_br/

use std::borrow::Cow;

use der::{asn1::ObjectIdentifier, Decode as _};
use x509_cert::Certificate;

use crate::{Lint, LintParameter, LintResult, ParameterError, Scope, Severity, SubjectKind};

// ---------------------------------------------------------------------------
// OID constants (RFC 5280 §4.2.1 — standard certificate extensions)
// ---------------------------------------------------------------------------

/// `BasicConstraints` extension OID — RFC 5280 §4.2.1.9.
const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");

/// `ExtendedKeyUsage` extension OID — RFC 5280 §4.2.1.12.
const OID_EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");

/// `SubjectAltName` extension OID — RFC 5280 §4.2.1.6.
const OID_SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");

/// id-kp-serverAuth — RFC 5280 §4.2.1.12 (TLS WWW server authentication).
const ID_KP_SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");

// ---------------------------------------------------------------------------
// rfc5280.cert.serial_number.max_octets
// ---------------------------------------------------------------------------

/// RFC 5280 §4.1.2.2: serialNumber must not exceed 20 octets.
///
/// > Conforming CAs MUST NOT use serialNumber values longer than 20
/// > octets.  Conforming CAs MUST NOT use the value zero for the
/// > serialNumber field.
///
/// This lint enforces the upper-bound clause. The 20-octet cap is the
/// default; operators may tighten it via the `max-octets` OSCAL parameter
/// (e.g., to model a more restrictive in-house issuance policy). Setting
/// `max-octets` above 20 is permitted but advertises a deliberate
/// deviation from RFC 5280 baseline.
///
/// # OSCAL parameters
///
/// | id            | label                                            | default |
/// |---------------|--------------------------------------------------|--------:|
/// | `max-octets`  | Maximum allowed serial number length in octets   | `20`    |
///
/// # Provenance
///
/// First parametric Lint added under PKIX-9vnx.6.4. Doubles as the
/// pkix-lint built-in fixture that tests OSCAL parameter overrides.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rfc5280MaxSerialLengthLint {
    max_octets: usize,
    parameters: Vec<LintParameter>,
}

impl Default for Rfc5280MaxSerialLengthLint {
    fn default() -> Self {
        // RFC 5280 §4.1.2.2 baseline cap.
        Self::with_max_octets(20)
    }
}

impl Rfc5280MaxSerialLengthLint {
    /// Construct the lint with an explicit `max_octets` cap.
    ///
    /// Equivalent to calling [`Default::default`] followed by
    /// [`Lint::set_parameter`] with id `"max-octets"`; provided as a typed
    /// constructor for callers configuring the lint at compile time.
    #[must_use]
    pub fn with_max_octets(max_octets: usize) -> Self {
        let parameters = vec![LintParameter {
            id: Cow::Borrowed("max-octets"),
            label: Cow::Borrowed("Maximum allowed serial number length in octets"),
            default_value: Cow::Borrowed("20"),
        }];
        Self {
            max_octets,
            parameters,
        }
    }

    /// Current `max_octets` cap. Useful for round-trip OSCAL emit tests.
    #[must_use]
    pub fn max_octets(&self) -> usize {
        self.max_octets
    }
}

impl Lint for Rfc5280MaxSerialLengthLint {
    fn id(&self) -> &'static str {
        "rfc5280.cert.serial_number.max_octets"
    }

    fn citation(&self) -> &'static str {
        "RFC 5280 §4.1.2.2"
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
        "Certificate serialNumber must not exceed 20 octets"
    }

    fn spec_section_id(&self) -> Option<&str> {
        Some("rfc5280-4.1.2.2")
    }

    fn spec_url(&self) -> Option<&str> {
        Some("https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.2")
    }

    fn parameters(&self) -> &[LintParameter] {
        &self.parameters
    }

    fn set_parameter(&mut self, id: &str, value: &str) -> Result<(), ParameterError> {
        match id {
            "max-octets" => {
                let parsed: usize = value.parse().map_err(|_| ParameterError::InvalidValue {
                    id: id.to_owned(),
                    reason: format!("expected non-negative integer, got '{value}'"),
                })?;
                if parsed == 0 {
                    return Err(ParameterError::InvalidValue {
                        id: id.to_owned(),
                        reason: "max-octets must be at least 1".to_string(),
                    });
                }
                self.max_octets = parsed;
                Ok(())
            }
            other => Err(ParameterError::UnknownParameter(other.to_owned())),
        }
    }

    fn check_cert(&self, cert: &Certificate, _kind: SubjectKind, _now_unix: u64) -> LintResult {
        // `SerialNumber::as_bytes` returns the canonical big-endian unsigned
        // bytes (DER content of the INTEGER, with any leading 0x00 sign
        // padding byte already stripped per the SerialNumber type's invariant
        // in the x509-cert crate).  The RFC 5280 "20 octets" cap is on the
        // ENCODED INTEGER content, which is exactly what `as_bytes` reports;
        // confirmed against the x509-cert SerialNumber rustdoc.
        let len = cert.tbs_certificate.serial_number.as_bytes().len();
        if len > self.max_octets {
            // Dynamic detail (Cow::Owned): include the actual length so
            // the audit trail attributes the failure to a specific value.
            LintResult::error(format!(
                "certificate serialNumber is {} octets, exceeds cap of {} octets",
                len, self.max_octets
            ))
        } else {
            LintResult::Pass
        }
    }
}

// ---------------------------------------------------------------------------
// rfc5280.cert.bc.ca_false_for_leaf
// ---------------------------------------------------------------------------

/// RFC 5280 §4.2.1.9: end-entity certificates MUST NOT assert `cA=TRUE`.
///
/// > The cA boolean indicates whether the certified public key may be used
/// > to verify certificate signatures.  If the cA boolean is not asserted,
/// > then the keyCertSign bit in the key usage extension MUST NOT be
/// > asserted.  If the basic constraints extension is not present in a
/// > version 3 certificate, or the extension is present but the cA boolean
/// > is not asserted, then the certified public key MUST NOT be used to
/// > verify certificate signatures.
///
/// The complement of `pkix_lint_cabf::cabf_tls_br::BcCaFlagLint`, which
/// requires `cA=TRUE` on intermediate CAs. This lint requires `cA=FALSE`
/// (or `BasicConstraints` absent, which has the same meaning per the spec)
/// on end-entity (`SubjectKind::Leaf`) certificates.
///
/// # Behavior
///
/// - `BasicConstraints` extension absent → `Pass` (defaults to cA=FALSE).
/// - `BasicConstraints` present with cA=FALSE → `Pass`.
/// - `BasicConstraints` present with cA=TRUE → `Error`.
/// - `BasicConstraints` extension value is malformed → `Error` (cannot
///   confirm cA=FALSE).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Rfc5280BasicConstraintsCaLeafLint;

impl Lint for Rfc5280BasicConstraintsCaLeafLint {
    fn id(&self) -> &'static str {
        "rfc5280.cert.bc.ca_false_for_leaf"
    }

    fn citation(&self) -> &'static str {
        "RFC 5280 §4.2.1.9"
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
        "End-entity certificate must not assert BasicConstraints.cA=TRUE"
    }

    fn spec_section_id(&self) -> Option<&str> {
        Some("rfc5280-4.2.1.9")
    }

    fn spec_url(&self) -> Option<&str> {
        Some("https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.9")
    }

    fn check_cert(&self, cert: &Certificate, _kind: SubjectKind, _now_unix: u64) -> LintResult {
        // No extensions at all is fine: BasicConstraints is implicitly absent
        // and defaults to cA=FALSE per the spec.
        let Some(extensions) = &cert.tbs_certificate.extensions else {
            return LintResult::Pass;
        };

        // BasicConstraints absent is the same as cA=FALSE.
        let Some(bc_ext) = extensions
            .iter()
            .find(|e| e.extn_id == OID_BASIC_CONSTRAINTS)
        else {
            return LintResult::Pass;
        };

        match x509_cert::ext::pkix::BasicConstraints::from_der(bc_ext.extn_value.as_bytes()) {
            Ok(bc) => {
                if bc.ca {
                    LintResult::error(
                        "end-entity certificate asserts BasicConstraints.cA=TRUE; \
                         only CA certificates may assert cA",
                    )
                } else {
                    LintResult::Pass
                }
            }
            Err(e) => LintResult::error(format!(
                "BasicConstraints extension value is malformed DER: {e}"
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// rfc5280.cert.eku.server_auth_required
// ---------------------------------------------------------------------------

/// RFC 5280 §4.2.1.12: TLS server end-entity certificates MUST assert
/// `id-kp-serverAuth` in `ExtendedKeyUsage`.
///
/// > KeyPurposeId ::= OBJECT IDENTIFIER
/// >
/// > -- TLS WWW server authentication
/// > -- Key usage bits that may be consistent: digitalSignature,
/// > -- keyEncipherment or keyAgreement
/// > id-kp-serverAuth             OBJECT IDENTIFIER ::= { id-kp 1 }
///
/// This is the RFC-conformance variant of the CA/B Forum
/// [`cabf.br.tls.eku.server_auth`][cabf-eku] lint. Identical logic, RFC
/// 5280 citation. The lint is leaf-only because EKU on intermediates is
/// constrained by the chain-walking name-space (RFC 5280 §4.2.1.12 second
/// paragraph) and is checked at path-validation time, not as a leaf shape
/// requirement.
///
/// [cabf-eku]: https://docs.rs/pkix-lint-cabf/latest/pkix_lint_cabf/cabf_tls_br/struct.EkuServerAuthLint.html
///
/// # Use-case applicability — operator contract
///
/// This lint is **use-case specific** to TLS server certificates. It
/// asserts a property the RFC requires of TLS server certs and **only**
/// TLS server certs. Registering it against arbitrary leaves produces
/// false-positive `Error` findings on S/MIME, code-signing, OCSP-responder,
/// or any other non-TLS-server end-entity certificate.
///
/// **Operators MUST register this lint only through a use-case-specific
/// [`LintProfile`][crate::LintProfile] that bundles it with other
/// TLS-server lints (SAN dNSName, etc.).**
/// `pkix_profiles::BasicTlsProfile` is the canonical bundler. There is no
/// "generic rfc5280-conformance" bundle that mixes this lint with
/// `Rfc8551EkuEmailProtectionLint` or `Rfc8398SmimeSanLint`: those four
/// lints assert mutually-exclusive shape requirements (no leaf cert
/// satisfies all four simultaneously) and must be selected by use case.
///
/// The lint trait deliberately does not encode use case in its type
/// signature; use-case selection is the `LintProfile` bundle's
/// responsibility. See [`crate::Lint`] trait rustdoc for the contract.
///
/// # Behavior
///
/// - `ExtendedKeyUsage` extension absent → `Error`.
/// - `ExtendedKeyUsage` present and contains `id-kp-serverAuth` → `Pass`.
/// - `ExtendedKeyUsage` present but does not contain `id-kp-serverAuth` →
///   `Error`.
/// - `ExtendedKeyUsage` extension value is malformed → `Error`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Rfc5280EkuServerAuthLint;

impl Lint for Rfc5280EkuServerAuthLint {
    fn id(&self) -> &'static str {
        "rfc5280.cert.eku.server_auth_required"
    }

    fn citation(&self) -> &'static str {
        "RFC 5280 §4.2.1.12"
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
        "TLS server certificate must include id-kp-serverAuth EKU"
    }

    fn spec_section_id(&self) -> Option<&str> {
        Some("rfc5280-4.2.1.12")
    }

    fn spec_url(&self) -> Option<&str> {
        Some("https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.12")
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
            Err(e) => LintResult::error(format!(
                "ExtendedKeyUsage extension value is malformed DER: {e}"
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// rfc5280.cert.san.required_when_subject_empty
// ---------------------------------------------------------------------------

/// RFC 5280 §4.2.1.6: certificates with an empty subject MUST include a
/// critical `subjectAltName` extension.
///
/// > If the subject field contains an empty sequence, then the issuing CA
/// > MUST include a subjectAltName extension that is marked as critical.
///
/// The lint enforces both clauses on certificates whose Subject is the
/// zero-length `RDNSequence`:
///
/// 1. `subjectAltName` MUST be present.
/// 2. The `subjectAltName` extension MUST be marked `critical`.
///
/// Certificates with a non-empty Subject are out of scope (`Pass`) — the
/// criticality of SAN on those is governed by separate rules (RFC 5280
/// §4.2.1.6 says SAN SHOULD be marked non-critical when the Subject is
/// also present; that SHOULD-clause is not covered here).
///
/// # Behavior
///
/// - Subject non-empty → `Pass` (this lint does not apply).
/// - Subject empty, `SubjectAltName` extension absent → `Error`.
/// - Subject empty, `SubjectAltName` present but not critical → `Error`.
/// - Subject empty, `SubjectAltName` present and critical → `Pass`.
///
/// # Provenance
///
/// Filed under PKIX-9vnx.9.2.1.1 as one of the three RFC-conformance
/// lints deferred from the initial PKIX-9vnx.9.2.1 batch. Negative-test
/// fixture (empty-subject leaf with missing-or-non-critical SAN) is not
/// yet present in the workspace fixture corpus; the lint ships with a
/// positive test only (existing fixtures all have non-empty Subjects).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Rfc5280SanRequiredWhenSubjectEmptyLint;

impl Lint for Rfc5280SanRequiredWhenSubjectEmptyLint {
    fn id(&self) -> &'static str {
        "rfc5280.cert.san.required_when_subject_empty"
    }

    fn citation(&self) -> &'static str {
        "RFC 5280 §4.2.1.6"
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
        "Empty-subject certificate must include a critical subjectAltName"
    }

    fn spec_section_id(&self) -> Option<&str> {
        Some("rfc5280-4.2.1.6")
    }

    fn spec_url(&self) -> Option<&str> {
        Some("https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.6")
    }

    fn check_cert(&self, cert: &Certificate, _kind: SubjectKind, _now_unix: u64) -> LintResult {
        // The lint is conditional on an empty Subject. Non-empty Subjects
        // are out of scope here — they Pass even if SAN is absent.
        if !cert.tbs_certificate.subject.is_empty() {
            return LintResult::Pass;
        }

        let Some(extensions) = &cert.tbs_certificate.extensions else {
            return LintResult::error(
                "empty-subject certificate has no extensions; \
                 RFC 5280 §4.2.1.6 requires a critical subjectAltName",
            );
        };

        let Some(san_ext) = extensions
            .iter()
            .find(|e| e.extn_id == OID_SUBJECT_ALT_NAME)
        else {
            return LintResult::error(
                "empty-subject certificate omits subjectAltName; \
                 RFC 5280 §4.2.1.6 requires it to be present and critical",
            );
        };

        if !san_ext.critical {
            return LintResult::error(
                "empty-subject certificate carries subjectAltName but it is not marked critical; \
                 RFC 5280 §4.2.1.6 requires the extension to be critical when the Subject is empty",
            );
        }

        LintResult::Pass
    }
}

// ---------------------------------------------------------------------------
// rfc5280.cert.signature_algorithm_match
// ---------------------------------------------------------------------------

/// RFC 5280 §4.1.1.2: outer `signatureAlgorithm` MUST equal inner
/// `tbsCertificate.signature`.
///
/// > This field MUST contain the same algorithm identifier as the
/// > signature field in the sequence tbsCertificate (Section 4.1.2.3).
/// > The contents of the optional parameters field will vary according to
/// > the algorithm identified.  This field is used as a redundant
/// > consistency check.
///
/// The two `AlgorithmIdentifier` values are compared structurally: the
/// algorithm OID and the optional parameters field must both match. The
/// comparison uses x509-cert's `AlgorithmIdentifier` `PartialEq` impl,
/// which compares both the OID and the encoded parameters value.
///
/// # Note on NULL vs absent parameters
///
/// RFC 4055 §2.1 mandates a NULL parameters value for RSA-PKCS1 signature
/// algorithms; some real-world certificates omit the parameters entirely.
/// This lint reports such intra-certificate inconsistency: if the outer
/// `signatureAlgorithm` has `parameters: NULL` and the inner
/// `tbsCertificate.signature` has `parameters: absent` (or vice versa),
/// the lint fires `Error`. That is the correct reading of §4.1.1.2's
/// "MUST contain the same algorithm identifier" wording — the redundancy
/// check exists precisely to catch encoder bugs that produce non-matching
/// outer/inner identifiers.
///
/// # Behavior
///
/// - Outer and inner `AlgorithmIdentifier` byte-equal → `Pass`.
/// - Otherwise → `Error` with both OIDs in the detail string.
///
/// # Provenance
///
/// Filed under PKIX-9vnx.9.2.1.1 as one of three deferred lints from the
/// PKIX-9vnx.9.2.1 batch. Negative-test fixture (cert with mismatched
/// outer/inner signature algorithms) is not yet present in the workspace
/// fixture corpus — well-behaved encoders such as OpenSSL and pyca always
/// produce matching identifiers. Fixture generation requires custom
/// DER-level synthesis and is out of scope here.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Rfc5280SignatureAlgorithmMatchLint;

impl Lint for Rfc5280SignatureAlgorithmMatchLint {
    fn id(&self) -> &'static str {
        "rfc5280.cert.signature_algorithm_match"
    }

    fn citation(&self) -> &'static str {
        "RFC 5280 §4.1.1.2"
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
        "Outer signatureAlgorithm must equal tbsCertificate.signature"
    }

    fn spec_section_id(&self) -> Option<&str> {
        Some("rfc5280-4.1.1.2")
    }

    fn spec_url(&self) -> Option<&str> {
        Some("https://www.rfc-editor.org/rfc/rfc5280#section-4.1.1.2")
    }

    fn check_cert(&self, cert: &Certificate, _kind: SubjectKind, _now_unix: u64) -> LintResult {
        let outer = &cert.signature_algorithm;
        let inner = &cert.tbs_certificate.signature;
        if outer == inner {
            LintResult::Pass
        } else {
            LintResult::error(format!(
                "outer signatureAlgorithm ({}) does not match \
                 tbsCertificate.signature ({}); \
                 RFC 5280 §4.1.1.2 requires both to be identical",
                outer.oid, inner.oid
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    //! Independent oracle for serial-length assertions:
    //!
    //! ```text
    //! openssl x509 -in <fixture> -inform DER -noout -serial \
    //!   | sed 's/serial=//' \
    //!   | awk '{ print length($0)/2 " octets" }'
    //! ```
    //!
    //! Fixture serial-length oracle values (verified 2026-05-11):
    //!
    //! | fixture                                 | serial octets |
    //! |-----------------------------------------|--------------:|
    //! | leaf-rsa2047-365d-san-eku.der           |             3 |
    //! | leaf-p256-50d-post-sc081-100d.der       |            20 |
    //! | leaf-rsa2048-sha1.der                   |            20 |
    //!
    //! These values are the OS `openssl` reading of the certificate's
    //! `tbsCertificate.serialNumber` INTEGER content, independent of the
    //! code under test (which uses the `x509-cert` Rust crate's parser).
    //!
    //! Note on "21-octet" boundary: the `x509-cert` `SerialNumber::new`
    //! constructor refuses inputs longer than 20 bytes (`Overlength`
    //! error), and the `Rfc5280` Profile's decode-time check rejects
    //! anything beyond 21 bytes — so a real-world cert with a > 21-octet
    //! serial cannot be loaded through this stack at all. We exercise
    //! the lint's `> max_octets` branch by tightening the parameter (cap
    //! < the fixture's serial length) rather than constructing an
    //! oversize synthetic cert; the comparison is the same
    //! `len > self.max_octets` integer test either way.
    //!
    //! No test uses the code under test as its own oracle.

    use super::*;
    use x509_cert::Certificate;

    fn load_cert(name: &str) -> Certificate {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../pkix-path/tests/fixtures/policy-checks/")
            .join(name);
        let der =
            std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()));
        <Certificate as der::Decode>::from_der(&der)
            .unwrap_or_else(|e| panic!("decode fixture {name}: {e}"))
    }

    #[test]
    fn default_lint_accepts_20_octet_serial() {
        // Oracle: `openssl x509 -serial` on leaf-p256-50d-post-sc081-100d.der
        // reports 20 octets.
        let lint = Rfc5280MaxSerialLengthLint::default();
        assert_eq!(lint.max_octets(), 20);
        let cert = load_cert("leaf-p256-50d-post-sc081-100d.der");
        assert_eq!(cert.tbs_certificate.serial_number.as_bytes().len(), 20);
        assert_eq!(
            lint.check_cert(&cert, SubjectKind::Leaf, 0),
            LintResult::Pass
        );
    }

    #[test]
    fn default_lint_accepts_short_serial() {
        // Oracle: leaf-rsa2047-365d-san-eku.der has a 3-octet serial.
        let lint = Rfc5280MaxSerialLengthLint::default();
        let cert = load_cert("leaf-rsa2047-365d-san-eku.der");
        assert_eq!(cert.tbs_certificate.serial_number.as_bytes().len(), 3);
        assert_eq!(
            lint.check_cert(&cert, SubjectKind::Leaf, 0),
            LintResult::Pass
        );
    }

    #[test]
    fn tightened_cap_rejects_20_octet_serial_with_attribution() {
        // Tighten the cap below the fixture's 20-octet serial — same code
        // path as the RFC-baseline rejection of a hypothetical > 20-octet
        // serial, but constructible from real fixtures (see module-level
        // oracle note).
        let mut lint = Rfc5280MaxSerialLengthLint::default();
        lint.set_parameter("max-octets", "10")
            .expect("set_parameter ok");
        let cert = load_cert("leaf-rsa2048-sha1.der");
        assert_eq!(cert.tbs_certificate.serial_number.as_bytes().len(), 20);
        match lint.check_cert(&cert, SubjectKind::Leaf, 0) {
            LintResult::Error(detail) => {
                assert!(
                    detail.contains("20 octets"),
                    "error detail must name the actual length 20; got: {detail}"
                );
                assert!(
                    detail.contains("10 octets"),
                    "error detail must name the cap 10; got: {detail}"
                );
            }
            other => panic!("expected Error, got: {other:?}"),
        }
    }

    #[test]
    fn set_parameter_to_3_keeps_3_octet_serial_passing() {
        // Boundary case: a 3-octet serial must pass when the cap is set
        // to exactly 3. Verifies the comparison is `>` not `>=`.
        let mut lint = Rfc5280MaxSerialLengthLint::default();
        lint.set_parameter("max-octets", "3").expect("set ok");
        let cert = load_cert("leaf-rsa2047-365d-san-eku.der");
        assert_eq!(cert.tbs_certificate.serial_number.as_bytes().len(), 3);
        assert_eq!(
            lint.check_cert(&cert, SubjectKind::Leaf, 0),
            LintResult::Pass
        );
    }

    #[test]
    fn set_parameter_to_2_rejects_3_octet_serial() {
        // Tighten one octet below the fixture; expect Error with both
        // actual (3) and cap (2) reported.
        let mut lint = Rfc5280MaxSerialLengthLint::default();
        lint.set_parameter("max-octets", "2").expect("set ok");
        let cert = load_cert("leaf-rsa2047-365d-san-eku.der");
        match lint.check_cert(&cert, SubjectKind::Leaf, 0) {
            LintResult::Error(detail) => {
                assert!(detail.contains("3 octets"));
                assert!(detail.contains("2 octets"));
            }
            other => panic!("expected Error, got: {other:?}"),
        }
    }

    #[test]
    fn set_parameter_unknown_id_errors() {
        let mut lint = Rfc5280MaxSerialLengthLint::default();
        let err = lint
            .set_parameter("not-a-real-parameter", "1")
            .expect_err("unknown id must error");
        match err {
            ParameterError::UnknownParameter(id) => {
                assert_eq!(id, "not-a-real-parameter");
            }
            other => panic!("expected UnknownParameter, got: {other:?}"),
        }
    }

    #[test]
    fn set_parameter_invalid_value_errors() {
        let mut lint = Rfc5280MaxSerialLengthLint::default();
        // Non-numeric input.
        let err = lint
            .set_parameter("max-octets", "not-a-number")
            .expect_err("non-numeric value must error");
        match err {
            ParameterError::InvalidValue { id, .. } => assert_eq!(id, "max-octets"),
            other => panic!("expected InvalidValue, got: {other:?}"),
        }
        // Zero is rejected (a zero cap would reject every serialNumber,
        // including valid ones — almost certainly an operator typo).
        let err_zero = lint
            .set_parameter("max-octets", "0")
            .expect_err("zero value must error");
        match err_zero {
            ParameterError::InvalidValue { id, reason } => {
                assert_eq!(id, "max-octets");
                assert!(reason.contains("at least 1"));
            }
            other => panic!("expected InvalidValue, got: {other:?}"),
        }
    }

    #[test]
    fn parameters_advertises_max_octets() {
        let lint = Rfc5280MaxSerialLengthLint::default();
        let params = lint.parameters();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].id, "max-octets");
        assert_eq!(params[0].default_value, "20");
        assert!(!params[0].label.is_empty());
    }

    #[test]
    fn metadata_matches_rfc_section() {
        let lint = Rfc5280MaxSerialLengthLint::default();
        assert_eq!(lint.id(), "rfc5280.cert.serial_number.max_octets");
        assert_eq!(lint.citation(), "RFC 5280 §4.1.2.2");
        assert_eq!(lint.spec_section_id(), Some("rfc5280-4.1.2.2"));
        assert_eq!(
            lint.spec_url(),
            Some("https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.2")
        );
    }

    // -----------------------------------------------------------------------
    // Rfc5280BasicConstraintsCaLeafLint
    //
    // Oracle: `openssl x509 -text` reports cA flag for each fixture
    // (verified 2026-05-12):
    //
    // | fixture                              | BC.cA   | cert role |
    // |--------------------------------------|---------|-----------|
    // | leaf-p256-365d-san-eku.der           | FALSE   | leaf      |
    // | webpki-self-signed-365d.der          | TRUE    | self-CA   |
    // | smime-self-signed-365d.der           | TRUE    | self-CA   |
    // | codesign-self-signed-365d.der        | TRUE    | self-CA   |
    //
    // The CA-flagged fixtures are intentionally self-signed CA certs; we
    // exercise the lint by passing them with `SubjectKind::Leaf` to test
    // the lint's negative path, since no all-extensions-set leaf-with-CA
    // fixture exists. The lint's `check_cert` does not consult `kind`
    // beyond what the runner's `applies_to` filter does, so this is a
    // faithful test of the lint's logic.
    // -----------------------------------------------------------------------

    #[test]
    fn bc_ca_leaf_lint_accepts_normal_leaf() {
        let lint = Rfc5280BasicConstraintsCaLeafLint;
        let cert = load_cert("leaf-p256-365d-san-eku.der");
        assert_eq!(
            lint.check_cert(&cert, SubjectKind::Leaf, 0),
            LintResult::Pass
        );
    }

    #[test]
    fn bc_ca_leaf_lint_rejects_cert_with_ca_true() {
        let lint = Rfc5280BasicConstraintsCaLeafLint;
        // webpki-self-signed-365d.der has cA=TRUE; passed as Leaf, this
        // must trigger the lint's error path.
        let cert = load_cert("webpki-self-signed-365d.der");
        match lint.check_cert(&cert, SubjectKind::Leaf, 0) {
            LintResult::Error(detail) => {
                assert!(
                    detail.contains("cA=TRUE"),
                    "error detail must mention cA=TRUE; got: {detail}"
                );
            }
            other => panic!("expected Error, got: {other:?}"),
        }
    }

    #[test]
    fn bc_ca_leaf_lint_metadata_matches_rfc_section() {
        let lint = Rfc5280BasicConstraintsCaLeafLint;
        assert_eq!(lint.id(), "rfc5280.cert.bc.ca_false_for_leaf");
        assert_eq!(lint.citation(), "RFC 5280 §4.2.1.9");
        assert_eq!(lint.severity(), Severity::Error);
        assert_eq!(lint.scope(), Scope::Certificate);
        assert_eq!(lint.applies_to(), SubjectKind::Leaf);
        assert_eq!(lint.spec_section_id(), Some("rfc5280-4.2.1.9"));
        assert_eq!(
            lint.spec_url(),
            Some("https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.9")
        );
    }

    // -----------------------------------------------------------------------
    // Rfc5280EkuServerAuthLint
    //
    // Oracle: `openssl x509 -text` reports EKU for each fixture
    // (verified 2026-05-12):
    //
    // | fixture                              | EKU                      |
    // |--------------------------------------|--------------------------|
    // | leaf-p256-365d-san-eku.der           | TLS Web Server Auth      |
    // | leaf-p256-365d-no-eku.der            | (absent)                 |
    // | leaf-p256-365d-wrong-eku.der         | E-mail Protection        |
    // -----------------------------------------------------------------------

    #[test]
    fn eku_server_auth_lint_accepts_server_auth_eku() {
        let lint = Rfc5280EkuServerAuthLint;
        let cert = load_cert("leaf-p256-365d-san-eku.der");
        assert_eq!(
            lint.check_cert(&cert, SubjectKind::Leaf, 0),
            LintResult::Pass
        );
    }

    #[test]
    fn eku_server_auth_lint_rejects_missing_eku() {
        let lint = Rfc5280EkuServerAuthLint;
        let cert = load_cert("leaf-p256-365d-no-eku.der");
        match lint.check_cert(&cert, SubjectKind::Leaf, 0) {
            LintResult::Error(detail) => {
                assert!(
                    detail.contains("ExtendedKeyUsage extension absent"),
                    "error detail must mention missing EKU; got: {detail}"
                );
            }
            other => panic!("expected Error, got: {other:?}"),
        }
    }

    #[test]
    fn eku_server_auth_lint_rejects_wrong_eku() {
        let lint = Rfc5280EkuServerAuthLint;
        // leaf-p256-365d-wrong-eku.der has E-mail Protection but not Server Auth.
        let cert = load_cert("leaf-p256-365d-wrong-eku.der");
        match lint.check_cert(&cert, SubjectKind::Leaf, 0) {
            LintResult::Error(detail) => {
                assert!(
                    detail.contains("id-kp-serverAuth"),
                    "error detail must mention id-kp-serverAuth; got: {detail}"
                );
            }
            other => panic!("expected Error, got: {other:?}"),
        }
    }

    #[test]
    fn eku_server_auth_lint_metadata_matches_rfc_section() {
        let lint = Rfc5280EkuServerAuthLint;
        assert_eq!(lint.id(), "rfc5280.cert.eku.server_auth_required");
        assert_eq!(lint.citation(), "RFC 5280 §4.2.1.12");
        assert_eq!(lint.severity(), Severity::Error);
        assert_eq!(lint.scope(), Scope::Certificate);
        assert_eq!(lint.applies_to(), SubjectKind::Leaf);
        assert_eq!(lint.spec_section_id(), Some("rfc5280-4.2.1.12"));
        assert_eq!(
            lint.spec_url(),
            Some("https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.12")
        );
    }

    // -----------------------------------------------------------------------
    // Rfc5280SanRequiredWhenSubjectEmptyLint
    //
    // Oracle: `openssl x509 -text` reads Subject and SAN criticality for
    // each fixture (verified 2026-05-12):
    //
    // | fixture                              | Subject empty? | SAN ext? | SAN critical? |
    // |--------------------------------------|----------------|----------|---------------|
    // | leaf-p256-365d-san-eku.der           | no             | yes      | no            |
    // | leaf-p256-365d-no-san.der            | no             | no       | n/a           |
    // | smime-self-signed-365d.der           | no             | yes      | no            |
    //
    // No empty-subject fixture currently exists in the workspace. The
    // positive paths verified here are: (a) non-empty Subject + SAN
    // present → Pass (lint does not apply), (b) non-empty Subject + SAN
    // absent → Pass (still does not apply). The negative path (empty
    // Subject + missing-or-non-critical SAN → Error) requires fixture
    // generation (pyca/cryptography `Name([])` + matching SAN
    // configuration) and is filed as out-of-scope per the bead.
    // -----------------------------------------------------------------------

    #[test]
    fn san_required_when_subject_empty_passes_when_subject_present() {
        let lint = Rfc5280SanRequiredWhenSubjectEmptyLint;
        let cert = load_cert("leaf-p256-365d-san-eku.der");
        assert!(
            !cert.tbs_certificate.subject.is_empty(),
            "fixture must have a non-empty Subject for this test"
        );
        assert_eq!(
            lint.check_cert(&cert, SubjectKind::Leaf, 0),
            LintResult::Pass
        );
    }

    #[test]
    fn san_required_when_subject_empty_passes_with_no_san_when_subject_present() {
        // Lint must not fire on certs that have a non-empty Subject and
        // no SAN — those are out of scope for this RFC 5280 §4.2.1.6
        // clause (which is conditional on an empty Subject).
        let lint = Rfc5280SanRequiredWhenSubjectEmptyLint;
        let cert = load_cert("leaf-p256-365d-no-san.der");
        assert!(!cert.tbs_certificate.subject.is_empty());
        assert_eq!(
            lint.check_cert(&cert, SubjectKind::Leaf, 0),
            LintResult::Pass
        );
    }

    #[test]
    fn san_required_when_subject_empty_metadata_matches_rfc_section() {
        let lint = Rfc5280SanRequiredWhenSubjectEmptyLint;
        assert_eq!(lint.id(), "rfc5280.cert.san.required_when_subject_empty");
        assert_eq!(lint.citation(), "RFC 5280 §4.2.1.6");
        assert_eq!(lint.severity(), Severity::Error);
        assert_eq!(lint.scope(), Scope::Certificate);
        assert_eq!(lint.applies_to(), SubjectKind::Any);
        assert_eq!(lint.spec_section_id(), Some("rfc5280-4.2.1.6"));
        assert_eq!(
            lint.spec_url(),
            Some("https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.6")
        );
    }

    // -----------------------------------------------------------------------
    // Rfc5280SignatureAlgorithmMatchLint
    //
    // Oracle: `openssl asn1parse -i -in <fixture> -inform DER` reads both
    // the inner `tbsCertificate.signature` and outer `signatureAlgorithm`
    // SEQUENCEs. Well-formed certificates produced by OpenSSL and pyca
    // always have byte-identical outer/inner identifiers, including the
    // NULL parameters value for RSA-PKCS1 algorithms. Verified
    // 2026-05-12: all of the policy-checks/*.der fixtures pass the lint.
    //
    // The negative path (mismatched outer/inner) requires custom
    // DER-level synthesis since neither OpenSSL nor pyca will produce a
    // mismatched cert. Out of scope per the bead.
    // -----------------------------------------------------------------------

    #[test]
    fn signature_algorithm_match_passes_on_well_formed_rsa_fixture() {
        let lint = Rfc5280SignatureAlgorithmMatchLint;
        let cert = load_cert("leaf-rsa2048-365d-san-eku.der");
        assert_eq!(
            lint.check_cert(&cert, SubjectKind::Any, 0),
            LintResult::Pass
        );
    }

    #[test]
    fn signature_algorithm_match_passes_on_well_formed_ecdsa_fixture() {
        let lint = Rfc5280SignatureAlgorithmMatchLint;
        let cert = load_cert("leaf-p256-365d-san-eku.der");
        assert_eq!(
            lint.check_cert(&cert, SubjectKind::Any, 0),
            LintResult::Pass
        );
    }

    #[test]
    fn signature_algorithm_match_metadata_matches_rfc_section() {
        let lint = Rfc5280SignatureAlgorithmMatchLint;
        assert_eq!(lint.id(), "rfc5280.cert.signature_algorithm_match");
        assert_eq!(lint.citation(), "RFC 5280 §4.1.1.2");
        assert_eq!(lint.severity(), Severity::Error);
        assert_eq!(lint.scope(), Scope::Certificate);
        assert_eq!(lint.applies_to(), SubjectKind::Any);
        assert_eq!(lint.spec_section_id(), Some("rfc5280-4.1.1.2"));
        assert_eq!(
            lint.spec_url(),
            Some("https://www.rfc-editor.org/rfc/rfc5280#section-4.1.1.2")
        );
    }
}
