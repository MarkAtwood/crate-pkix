//! RFC 8551 conformance lints.
//!
//! This module ships [`Lint`] implementations that enforce structural and
//! semantic rules from [RFC 8551][rfc8551] — Secure/Multipurpose Internet
//! Mail Extensions (S/MIME) Version 4.0 Message Specification.
//!
//! Each lint is keyed by an OSCAL Control-id-shaped identifier
//! (`rfc8551-<section>`) and cites the relevant section in its rustdoc.
//!
//! [rfc8551]: https://www.rfc-editor.org/rfc/rfc8551
//!
//! # Provenance
//!
//! Added in PKIX-9vnx.9.2.1 to provide RFC-conformance shape checks for
//! the `BasicSmimeProfile` shipped in `pkix-profiles`. RFC 8551 §3.3
//! defines the `id-kp-emailProtection` EKU requirement for S/MIME signer
//! and recipient certificates; that EKU is the universally-required
//! purpose marker for S/MIME identity, mirroring `id-kp-serverAuth` in
//! the TLS server context.

use der::{asn1::ObjectIdentifier, Decode as _};
use x509_cert::Certificate;

use crate::{Lint, LintResult, Scope, Severity, SubjectKind};

// ---------------------------------------------------------------------------
// OID constants
// ---------------------------------------------------------------------------

/// `ExtendedKeyUsage` extension OID — RFC 5280 §4.2.1.12.
const OID_EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");

/// id-kp-emailProtection — RFC 5280 §4.2.1.12 (email protection).
const ID_KP_EMAIL_PROTECTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.4");

// ---------------------------------------------------------------------------
// rfc8551.cert.eku.email_protection_required
// ---------------------------------------------------------------------------

/// RFC 5280 §4.2.1.12 + RFC 8551 §3.3: S/MIME certificates MUST assert
/// `id-kp-emailProtection` in `ExtendedKeyUsage`.
///
/// > -- Email protection
/// > -- Key usage bits that may be consistent: digitalSignature,
/// > -- nonRepudiation, and/or (keyEncipherment or keyAgreement)
/// > id-kp-emailProtection        OBJECT IDENTIFIER ::= { id-kp 4 }
///
/// RFC 8551 §3.3 ("Identifying the Originator and Recipients of S/MIME
/// Messages") cites the RFC 5280 EKU mechanism for binding a cert to
/// S/MIME usage. This lint is the RFC-conformance analog of
/// [`crate::rfc5280::Rfc5280EkuServerAuthLint`] for the S/MIME use case.
///
/// # Use-case applicability — operator contract
///
/// This lint is **use-case specific** to S/MIME certificates. It asserts
/// a property RFC 8551 §3.3 requires of S/MIME certs and **only** S/MIME
/// certs. Registering it against arbitrary leaves produces false-positive
/// `Error` findings on TLS server, code-signing, OCSP-responder, or any
/// other non-S/MIME end-entity certificate.
///
/// **Operators MUST register this lint only through a use-case-specific
/// [`LintProfile`][crate::LintProfile] that bundles it with other S/MIME
/// lints (`Rfc8398SmimeSanLint` etc.).** `pkix_profiles::BasicSmimeProfile`
/// is the canonical bundler. See [`crate::Lint`] trait rustdoc for the
/// contract.
///
/// # Behavior
///
/// - `ExtendedKeyUsage` extension absent → `Error`.
/// - `ExtendedKeyUsage` present and contains `id-kp-emailProtection` → `Pass`.
/// - `ExtendedKeyUsage` present but does not contain `id-kp-emailProtection`
///   → `Error`.
/// - `ExtendedKeyUsage` extension value is malformed → `Error`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Rfc8551EkuEmailProtectionLint;

impl Lint for Rfc8551EkuEmailProtectionLint {
    fn id(&self) -> &'static str {
        "rfc8551.cert.eku.email_protection_required"
    }

    fn citation(&self) -> &'static str {
        "RFC 8551 §3.3 (+ RFC 5280 §4.2.1.12)"
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
        "S/MIME certificate must include id-kp-emailProtection EKU"
    }

    fn spec_section_id(&self) -> Option<&str> {
        Some("rfc8551-3.3")
    }

    fn spec_url(&self) -> Option<&str> {
        Some("https://www.rfc-editor.org/rfc/rfc8551#section-3.3")
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
                if eku.0.contains(&ID_KP_EMAIL_PROTECTION) {
                    LintResult::Pass
                } else {
                    LintResult::error(
                        "ExtendedKeyUsage does not include id-kp-emailProtection \
                         (1.3.6.1.5.5.7.3.4)",
                    )
                }
            }
            Err(_) => LintResult::error("ExtendedKeyUsage extension value is malformed DER"),
        }
    }
}

#[cfg(test)]
mod tests {
    //! Independent oracle for EKU content (verified 2026-05-12 via
    //! `openssl x509 -text`):
    //!
    //! | fixture                              | EKU                      |
    //! |--------------------------------------|--------------------------|
    //! | smime-self-signed-365d.der           | E-mail Protection        |
    //! | leaf-p256-365d-wrong-eku.der         | E-mail Protection        |
    //! | leaf-p256-365d-no-eku.der            | (EKU absent)             |
    //! | leaf-p256-365d-san-eku.der           | TLS Web Server Auth      |
    //!
    //! Both `smime-self-signed-365d.der` and `leaf-p256-365d-wrong-eku.der`
    //! carry `E-mail Protection` EKU; the latter exists because in the
    //! TLS-server-auth context an emailProtection EKU is "wrong", but it
    //! is "right" for the S/MIME context. Both are valid positive cases
    //! for this lint.

    use super::*;

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
    fn email_protection_lint_accepts_email_protection_eku() {
        let lint = Rfc8551EkuEmailProtectionLint;
        let cert = load_cert("smime-self-signed-365d.der");
        assert_eq!(
            lint.check_cert(&cert, SubjectKind::Leaf, 0),
            LintResult::Pass
        );
    }

    #[test]
    fn email_protection_lint_accepts_wrong_eku_fixture() {
        // leaf-p256-365d-wrong-eku.der has emailProtection EKU — positive
        // for this lint (it's "wrong" relative to TLS server auth, not
        // relative to S/MIME).
        let lint = Rfc8551EkuEmailProtectionLint;
        let cert = load_cert("leaf-p256-365d-wrong-eku.der");
        assert_eq!(
            lint.check_cert(&cert, SubjectKind::Leaf, 0),
            LintResult::Pass
        );
    }

    #[test]
    fn email_protection_lint_rejects_missing_eku() {
        let lint = Rfc8551EkuEmailProtectionLint;
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
    fn email_protection_lint_rejects_server_auth_only() {
        let lint = Rfc8551EkuEmailProtectionLint;
        // leaf-p256-365d-san-eku.der has serverAuth EKU only — must reject.
        let cert = load_cert("leaf-p256-365d-san-eku.der");
        match lint.check_cert(&cert, SubjectKind::Leaf, 0) {
            LintResult::Error(detail) => {
                assert!(
                    detail.contains("id-kp-emailProtection"),
                    "error detail must mention id-kp-emailProtection; got: {detail}"
                );
            }
            other => panic!("expected Error, got: {other:?}"),
        }
    }

    #[test]
    fn email_protection_lint_metadata_matches_rfc_section() {
        let lint = Rfc8551EkuEmailProtectionLint;
        assert_eq!(lint.id(), "rfc8551.cert.eku.email_protection_required");
        assert_eq!(lint.citation(), "RFC 8551 §3.3 (+ RFC 5280 §4.2.1.12)");
        assert_eq!(lint.severity(), Severity::Error);
        assert_eq!(lint.scope(), Scope::Certificate);
        assert_eq!(lint.applies_to(), SubjectKind::Leaf);
        assert_eq!(lint.spec_section_id(), Some("rfc8551-3.3"));
        assert_eq!(
            lint.spec_url(),
            Some("https://www.rfc-editor.org/rfc/rfc8551#section-3.3")
        );
    }
}
