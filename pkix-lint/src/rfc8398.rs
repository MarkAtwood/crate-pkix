//! RFC 8398 conformance lints.
//!
//! This module ships [`Lint`] implementations that enforce structural and
//! semantic rules from [RFC 8398][rfc8398] — Internationalized Email
//! Addresses in X.509 Certificates.
//!
//! Each lint is keyed by an OSCAL Control-id-shaped identifier
//! (`rfc8398-<section>`) and cites the relevant section in its rustdoc.
//!
//! [rfc8398]: https://www.rfc-editor.org/rfc/rfc8398
//!
//! # Provenance
//!
//! Added in PKIX-9vnx.9.2.1 to provide RFC-conformance shape checks for
//! the `BasicSmimeProfile` shipped in `pkix-profiles`. The RFC 8398
//! requirements layer on top of the older RFC 5280 §4.2.1.6 rfc822Name
//! SAN handling to admit UTF-8 mailbox addresses for S/MIME.

use der::{asn1::ObjectIdentifier, Decode as _};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::Certificate;

use crate::{Lint, LintResult, Scope, Severity, SubjectKind};

// ---------------------------------------------------------------------------
// OID constants
// ---------------------------------------------------------------------------

/// `SubjectAltName` extension OID — RFC 5280 §4.2.1.6.
const OID_SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");

/// `id-on-SmtpUTF8Mailbox` `OtherName` type-id — RFC 8398 §3.
const ID_ON_SMTP_UTF8_MAILBOX: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.8.9");

// ---------------------------------------------------------------------------
// rfc8398.cert.san.smime_mailbox_required
// ---------------------------------------------------------------------------

/// RFC 8398 §3 + RFC 5280 §4.2.1.6: S/MIME certificates MUST carry a
/// `subjectAltName` containing at least one `rfc822Name` entry or an
/// `otherName` of type `id-on-SmtpUTF8Mailbox`.
///
/// > [...] this document specifies a new name form for inclusion in the
/// > otherName field of GeneralName.  The new name form represents a
/// > native UTF-8 mailbox address used to convey an internationalized
/// > email address.
///
/// The two SAN encodings are equivalent for S/MIME identity-binding
/// purposes: an `rfc822Name` carries an ASCII mailbox address, an
/// `otherName{id-on-SmtpUTF8Mailbox}` carries a UTF-8 mailbox address.
/// Either is sufficient; both may appear (see RFC 8398 §3 for the
/// "MUST be equivalent if both present" rule — checked in a separate
/// lint).
///
/// # Behavior
///
/// - `SubjectAltName` extension absent → `Error`.
/// - `SubjectAltName` present with no entries → `Error`.
/// - `SubjectAltName` present but no `rfc822Name` or `id-on-SmtpUTF8Mailbox`
///   `otherName` entry → `Error`.
/// - `SubjectAltName` present with at least one such entry → `Pass`.
/// - `SubjectAltName` extension value is malformed → `Error`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Rfc8398SmimeSanLint;

impl Lint for Rfc8398SmimeSanLint {
    fn id(&self) -> &'static str {
        "rfc8398.cert.san.smime_mailbox_required"
    }

    fn citation(&self) -> &'static str {
        "RFC 8398 §3 (+ RFC 5280 §4.2.1.6)"
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
        "S/MIME certificate must include SAN rfc822Name or SmtpUTF8Mailbox"
    }

    fn spec_section_id(&self) -> Option<&str> {
        Some("rfc8398-3")
    }

    fn spec_url(&self) -> Option<&str> {
        Some("https://www.rfc-editor.org/rfc/rfc8398#section-3")
    }

    fn check_cert(&self, cert: &Certificate, _kind: SubjectKind, _now_unix: u64) -> LintResult {
        let Some(extensions) = &cert.tbs_certificate.extensions else {
            return LintResult::error("leaf certificate has no extensions; SubjectAltName absent");
        };

        let Some(san_ext) = extensions
            .iter()
            .find(|e| e.extn_id == OID_SUBJECT_ALT_NAME)
        else {
            return LintResult::error(
                "SubjectAltName extension absent from leaf certificate; RFC 8398 §3 \
                 requires an rfc822Name or id-on-SmtpUTF8Mailbox otherName entry",
            );
        };

        let san =
            match x509_cert::ext::pkix::SubjectAltName::from_der(san_ext.extn_value.as_bytes()) {
                Ok(san) => san,
                Err(_) => {
                    return LintResult::error("SubjectAltName extension value is malformed DER");
                }
            };

        if san.0.is_empty() {
            return LintResult::error("SubjectAltName extension is present but contains no names");
        }

        let has_mailbox = san.0.iter().any(|gn| match gn {
            GeneralName::Rfc822Name(_) => true,
            GeneralName::OtherName(on) => on.type_id == ID_ON_SMTP_UTF8_MAILBOX,
            _ => false,
        });

        if has_mailbox {
            LintResult::Pass
        } else {
            LintResult::error(
                "SubjectAltName does not contain an rfc822Name or id-on-SmtpUTF8Mailbox \
                 otherName; RFC 8398 §3 requires at least one for S/MIME identity",
            )
        }
    }
}

#[cfg(test)]
mod tests {
    //! Independent oracle for SAN content (verified 2026-05-12 via
    //! `openssl x509 -text`):
    //!
    //! | fixture                              | SAN content              |
    //! |--------------------------------------|--------------------------|
    //! | smime-self-signed-365d.der           | email:test@example.com   |
    //! | leaf-p256-365d-no-san.der            | (SAN extension absent)   |
    //! | leaf-p256-365d-san-eku.der           | DNS:test.example.com     |

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
    fn smime_san_lint_accepts_rfc822_san() {
        let lint = Rfc8398SmimeSanLint;
        let cert = load_cert("smime-self-signed-365d.der");
        assert_eq!(
            lint.check_cert(&cert, SubjectKind::Leaf, 0),
            LintResult::Pass
        );
    }

    #[test]
    fn smime_san_lint_rejects_missing_san() {
        let lint = Rfc8398SmimeSanLint;
        let cert = load_cert("leaf-p256-365d-no-san.der");
        match lint.check_cert(&cert, SubjectKind::Leaf, 0) {
            LintResult::Error(detail) => {
                assert!(
                    detail.contains("SubjectAltName extension absent"),
                    "error detail must mention missing SAN; got: {detail}"
                );
            }
            other => panic!("expected Error, got: {other:?}"),
        }
    }

    #[test]
    fn smime_san_lint_rejects_san_without_mailbox() {
        let lint = Rfc8398SmimeSanLint;
        // leaf-p256-365d-san-eku.der has only DNS in SAN — no rfc822Name,
        // no otherName SmtpUTF8Mailbox.
        let cert = load_cert("leaf-p256-365d-san-eku.der");
        match lint.check_cert(&cert, SubjectKind::Leaf, 0) {
            LintResult::Error(detail) => {
                assert!(
                    detail.contains("rfc822Name") || detail.contains("SmtpUTF8Mailbox"),
                    "error detail must name the required SAN types; got: {detail}"
                );
            }
            other => panic!("expected Error, got: {other:?}"),
        }
    }

    #[test]
    fn smime_san_lint_metadata_matches_rfc_section() {
        let lint = Rfc8398SmimeSanLint;
        assert_eq!(lint.id(), "rfc8398.cert.san.smime_mailbox_required");
        assert_eq!(lint.citation(), "RFC 8398 §3 (+ RFC 5280 §4.2.1.6)");
        assert_eq!(lint.severity(), Severity::Error);
        assert_eq!(lint.scope(), Scope::Certificate);
        assert_eq!(lint.applies_to(), SubjectKind::Leaf);
        assert_eq!(lint.spec_section_id(), Some("rfc8398-3"));
        assert_eq!(
            lint.spec_url(),
            Some("https://www.rfc-editor.org/rfc/rfc8398#section-3")
        );
    }
}
