//! RFC 6125 conformance lints.
//!
//! This module ships [`Lint`] implementations that enforce structural and
//! semantic rules from [RFC 6125][rfc6125] — Representation and Verification
//! of Domain-Based Application Service Identity within Internet Public Key
//! Infrastructure Using X.509 (PKIX) Certificates in the Context of
//! Transport Layer Security (TLS).
//!
//! Each lint is keyed by an OSCAL Control-id-shaped identifier
//! (`rfc6125-<section>`) and cites the relevant section in its rustdoc.
//!
//! [rfc6125]: https://www.rfc-editor.org/rfc/rfc6125
//!
//! # Provenance
//!
//! Added in PKIX-9vnx.9.2.1 to provide RFC-conformance shape checks for
//! the `BasicTlsProfile` shipped in `pkix-profiles`. CA/B-Forum-shaped
//! variants of these checks live in
//! [`pkix-lint-cabf::cabf_tls_br`][cabf_tls_br].
//!
//! [cabf_tls_br]: https://docs.rs/pkix-lint-cabf/latest/pkix_lint_cabf/cabf_tls_br/

use der::{asn1::ObjectIdentifier, Decode as _};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::Certificate;

use crate::{Lint, LintResult, Scope, Severity, SubjectKind};

// ---------------------------------------------------------------------------
// OID constants
// ---------------------------------------------------------------------------

/// `SubjectAltName` extension OID — RFC 5280 §4.2.1.6.
const OID_SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");

// ---------------------------------------------------------------------------
// rfc6125.cert.san.tls_server_dns_or_ip_required
// ---------------------------------------------------------------------------

/// RFC 6125 §6.4.1: TLS server certificates MUST carry a `subjectAltName`
/// containing at least one `dNSName` or `iPAddress` entry.
///
/// > As noted, a client MUST NOT seek a match for a reference identifier
/// > of CN-ID if the presented identifiers include a DNS-ID, SRV-ID,
/// > URI-ID, or any application-specific identifier types supported by
/// > the client.
///
/// Combined with the obsoleting of the `commonName`-as-DNS-name practice
/// in §6.4.4, this makes a `dNSName`/`iPAddress` SAN entry the only
/// reliable way to bind a TLS server certificate to its service identity.
///
/// This is the RFC-conformance variant of the CA/B Forum
/// [`cabf.br.tls.san.required`][cabf-san] lint, which requires the SAN
/// extension to be present with at least one entry. RFC 6125 tightens
/// this by additionally requiring at least one entry to be a `dNSName`
/// or `iPAddress` (the identifier types relevant to TLS server identity
/// matching).
///
/// [cabf-san]: https://docs.rs/pkix-lint-cabf/latest/pkix_lint_cabf/cabf_tls_br/struct.SanRequiredLint.html
///
/// # Behavior
///
/// - `SubjectAltName` extension absent → `Error`.
/// - `SubjectAltName` present with no entries → `Error`.
/// - `SubjectAltName` present but no `dNSName` or `iPAddress` entry → `Error`.
/// - `SubjectAltName` present with at least one `dNSName` or `iPAddress`
///   entry → `Pass`.
/// - `SubjectAltName` extension value is malformed → `Error`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Rfc6125TlsServerSanLint;

impl Lint for Rfc6125TlsServerSanLint {
    fn id(&self) -> &'static str {
        "rfc6125.cert.san.tls_server_dns_or_ip_required"
    }

    fn citation(&self) -> &'static str {
        "RFC 6125 §6.4.1"
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
        "TLS server certificate must include SAN dNSName or iPAddress"
    }

    fn spec_section_id(&self) -> Option<&str> {
        Some("rfc6125-6.4.1")
    }

    fn spec_url(&self) -> Option<&str> {
        Some("https://www.rfc-editor.org/rfc/rfc6125#section-6.4.1")
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
                "SubjectAltName extension absent from leaf certificate; RFC 6125 §6.4.1 \
                 requires a dNSName or iPAddress entry",
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

        let has_dns_or_ip = san
            .0
            .iter()
            .any(|gn| matches!(gn, GeneralName::DnsName(_) | GeneralName::IpAddress(_)));

        if has_dns_or_ip {
            LintResult::Pass
        } else {
            LintResult::error(
                "SubjectAltName does not contain a dNSName or iPAddress entry; \
                 RFC 6125 §6.4.1 requires at least one for TLS server identity",
            )
        }
    }
}

#[cfg(test)]
mod tests {
    //! Independent oracle for SAN content: `openssl x509 -text` reports
    //! the SAN GeneralName types for each fixture (verified 2026-05-12):
    //!
    //! | fixture                              | SAN content              |
    //! |--------------------------------------|--------------------------|
    //! | leaf-p256-365d-san-eku.der           | DNS:test.example.com     |
    //! | leaf-p256-365d-no-san.der            | (SAN extension absent)   |
    //! | smime-self-signed-365d.der           | email:test@example.com   |
    //!
    //! `smime-self-signed-365d.der` is the negative case for the "no
    //! dNSName or iPAddress entry" branch: the SAN extension is present
    //! and non-empty, but contains only an rfc822Name. This is a CA cert
    //! (cA=TRUE) used as a leaf-shape negative; the lint's `check_cert`
    //! does not consult `kind` beyond what the runner's `applies_to`
    //! filter does, so this is a faithful test of the lint's logic.

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
    fn tls_server_san_lint_accepts_dns_san() {
        let lint = Rfc6125TlsServerSanLint;
        let cert = load_cert("leaf-p256-365d-san-eku.der");
        assert_eq!(
            lint.check_cert(&cert, SubjectKind::Leaf, 0),
            LintResult::Pass
        );
    }

    #[test]
    fn tls_server_san_lint_rejects_missing_san() {
        let lint = Rfc6125TlsServerSanLint;
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
    fn tls_server_san_lint_rejects_san_without_dns_or_ip() {
        let lint = Rfc6125TlsServerSanLint;
        // smime-self-signed-365d.der has only rfc822Name in SAN — no
        // dNSName, no iPAddress.
        let cert = load_cert("smime-self-signed-365d.der");
        match lint.check_cert(&cert, SubjectKind::Leaf, 0) {
            LintResult::Error(detail) => {
                assert!(
                    detail.contains("dNSName") || detail.contains("iPAddress"),
                    "error detail must name the required SAN types; got: {detail}"
                );
            }
            other => panic!("expected Error, got: {other:?}"),
        }
    }

    #[test]
    fn tls_server_san_lint_metadata_matches_rfc_section() {
        let lint = Rfc6125TlsServerSanLint;
        assert_eq!(lint.id(), "rfc6125.cert.san.tls_server_dns_or_ip_required");
        assert_eq!(lint.citation(), "RFC 6125 §6.4.1");
        assert_eq!(lint.severity(), Severity::Error);
        assert_eq!(lint.scope(), Scope::Certificate);
        assert_eq!(lint.applies_to(), SubjectKind::Leaf);
        assert_eq!(lint.spec_section_id(), Some("rfc6125-6.4.1"));
        assert_eq!(
            lint.spec_url(),
            Some("https://www.rfc-editor.org/rfc/rfc6125#section-6.4.1")
        );
    }
}
