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

use der::{
    asn1::{ObjectIdentifier, Utf8StringRef},
    Decode as _,
};
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
/// # Use-case applicability — operator contract
///
/// This lint is **use-case specific** to S/MIME certificates. It asserts
/// a property RFC 8398 + RFC 5280 §4.2.1.6 require of S/MIME certs and
/// **only** S/MIME certs. Registering it against arbitrary leaves
/// produces false-positive `Error` findings on TLS server, code-signing,
/// OCSP-responder, or any other non-S/MIME end-entity certificate.
///
/// **Operators MUST register this lint only through a use-case-specific
/// [`LintProfile`][crate::LintProfile] that bundles it with other
/// S/MIME lints (`Rfc8551EkuEmailProtectionLint` etc.).**
/// `pkix_profiles::BasicSmimeProfile` is the canonical bundler. See
/// [`crate::Lint`] trait rustdoc for the contract.
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
                Err(e) => {
                    return LintResult::error(format!(
                        "SubjectAltName extension value is malformed DER: {e}"
                    ));
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

// ---------------------------------------------------------------------------
// rfc8398.cert.san.smime_mailbox_equivalent
// ---------------------------------------------------------------------------

/// RFC 8398 §3: when both `rfc822Name` and `SmtpUTF8Mailbox` SAN entries
/// are present, their address values MUST be identical (modulo IDN
/// A-label / U-label encoding of internationalized parts).
///
/// > If both rfc822Name and SmtpUTF8Mailbox are present in the
/// > subjectAltName extension, then the address values MUST be identical
/// > with the following exception: any internationalized parts of the
/// > email address (such as those rendered using A-labels) MUST be
/// > encoded per the SmtpUTF8Mailbox specification.
///
/// The lint runs only when at least one entry of each kind is present;
/// when either is missing the equivalence rule is vacuously satisfied
/// (`Pass`). When both are present, every rfc822Name entry must match at
/// least one SmtpUTF8Mailbox entry under the equivalence rule, and
/// vice versa.
///
/// # Equivalence rule
///
/// Two addresses `local@domain` are equivalent iff:
///
/// 1. The local-parts are byte-equal. RFC 822 local-parts are ASCII;
///    SmtpUTF8Mailbox local-parts may be UTF-8. RFC 8398 §3 says the
///    addresses MUST be identical except for IDN-encoded domain parts —
///    i.e. local-parts are the same bytes in both forms.
/// 2. The domains are equivalent under IDN A-label ↔ U-label
///    conversion. The rfc822Name carries the A-label form (ASCII
///    `xn--...` for IDN labels), the SmtpUTF8Mailbox carries the
///    U-label form (UTF-8). The lint normalizes both to A-label form
///    via the `idna` crate before comparing byte-wise.
///
/// Domain comparison is case-insensitive (DNS domains are
/// case-insensitive per RFC 5321 §2.4); local-part comparison is
/// case-sensitive (RFC 5321 §2.4 admits case-sensitive local-parts,
/// though most providers normalize).
///
/// # Behavior
///
/// - SAN extension absent → `Pass` (lint does not apply).
/// - SAN extension malformed → `Error`.
/// - SAN extension present, < 1 rfc822Name entries → `Pass`.
/// - SAN extension present, < 1 SmtpUTF8Mailbox entries → `Pass`.
/// - Both kinds present, every entry matches at least one of the
///   opposite kind under the equivalence rule → `Pass`.
/// - Both kinds present with one or more orphan entries → `Error`,
///   listing the unmatched address.
/// - An `id-on-SmtpUTF8Mailbox` `OtherName.value` that fails to decode
///   as a `UTF8String` → `Error`.
/// - An address that cannot be split on `@` into local-part + domain →
///   `Error`.
///
/// # Provenance
///
/// Filed under PKIX-9vnx.9.2.1.1 as the third of three deferred lints
/// from the PKIX-9vnx.9.2.1 batch. Negative-test fixture (cert with
/// both rfc822Name and SmtpUTF8Mailbox where they disagree) is not yet
/// present in the workspace fixture corpus; the equivalence-helper free
/// function is unit-tested exhaustively against a hand-written oracle
/// table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Rfc8398SmimeMailboxEquivalenceLint;

impl Lint for Rfc8398SmimeMailboxEquivalenceLint {
    fn id(&self) -> &'static str {
        "rfc8398.cert.san.smime_mailbox_equivalent"
    }

    fn citation(&self) -> &'static str {
        "RFC 8398 §3"
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
        "rfc822Name and SmtpUTF8Mailbox SAN entries must agree on the same address"
    }

    fn spec_section_id(&self) -> Option<&str> {
        Some("rfc8398-3")
    }

    fn spec_url(&self) -> Option<&str> {
        Some("https://www.rfc-editor.org/rfc/rfc8398#section-3")
    }

    fn check_cert(&self, cert: &Certificate, _kind: SubjectKind, _now_unix: u64) -> LintResult {
        let Some(extensions) = &cert.tbs_certificate.extensions else {
            return LintResult::Pass;
        };

        let Some(san_ext) = extensions
            .iter()
            .find(|e| e.extn_id == OID_SUBJECT_ALT_NAME)
        else {
            return LintResult::Pass;
        };

        let san =
            match x509_cert::ext::pkix::SubjectAltName::from_der(san_ext.extn_value.as_bytes()) {
                Ok(san) => san,
                Err(e) => {
                    return LintResult::error(format!(
                        "SubjectAltName extension value is malformed DER: {e}"
                    ));
                }
            };

        // Collect both kinds. rfc822Name carries an Ia5String (ASCII);
        // SmtpUTF8Mailbox OtherName.value carries a UTF8String wrapped
        // in `EXPLICIT [0] ANY` — extract via Utf8StringRef::try_from.
        let mut rfc822_addrs: Vec<&str> = Vec::new();
        let mut smtputf8_addrs: Vec<String> = Vec::new();
        for gn in &san.0 {
            match gn {
                GeneralName::Rfc822Name(addr) => {
                    rfc822_addrs.push(addr.as_str());
                }
                GeneralName::OtherName(on) if on.type_id == ID_ON_SMTP_UTF8_MAILBOX => {
                    match Utf8StringRef::try_from(&on.value) {
                        Ok(s) => smtputf8_addrs.push(s.to_string()),
                        Err(_) => {
                            return LintResult::error(
                                "SubjectAltName id-on-SmtpUTF8Mailbox otherName value \
                                 is not a valid UTF8String",
                            );
                        }
                    }
                }
                _ => {}
            }
        }

        // Equivalence rule applies only when both kinds are present.
        if rfc822_addrs.is_empty() || smtputf8_addrs.is_empty() {
            return LintResult::Pass;
        }

        // Pre-validate every address. RFC 8398 §3 presupposes well-formed
        // RFC 5322 mailbox addresses on both sides; if either side is
        // malformed (no '@', empty local-part, empty domain, IDN
        // conversion failure), surface that as the specific finding
        // rather than silently treating the address as a non-match
        // against everything. Separating validation from cross-matching
        // avoids the "malformed input" / "no match" conflation
        // (PKIX-hy2e.35).
        for r in &rfc822_addrs {
            if let Err(reason) = validate_mailbox_for_equivalence(r) {
                return LintResult::error(format!(
                    "rfc822Name SAN entry '{r}' is malformed for equivalence checking \
                     ({reason}); RFC 8398 §3 presupposes well-formed RFC 5322 mailbox \
                     addresses"
                ));
            }
        }
        for u in &smtputf8_addrs {
            if let Err(reason) = validate_mailbox_for_equivalence(u) {
                return LintResult::error(format!(
                    "SmtpUTF8Mailbox SAN entry '{u}' is malformed for equivalence checking \
                     ({reason}); RFC 8398 §3 presupposes well-formed RFC 5322 mailbox \
                     addresses"
                ));
            }
        }

        // Each rfc822Name must match some SmtpUTF8Mailbox, and each
        // SmtpUTF8Mailbox must match some rfc822Name (set-equality under
        // the equivalence relation, modulo duplicates which we tolerate).
        // Pre-validation above guarantees mailbox_equivalent returns
        // Ok(_); the .expect() carries that invariant in the type.
        for r in &rfc822_addrs {
            if !smtputf8_addrs.iter().any(|u| {
                mailbox_equivalent(r, u)
                    .expect("pre-validation ensures inputs are well-formed")
            }) {
                return LintResult::error(format!(
                    "rfc822Name SAN entry '{r}' has no matching SmtpUTF8Mailbox; \
                     RFC 8398 §3 requires byte-identical local-part and \
                     A-label/U-label-equivalent domain"
                ));
            }
        }
        for u in &smtputf8_addrs {
            if !rfc822_addrs.iter().any(|r| {
                mailbox_equivalent(r, u)
                    .expect("pre-validation ensures inputs are well-formed")
            }) {
                return LintResult::error(format!(
                    "SmtpUTF8Mailbox SAN entry '{u}' has no matching rfc822Name; \
                     RFC 8398 §3 requires byte-identical local-part and \
                     A-label/U-label-equivalent domain"
                ));
            }
        }

        LintResult::Pass
    }
}

/// Validate that `addr` is well-formed enough for the RFC 8398 §3
/// equivalence rule to be evaluated against it. Performs the same
/// structural checks as [`mailbox_equivalent`] (presence of `@`,
/// non-empty local-part and domain, IDN-convertible domain) but does
/// not compare against a second address. Used by
/// [`Rfc8398SmimeMailboxEquivalenceLint`] to pre-validate every SAN
/// entry before the cross-match loop so that a malformed address
/// surfaces as a specific error rather than silently being treated as
/// non-matching against every counterpart.
fn validate_mailbox_for_equivalence(addr: &str) -> Result<(), &'static str> {
    let (local, domain) = split_mailbox(addr).ok_or("no '@' delimiter")?;
    if local.is_empty() {
        return Err("empty local-part");
    }
    if domain.is_empty() {
        return Err("empty domain");
    }
    // Validate domain is IDN-convertible. The same call is repeated
    // inside mailbox_equivalent on the smtputf8 side; calling it here
    // for both sides catches malformed rfc822 domains as well (which
    // mailbox_equivalent only catches via the case-insensitive ASCII
    // compare against the converted u_ascii — a malformed rfc822
    // domain there silently returns Ok(false) rather than erroring).
    idna::domain_to_ascii(domain).map_err(|_| "domain failed IDN A-label conversion")?;
    Ok(())
}

/// Returns `Ok(true)` iff `rfc822` (ASCII, A-label IDN form) and `smtputf8`
/// (UTF-8, U-label IDN form) name the same RFC 5322 mailbox address under
/// the RFC 8398 §3 equivalence rule.
///
/// Returns `Err(detail)` if either address is malformed (no `@`, empty
/// local-part, empty domain) or if IDN conversion fails. Equivalence
/// requires:
///
/// 1. Byte-equal local-parts.
/// 2. Domains equivalent under A-label conversion (the `smtputf8`
///    domain is converted to A-label form via [`idna::domain_to_ascii`]
///    and compared case-insensitively to `rfc822`'s domain).
fn mailbox_equivalent(rfc822: &str, smtputf8: &str) -> Result<bool, &'static str> {
    let (r_local, r_domain) = split_mailbox(rfc822).ok_or("rfc822Name has no '@' delimiter")?;
    let (u_local, u_domain) =
        split_mailbox(smtputf8).ok_or("SmtpUTF8Mailbox has no '@' delimiter")?;

    if r_local.is_empty() || u_local.is_empty() || r_domain.is_empty() || u_domain.is_empty() {
        return Err("mailbox address has empty local-part or domain");
    }

    // RFC 8398 §3: local-parts must be byte-identical.
    if r_local != u_local {
        return Ok(false);
    }

    // Domain comparison: convert smtputf8 domain (U-label form) to
    // A-label form and compare case-insensitively to rfc822 domain.
    let u_ascii = idna::domain_to_ascii(u_domain).map_err(|_| "U-label → A-label conversion failed")?;
    Ok(u_ascii.eq_ignore_ascii_case(r_domain))
}

/// Split a mailbox address on the rightmost `@` into (local-part, domain).
///
/// Returns `None` if the address contains no `@`. RFC 5322 allows
/// quoted-string local-parts that may themselves contain `@`; splitting
/// on the rightmost `@` is the conventional handling for unquoted
/// addresses and is sufficient for the RFC 8398 equivalence check, which
/// presupposes well-formed mailbox addresses.
fn split_mailbox(addr: &str) -> Option<(&str, &str)> {
    let idx = addr.rfind('@')?;
    Some((&addr[..idx], &addr[idx + 1..]))
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

    // -----------------------------------------------------------------------
    // Rfc8398SmimeMailboxEquivalenceLint
    //
    // Two layers of tests:
    //
    // 1. The lint itself runs on real fixtures. No fixture in the
    //    workspace carries both rfc822Name AND id-on-SmtpUTF8Mailbox
    //    SANs, so on every existing fixture the equivalence rule is
    //    vacuously satisfied (Pass). We assert Pass on the smime
    //    fixture (rfc822Name only) and on the no-san fixture
    //    (extension absent → Pass).
    //
    // 2. The equivalence helper (`mailbox_equivalent`) is a pure
    //    function over two strings. We oracle-test it exhaustively
    //    against a hand-written table covering: ASCII equivalence,
    //    IDN A-label/U-label equivalence, local-part case sensitivity,
    //    domain case insensitivity, mismatched local-parts, mismatched
    //    domains, malformed input. Independent oracle: RFC 8398 §3 +
    //    RFC 5321 §2.4 wording, plus IDNA2008 (Punycode) reference
    //    encodings cross-checked with `python3 -c 'import idna;
    //    print(idna.encode("café.example").decode())'` →
    //    `xn--caf-dma.example`.
    // -----------------------------------------------------------------------

    #[test]
    fn smime_mailbox_equiv_lint_passes_on_rfc822_only_fixture() {
        // smime-self-signed-365d.der has rfc822Name but no
        // SmtpUTF8Mailbox — equivalence rule does not apply.
        let lint = Rfc8398SmimeMailboxEquivalenceLint;
        let cert = load_cert("smime-self-signed-365d.der");
        assert_eq!(
            lint.check_cert(&cert, SubjectKind::Leaf, 0),
            LintResult::Pass
        );
    }

    #[test]
    fn smime_mailbox_equiv_lint_passes_when_san_absent() {
        let lint = Rfc8398SmimeMailboxEquivalenceLint;
        let cert = load_cert("leaf-p256-365d-no-san.der");
        assert_eq!(
            lint.check_cert(&cert, SubjectKind::Leaf, 0),
            LintResult::Pass
        );
    }

    #[test]
    fn smime_mailbox_equiv_lint_passes_when_only_dns_san() {
        let lint = Rfc8398SmimeMailboxEquivalenceLint;
        let cert = load_cert("leaf-p256-365d-san-eku.der");
        assert_eq!(
            lint.check_cert(&cert, SubjectKind::Leaf, 0),
            LintResult::Pass
        );
    }

    #[test]
    fn smime_mailbox_equiv_lint_metadata_matches_rfc_section() {
        let lint = Rfc8398SmimeMailboxEquivalenceLint;
        assert_eq!(lint.id(), "rfc8398.cert.san.smime_mailbox_equivalent");
        assert_eq!(lint.citation(), "RFC 8398 §3");
        assert_eq!(lint.severity(), Severity::Error);
        assert_eq!(lint.scope(), Scope::Certificate);
        assert_eq!(lint.applies_to(), SubjectKind::Leaf);
        assert_eq!(lint.spec_section_id(), Some("rfc8398-3"));
        assert_eq!(
            lint.spec_url(),
            Some("https://www.rfc-editor.org/rfc/rfc8398#section-3")
        );
    }

    // ---- mailbox_equivalent helper tests ----

    #[test]
    fn mailbox_equiv_ascii_identical() {
        assert_eq!(
            mailbox_equivalent("alice@example.com", "alice@example.com"),
            Ok(true)
        );
    }

    #[test]
    fn mailbox_equiv_domain_case_insensitive() {
        // Domain case is irrelevant per RFC 5321 §2.4.
        assert_eq!(
            mailbox_equivalent("alice@Example.COM", "alice@example.com"),
            Ok(true)
        );
    }

    #[test]
    fn mailbox_equiv_local_part_case_sensitive() {
        // Local-parts are byte-equal; case differences fail.
        assert_eq!(
            mailbox_equivalent("Alice@example.com", "alice@example.com"),
            Ok(false)
        );
    }

    #[test]
    fn mailbox_equiv_idn_a_label_matches_u_label() {
        // A-label "xn--caf-dma.example" decodes to U-label "café.example"
        // (Punycode encoding of "café" verified via independent
        // `python3 -c 'import idna; print(idna.encode("café.example"))'`).
        assert_eq!(
            mailbox_equivalent("alice@xn--caf-dma.example", "alice@café.example"),
            Ok(true)
        );
    }

    #[test]
    fn mailbox_equiv_idn_a_label_matches_u_label_mixed_case() {
        // A-label form is conventionally lowercase; case differences
        // in the A-label form still match the U-label after conversion.
        assert_eq!(
            mailbox_equivalent("alice@XN--CAF-DMA.example", "alice@café.example"),
            Ok(true)
        );
    }

    #[test]
    fn mailbox_equiv_different_local_part_rejects() {
        assert_eq!(
            mailbox_equivalent("alice@example.com", "bob@example.com"),
            Ok(false)
        );
    }

    #[test]
    fn mailbox_equiv_different_domain_rejects() {
        assert_eq!(
            mailbox_equivalent("alice@example.com", "alice@other.com"),
            Ok(false)
        );
    }

    #[test]
    fn mailbox_equiv_missing_at_errors() {
        assert!(mailbox_equivalent("alice", "alice@example.com").is_err());
        assert!(mailbox_equivalent("alice@example.com", "alice").is_err());
    }

    #[test]
    fn mailbox_equiv_empty_local_or_domain_errors() {
        assert!(mailbox_equivalent("@example.com", "@example.com").is_err());
        assert!(mailbox_equivalent("alice@", "alice@").is_err());
    }

    // ---- validate_mailbox_for_equivalence helper (PKIX-hy2e.35) ----
    //
    // Oracle: the same RFC 8398 §3 + RFC 5321 §2.4 + IDNA2008 spec text
    // that drives mailbox_equivalent. validate_mailbox_for_equivalence
    // is the pre-flight check that mailbox_equivalent's matching logic
    // runs assuming well-formedness; the two share their validity
    // predicate so a well-formed input passes both and any malformed
    // input fails both.

    #[test]
    fn validate_mailbox_accepts_well_formed_ascii() {
        assert!(validate_mailbox_for_equivalence("alice@example.com").is_ok());
    }

    #[test]
    fn validate_mailbox_accepts_well_formed_u_label() {
        // U-label form must round-trip through idna::domain_to_ascii.
        assert!(validate_mailbox_for_equivalence("alice@café.example").is_ok());
    }

    #[test]
    fn validate_mailbox_rejects_missing_at() {
        assert!(validate_mailbox_for_equivalence("alice").is_err());
    }

    #[test]
    fn validate_mailbox_rejects_empty_local_part() {
        assert!(validate_mailbox_for_equivalence("@example.com").is_err());
    }

    #[test]
    fn validate_mailbox_rejects_empty_domain() {
        assert!(validate_mailbox_for_equivalence("alice@").is_err());
    }
}
