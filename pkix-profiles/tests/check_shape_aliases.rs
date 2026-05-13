//! Tests for the per-Basic*Profile shape-check convenience aliases
//! (PKIX-9vnx.9.2): `check_basic_tls_shape`, `check_basic_smime_shape`.
//!
//! Test oracle: each alias is a one-line wrapper over `pkix_lint::check_shape`
//! with the corresponding Profile. The independent oracle here is the lint
//! set itself (RFC 5280 / 6125 / 8398 / 8551 baselines): if an `Error`-severity
//! lint fires on a known-bad cert, the alias must return `Err`; if no
//! `Error`/`Fatal` lints fire on a known-good cert, the alias must return `Ok`.
//!
//! Fixtures are reused from `pkix-path/tests/fixtures/policy-checks/`; their
//! properties are pinned by `openssl x509 -text` verification in
//! `pkix-lint-cabf/tests/cabf_tls_br_tests.rs` (the original consumer).

use der::Decode as _;
use pkix_profiles::{check_basic_smime_shape, check_basic_tls_shape};
use x509_cert::Certificate;

/// 2026-06-01T00:00:00Z — within the validity period of every 2026-01-01-issued
/// fixture. Verified via:
/// `python3 -c "import calendar; print(calendar.timegm((2026,6,1,0,0,0,0,0,0)))"`
const NOW_2026_JUN_01: u64 = 1_780_272_000;

macro_rules! load_cert {
    ($path:literal) => {{
        Certificate::from_der(include_bytes!(concat!(
            "../../pkix-path/tests/fixtures/policy-checks/",
            $path
        )))
        .expect(concat!("fixture ", $path, " is valid DER"))
    }};
}

// ---------------------------------------------------------------------------
// check_basic_tls_shape
// ---------------------------------------------------------------------------

#[test]
fn check_basic_tls_shape_ok_on_proper_leaf() {
    // leaf-p256-365d-san-eku.der: P-256 issued by int-p256, basicConstraints
    // cA=FALSE, DNS SAN, serverAuth EKU, 365 days, notBefore=2026-01-01.
    // Satisfies RFC 5280 + RFC 6125 baseline (proper leaf shape).
    let cert = load_cert!("leaf-p256-365d-san-eku.der");
    let result = check_basic_tls_shape(&cert, NOW_2026_JUN_01);
    if let Err(findings) = &result {
        let actionable: Vec<_> = findings
            .iter()
            .filter(|f| f.result.is_finding())
            .map(|f| format!("{}: {:?}", f.lint_id, f.result))
            .collect();
        panic!(
            "leaf-p256-365d-san-eku.der must pass basic TLS shape check; actionable findings: {actionable:?}"
        );
    }
}

#[test]
fn check_basic_tls_shape_err_on_missing_eku() {
    // leaf-p256-365d-no-eku.der: P-256, DNS SAN, NO EKU extension. Must fire
    // Rfc5280EkuServerAuthLint Error.
    let cert = load_cert!("leaf-p256-365d-no-eku.der");
    let result = check_basic_tls_shape(&cert, NOW_2026_JUN_01);
    assert!(
        result.is_err(),
        "leaf without serverAuth EKU must fail basic TLS shape check"
    );
    let findings = result.unwrap_err();
    assert!(
        findings
            .iter()
            .any(|f| f.lint_id.starts_with("rfc5280.cert.eku.")),
        "expected an rfc5280.cert.eku.* finding among: {:?}",
        findings.iter().map(|f| &f.lint_id).collect::<Vec<_>>()
    );
}

#[test]
fn check_basic_tls_shape_err_on_missing_san() {
    // leaf-p256-365d-no-san.der: P-256, serverAuth EKU, NO SAN extension. Must
    // fire Rfc6125TlsServerSanLint Error (RFC 6125 requires SAN for TLS).
    let cert = load_cert!("leaf-p256-365d-no-san.der");
    let result = check_basic_tls_shape(&cert, NOW_2026_JUN_01);
    assert!(
        result.is_err(),
        "leaf without SAN must fail basic TLS shape check (RFC 6125)"
    );
    let findings = result.unwrap_err();
    assert!(
        findings
            .iter()
            .any(|f| f.lint_id.starts_with("rfc6125.")),
        "expected an rfc6125.* finding among: {:?}",
        findings.iter().map(|f| &f.lint_id).collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// check_basic_smime_shape
// ---------------------------------------------------------------------------

#[test]
fn check_basic_smime_shape_ok_on_smime_leaf() {
    // smime-self-signed-365d.der: P-256, emailProtection EKU, 365 days.
    // Satisfies RFC 8551 + RFC 8398 + RFC 5280 baseline.
    let cert = load_cert!("smime-self-signed-365d.der");
    assert!(
        check_basic_smime_shape(&cert, NOW_2026_JUN_01).is_ok(),
        "smime-self-signed-365d.der must pass basic S/MIME shape check"
    );
}

#[test]
fn check_basic_smime_shape_err_on_tls_leaf() {
    // webpki-self-signed-365d.der: has serverAuth EKU, NOT emailProtection.
    // Must fire Rfc8551EkuEmailProtectionLint Error and/or Rfc8398SmimeSanLint
    // (the cert's SAN is dNSName, not rfc822Name/SmtpUTF8Mailbox).
    let cert = load_cert!("webpki-self-signed-365d.der");
    let result = check_basic_smime_shape(&cert, NOW_2026_JUN_01);
    assert!(
        result.is_err(),
        "TLS-shaped cert must fail basic S/MIME shape check"
    );
    let findings = result.unwrap_err();
    assert!(
        findings.iter().any(|f| {
            f.lint_id.starts_with("rfc8551.") || f.lint_id.starts_with("rfc8398.")
        }),
        "expected an rfc8551.* or rfc8398.* finding among: {:?}",
        findings.iter().map(|f| &f.lint_id).collect::<Vec<_>>()
    );
}
