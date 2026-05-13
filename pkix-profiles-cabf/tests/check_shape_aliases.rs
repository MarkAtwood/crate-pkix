//! Tests for the per-cabf-Profile shape-check convenience aliases
//! (PKIX-9vnx.9.2): `check_web_pki_shape`, `check_smime_shape`,
//! `check_code_signing_shape`.
//!
//! Test oracle:
//! - `check_web_pki_shape` is a thin wrapper over `pkix_lint::check_shape`
//!   with `WebPkiProfile`, which bundles the six CA/B Forum TLS BR lints
//!   from `pkix_lint_cabf::cabf_tls_br`. The independent oracle is those
//!   lints' Error/Pass semantics.
//! - `check_smime_shape` and `check_code_signing_shape` have empty lint
//!   sets today (no `cabf_smime_br` / `cabf_cs_br` module ships in
//!   `pkix-lint-cabf` yet); they currently return `Ok(())` unconditionally.
//!   The tests pin that contract so adding the lint modules later surfaces
//!   the contract change deliberately.

use der::Decode as _;
use pkix_profiles_cabf::{check_code_signing_shape, check_smime_shape, check_web_pki_shape};
use x509_cert::Certificate;

/// 2026-06-01T00:00:00Z — within the validity period of every 2026-01-01-issued
/// fixture. Pre-SC-081 cap window (398-day cap applies).
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
// check_web_pki_shape
// ---------------------------------------------------------------------------

#[test]
fn check_web_pki_shape_ok_on_proper_leaf() {
    // leaf-p256-365d-san-eku.der: P-256, serverAuth EKU, DNS SAN, CA:FALSE,
    // 365 days, notBefore=2026-01-01. 365 days is within the pre-SC-081
    // 398-day cap. Should pass every CA/B Forum TLS BR lint:
    //   validity.max: 365 <= 398 ✓
    //   alg.sha1_prohibited: ECDSA-SHA256, not SHA-1 ✓
    //   rsa.min_key_size: NotApplicable (P-256, not RSA)
    //   san.required: DNS SAN present ✓
    //   eku.server_auth: id-kp-serverAuth present ✓
    //   bc.ca_flag: NotApplicable (Leaf, lint applies to IntermediateCa)
    let cert = load_cert!("leaf-p256-365d-san-eku.der");
    let result = check_web_pki_shape(&cert, NOW_2026_JUN_01);
    if let Err(findings) = &result {
        let actionable: Vec<_> = findings
            .iter()
            .filter(|f| f.result.is_finding())
            .map(|f| format!("{}: {:?}", f.lint_id, f.result))
            .collect();
        panic!(
            "leaf-p256-365d-san-eku.der must pass CA/B Forum TLS BR shape check; actionable findings: {actionable:?}"
        );
    }
}

#[test]
fn check_web_pki_shape_err_on_sha1_signature() {
    // leaf-rsa2048-sha1.der: RSA-2048 with sha1WithRSAEncryption signature.
    // Must fire cabf.br.tls.alg.sha1_prohibited.
    let cert = load_cert!("leaf-rsa2048-sha1.der");
    let result = check_web_pki_shape(&cert, NOW_2026_JUN_01);
    assert!(
        result.is_err(),
        "SHA-1-signed leaf must fail CA/B Forum TLS BR shape check"
    );
    let findings = result.unwrap_err();
    assert!(
        findings
            .iter()
            .any(|f| f.lint_id == "cabf.br.tls.alg.sha1_prohibited"),
        "expected cabf.br.tls.alg.sha1_prohibited among: {:?}",
        findings.iter().map(|f| &f.lint_id).collect::<Vec<_>>()
    );
}

#[test]
fn check_web_pki_shape_err_on_rsa1024() {
    // leaf-rsa1024-365d-san-eku.der: RSA-1024 leaf (below 2048-bit floor).
    // Must fire cabf.br.tls.rsa.min_key_size.
    let cert = load_cert!("leaf-rsa1024-365d-san-eku.der");
    let result = check_web_pki_shape(&cert, NOW_2026_JUN_01);
    assert!(
        result.is_err(),
        "RSA-1024 leaf must fail CA/B Forum TLS BR shape check"
    );
    let findings = result.unwrap_err();
    assert!(
        findings
            .iter()
            .any(|f| f.lint_id == "cabf.br.tls.rsa.min_key_size"),
        "expected cabf.br.tls.rsa.min_key_size among: {:?}",
        findings.iter().map(|f| &f.lint_id).collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// check_smime_shape — currently no-op (empty lint set; see source rustdoc)
// ---------------------------------------------------------------------------

#[test]
fn check_smime_shape_currently_passes_any_cert() {
    // The cabf S/MIME BR lint module does not yet ship in pkix-lint-cabf, so
    // SmimeProfile's LintProfile impl returns an empty Vec. This test pins
    // that contract: until a cabf_smime_br module lands, this alias accepts
    // anything. The test will fail (deliberately) once cabf S/MIME BR lints
    // are added — that failure is the intended signal that this alias
    // becomes substantive.
    let smime_cert = load_cert!("smime-self-signed-365d.der");
    assert!(check_smime_shape(&smime_cert, NOW_2026_JUN_01).is_ok());

    // Even a TLS-shaped cert passes because the lint set is empty.
    let tls_cert = load_cert!("webpki-self-signed-365d.der");
    assert!(check_smime_shape(&tls_cert, NOW_2026_JUN_01).is_ok());
}

// ---------------------------------------------------------------------------
// check_code_signing_shape — currently no-op (empty lint set; see source rustdoc)
// ---------------------------------------------------------------------------

#[test]
fn check_code_signing_shape_currently_passes_any_cert() {
    // The cabf CS BR lint module does not yet ship in pkix-lint-cabf, so
    // CodeSigningProfile's LintProfile impl returns an empty Vec. Same
    // contract as check_smime_shape above: this test will fail once cabf
    // CS BR lints land, signalling the alias has become substantive.
    let cs_cert = load_cert!("codesign-self-signed-365d.der");
    assert!(check_code_signing_shape(&cs_cert, NOW_2026_JUN_01).is_ok());

    let tls_cert = load_cert!("webpki-self-signed-365d.der");
    assert!(check_code_signing_shape(&tls_cert, NOW_2026_JUN_01).is_ok());
}
