//! Integration tests for [`WebPkiProfile`]'s `pkix_lint::LintProfile` impl.
//!
//! These tests were originally part of `pkix-lint-cabf/tests/cabf_tls_br_tests.rs`,
//! gated on the now-deleted `CabfTlsBrProfile` type. The bundling lives on
//! `pkix_profiles_cabf::WebPkiProfile` after the PKIX-9vnx.9.2.2 cycle-break.
//!
//! Test oracle: the canonical list of six CA/B Forum TLS BR lints is
//! `pkix_lint_cabf::cabf_tls_br::all_lints` — an independent source from the
//! `WebPkiProfile::lints()` / `WebPkiProfile::lint_runner()` methods under test
//! (the profile's `LintProfile` impl is the code under test; `all_lints` is
//! the source of truth it must agree with).
//!
//! Fixture: `webpki-self-signed-365d.der` is a P-256 cert with serverAuth EKU,
//! DNS SAN, 365-day validity period, notBefore = 2026-01-01. Pre-SC-081 cap
//! window (398 days) → should produce no error findings.

use der::Decode as _;
use pkix_lint::{LintProfile, SubjectKind};
use pkix_profiles_cabf::WebPkiProfile;
use x509_cert::Certificate;

/// 2026-01-01T00:00:00Z — pre-SC-081 (cap = 398 days).
///
/// Verified via: `python3 -c "import calendar; print(calendar.timegm((2026,1,1,0,0,0,0,0,0)))"`
const T_2026_JAN_01: u64 = 1_767_225_600;

/// Load `webpki-self-signed-365d.der` from the shared policy-checks fixture tree.
fn load_webpki_self_signed_365d() -> Certificate {
    Certificate::from_der(include_bytes!(
        "../../pkix-path/tests/fixtures/policy-checks/webpki-self-signed-365d.der"
    ))
    .expect("webpki-self-signed-365d.der is valid DER")
}

#[test]
fn web_pki_profile_lint_runner_has_all_six_lints() {
    let runner = WebPkiProfile.lint_runner();
    let ids: Vec<&str> = runner.lints().iter().map(|l| l.id()).collect();
    assert!(
        ids.contains(&"cabf.br.tls.validity.max"),
        "missing validity.max lint"
    );
    assert!(
        ids.contains(&"cabf.br.tls.alg.sha1_prohibited"),
        "missing sha1_prohibited lint"
    );
    assert!(
        ids.contains(&"cabf.br.tls.rsa.min_key_size"),
        "missing rsa.min_key_size lint"
    );
    assert!(
        ids.contains(&"cabf.br.tls.san.required"),
        "missing san.required lint"
    );
    assert!(
        ids.contains(&"cabf.br.tls.eku.server_auth"),
        "missing eku.server_auth lint"
    );
    assert!(
        ids.contains(&"cabf.br.tls.bc.ca_flag"),
        "missing bc.ca_flag lint"
    );
    assert_eq!(
        ids.len(),
        6,
        "expected exactly 6 lints in WebPkiProfile's LintProfile bundle"
    );
}

#[test]
fn web_pki_profile_lints_method_has_all_ids() {
    let profile = WebPkiProfile;
    let lints = profile.lints();
    let ids: Vec<&str> = lints.iter().map(|l| l.id()).collect();
    assert!(ids.contains(&"cabf.br.tls.validity.max"));
    assert!(ids.contains(&"cabf.br.tls.alg.sha1_prohibited"));
    assert!(ids.contains(&"cabf.br.tls.rsa.min_key_size"));
    assert!(ids.contains(&"cabf.br.tls.san.required"));
    assert!(ids.contains(&"cabf.br.tls.eku.server_auth"));
    assert!(ids.contains(&"cabf.br.tls.bc.ca_flag"));
    assert_eq!(
        ids.len(),
        6,
        "expected exactly 6 lints from WebPkiProfile::lints()"
    );
}

#[test]
fn web_pki_profile_lints_matches_canonical_constructor() {
    // Cross-validation against the independent oracle:
    // `pkix_lint_cabf::cabf_tls_br::all_lints` is the canonical constructor.
    // WebPkiProfile's LintProfile impl must return the same lint IDs.
    let from_profile: Vec<&str> = WebPkiProfile.lints().iter().map(|l| l.id()).collect();
    let from_constructor: Vec<String> = pkix_lint_cabf::cabf_tls_br::all_lints()
        .iter()
        .map(|l| l.id().to_string())
        .collect();
    let from_constructor_ref: Vec<&str> = from_constructor.iter().map(String::as_str).collect();
    assert_eq!(
        from_profile, from_constructor_ref,
        "WebPkiProfile::lints() must mirror pkix_lint_cabf::cabf_tls_br::all_lints()"
    );
}

#[test]
fn web_pki_profile_run_chain_webpki_cert_all_pass() {
    // webpki-self-signed-365d.der evaluated pre-SC-081 (T_2026_JAN_01) should
    // produce no error findings for cert-scope lints that apply to Leaf.
    // now = 2026-01-01 (cap = 398 days); cert is 365 days → validity passes.
    let cert = load_webpki_self_signed_365d();
    let runner = WebPkiProfile.lint_runner();
    let findings = runner.run_cert(&cert, SubjectKind::Leaf, 0, T_2026_JAN_01);

    // Collect only actionable findings (not Pass / NotApplicable).
    let errors: Vec<_> = findings.iter().filter(|f| f.result.is_finding()).collect();
    assert!(
        errors.is_empty(),
        "webpki cert at pre-SC-081 time must produce no error findings; got: {errors:?}"
    );
}
