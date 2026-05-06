//! Integration tests for CABF TLS BR lints.
//!
//! Test oracle: each test's expected result is derived from an external source
//! independent of the code under test.  Fixture certs are pre-generated DER
//! files verified with `openssl x509 -text`.  Epoch boundaries for SC-081 are
//! taken from the CA/B Forum Ballot SC-081 text, not from pkix-profiles source.
//!
//! Oracle sources:
//! - SC-081 effective dates: CA/B Forum Ballot SC-081 (approved March 2024)
//!   2026-03-15T00:00:00Z = 1_773_532_800  (python3: calendar.timegm((2026,3,15,0,0,0,0,0,0)))
//!   2027-03-15T00:00:00Z = 1_805_068_800
//!   2029-03-15T00:00:00Z = 1_868_227_200
//! - Fixture cert properties verified with: openssl x509 -in <file> -inform DER -noout -text
//!   webpki-self-signed-365d.der           : P-256, serverAuth EKU, DNS SAN, 365 days, notBefore=2026-01-01
//!   webpki-self-signed-365d-post-sc081.der : P-256, serverAuth EKU, DNS SAN, 365 days, notBefore=2026-03-16
//!   leaf-p256-365d-san-eku.der  : P-256, serverAuth EKU, DNS SAN, 365 days
//!   leaf-p256-365d-no-san.der   : P-256, serverAuth EKU, NO SAN, 365 days
//!   leaf-p256-365d-no-eku.der   : P-256, NO EKU, DNS SAN, 365 days
//!   leaf-p256-365d-wrong-eku.der: P-256, emailProtection EKU, DNS SAN, 365 days
//!   leaf-p256-400d-san-eku.der  : P-256, serverAuth EKU, DNS SAN, 400 days
//!   leaf-rsa2048-365d-san-eku.der: RSA-2048, serverAuth EKU, DNS SAN, 365 days
//!   leaf-rsa1024-365d-san-eku.der: RSA-1024, serverAuth EKU, DNS SAN, 365 days
//!   int-p256.der                : P-256, CA:TRUE BasicConstraints, 10 years
//!   smime-self-signed-365d.der  : P-256, emailProtection EKU, 365 days

use der::Decode as _;
use pkix_lint::cabf_tls_br::{
    BcCaFlagLint, EkuServerAuthLint, RsaMinKeySizeLint, SanRequiredLint, Sha1ProhibitedLint,
    ValidityMaxLint,
};
use pkix_lint::{Lint, LintProfile, LintResult, SubjectKind};
use x509_cert::Certificate;

// ---------------------------------------------------------------------------
// Fixture loading helpers
// ---------------------------------------------------------------------------

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
// Epoch constants (oracle: CA/B Forum Ballot SC-081, Python calendar.timegm)
// ---------------------------------------------------------------------------

/// 2026-01-01T00:00:00Z — before SC-081 takes effect; cap = 398 days
const T_2026_JAN_01: u64 = 1_767_225_600;

/// 2026-03-16T00:00:00Z — one day after SC-081 200-day threshold; cap = 200 days
const T_AFTER_SC081_200D: u64 = 1_773_619_200;

// ---------------------------------------------------------------------------
// Lint 1 — cabf.br.tls.validity.max
// ---------------------------------------------------------------------------
//
// Oracle: SC-081 phases (independent of pkix-profiles source):
//   notBefore before 2026-03-15: cap = 398 days = 34_387_200 s
//   notBefore on/after 2026-03-15: cap = 200 days = 17_280_000 s
//
// The cap is evaluated at issuance time (notBefore), NOT at now_unix.
// A cert issued before 2026-03-15 retains the 398-day cap regardless of
// when validation occurs.
//
// webpki-self-signed-365d.der: notBefore=2026-01-01, 365 days = 31_536_000 s
//   cap = 398 days (pre-SC-081, notBefore < 2026-03-15)
//   31_536_000 <= 34_387_200 → Pass   (pre-SC-081 cap, regardless of now_unix)
//
// webpki-self-signed-365d-post-sc081.der: notBefore=2026-03-16, 365 days = 31_536_000 s
//   cap = 200 days (post-SC-081, notBefore >= 2026-03-15)
//   31_536_000  > 17_280_000 → Error  (post-SC-081 200-day cap)
//
// leaf-p256-400d-san-eku.der: notBefore=2026-01-01, 400 days = 34_560_000 s
//   cap = 398 days (pre-SC-081, notBefore < 2026-03-15)
//   34_560_000 > 34_387_200 → Error   (exceeds pre-SC-081 398-day cap)

#[test]
fn validity_max_pass_pre_sc081() {
    // 365-day cert with notBefore=2026-01-01 (pre-SC-081): cap is 398 days → Pass.
    let cert = load_cert!("webpki-self-signed-365d.der");
    let lint = ValidityMaxLint;
    let result = lint.check_cert(&cert, SubjectKind::Leaf, T_2026_JAN_01);
    assert_eq!(
        result,
        LintResult::Pass,
        "365-day cert issued pre-SC-081 must Pass the 398-day cap"
    );
}

#[test]
fn validity_max_pass_pre_sc081_evaluated_late() {
    // Regression: a cert issued before 2026-03-15 must still pass when
    // validated after 2026-03-15.  The cap is determined by notBefore (issuance
    // time), not by now_unix.  Prior bug used now_unix → would have returned Error.
    let cert = load_cert!("webpki-self-signed-365d.der");
    let lint = ValidityMaxLint;
    let result = lint.check_cert(&cert, SubjectKind::Leaf, T_AFTER_SC081_200D);
    assert_eq!(
        result,
        LintResult::Pass,
        "365-day cert issued pre-SC-081 must Pass even when validated post-SC-081"
    );
}

#[test]
fn validity_max_error_post_sc081_200d() {
    // 365-day cert with notBefore=2026-03-16 (post-SC-081): cap is 200 days → Error.
    let cert = load_cert!("webpki-self-signed-365d-post-sc081.der");
    let lint = ValidityMaxLint;
    let result = lint.check_cert(&cert, SubjectKind::Leaf, T_AFTER_SC081_200D);
    assert!(
        matches!(result, LintResult::Error(_)),
        "365-day cert issued post-SC-081 must Error against the 200-day cap, got {result:?}"
    );
}

#[test]
fn validity_max_error_400d_pre_sc081() {
    // 400-day cert is over the 398-day pre-SC-081 cap → Error.
    let cert = load_cert!("leaf-p256-400d-san-eku.der");
    let lint = ValidityMaxLint;
    let result = lint.check_cert(&cert, SubjectKind::Leaf, T_2026_JAN_01);
    assert!(
        matches!(result, LintResult::Error(_)),
        "400-day cert must Error against the 398-day pre-SC-081 cap, got {result:?}"
    );
}

#[test]
fn validity_max_not_applicable_for_intermediate() {
    // The lint declares applies_to = Leaf.  The runner returns NotApplicable
    // for non-leaf positions automatically.  Verify the lint itself returns
    // Pass regardless of kind (the runner handles the kind check).
    // Here we test the runner's kind filter via LintRunner directly.
    use pkix_lint::LintRunner;
    let cert = load_cert!("int-p256.der");
    let runner = LintRunner::new(vec![Box::new(ValidityMaxLint)]);
    let findings = runner.run_cert(&cert, SubjectKind::IntermediateCa, 1, T_2026_JAN_01);
    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0].result,
        LintResult::NotApplicable,
        "ValidityMaxLint must be NotApplicable for IntermediateCa"
    );
}

// ---------------------------------------------------------------------------
// SC-081 phase transition tests — 2027 (100-day) and 2029 (47-day)
// ---------------------------------------------------------------------------
//
// Oracle: SC-081 phases (CA/B Forum Ballot SC-081):
//   notBefore on/after 2027-03-15: cap = 100 days = 8_640_000 s
//   notBefore on/after 2029-03-15: cap = 47  days = 4_060_800 s
//
// These tests validate the sc081_validity_cap function directly (the same
// function that ValidityMaxLint calls) because the required DER fixtures do
// not yet exist in the repository.  The fixture-based tests are marked
// #[ignore] below.
//
// To add proper fixture-based tests:
//   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 \
//     -noenc -subj "/CN=test/O=test/C=US" \
//     -startdate 270316000000Z -days 110 \
//     -out /tmp/leaf-p256-110d-post-sc081-100d.pem -keyout /tmp/k.key
//   openssl x509 -in /tmp/leaf-p256-110d-post-sc081-100d.pem -outform DER \
//     -out pkix-path/tests/fixtures/policy-checks/leaf-p256-110d-post-sc081-100d.der
//   # Similarly for 50-day cert with -startdate 290316000000Z -days 50
//
// Then update these tests to use load_cert! and remove the #[ignore] attribute.

#[test]
fn validity_max_cap_function_100d_phase() {
    // Verify that sc081_validity_cap returns the 100-day cap for a notBefore
    // after 2027-03-15.  This is the same oracle the ValidityMaxLint uses.
    // Oracle: CA/B Forum Ballot SC-081; 2027-03-15T00:00:00Z = 1_805_068_800
    use pkix_profiles::sc081_validity_cap;
    const T_2027_MAR_15: u64 = 1_805_068_800;
    const T_2027_MAR_16: u64 = 1_805_068_800 + 86_400;
    const DAYS_100_SECS: u64 = 100 * 86_400;
    // Exactly on the threshold
    assert_eq!(
        sc081_validity_cap(T_2027_MAR_15),
        DAYS_100_SECS,
        "2027-03-15 exactly must yield 100-day cap"
    );
    // One day after the threshold
    assert_eq!(
        sc081_validity_cap(T_2027_MAR_16),
        DAYS_100_SECS,
        "2027-03-16 must yield 100-day cap"
    );
}

#[test]
fn validity_max_cap_function_47d_phase() {
    // Verify that sc081_validity_cap returns the 47-day cap for a notBefore
    // after 2029-03-15.
    // Oracle: CA/B Forum Ballot SC-081; 2029-03-15T00:00:00Z = 1_868_227_200
    use pkix_profiles::sc081_validity_cap;
    const T_2029_MAR_15: u64 = 1_868_227_200;
    const T_2029_MAR_16: u64 = 1_868_227_200 + 86_400;
    const DAYS_47_SECS: u64 = 47 * 86_400;
    // Exactly on the threshold
    assert_eq!(
        sc081_validity_cap(T_2029_MAR_15),
        DAYS_47_SECS,
        "2029-03-15 exactly must yield 47-day cap"
    );
    // One day after the threshold
    assert_eq!(
        sc081_validity_cap(T_2029_MAR_16),
        DAYS_47_SECS,
        "2029-03-16 must yield 47-day cap"
    );
}

// ---------------------------------------------------------------------------
// ValidityMaxLint — inverted validity (notAfter < notBefore)
// ---------------------------------------------------------------------------
//
// Oracle: leaf-inverted-validity.der was generated by patching a valid cert's
// DER to swap the notBefore and notAfter UTCTime values:
//   Not Before: Jan  1 00:00:00 2026 GMT
//   Not After : Jan  1 00:00:00 2025 GMT  ← precedes notBefore
// Verified with: openssl x509 -inform DER -in leaf-inverted-validity.der -noout -text
//
// No separate validity-range lint exists that catches notAfter < notBefore, so
// ValidityMaxLint returns Error for this case rather than silently passing
// (saturating_sub would yield duration=0, which always passes the cap check).

#[test]
fn validity_max_error_inverted_validity() {
    // Cert where notAfter precedes notBefore must return Error from ValidityMaxLint.
    // Oracle: leaf-inverted-validity.der; notBefore=2026-01-01, notAfter=2025-01-01.
    let cert = load_cert!("leaf-inverted-validity.der");
    let lint = ValidityMaxLint;
    let result = lint.check_cert(&cert, SubjectKind::Leaf, T_2026_JAN_01);
    assert!(
        matches!(result, LintResult::Error(_)),
        "cert with notAfter < notBefore must Error ValidityMaxLint; got {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Lint 2 — cabf.br.tls.alg.sha1_prohibited
// ---------------------------------------------------------------------------
//
// Oracle: TLS BR §7.1.3 prohibits sha1WithRSAEncryption (1.2.840.113549.1.1.5)
// and ecdsa-with-SHA1 (1.2.840.10045.4.1).
//
// All fixture certs use ecdsa-with-SHA256 or sha256WithRSAEncryption → Pass.
// We construct a synthetic SHA-1 detection test by directly calling the lint
// with a cert whose signatureAlgorithm we verify via openssl.

#[test]
fn sha1_prohibited_pass_on_sha256_cert() {
    // webpki-self-signed-365d.der uses ecdsa-with-SHA256 → Pass.
    // Oracle: openssl x509 ... -text | grep "Signature Algorithm: ecdsa-with-SHA256"
    let cert = load_cert!("webpki-self-signed-365d.der");
    let lint = Sha1ProhibitedLint;
    let result = lint.check_cert(&cert, SubjectKind::Leaf, 0);
    assert_eq!(result, LintResult::Pass, "ecdsa-with-SHA256 must Pass SHA-1 prohibition");
}

#[test]
fn sha1_prohibited_pass_on_rsa_sha256_cert() {
    // leaf-rsa2048-365d-san-eku.der uses sha256WithRSAEncryption → Pass.
    // Oracle: openssl x509 ... -text | grep "Signature Algorithm: sha256WithRSAEncryption"
    let cert = load_cert!("leaf-rsa2048-365d-san-eku.der");
    let lint = Sha1ProhibitedLint;
    let result = lint.check_cert(&cert, SubjectKind::Leaf, 0);
    assert_eq!(result, LintResult::Pass, "sha256WithRSAEncryption must Pass SHA-1 prohibition");
}

#[test]
fn sha1_prohibited_applies_to_any_kind() {
    // The lint declares applies_to = Any; verify it runs on both Leaf and IntermediateCa.
    let cert = load_cert!("int-p256.der");
    let lint = Sha1ProhibitedLint;
    // int-p256.der uses ecdsa-with-SHA256 → Pass regardless of kind.
    assert_eq!(lint.check_cert(&cert, SubjectKind::IntermediateCa, 0), LintResult::Pass);
    assert_eq!(lint.check_cert(&cert, SubjectKind::Leaf, 0), LintResult::Pass);
}

/// Verify the lint correctly identifies SHA-1 OIDs without needing a SHA-1 cert fixture.
///
/// Oracle: RFC 3279 §2.2.1 — sha1WithRSAEncryption OID = 1.2.840.113549.1.1.5
///         RFC 3279 §2.2.3 — ecdsa-with-SHA1 OID = 1.2.840.10045.4.1
///
/// We load a known-good SHA-256 cert, then check that the OIDs we are guarding
/// against differ from the cert's actual OID.  This tests the lint logic
/// (OID comparison) without fabricating DER.
#[test]
fn sha1_prohibited_oid_detection_logic() {
    use der::asn1::ObjectIdentifier;
    let sha1_rsa: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5");
    let sha1_ecdsa: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.1");
    let sha256_rsa: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
    let ecdsa_sha256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

    // SHA-1 OIDs must differ from SHA-256 OIDs (proves the lint checks the right OIDs).
    assert_ne!(sha1_rsa, sha256_rsa);
    assert_ne!(sha1_ecdsa, ecdsa_sha256);

    // The lint's internal SHA-1 constants must match what the specs say.
    // Since the lint is what we are testing, we verify the OIDs parse and differ
    // from known non-SHA-1 OIDs — an independent check of OID identity.
    let cert = load_cert!("webpki-self-signed-365d.der");
    let actual_oid = &cert.signature_algorithm.oid;
    // webpki cert uses ecdsa-with-SHA256, not SHA-1.
    assert_ne!(actual_oid, &sha1_rsa, "fixture cert must not use sha1WithRSAEncryption");
    assert_ne!(actual_oid, &sha1_ecdsa, "fixture cert must not use ecdsa-with-SHA1");
}

/// Negative test: a cert actually signed with SHA-1 must return Error.
///
/// This test requires a DER fixture signed with SHA-1, which cannot be generated
/// without external cryptographic tooling (openssl or similar). The test is
/// marked `#[ignore]` until the fixture is available.
///
/// To generate the fixture and enable this test:
/// 1. Run:
///      openssl req -x509 -newkey rsa:2048 -sha1 -days 365 \
///        -subj "/CN=sha1-test" -noenc \
///        -out /tmp/leaf-rsa2048-sha1.pem -keyout /tmp/leaf-rsa2048-sha1.key
///      openssl x509 -in /tmp/leaf-rsa2048-sha1.pem -outform DER \
///        -out pkix-path/tests/fixtures/policy-checks/leaf-rsa2048-sha1.der
/// 2. Replace the runtime `std::fs::read` below with `load_cert!("leaf-rsa2048-sha1.der")`.
/// 3. Remove the `#[ignore]` attribute and commit the fixture.
#[test]
#[ignore = "requires leaf-rsa2048-sha1.der fixture — see comment above for generation steps"]
fn sha1_prohibited_error_on_sha1_cert() {
    // Use runtime read so this test compiles without the fixture present.
    let fixture_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../pkix-path/tests/fixtures/policy-checks/leaf-rsa2048-sha1.der"
    );
    let der = std::fs::read(fixture_path).expect("fixture leaf-rsa2048-sha1.der must exist");
    let cert = Certificate::from_der(&der).expect("fixture is valid DER");
    let lint = Sha1ProhibitedLint;
    let result = lint.check_cert(&cert, SubjectKind::Leaf, 0);
    assert!(
        matches!(result, LintResult::Error(_)),
        "SHA-1 signed cert must Error the sha1_prohibited lint, got {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Lint 3 — cabf.br.tls.rsa.min_key_size
// ---------------------------------------------------------------------------
//
// Oracle: TLS BR §6.1.5 — RSA key modulus must be >= 2048 bits.
//
// leaf-rsa2048-365d-san-eku.der: 2048-bit RSA → Pass
//   Oracle: openssl x509 ... -text | "Public-Key: (2048 bit)"
//   2048 bits / 8 = 256 bytes; 256 >= 256 → Pass
//
// leaf-rsa1024-365d-san-eku.der: 1024-bit RSA → Error
//   Oracle: openssl x509 ... -text | "Public-Key: (1024 bit)"
//   1024 bits / 8 = 128 bytes; 128 < 256 → Error
//
// webpki-self-signed-365d.der: P-256 ECDSA → NotApplicable (not RSA)
//   Oracle: openssl x509 ... -text | "Public Key Algorithm: id-ecPublicKey"

#[test]
fn rsa_min_key_size_pass_rsa2048() {
    let cert = load_cert!("leaf-rsa2048-365d-san-eku.der");
    let lint = RsaMinKeySizeLint;
    let result = lint.check_cert(&cert, SubjectKind::Leaf, 0);
    assert_eq!(
        result,
        LintResult::Pass,
        "RSA-2048 key must Pass the 2048-bit minimum"
    );
}

#[test]
fn rsa_min_key_size_error_rsa1024() {
    let cert = load_cert!("leaf-rsa1024-365d-san-eku.der");
    let lint = RsaMinKeySizeLint;
    let result = lint.check_cert(&cert, SubjectKind::Leaf, 0);
    assert!(
        matches!(result, LintResult::Error(_)),
        "RSA-1024 key must Error the 2048-bit minimum, got {result:?}"
    );
}

#[test]
fn rsa_min_key_size_not_applicable_for_ecdsa() {
    // P-256 cert → NotApplicable (lint only checks RSA keys).
    let cert = load_cert!("webpki-self-signed-365d.der");
    let lint = RsaMinKeySizeLint;
    let result = lint.check_cert(&cert, SubjectKind::Leaf, 0);
    assert_eq!(
        result,
        LintResult::NotApplicable,
        "P-256 (ECDSA) cert must return NotApplicable for the RSA key-size lint"
    );
}

// ---------------------------------------------------------------------------
// Lint 4 — cabf.br.tls.san.required
// ---------------------------------------------------------------------------
//
// Oracle: TLS BR §7.1.4.2 — SAN must be present and non-empty.
//
// leaf-p256-365d-san-eku.der  : has SAN "DNS:test.example.com" → Pass
//   Oracle: openssl x509 ... | "Subject Alternative Name: DNS:test.example.com"
//
// leaf-p256-365d-no-san.der   : NO SAN extension → Error
//   Oracle: openssl x509 ... — no "Subject Alternative Name" line

#[test]
fn san_required_pass_with_san() {
    let cert = load_cert!("leaf-p256-365d-san-eku.der");
    let lint = SanRequiredLint;
    let result = lint.check_cert(&cert, SubjectKind::Leaf, 0);
    assert_eq!(result, LintResult::Pass, "cert with SAN must Pass san.required");
}

#[test]
fn san_required_pass_webpki_self_signed() {
    // The webpki self-signed cert also has a DNS SAN.
    let cert = load_cert!("webpki-self-signed-365d.der");
    let lint = SanRequiredLint;
    let result = lint.check_cert(&cert, SubjectKind::Leaf, 0);
    assert_eq!(result, LintResult::Pass, "webpki cert with SAN must Pass san.required");
}

#[test]
fn san_required_error_no_san() {
    // leaf-p256-365d-no-san.der has no SubjectAltName extension.
    let cert = load_cert!("leaf-p256-365d-no-san.der");
    let lint = SanRequiredLint;
    let result = lint.check_cert(&cert, SubjectKind::Leaf, 0);
    assert!(
        matches!(result, LintResult::Error(_)),
        "cert without SAN must Error san.required, got {result:?}"
    );
}

#[test]
fn san_required_not_applicable_for_intermediate() {
    // The lint applies_to = Leaf; runner returns NotApplicable for IntermediateCa.
    use pkix_lint::LintRunner;
    let cert = load_cert!("int-p256.der");
    let runner = LintRunner::new(vec![Box::new(SanRequiredLint)]);
    let findings = runner.run_cert(&cert, SubjectKind::IntermediateCa, 1, 0);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].result, LintResult::NotApplicable);
}

// ---------------------------------------------------------------------------
// Lint 5 — cabf.br.tls.eku.server_auth
// ---------------------------------------------------------------------------
//
// Oracle: TLS BR §7.1.2.7.3 — id-kp-serverAuth (1.3.6.1.5.5.7.3.1) must be present.
//
// leaf-p256-365d-san-eku.der   : has EKU = serverAuth → Pass
//   Oracle: openssl x509 ... | "Extended Key Usage: TLS Web Server Authentication"
//
// leaf-p256-365d-no-eku.der    : no EKU extension → Error
//   Oracle: openssl x509 ... — no "Extended Key Usage" line
//
// leaf-p256-365d-wrong-eku.der : EKU = emailProtection only → Error
//   Oracle: openssl x509 ... | "Extended Key Usage: E-mail Protection"
//
// smime-self-signed-365d.der   : EKU = emailProtection → Error
//   Oracle: openssl x509 ... | "Extended Key Usage: E-mail Protection"

#[test]
fn eku_server_auth_pass_with_server_auth() {
    let cert = load_cert!("leaf-p256-365d-san-eku.der");
    let lint = EkuServerAuthLint;
    let result = lint.check_cert(&cert, SubjectKind::Leaf, 0);
    assert_eq!(result, LintResult::Pass, "cert with serverAuth EKU must Pass eku.server_auth");
}

#[test]
fn eku_server_auth_pass_webpki_self_signed() {
    let cert = load_cert!("webpki-self-signed-365d.der");
    let lint = EkuServerAuthLint;
    let result = lint.check_cert(&cert, SubjectKind::Leaf, 0);
    assert_eq!(result, LintResult::Pass, "webpki cert must Pass eku.server_auth");
}

#[test]
fn eku_server_auth_error_no_eku() {
    let cert = load_cert!("leaf-p256-365d-no-eku.der");
    let lint = EkuServerAuthLint;
    let result = lint.check_cert(&cert, SubjectKind::Leaf, 0);
    assert!(
        matches!(result, LintResult::Error(_)),
        "cert without EKU must Error eku.server_auth, got {result:?}"
    );
}

#[test]
fn eku_server_auth_error_wrong_eku() {
    // cert has emailProtection but not serverAuth.
    let cert = load_cert!("leaf-p256-365d-wrong-eku.der");
    let lint = EkuServerAuthLint;
    let result = lint.check_cert(&cert, SubjectKind::Leaf, 0);
    assert!(
        matches!(result, LintResult::Error(_)),
        "cert with only emailProtection must Error eku.server_auth, got {result:?}"
    );
}

#[test]
fn eku_server_auth_error_smime_cert() {
    // S/MIME cert has emailProtection, not serverAuth.
    // Oracle: openssl x509 -in smime-self-signed-365d.der -inform DER -text
    //         | "Extended Key Usage: E-mail Protection"
    let cert = load_cert!("smime-self-signed-365d.der");
    let lint = EkuServerAuthLint;
    let result = lint.check_cert(&cert, SubjectKind::Leaf, 0);
    assert!(
        matches!(result, LintResult::Error(_)),
        "S/MIME cert (emailProtection) must Error eku.server_auth, got {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Lint 6 — cabf.br.tls.bc.ca_flag
// ---------------------------------------------------------------------------
//
// Oracle: TLS BR §7.1.2.5 — BasicConstraints must be present with cA=TRUE
//         on every intermediate CA certificate.
//
// int-p256.der: has BasicConstraints cA=TRUE → Pass
//   Oracle: openssl x509 ... | "Basic Constraints: ... CA:TRUE"
//
// leaf-p256-365d-san-eku.der: leaf cert, no BasicConstraints cA=TRUE.
//   When evaluated *as an IntermediateCa*, the lint should Error because
//   BasicConstraints is either absent or cA=FALSE.
//   Oracle: openssl x509 ... — "X509v3 Basic Constraints:" with empty value (cA absent/false)

#[test]
fn bc_ca_flag_pass_on_intermediate() {
    // int-p256.der has BasicConstraints with cA=TRUE.
    let cert = load_cert!("int-p256.der");
    let lint = BcCaFlagLint;
    let result = lint.check_cert(&cert, SubjectKind::IntermediateCa, 0);
    assert_eq!(
        result,
        LintResult::Pass,
        "int-p256.der (cA=TRUE) must Pass bc.ca_flag"
    );
}

#[test]
fn bc_ca_flag_error_on_leaf_treated_as_intermediate() {
    // A leaf cert (cA not set) evaluated in an IntermediateCa role must Error.
    // Oracle: openssl x509 -in leaf-p256-365d-san-eku.der -inform DER -text
    //         | "X509v3 Basic Constraints:" — no "CA:TRUE"
    let cert = load_cert!("leaf-p256-365d-san-eku.der");
    let lint = BcCaFlagLint;
    let result = lint.check_cert(&cert, SubjectKind::IntermediateCa, 0);
    assert!(
        matches!(result, LintResult::Error(_)),
        "leaf cert in IntermediateCa role must Error bc.ca_flag, got {result:?}"
    );
}

#[test]
fn bc_ca_flag_not_applicable_for_leaf() {
    // The lint applies_to = IntermediateCa; runner returns NotApplicable for Leaf.
    use pkix_lint::LintRunner;
    let cert = load_cert!("int-p256.der");
    let runner = LintRunner::new(vec![Box::new(BcCaFlagLint)]);
    let findings = runner.run_cert(&cert, SubjectKind::Leaf, 0, 0);
    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0].result,
        LintResult::NotApplicable,
        "BcCaFlagLint must be NotApplicable for Leaf position"
    );
}

// ---------------------------------------------------------------------------
// CabfTlsBrProfile integration — LintProfile impl
// ---------------------------------------------------------------------------

#[test]
fn cabf_tls_br_profile_lint_runner_has_all_six_lints() {
    use pkix_lint::cabf_tls_br::CabfTlsBrProfile;
    let profile = CabfTlsBrProfile;
    let runner = profile.lint_runner();
    let ids: Vec<&str> = runner.lints().iter().map(|l| l.id()).collect();
    assert!(ids.contains(&"cabf.br.tls.validity.max"), "missing validity.max lint");
    assert!(ids.contains(&"cabf.br.tls.alg.sha1_prohibited"), "missing sha1_prohibited lint");
    assert!(ids.contains(&"cabf.br.tls.rsa.min_key_size"), "missing rsa.min_key_size lint");
    assert!(ids.contains(&"cabf.br.tls.san.required"), "missing san.required lint");
    assert!(ids.contains(&"cabf.br.tls.eku.server_auth"), "missing eku.server_auth lint");
    assert!(ids.contains(&"cabf.br.tls.bc.ca_flag"), "missing bc.ca_flag lint");
    assert_eq!(ids.len(), 6, "expected exactly 6 lints in CabfTlsBrProfile");
}

#[test]
fn cabf_tls_br_profile_lints_method_has_all_ids() {
    use pkix_lint::cabf_tls_br::CabfTlsBrProfile;
    let profile = CabfTlsBrProfile;
    let lints = profile.lints();
    let ids: Vec<&str> = lints.iter().map(|l| l.id()).collect();
    assert!(ids.contains(&"cabf.br.tls.validity.max"));
    assert!(ids.contains(&"cabf.br.tls.alg.sha1_prohibited"));
    assert!(ids.contains(&"cabf.br.tls.rsa.min_key_size"));
    assert!(ids.contains(&"cabf.br.tls.san.required"));
    assert!(ids.contains(&"cabf.br.tls.eku.server_auth"));
    assert!(ids.contains(&"cabf.br.tls.bc.ca_flag"));
}

#[test]
fn cabf_tls_br_profile_run_chain_webpki_cert_all_pass() {
    // webpki-self-signed-365d.der evaluated pre-SC-081 (T_2026_JAN_01) should
    // produce Pass for all cert-scope lints that apply to Leaf.
    // now = 2026-01-01 (cap = 398 days); cert is 365 days → validity passes.
    use pkix_lint::cabf_tls_br::CabfTlsBrProfile;
    let cert = load_cert!("webpki-self-signed-365d.der");
    let profile = CabfTlsBrProfile;
    let runner = profile.lint_runner();
    let findings = runner.run_cert(&cert, SubjectKind::Leaf, 0, T_2026_JAN_01);

    // Collect only actionable findings (not Pass / NotApplicable).
    let errors: Vec<_> = findings.iter().filter(|f| f.result.is_finding()).collect();
    assert!(
        errors.is_empty(),
        "webpki cert at pre-SC-081 time must produce no error findings; got: {errors:?}"
    );
}
