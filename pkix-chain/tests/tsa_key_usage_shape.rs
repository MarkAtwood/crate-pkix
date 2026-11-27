//! RFC 3161 §2.1 #10: a TSA key is for signing and nothing else.
//!
//! `enforce_timestamping_ku_shape` rejects a TSA leaf asserting any
//! non-signing KeyUsage bit. The check is one seven-way `||` chain, and a
//! mutation sweep found five of its six `||` operators unguarded.
//!
//! Why five, and why one test per bit: mutating the i-th `||` to `&&` costs
//! the i-th bit its standalone power, because `A || B || C` becomes
//! `A && B || C`, which parses as `(A && B) || C`. A certificate with only
//! `A` set then stops being rejected. The pre-existing
//! `leaf-timestamping-bad-ku.der` asserts digitalSignature + keyEncipherment,
//! so it kills the first operator and tells us nothing about the rest. Each
//! remaining operator needs a certificate with exactly one bit set.
//!
//! Fixtures: `tests/fixtures/tsa-ku/` (see `gen.py`). KeyUsage is raw DER
//! there, because `cryptography` refuses `encipherOnly` without
//! `keyAgreement` — correctly, per RFC 5280 — and that pairing would trip the
//! rule through `keyAgreement` and prove nothing about `encipherOnly`.

use pkix_chain::{
    verify_time_stamper, DefaultVerifier, Error, NoAiaFetcher, NoRevocation, ProfileViolationKind,
    TrustAnchor,
};
use pkix_profiles::BasicTimeStampingProfile;
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

const NOW: u64 = 1_800_000_000; // 2027-01-15, inside the fixtures' window

fn load(name: &str) -> Certificate {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/tsa-ku")
        .join(format!("{name}.der"));
    Certificate::from_der(&std::fs::read(&p).expect("fixture present")).expect("parses")
}

fn run(leaf: &str) -> Result<pkix_chain::ValidatedPath, Error> {
    verify_time_stamper(
        &[load(leaf)],
        &[TrustAnchor::from_cert(load("tsa-ku-root"))],
        &BasicTimeStampingProfile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
}

/// Each non-signing bit is rejected on its own, citing the rule.
///
/// One assertion per bit rather than one fixture with several set: a
/// certificate asserting two of them cannot show which one did the
/// rejecting, and that is exactly the distinction the surviving mutations
/// turned on.
///
/// The error kind is checked in the same loop rather than in a second test.
/// A separate "is it rejected" test was written first and had its Result
/// inverted — `unwrap_or_else` panics on the `Err` that is the expected
/// outcome — so it failed for the one bit that worked. Asserting the kind
/// subsumes asserting the refusal, so there is no second loop.
#[test]
fn the_refusal_cites_the_key_usage_rule() {
    for bit in [
        "data-encipherment",
        "key-agreement",
        "key-cert-sign",
        "crl-sign",
        "encipher-only",
        "decipher-only",
    ] {
        match run(&format!("tsa-ku-{bit}")).expect_err("must be refused") {
            Error::ProfileViolation { kind, .. } => assert_eq!(
                kind,
                ProfileViolationKind::TsaKeyUsageNotSigningOnly,
                "{bit} must cite the TSA key-usage rule"
            ),
            other => panic!("{bit}: expected ProfileViolation, got {other:?}"),
        }
    }
}

/// `digitalSignature` alone validates.
///
/// Without this the tests above would pass against a wrapper that refused
/// every timestamping certificate — the fixtures share a root, an EKU shape
/// and a validity window, so a fault in any of those would look like the
/// KeyUsage rule firing.
#[test]
fn digital_signature_alone_is_a_valid_tsa_key_shape() {
    run("tsa-ku-digital-signature")
        .expect("RFC 3161 permits a signing-only key; digitalSignature is exactly that");
}
