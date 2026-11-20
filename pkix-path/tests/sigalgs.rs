//! Signature-algorithm coverage of the `RustCrypto` verifiers.
//!
//! Oracle: every fixture pair in `tests/fixtures/sigalgs/` was produced by
//! the OpenSSL CLI and accepted by `openssl verify` (see `gen.sh` there);
//! pkix-path played no part in producing the expected verdicts.
//!
//! The ECDSA cases cross curves and digests on purpose: OpenSSL signs with
//! SHA-256 by default whatever the curve, so a P-384 or P-521 issuer key
//! with `ecdsa-with-SHA256` is common. The curve must come from the
//! issuer's `SubjectPublicKeyInfo`, not from the signature OID.
#![cfg(all(
    feature = "p256",
    feature = "p384",
    feature = "p521",
    feature = "rsa",
    feature = "ed25519"
))]

mod support {
    pub mod raw_cert;
}

use der::Decode as _;
use pkix_path::{
    validate_path, DefaultVerifier, EcdsaP256Verifier, EcdsaP384Verifier, EcdsaP521Verifier,
    Ed25519Verifier, Error, RsaPkcs1v15Sha256Verifier, RsaPssVerifier, SignatureVerifier,
    TrustAnchor, ValidationPolicy,
};
use x509_cert::Certificate;

/// 2027-01-01T00:00:00Z, inside every fixture's validity window.
const NOW: u64 = 1_798_761_600;

fn load(name: &str) -> Certificate {
    let path = format!(
        "{}/tests/fixtures/sigalgs/{name}.der",
        env!("CARGO_MANIFEST_DIR")
    );
    Certificate::from_der(&std::fs::read(&path).expect("read fixture")).expect("parse fixture")
}

fn pair(case: &str) -> (Certificate, Certificate) {
    (load(&format!("{case}-leaf")), load(&format!("{case}-ca")))
}

fn validate<V: SignatureVerifier>(case: &str, verifier: &V) -> Result<(), Error> {
    let (leaf, ca) = pair(case);
    let anchors = [TrustAnchor::from_cert(ca)];
    validate_path(&[leaf], &anchors, &ValidationPolicy::new(NOW), verifier).map(|_| ())
}

/// Copy of `cert` with one bit of its signature flipped.
fn tamper(cert: &Certificate) -> Certificate {
    support::raw_cert::edit_cert(cert, |raw| {
        let mut sig = raw.signature.raw_bytes().to_vec();
        let mid = sig.len() / 2;
        sig[mid] ^= 0x01;
        raw.signature = der::asn1::BitString::from_bytes(&sig).expect("bit string");
    })
}

const ALL_CASES: &[&str] = &[
    "p256-sha256",
    "p256-sha384",
    "p384-sha256",
    "p384-sha384",
    "p521-sha256",
    "p521-sha512",
    "rsa-pss-sha256",
    "rsa-pss-sha512",
    "rsa-pss-key",
    "ed25519",
];

#[test]
fn default_verifier_accepts_every_openssl_pair() {
    for case in ALL_CASES {
        validate(case, &DefaultVerifier).unwrap_or_else(|e| panic!("{case}: {e:?}"));
    }
}

#[test]
fn default_verifier_rejects_tampered_signatures() {
    for case in ALL_CASES {
        let (leaf, ca) = pair(case);
        let anchors = [TrustAnchor::from_cert(ca)];
        let result = validate_path(
            &[tamper(&leaf)],
            &anchors,
            &ValidationPolicy::new(NOW),
            &DefaultVerifier,
        );
        assert_eq!(
            result.map(|_| ()),
            Err(Error::SignatureInvalid { index: 0 }),
            "{case}: tampered signature must not verify"
        );
    }
}

/// Regression: a P-384 key signing with `ecdsa-with-SHA256` used to fail
/// because the curve was chosen from the signature OID.
#[test]
fn p384_key_with_sha256_digest_verifies() {
    validate("p384-sha256", &DefaultVerifier).expect("DefaultVerifier");
    validate("p384-sha256", &EcdsaP384Verifier).expect("EcdsaP384Verifier");
}

#[test]
fn p256_key_with_sha384_digest_verifies() {
    validate("p256-sha384", &EcdsaP256Verifier).expect("EcdsaP256Verifier");
}

#[test]
fn p521_verifier_accepts_sha256_and_sha512() {
    validate("p521-sha256", &EcdsaP521Verifier).expect("SHA-256");
    validate("p521-sha512", &EcdsaP521Verifier).expect("SHA-512");
}

#[test]
fn per_curve_verifiers_reject_other_curves() {
    for (case, ok_for) in [
        ("p256-sha256", "p256"),
        ("p384-sha384", "p384"),
        ("p521-sha512", "p521"),
    ] {
        assert_eq!(
            validate(case, &EcdsaP256Verifier).is_ok(),
            ok_for == "p256",
            "{case}"
        );
        assert_eq!(
            validate(case, &EcdsaP384Verifier).is_ok(),
            ok_for == "p384",
            "{case}"
        );
        assert_eq!(
            validate(case, &EcdsaP521Verifier).is_ok(),
            ok_for == "p521",
            "{case}"
        );
    }
}

#[test]
fn rsa_pss_verifier_accepts_openssl_pss() {
    validate("rsa-pss-sha256", &RsaPssVerifier).expect("PSS SHA-256, salt 32");
    validate("rsa-pss-sha512", &RsaPssVerifier).expect("PSS SHA-512, salt 64");
    // Issuer key is an id-RSASSA-PSS key restricted to SHA-256 (RFC 4055 §1.2).
    validate("rsa-pss-key", &RsaPssVerifier).expect("id-RSASSA-PSS issuer key");
}

#[test]
fn pkcs1v15_verifier_rejects_pss_signature() {
    assert_eq!(
        validate("rsa-pss-sha256", &RsaPkcs1v15Sha256Verifier),
        Err(Error::SignatureInvalid { index: 0 })
    );
}

#[test]
fn ed25519_verifier_accepts_openssl_ed25519() {
    validate("ed25519", &Ed25519Verifier).expect("Ed25519");
    assert_eq!(
        validate("p256-sha256", &Ed25519Verifier),
        Err(Error::SignatureInvalid { index: 0 })
    );
}
