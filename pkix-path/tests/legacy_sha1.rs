//! Legacy SHA-1 verification: it works when asked for, and is absent otherwise.
//!
//! The stance these tests encode is verify-only, opt-in, off by default.
//! SHA-1 chains exist in the field — pre-2018 government PKI, federal
//! bridge cross-certs, long-lived enterprise CAs — and a client that
//! cannot check them cannot tell its user anything useful. Nothing here
//! signs with SHA-1 and nothing is intended to.
//!
//! Vectors in `tests/fixtures/legacy-sha1/` are real signatures produced
//! by pyca/cryptography, so these exercise the actual crypto rather than a
//! round trip against this crate's own output. The P-384 pair exists to
//! pin the documented scope limit.
//!
//! Run: cargo test -p pkix-path --features rsa-sha1,ecdsa-sha1 --test legacy_sha1

#![cfg(any(feature = "rsa-sha1", feature = "ecdsa-sha1"))]

use pkix_path::{SignatureVerifier, VerificationErrorKind};
use spki::der::referenced::OwnedToRef as _;
use spki::der::Decode as _;
use spki::SubjectPublicKeyInfoRef;

const MSG: &[u8] = b"pkix-path legacy SHA-1 verification test vector";

const SHA1_WITH_RSA: &str = "1.2.840.113549.1.1.5";
const ECDSA_WITH_SHA1: &str = "1.2.840.10045.4.1";

fn fixture(name: &str) -> Vec<u8> {
    let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/legacy-sha1")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

fn alg(oid: &str) -> spki::AlgorithmIdentifierOwned {
    spki::AlgorithmIdentifierOwned {
        oid: oid.parse().expect("oid"),
        parameters: None,
    }
}

/// RSA PKCS#1 v1.5 over SHA-1 verifies a genuine signature.
#[cfg(feature = "rsa-sha1")]
#[test]
fn rsa_pkcs1v15_sha1_verifies_a_real_signature() {
    use pkix_path::RsaPkcs1v15Sha1Verifier;

    let spki_der = fixture("rsa-spki.bin");
    let spki = SubjectPublicKeyInfoRef::from_der(&spki_der).expect("spki");
    let sig = fixture("rsa-sig.bin");

    RsaPkcs1v15Sha1Verifier
        .verify_signature(alg(SHA1_WITH_RSA).owned_to_ref(), spki, MSG, &sig)
        .expect("a real SHA-1 signature must verify");

    // sha1WithRSAEncryption carries an explicit NULL in the wild; both
    // that and an absent parameter must be accepted. Re-decoded because
    // SubjectPublicKeyInfoRef is not Copy.
    let spki = SubjectPublicKeyInfoRef::from_der(&spki_der).expect("spki");
    let with_null = spki::AlgorithmIdentifierOwned {
        oid: SHA1_WITH_RSA.parse().expect("oid"),
        parameters: Some(spki::der::Any::null()),
    };
    RsaPkcs1v15Sha1Verifier
        .verify_signature(with_null.owned_to_ref(), spki, MSG, &sig)
        .expect("an explicit NULL parameter is the common encoding");
}

/// A tampered message does not verify, so the test above is not vacuous.
#[cfg(feature = "rsa-sha1")]
#[test]
fn rsa_pkcs1v15_sha1_rejects_a_tampered_message() {
    use pkix_path::RsaPkcs1v15Sha1Verifier;

    let spki_der = fixture("rsa-spki.bin");
    let spki = SubjectPublicKeyInfoRef::from_der(&spki_der).expect("spki");
    let sig = fixture("rsa-sig.bin");
    let mut tampered = MSG.to_vec();
    tampered[0] ^= 0x01;

    let err = RsaPkcs1v15Sha1Verifier
        .verify_signature(alg(SHA1_WITH_RSA).owned_to_ref(), spki, &tampered, &sig)
        .expect_err("a changed message must not verify");
    assert_eq!(err.kind(), VerificationErrorKind::InvalidSignature);
}

/// The verifier answers only for its own OID; a SHA-256 signature is not
/// silently checked with SHA-1.
#[cfg(feature = "rsa-sha1")]
#[test]
fn rsa_pkcs1v15_sha1_refuses_other_algorithms() {
    use pkix_path::RsaPkcs1v15Sha1Verifier;

    let spki_der = fixture("rsa-spki.bin");
    let spki = SubjectPublicKeyInfoRef::from_der(&spki_der).expect("spki");
    let sig = fixture("rsa-sig.bin");

    let err = RsaPkcs1v15Sha1Verifier
        .verify_signature(alg("1.2.840.113549.1.1.11").owned_to_ref(), spki, MSG, &sig)
        .expect_err("sha256WithRSAEncryption is not this verifier's business");
    assert_eq!(err.kind(), VerificationErrorKind::UnsupportedAlgorithm);
}

/// ECDSA P-256 over SHA-1 verifies a genuine signature.
///
/// This is the path where the digest is shorter than the field, so it also
/// exercises the FIPS 186-4 left-padding.
#[cfg(feature = "ecdsa-sha1")]
#[test]
fn ecdsa_p256_sha1_verifies_a_real_signature() {
    use pkix_path::EcdsaP256Sha1Verifier;

    let spki_der = fixture("ecdsa-spki.bin");
    let spki = SubjectPublicKeyInfoRef::from_der(&spki_der).expect("spki");
    let sig = fixture("ecdsa-sig.bin");

    EcdsaP256Sha1Verifier
        .verify_signature(alg(ECDSA_WITH_SHA1).owned_to_ref(), spki, MSG, &sig)
        .expect("a real ECDSA P-256 + SHA-1 signature must verify");
}

#[cfg(feature = "ecdsa-sha1")]
#[test]
fn ecdsa_p256_sha1_rejects_a_tampered_message() {
    use pkix_path::EcdsaP256Sha1Verifier;

    let spki_der = fixture("ecdsa-spki.bin");
    let spki = SubjectPublicKeyInfoRef::from_der(&spki_der).expect("spki");
    let sig = fixture("ecdsa-sig.bin");
    let mut tampered = MSG.to_vec();
    tampered[0] ^= 0x01;

    let err = EcdsaP256Sha1Verifier
        .verify_signature(alg(ECDSA_WITH_SHA1).owned_to_ref(), spki, &tampered, &sig)
        .expect_err("a changed message must not verify");
    assert_eq!(err.kind(), VerificationErrorKind::InvalidSignature);
}

/// The documented scope limit is enforced, and says the curve was why.
///
/// `ecdsa-with-SHA1` names no curve, so a P-384 key with a P-384+SHA-1
/// signature is well-formed and out of scope. It must be refused as
/// `UnsupportedKey` — not verified against P-256 by mistake, and not reported as
/// an invalid signature, which would suggest a bad certificate.
#[cfg(feature = "ecdsa-sha1")]
#[test]
fn ecdsa_sha1_refuses_a_p384_key_as_unsupported_not_invalid() {
    use pkix_path::EcdsaP256Sha1Verifier;

    let spki_der = fixture("p384-spki.bin");
    let spki = SubjectPublicKeyInfoRef::from_der(&spki_der).expect("spki");
    let sig = fixture("p384-sig.bin");

    let err = EcdsaP256Sha1Verifier
        .verify_signature(alg(ECDSA_WITH_SHA1).owned_to_ref(), spki, MSG, &sig)
        .expect_err("P-384 is out of scope for this verifier");
    assert_eq!(
        err.kind(),
        VerificationErrorKind::UnsupportedKey,
        "the curve is the problem, and the error should say so"
    );
}

/// `DefaultVerifier` dispatches SHA-1 when the features are compiled in.
///
/// The verifiers being reachable directly is not enough: a caller
/// validating a legacy chain goes through `DefaultVerifier`, so that is
/// where it has to work.
#[test]
fn default_verifier_dispatches_the_enabled_sha1_algorithms() {
    use pkix_path::DefaultVerifier;

    #[cfg(feature = "rsa-sha1")]
    {
        let spki_der = fixture("rsa-spki.bin");
        let spki = SubjectPublicKeyInfoRef::from_der(&spki_der).expect("spki");
        let sig = fixture("rsa-sig.bin");
        DefaultVerifier
            .verify_signature(alg(SHA1_WITH_RSA).owned_to_ref(), spki, MSG, &sig)
            .expect("DefaultVerifier must dispatch sha1WithRSAEncryption when rsa-sha1 is on");
    }
    #[cfg(feature = "ecdsa-sha1")]
    {
        let spki_der = fixture("ecdsa-spki.bin");
        let spki = SubjectPublicKeyInfoRef::from_der(&spki_der).expect("spki");
        let sig = fixture("ecdsa-sig.bin");
        DefaultVerifier
            .verify_signature(alg(ECDSA_WITH_SHA1).owned_to_ref(), spki, MSG, &sig)
            .expect("DefaultVerifier must dispatch ecdsa-with-SHA1 when ecdsa-sha1 is on");
    }
}
