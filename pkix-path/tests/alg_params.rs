//! Algorithm and key parameters the RSA-PSS and Ed25519 verifiers must read.
//!
//! These tests call [`SignatureVerifier::verify_signature`] directly on the
//! raw DER in `tests/fixtures/alg-params/` rather than validating a
//! certificate. A certificate cannot express these cases: its
//! `signatureAlgorithm` is covered by its own signature, so changing a
//! parameter to disagree with the signature that was produced also
//! invalidates it, and the disagreement is the whole subject here.
//!
//! Every signature in that directory is genuine for the parameters it is
//! named after, and every key is sound. So each verdict below turns on one
//! comparison between a declared parameter and the signature or key it is
//! declared about, and on nothing else. A verifier that skips the
//! comparison accepts the signature -- the fail-open direction.
//!
//! Oracle: `cryptography` produced the signatures, and the rules are quoted
//! from RFC 3279 §2.3.1, RFC 4055 §1.2 and §3.1 and RFC 8410 §3. See
//! `gen.py` in the fixture directory.
#![cfg(all(feature = "rsa", feature = "ed25519"))]

use der::Decode as _;
use pkix_path::{
    Ed25519Verifier, RsaPkcs1v15Sha256Verifier, RsaPssVerifier, SignatureVerifier,
    VerificationErrorKind,
};
use spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};

fn bytes(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/alg-params/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

/// Verdict of `verifier` on one (algorithm, key, signature) triple, reduced
/// to the error kind so the assertions read as the rule they are about.
fn check<V: SignatureVerifier>(
    verifier: &V,
    alg_file: &str,
    key_file: &str,
    sig_file: &str,
) -> Result<(), VerificationErrorKind> {
    let alg_der = bytes(alg_file);
    let key_der = bytes(key_file);
    let signature = bytes(sig_file);
    let message = bytes("message.bin");
    let algorithm = AlgorithmIdentifierRef::from_der(&alg_der).expect("algorithm identifier");
    let key = SubjectPublicKeyInfoRef::from_der(&key_der).expect("subject public key info");
    verifier
        .verify_signature(algorithm, key, &message, &signature)
        .map_err(|e| e.kind())
}

// ---------------------------------------------------------------------------
// RFC 4055 §2.1: the hash table, including the SHA-384 row
// ---------------------------------------------------------------------------

/// Each PSS parameter set verifies the signature made under it.
///
/// SHA-384 is the row that matters: the `sigalgs` corpus has PSS with
/// SHA-256 and SHA-512 and nothing with SHA-384, so its arm of the RFC 4055
/// §2.1 hash table went unreached, and a build that answered `None` there
/// would have refused a perfectly ordinary signature.
#[test]
fn pss_verifies_a_signature_made_under_its_own_parameters() {
    for (digest, salt) in [("sha256", 32), ("sha256", 48), ("sha384", 48)] {
        let alg = format!("alg-pss-{digest}-salt{salt}.der");
        let sig = format!("sig-pss-{digest}-salt{salt}.bin");
        assert_eq!(
            check(&RsaPssVerifier, &alg, "rsa-spki.der", &sig),
            Ok(()),
            "{digest} with salt {salt}"
        );
    }
}

/// RFC 4055 §3.1: the parameters are required. Their ASN.1 defaults name
/// SHA-1, which this crate does not verify PSS under, so an absent
/// parameter field is an unsupported algorithm rather than a SHA-1 attempt.
#[test]
fn pss_without_parameters_is_unsupported() {
    assert_eq!(
        check(
            &RsaPssVerifier,
            "alg-pss-no-params.der",
            "rsa-spki.der",
            "sig-pss-sha256-salt32.bin",
        ),
        Err(VerificationErrorKind::UnsupportedAlgorithm)
    );
}

// ---------------------------------------------------------------------------
// RFC 4055 §3.1: one hash for both the digest and MGF1
// ---------------------------------------------------------------------------

/// `hashAlgorithm` and the MGF1 parameter must name the same hash.
///
/// The fixture declares SHA-384 for MGF1 and SHA-256 for the digest, over a
/// signature that really is SHA-256 with MGF1-SHA-256. Verification runs
/// under the hash read from `hashAlgorithm`, so a verifier that does not
/// compare the two accepts this signature and reports a mask generation
/// function it never used.
#[test]
fn a_pss_signature_names_one_hash_for_the_digest_and_mgf1() {
    assert_eq!(
        check(
            &RsaPssVerifier,
            "alg-pss-mgf-sha384-hash-sha256.der",
            "rsa-spki.der",
            "sig-pss-sha256-salt32.bin",
        ),
        Err(VerificationErrorKind::UnsupportedAlgorithm)
    );
}

// ---------------------------------------------------------------------------
// RFC 3279 §2.3.1 and RFC 4055 §1.2: what the key's own OID allows
// ---------------------------------------------------------------------------

/// An `rsaEncryption` key's parameters MUST be NULL (RFC 3279 §2.3.1).
///
/// The bogus-parameters fixture is the same modulus with an INTEGER in the
/// parameters, and the signature over it is genuine, so a verifier that
/// reads the OID and ignores the parameters returns `Ok`.
#[test]
fn an_rsa_encryption_key_carries_null_parameters() {
    assert_eq!(
        check(
            &RsaPkcs1v15Sha256Verifier,
            "alg-sha256-rsa.der",
            "rsa-spki.der",
            "sig-pkcs1v15-sha256.bin",
        ),
        Ok(()),
        "the same key and signature with NULL parameters"
    );
    assert_eq!(
        check(
            &RsaPkcs1v15Sha256Verifier,
            "alg-sha256-rsa.der",
            "rsa-spki-bogus-params.der",
            "sig-pkcs1v15-sha256.bin",
        ),
        Err(VerificationErrorKind::UnsupportedKey)
    );
}

/// A key identified by `id-RSASSA-PSS` is restricted to PSS (RFC 4055 §1.2).
///
/// `pss-spki-bare` is the same modulus under that OID, and the PKCS#1 v1.5
/// signature offered with it is one that key really produced. The refusal
/// is about the key's OID, not about the arithmetic, which is why the
/// signature verifies when the same key is presented for PSS.
#[test]
fn a_pss_restricted_key_is_not_a_pkcs1v15_key() {
    assert_eq!(
        check(
            &RsaPkcs1v15Sha256Verifier,
            "alg-sha256-rsa.der",
            "pss-spki-bare.der",
            "sig-pkcs1v15-sha256.bin",
        ),
        Err(VerificationErrorKind::UnsupportedKey)
    );
    assert_eq!(
        check(
            &RsaPssVerifier,
            "alg-pss-sha256-salt32.der",
            "pss-spki-bare.der",
            "sig-pss-sha256-salt32.bin",
        ),
        Ok(()),
        "a bare id-RSASSA-PSS key is a PSS key"
    );
}

/// Neither RSA verifier takes a key of another type.
///
/// An Ed25519 `SubjectPublicKeyInfo` has absent parameters, which satisfies
/// half of the `rsaEncryption` test on its own; the key type is the other
/// half, and `UnsupportedKey` rather than `MalformedKey` is what says the
/// key was read and rejected rather than failing to parse as RSA.
#[test]
fn an_rsa_verifier_refuses_a_key_of_another_type() {
    assert_eq!(
        check(
            &RsaPkcs1v15Sha256Verifier,
            "alg-sha256-rsa.der",
            "ed25519-spki.der",
            "sig-pkcs1v15-sha256.bin",
        ),
        Err(VerificationErrorKind::UnsupportedKey)
    );
    assert_eq!(
        check(
            &RsaPssVerifier,
            "alg-pss-sha256-salt32.der",
            "ed25519-spki.der",
            "sig-pss-sha256-salt32.bin",
        ),
        Err(VerificationErrorKind::UnsupportedKey)
    );
}

// ---------------------------------------------------------------------------
// RFC 4055 §3.1: parameters carried by the key constrain its signatures
// ---------------------------------------------------------------------------

/// A PSS key that names a hash accepts signatures under that hash only.
///
/// The key says SHA-384; the signature is a genuine SHA-256 one with a salt
/// long enough to satisfy the key's floor, so the hash is the only thing
/// wrong with it.
#[test]
fn a_pss_key_pins_the_hash_its_signatures_use() {
    assert_eq!(
        check(
            &RsaPssVerifier,
            "alg-pss-sha384-salt48.der",
            "pss-spki-sha384-salt48.der",
            "sig-pss-sha384-salt48.bin",
        ),
        Ok(()),
        "the hash the key names"
    );
    assert_eq!(
        check(
            &RsaPssVerifier,
            "alg-pss-sha256-salt48.der",
            "pss-spki-sha384-salt48.der",
            "sig-pss-sha256-salt48.bin",
        ),
        Err(VerificationErrorKind::UnsupportedKey)
    );
}

/// A PSS key's `saltLength` is a floor, not an exact match.
///
/// RFC 4055 §3.1 reads the key's salt length as the minimum its signatures
/// must use, so a longer salt is fine and a shorter one is not. Both
/// directions are here because one comparison decides both, and a verifier
/// that has the inequality backwards refuses the stronger signature while
/// accepting the weaker.
#[test]
fn a_pss_key_sets_a_salt_floor_not_a_ceiling() {
    assert_eq!(
        check(
            &RsaPssVerifier,
            "alg-pss-sha256-salt48.der",
            "pss-spki-sha256-salt32.der",
            "sig-pss-sha256-salt48.bin",
        ),
        Ok(()),
        "a salt longer than the key requires"
    );
    assert_eq!(
        check(
            &RsaPssVerifier,
            "alg-pss-sha256-salt32.der",
            "pss-spki-sha256-salt48.der",
            "sig-pss-sha256-salt32.bin",
        ),
        Err(VerificationErrorKind::UnsupportedKey),
        "a salt shorter than the key requires"
    );
}

// ---------------------------------------------------------------------------
// RFC 8410 §3: Ed25519 takes absent parameters
// ---------------------------------------------------------------------------

/// `id-Ed25519` carries no parameters, in the key as well as the signature
/// algorithm.
///
/// The NULL-parameters fixture is otherwise a working key over a genuine
/// signature, so a verifier that checks only the key's OID accepts it.
#[test]
fn ed25519_takes_no_key_parameters() {
    assert_eq!(
        check(
            &Ed25519Verifier,
            "alg-ed25519.der",
            "ed25519-spki.der",
            "sig-ed25519.bin",
        ),
        Ok(()),
        "the same key and signature with the parameters absent"
    );
    assert_eq!(
        check(
            &Ed25519Verifier,
            "alg-ed25519.der",
            "ed25519-spki-null-params.der",
            "sig-ed25519.bin",
        ),
        Err(VerificationErrorKind::UnsupportedKey)
    );
}
