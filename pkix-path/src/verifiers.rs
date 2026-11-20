//! `RustCrypto` [`SignatureVerifier`] backends.
//!
//! Every verifier here takes the algorithm from two places, as RFC 5280
//! §4.1.1.2 and RFC 5480 §2.1.1 require:
//!
//! - the **key type and curve** come from the issuer's
//!   `SubjectPublicKeyInfo` (for ECDSA, its `namedCurve` parameter), and
//! - the **signature scheme and digest** come from the subject's
//!   `signatureAlgorithm`.
//!
//! So a P-384 issuer key that signs with `ecdsa-with-SHA256` (OpenSSL's
//! default digest for EC keys) verifies, and an ECDSA signature whose
//! algorithm OID names one digest cannot be checked against a curve chosen
//! from that OID.

// With only some backend features enabled, the OIDs and helpers of the
// others are unused; gating each item separately would obscure the code.
#![cfg_attr(
    not(all(
        feature = "p256",
        feature = "p384",
        feature = "p521",
        feature = "rsa",
        feature = "ed25519"
    )),
    allow(dead_code, unused_imports, unused_variables)
)]

use crate::SignatureVerifier;
#[cfg(any(feature = "p256", feature = "p384", feature = "p521", feature = "rsa"))]
use crate::Vec;
use der::asn1::ObjectIdentifier;
use signature::Error as SignatureError;
use spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};

type VerifyResult = core::result::Result<(), SignatureError>;

// ---------------------------------------------------------------------------
// OIDs
// ---------------------------------------------------------------------------

/// `ecdsa-with-SHA256` (RFC 5758 §3.2): 1.2.840.10045.4.3.2.
pub(crate) const OID_ECDSA_WITH_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
/// `ecdsa-with-SHA384` (RFC 5758 §3.2): 1.2.840.10045.4.3.3.
pub(crate) const OID_ECDSA_WITH_SHA384: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
/// `ecdsa-with-SHA512` (RFC 5758 §3.2): 1.2.840.10045.4.3.4.
pub(crate) const OID_ECDSA_WITH_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

/// `id-ecPublicKey` (RFC 5480 §2.1.1): 1.2.840.10045.2.1.
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// `secp256r1` / `prime256v1` (RFC 5480 §2.1.1.1).
const OID_SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
/// `secp384r1` (RFC 5480 §2.1.1.1).
const OID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
/// `secp521r1` (RFC 5480 §2.1.1.1).
const OID_SECP521R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");

/// `rsaEncryption` (RFC 3279 §2.3.1).
pub(crate) const OID_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
/// `sha256WithRSAEncryption` (RFC 4055 §5).
pub(crate) const OID_SHA256_WITH_RSA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
/// `sha384WithRSAEncryption` (RFC 4055 §5).
pub(crate) const OID_SHA384_WITH_RSA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
/// `sha512WithRSAEncryption` (RFC 4055 §5).
pub(crate) const OID_SHA512_WITH_RSA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
/// `id-RSASSA-PSS` (RFC 4055 §3.1).
pub(crate) const OID_RSASSA_PSS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
/// `id-mgf1` (RFC 4055 §2.2).
#[cfg(feature = "rsa")]
const OID_MGF1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");
/// `id-sha256` (RFC 4055 §2.1).
#[cfg(feature = "rsa")]
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
/// `id-sha384` (RFC 4055 §2.1).
#[cfg(feature = "rsa")]
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
/// `id-sha512` (RFC 4055 §2.1).
#[cfg(feature = "rsa")]
const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

/// `id-Ed25519` (RFC 8410 §3): 1.3.101.112.
pub(crate) const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

// ---------------------------------------------------------------------------
// Digest selection
// ---------------------------------------------------------------------------

/// A SHA-2 digest named by a signature or hash algorithm OID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sha2 {
    Sha256,
    Sha384,
    Sha512,
}

/// Digest named by an `ecdsa-with-SHA*` signature OID, or `None`.
fn ecdsa_digest(oid: ObjectIdentifier) -> Option<Sha2> {
    match oid {
        OID_ECDSA_WITH_SHA256 => Some(Sha2::Sha256),
        OID_ECDSA_WITH_SHA384 => Some(Sha2::Sha384),
        OID_ECDSA_WITH_SHA512 => Some(Sha2::Sha512),
        _ => None,
    }
}

#[cfg(any(feature = "p256", feature = "p384", feature = "p521", feature = "rsa"))]
fn sha2_digest(alg: Sha2, message: &[u8]) -> Vec<u8> {
    use sha2::Digest as _;
    match alg {
        Sha2::Sha256 => sha2::Sha256::digest(message).to_vec(),
        Sha2::Sha384 => sha2::Sha384::digest(message).to_vec(),
        Sha2::Sha512 => sha2::Sha512::digest(message).to_vec(),
    }
}

// ---------------------------------------------------------------------------
// ECDSA
// ---------------------------------------------------------------------------

/// Named curve of an `id-ecPublicKey` SPKI, or `None` for any other key.
fn ec_named_curve(spki: &SubjectPublicKeyInfoRef<'_>) -> Option<ObjectIdentifier> {
    if spki.algorithm.oid != OID_EC_PUBLIC_KEY {
        return None;
    }
    spki.algorithm
        .parameters?
        .decode_as::<ObjectIdentifier>()
        .ok()
}

/// Left-pads a digest shorter than the curve order with zero bytes.
///
/// SEC 1 v2 §4.1.4 step 5 converts the digest to an integer, so leading
/// zero bytes do not change the value. The `ecdsa` crate rejects prehashes
/// shorter than half the field size, which would otherwise refuse, for
/// example, P-521 with `ecdsa-with-SHA256`.
#[cfg(any(feature = "p256", feature = "p384", feature = "p521"))]
fn pad_prehash(mut digest: Vec<u8>, field_len: usize) -> Vec<u8> {
    if digest.len() < field_len {
        let mut padded = vec![0u8; field_len - digest.len()];
        padded.append(&mut digest);
        padded
    } else {
        digest
    }
}

macro_rules! ecdsa_curve_verify {
    ($fn_name:ident, $feature:literal, $krate:ident, $field_len:expr) => {
        #[cfg(feature = $feature)]
        fn $fn_name(
            spki: SubjectPublicKeyInfoRef<'_>,
            digest: Sha2,
            message: &[u8],
            signature: &[u8],
        ) -> VerifyResult {
            use signature::hazmat::PrehashVerifier as _;
            use $krate::ecdsa::{DerSignature, VerifyingKey};

            let vk = VerifyingKey::try_from(spki).map_err(|_| SignatureError::new())?;
            let sig = DerSignature::try_from(signature).map_err(|_| SignatureError::new())?;
            let prehash = pad_prehash(sha2_digest(digest, message), $field_len);
            vk.verify_prehash(&prehash, &sig)
                .map_err(|_| SignatureError::new())
        }
    };
}

ecdsa_curve_verify!(verify_ecdsa_p256, "p256", p256, 32);
ecdsa_curve_verify!(verify_ecdsa_p384, "p384", p384, 48);
ecdsa_curve_verify!(verify_ecdsa_p521, "p521", p521, 66);

/// Which curves an ECDSA verifier accepts.
#[derive(Clone, Copy)]
struct Curves {
    p256: bool,
    p384: bool,
    p521: bool,
}

/// ECDSA dispatch: digest from `algorithm`, curve from `issuer_spki`.
fn verify_ecdsa(
    curves: Curves,
    algorithm: AlgorithmIdentifierRef<'_>,
    issuer_spki: SubjectPublicKeyInfoRef<'_>,
    message: &[u8],
    signature: &[u8],
) -> VerifyResult {
    let digest = ecdsa_digest(algorithm.oid).ok_or_else(SignatureError::new)?;
    // RFC 5758 §3.2: the parameters field MUST be absent.
    if algorithm.parameters.is_some() {
        return Err(SignatureError::new());
    }
    let curve = ec_named_curve(&issuer_spki).ok_or_else(SignatureError::new)?;
    match curve {
        #[cfg(feature = "p256")]
        OID_SECP256R1 if curves.p256 => verify_ecdsa_p256(issuer_spki, digest, message, signature),
        #[cfg(feature = "p384")]
        OID_SECP384R1 if curves.p384 => verify_ecdsa_p384(issuer_spki, digest, message, signature),
        #[cfg(feature = "p521")]
        OID_SECP521R1 if curves.p521 => verify_ecdsa_p521(issuer_spki, digest, message, signature),
        _ => Err(SignatureError::new()),
    }
}

macro_rules! ecdsa_verifier {
    ($(#[$doc:meta])* $name:ident, $feature:literal, $field:ident) => {
        $(#[$doc])*
        #[cfg(feature = $feature)]
        #[cfg_attr(docsrs, doc(cfg(feature = $feature)))]
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
        pub struct $name;

        #[cfg(feature = $feature)]
        impl SignatureVerifier for $name {
            fn verify_signature(
                &self,
                algorithm: AlgorithmIdentifierRef<'_>,
                issuer_spki: SubjectPublicKeyInfoRef<'_>,
                message: &[u8],
                signature: &[u8],
            ) -> VerifyResult {
                let curves = Curves {
                    p256: false,
                    p384: false,
                    p521: false,
                };
                let curves = Curves {
                    $field: true,
                    ..curves
                };
                verify_ecdsa(curves, algorithm, issuer_spki, message, signature)
            }
        }
    };
}

ecdsa_verifier!(
    /// ECDSA verifier for P-256 (`secp256r1`) issuer keys.
    ///
    /// Accepts `ecdsa-with-SHA256`, `ecdsa-with-SHA384` and
    /// `ecdsa-with-SHA512` (RFC 5758 §3.2; the `parameters` field must be
    /// absent). Rejects issuer keys on any other curve.
    /// Feature-gated behind `p256`.
    EcdsaP256Verifier,
    "p256",
    p256
);

ecdsa_verifier!(
    /// ECDSA verifier for P-384 (`secp384r1`) issuer keys.
    ///
    /// Accepts `ecdsa-with-SHA256`, `ecdsa-with-SHA384` and
    /// `ecdsa-with-SHA512` (RFC 5758 §3.2; the `parameters` field must be
    /// absent). Rejects issuer keys on any other curve.
    /// Feature-gated behind `p384`.
    EcdsaP384Verifier,
    "p384",
    p384
);

ecdsa_verifier!(
    /// ECDSA verifier for P-521 (`secp521r1`) issuer keys.
    ///
    /// Accepts `ecdsa-with-SHA256`, `ecdsa-with-SHA384` and
    /// `ecdsa-with-SHA512` (RFC 5758 §3.2; the `parameters` field must be
    /// absent). Rejects issuer keys on any other curve.
    /// Feature-gated behind `p521`.
    EcdsaP521Verifier,
    "p521",
    p521
);

// ---------------------------------------------------------------------------
// RSA
// ---------------------------------------------------------------------------

/// Decodes an RSA public key from an SPKI whose algorithm is `rsaEncryption`
/// (parameters NULL or absent, RFC 3279 §2.3.1) or, when `allow_pss_key` is
/// set, `id-RSASSA-PSS` (RFC 4055 §1.2).
///
/// Moduli from 1024 to 8192 bits are accepted (the `rsa` crate's limits).
#[cfg(feature = "rsa")]
fn rsa_public_key(
    spki: &SubjectPublicKeyInfoRef<'_>,
    allow_pss_key: bool,
) -> core::result::Result<rsa::PublicKey, SignatureError> {
    use rsa::pkcs1::DecodeRsaPublicKey as _;

    let oid_ok = spki.algorithm.oid == OID_RSA_ENCRYPTION
        && spki.algorithm.parameters.is_none_or(|p| p.is_null());
    let pss_ok = allow_pss_key && spki.algorithm.oid == OID_RSASSA_PSS;
    if !(oid_ok || pss_ok) {
        return Err(SignatureError::new());
    }
    let key_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(SignatureError::new)?;
    rsa::PublicKey::from_pkcs1_der(key_bytes).map_err(|_| SignatureError::new())
}

/// RSA PKCS#1 v1.5 verification with the given digest.
#[cfg(feature = "rsa")]
fn verify_rsa_pkcs1v15(
    digest: Sha2,
    algorithm: AlgorithmIdentifierRef<'_>,
    issuer_spki: SubjectPublicKeyInfoRef<'_>,
    message: &[u8],
    signature: &[u8],
) -> VerifyResult {
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier as _;

    // RFC 4055 §5: parameters MUST be NULL; absent is accepted for
    // interoperability, matching the issuer-key decoding above.
    if !algorithm.parameters.is_none_or(|p| p.is_null()) {
        return Err(SignatureError::new());
    }
    let key = rsa_public_key(&issuer_spki, false)?;
    let sig = Signature::try_from(signature).map_err(|_| SignatureError::new())?;
    let result = match digest {
        Sha2::Sha256 => VerifyingKey::<sha2::Sha256>::new(key).verify(message, &sig),
        Sha2::Sha384 => VerifyingKey::<sha2::Sha384>::new(key).verify(message, &sig),
        Sha2::Sha512 => VerifyingKey::<sha2::Sha512>::new(key).verify(message, &sig),
    };
    result.map_err(|_| SignatureError::new())
}

/// Hash named by an RFC 4055 `HashAlgorithm` identifier (parameters NULL or
/// absent, RFC 4055 §2.1).
#[cfg(feature = "rsa")]
fn rfc4055_hash(alg: &spki::AlgorithmIdentifierOwned) -> Option<Sha2> {
    if !alg.parameters.as_ref().is_none_or(der::Any::is_null) {
        return None;
    }
    match alg.oid {
        OID_SHA256 => Some(Sha2::Sha256),
        OID_SHA384 => Some(Sha2::Sha384),
        OID_SHA512 => Some(Sha2::Sha512),
        _ => None,
    }
}

/// RSASSA-PSS verification (RFC 4055 §3.1, RFC 8017 §8.1.2).
///
/// Supported parameters: `hashAlgorithm` SHA-256, SHA-384 or SHA-512;
/// `maskGenAlgorithm` MGF1 over the same hash; any `saltLength`;
/// `trailerField` 1. The default parameters (SHA-1) are rejected.
#[cfg(feature = "rsa")]
fn verify_rsa_pss(
    algorithm: AlgorithmIdentifierRef<'_>,
    issuer_spki: SubjectPublicKeyInfoRef<'_>,
    message: &[u8],
    signature: &[u8],
) -> VerifyResult {
    use der::{Decode as _, Encode as _};
    use rsa::pkcs1::{RsaPssParamsOwned, TrailerField};
    use rsa::pss::{Signature, VerifyingKey};
    use rsa::signature::hazmat::PrehashVerifier as _;

    let params_der = algorithm
        .parameters
        .ok_or_else(SignatureError::new)?
        .to_der()
        .map_err(|_| SignatureError::new())?;
    let params = RsaPssParamsOwned::from_der(&params_der).map_err(|_| SignatureError::new())?;
    let hash = rfc4055_hash(&params.hash).ok_or_else(SignatureError::new)?;
    if params.mask_gen.oid != OID_MGF1 {
        return Err(SignatureError::new());
    }
    let mgf_hash = params
        .mask_gen
        .parameters
        .as_ref()
        .and_then(rfc4055_hash)
        .ok_or_else(SignatureError::new)?;
    if mgf_hash != hash || params.trailer_field != TrailerField::BC {
        return Err(SignatureError::new());
    }
    // RFC 4055 §3.1: when the issuer key is an id-RSASSA-PSS key with
    // parameters, the signature must use the same hash and MGF and a salt
    // at least as long. We check the hash and MGF; a key restricted that
    // way still verifies only signatures that match its own parameters.
    if issuer_spki.algorithm.oid == OID_RSASSA_PSS {
        if let Some(key_params) = issuer_spki.algorithm.parameters {
            let key_params_der = key_params.to_der().map_err(|_| SignatureError::new())?;
            let key_params =
                RsaPssParamsOwned::from_der(&key_params_der).map_err(|_| SignatureError::new())?;
            let key_hash = rfc4055_hash(&key_params.hash).ok_or_else(SignatureError::new)?;
            if key_hash != hash || params.salt_len < key_params.salt_len {
                return Err(SignatureError::new());
            }
        }
    }
    let key = rsa_public_key(&issuer_spki, true)?;
    let sig = Signature::try_from(signature).map_err(|_| SignatureError::new())?;
    let salt_len = usize::from(params.salt_len);
    let prehash = sha2_digest(hash, message);
    let result = match hash {
        Sha2::Sha256 => VerifyingKey::<sha2::Sha256>::new_with_salt_len(key, salt_len)
            .verify_prehash(&prehash, &sig),
        Sha2::Sha384 => VerifyingKey::<sha2::Sha384>::new_with_salt_len(key, salt_len)
            .verify_prehash(&prehash, &sig),
        Sha2::Sha512 => VerifyingKey::<sha2::Sha512>::new_with_salt_len(key, salt_len)
            .verify_prehash(&prehash, &sig),
    };
    result.map_err(|_| SignatureError::new())
}

macro_rules! rsa_pkcs1v15_verifier {
    ($(#[$doc:meta])* $name:ident, $oid:ident, $digest:ident) => {
        $(#[$doc])*
        #[cfg(feature = "rsa")]
        #[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
        pub struct $name;

        #[cfg(feature = "rsa")]
        impl SignatureVerifier for $name {
            fn verify_signature(
                &self,
                algorithm: AlgorithmIdentifierRef<'_>,
                issuer_spki: SubjectPublicKeyInfoRef<'_>,
                message: &[u8],
                signature: &[u8],
            ) -> VerifyResult {
                if algorithm.oid != $oid {
                    return Err(SignatureError::new());
                }
                verify_rsa_pkcs1v15(Sha2::$digest, algorithm, issuer_spki, message, signature)
            }
        }
    };
}

rsa_pkcs1v15_verifier!(
    /// RSA with PKCS#1 v1.5 padding and SHA-256 signature verifier.
    ///
    /// Handles OID `sha256WithRSAEncryption` (1.2.840.113549.1.1.11).
    /// Feature-gated behind `rsa`.
    RsaPkcs1v15Sha256Verifier,
    OID_SHA256_WITH_RSA,
    Sha256
);

rsa_pkcs1v15_verifier!(
    /// RSA with PKCS#1 v1.5 padding and SHA-384 signature verifier.
    ///
    /// Handles OID `sha384WithRSAEncryption` (1.2.840.113549.1.1.12).
    /// Feature-gated behind `rsa`.
    RsaPkcs1v15Sha384Verifier,
    OID_SHA384_WITH_RSA,
    Sha384
);

rsa_pkcs1v15_verifier!(
    /// RSA with PKCS#1 v1.5 padding and SHA-512 signature verifier.
    ///
    /// Handles OID `sha512WithRSAEncryption` (1.2.840.113549.1.1.13).
    /// Feature-gated behind `rsa`.
    RsaPkcs1v15Sha512Verifier,
    OID_SHA512_WITH_RSA,
    Sha512
);

/// RSASSA-PSS signature verifier (RFC 4055 §3.1).
///
/// Handles OID `id-RSASSA-PSS` (1.2.840.113549.1.1.10) with
/// `hashAlgorithm` SHA-256, SHA-384 or SHA-512, `maskGenAlgorithm` MGF1
/// over the same hash, any `saltLength`, and `trailerField` 1. The issuer
/// key may be `rsaEncryption` or `id-RSASSA-PSS`. Feature-gated behind
/// `rsa`.
#[cfg(feature = "rsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct RsaPssVerifier;

#[cfg(feature = "rsa")]
impl SignatureVerifier for RsaPssVerifier {
    fn verify_signature(
        &self,
        algorithm: AlgorithmIdentifierRef<'_>,
        issuer_spki: SubjectPublicKeyInfoRef<'_>,
        message: &[u8],
        signature: &[u8],
    ) -> VerifyResult {
        if algorithm.oid != OID_RSASSA_PSS {
            return Err(SignatureError::new());
        }
        verify_rsa_pss(algorithm, issuer_spki, message, signature)
    }
}

// ---------------------------------------------------------------------------
// Ed25519
// ---------------------------------------------------------------------------

/// Ed25519 signature verifier (RFC 8410, RFC 8032 §5.1.7).
///
/// Handles OID `id-Ed25519` (1.3.101.112) for both the signature algorithm
/// and the issuer key; RFC 8410 §3 requires absent parameters in both.
/// Verification uses `ed25519-dalek`'s `verify_strict`, which also rejects
/// small-order public keys and non-canonical signatures.
/// Feature-gated behind `ed25519`.
#[cfg(feature = "ed25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "ed25519")))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Ed25519Verifier;

#[cfg(feature = "ed25519")]
impl SignatureVerifier for Ed25519Verifier {
    fn verify_signature(
        &self,
        algorithm: AlgorithmIdentifierRef<'_>,
        issuer_spki: SubjectPublicKeyInfoRef<'_>,
        message: &[u8],
        signature: &[u8],
    ) -> VerifyResult {
        if algorithm.oid != OID_ED25519
            || algorithm.parameters.is_some()
            || issuer_spki.algorithm.oid != OID_ED25519
            || issuer_spki.algorithm.parameters.is_some()
        {
            return Err(SignatureError::new());
        }
        let key_bytes: &[u8; 32] = issuer_spki
            .subject_public_key
            .as_bytes()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(SignatureError::new)?;
        let vk = ed25519_dalek::VerifyingKey::from_bytes(key_bytes)
            .map_err(|_| SignatureError::new())?;
        let sig =
            ed25519_dalek::Signature::from_slice(signature).map_err(|_| SignatureError::new())?;
        vk.verify_strict(message, &sig)
            .map_err(|_| SignatureError::new())
    }
}

// ---------------------------------------------------------------------------
// DefaultVerifier
// ---------------------------------------------------------------------------

/// A [`SignatureVerifier`] covering every `RustCrypto` backend enabled at
/// build time.
///
/// This is the recommended out-of-the-box verifier. With all backend
/// features on (`rustcrypto`) it supports:
///
/// - ECDSA (`ecdsa-with-SHA256`, `-SHA384`, `-SHA512`) on P-256, P-384 and
///   P-521 issuer keys (features `p256`, `p384`, `p521`). The curve is taken
///   from the issuer's `SubjectPublicKeyInfo`, not from the signature OID.
/// - RSA PKCS#1 v1.5 with SHA-256, SHA-384 or SHA-512 (feature `rsa`).
/// - RSASSA-PSS as described on [`RsaPssVerifier`] (feature `rsa`).
/// - Ed25519 (feature `ed25519`).
///
/// Anything else returns `Err(signature::Error::new())`, including SHA-1
/// based algorithms.
///
/// To support additional algorithms, implement [`SignatureVerifier`]
/// directly and fall back to `DefaultVerifier` for the rest.
#[cfg(any(
    feature = "p256",
    feature = "p384",
    feature = "p521",
    feature = "rsa",
    feature = "ed25519"
))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "p256",
        feature = "p384",
        feature = "p521",
        feature = "rsa",
        feature = "ed25519"
    )))
)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct DefaultVerifier;

#[cfg(any(
    feature = "p256",
    feature = "p384",
    feature = "p521",
    feature = "rsa",
    feature = "ed25519"
))]
impl SignatureVerifier for DefaultVerifier {
    fn verify_signature(
        &self,
        algorithm: AlgorithmIdentifierRef<'_>,
        issuer_spki: SubjectPublicKeyInfoRef<'_>,
        message: &[u8],
        signature: &[u8],
    ) -> VerifyResult {
        let oid = algorithm.oid;
        if ecdsa_digest(oid).is_some() {
            let curves = Curves {
                p256: cfg!(feature = "p256"),
                p384: cfg!(feature = "p384"),
                p521: cfg!(feature = "p521"),
            };
            return verify_ecdsa(curves, algorithm, issuer_spki, message, signature);
        }
        #[cfg(feature = "rsa")]
        {
            let digest = match oid {
                OID_SHA256_WITH_RSA => Some(Sha2::Sha256),
                OID_SHA384_WITH_RSA => Some(Sha2::Sha384),
                OID_SHA512_WITH_RSA => Some(Sha2::Sha512),
                _ => None,
            };
            if let Some(digest) = digest {
                return verify_rsa_pkcs1v15(digest, algorithm, issuer_spki, message, signature);
            }
            if oid == OID_RSASSA_PSS {
                return verify_rsa_pss(algorithm, issuer_spki, message, signature);
            }
        }
        #[cfg(feature = "ed25519")]
        if oid == OID_ED25519 {
            return Ed25519Verifier.verify_signature(algorithm, issuer_spki, message, signature);
        }
        Err(SignatureError::new())
    }
}
