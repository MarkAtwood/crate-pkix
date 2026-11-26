//! Verifying the TLS handshake signature with this workspace's parser
//! and crypto, instead of rustls's helper.
//!
//! # Why this is not delegated
//!
//! rustls will do this for you —
//! [`rustls::crypto::verify_tls12_signature`] and its TLS 1.3 twin —
//! and this crate used to call them. They begin like this:
//!
//! ```text
//! let cert = webpki::EndEntityCert::try_from(cert)?;
//! cert.verify_signature(alg, message, dss.signature())
//! ```
//!
//! So webpki parses the leaf certificate, on every handshake, to pull
//! the public key out of it. Delegating therefore meant **two X.509
//! parsers touching the same certificate**: this workspace's for the
//! chain, webpki's for the handshake signature. Two parsers disagreeing
//! about one certificate is the thing this workspace exists to be
//! careful about, so the delegation was the wrong trade even though the
//! signature check itself is not a PKI question.
//!
//! Doing it here means `x509-cert` parses the certificate and
//! [`pkix_path::SignatureVerifier`] verifies the signature, and no
//! webpki code runs in the connection at all — the default verifier is
//! not installed, and this was the only other live path into it. webpki
//! remains linked, because rustls depends on it unconditionally, but it
//! is dead code.
//!
//! # What has to be exactly right
//!
//! A TLS `SignatureScheme` says more than an X.509 signature OID does,
//! and the extra constraints are the security-relevant part:
//!
//! - **The curve.** `ecdsa_secp256r1_sha256` means P-256 specifically,
//!   while the X.509 OID `ecdsa-with-SHA256` says nothing about the
//!   curve — that comes from the key. A peer that signs with
//!   `ecdsa_secp256r1_sha256` using a P-384 key is violating RFC 8446
//!   §4.2.3, and accepting it would make this verifier laxer than the
//!   one it replaces. The curve is checked against the key.
//! - **PKCS#1 v1.5 is forbidden in TLS 1.3.** RFC 8446 §4.2.3: the
//!   `rsa_pkcs1_*` schemes are for certificate signatures only and
//!   "MUST NOT be used in signed TLS handshake messages". They are
//!   refused in the 1.3 path and allowed in 1.2.
//! - **PSS parameters.** `rsa_pss_rsae_sha256` fixes the hash, the MGF1
//!   hash and a salt length equal to the hash length. Those have to be
//!   encoded into the `AlgorithmIdentifier`, because that is how
//!   `pkix-path` is told what to do; getting them wrong would either
//!   reject good signatures or, worse, accept a weaker parameter set
//!   than the peer advertised. The encodings are checked byte-for-byte
//!   against real CA-emitted ones in the tests.

use der::asn1::ObjectIdentifier;
use der::{Decode as _, Encode as _};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::{CertificateError, Error as RustlsError, PeerMisbehaved, SignatureScheme};
use rustls_pki_types::CertificateDer;
use x509_cert::spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};
use x509_cert::Certificate;

use pkix_path::SignatureVerifier;

/// Which TLS version's rules apply to the signature being checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// RFC 5246. `rsa_pkcs1_*` is permitted here.
    Tls12,
    /// RFC 8446. `rsa_pkcs1_*` is not.
    Tls13,
}

// X.509 signature algorithm OIDs, written as dotted strings and encoded
// by `const-oid` rather than by hand.
const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_SHA384_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const OID_SHA512_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
const OID_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
const OID_MGF1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");
const OID_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_WITH_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_ECDSA_WITH_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_SECP521R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");

/// DER tags used when building the `AlgorithmIdentifier`s.
const TAG_SEQUENCE: u8 = 0x30;
const TAG_OID: u8 = 0x06;
const TAG_NULL: u8 = 0x05;
const TAG_INTEGER: u8 = 0x02;

/// Wrap `body` in a DER tag-length-value triple.
///
/// Every structure built here is far below 128 octets, so the length is
/// always short-form; the assertion holds that true rather than
/// trusting it.
fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    assert!(body.len() < 0x80, "short-form length only");
    let mut out = Vec::with_capacity(2 + body.len());
    out.push(tag);
    out.push(body.len() as u8);
    out.extend_from_slice(body);
    out
}

/// `AlgorithmIdentifier { algorithm, parameters NULL }` — RFC 3279
/// §2.3.1 for the RSA PKCS#1 v1.5 OIDs, and the shape RFC 4055 uses for
/// a hash algorithm.
fn alg_id_null(oid: ObjectIdentifier) -> Vec<u8> {
    let mut body = tlv(TAG_OID, oid.as_bytes());
    body.extend_from_slice(&tlv(TAG_NULL, &[]));
    tlv(TAG_SEQUENCE, &body)
}

/// `AlgorithmIdentifier { algorithm }` with the parameters absent —
/// RFC 5758 §3.2 for ECDSA, RFC 8410 §3 for Ed25519.
fn alg_id_absent(oid: ObjectIdentifier) -> Vec<u8> {
    tlv(TAG_SEQUENCE, &tlv(TAG_OID, oid.as_bytes()))
}

/// `AlgorithmIdentifier` for `id-RSASSA-PSS` with RFC 4055 §3.1
/// parameters: `hashAlgorithm` and an MGF1 `maskGenAlgorithm` over the
/// same hash, with `saltLength` equal to the hash length and the
/// default `trailerField`.
///
/// Those are the parameters the TLS `rsa_pss_rsae_*` schemes mean, per
/// RFC 8446 §4.2.3. `trailerField` is left at its DEFAULT of 1 by
/// omission, matching what CAs emit — the encodings are compared
/// against real ones in the tests.
fn alg_id_pss(hash: ObjectIdentifier, salt_len: u8) -> Vec<u8> {
    let hash_alg = alg_id_null(hash);
    let mut mgf_body = tlv(TAG_OID, OID_MGF1.as_bytes());
    mgf_body.extend_from_slice(&hash_alg);
    let mgf_alg = tlv(TAG_SEQUENCE, &mgf_body);

    let mut params = Vec::new();
    // [0] hashAlgorithm, [1] maskGenAlgorithm, [2] saltLength — all
    // EXPLICIT, since RFC 4055 declares them so.
    params.extend_from_slice(&tlv(0xA0, &hash_alg));
    params.extend_from_slice(&tlv(0xA1, &mgf_alg));
    params.extend_from_slice(&tlv(0xA2, &tlv(TAG_INTEGER, &[salt_len])));

    let mut body = tlv(TAG_OID, OID_RSASSA_PSS.as_bytes());
    body.extend_from_slice(&tlv(TAG_SEQUENCE, &params));
    tlv(TAG_SEQUENCE, &body)
}

/// What a TLS signature scheme requires of the certificate and the
/// signature.
struct SchemeRules {
    /// The X.509 `AlgorithmIdentifier` to hand `pkix-path`.
    algorithm: Vec<u8>,
    /// For ECDSA, the curve the key must be on. `None` for RSA and
    /// Ed25519, whose schemes do not name a curve.
    required_curve: Option<ObjectIdentifier>,
    /// Whether RFC 8446 §4.2.3 permits this scheme in a TLS 1.3
    /// `CertificateVerify`.
    allowed_in_tls13: bool,
}

/// Translate a TLS signature scheme into the X.509 terms `pkix-path`
/// speaks, or `None` for a scheme this crate cannot verify.
///
/// `None` covers schemes nobody should be using — the two SHA-1 ones,
/// which TLS 1.3 removed and which no current profile permits — and
/// ones not implemented here: Ed448 and the ML-DSA set. A peer that
/// signs with any of them is signing with something
/// [`supported_verify_schemes`](crate::PkixServerCertVerifier) never
/// advertised.
fn scheme_rules(scheme: SignatureScheme) -> Option<SchemeRules> {
    let (algorithm, required_curve, allowed_in_tls13) = match scheme {
        // RSASSA-PKCS1-v1_5. Certificate signatures only in TLS 1.3.
        SignatureScheme::RSA_PKCS1_SHA256 => (alg_id_null(OID_SHA256_WITH_RSA), None, false),
        SignatureScheme::RSA_PKCS1_SHA384 => (alg_id_null(OID_SHA384_WITH_RSA), None, false),
        SignatureScheme::RSA_PKCS1_SHA512 => (alg_id_null(OID_SHA512_WITH_RSA), None, false),

        // RSASSA-PSS. Salt length equals the hash length.
        SignatureScheme::RSA_PSS_SHA256 => (alg_id_pss(OID_SHA256, 32), None, true),
        SignatureScheme::RSA_PSS_SHA384 => (alg_id_pss(OID_SHA384, 48), None, true),
        SignatureScheme::RSA_PSS_SHA512 => (alg_id_pss(OID_SHA512, 64), None, true),

        // ECDSA. The scheme names the curve; the OID does not, so the
        // curve is carried here and checked against the key.
        SignatureScheme::ECDSA_NISTP256_SHA256 => (
            alg_id_absent(OID_ECDSA_WITH_SHA256),
            Some(OID_SECP256R1),
            true,
        ),
        SignatureScheme::ECDSA_NISTP384_SHA384 => (
            alg_id_absent(OID_ECDSA_WITH_SHA384),
            Some(OID_SECP384R1),
            true,
        ),
        SignatureScheme::ECDSA_NISTP521_SHA512 => (
            alg_id_absent(OID_ECDSA_WITH_SHA512),
            Some(OID_SECP521R1),
            true,
        ),

        SignatureScheme::ED25519 => (alg_id_absent(OID_ED25519), None, true),

        _ => return None,
    };
    Some(SchemeRules {
        algorithm,
        required_curve,
        allowed_in_tls13,
    })
}

/// Every scheme [`verify`] can check, most preferred first.
///
/// Ordering is the preference expressed to the peer: ECDSA and Ed25519
/// ahead of RSA, PSS ahead of PKCS#1 v1.5. The PKCS#1 entries are last
/// because they are only usable in TLS 1.2.
pub const SUPPORTED_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ED25519,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

/// Verify a handshake signature against the key in `cert`.
///
/// Takes the scheme and signature separately rather than rustls's
/// [`rustls::DigitallySignedStruct`], which cannot be constructed from
/// outside rustls — so a function taking one could not be tested
/// against a real signature. The trait methods destructure it and call
/// this.
///
/// # Errors
///
/// - [`rustls::PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme`]
///   if the scheme is one this crate does not verify, or one RFC 8446
///   §4.2.3 forbids in a TLS 1.3 handshake.
/// - [`rustls::CertificateError::BadEncoding`] if the certificate or
///   its public key will not parse.
/// - [`rustls::CertificateError::Other`] carrying [`CurveMismatch`] if
///   an ECDSA scheme names a curve the key is not on.
/// - [`rustls::CertificateError::BadSignature`] if the signature does
///   not verify.
pub fn verify<V: SignatureVerifier>(
    verifier: &V,
    message: &[u8],
    cert: &CertificateDer<'_>,
    scheme: SignatureScheme,
    signature: &[u8],
    protocol: Protocol,
) -> Result<HandshakeSignatureValid, RustlsError> {
    let rules =
        scheme_rules(scheme).ok_or(PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme)?;

    if protocol == Protocol::Tls13 && !rules.allowed_in_tls13 {
        // RFC 8446 §4.2.3. Letting this through would accept a
        // signature rustls itself refuses.
        return Err(PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme.into());
    }

    // Our parser, not webpki's. This is the whole point of the module.
    let parsed = Certificate::from_der(cert)
        .map_err(|_| RustlsError::InvalidCertificate(CertificateError::BadEncoding))?;
    let spki_der = parsed
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|_| RustlsError::InvalidCertificate(CertificateError::BadEncoding))?;
    let spki = SubjectPublicKeyInfoRef::from_der(&spki_der)
        .map_err(|_| RustlsError::InvalidCertificate(CertificateError::BadEncoding))?;

    if let Some(expected) = rules.required_curve {
        check_curve(&spki, expected)?;
    }

    let algorithm = AlgorithmIdentifierRef::from_der(&rules.algorithm)
        .expect("the algorithm identifiers built in this module are valid DER");

    verifier
        .verify_signature(algorithm, spki, message, signature)
        .map(|()| HandshakeSignatureValid::assertion())
        .map_err(|_| RustlsError::InvalidCertificate(CertificateError::BadSignature))
}

/// Require the key to be on the curve the scheme names.
///
/// RFC 8446 §4.2.3 ties each `ecdsa_*` scheme to one curve. The X.509
/// `ecdsa-with-SHA*` OIDs do not, so without this check a peer could
/// sign with `ecdsa_secp256r1_sha256` over a P-384 key and be believed
/// — which rustls's own verifier refuses, and being laxer than the
/// thing this replaces is not acceptable.
fn check_curve(
    spki: &SubjectPublicKeyInfoRef<'_>,
    expected: ObjectIdentifier,
) -> Result<(), RustlsError> {
    let mismatch = || {
        RustlsError::InvalidCertificate(CertificateError::Other(rustls::OtherError(
            std::sync::Arc::new(CurveMismatch),
        )))
    };
    if spki.algorithm.oid != OID_EC_PUBLIC_KEY {
        return Err(mismatch());
    }
    let params = spki.algorithm.parameters.ok_or_else(mismatch)?;
    let named = params
        .decode_as::<ObjectIdentifier>()
        .map_err(|_| mismatch())?;
    if named != expected {
        return Err(mismatch());
    }
    Ok(())
}

/// The peer signed with an ECDSA scheme whose curve is not the curve of
/// the key in its certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CurveMismatch;

impl std::fmt::Display for CurveMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "the ECDSA signature scheme names a different curve than the \
             certificate's public key is on (RFC 8446 §4.2.3)",
        )
    }
}

impl std::error::Error for CurveMismatch {}

#[cfg(test)]
mod tests {
    use super::*;

    /// A certificate is a signature over its own TBSCertificate, made
    /// with the issuer's key — which is exactly the shape of a
    /// handshake signature: *verify these bytes against the key in
    /// that certificate*. So the sigalgs corpus gives real signatures
    /// made by real keys, with no TLS stack and no private keys
    /// needed, and the fact that the signed bytes are a TBS rather
    /// than a transcript is nothing to this function.
    ///
    /// This is the test that matters. Everything else here checks the
    /// mapping; this checks that the mapping actually verifies
    /// signatures — in particular that the hand-built PSS parameters
    /// work against a signature OpenSSL produced, not merely that
    /// their bytes look right.
    /// `(leaf TBS bytes, leaf signature bytes, issuer certificate DER)`
    /// for one fixture pair.
    fn signed_by(stem: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../pkix-path/tests/fixtures/sigalgs");
        let leaf = std::fs::read(dir.join(format!("{stem}-leaf.der"))).expect("leaf fixture");
        let ca = std::fs::read(dir.join(format!("{stem}-ca.der"))).expect("ca fixture");
        let (tbs, sig) = split_signed(&leaf);
        (tbs.to_vec(), sig, ca)
    }

    /// `(tbsCertificate bytes, signatureValue bytes)` of a certificate.
    fn split_signed(der: &[u8]) -> (&[u8], Vec<u8>) {
        fn header(b: &[u8], i: usize) -> (usize, usize) {
            let first = b[i + 1];
            if first < 0x80 {
                (first as usize, 2)
            } else {
                let n = (first & 0x7F) as usize;
                let mut len = 0usize;
                for &x in &b[i + 2..i + 2 + n] {
                    len = (len << 8) | x as usize;
                }
                (len, 2 + n)
            }
        }
        let (cv, ch) = header(der, 0);
        let body = &der[ch..ch + cv];
        let (tv, th) = header(body, 0);
        let tbs = &body[..th + tv];
        // signatureAlgorithm, then signatureValue as a BIT STRING whose
        // first content octet is the unused-bit count.
        let (av, ah) = header(body, th + tv);
        let sig_off = th + tv + ah + av;
        let (sv, sh) = header(body, sig_off);
        let bitstring = &body[sig_off + sh..sig_off + sh + sv];
        (tbs, bitstring[1..].to_vec())
    }

    /// Real signatures, through the real verification path.
    #[test]
    fn real_signatures_verify_for_every_scheme_with_a_fixture() {
        let cases = [
            ("p256-sha256", SignatureScheme::ECDSA_NISTP256_SHA256),
            ("p384-sha384", SignatureScheme::ECDSA_NISTP384_SHA384),
            ("ed25519", SignatureScheme::ED25519),
            ("rsa-pss-sha256", SignatureScheme::RSA_PSS_SHA256),
            ("rsa-pss-sha512", SignatureScheme::RSA_PSS_SHA512),
        ];
        for (stem, scheme) in cases {
            let (tbs, sig, ca) = signed_by(stem);
            let cert = CertificateDer::from(ca.as_slice());

            verify(
                &pkix_path::DefaultVerifier,
                &tbs,
                &cert,
                scheme,
                &sig,
                Protocol::Tls13,
            )
            .unwrap_or_else(|e| panic!("{stem} with {scheme:?} should verify: {e:?}"));

            // One flipped byte in the signature must be refused. Without
            // this the test above would pass against a verifier that
            // accepted everything.
            let mut tampered = sig.clone();
            let last = tampered.len() - 1;
            tampered[last] ^= 0x01;
            let err = verify(
                &pkix_path::DefaultVerifier,
                &tbs,
                &cert,
                scheme,
                &tampered,
                Protocol::Tls13,
            )
            .expect_err("a tampered signature must not verify");
            assert!(
                matches!(
                    err,
                    RustlsError::InvalidCertificate(CertificateError::BadSignature)
                ),
                "{stem}: expected BadSignature, got {err:?}"
            );
        }
    }

    /// The curve check, against a real key on the wrong curve.
    ///
    /// The P-384 CA's key signs with `ecdsa-with-SHA384`, and
    /// `ecdsa_secp384r1_sha384` is the scheme for it. Asking the same
    /// signature to be read as `ecdsa_secp256r1_sha256` must be
    /// refused for naming the wrong curve, not merely fail to verify:
    /// RFC 8446 §4.2.3 ties the scheme to one curve, and accepting
    /// this would be laxer than rustls.
    #[test]
    fn an_ecdsa_scheme_naming_the_wrong_curve_is_refused() {
        let (tbs, sig, ca) = signed_by("p384-sha384");
        let cert = CertificateDer::from(ca.as_slice());

        let err = verify(
            &pkix_path::DefaultVerifier,
            &tbs,
            &cert,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &sig,
            Protocol::Tls13,
        )
        .expect_err("a P-384 key is not valid for the P-256 scheme");
        let RustlsError::InvalidCertificate(CertificateError::Other(other)) = &err else {
            panic!("expected Other(CurveMismatch), got {err:?}");
        };
        assert!(
            other.0.downcast_ref::<CurveMismatch>().is_some(),
            "the refusal must say the curve was wrong, not something else"
        );
    }

    /// PKCS#1 v1.5 is refused in TLS 1.3 before any cryptography runs,
    /// and the same inputs are accepted in TLS 1.2.
    #[test]
    fn pkcs1_is_refused_in_tls13_at_the_protocol_level() {
        let (tbs, sig, ca) = signed_by("rsa-pss-sha256");
        let cert = CertificateDer::from(ca.as_slice());

        // The signature is PSS, so it will not verify as PKCS#1 under
        // either protocol — but the TLS 1.3 refusal must come from the
        // protocol rule, which is a different error than a failed
        // signature.
        let err = verify(
            &pkix_path::DefaultVerifier,
            &tbs,
            &cert,
            SignatureScheme::RSA_PKCS1_SHA256,
            &sig,
            Protocol::Tls13,
        )
        .expect_err("PKCS#1 v1.5 is not permitted in TLS 1.3");
        assert!(
            !matches!(
                err,
                RustlsError::InvalidCertificate(CertificateError::BadSignature)
            ),
            "the refusal must be the protocol rule, not a signature failure: {err:?}"
        );

        // In TLS 1.2 the scheme is permitted, so it gets as far as the
        // cryptography and fails there instead.
        let err = verify(
            &pkix_path::DefaultVerifier,
            &tbs,
            &cert,
            SignatureScheme::RSA_PKCS1_SHA256,
            &sig,
            Protocol::Tls12,
        )
        .expect_err("a PSS signature is not a valid PKCS#1 signature");
        assert!(
            matches!(
                err,
                RustlsError::InvalidCertificate(CertificateError::BadSignature)
            ),
            "TLS 1.2 should reach the signature check: {err:?}"
        );
    }

    /// The PSS parameter encodings must match what a real CA emits.
    ///
    /// These are the `signatureAlgorithm` fields lifted out of
    /// `pkix-path/tests/fixtures/sigalgs/rsa-pss-sha{256,512}-leaf.der`,
    /// which were generated by OpenSSL. If what this module builds
    /// differs by a byte, `pkix-path` reads different parameters than
    /// the peer meant — rejecting good signatures at best, and
    /// accepting a weaker salt or hash than advertised at worst.
    #[test]
    fn pss_parameters_match_a_real_ca() {
        let sha256 = alg_id_pss(OID_SHA256, 32);
        assert_eq!(
            hex(&sha256),
            "304106092a864886f70d01010a3034a00f300d0609608648016503040201\
             0500a11c301a06092a864886f70d010108300d060960864801650304020105\
             00a203020120",
            "SHA-256 PSS parameters differ from the OpenSSL-emitted fixture"
        );

        let sha512 = alg_id_pss(OID_SHA512, 64);
        assert_eq!(
            hex(&sha512),
            "304106092a864886f70d01010a3034a00f300d0609608648016503040203\
             0500a11c301a06092a864886f70d010108300d060960864801650304020305\
             00a203020140",
            "SHA-512 PSS parameters differ from the OpenSSL-emitted fixture"
        );

        // SHA-384 has no fixture; the structure is identical and only
        // the hash OID and salt length move, which the two above pin.
        let sha384 = alg_id_pss(OID_SHA384, 48);
        assert_eq!(sha384.len(), sha256.len());
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Everything built here must re-read as the structure it claims to
    /// be, or `pkix-path` is handed something it will reject for the
    /// wrong reason.
    #[test]
    fn every_scheme_builds_valid_der() {
        for &scheme in SUPPORTED_SCHEMES {
            let rules = scheme_rules(scheme)
                .unwrap_or_else(|| panic!("{scheme:?} is advertised but has no rules"));
            AlgorithmIdentifierRef::from_der(&rules.algorithm)
                .unwrap_or_else(|e| panic!("{scheme:?} built invalid DER: {e}"));
        }
    }

    /// The advertised list and the implemented mapping must be the same
    /// set. Advertising a scheme we then refuse would make peers pick
    /// it and fail; implementing one we never advertise is dead code
    /// that a peer could still reach.
    #[test]
    fn advertised_and_implemented_agree() {
        for &scheme in SUPPORTED_SCHEMES {
            assert!(
                scheme_rules(scheme).is_some(),
                "{scheme:?} is advertised but not implemented"
            );
        }
        // The schemes deliberately left out.
        for scheme in [
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::ED448,
            SignatureScheme::ML_DSA_44,
            SignatureScheme::ML_DSA_65,
            SignatureScheme::ML_DSA_87,
        ] {
            assert!(
                scheme_rules(scheme).is_none(),
                "{scheme:?} is implemented but not advertised"
            );
            assert!(
                !SUPPORTED_SCHEMES.contains(&scheme),
                "{scheme:?} must not be advertised"
            );
        }
    }

    /// TLS 1.3 removed PKCS#1 v1.5 from handshake signatures, and TLS
    /// 1.2 did not.
    #[test]
    fn pkcs1_is_tls12_only() {
        for scheme in [
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ] {
            assert!(
                !scheme_rules(scheme).expect("implemented").allowed_in_tls13,
                "{scheme:?} must be refused in TLS 1.3"
            );
        }
        for scheme in [
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
        ] {
            assert!(
                scheme_rules(scheme).expect("implemented").allowed_in_tls13,
                "{scheme:?} must be allowed in TLS 1.3"
            );
        }
    }

    /// Each ECDSA scheme must carry its curve, and nothing else should.
    #[test]
    fn only_ecdsa_schemes_pin_a_curve() {
        assert_eq!(
            scheme_rules(SignatureScheme::ECDSA_NISTP256_SHA256)
                .unwrap()
                .required_curve,
            Some(OID_SECP256R1)
        );
        assert_eq!(
            scheme_rules(SignatureScheme::ECDSA_NISTP384_SHA384)
                .unwrap()
                .required_curve,
            Some(OID_SECP384R1)
        );
        assert_eq!(
            scheme_rules(SignatureScheme::ECDSA_NISTP521_SHA512)
                .unwrap()
                .required_curve,
            Some(OID_SECP521R1)
        );
        for scheme in [
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ED25519,
        ] {
            assert!(scheme_rules(scheme).unwrap().required_curve.is_none());
        }
    }
}
