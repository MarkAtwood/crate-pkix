//! Build DER-encoded OCSP requests suitable for HTTP POST to a responder.
//!
//! RFC 6960 §4.1.1 specifies the `OCSPRequest` ASN.1 structure; §A.1
//! specifies the HTTP transport (`POST` with `Content-Type:
//! application/ocsp-request`). [`build_ocsp_request`] produces both.

use der::Encode;
use x509_cert::Certificate;
use x509_ocsp::{builder::OcspRequestBuilder, Request};

/// Hash algorithm used in the `CertID.hashAlgorithm` field of an OCSP
/// request (RFC 6960 §4.1.1).
///
/// RFC 6960 §4.3 designates SHA-1 as the MUST-implement algorithm; nearly
/// all responders accept SHA-256 in practice. Other hashes (SHA-384,
/// SHA-512) are deployed too but are not yet exposed here — extending
/// the enum is a non-breaking change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OcspHashAlg {
    /// SHA-1 (RFC 3174). MUST-implement per RFC 6960 §4.3.
    Sha1,
    /// SHA-256 (FIPS 180-4). Widely supported in modern responders.
    Sha256,
}

/// DER bytes of an OCSP request and the matching `Content-Type` header
/// for an HTTP POST per RFC 6960 §A.1.
#[derive(Debug, Clone)]
pub struct OcspRequestBytes {
    /// DER-encoded `OCSPRequest`. Suitable as the body of an HTTP POST.
    pub body: Vec<u8>,
    /// Always `"application/ocsp-request"` (RFC 6960 §A.1).
    pub content_type: &'static str,
}

/// Errors returned by [`build_ocsp_request`].
#[derive(Debug)]
#[non_exhaustive]
pub enum BuildError {
    /// DER encoding of the request or its inputs failed.
    ///
    /// In practice this means the issuer certificate's
    /// `subject` distinguished name or `subjectPublicKeyInfo` failed to
    /// re-encode for hashing — both are pulled out of an already-parsed
    /// `Certificate`, so the failure mode is rare and indicates a
    /// structurally broken input.
    Asn1(der::Error),
}

impl core::fmt::Display for BuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Asn1(e) => write!(f, "OCSP request encoding error: {e}"),
        }
    }
}

impl std::error::Error for BuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Asn1(e) => Some(e),
        }
    }
}

impl From<der::Error> for BuildError {
    fn from(e: der::Error) -> Self {
        Self::Asn1(e)
    }
}

/// Build an OCSP request DER body and matching HTTP `Content-Type`.
///
/// Produces a single-`Request` `OCSPRequest` whose `CertID` is computed
/// from `(issuer.subject, issuer.spki, cert.serial)` per RFC 6960 §4.1.1.
/// No nonce extension is added (caller can add nonces later via a
/// follow-up; v0.x acceptance criteria explicitly defer nonces).
///
/// # Hashing
///
/// `hash_alg` controls the `CertID.hashAlgorithm`:
///
/// - [`OcspHashAlg::Sha1`] uses OID `1.3.14.3.2.26`.
/// - [`OcspHashAlg::Sha256`] uses OID `2.16.840.1.101.3.4.2.1`.
///
/// `AlgorithmIdentifier.parameters` is `NULL` in both cases, matching
/// `openssl ocsp -reqout`'s output (verified by the unit tests).
///
/// # Errors
///
/// Returns [`BuildError::Asn1`] if re-encoding the issuer's
/// `subject` DN or `subjectPublicKeyInfo` for hashing fails, or if the
/// resulting `OCSPRequest` cannot be DER-encoded. Both failure modes
/// require a structurally broken input cert.
pub fn build_ocsp_request(
    cert: &Certificate,
    issuer: &Certificate,
    hash_alg: OcspHashAlg,
) -> Result<OcspRequestBytes, BuildError> {
    // Request::from_cert::<D>(issuer, cert) builds a CertID by hashing the
    // issuer's DN and SPKI bits with D, and pulling the serial from cert.
    // This matches RFC 6960 §4.1.1 directly. We map x509-ocsp's builder
    // Error to ours; only the Asn1 variant is reachable here because
    // from_cert does no signing.
    let request = match hash_alg {
        OcspHashAlg::Sha1 => Request::from_cert::<sha1::Sha1>(issuer, cert),
        OcspHashAlg::Sha256 => Request::from_cert::<sha2::Sha256>(issuer, cert),
    }
    .map_err(map_builder_err)?;

    let req = OcspRequestBuilder::default().with_request(request).build();

    let body = req.to_der()?;

    Ok(OcspRequestBytes {
        body,
        content_type: "application/ocsp-request",
    })
}

/// Convert an x509-ocsp builder error to our [`BuildError`].
///
/// `Request::from_cert` only hits the `Asn1` arm in practice (no signing
/// is performed), but match exhaustively so a future x509-ocsp release
/// adding variants is a compile-time error rather than a silent drop.
fn map_builder_err(e: x509_ocsp::builder::Error) -> BuildError {
    match e {
        x509_ocsp::builder::Error::Asn1(d) => BuildError::Asn1(d),
        x509_ocsp::builder::Error::PublicKey(_) | x509_ocsp::builder::Error::Signature(_) => {
            // Build path is non-signing; these arms are unreachable in
            // practice but we still convert safely. Wrap as a synthetic
            // DER error so the public surface remains a single variant.
            BuildError::Asn1(der::Error::from(der::ErrorKind::Failed))
        }
    }
}

#[cfg(test)]
mod tests {
    //! OCSP request encoding tests.
    //!
    //! Independent oracle: `openssl ocsp -no_nonce -reqout` against the
    //! same cert + issuer pair, with `-sha1` and `-sha256` variants.
    //! Reference DER files committed under `tests/fixtures/`. The
    //! generation recipe is `tests/fixtures/gen.sh`. A re-run produces
    //! identical bytes for the request files even if the cert serial
    //! changes — `-no_nonce` removes the only random part.
    //!
    //! Stability rationale: the `CertID.hashAlgorithm` field is encoded
    //! with `parameters: NULL` by both x509-ocsp and openssl, so the
    //! `AlgorithmIdentifier` matches byte-for-byte. The remaining
    //! `CertID` fields (issuerNameHash, issuerKeyHash, serial) are
    //! deterministic functions of the input certs.
    use super::*;
    use der::Decode;

    const CA: &[u8] = include_bytes!("../tests/fixtures/ca.der");
    const LEAF: &[u8] = include_bytes!("../tests/fixtures/leaf.der");
    const REQ_SHA1: &[u8] = include_bytes!("../tests/fixtures/req-sha1.der");
    const REQ_SHA256: &[u8] = include_bytes!("../tests/fixtures/req-sha256.der");

    fn fixtures() -> (Certificate, Certificate) {
        let ca = Certificate::from_der(CA).expect("CA fixture parses");
        let leaf = Certificate::from_der(LEAF).expect("leaf fixture parses");
        (ca, leaf)
    }

    #[test]
    fn sha1_request_matches_openssl_byte_for_byte() {
        let (ca, leaf) = fixtures();
        let out = build_ocsp_request(&leaf, &ca, OcspHashAlg::Sha1).unwrap();
        assert_eq!(out.content_type, "application/ocsp-request");
        assert_eq!(
            out.body,
            REQ_SHA1,
            "SHA-1 OCSP request does not match openssl reference (len {} vs {})",
            out.body.len(),
            REQ_SHA1.len()
        );
    }

    #[test]
    fn sha256_request_matches_openssl_byte_for_byte() {
        let (ca, leaf) = fixtures();
        let out = build_ocsp_request(&leaf, &ca, OcspHashAlg::Sha256).unwrap();
        assert_eq!(out.content_type, "application/ocsp-request");
        assert_eq!(
            out.body,
            REQ_SHA256,
            "SHA-256 OCSP request does not match openssl reference (len {} vs {})",
            out.body.len(),
            REQ_SHA256.len()
        );
    }

    #[test]
    fn output_round_trips_through_x509_ocsp_parser() {
        // Sanity check: whatever bytes we emit must decode as an OCSPRequest.
        // Independent of openssl. Any time we emit something the parser
        // rejects, this catches it.
        let (ca, leaf) = fixtures();
        for alg in [OcspHashAlg::Sha1, OcspHashAlg::Sha256] {
            let out = build_ocsp_request(&leaf, &ca, alg).unwrap();
            x509_ocsp::OcspRequest::from_der(&out.body).expect("emitted bytes must round-trip");
        }
    }

    #[test]
    fn cert_id_uses_issuer_subject_not_self() {
        // Regression guard: the CertID's issuerNameHash MUST be over the
        // issuer's subject DN, not the leaf's subject DN. If we ever
        // accidentally swap arguments, this catches it.
        let (ca, leaf) = fixtures();
        let with_correct = build_ocsp_request(&leaf, &ca, OcspHashAlg::Sha256).unwrap();
        let with_swapped = build_ocsp_request(&ca, &leaf, OcspHashAlg::Sha256).unwrap();
        assert_ne!(
            with_correct.body, with_swapped.body,
            "swapping (cert, issuer) must produce different CertIDs"
        );
    }
}
