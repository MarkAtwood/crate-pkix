//! Offline OCSP-based revocation checker.
//!
//! Enabled by the `ocsp` feature.

use crate::{Error, RevocationChecker};
use der::{Decode as _, Encode as _};
use pkix_path::{names_match, SignatureVerifier, TrustAnchor};
use spki::der::referenced::OwnedToRef as _;
use x509_cert::Certificate;
use x509_ocsp::{BasicOcspResponse, CertStatus, OcspResponse, OcspResponseStatus, ResponderId};

// OID 1.3.6.1.5.5.7.48.1.1 — id-pkix-ocsp-basic
const OID_PKIX_OCSP_BASIC: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1");

// Hash algorithm OIDs used in CertID (RFC 6960 §4.1.1)
const OID_SHA1: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const OID_SHA256: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_SHA384: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const OID_SHA512: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

/// Offline OCSP-based revocation checker.
///
/// Parses a pre-fetched DER-encoded OCSP response, verifies its signature
/// against the issuer's SPKI, checks the validity window of the matching
/// [`SingleResponse`][x509_ocsp::SingleResponse], and reports the certificate's
/// revocation status.
///
/// # Feature
///
/// Only available when the `ocsp` feature is enabled.
///
/// # Limitations (v0.1)
///
/// - The OCSP response is re-parsed from DER on every [`check_revocation`] call.
///   For chains with multiple certificates validated against the same response,
///   this is O(N) redundant parsing. Tracked for v0.3 (cache the parsed
///   `BasicOcspResponse` in `new`).
/// - Only issuer-signed (direct) OCSP responses are supported.
///   Delegated OCSP responders (responses signed by a separate responder
///   certificate, not by the issuer directly) will fail with
///   [`Error::OcspSignatureInvalid`] because the signature is verified against
///   the issuer's key. This is a v0.1 limitation tracked for v0.3.
///
/// [`check_revocation`]: crate::RevocationChecker::check_revocation
 /// - `SingleResponse` matching uses both serial number and the `CertID`
 ///   `issuerNameHash`/`issuerKeyHash` fields (RFC 6960 §4.1.1). An OCSP
 ///   response from a different CA with the same serial number will be rejected
 ///   by the hash checks.
 /// - The `ResponderId` field is verified against the issuer identity per
 ///   RFC 6960 §2.2: `byName` is compared against the issuer's subject DN using
 ///   [`pkix_path::names_match`]; `byKey` is compared against SHA-1 of the
 ///   issuer's SPKI `subjectPublicKey` bit string.
 /// - If no `SingleResponse` matches the certificate's serial number,
 ///   `OcspStatusUnknown` is returned (hard-fail).
 /// - [`RevocationChecker::check_revocation_against_anchor`] is overridden.
 ///   For the certificate issued directly by a trust anchor, the checker
 ///   uses the anchor's subject DN and SPKI to verify the OCSP response.
  ///   The response DER must be supplied at construction time; this method
  ///   always attempts to verify it against the anchor.
 ///
 /// [`RevocationChecker::check_revocation_against_anchor`]: crate::RevocationChecker::check_revocation_against_anchor
#[derive(Clone, Debug)]
pub struct OcspChecker<V> {
    response_der: Vec<u8>,
    now_unix: u64,
    verifier: V,
}

impl<V: SignatureVerifier> OcspChecker<V> {
    /// Create a new `OcspChecker`.
    ///
    /// - `response_der` — DER-encoded `OCSPResponse` (any `Into<Vec<u8>>`, e.g. `Vec<u8>` or `&[u8]`)
    /// - `now_unix`     — current time as seconds since the Unix epoch
    /// - `verifier`     — signature verifier used to authenticate the OCSP response
    #[must_use]
    pub fn new(response_der: impl Into<Vec<u8>>, now_unix: u64, verifier: V) -> Self {
        Self {
            response_der: response_der.into(),
            now_unix,
            verifier,
        }
    }
}

impl<V: SignatureVerifier> RevocationChecker for OcspChecker<V> {
    fn check_revocation(&self, cert: &Certificate, issuer: &Certificate) -> crate::Result<()> {
        // (0) Verify that `issuer` is actually the issuer of `cert`.
        //
        // Defense-in-depth: a caller could pass a mismatched `issuer` certificate
        // whose key happens to verify the OCSP response signature, but which did
        // not actually issue `cert`. Rejecting early prevents the downstream
        // signature and CertID hash checks from operating on the wrong identity.
        if !names_match(
            &issuer.tbs_certificate.subject,
            &cert.tbs_certificate.issuer,
        ) {
            return Err(Error::OcspCertIdMismatch);
        }

        // (1)-(6) Parse and verify the BasicOCSPResponse.
        let basic = parse_and_verify_basic_response(
            &self.response_der,
            &self.verifier,
            issuer
                .tbs_certificate
                .subject_public_key_info
                .owned_to_ref(),
        )?;

        // (6b) RFC 6960 §2.2: verify ResponderId against the issuer identity.
        //
        // The ResponderId in the response must match the issuer whose SPKI was
        // used to verify the signature above.  A rogue responder for a different
        // CA could still produce a validly structured response — this check
        // ensures the response explicitly asserts the correct issuer identity.
        verify_responder_id(
            &basic.tbs_response_data.responder_id,
            issuer,
        )?;

        // (7) Find the SingleResponse for this certificate (match by serial number).
        let cert_serial = &cert.tbs_certificate.serial_number;
        let single = basic
            .tbs_response_data
            .responses
            .iter()
            .find(|r| &r.cert_id.serial_number == cert_serial)
            .ok_or(Error::OcspStatusUnknown)?;

        // (7a) Verify CertID issuer hashes (RFC 6960 §4.1.1).
        //
        // issuerNameHash = hash(DER(issuer.subject))
        // issuerKeyHash  = hash(issuer.spki.subject_public_key.raw_bytes())
        //
        // Without this check a response produced for a cert with the same serial
        // number issued by a *different* CA could pass serial-only matching.
        let hash_oid = &single.cert_id.hash_algorithm.oid;
        let name_der = issuer
            .tbs_certificate
            .subject
            .to_der()
            .map_err(Error::OcspParseError)?;
        let key_raw = issuer
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        let expected_name_hash = hash_certid_input(hash_oid, &name_der)?;
        let expected_key_hash = hash_certid_input(hash_oid, key_raw)?;
        if single.cert_id.issuer_name_hash.as_bytes() != expected_name_hash.as_slice()
            || single.cert_id.issuer_key_hash.as_bytes() != expected_key_hash.as_slice()
        {
            // The response was produced for a certificate from a different CA;
            // this is not a responder-reported "unknown" — it is an identity mismatch.
            return Err(Error::OcspCertIdMismatch);
        }

        // (8) Check validity windows.
        //
        // producedAt must not be in the future.  A future-dated `producedAt` is
        // structurally suspicious — a legitimate responder cannot claim to have
        // produced a response after "now".  This is not a case of the responder
        // saying "unknown"; it is a malformed or tampered response, so we return
        // `OcspMalformed` rather than `OcspStatusUnknown`.
        let produced_at = basic
            .tbs_response_data
            .produced_at
            .as_ref()
            .to_unix_duration()
            .as_secs();
        if self.now_unix < produced_at {
            return Err(Error::OcspMalformed);
        }
        // thisUpdate ≤ now: the SingleResponse is not yet valid (stale clock or
        // pre-dated response).  This is the same freshness failure as a past-due
        // nextUpdate, so return `OcspExpired` for consistent caller semantics.
        let this_update = single.this_update.as_ref().to_unix_duration().as_secs();
        if self.now_unix < this_update {
            return Err(Error::OcspExpired);
        }
        // now ≤ nextUpdate: absent nextUpdate is treated as stale (no freshness
        // guarantee means we cannot rely on the response).
        let next_update = single.next_update.as_ref().ok_or(Error::OcspExpired)?;
        if self.now_unix > next_update.as_ref().to_unix_duration().as_secs() {
            return Err(Error::OcspExpired);
        }

        // (9) Return based on certStatus.
        match single.cert_status {
            CertStatus::Good(_) => Ok(()),
            CertStatus::Revoked(ref info) => Err(Error::Revoked {
                serial: cert_serial.clone(),
                reason_code: info.revocation_reason,
            }),
            CertStatus::Unknown(_) => Err(Error::OcspStatusUnknown),
        }
    }

    /// Check revocation for `cert` issued directly by a trust anchor.
    ///
    /// Parses the pre-loaded OCSP response and verifies it against the anchor's
    /// SPKI and subject DN.  The anchor fields (`subject` and
    /// `subject_public_key_info`) are used in place of the missing issuer
    /// `Certificate`.
    ///
    /// # Limitations (v0.1)
    ///
    /// OCSP responder discovery via the Authority Information Access extension
    /// (RFC 6960 §3.1) is not implemented.  The response DER must be supplied
    /// at construction time and is always verified.  If the serial number is
    /// not found in the response, [`Error::OcspStatusUnknown`] is returned.
    fn check_revocation_against_anchor(
        &self,
        cert: &Certificate,
        anchor: &TrustAnchor,
    ) -> crate::Result<()> {
        // (0) Verify that the anchor is actually the issuer of `cert`.
        //
        // Defense-in-depth: guards against a caller passing an anchor whose SPKI
        // happens to verify the OCSP response but which did not issue `cert`.
        if !names_match(&anchor.subject, &cert.tbs_certificate.issuer) {
            return Err(Error::OcspCertIdMismatch);
        }

        // (1)-(6) Parse and verify the BasicOCSPResponse.
        let basic = parse_and_verify_basic_response(
            &self.response_der,
            &self.verifier,
            anchor.subject_public_key_info.owned_to_ref(),
        )?;

        // (6b) Verify ResponderId against the anchor's identity.
        verify_responder_id_anchor(&basic.tbs_response_data.responder_id, anchor)?;

        // (7) Find the SingleResponse for this certificate.
        let cert_serial = &cert.tbs_certificate.serial_number;
        let single = basic
            .tbs_response_data
            .responses
            .iter()
            .find(|r| &r.cert_id.serial_number == cert_serial)
            .ok_or(Error::OcspStatusUnknown)?;

        // (7a) Verify CertID issuer hashes using the anchor's name/SPKI.
        let hash_oid = &single.cert_id.hash_algorithm.oid;
        let anchor_name_der = anchor
            .subject
            .to_der()
            .map_err(Error::OcspParseError)?;
        let anchor_key_raw = anchor
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        let expected_name_hash = hash_certid_input(hash_oid, &anchor_name_der)?;
        let expected_key_hash = hash_certid_input(hash_oid, anchor_key_raw)?;
        if single.cert_id.issuer_name_hash.as_bytes() != expected_name_hash.as_slice()
            || single.cert_id.issuer_key_hash.as_bytes() != expected_key_hash.as_slice()
        {
            // Response covers a certificate from a different CA — identity mismatch,
            // not a responder-reported "unknown".
            return Err(Error::OcspCertIdMismatch);
        }

        // (8) Check validity windows.
        //
        // producedAt must not be in the future.  A future-dated `producedAt` is
        // structurally suspicious — a legitimate responder cannot claim to have
        // produced a response after "now".  Return `OcspMalformed` rather than
        // `OcspStatusUnknown` because this is not a responder-reported "unknown"
        // status but a structurally invalid response.
        let produced_at = basic
            .tbs_response_data
            .produced_at
            .as_ref()
            .to_unix_duration()
            .as_secs();
        if self.now_unix < produced_at {
            return Err(Error::OcspMalformed);
        }
        // thisUpdate ≤ now: same freshness failure as nextUpdate expired.
        let this_update = single.this_update.as_ref().to_unix_duration().as_secs();
        if self.now_unix < this_update {
            return Err(Error::OcspExpired);
        }
        let next_update = single.next_update.as_ref().ok_or(Error::OcspExpired)?;
        if self.now_unix > next_update.as_ref().to_unix_duration().as_secs() {
            return Err(Error::OcspExpired);
        }

        // (9) Return based on certStatus.
        match single.cert_status {
            CertStatus::Good(_) => Ok(()),
            CertStatus::Revoked(ref info) => Err(Error::Revoked {
                serial: cert_serial.clone(),
                reason_code: info.revocation_reason,
            }),
            CertStatus::Unknown(_) => Err(Error::OcspStatusUnknown),
        }
    }
}

/// Parse a DER-encoded `OCSPResponse`, verify its structure, and return the
/// verified [`BasicOcspResponse`].
///
/// Performs steps 1-6 common to both `check_revocation` and
/// `check_revocation_against_anchor`:
/// 1. Parse the outer `OcspResponse` from DER.
/// 2. Require `response_status == Successful` (others return `OcspMalformed`).
/// 3. Extract `response_bytes` (error if absent).
/// 4. Verify `response_type == id-pkix-ocsp-basic`.
/// 5. Parse the `BasicOcspResponse`.
/// 6. Verify the signature over `tbs_response_data` using `issuer_spki`.
///
/// The caller is responsible for the `ResponderId` check (step 6b) and all
/// subsequent steps, which differ between the two callers.
fn parse_and_verify_basic_response<V: SignatureVerifier>(
    response_der: &[u8],
    verifier: &V,
    issuer_spki: spki::SubjectPublicKeyInfoRef<'_>,
) -> crate::Result<BasicOcspResponse> {
    // (1) Parse the outer OCSPResponse.
    let resp = OcspResponse::from_der(response_der).map_err(Error::OcspParseError)?;

    // (2) Require responseStatus == successful; any other (TryLater,
    // InternalError, MalformedRequest, SigRequired, Unauthorized) → OcspMalformed.
    // These are server-side error codes, not a responder-reported "unknown" status.
    if resp.response_status != OcspResponseStatus::Successful {
        return Err(Error::OcspMalformed);
    }

    // (3) Extract responseBytes (must be present for a Successful response).
    let resp_bytes = resp.response_bytes.ok_or(Error::OcspMalformed)?;

    // (4) Verify responseType is id-pkix-ocsp-basic.
    if resp_bytes.response_type != OID_PKIX_OCSP_BASIC {
        return Err(Error::OcspMalformed);
    }

    // (5) Parse the BasicOCSPResponse.
    let basic = BasicOcspResponse::from_der(resp_bytes.response.as_bytes())
        .map_err(Error::OcspParseError)?;

    // (6) Verify the OCSP signature against the supplied SPKI.
    //
    // v0.1 limitation: assumes the response is signed directly by the issuer.
    // The signature covers the DER encoding of ResponseData (tbs_response_data).
    let tbs_bytes = basic
        .tbs_response_data
        .to_der()
        .map_err(Error::OcspParseError)?;
    verifier
        .verify_signature(
            basic.signature_algorithm.owned_to_ref(),
            issuer_spki,
            &tbs_bytes,
            basic.signature.raw_bytes(),
        )
        .map_err(|_| Error::OcspSignatureInvalid)?;

    Ok(basic)
}

/// Stack-allocated hash output for CertID hash comparisons.
///
/// Holds the digest bytes for one of the four hash algorithms recognised in
/// CertID (RFC 6960 §4.1.1), without heap allocation.
enum HashOutput {
    Sha1([u8; 20]),
    Sha256([u8; 32]),
    Sha384([u8; 48]),
    Sha512([u8; 64]),
}

impl HashOutput {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Sha1(b) => b,
            Self::Sha256(b) => b,
            Self::Sha384(b) => b,
            Self::Sha512(b) => b,
        }
    }
}

/// Hash `data` using the algorithm identified by `oid`.
///
/// Supports SHA-1 (OID 1.3.14.3.2.26), SHA-256 (OID 2.16.840.1.101.3.4.2.1),
/// SHA-384 (OID 2.16.840.1.101.3.4.2.2), and SHA-512 (OID 2.16.840.1.101.3.4.2.3).
/// Returns [`Error::OcspMalformed`] for any other OID.
fn hash_certid_input(
    oid: &der::asn1::ObjectIdentifier,
    data: &[u8],
) -> crate::Result<HashOutput> {
    match *oid {
        OID_SHA1 => {
            use sha1::Digest as _;
            Ok(HashOutput::Sha1(sha1::Sha1::digest(data).into()))
        }
        OID_SHA256 => {
            use sha2::Digest as _;
            Ok(HashOutput::Sha256(sha2::Sha256::digest(data).into()))
        }
        OID_SHA384 => {
            use sha2::Digest as _;
            Ok(HashOutput::Sha384(sha2::Sha384::digest(data).into()))
        }
        OID_SHA512 => {
            use sha2::Digest as _;
            Ok(HashOutput::Sha512(sha2::Sha512::digest(data).into()))
        }
        _ => Err(Error::OcspMalformed),
    }
}

/// Verify that a `ResponderId` matches the identity of an issuer `Certificate`.
///
/// RFC 6960 §2.2 defines two cases:
/// - `byName`: the Name must equal the issuer's subject DN (RFC 4518 comparison
///   via [`pkix_path::names_match`]).
/// - `byKey`: the `KeyHash` must equal SHA-1 of the issuer's SPKI
///   `subjectPublicKey` bit string (raw bytes, tag/length/unused-bits stripped).
///
/// Returns [`Error::OcspSignatureInvalid`] on mismatch, as a mismatch means
/// the response was not produced by the expected issuer.
fn verify_responder_id(id: &ResponderId, issuer: &Certificate) -> crate::Result<()> {
    verify_responder_id_impl(
        id,
        &issuer.tbs_certificate.subject,
        issuer
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes(),
    )
}

/// Same as [`verify_responder_id`] but uses a [`TrustAnchor`]'s identity instead
/// of a full `Certificate`.
///
/// Used by [`OcspChecker::check_revocation_against_anchor`] where only the
/// anchor's subject DN and SPKI are available.
fn verify_responder_id_anchor(id: &ResponderId, anchor: &TrustAnchor) -> crate::Result<()> {
    verify_responder_id_impl(
        id,
        &anchor.subject,
        anchor
            .subject_public_key_info
            .subject_public_key
            .raw_bytes(),
    )
}

/// Common implementation for [`verify_responder_id`] and [`verify_responder_id_anchor`].
///
/// Checks that the OCSP `ResponderId` matches the expected identity
/// (either a certificate subject or a trust anchor subject).
fn verify_responder_id_impl(
    id: &ResponderId,
    subject: &x509_cert::name::Name,
    spki_raw: &[u8],
) -> crate::Result<()> {
    match id {
        ResponderId::ByName(name) => {
            if !names_match(name, subject) {
                return Err(Error::OcspSignatureInvalid);
            }
        }
        ResponderId::ByKey(key_hash) => {
            use sha1::Digest as _;
            let expected: [u8; 20] = sha1::Sha1::digest(spki_raw).into();
            if key_hash.as_bytes() != expected.as_ref() {
                return Err(Error::OcspSignatureInvalid);
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests for hash_certid_input
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-384 of b"test".
    ///
    /// Oracle: python3 -c "import hashlib, binascii; print(binascii.hexlify(hashlib.sha384(b'test').digest()).decode())"
    /// → 768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9
    #[test]
    fn hash_certid_sha384() {
        let expected: &[u8] = &[
            0x76, 0x84, 0x12, 0x32, 0x0f, 0x7b, 0x0a, 0xa5, 0x81, 0x2f, 0xce, 0x42,
            0x8d, 0xc4, 0x70, 0x6b, 0x3c, 0xae, 0x50, 0xe0, 0x2a, 0x64, 0xca, 0xa1,
            0x6a, 0x78, 0x22, 0x49, 0xbf, 0xe8, 0xef, 0xc4, 0xb7, 0xef, 0x1c, 0xcb,
            0x12, 0x62, 0x55, 0xd1, 0x96, 0x04, 0x7d, 0xfe, 0xdf, 0x17, 0xa0, 0xa9,
        ];
        let result = hash_certid_input(&OID_SHA384, b"test").expect("SHA-384 must succeed");
        assert_eq!(result.as_slice(), expected, "SHA-384(\"test\") must match Python oracle");
    }

    /// SHA-512 of b"test".
    ///
    /// Oracle: python3 -c "import hashlib, binascii; print(binascii.hexlify(hashlib.sha512(b'test').digest()).decode())"
    /// → ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff
    #[test]
    fn hash_certid_sha512() {
        let expected: &[u8] = &[
            0xee, 0x26, 0xb0, 0xdd, 0x4a, 0xf7, 0xe7, 0x49, 0xaa, 0x1a, 0x8e, 0xe3,
            0xc1, 0x0a, 0xe9, 0x92, 0x3f, 0x61, 0x89, 0x80, 0x77, 0x2e, 0x47, 0x3f,
            0x88, 0x19, 0xa5, 0xd4, 0x94, 0x0e, 0x0d, 0xb2, 0x7a, 0xc1, 0x85, 0xf8,
            0xa0, 0xe1, 0xd5, 0xf8, 0x4f, 0x88, 0xbc, 0x88, 0x7f, 0xd6, 0x7b, 0x14,
            0x37, 0x32, 0xc3, 0x04, 0xcc, 0x5f, 0xa9, 0xad, 0x8e, 0x6f, 0x57, 0xf5,
            0x00, 0x28, 0xa8, 0xff,
        ];
        let result = hash_certid_input(&OID_SHA512, b"test").expect("SHA-512 must succeed");
        assert_eq!(result.as_slice(), expected, "SHA-512(\"test\") must match Python oracle");
    }

    /// Unknown OID must return OcspMalformed.
    #[test]
    fn hash_certid_unknown_oid_returns_malformed() {
        let unknown = der::asn1::ObjectIdentifier::new_unwrap("1.2.3.4.5");
        let result = hash_certid_input(&unknown, b"test");
        assert!(
            matches!(result, Err(Error::OcspMalformed)),
            "unknown hash OID must return OcspMalformed"
        );
    }
}
