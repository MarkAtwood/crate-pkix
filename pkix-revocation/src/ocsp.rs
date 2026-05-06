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
///   this is O(N) redundant parsing. Tracked for v0.2 (cache the parsed
///   `BasicOcspResponse` in `new`).
/// - Only issuer-signed (direct) OCSP responses are supported.
///   Delegated OCSP responders (responses signed by a separate responder
///   certificate, not by the issuer directly) will fail with
///   [`Error::OcspSignatureInvalid`] because the signature is verified against
///   the issuer's key. This is a v0.1 limitation tracked for v0.2.
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
 ///   If the certificate has no OCSP URL (not supported in v0.1), the method
 ///   returns `Ok(())` (not-covered; same semantics as no OCSP source available).
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
        // (1) Parse the outer OCSPResponse.
        let resp = OcspResponse::from_der(&self.response_der).map_err(Error::OcspParseError)?;

        // (2) Require responseStatus == successful; any other → OcspStatusUnknown.
        if resp.response_status != OcspResponseStatus::Successful {
            return Err(Error::OcspStatusUnknown);
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

        // (6) Verify the OCSP signature against the issuer's SPKI.
        //
        // v0.1 limitation: assumes the response is signed directly by the issuer.
        // The signature covers the DER encoding of ResponseData (tbs_response_data).
        let tbs_bytes = basic
            .tbs_response_data
            .to_der()
            .map_err(Error::OcspParseError)?;
        self.verifier
            .verify_signature(
                basic.signature_algorithm.owned_to_ref(),
                issuer
                    .tbs_certificate
                    .subject_public_key_info
                    .owned_to_ref(),
                &tbs_bytes,
                basic.signature.raw_bytes(),
            )
            .map_err(|_| Error::OcspSignatureInvalid)?;

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
            return Err(Error::OcspStatusUnknown);
        }

        // (8) Check validity windows.
        //
        // producedAt must not be in the future: a future-dated response indicates
        // clock skew or a response generated after "now"; reject as unknown.
        let produced_at = basic
            .tbs_response_data
            .produced_at
            .as_ref()
            .to_unix_duration()
            .as_secs();
        if self.now_unix < produced_at {
            return Err(Error::OcspStatusUnknown);
        }
        // thisUpdate ≤ now: the SingleResponse is not yet valid.
        let this_update = single.this_update.as_ref().to_unix_duration().as_secs();
        if self.now_unix < this_update {
            return Err(Error::OcspStatusUnknown);
        }
        // now ≤ nextUpdate: absent nextUpdate is treated as unknown (no expiry info
        // means we cannot trust the freshness of the status).
        match &single.next_update {
            Some(next_update) => {
                if self.now_unix > next_update.as_ref().to_unix_duration().as_secs() {
                    return Err(Error::OcspStatusUnknown);
                }
            }
            None => return Err(Error::OcspStatusUnknown),
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
    /// at construction time.  If the certificate has no OCSP URL, this method
    /// returns `Ok(())` (not-covered), matching the behaviour of
    /// [`check_revocation`] when no OCSP source is available.
    ///
    /// [`check_revocation`]: crate::RevocationChecker::check_revocation
    fn check_revocation_against_anchor(
        &self,
        cert: &Certificate,
        anchor: &TrustAnchor,
    ) -> crate::Result<()> {
        // (1) Parse the outer OCSPResponse.
        let resp =
            OcspResponse::from_der(&self.response_der).map_err(Error::OcspParseError)?;

        // (2) Require responseStatus == successful.
        if resp.response_status != OcspResponseStatus::Successful {
            return Err(Error::OcspStatusUnknown);
        }

        // (3) Extract responseBytes.
        let resp_bytes = resp.response_bytes.ok_or(Error::OcspMalformed)?;

        // (4) Verify responseType is id-pkix-ocsp-basic.
        if resp_bytes.response_type != OID_PKIX_OCSP_BASIC {
            return Err(Error::OcspMalformed);
        }

        // (5) Parse the BasicOCSPResponse.
        let basic = BasicOcspResponse::from_der(resp_bytes.response.as_bytes())
            .map_err(Error::OcspParseError)?;

        // (6) Verify the OCSP signature against the anchor's SPKI.
        let tbs_bytes = basic
            .tbs_response_data
            .to_der()
            .map_err(Error::OcspParseError)?;
        self.verifier
            .verify_signature(
                basic.signature_algorithm.owned_to_ref(),
                anchor.subject_public_key_info.owned_to_ref(),
                &tbs_bytes,
                basic.signature.raw_bytes(),
            )
            .map_err(|_| Error::OcspSignatureInvalid)?;

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
            return Err(Error::OcspStatusUnknown);
        }

        // (8) Check validity windows.
        let produced_at = basic
            .tbs_response_data
            .produced_at
            .as_ref()
            .to_unix_duration()
            .as_secs();
        if self.now_unix < produced_at {
            return Err(Error::OcspStatusUnknown);
        }
        let this_update = single.this_update.as_ref().to_unix_duration().as_secs();
        if self.now_unix < this_update {
            return Err(Error::OcspStatusUnknown);
        }
        match &single.next_update {
            Some(next_update) => {
                if self.now_unix > next_update.as_ref().to_unix_duration().as_secs() {
                    return Err(Error::OcspStatusUnknown);
                }
            }
            None => return Err(Error::OcspStatusUnknown),
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

/// Hash `data` using the algorithm identified by `oid`.
///
/// Supports SHA-1 (OID 1.3.14.3.2.26) and SHA-256 (OID 2.16.840.1.101.3.4.2.1).
/// Returns [`Error::OcspMalformed`] for any other OID.
fn hash_certid_input(oid: &der::asn1::ObjectIdentifier, data: &[u8]) -> crate::Result<Vec<u8>> {
    match *oid {
        OID_SHA1 => {
            use sha1::Digest as _;
            Ok(sha1::Sha1::digest(data).to_vec())
        }
        OID_SHA256 => {
            use sha2::Digest as _;
            Ok(sha2::Sha256::digest(data).to_vec())
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
    match id {
        ResponderId::ByName(name) => {
            if !names_match(name, &issuer.tbs_certificate.subject) {
                return Err(Error::OcspSignatureInvalid);
            }
        }
        ResponderId::ByKey(key_hash) => {
            use sha1::Digest as _;
            let raw = issuer
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes();
            let expected: [u8; 20] = sha1::Sha1::digest(raw).into();
            if key_hash.as_bytes() != expected.as_ref() {
                return Err(Error::OcspSignatureInvalid);
            }
        }
    }
    Ok(())
}

/// Same as [`verify_responder_id`] but uses a [`TrustAnchor`]'s identity instead
/// of a full `Certificate`.
///
/// Used by [`OcspChecker::check_revocation_against_anchor`] where only the
/// anchor's subject DN and SPKI are available.
fn verify_responder_id_anchor(id: &ResponderId, anchor: &TrustAnchor) -> crate::Result<()> {
    match id {
        ResponderId::ByName(name) => {
            if !names_match(name, &anchor.subject) {
                return Err(Error::OcspSignatureInvalid);
            }
        }
        ResponderId::ByKey(key_hash) => {
            use sha1::Digest as _;
            let raw = anchor
                .subject_public_key_info
                .subject_public_key
                .raw_bytes();
            let expected: [u8; 20] = sha1::Sha1::digest(raw).into();
            if key_hash.as_bytes() != expected.as_ref() {
                return Err(Error::OcspSignatureInvalid);
            }
        }
    }
    Ok(())
}
