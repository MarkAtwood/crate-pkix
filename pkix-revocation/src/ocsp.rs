//! Offline OCSP-based revocation checker.
//!
//! Enabled by the `ocsp` feature.

use crate::{Error, RevocationChecker};
use der::{Decode as _, Encode as _, ErrorKind, Length};
use pkix_path::SignatureVerifier;
use spki::der::referenced::OwnedToRef as _;
use x509_cert::Certificate;
use x509_ocsp::{BasicOcspResponse, CertStatus, OcspResponse, OcspResponseStatus};

// OID 1.3.6.1.5.5.7.48.1.1 — id-pkix-ocsp-basic
const OID_PKIX_OCSP_BASIC: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1");

/// A placeholder `der::Error` used when a structural invariant is violated.
///
/// This is returned in two places:
/// - `responseBytes` absent in a `Successful` response (RFC 6960 §4.2.1 requires it)
/// - `responseType` is not `id-pkix-ocsp-basic` (unrecognized response format)
///
/// Both indicate a malformed OCSP response that does not conform to RFC 6960.
/// `Length::ZERO` is used as a placeholder since `der::Error` requires a length.
fn der_failed() -> der::Error {
    der::Error::new(ErrorKind::Failed, Length::ZERO)
}

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
///
/// [`check_revocation`]: crate::RevocationChecker::check_revocation
///   Delegated OCSP responders (responses signed by a separate responder
///   certificate, not by the issuer directly) will fail with
///   [`Error::OcspSignatureInvalid`] because the signature is verified against
///   the issuer's key. This is a v0.1 limitation tracked for v0.2.
/// - **Security**: `SingleResponse` matching is by serial number only; the
///   `CertID.issuerNameHash` and `CertID.issuerKeyHash` fields are not verified.
///   Serial numbers are only unique within a single CA's issuance, not globally.
///   An OCSP response for a certificate with the same serial number from a
///   different CA could satisfy this check. For deployments where multiple CAs
///   share an OCSP responder or serial number collisions are possible, verify
///   the issuer hash fields before using this checker.
/// - The `ResponderId` field is not verified against the issuer identity.
/// - If no `SingleResponse` matches the certificate's serial number,
///   `OcspStatusUnknown` is returned (hard-fail).
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
        let resp_bytes = resp
            .response_bytes
            .ok_or_else(|| Error::OcspParseError(der_failed()))?;

        // (4) Verify responseType is id-pkix-ocsp-basic.
        if resp_bytes.response_type != OID_PKIX_OCSP_BASIC {
            return Err(Error::OcspParseError(der_failed()));
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

        // (7) Find the SingleResponse for this certificate (match by serial number).
        let cert_serial = &cert.tbs_certificate.serial_number;
        let single = basic
            .tbs_response_data
            .responses
            .iter()
            .find(|r| &r.cert_id.serial_number == cert_serial)
            .ok_or(Error::OcspStatusUnknown)?;

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
}
