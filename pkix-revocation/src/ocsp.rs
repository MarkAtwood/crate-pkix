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

// OID 2.5.29.37 — id-ce-extKeyUsage (RFC 5280 §4.2.1.12)
const OID_EXTENDED_KEY_USAGE: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.37");

// OID 1.3.6.1.5.5.7.3.9 — id-kp-OCSPSigning (RFC 6960 §4.2.2.2)
const OID_KP_OCSP_SIGNING: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.9");

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
/// # Supported responder shapes
///
/// - **Direct** (RFC 6960 §4.2.2.2): the response is signed by the cert's
///   issuer CA. `ResponderId` matches the issuer's name or SHA-1(SPKI);
///   the response signature verifies against the issuer's SPKI.
/// - **CA Designated Responder** (RFC 6960 §4.2.2.2, "delegated"): the
///   response is signed by a separate responder certificate embedded in
///   the response's `certs` field. The responder cert MUST be issued
///   directly by the same CA, MUST carry `id-kp-OCSPSigning` Extended Key
///   Usage, MUST have a validity period containing the response's
///   `producedAt`, and the issuer's signature on it MUST verify against
///   the issuer's SPKI. Failures map to distinct error variants
///   ([`Error::OcspResponderEkuMissing`],
///   [`Error::OcspResponderEkuMalformed`],
///   [`Error::OcspResponderCertNotIssuedByCa`],
///   [`Error::OcspResponderCertExpired`],
///   [`Error::OcspResponderCertSigInvalid`]).
/// - The `id-pkix-ocsp-nocheck` extension on a delegate cert (RFC 6960
///   §4.2.2.2.1) is **not** parsed by this crate: the checker is
///   single-shot and never recurses into the delegate's revocation
///   regardless of the extension. Callers wrapping this checker in a
///   chain validator MUST honor `ocsp-nocheck` themselves to prevent
///   infinite recursion.
///
/// # Limitations
///
/// - **Trusted Responder** (third RFC 6960 case — a responder whose key
///   the requester trusts out-of-band) is not modeled. Callers needing
///   it can supply the trusted responder cert as the `issuer` argument.
/// - No OCSP request generation. The response DER must be supplied at
///   construction time; the checker is offline. The OCSP `nonce` extension
///   is therefore not generated or checked.
/// - No AIA-based responder discovery (RFC 6960 §3.1). The
///   `AuthorityInfoAccess` extension's `id-ad-ocsp` URL is not consulted —
///   the caller is responsible for fetching the response out-of-band. See
///   the planned `pkix-revocation-http` crate for online responder support.
///
/// # Behavior
///
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
/// [`check_revocation`]: crate::RevocationChecker::check_revocation
/// [`RevocationChecker::check_revocation_against_anchor`]: crate::RevocationChecker::check_revocation_against_anchor
#[derive(Clone, Debug)]
pub struct OcspChecker<V> {
    /// Pre-parsed `BasicOCSPResponse`, decoded once at construction time and
    /// reused on every check. Signature verification still happens per-call
    /// because the issuer SPKI varies between
    /// [`RevocationChecker::check_revocation`] (issuer cert) and
    /// [`RevocationChecker::check_revocation_against_anchor`] (anchor SPKI).
    basic: BasicOcspResponse,
    now_unix: u64,
    verifier: V,
}

impl<V: SignatureVerifier> OcspChecker<V> {
    /// Create a new `OcspChecker`.
    ///
    /// - `response_der` — DER-encoded `OCSPResponse` (any `AsRef<[u8]>`, e.g. `Vec<u8>` or `&[u8]`)
    /// - `now_unix`     — current time as seconds since the Unix epoch
    /// - `verifier`     — signature verifier used to authenticate the OCSP response
    ///
    /// The response is parsed once at construction time; subsequent
    /// [`RevocationChecker::check_revocation`] calls reuse the cached
    /// [`BasicOcspResponse`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::OcspParseError`] if `response_der` cannot be DER-decoded
    /// or [`Error::OcspMalformed`] if the response status is non-`Successful`,
    /// `responseBytes` is absent, or the inner `responseType` is not
    /// `id-pkix-ocsp-basic`.
    pub fn new(response_der: impl AsRef<[u8]>, now_unix: u64, verifier: V) -> crate::Result<Self> {
        let basic = parse_basic_response(response_der.as_ref())?;
        Ok(Self {
            basic,
            now_unix,
            verifier,
        })
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
            return Err(Error::OcspIssuerCertMismatch);
        }

        // (1)-(5) parsing was performed in `new()`; reuse the cached
        // `BasicOcspResponse`.
        let basic = &self.basic;

        // (6) RFC 6960 §4.2.2.2: resolve which key signs this response —
        // either the issuer (direct) or a CA Designated Responder cert
        // embedded in `basic.certs` (delegated). The resolver also
        // performs the ResponderId match (step 6b in the legacy flow)
        // because for delegated responses the ResponderId must match the
        // delegate, not the issuer.
        let issuer_subject = &issuer.tbs_certificate.subject;
        let issuer_spki_owned = &issuer.tbs_certificate.subject_public_key_info;
        let issuer_spki_raw = issuer_spki_owned.subject_public_key.raw_bytes();
        let signing_spki = resolve_signing_key_for_response(
            basic,
            issuer_subject,
            issuer_spki_owned.owned_to_ref(),
            issuer_spki_raw,
            &self.verifier,
            produced_at_unix_secs(basic),
        )?;

        // (6 cont.) Verify the response signature using the resolved key.
        let tbs_bytes = basic
            .tbs_response_data
            .to_der()
            .map_err(|e| Error::OcspParseError(crate::DerError(e)))?;
        self.verifier
            .verify_signature(
                basic.signature_algorithm.owned_to_ref(),
                signing_spki,
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
            .map_err(|e| Error::OcspParseError(crate::DerError(e)))?;
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
    /// # Limitations
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
            return Err(Error::OcspIssuerCertMismatch);
        }

        // (1)-(5) parsing was performed in `new()`; reuse the cached
        // `BasicOcspResponse`.
        let basic = &self.basic;

        // (6) Resolve signing key (direct vs delegated) and verify the
        // response signature. See `check_revocation` above for the full
        // commentary on the two paths.
        let anchor_subject = &anchor.subject;
        let anchor_spki_raw = anchor.subject_public_key_info.subject_public_key.raw_bytes();
        let signing_spki = resolve_signing_key_for_response(
            basic,
            anchor_subject,
            anchor.subject_public_key_info.owned_to_ref(),
            anchor_spki_raw,
            &self.verifier,
            produced_at_unix_secs(basic),
        )?;

        let tbs_bytes = basic
            .tbs_response_data
            .to_der()
            .map_err(|e| Error::OcspParseError(crate::DerError(e)))?;
        self.verifier
            .verify_signature(
                basic.signature_algorithm.owned_to_ref(),
                signing_spki,
                &tbs_bytes,
                basic.signature.raw_bytes(),
            )
            .map_err(|_| Error::OcspSignatureInvalid)?;

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
            .map_err(|e| Error::OcspParseError(crate::DerError(e)))?;
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

/// Parse an `OCSPResponse` DER blob and extract its inner `BasicOCSPResponse`.
///
/// Performs steps (1)–(5) of the OCSP processing pipeline (decode outer
/// `OCSPResponse`, require `Successful` status, extract `responseBytes`,
/// verify `responseType`, decode inner `BasicOCSPResponse`). Signature
/// verification is intentionally **not** performed here so the caller can
/// supply the appropriate issuer SPKI per call.
fn parse_basic_response(response_der: &[u8]) -> crate::Result<BasicOcspResponse> {
    // (1) Parse the outer OCSPResponse.
    let resp = OcspResponse::from_der(response_der)
        .map_err(|e| Error::OcspParseError(crate::DerError(e)))?;

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
    BasicOcspResponse::from_der(resp_bytes.response.as_bytes())
        .map_err(|e| Error::OcspParseError(crate::DerError(e)))
}

/// Stack-allocated hash output for `CertID` hash comparisons.
///
/// Holds the digest bytes for one of the four hash algorithms recognised in
/// `CertID` (RFC 6960 §4.1.1), without heap allocation.
enum HashOutput {
    Sha1([u8; 20]),
    Sha256([u8; 32]),
    Sha384([u8; 48]),
    Sha512([u8; 64]),
}

impl HashOutput {
    const fn as_slice(&self) -> &[u8] {
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
fn hash_certid_input(oid: &der::asn1::ObjectIdentifier, data: &[u8]) -> crate::Result<HashOutput> {
    // sha1 and sha2 both re-export `digest::Digest`; one import is sufficient.
    use sha1::Digest as _;
    match *oid {
        OID_SHA1 => Ok(HashOutput::Sha1(sha1::Sha1::digest(data).into())),
        OID_SHA256 => Ok(HashOutput::Sha256(sha2::Sha256::digest(data).into())),
        OID_SHA384 => Ok(HashOutput::Sha384(sha2::Sha384::digest(data).into())),
        OID_SHA512 => Ok(HashOutput::Sha512(sha2::Sha512::digest(data).into())),
        _ => Err(Error::OcspMalformed),
    }
}

/// Bool-returning core of `ResponderId` matching.
///
/// RFC 6960 §2.2 defines two `ResponderId` shapes:
/// - `byName`: the contained Name must equal `subject` (RFC 4518 comparison
///   via [`pkix_path::names_match`]).
/// - `byKey`: the contained `KeyHash` must equal SHA-1 of `spki_raw` (the
///   raw `subjectPublicKey` BIT STRING contents — no tag, length, or unused-
///   bits prefix).
///
/// Returns `true` iff the supplied identity matches the response's
/// `ResponderId`. Used both directly (delegated OCSP, where one ResponderId
/// is checked against many candidate identities and "no match" is not an
/// error) and via [`verify_responder_id_impl`] (direct OCSP, where mismatch
/// is fatal).
fn responder_id_matches(
    id: &ResponderId,
    subject: &x509_cert::name::Name,
    spki_raw: &[u8],
) -> bool {
    match id {
        ResponderId::ByName(name) => names_match(name, subject),
        ResponderId::ByKey(key_hash) => {
            use sha1::Digest as _;
            let expected: [u8; 20] = sha1::Sha1::digest(spki_raw).into();
            key_hash.as_bytes() == expected.as_ref()
        }
    }
}

/// Check whether `cert` carries the `id-kp-OCSPSigning` Extended Key Usage
/// (RFC 6960 §4.2.2.2 — required on a "CA Designated Responder" certificate).
///
/// - `Ok(true)`: EKU extension present and contains `id-kp-OCSPSigning`.
/// - `Ok(false)`: EKU absent, or present but does not contain that OID.
/// - `Err(`[`Error::OcspResponderEkuMalformed`]`)`: EKU present but cannot
///   be DER-decoded. Fail-closed: a malformed EKU on a candidate responder
///   cert rejects the response rather than silently treating the cert as
///   if the OCSPSigning purpose were absent.
///
/// Mirrors the fail-closed pattern in `pkix-path` (`try_find_cert_ext` ->
/// `MalformedCertificate` on parse error). Re-implemented locally because
/// `try_find_cert_ext` is private to `pkix-path`; promoting it would widen
/// the trait surface for one use site.
fn cert_has_ocsp_signing_eku(cert: &Certificate) -> crate::Result<bool> {
    use x509_cert::ext::pkix::ExtendedKeyUsage;

    let extns = match cert.tbs_certificate.extensions.as_deref() {
        Some(e) => e,
        None => return Ok(false),
    };
    let extn = match extns.iter().find(|e| e.extn_id == OID_EXTENDED_KEY_USAGE) {
        Some(e) => e,
        None => return Ok(false),
    };
    let eku = ExtendedKeyUsage::from_der(extn.extn_value.as_bytes())
        .map_err(|_| Error::OcspResponderEkuMalformed)?;
    Ok(eku.0.contains(&OID_KP_OCSP_SIGNING))
}

/// Validate a delegated OCSP responder cert against its supposed issuer.
///
/// RFC 6960 §4.2.2.2 — for a "CA Designated Responder" cert to be trusted:
///
/// 1. It must be issued directly by the CA whose certs the responder
///    asserts status for (not by some unrelated CA with the OCSPSigning
///    EKU).
/// 2. It must carry `id-kp-OCSPSigning` in its `ExtendedKeyUsage`.
/// 3. Its validity period must include the time the response was
///    generated (the response's `producedAt`).
/// 4. The CA's signature on its TBS must verify against the issuer's SPKI.
///
/// Each requirement maps to a distinct error variant for diagnostic
/// clarity; failures short-circuit (no later check runs after an earlier
/// one fails).
///
/// **Note on `id-pkix-ocsp-nocheck`**: per RFC 6960 §4.2.2.2.1 a delegate
/// cert MAY carry the `id-pkix-ocsp-nocheck` extension to signal that
/// callers MUST NOT recursively check the delegate's own revocation
/// status. This crate is a single-shot offline checker — it never
/// recurses into the delegate's revocation regardless of the extension —
/// so we neither parse nor enforce that extension. Documentation only.
fn validate_delegate_responder_cert<V: SignatureVerifier>(
    delegate: &Certificate,
    issuer_subject: &x509_cert::name::Name,
    issuer_spki: spki::SubjectPublicKeyInfoRef<'_>,
    verifier: &V,
    produced_at_unix: u64,
) -> crate::Result<()> {
    // (a) Issued by the same CA that issued the cert under check.
    if !names_match(&delegate.tbs_certificate.issuer, issuer_subject) {
        return Err(Error::OcspResponderCertNotIssuedByCa);
    }

    // (b) Carries id-kp-OCSPSigning EKU.
    match cert_has_ocsp_signing_eku(delegate)? {
        true => {}
        false => return Err(Error::OcspResponderEkuMissing),
    }

    // (c) Validity window includes the response's producedAt time.
    //     Using producedAt (not now_unix) means we reject responses
    //     produced after the responder cert expired even if the rest of
    //     the response window is still fresh — the signing key was no
    //     longer authoritative when the response claims to have been
    //     generated.
    let nb = delegate
        .tbs_certificate
        .validity
        .not_before
        .to_unix_duration()
        .as_secs();
    let na = delegate
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs();
    if produced_at_unix < nb || produced_at_unix > na {
        return Err(Error::OcspResponderCertExpired);
    }

    // (d) Issuer's signature on the delegate cert verifies. This is a
    //     SEPARATE signature from the OCSP response signature — distinct
    //     error variant for diagnostics. The TBS bytes are re-encoded
    //     here rather than spliced from the original DER because we only
    //     have the parsed `Certificate` value; for the typical responder-
    //     cert size this is microseconds.
    let tbs_bytes = delegate
        .tbs_certificate
        .to_der()
        .map_err(|e| Error::OcspParseError(crate::DerError(e)))?;
    verifier
        .verify_signature(
            delegate.signature_algorithm.owned_to_ref(),
            issuer_spki,
            &tbs_bytes,
            delegate.signature.raw_bytes(),
        )
        .map_err(|_| Error::OcspResponderCertSigInvalid)?;

    Ok(())
}

/// Resolve which key signs the OCSP response. Returns the SPKI to use for
/// the response signature check, plus a borrow lifetime tied to either
/// the issuer reference or the embedded responder cert (whichever path
/// applies).
///
/// RFC 6960 §4.2.2.2 — three signing-key cases:
/// 1. **Direct**: the response is signed by the CA itself. `ResponderId`
///    matches the issuer's name or SHA-1(SPKI). Use the issuer's SPKI.
/// 2. **CA Designated Responder (delegated)**: the response is signed by
///    a separate cert with the OCSPSigning EKU, embedded in the response's
///    `certs` field. Find the cert matching `ResponderId`, validate it as
///    a designated responder, and use its SPKI.
/// 3. **Trusted Responder** (out of scope for this crate): a responder
///    whose key the caller already trusts out-of-band. Not supported here;
///    callers needing this can supply the trusted responder cert as the
///    `issuer` argument when the cert under check has been issued by it.
///
/// The returned reference borrows from one of `basic` or `issuer`,
/// constrained to the same lifetime via `'a`. The caller drops the SPKI
/// ref before any further mutation of either source.
fn resolve_signing_key_for_response<'a, V: SignatureVerifier>(
    basic: &'a BasicOcspResponse,
    issuer_subject: &'a x509_cert::name::Name,
    issuer_spki: spki::SubjectPublicKeyInfoRef<'a>,
    issuer_spki_raw: &[u8],
    verifier: &V,
    produced_at_unix: u64,
) -> crate::Result<spki::SubjectPublicKeyInfoRef<'a>> {
    let rid = &basic.tbs_response_data.responder_id;

    // Direct path: ResponderId matches the issuer.
    if responder_id_matches(rid, issuer_subject, issuer_spki_raw) {
        return Ok(issuer_spki);
    }

    // Delegated path: scan `basic.certs` for a cert whose identity matches
    // ResponderId, then validate it as a CA Designated Responder.
    let certs: &[Certificate] = match basic.certs.as_deref() {
        Some(c) => c,
        None => &[],
    };
    for delegate in certs {
        let d_subject = &delegate.tbs_certificate.subject;
        let d_spki_raw = delegate
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        if !responder_id_matches(rid, d_subject, d_spki_raw) {
            continue;
        }

        // Found a candidate. Validate it strictly — any failure is a
        // distinct error variant; we do NOT fall through to "try the
        // next candidate" because RFC 6960 §4.2.2.2 only contemplates
        // one signing key per response, and silently skipping a
        // candidate after partial validation would obscure attacks.
        validate_delegate_responder_cert(
            delegate,
            issuer_subject,
            issuer_spki,
            verifier,
            produced_at_unix,
        )?;

        return Ok(delegate
            .tbs_certificate
            .subject_public_key_info
            .owned_to_ref());
    }

    // ResponderId matches neither the issuer nor any embedded cert.
    Err(Error::OcspResponderIdMismatch)
}

/// Extract the `producedAt` time from a [`BasicOcspResponse`] as a Unix
/// timestamp. Used by the delegated-responder validity check; declared
/// here rather than inline to keep the call sites tight.
fn produced_at_unix_secs(basic: &BasicOcspResponse) -> u64 {
    basic
        .tbs_response_data
        .produced_at
        .as_ref()
        .to_unix_duration()
        .as_secs()
}

// ---------------------------------------------------------------------------
// Unit tests for hash_certid_input
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-384 of b"test".
    ///
    /// Oracle: python3 -c "import hashlib, binascii; print(binascii.hexlify(hashlib.sha384(b'test').`digest()).decode()`)"
    /// → 768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9
    #[test]
    fn hash_certid_sha384() {
        let expected: &[u8] = &[
            0x76, 0x84, 0x12, 0x32, 0x0f, 0x7b, 0x0a, 0xa5, 0x81, 0x2f, 0xce, 0x42, 0x8d, 0xc4,
            0x70, 0x6b, 0x3c, 0xae, 0x50, 0xe0, 0x2a, 0x64, 0xca, 0xa1, 0x6a, 0x78, 0x22, 0x49,
            0xbf, 0xe8, 0xef, 0xc4, 0xb7, 0xef, 0x1c, 0xcb, 0x12, 0x62, 0x55, 0xd1, 0x96, 0x04,
            0x7d, 0xfe, 0xdf, 0x17, 0xa0, 0xa9,
        ];
        let result = hash_certid_input(&OID_SHA384, b"test").expect("SHA-384 must succeed");
        assert_eq!(
            result.as_slice(),
            expected,
            "SHA-384(\"test\") must match Python oracle"
        );
    }

    /// SHA-512 of b"test".
    ///
    /// Oracle: python3 -c "import hashlib, binascii; print(binascii.hexlify(hashlib.sha512(b'test').`digest()).decode()`)"
    /// → ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff
    #[test]
    fn hash_certid_sha512() {
        let expected: &[u8] = &[
            0xee, 0x26, 0xb0, 0xdd, 0x4a, 0xf7, 0xe7, 0x49, 0xaa, 0x1a, 0x8e, 0xe3, 0xc1, 0x0a,
            0xe9, 0x92, 0x3f, 0x61, 0x89, 0x80, 0x77, 0x2e, 0x47, 0x3f, 0x88, 0x19, 0xa5, 0xd4,
            0x94, 0x0e, 0x0d, 0xb2, 0x7a, 0xc1, 0x85, 0xf8, 0xa0, 0xe1, 0xd5, 0xf8, 0x4f, 0x88,
            0xbc, 0x88, 0x7f, 0xd6, 0x7b, 0x14, 0x37, 0x32, 0xc3, 0x04, 0xcc, 0x5f, 0xa9, 0xad,
            0x8e, 0x6f, 0x57, 0xf5, 0x00, 0x28, 0xa8, 0xff,
        ];
        let result = hash_certid_input(&OID_SHA512, b"test").expect("SHA-512 must succeed");
        assert_eq!(
            result.as_slice(),
            expected,
            "SHA-512(\"test\") must match Python oracle"
        );
    }

    /// Unknown OID must return `OcspMalformed`.
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
