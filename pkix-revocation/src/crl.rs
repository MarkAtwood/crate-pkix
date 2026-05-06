//! Offline CRL-based revocation checker.
//!
//! Enabled by the `crl` feature.

use crate::{Error, RevocationChecker};
use der::{Decode as _, Encode as _};
use pkix_path::{names_match, SignatureVerifier, TrustAnchor};
use spki::der::referenced::OwnedToRef as _;
use x509_cert::{
    crl::{CertificateList, RevokedCert},
    ext::pkix::crl::CrlReason,
    Certificate,
};

// OID 2.5.29.21 — id-ce-CRLReasons (RFC 5280 §5.3.1)
const OID_CRL_REASONS: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.21");

/// OID for `CRLNumber` extension (RFC 5280 §5.2.3) — id-ce-cRLNumber: 2.5.29.20
const OID_CRL_NUMBER: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.20");

/// OID for deltaCRLIndicator extension (RFC 5280 §5.2.4) — id-ce-deltaCRLIndicator: 2.5.29.27
/// This extension is CRITICAL; its presence marks a delta CRL.
const OID_DELTA_CRL_INDICATOR: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.27");

/// OID for issuingDistributionPoint extension (RFC 5280 §5.2.5) — 2.5.29.28
/// Note: x509-cert 0.2.5 has a wrong `AssociatedOid` for `IssuingDistributionPoint`
/// (it uses `SubjectInfoAccess` OID instead). Always look up this extension by
/// raw OID rather than using AssociatedOid-based helpers.
const OID_ISSUING_DISTRIBUTION_POINT: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.28");

/// OID for `KeyUsage` extension (RFC 5280 §4.2.1.3) — id-ce-keyUsage: 2.5.29.15
/// Used to check the `cRLSign` bit on the CRL issuer.
const OID_KEY_USAGE_CRL: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.15");

/// OID for `BasicConstraints` extension (RFC 5280 §4.2.1.9) — id-ce-basicConstraints: 2.5.29.19
const OID_BASIC_CONSTRAINTS: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.19");

/// Offline CRL-based revocation checker.
///
/// Parses a DER-encoded [`CertificateList`][x509_cert::crl::CertificateList],
/// verifies its signature against the issuer's SPKI, checks the
/// `thisUpdate`/`nextUpdate` validity window, and reports whether the
/// certificate's serial number appears in the revoked list.
///
/// To also apply a delta CRL (RFC 5280 §5.2.4), use [`CrlChecker::with_delta`].
///
/// # Feature
///
/// Only available when the `crl` feature is enabled.
///
/// # Return value semantics
///
/// [`RevocationChecker::check_revocation`] returns `Ok(())` in two distinct cases:
///
/// 1. **Not revoked**: the CRL covers this certificate type and the serial number
///    was not found in the revoked list.
/// 2. **Not covered**: the CRL's `IssuingDistributionPoint` scope flags
///    (`onlyContainsUserCerts`, `onlyContainsCACerts`, `onlyContainsAttributeCerts`)
///    indicate the CRL does not apply to this certificate type.
///
/// These two outcomes are indistinguishable from the caller's perspective.
/// Callers enforcing a **hard-fail** revocation policy must separately verify
/// that at least one CRL or OCSP response actually covers the certificate
/// in question; receiving `Ok(())` alone is not sufficient.
///
/// # Limitations (v0.1)
///
 /// - The CRL must be signed directly by the certificate issuer
///   (indirect CRLs are not supported; deferred to v0.2).
/// - CRL Distribution Point name matching (CDP vs IDP name) is not implemented.
///   The checker does enforce `onlyContainsUserCerts`, `onlyContainsCACerts`, and
///   `onlyContainsAttributeCerts` scope flags; full CDP/IDP name matching is v0.2.
/// - Both the base CRL and the delta CRL (if present) are re-parsed from DER on
///   every [`check_revocation`] call. For long chains validated against the same
///   CRL pair, this is O(N) redundant parsing. Tracked for v0.3 (cache the parsed
///   `CertificateList` in `new` / `with_delta`).
/// - [`RevocationChecker::check_revocation_against_anchor`] is overridden.
///   For the certificate issued directly by a trust anchor, the CRL is verified
///   using the anchor's subject DN and SPKI in place of the missing issuer
///   `Certificate`.  The `cRLSign` KeyUsage check is omitted for trust anchors
///   (anchors are trusted by construction; they carry no KeyUsage to inspect).
///   If the CRL's issuer name does not match the anchor, the method returns
///   [`Error::CrlIssuerMismatch`] rather than `Ok(())`.
///
/// [`check_revocation`]: crate::RevocationChecker::check_revocation
/// [`RevocationChecker::check_revocation_against_anchor`]: crate::RevocationChecker::check_revocation_against_anchor
#[derive(Clone, Debug)]
pub struct CrlChecker<V> {
    crl_der: Vec<u8>,
    /// Optional delta CRL DER. When present, its entries are merged with the
    /// base CRL in `check_revocation` (RFC 5280 §5.2.4).
    delta_crl_der: Option<Vec<u8>>,
    now_unix: u64,
    verifier: V,
}

impl<V: SignatureVerifier> CrlChecker<V> {
    /// Create a new `CrlChecker`.
    ///
    /// - `crl_der`  — DER-encoded `CertificateList` (any `Into<Vec<u8>>`, e.g. `Vec<u8>` or `&[u8]`)
    /// - `now_unix` — current time as seconds since the Unix epoch
    /// - `verifier` — signature verifier used to authenticate the CRL
    #[must_use]
    pub fn new(crl_der: impl Into<Vec<u8>>, now_unix: u64, verifier: V) -> Self {
        Self {
            crl_der: crl_der.into(),
            delta_crl_der: None,
            now_unix,
            verifier,
        }
    }

    /// Create a `CrlChecker` with a base CRL and a delta CRL.
    ///
    /// The delta CRL is merged into the base CRL per RFC 5280 §5.2.4:
    /// - Entries in the delta that are not in the base are added.
    /// - Entries in the delta with reason `removeFromCRL` are removed from the
    ///   base.
    /// - The merged result is used for all subsequent `check_revocation` calls.
    ///
    /// Returns `Err(Error::DeltaCrlBaseMismatch)` if:
    /// - The delta CRL's `BaseCRLNumber` is absent (not a delta CRL), or
    /// - The delta's `BaseCRLNumber` is greater than the base CRL's `CRLNumber`
    ///   (the delta was produced against a newer base than the one supplied).
    pub fn with_delta(
        base_der: impl Into<Vec<u8>>,
        delta_der: impl Into<Vec<u8>>,
        now_unix: u64,
        verifier: V,
    ) -> crate::Result<Self> {
        let base_der = base_der.into();
        let delta_der_bytes = delta_der.into();

        // Parse both to validate structure and extract CRL numbers.
        let base_crl = CertificateList::from_der(&base_der).map_err(Error::CrlParseError)?;
        let delta_crl =
            CertificateList::from_der(&delta_der_bytes).map_err(Error::CrlParseError)?;

        // The base CRL MUST NOT itself be a delta CRL (RFC 5280 §5.2.4: only a
        // full CRL may serve as the base).  Detect by OID presence alone — do not
        // rely on successful decode, since a malformed deltaCRLIndicator value
        // would cause base_crl_number() to return None and silently pass as a base.
        if has_delta_crl_indicator(&base_crl) {
            return Err(Error::DeltaCrlBaseMismatch);
        }

        // The delta MUST have a deltaCRLIndicator extension (marks it as a delta CRL).
        // Check presence by OID first to distinguish "absent" from "present but malformed":
        //   - Extension absent           → not a delta CRL → DeltaCrlBaseMismatch
        //   - Extension present, value malformed → CrlParseError (structural error)
        if !has_delta_crl_indicator(&delta_crl) {
            // No deltaCRLIndicator OID → this is not a delta CRL.
            return Err(Error::DeltaCrlBaseMismatch);
        }
        let delta_base_num = base_crl_number(&delta_crl);
        if delta_base_num.is_none() {
            // deltaCRLIndicator OID is present but its INTEGER value cannot be decoded.
            return Err(Error::CrlParseError(der::Error::from(
                der::ErrorKind::Failed,
            )));
        }

        // The base CRL and delta CRL MUST have the same issuer.
        if !names_match(
            &base_crl.tbs_cert_list.issuer,
            &delta_crl.tbs_cert_list.issuer,
        ) {
            return Err(Error::DeltaCrlBaseMismatch);
        }

        // If both CRL numbers are present, the delta's BaseCRLNumber must be
        // ≤ the base's CRLNumber (we have a base that is at least as current as
        // what the delta expects).
        if let (Some(base_num), Some(db_num)) = (crl_number(&base_crl), delta_base_num) {
            if db_num > base_num {
                return Err(Error::CrlNumberMismatch);
            }
        }

        Ok(Self {
            crl_der: base_der,
            delta_crl_der: Some(delta_der_bytes),
            now_unix,
            verifier,
        })
    }
}

impl<V: SignatureVerifier> RevocationChecker for CrlChecker<V> {
    fn check_revocation(&self, cert: &Certificate, issuer: &Certificate) -> crate::Result<()> {
        // (1) Parse the base CRL.
        let crl = CertificateList::from_der(&self.crl_der).map_err(Error::CrlParseError)?;

        // (2) Verify the CRL issuer name matches the certificate's issuer.
        //     A CRL signed by a different CA does not convey revocation status for
        //     certificates issued by this CA.
        if !names_match(&crl.tbs_cert_list.issuer, &cert.tbs_certificate.issuer) {
            return Err(Error::CrlIssuerMismatch);
        }
        // (2b) Verify the `issuer` Certificate's subject DN matches the CRL issuer.
        //      This guards against a caller passing a mismatched issuer certificate
        //      (e.g., a cert from a different CA whose name happens to appear in a
        //      CRL distribution point). Without this check, the cRLSign and SPKI
        //      checks below would operate on the wrong certificate.
        if !names_match(&issuer.tbs_certificate.subject, &crl.tbs_cert_list.issuer) {
            return Err(Error::CrlIssuerMismatch);
        }

        // (3) RFC 5280 §6.3.3(f): the CRL issuer must have cRLSign in KeyUsage when present.
        //     Check this before verifying the signature so we reject on the correct error
        //     (CrlSignMissing rather than CrlSignatureInvalid) when the key lacks cRLSign.
        if !issuer_has_crl_sign(issuer) {
            return Err(Error::CrlSignMissing);
        }

        // (3b) Verify the CRL signature against the issuer's SPKI.
        let tbs_bytes = crl.tbs_cert_list.to_der().map_err(Error::CrlParseError)?;
        self.verifier
            .verify_signature(
                crl.signature_algorithm.owned_to_ref(),
                issuer
                    .tbs_certificate
                    .subject_public_key_info
                    .owned_to_ref(),
                &tbs_bytes,
                crl.signature.raw_bytes(),
            )
            .map_err(|_| Error::CrlSignatureInvalid)?;

        // (4) Check CRL validity window: thisUpdate ≤ now ≤ nextUpdate.
        //     Absent nextUpdate is treated as expired: an indefinitely valid CRL would
        //     allow a stale revocation list to suppress detection of revoked certificates.
        let this_update = crl.tbs_cert_list.this_update.to_unix_duration().as_secs();
        if self.now_unix < this_update {
            return Err(Error::CrlExpired);
        }
        let next_update = crl.tbs_cert_list.next_update.as_ref().ok_or(Error::CrlExpired)?;
        if self.now_unix > next_update.to_unix_duration().as_secs() {
            return Err(Error::CrlExpired);
        }

        // (5) RFC 5280 §5.2.5: if the CRL has an IssuingDistributionPoint extension
        //     (critical), check scope constraints against the certificate.
        if let Some(idp) = parse_issuing_dp(&crl) {
            // onlyContainsAttributeCerts: attribute cert validation is out of scope
            // for pkix-revocation (RFC 5755 is handled by pkix-ac, tracked for v0.2).
            if idp.only_contains_attribute_certs {
                // CRL does not cover this cert type — returning Ok(()) (not-covered, not not-revoked).
                // Callers with hard-fail revocation requirements must verify CRL coverage separately.
                return Ok(());
            }
            let cert_is_ca = cert_is_ca_cert(cert);
            // onlyContainsUserCerts: CRL only covers end-entity (non-CA) certs.
            if idp.only_contains_user_certs && cert_is_ca {
                // CRL does not cover this cert type — returning Ok(()) (not-covered, not not-revoked).
                // Callers with hard-fail revocation requirements must verify CRL coverage separately.
                return Ok(());
            }
            // onlyContainsCACerts: CRL only covers CA certs.
            if idp.only_contains_ca_certs && !cert_is_ca {
                // CRL does not cover this cert type — returning Ok(()) (not-covered, not not-revoked).
                // Callers with hard-fail revocation requirements must verify CRL coverage separately.
                return Ok(());
            }
        }

        // (6) §5.2.4 delta CRL merge: if a delta CRL is present, verify and collect
        //     its revoked entries.  verify_delta_crl_and_collect handles sig, expiry,
        //     and the primary issuer-name check.  The extra checks below are
        //     defense-in-depth: they guard against any future code path that bypasses
        //     the with_delta() constructor and against subtle cross-name mismatches.
        let delta_entries: Vec<RevokedCert> = if let Some(ref delta_der) = self.delta_crl_der {
            // Extra check: delta CRL issuer must also match the base CRL issuer
            // (construction-time invariant, re-checked here for defense-in-depth).
            // We parse once to get the issuer, then rely on the helper for the rest.
            let delta_issuer = {
                let delta_hdr =
                    CertificateList::from_der(delta_der).map_err(Error::CrlParseError)?;
                if !names_match(&delta_hdr.tbs_cert_list.issuer, &crl.tbs_cert_list.issuer) {
                    return Err(Error::CrlIssuerMismatch);
                }
                // Also verify against cert's issuer (transitively guaranteed above, explicit for clarity).
                if !names_match(
                    &delta_hdr.tbs_cert_list.issuer,
                    &cert.tbs_certificate.issuer,
                ) {
                    return Err(Error::CrlIssuerMismatch);
                }
                delta_hdr.tbs_cert_list.issuer
            };

            // Verify the `issuer` Certificate's subject DN matches the delta CRL issuer.
            // Mirrors step (2b) for the base CRL.
            if !names_match(&issuer.tbs_certificate.subject, &delta_issuer) {
                return Err(Error::CrlIssuerMismatch);
            }

            // cRLSign was already verified at line 218 for the base CRL issuer.
            // The delta CRL uses the same `issuer` (confirmed by the name-match
            // checks above), so the cRLSign bit check is not repeated here.
            // If a future extension introduces independent delta issuers, a
            // separate issuer_has_crl_sign() call must be added at that point.
            verify_delta_crl_and_collect(
                delta_der,
                &self.verifier,
                issuer
                    .tbs_certificate
                    .subject_public_key_info
                    .owned_to_ref(),
                &issuer.tbs_certificate.subject,
                self.now_unix,
            )?
        } else {
            Vec::new()
        };

        // (7) Search for the certificate's serial number, delta entries first.
        //     RFC 5280 §5.2.4: delta CRL entries take precedence over base entries.
        //     A removeFromCRL reason in the delta means the cert was un-held.
        let cert_serial = &cert.tbs_certificate.serial_number;
        check_revocation_status(cert_serial, &delta_entries, &crl)
    }

    /// Check revocation for `cert` issued directly by a trust anchor.
    ///
    /// Uses the anchor's `subject` and `subject_public_key_info` in place of
    /// an issuer `Certificate` to verify the CRL.  The `cRLSign` KeyUsage bit
    /// check is omitted because trust anchors do not carry a `Certificate` with
    /// extensions to inspect.
    ///
    /// # Limitations (v0.1)
    ///
    /// CRL discovery via the `cRLDistributionPoints` extension is not
    /// implemented.  The CRL DER must be supplied at construction time.
    /// If the CRL's issuer name does not match the anchor's subject, this
    /// method returns [`Error::CrlIssuerMismatch`] rather than `Ok(())`,
    /// ensuring a mismatched CRL is surfaced rather than silently skipped.
    fn check_revocation_against_anchor(
        &self,
        cert: &Certificate,
        anchor: &TrustAnchor,
    ) -> crate::Result<()> {
        // (1) Parse the base CRL.
        let crl = CertificateList::from_der(&self.crl_der).map_err(Error::CrlParseError)?;

        // (2) The CRL issuer must match the anchor's subject DN, and the
        // certificate being checked must also be issued by that anchor.
        // Without the second check a caller can supply an anchor for CA-A and
        // a cert issued by CA-B and get Ok(()) (cert not found in CA-A's CRL)
        // when it should get CrlIssuerMismatch.
        if !names_match(&crl.tbs_cert_list.issuer, &anchor.subject) {
            return Err(Error::CrlIssuerMismatch);
        }
        if !names_match(&cert.tbs_certificate.issuer, &anchor.subject) {
            return Err(Error::CrlIssuerMismatch);
        }

        // (3) Verify the CRL signature against the anchor's SPKI.
        //     cRLSign KeyUsage check is skipped: trust anchors have no KeyUsage
        //     extension accessible to us (they are trusted by construction).
        let tbs_bytes = crl.tbs_cert_list.to_der().map_err(Error::CrlParseError)?;
        self.verifier
            .verify_signature(
                crl.signature_algorithm.owned_to_ref(),
                anchor.subject_public_key_info.owned_to_ref(),
                &tbs_bytes,
                crl.signature.raw_bytes(),
            )
            .map_err(|_| Error::CrlSignatureInvalid)?;

        // (4) Check CRL validity window.
        let this_update = crl.tbs_cert_list.this_update.to_unix_duration().as_secs();
        if self.now_unix < this_update {
            return Err(Error::CrlExpired);
        }
        let next_update = crl.tbs_cert_list.next_update.as_ref().ok_or(Error::CrlExpired)?;
        if self.now_unix > next_update.to_unix_duration().as_secs() {
            return Err(Error::CrlExpired);
        }

        // (5) IssuingDistributionPoint scope check (same as check_revocation).
        if let Some(idp) = parse_issuing_dp(&crl) {
            if idp.only_contains_attribute_certs {
                return Ok(());
            }
            let cert_is_ca = cert_is_ca_cert(cert);
            if idp.only_contains_user_certs && cert_is_ca {
                return Ok(());
            }
            if idp.only_contains_ca_certs && !cert_is_ca {
                return Ok(());
            }
        }

        // (6) Delta CRL merge — if a delta CRL is present, verify and merge it.
        //     Uses the anchor SPKI for the delta signature check.
        let delta_entries: Vec<RevokedCert> = if let Some(ref delta_der) = self.delta_crl_der {
            verify_delta_crl_and_collect(
                delta_der,
                &self.verifier,
                anchor.subject_public_key_info.owned_to_ref(),
                &anchor.subject,
                self.now_unix,
            )?
        } else {
            Vec::new()
        };

        // (7) Search for the certificate's serial (delta entries take precedence).
        let cert_serial = &cert.tbs_certificate.serial_number;
        check_revocation_status(cert_serial, &delta_entries, &crl)
    }
}

// ---------------------------------------------------------------------------
// Revocation status helper
// ---------------------------------------------------------------------------

/// Search for `cert_serial` in `delta_entries` (higher priority) and then in
/// the base `crl`, and return the appropriate revocation result.
///
/// RFC 5280 §5.2.4: delta CRL entries take precedence over base entries.
/// - If found in `delta_entries` with reason `RemoveFromCRL`, the
///   certificateHold was lifted and the certificate is not revoked → `Ok(())`.
/// - If found in `delta_entries` for any other reason → `Err(Revoked)`.
/// - If found in the base CRL → `Err(Revoked)`.
/// - If not found in either → `Ok(())` (not revoked).
fn check_revocation_status(
    cert_serial: &x509_cert::serial_number::SerialNumber,
    delta_entries: &[RevokedCert],
    crl: &CertificateList,
) -> crate::Result<()> {
    // Check delta CRL entries first (they take precedence over base entries).
    if let Some(delta_entry) = delta_entries
        .iter()
        .find(|e| &e.serial_number == cert_serial)
    {
        let reason = extract_reason_code(delta_entry);
        if reason == Some(CrlReason::RemoveFromCRL) {
            // certificateHold was lifted; cert is not revoked.
            return Ok(());
        }
        return Err(Error::Revoked {
            serial: cert_serial.clone(),
            reason_code: reason,
        });
    }

    // Check base CRL entries.
    if let Some(revoked) = &crl.tbs_cert_list.revoked_certificates {
        if let Some(entry) = revoked.iter().find(|e| &e.serial_number == cert_serial) {
            return Err(Error::Revoked {
                serial: cert_serial.clone(),
                reason_code: extract_reason_code(entry),
            });
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Delta-CRL helper
// ---------------------------------------------------------------------------

/// Verify a delta CRL and return its revoked-certificate entries.
///
/// Performs (in order):
/// 1. Parse the delta DER.
/// 2. Check that the delta CRL issuer matches `expected_issuer_name`.
/// 3. Verify the delta signature using `issuer_spki`.
/// 4. Check the delta validity window against `now_unix`.
/// 5. Return the delta's revoked-certificates list (empty if absent).
///
/// The caller is responsible for any additional issuer-name cross-checks
/// needed by the calling context (e.g., checking the delta issuer against
/// the base CRL issuer or the subject certificate's issuer).
fn verify_delta_crl_and_collect<V: SignatureVerifier>(
    delta_der: &[u8],
    verifier: &V,
    issuer_spki: spki::SubjectPublicKeyInfoRef<'_>,
    expected_issuer_name: &x509_cert::name::Name,
    now_unix: u64,
) -> crate::Result<Vec<RevokedCert>> {
    let delta_crl = CertificateList::from_der(delta_der).map_err(Error::CrlParseError)?;

    if !names_match(&delta_crl.tbs_cert_list.issuer, expected_issuer_name) {
        return Err(Error::CrlIssuerMismatch);
    }

    let delta_tbs_bytes = delta_crl
        .tbs_cert_list
        .to_der()
        .map_err(Error::CrlParseError)?;
    verifier
        .verify_signature(
            delta_crl.signature_algorithm.owned_to_ref(),
            issuer_spki,
            &delta_tbs_bytes,
            delta_crl.signature.raw_bytes(),
        )
        .map_err(|_| Error::CrlSignatureInvalid)?;

    let delta_this_update = delta_crl
        .tbs_cert_list
        .this_update
        .to_unix_duration()
        .as_secs();
    if now_unix < delta_this_update {
        return Err(Error::CrlExpired);
    }
    let delta_next_update = delta_crl
        .tbs_cert_list
        .next_update
        .as_ref()
        .ok_or(Error::CrlExpired)?;
    if now_unix > delta_next_update.to_unix_duration().as_secs() {
        return Err(Error::CrlExpired);
    }

    Ok(delta_crl
        .tbs_cert_list
        .revoked_certificates
        .unwrap_or_default())
}

// ---------------------------------------------------------------------------
// Extension helpers
// ---------------------------------------------------------------------------

/// Convert a DER [`Uint`][der::asn1::Uint] to a `u64`, padding from the left.
///
/// Returns `None` if the integer is larger than 8 bytes (would overflow `u64`).
/// CRL numbers in PKITS are small (1–5), so this is not a practical limit.
fn uint_to_u64(n: &der::asn1::Uint) -> Option<u64> {
    let b = n.as_bytes();
    if b.len() > 8 {
        return None; // too large for u64
    }
    let mut arr = [0u8; 8];
    arr[8 - b.len()..].copy_from_slice(b);
    Some(u64::from_be_bytes(arr))
}

/// Extract the CRL number from a `CertificateList`'s extensions.
///
/// Returns `None` if the `CRLNumber` extension is absent or cannot be decoded.
/// `CRLNumber` is a non-negative INTEGER (RFC 5280 §5.2.3).
fn crl_number(crl: &CertificateList) -> Option<u64> {
    crl.tbs_cert_list
        .crl_extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find(|e| e.extn_id == OID_CRL_NUMBER)
        .and_then(|e| {
            der::asn1::Uint::from_der(e.extn_value.as_bytes())
                .ok()
                .and_then(|n| uint_to_u64(&n))
        })
}

/// Returns `true` if `crl` contains a `deltaCRLIndicator` extension (OID 2.5.29.27),
/// regardless of whether the extension value can be decoded.
///
/// Presence of this OID (which MUST be critical) is the canonical marker that a
/// CRL is a delta CRL per RFC 5280 §5.2.4.  Checking presence — not decode success —
/// is important: a malformed value still makes the CRL a delta CRL and must prevent
/// it from being used as a base.
fn has_delta_crl_indicator(crl: &CertificateList) -> bool {
    crl.tbs_cert_list
        .crl_extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .any(|e| e.extn_id == OID_DELTA_CRL_INDICATOR)
}

/// Extract the `BaseCRLNumber` from a delta CRL's extensions.
///
/// The `deltaCRLIndicator` extension value IS the `BaseCRLNumber` — it is an
/// INTEGER encoding the CRL number of the base CRL this delta updates.
/// This extension MUST be critical (RFC 5280 §5.2.4).
///
/// Returns `None` if the extension is absent (CRL is not a delta CRL),
/// or the `u64` value if it is present.
fn base_crl_number(crl: &CertificateList) -> Option<u64> {
    crl.tbs_cert_list
        .crl_extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find(|e| e.extn_id == OID_DELTA_CRL_INDICATOR)
        .and_then(|e| {
            der::asn1::Uint::from_der(e.extn_value.as_bytes())
                .ok()
                .and_then(|n| uint_to_u64(&n))
        })
}

/// Returns `true` if the certificate has `cRLSign` set in its `KeyUsage` extension,
/// OR if the `KeyUsage` extension is absent (no constraint).
///
/// RFC 5280 §6.3.3(f): a CRL issuer that has a `KeyUsage` extension MUST assert
/// the `cRLSign` bit. If `KeyUsage` is absent, there is no constraint.
fn issuer_has_crl_sign(cert: &Certificate) -> bool {
    use x509_cert::ext::pkix::KeyUsage;

    let Some(ku_ext) = cert
        .tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find(|e| e.extn_id == OID_KEY_USAGE_CRL)
    else {
        return true; // KeyUsage absent (or no extensions) → no constraint
    };
    KeyUsage::from_der(ku_ext.extn_value.as_bytes())
        .map(|ku| ku.crl_sign())
        .unwrap_or(false) // malformed KeyUsage → treat as missing the bit
}

/// Extract the `CRLReason` code from a revoked cert entry's extensions, if present.
///
/// Returns the `CrlReason` (RFC 5280 §5.3.1), or `None` if the extension is absent.
fn extract_reason_code(entry: &RevokedCert) -> Option<CrlReason> {
    let exts = entry.crl_entry_extensions.as_ref()?;
    exts.iter()
        .find(|ext| ext.extn_id == OID_CRL_REASONS)
        .and_then(|ext| CrlReason::from_der(ext.extn_value.as_bytes()).ok())
}

/// Extract the `IssuingDistributionPoint` from a CRL, if present.
///
/// Uses raw OID lookup because x509-cert 0.2.5 has a wrong `AssociatedOid` for
/// this type (it maps to `SubjectInfoAccess` instead of 2.5.29.28).
fn parse_issuing_dp(
    crl: &CertificateList,
) -> Option<x509_cert::ext::pkix::crl::IssuingDistributionPoint> {
    use x509_cert::ext::pkix::crl::IssuingDistributionPoint;

    crl.tbs_cert_list
        .crl_extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find(|e| e.extn_id == OID_ISSUING_DISTRIBUTION_POINT)
        .and_then(|e| IssuingDistributionPoint::from_der(e.extn_value.as_bytes()).ok())
}

/// Returns `true` if `cert` is a CA certificate (`BasicConstraints` `cA = TRUE`).
fn cert_is_ca_cert(cert: &Certificate) -> bool {
    use x509_cert::ext::pkix::BasicConstraints;

    cert.tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find(|e| e.extn_id == OID_BASIC_CONSTRAINTS)
        .and_then(|e| BasicConstraints::from_der(e.extn_value.as_bytes()).ok())
        .map(|bc| bc.ca)
        .unwrap_or(false)
}
