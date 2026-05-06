//! Offline CRL-based revocation checker.
//!
//! Enabled by the `crl` feature.

use crate::{Error, RevocationChecker};
use der::{Decode as _, Encode as _};
use pkix_path::{names_match, SignatureVerifier};
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
/// # Limitations (v0.1)
///
/// - The CRL must be signed directly by the certificate issuer
///   (indirect CRLs are not supported).
/// - CRL Distribution Point name matching (CDP vs IDP name) is not implemented.
///   The checker does enforce `onlyContainsUserCerts`, `onlyContainsCACerts`, and
///   `onlyContainsAttributeCerts` scope flags; full CDP/IDP name matching is v0.2.
/// - Both the base CRL and the delta CRL (if present) are re-parsed from DER on
///   every [`check_revocation`] call. For long chains validated against the same
///   CRL pair, this is O(N) redundant parsing. Tracked for v0.2 (cache the parsed
///   `CertificateList` in `new` / `with_delta`).
/// - [`RevocationChecker::check_revocation_against_anchor`] is not overridden.
///   The certificate immediately issued by the trust anchor is not
///   revocation-checked by this type; revocation against the anchor is the
///   responsibility of the path validator (a v0.1 limitation).
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

        // The delta MUST have a BaseCRLNumber extension (marks it as a delta CRL).
        let delta_base_num = base_crl_number(&delta_crl);
        if delta_base_num.is_none() {
            // No deltaCRLIndicator → this is not a delta CRL.
            return Err(Error::DeltaCrlBaseMismatch);
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
        match &crl.tbs_cert_list.next_update {
            Some(next_update) => {
                if self.now_unix > next_update.to_unix_duration().as_secs() {
                    return Err(Error::CrlExpired);
                }
            }
            None => return Err(Error::CrlExpired),
        }

        // (5) RFC 5280 §5.2.5: if the CRL has an IssuingDistributionPoint extension
        //     (critical), check scope constraints against the certificate.
        if let Some(idp) = parse_issuing_dp(&crl) {
            // onlyContainsAttributeCerts: we never handle attribute certs.
            if idp.only_contains_attribute_certs {
                return Ok(()); // CRL does not cover this certificate
            }
            let cert_is_ca = cert_is_ca_cert(cert);
            // onlyContainsUserCerts: CRL only covers end-entity (non-CA) certs.
            if idp.only_contains_user_certs && cert_is_ca {
                return Ok(()); // CRL does not cover CA certs
            }
            // onlyContainsCACerts: CRL only covers CA certs.
            if idp.only_contains_ca_certs && !cert_is_ca {
                return Ok(()); // CRL does not cover end-entity certs
            }
        }

        // (6) §5.2.4 delta CRL merge: if a delta CRL is present, collect its revoked
        //     entries and merge with the base CRL's revoked list.
        let delta_entries: Vec<RevokedCert> = if let Some(ref delta_der) = self.delta_crl_der {
            let delta_crl = CertificateList::from_der(delta_der).map_err(Error::CrlParseError)?;

            // Defense-in-depth: verify delta CRL issuer matches the base CRL issuer.
            // The with_delta() constructor already enforces this at construction time,
            // but re-checking here guards against any future path that bypasses the
            // constructor (RFC 5280 §5.2.4: base and delta must come from the same CA).
            if !names_match(&delta_crl.tbs_cert_list.issuer, &crl.tbs_cert_list.issuer) {
                return Err(Error::CrlIssuerMismatch);
            }

            // Verify delta CRL issuer also matches the certificate's issuer
            // (transitively guaranteed by the two checks above, but explicit for clarity).
            if !names_match(
                &delta_crl.tbs_cert_list.issuer,
                &cert.tbs_certificate.issuer,
            ) {
                return Err(Error::CrlIssuerMismatch);
            }

            // Verify delta CRL signature.
            let delta_tbs_bytes = delta_crl
                .tbs_cert_list
                .to_der()
                .map_err(Error::CrlParseError)?;
            self.verifier
                .verify_signature(
                    delta_crl.signature_algorithm.owned_to_ref(),
                    issuer
                        .tbs_certificate
                        .subject_public_key_info
                        .owned_to_ref(),
                    &delta_tbs_bytes,
                    delta_crl.signature.raw_bytes(),
                )
                .map_err(|_| Error::CrlSignatureInvalid)?;

            // Verify delta CRL validity window.
            let delta_this_update = delta_crl
                .tbs_cert_list
                .this_update
                .to_unix_duration()
                .as_secs();
            if self.now_unix < delta_this_update {
                return Err(Error::CrlExpired);
            }
            match &delta_crl.tbs_cert_list.next_update {
                Some(nu) => {
                    if self.now_unix > nu.to_unix_duration().as_secs() {
                        return Err(Error::CrlExpired);
                    }
                }
                None => return Err(Error::CrlExpired),
            }

            delta_crl
                .tbs_cert_list
                .revoked_certificates
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        // (7) Search for the certificate's serial number, delta entries first.
        //     RFC 5280 §5.2.4: delta CRL entries take precedence over base entries.
        //     A removeFromCRL reason in the delta means the cert was un-held.
        let cert_serial = &cert.tbs_certificate.serial_number;

        // Check delta CRL entries (they take precedence).
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
