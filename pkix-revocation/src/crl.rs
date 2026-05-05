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

/// OID for CRLNumber extension (RFC 5280 §5.2.3) — id-ce-cRLNumber: 2.5.29.20
#[allow(dead_code)]
const OID_CRL_NUMBER: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.20");

/// OID for deltaCRLIndicator extension (RFC 5280 §5.2.4) — id-ce-deltaCRLIndicator: 2.5.29.27
/// This extension is CRITICAL; its presence marks a delta CRL.
#[allow(dead_code)]
const OID_DELTA_CRL_INDICATOR: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.27");

/// OID for issuingDistributionPoint extension (RFC 5280 §5.2.5) — 2.5.29.28
/// Note: x509-cert 0.2.5 has a wrong AssociatedOid for IssuingDistributionPoint
/// (it uses SubjectInfoAccess OID instead). Always look up this extension by
/// raw OID rather than using AssociatedOid-based helpers.
#[allow(dead_code)]
const OID_ISSUING_DISTRIBUTION_POINT: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.28");

/// OID for KeyUsage extension (RFC 5280 §4.2.1.3) — id-ce-keyUsage: 2.5.29.15
/// Used to check the cRLSign bit on the CRL issuer.
const OID_KEY_USAGE_CRL: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.15");

/// Offline CRL-based revocation checker.
///
/// Parses a DER-encoded [`CertificateList`][x509_cert::crl::CertificateList],
/// verifies its signature against the issuer's SPKI, checks the
/// `thisUpdate`/`nextUpdate` validity window, and reports whether the
/// certificate's serial number appears in the revoked list.
///
/// # Feature
///
/// Only available when the `crl` feature is enabled.
///
/// # Limitations (v0.1)
///
/// - The CRL must be signed directly by the certificate issuer
///   (indirect CRLs are not supported).
/// - Delta CRLs are not supported.
/// - The CRL is re-parsed from DER on every [`check_revocation`] call.
///   For long chains validated against the same CRL, this is O(N) redundant
///   parsing. Tracked for v0.2 (cache the parsed `CertificateList` in `new`).
///
/// [`check_revocation`]: crate::RevocationChecker::check_revocation
#[derive(Clone, Debug)]
pub struct CrlChecker<V> {
    crl_der: Vec<u8>,
    now_unix: u64,
    verifier: V,
}

impl<V: SignatureVerifier> CrlChecker<V> {
    /// Create a new `CrlChecker`.
    ///
    /// - `crl_der`  — DER-encoded `CertificateList` (any `Into<Vec<u8>>`, e.g. `Vec<u8>` or `&[u8]`)
    /// - `now_unix` — current time as seconds since the Unix epoch
    /// - `verifier` — signature verifier used to authenticate the CRL
    pub fn new(crl_der: impl Into<Vec<u8>>, now_unix: u64, verifier: V) -> Self {
        Self {
            crl_der: crl_der.into(),
            now_unix,
            verifier,
        }
    }
}

impl<V: SignatureVerifier> RevocationChecker for CrlChecker<V> {
    fn check_revocation(&self, cert: &Certificate, issuer: &Certificate) -> crate::Result<()> {
        // (1) Parse the CRL.
        let crl = CertificateList::from_der(&self.crl_der).map_err(Error::CrlParseError)?;

        // (2) Verify the CRL issuer name matches the certificate's issuer.
        //     A CRL signed by a different CA does not convey revocation status for
        //     certificates issued by this CA.
        if !names_match(&crl.tbs_cert_list.issuer, &cert.tbs_certificate.issuer) {
            return Err(Error::CrlIssuerMismatch);
        }

        // (3) Verify the CRL signature against the issuer's SPKI.
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

        // (3b) RFC 5280 §6.3.3(f): the CRL issuer must have cRLSign in KeyUsage when present.
        if !issuer_has_crl_sign(issuer) {
            return Err(Error::CrlSignMissing);
        }

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

        // (5) Search the revoked list for this certificate's serial number.
        let cert_serial = &cert.tbs_certificate.serial_number;
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

/// Convert a DER [`Uint`][der::asn1::Uint] to a `u64`, padding from the left.
///
/// Returns `None` if the integer is larger than 8 bytes (would overflow `u64`).
/// CRL numbers in PKITS are small (1–5), so this is not a practical limit.
#[allow(dead_code)]
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
/// Returns `None` if the CRLNumber extension is absent or cannot be decoded.
/// CRLNumber is a non-negative INTEGER (RFC 5280 §5.2.3).
#[allow(dead_code)]
fn crl_number(crl: &x509_cert::crl::CertificateList) -> Option<u64> {
    use der::Decode as _;
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

/// Extract the BaseCRLNumber from a delta CRL's extensions.
///
/// The `deltaCRLIndicator` extension value IS the BaseCRLNumber — it is an
/// INTEGER encoding the CRL number of the base CRL this delta updates.
/// This extension MUST be critical (RFC 5280 §5.2.4).
///
/// Returns `None` if the extension is absent (CRL is not a delta CRL),
/// or the `u64` value if it is present.
#[allow(dead_code)]
fn base_crl_number(crl: &x509_cert::crl::CertificateList) -> Option<u64> {
    use der::Decode as _;
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

/// Returns `true` if the certificate has `cRLSign` set in its KeyUsage extension,
/// OR if the KeyUsage extension is absent (no constraint).
///
/// RFC 5280 §6.3.3(f): a CRL issuer that has a KeyUsage extension MUST assert
/// the `cRLSign` bit. If KeyUsage is absent, there is no constraint.
fn issuer_has_crl_sign(cert: &x509_cert::Certificate) -> bool {
    use der::Decode as _;
    use x509_cert::ext::pkix::KeyUsage;

    let Some(exts) = cert.tbs_certificate.extensions.as_ref() else {
        return true; // No extensions at all → no KeyUsage constraint
    };
    let Some(ku_ext) = exts.iter().find(|e| e.extn_id == OID_KEY_USAGE_CRL) else {
        return true; // KeyUsage absent → no constraint
    };
    KeyUsage::from_der(ku_ext.extn_value.as_bytes())
        .map(|ku| ku.crl_sign())
        .unwrap_or(false) // malformed KeyUsage → treat as missing the bit
}

/// Extract the CRLReason code from a revoked cert entry's extensions, if present.
///
/// Returns the `CrlReason` (RFC 5280 §5.3.1), or `None` if the extension is absent.
fn extract_reason_code(entry: &RevokedCert) -> Option<CrlReason> {
    let exts = entry.crl_entry_extensions.as_ref()?;
    exts.iter()
        .find(|ext| ext.extn_id == OID_CRL_REASONS)
        .and_then(|ext| CrlReason::from_der(ext.extn_value.as_bytes()).ok())
}
