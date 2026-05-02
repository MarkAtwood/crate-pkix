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

        // (4) Search the revoked list for this certificate's serial number.
        let cert_serial = &cert.tbs_certificate.serial_number;
        if let Some(revoked) = &crl.tbs_cert_list.revoked_certificates {
            for entry in revoked {
                if &entry.serial_number == cert_serial {
                    return Err(Error::Revoked {
                        serial: cert_serial.clone(),
                        reason_code: extract_reason_code(entry),
                    });
                }
            }
        }

        Ok(())
    }
}

/// Extract the CRLReason code from a revoked cert entry's extensions, if present.
///
/// Returns the numeric reason code (RFC 5280 §5.3.1) as a `u8`, or `None` if
/// the `CRLReasons` extension is absent.
fn extract_reason_code(entry: &RevokedCert) -> Option<u8> {
    let exts = entry.crl_entry_extensions.as_ref()?;
    for ext in exts.iter() {
        if ext.extn_id == OID_CRL_REASONS {
            let reason = CrlReason::from_der(ext.extn_value.as_bytes()).ok()?;
            // CrlReason is a repr(u8) enum; the cast is always safe.
            return Some(reason as u8);
        }
    }
    None
}
