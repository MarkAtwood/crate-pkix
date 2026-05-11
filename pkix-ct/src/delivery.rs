//! Adapters for SCT-list delivery channels other than the cert extension.
//!
//! RFC 6962 §3.3 defines three delivery channels for `SignedCertificateTimestampList`:
//!
//! 1. **Embedded in the cert** (extension OID 1.3.6.1.4.1.11129.2.4.2) —
//!    use [`SctList::from_extension_value`] directly. The extension's
//!    `extnValue` is double-OCTET-STRING-wrapped per the spec; that
//!    constructor handles the wrap.
//! 2. **OCSP-stapled** (extension OID 1.3.6.1.4.1.11129.2.4.5, inside a
//!    `BasicOcspResponse`) — use [`sct_list_from_ocsp_response`]. The
//!    extension's wire shape is the same OCTET-STRING-wrapping-`SerializedSCTList`
//!    as the cert form. Requires the `ocsp` crate feature.
//! 3. **TLS handshake extension 18** (`signed_certificate_timestamp`,
//!    RFC 6962 §3.3 / RFC 8446 §4.2) — use [`sct_list_from_tls_extension`].
//!    The TLS extension payload is the bare `SerializedSCTList` without
//!    any OCTET STRING wrapping; this is just a thin alias over
//!    [`SctList::from_serialized_list`].
//!
//! [`SctList::from_extension_value`]: crate::SctList::from_extension_value
//! [`SctList::from_serialized_list`]: crate::SctList::from_serialized_list

use crate::{Result, SctList};

/// Parse the SCT list from a TLS extension 18 (`signed_certificate_timestamp`)
/// payload.
///
/// The payload is a bare `SerializedSCTList` (RFC 6962 §3.3) — that is,
/// the same shape as the inner contents of the cert extension's second
/// OCTET STRING. There is no DER OCTET STRING wrapping on the TLS-wire
/// form; the TLS-wire u16 extension-data length already delimits the
/// payload.
///
/// # Errors
///
/// Forwards errors from [`SctList::from_serialized_list`].
pub fn sct_list_from_tls_extension(tls_ext_payload: &[u8]) -> Result<SctList> {
    SctList::from_serialized_list(tls_ext_payload)
}

/// Parse the SCT list from an OCSP response (RFC 6962 §3.3, OID
/// 1.3.6.1.4.1.11129.2.4.5).
///
/// Searches `BasicOcspResponse`'s `tbs_response_data.responses[*].single_extensions`
/// first (where deployed CAs typically place the extension, since the SCT
/// applies to the specific cert in that `SingleResponse`), then falls
/// back to `tbs_response_data.response_extensions`. Returns the first
/// list found.
///
/// Returns `Ok(None)` if the OCSP response parses cleanly but contains
/// no SCT extension at either level.
///
/// # Errors
///
/// Returns `Err(Error::ParseError)` if the OCSP-response DER does not
/// decode, or if the SCT-list extension value is malformed.
///
/// # Implementation note
///
/// `x509-ocsp` is the same OCSP parser pkix-revocation uses. This crate
/// does not duplicate that parsing — it just walks the extension list
/// for the SCT-list OID. pkix-ct deliberately does not depend on
/// pkix-revocation: pkix-revocation pulls in revocation-checking logic
/// pkix-ct does not need.
#[cfg(feature = "ocsp")]
#[cfg_attr(docsrs, doc(cfg(feature = "ocsp")))]
pub fn sct_list_from_ocsp_response(ocsp_response_der: &[u8]) -> Result<Option<SctList>> {
    use crate::Error;
    use der::asn1::ObjectIdentifier;
    use der::Decode;
    use x509_ocsp::{BasicOcspResponse, OcspResponse, OcspResponseStatus};

    // OID 1.3.6.1.4.1.11129.2.4.5 — id-pkix-ocsp-ct-sct (RFC 6962 §3.3).
    const SCT_OCSP_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.4.5");

    let response = OcspResponse::from_der(ocsp_response_der).map_err(|_| Error::ParseError)?;
    if response.response_status != OcspResponseStatus::Successful {
        return Ok(None);
    }
    let response_bytes = response.response_bytes.as_ref().ok_or(Error::ParseError)?;
    let basic = BasicOcspResponse::from_der(response_bytes.response.as_bytes())
        .map_err(|_| Error::ParseError)?;
    let tbs = &basic.tbs_response_data;

    // Look in each SingleResponse's single_extensions first — this is
    // where Let's Encrypt, GlobalSign, Sectigo, and most deployed CAs
    // place the SCT-list extension, because the SCTs apply to the
    // specific certificate identified by that SingleResponse.
    for single in &tbs.responses {
        if let Some(exts) = single.single_extensions.as_ref() {
            for ext in exts {
                if ext.extn_id == SCT_OCSP_OID {
                    return SctList::from_extension_value(ext.extn_value.as_bytes()).map(Some);
                }
            }
        }
    }

    // Fall back to top-level responseExtensions.
    if let Some(exts) = tbs.response_extensions.as_ref() {
        for ext in exts {
            if ext.extn_id == SCT_OCSP_OID {
                return SctList::from_extension_value(ext.extn_value.as_bytes()).map(Some);
            }
        }
    }

    Ok(None)
}
