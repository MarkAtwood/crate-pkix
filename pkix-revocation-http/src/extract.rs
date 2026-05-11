//! Extract HTTP URLs from certificate extensions.
//!
//! - [`extract_cdp_http_urls`] reads the `cRLDistributionPoints` extension
//!   (RFC 5280 §4.2.1.13) and returns each `http://` or `https://` URI it
//!   advertises.
//! - [`extract_aia_http_urls`] reads the `authorityInfoAccess` extension
//!   (RFC 5280 §4.2.2.1) and partitions its `http://` / `https://` URIs by
//!   access method into OCSP responder URLs and CA-issuer URLs.
//!
//! Both helpers filter out non-HTTP transports (LDAP, FTP, file:// etc.).
//! They are deliberately lossy: the goal is "URLs the synchronous HTTP
//! fetcher knows what to do with"; consumers wanting LDAP CRL fetching can
//! parse the extensions themselves.

use crate::ExtractError;
use der::{asn1::Ia5String, Decode};
use x509_cert::{
    ext::pkix::{
        name::{DistributionPointName, GeneralName},
        AuthorityInfoAccessSyntax, CrlDistributionPoints,
    },
    Certificate,
};

/// `id-ce-cRLDistributionPoints` — RFC 5280 §4.2.1.13.
const OID_CRL_DISTRIBUTION_POINTS: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.31");

/// `id-pe-authorityInfoAccess` — RFC 5280 §4.2.2.1.
const OID_AUTHORITY_INFO_ACCESS: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1");

/// `id-ad-ocsp` — RFC 5280 §4.2.2.1, used as the `accessMethod` for an
/// OCSP responder URL inside `AuthorityInfoAccessSyntax`.
const OID_AD_OCSP: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1");

/// `id-ad-caIssuers` — RFC 5280 §4.2.2.1, used as the `accessMethod` for a
/// CA-issuer URL inside `AuthorityInfoAccessSyntax`.
const OID_AD_CA_ISSUERS: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.2");

/// HTTP/HTTPS URL extracted from a certificate's
/// `authorityInfoAccess` extension, partitioned by access method.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AiaUrls {
    /// OCSP responder URLs (accessMethod = `id-ad-ocsp`).
    pub ocsp: Vec<String>,
    /// CA-issuer URLs (accessMethod = `id-ad-caIssuers`) — used by
    /// path-builders to fetch missing intermediates. Returned for
    /// completeness; this crate's revocation checkers consume only `ocsp`.
    pub ca_issuers: Vec<String>,
}

impl AiaUrls {
    /// True when the certificate advertised no usable HTTP AIA URLs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ocsp.is_empty() && self.ca_issuers.is_empty()
    }
}

/// Extract HTTP/HTTPS CRL Distribution Point URLs from a certificate.
///
/// Walks the `cRLDistributionPoints` extension and yields every URI in
/// the `DistributionPointName::FullName` of every `DistributionPoint`,
/// in document order, filtered to HTTP and HTTPS schemes only.
///
/// # DistributionPointName handling
///
/// - `FullName(GeneralNames)` — yields its `UniformResourceIdentifier`
///   members. Other GeneralName variants (`directoryName`, `dNSName`,
///   `iPAddress`, etc.) are silently ignored — they are not HTTP-fetchable.
/// - `NameRelativeToCRLIssuer(RelativeDistinguishedName)` — yields nothing.
///   Resolving an RDN-relative name requires knowledge of the cRLIssuer
///   field that is out of scope for v0.x of this helper. Documented as a
///   limitation.
/// - `None` (the DistributionPoint has no `distributionPoint` field) —
///   yields nothing. Per RFC 5280 §4.2.1.13 the URL set is then implicitly
///   formed from `cRLIssuer` or the cert's own issuer; resolving that into
///   a URL requires lookup logic outside the scope of v0.x.
///
/// # Returns
///
/// - `Ok(Vec<String>)` with one entry per surviving HTTP/HTTPS URI, in
///   document order. May be empty (extension absent, all URIs filtered,
///   or only RDN-relative names present).
/// - `Err(ExtractError::Der(_))` when the extension value is present but
///   does not parse as `CrlDistributionPoints`.
///
/// # Errors
///
/// Returns [`ExtractError::Der`] when the extension value fails DER
/// decoding.
pub fn extract_cdp_http_urls(cert: &Certificate) -> Result<Vec<String>, ExtractError> {
    let Some(extn_value) = find_extension_value(cert, &OID_CRL_DISTRIBUTION_POINTS) else {
        return Ok(Vec::new());
    };
    let cdps = CrlDistributionPoints::from_der(extn_value)?;

    let mut urls = Vec::new();
    for dp in &cdps.0 {
        let Some(name) = &dp.distribution_point else {
            continue; // No DPN ⇒ implicit-via-cRLIssuer/issuer; out of scope
        };
        match name {
            DistributionPointName::FullName(general_names) => {
                for gn in general_names {
                    push_if_http_uri(&mut urls, gn);
                }
            }
            // RDN-relative names cannot be resolved to a URL without
            // additional context (see doc above).
            DistributionPointName::NameRelativeToCRLIssuer(_) => {}
        }
    }
    Ok(urls)
}

/// Extract HTTP/HTTPS Authority Information Access URLs from a
/// certificate, partitioned into OCSP-responder and CA-issuer buckets.
///
/// Walks the `authorityInfoAccess` extension. Only `AccessDescription`
/// entries whose `accessMethod` is `id-ad-ocsp` (`1.3.6.1.5.5.7.48.1`)
/// or `id-ad-caIssuers` (`1.3.6.1.5.5.7.48.2`) are considered, and only
/// HTTP/HTTPS URI accessLocations are kept. Every other combination is
/// silently dropped.
///
/// # Returns
///
/// - `Ok(AiaUrls)` with `ocsp` and `ca_issuers` lists (either or both may
///   be empty).
/// - `Err(ExtractError::Der(_))` on malformed DER.
///
/// # Errors
///
/// Returns [`ExtractError::Der`] when the extension value fails DER
/// decoding.
pub fn extract_aia_http_urls(cert: &Certificate) -> Result<AiaUrls, ExtractError> {
    let Some(extn_value) = find_extension_value(cert, &OID_AUTHORITY_INFO_ACCESS) else {
        return Ok(AiaUrls::default());
    };
    let aia = AuthorityInfoAccessSyntax::from_der(extn_value)?;

    let mut out = AiaUrls::default();
    for ad in &aia.0 {
        let target = if ad.access_method == OID_AD_OCSP {
            &mut out.ocsp
        } else if ad.access_method == OID_AD_CA_ISSUERS {
            &mut out.ca_issuers
        } else {
            // Other accessMethods (e.g., id-ad-timestamping, id-ad-rep-source-cert)
            // are out of scope here. Future work can extend the bucket set.
            continue;
        };
        push_if_http_uri(target, &ad.access_location);
    }
    Ok(out)
}

/// Look up the value bytes of an extension by OID.
///
/// Returns `Some(extn_value)` for the first matching extension or `None`
/// if the cert has no extensions or none of them match.
///
/// RFC 5280 §4.2 forbids duplicate extensions in a single certificate. We
/// do not enforce that uniqueness here — `extract_*` operates on the
/// first match and ignores later duplicates. A cert lint is the right
/// place to reject duplicates.
fn find_extension_value<'a>(
    cert: &'a Certificate,
    oid: &der::asn1::ObjectIdentifier,
) -> Option<&'a [u8]> {
    cert.tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find(|e| &e.extn_id == oid)
        .map(|e| e.extn_value.as_bytes())
}

/// Push `gn` onto `out` iff it is a `UniformResourceIdentifier` whose
/// scheme is `http` or `https` (case-insensitive comparison on the scheme
/// per RFC 3986 §3.1).
fn push_if_http_uri(out: &mut Vec<String>, gn: &GeneralName) {
    if let GeneralName::UniformResourceIdentifier(uri) = gn {
        if is_http_uri(uri.as_str()) {
            out.push(uri.as_str().to_owned());
        }
    }
}

/// Returns `true` iff `s` begins with `http://` or `https://`,
/// case-insensitive on the scheme part. Path/query/fragment beyond that
/// are not validated here — the HTTP client implementation does that.
fn is_http_uri(s: &str) -> bool {
    // RFC 3986: scheme letters are ASCII, comparison is case-insensitive.
    let lower = s.as_bytes();
    let starts_with_ci = |prefix: &[u8]| {
        lower.len() >= prefix.len()
            && lower
                .iter()
                .zip(prefix.iter())
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
    };
    starts_with_ci(b"http://") || starts_with_ci(b"https://")
}

// Compile-time bridge so the unused-import lint doesn't fire if the
// `Ia5String` reference becomes purely documentary in a refactor.
#[allow(dead_code)]
const _: fn() = || {
    let _: fn(Ia5String) -> Ia5String = core::convert::identity;
};

#[cfg(test)]
mod tests {
    //! Unit tests for the URL extraction helpers.
    //!
    //! Independent oracle: each fixture's expected output is derived from
    //! `openssl x509 -text -noout` reading of the `tests/fixtures/*.der`
    //! files. Re-running `tests/fixtures/gen.sh` regenerates the certs;
    //! the *extension contents* the tests assert against are stable
    //! across runs (only serial / signature change).
    //!
    //! These tests do NOT verify the extraction code by re-encoding what
    //! it just decoded — that would be a self-oracle. The expected URL
    //! lists are hardcoded from the openssl text output of the inputs.
    use super::*;

    fn parse_cert(bytes: &[u8]) -> Certificate {
        Certificate::from_der(bytes).expect("fixture parses")
    }

    const FIXTURE_HTTP: &[u8] = include_bytes!("../tests/fixtures/cert-cdp-aia-http.der");
    const FIXTURE_MIXED: &[u8] = include_bytes!("../tests/fixtures/cert-cdp-aia-mixed-schemes.der");
    const FIXTURE_NONE: &[u8] = include_bytes!("../tests/fixtures/cert-no-extensions.der");

    // ----- CDP -----

    #[test]
    fn cdp_returns_empty_when_extension_absent() {
        let cert = parse_cert(FIXTURE_NONE);
        assert_eq!(extract_cdp_http_urls(&cert).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn cdp_extracts_single_http_uri() {
        // Oracle: openssl x509 -in cert-cdp-aia-http.der -text -noout shows
        //   X509v3 CRL Distribution Points:
        //       Full Name: URI:http://crl.example.com/test.crl
        let cert = parse_cert(FIXTURE_HTTP);
        let urls = extract_cdp_http_urls(&cert).unwrap();
        assert_eq!(urls, vec!["http://crl.example.com/test.crl".to_string()]);
    }

    #[test]
    fn cdp_filters_non_http_schemes() {
        // Oracle: openssl shows four DistributionPoints in this fixture:
        //   URI:http://crl.example.com/a.crl
        //   URI:https://crl.example.com/b.crl
        //   URI:ldap://ldap.example.com/c
        //   URI:ftp://ftp.example.com/d.crl
        // Only the first two should survive scheme-filtering.
        let cert = parse_cert(FIXTURE_MIXED);
        let urls = extract_cdp_http_urls(&cert).unwrap();
        assert_eq!(
            urls,
            vec![
                "http://crl.example.com/a.crl".to_string(),
                "https://crl.example.com/b.crl".to_string(),
            ]
        );
    }

    #[test]
    fn cdp_name_relative_to_crl_issuer_yields_empty() {
        // openssl's -addext CLI cannot easily emit the
        // DistributionPointName::NameRelativeToCRLIssuer variant. Build a
        // CrlDistributionPoints DER blob programmatically and overwrite a
        // known-good fixture's CDP extension value with it. The function
        // under test reads cert.tbs_certificate.extensions, so writing the
        // tweaked extension into the parsed structure is enough.
        //
        // Independent oracle: hand-derived from RFC 5280 §4.2.1.13 ASN.1.
        // We assemble exactly one DistributionPoint with a single
        // RelativeDistinguishedName containing CN=ignored.
        use der::{asn1::SetOfVec, Encode};
        use x509_cert::{
            attr::AttributeTypeAndValue, ext::pkix::crl::dp::DistributionPoint,
            name::RelativeDistinguishedName,
        };

        let cn_oid = der::asn1::ObjectIdentifier::new_unwrap("2.5.4.3"); // id-at-commonName
        let cn_value = der::asn1::PrintableString::new("ignored").unwrap();
        let ava = AttributeTypeAndValue {
            oid: cn_oid,
            value: der::Any::encode_from(&cn_value).unwrap(),
        };
        let mut set = SetOfVec::<AttributeTypeAndValue>::new();
        set.insert(ava).unwrap();
        let rdn = RelativeDistinguishedName(set);

        let dp = DistributionPoint {
            distribution_point: Some(DistributionPointName::NameRelativeToCRLIssuer(rdn)),
            reasons: None,
            crl_issuer: None,
        };
        let cdps = CrlDistributionPoints(vec![dp]);
        let cdps_der = cdps.to_der().expect("encode cdps");

        let mut cert = parse_cert(FIXTURE_HTTP);
        let exts = cert.tbs_certificate.extensions.as_mut().unwrap();
        let cdp_ext = exts
            .iter_mut()
            .find(|e| e.extn_id == OID_CRL_DISTRIBUTION_POINTS)
            .expect("fixture has CDP");
        cdp_ext.extn_value = der::asn1::OctetString::new(cdps_der).unwrap();

        // Sanity: the extension value still re-decodes as
        // CrlDistributionPoints (so the test is exercising the
        // NameRelativeToCRLIssuer branch, not a parse failure).
        let reparsed = CrlDistributionPoints::from_der(cdp_ext.extn_value.as_bytes())
            .expect("synthesised CDP must round-trip");
        assert!(
            matches!(
                reparsed.0[0].distribution_point,
                Some(DistributionPointName::NameRelativeToCRLIssuer(_))
            ),
            "test synthesis must produce the variant under test"
        );

        let urls = extract_cdp_http_urls(&cert).unwrap();
        assert_eq!(
            urls,
            Vec::<String>::new(),
            "NameRelativeToCRLIssuer is not HTTP-resolvable; helper must yield empty"
        );
    }

    #[test]
    fn cdp_returns_err_on_malformed_der() {
        // Build a Certificate by tweaking a known-good one to include a
        // malformed CDP extension value. We cannot easily synthesise a
        // Certificate from scratch with x509-cert, so reach into the
        // parsed structure and overwrite the extension bytes.
        use der::Encode;

        let mut cert = parse_cert(FIXTURE_HTTP);
        let exts = cert.tbs_certificate.extensions.as_mut().unwrap();
        let cdp = exts
            .iter_mut()
            .find(|e| e.extn_id == OID_CRL_DISTRIBUTION_POINTS)
            .expect("fixture has CDP");
        // Overwrite with bytes that are not valid CrlDistributionPoints.
        // 0x30 0x01 0xFF is "SEQUENCE of length 1 containing one byte 0xFF",
        // which cannot decode as a SEQUENCE OF DistributionPoint.
        cdp.extn_value = der::asn1::OctetString::new(&[0x30, 0x01, 0xff][..]).unwrap();

        // Round-trip through DER so the parsed structure matches what
        // extract_cdp_http_urls would receive. We don't actually need to
        // re-encode here because extract_cdp_http_urls reads the parsed
        // extension's extn_value directly.
        let _ = cert.to_der().expect("re-encode for sanity");

        let err = extract_cdp_http_urls(&cert).unwrap_err();
        match err {
            ExtractError::Der(_) => {}
        }
    }

    // ----- AIA -----

    #[test]
    fn aia_returns_empty_when_extension_absent() {
        let cert = parse_cert(FIXTURE_NONE);
        let aia = extract_aia_http_urls(&cert).unwrap();
        assert!(aia.is_empty());
        assert_eq!(aia, AiaUrls::default());
    }

    #[test]
    fn aia_extracts_ocsp_and_ca_issuers() {
        // Oracle: openssl shows
        //   Authority Information Access:
        //       OCSP - URI:http://ocsp.example.com/
        //       CA Issuers - URI:http://ca.example.com/ca.cer
        let cert = parse_cert(FIXTURE_HTTP);
        let aia = extract_aia_http_urls(&cert).unwrap();
        assert_eq!(aia.ocsp, vec!["http://ocsp.example.com/".to_string()]);
        assert_eq!(
            aia.ca_issuers,
            vec!["http://ca.example.com/ca.cer".to_string()]
        );
    }

    #[test]
    fn aia_filters_ldap_ocsp_keeps_https() {
        // Oracle: openssl shows
        //   OCSP - URI:https://ocsp.example.com/
        //   OCSP - URI:ldap://ocsp-ldap.example.com/
        //   CA Issuers - URI:http://ca.example.com/ca.cer
        // Only HTTPS for OCSP should survive; LDAP filtered.
        let cert = parse_cert(FIXTURE_MIXED);
        let aia = extract_aia_http_urls(&cert).unwrap();
        assert_eq!(aia.ocsp, vec!["https://ocsp.example.com/".to_string()]);
        assert_eq!(
            aia.ca_issuers,
            vec!["http://ca.example.com/ca.cer".to_string()]
        );
    }

    #[test]
    fn aia_returns_err_on_malformed_der() {
        let mut cert = parse_cert(FIXTURE_HTTP);
        let exts = cert.tbs_certificate.extensions.as_mut().unwrap();
        let aia_ext = exts
            .iter_mut()
            .find(|e| e.extn_id == OID_AUTHORITY_INFO_ACCESS)
            .expect("fixture has AIA");
        aia_ext.extn_value = der::asn1::OctetString::new(&[0x30, 0x01, 0xff][..]).unwrap();

        let err = extract_aia_http_urls(&cert).unwrap_err();
        match err {
            ExtractError::Der(_) => {}
        }
    }

    // ----- Scheme filter -----

    #[test]
    fn http_uri_predicate_is_case_insensitive_on_scheme() {
        assert!(is_http_uri("http://x"));
        assert!(is_http_uri("https://x"));
        assert!(is_http_uri("HTTP://x"));
        assert!(is_http_uri("Https://x"));
        assert!(!is_http_uri("ldap://x"));
        assert!(!is_http_uri("ftp://x"));
        assert!(!is_http_uri("file:///x"));
        assert!(!is_http_uri("xhttp://x")); // prefix, not scheme — must reject
        assert!(!is_http_uri("")); // empty
        assert!(!is_http_uri("http")); // no separator
    }
}
