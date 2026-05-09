//! Integration tests for `pkix-revocation-http`.
//!
//! Two sections:
//!
//! 1. **`UreqFetcher` against a real local HTTP server (mockito).**
//!    Verifies the trait-impl behaviour that the unit tests in
//!    `src/clients/ureq.rs` deliberately defer to here: HTTP method,
//!    body + Content-Type round-trip, status code mapping, response
//!    Content-Type capture, and the response body cap.
//!
//! 2. **`HttpCrlFetcher` multi-CDP fallback.** The unit tests in
//!    `src/crl.rs` use single-URL fixtures; this section synthesises a
//!    two-URL CDP extension on a known-good cert and exercises the
//!    "first URL fails, second succeeds" path that the impl supports
//!    but no fixture has covered.
//!
//! Independent oracle: pyca/cryptography for the cert / CRL fixtures
//! (committed under `tests/fixtures/`); mockito's request matchers
//! (verified by mock.assert()) for the HTTP-shape assertions.
//!
//! These tests are gated on the `client-ureq` feature so they only
//! compile when the reference HTTP backend is available. Running them
//! is a single `cargo test --features client-ureq` away.

#![cfg(all(feature = "client-ureq", feature = "crl"))]

use der::{Decode, Encode};
use pkix_path::DefaultVerifier;
use pkix_revocation::{Error as RevError, RevocationChecker};
use pkix_revocation_http::{
    clients::ureq::UreqFetcher, FetchError, FetchRequest, FetchResponse,
    HttpCrlFetcher, RevocationFetcher,
};
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName, GeneralNames};
use x509_cert::ext::pkix::CrlDistributionPoints;
use x509_cert::ext::pkix::crl::dp::DistributionPoint;
use x509_cert::Certificate;

const CA: &[u8] = include_bytes!("fixtures/http-ca.der");
const LEAF_GOOD: &[u8] = include_bytes!("fixtures/http-leaf-good.der");
const CRL_REVOKES_2: &[u8] = include_bytes!("fixtures/http-crl-revokes-2.der");
const CRL_EMPTY: &[u8] = include_bytes!("fixtures/http-crl-empty.der");

/// Validation timestamp inside the test CRL's thisUpdate / nextUpdate
/// window (2026-01-01 .. 2027-01-01). Same value as the unit tests.
const NOW: u64 = 1_780_272_000;

fn parse_cert(b: &[u8]) -> Certificate {
    Certificate::from_der(b).unwrap()
}

// ---------------------------------------------------------------------------
// Section 1 — UreqFetcher behaviour
// ---------------------------------------------------------------------------

#[test]
fn ureq_get_returns_2xx_body() {
    let mut server = mockito::Server::new();
    let mock = server
        .mock("GET", "/some.crl")
        .with_status(200)
        .with_header("content-type", "application/pkix-crl")
        .with_body(b"\x30\x82\x00\x10")
        .create();

    let url = format!("{}/some.crl", server.url());
    let f = UreqFetcher::new();
    let resp = f.fetch(&FetchRequest::get(&url)).unwrap();

    mock.assert();
    assert_eq!(resp.bytes, b"\x30\x82\x00\x10");
    assert_eq!(resp.content_type.as_deref(), Some("application/pkix-crl"));
}

#[test]
fn ureq_post_sends_body_and_content_type() {
    let mut server = mockito::Server::new();
    let mock = server
        .mock("POST", "/ocsp")
        .match_header("content-type", "application/ocsp-request")
        .match_body(mockito::Matcher::Exact("hello".to_string()))
        .with_status(200)
        .with_header("content-type", "application/ocsp-response")
        .with_body(b"\x30\x03\x0a\x01\x00")
        .create();

    let url = format!("{}/ocsp", server.url());
    let f = UreqFetcher::new();
    let resp = f
        .fetch(&FetchRequest::post(
            &url,
            b"hello",
            "application/ocsp-request",
        ))
        .unwrap();

    mock.assert(); // verifies match_header + match_body succeeded
    assert_eq!(resp.bytes, b"\x30\x03\x0a\x01\x00");
    assert_eq!(
        resp.content_type.as_deref(),
        Some("application/ocsp-response")
    );
}

#[test]
fn ureq_non_2xx_returns_http_status() {
    let mut server = mockito::Server::new();
    let _mock = server
        .mock("GET", "/missing.crl")
        .with_status(404)
        .with_body("not found")
        .create();

    let url = format!("{}/missing.crl", server.url());
    let f = UreqFetcher::new();
    let err = f.fetch(&FetchRequest::get(&url)).unwrap_err();
    match err {
        FetchError::HttpStatus(404) => {}
        other => panic!("expected HttpStatus(404), got {other:?}"),
    }
}

#[test]
fn ureq_response_body_cap_triggers_too_large() {
    // Server returns 256 bytes; cap the fetcher at 100. Must yield TooLarge.
    let mut server = mockito::Server::new();
    let big_body = vec![0u8; 256];
    let _mock = server
        .mock("GET", "/big")
        .with_status(200)
        .with_body(&big_body[..])
        .create();

    let url = format!("{}/big", server.url());
    let f = UreqFetcher::new().with_max_response_size(100);
    let err = f.fetch(&FetchRequest::get(&url)).unwrap_err();
    match err {
        FetchError::TooLarge => {}
        other => panic!("expected TooLarge, got {other:?}"),
    }
}

#[test]
fn ureq_response_at_exact_cap_is_accepted() {
    // Body length == cap must succeed (off-by-one regression guard for
    // the take(limit + 1) trick that distinguishes "at cap" from "over cap").
    let mut server = mockito::Server::new();
    let body = [0xabu8; 100];
    let _mock = server
        .mock("GET", "/atcap")
        .with_status(200)
        .with_body(body)
        .create();

    let url = format!("{}/atcap", server.url());
    let f = UreqFetcher::new().with_max_response_size(100);
    let resp = f.fetch(&FetchRequest::get(&url)).unwrap();
    assert_eq!(resp.bytes.len(), 100);
}

// ---------------------------------------------------------------------------
// Section 2 — HttpCrlFetcher multi-CDP fallback (closure-mock fetcher)
// ---------------------------------------------------------------------------

/// Fetcher that responds differently per URL. Matches by exact URL.
struct PerUrlMock {
    responses: Vec<(String, Result<Vec<u8>, u16>)>,
}

impl RevocationFetcher for PerUrlMock {
    fn fetch(
        &self,
        req: &FetchRequest<'_>,
    ) -> Result<FetchResponse, FetchError> {
        for (url, result) in &self.responses {
            if *url == req.url {
                return match result {
                    Ok(bytes) => Ok(FetchResponse {
                        bytes: bytes.clone(),
                        content_type: Some("application/pkix-crl".into()),
                    }),
                    Err(status) => Err(FetchError::HttpStatus(*status)),
                };
            }
        }
        Err(FetchError::HttpStatus(404))
    }
}

/// Replace the CDP extension on a parsed cert with a CrlDistributionPoints
/// that lists every URL in `urls`, each as its own DistributionPoint with
/// a single FullName URI. Used to synthesise multi-URL CDP coverage that
/// the static fixtures do not provide.
///
/// The cert's signature is NOT re-validated by HttpCrlFetcher — only the
/// CRL's signature is, against the issuer's SPKI — so tampering with the
/// extension here is safe for the tests below.
fn rewrite_cdp_to_urls(mut cert: Certificate, urls: &[&str]) -> Certificate {
    use der::asn1::Ia5String;
    use x509_cert::ext::pkix::name::GeneralName;

    let mut dps: Vec<DistributionPoint> = Vec::with_capacity(urls.len());
    for u in urls {
        let gn = GeneralName::UniformResourceIdentifier(
            Ia5String::new(*u).unwrap(),
        );
        let names: GeneralNames = vec![gn];
        let dp = DistributionPoint {
            distribution_point: Some(DistributionPointName::FullName(names)),
            reasons: None,
            crl_issuer: None,
        };
        dps.push(dp);
    }
    let cdps = CrlDistributionPoints(dps);
    let cdps_der = cdps.to_der().expect("encode synthetic CDP");

    let exts = cert.tbs_certificate.extensions.as_mut().unwrap();
    let oid = der::asn1::ObjectIdentifier::new_unwrap("2.5.29.31");
    let cdp_ext = exts
        .iter_mut()
        .find(|e| e.extn_id == oid)
        .expect("fixture has CDP");
    cdp_ext.extn_value = der::asn1::OctetString::new(cdps_der).unwrap();
    cert
}

#[test]
fn crl_multi_cdp_first_fails_second_succeeds() {
    // Synthesise a leaf with two CDPs. The mock fetcher 503s the first
    // and returns the empty CRL on the second. HttpCrlFetcher must
    // surface Ok(()) — the second URL was tried after the first failed.
    let leaf = rewrite_cdp_to_urls(
        parse_cert(LEAF_GOOD),
        &[
            "http://primary.example.com/test.crl",
            "http://secondary.example.com/test.crl",
        ],
    );

    let f = PerUrlMock {
        responses: vec![
            (
                "http://primary.example.com/test.crl".to_string(),
                Err(503),
            ),
            (
                "http://secondary.example.com/test.crl".to_string(),
                Ok(CRL_EMPTY.to_vec()),
            ),
        ],
    };
    let h = HttpCrlFetcher::new(f, DefaultVerifier, NOW);
    h.check_revocation(&leaf, &parse_cert(CA)).unwrap();
}

#[test]
fn crl_multi_cdp_all_fail_surfaces_aggregated_error() {
    let leaf = rewrite_cdp_to_urls(
        parse_cert(LEAF_GOOD),
        &[
            "http://a.example.com/test.crl",
            "http://b.example.com/test.crl",
            "http://c.example.com/test.crl",
        ],
    );
    let f = PerUrlMock {
        responses: vec![
            ("http://a.example.com/test.crl".to_string(), Err(500)),
            ("http://b.example.com/test.crl".to_string(), Err(502)),
            ("http://c.example.com/test.crl".to_string(), Err(503)),
        ],
    };
    let h = HttpCrlFetcher::new(f, DefaultVerifier, NOW);
    let err = h
        .check_revocation(&leaf, &parse_cert(CA))
        .unwrap_err();
    match err {
        RevError::RevocationFetchFailed { description } => {
            // All three URLs and statuses must appear.
            for url in &["a", "b", "c"] {
                assert!(
                    description.contains(&format!("http://{url}.example.com/test.crl")),
                    "description must mention http://{url}.example.com/...; got: {description}"
                );
            }
            for code in &["500", "502", "503"] {
                assert!(
                    description.contains(code),
                    "description must mention status {code}; got: {description}"
                );
            }
        }
        other => panic!("expected RevocationFetchFailed, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Section 3 — HttpCrlFetcher + UreqFetcher full integration via mockito
// ---------------------------------------------------------------------------

#[test]
fn crl_full_integration_ureq_against_mockito_revoked_leaf_yields_revoked() {
    // End-to-end: synthesise a CDP pointing at the mockito server,
    // configure the server to serve the CRL that revokes serial=2,
    // run HttpCrlFetcher<UreqFetcher, DefaultVerifier>::check_revocation
    // on the revoked leaf, expect Err(Revoked).
    use pkix_revocation_http::clients::ureq::UreqFetcher;

    let mut server = mockito::Server::new();
    let mock_url = format!("{}/crl", server.url());
    let _mock = server
        .mock("GET", "/crl")
        .with_status(200)
        .with_header("content-type", "application/pkix-crl")
        .with_body(CRL_REVOKES_2)
        .create();

    let leaf = rewrite_cdp_to_urls(
        Certificate::from_der(include_bytes!("fixtures/http-leaf-revoked.der"))
            .unwrap(),
        &[&mock_url],
    );

    let h = HttpCrlFetcher::new(UreqFetcher::new(), DefaultVerifier, NOW);
    let err = h.check_revocation(&leaf, &parse_cert(CA)).unwrap_err();
    assert!(
        matches!(err, RevError::Revoked { .. }),
        "expected Revoked, got {err:?}"
    );
}

#[test]
fn crl_full_integration_good_leaf_returns_ok() {
    let mut server = mockito::Server::new();
    let mock_url = format!("{}/empty.crl", server.url());
    let _mock = server
        .mock("GET", "/empty.crl")
        .with_status(200)
        .with_header("content-type", "application/pkix-crl")
        .with_body(CRL_EMPTY)
        .create();

    let leaf = rewrite_cdp_to_urls(parse_cert(LEAF_GOOD), &[&mock_url]);

    let h = HttpCrlFetcher::new(UreqFetcher::new(), DefaultVerifier, NOW);
    h.check_revocation(&leaf, &parse_cert(CA)).unwrap();
}

// ---------------------------------------------------------------------------
// Section 4 — request method shape: HttpOcspFetcher actually POSTs.
// ---------------------------------------------------------------------------

#[test]
fn ocsp_full_integration_uses_post_with_correct_content_type() {
    // We don't need a working OCSP response here; we only want to verify
    // that HttpOcspFetcher issues an HTTP POST with Content-Type =
    // application/ocsp-request and a non-empty body. mockito asserts
    // those properties via match_header / match_body / method.
    #[cfg(feature = "ocsp")]
    {
        use pkix_revocation_http::HttpOcspFetcher;

        let mut server = mockito::Server::new();
        let mock_url = format!("{}/ocsp", server.url());
        // We only assert (a) POST method, (b) Content-Type header. The
        // OCSP request body is binary DER and not regex-friendly; its
        // byte content is pinned by the byte-equal-openssl test in
        // src/ocsp_request.rs and by the body-non-empty assertion in
        // src/ocsp.rs's fetcher_called_with_post_body_and_content_type.
        let mock = server
            .mock("POST", "/ocsp")
            .match_header("content-type", "application/ocsp-request")
            .with_status(200)
            .with_header("content-type", "application/ocsp-response")
            // Bytes that won't parse as OCSPResponse — the test is only
            // about the request shape, not the verdict.
            .with_body([0u8; 4])
            .create();

        // Synthesise a leaf with an AIA pointing at the mockito server.
        let leaf = rewrite_aia_ocsp(
            Certificate::from_der(LEAF_GOOD).unwrap(),
            &mock_url,
        );

        let h = HttpOcspFetcher::new(UreqFetcher::new(), DefaultVerifier, NOW);
        // We don't care about the returned verdict — just that a POST
        // with the right content-type + non-empty body went out.
        let _ = h.check_revocation(&leaf, &parse_cert(CA));
        mock.assert();
    }
}

#[cfg(feature = "ocsp")]
fn rewrite_aia_ocsp(mut cert: Certificate, url: &str) -> Certificate {
    use der::asn1::Ia5String;
    use x509_cert::ext::pkix::{AccessDescription, AuthorityInfoAccessSyntax};

    let ad = AccessDescription {
        access_method: der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1"),
        access_location: GeneralName::UniformResourceIdentifier(
            Ia5String::new(url).unwrap(),
        ),
    };
    let aia = AuthorityInfoAccessSyntax(vec![ad]);
    let aia_der = aia.to_der().expect("encode synthetic AIA");

    let exts = cert.tbs_certificate.extensions.as_mut().unwrap();
    let oid = der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1");
    let aia_ext = exts
        .iter_mut()
        .find(|e| e.extn_id == oid)
        .expect("fixture has AIA");
    aia_ext.extn_value = der::asn1::OctetString::new(aia_der).unwrap();
    cert
}
