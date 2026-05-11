//! Async integration tests for `pkix-revocation-http`.
//!
//! Mirror of `tests/integration.rs` but for the async trait family
//! (PKIX-a1yc.10). Three sections:
//!
//! 1. **`ReqwestFetcher` against a real local HTTP server (wiremock).**
//!    Verifies the trait-impl behaviour deferred from
//!    `src/clients/reqwest.rs` unit tests: HTTP method, body +
//!    Content-Type round-trip, status code mapping, response
//!    Content-Type capture, and the response body cap.
//!
//! 2. **`AsyncHttpCrlFetcher` multi-CDP fallback.** Mirrors section 2
//!    of the sync suite. Closure-mock fetcher, two-URL CDP, first 503
//!    second OK.
//!
//! 3. **`AsyncHttpCrlFetcher` + `ReqwestFetcher` full integration.**
//!    Mirrors section 3 of the sync suite: pyca-generated CRL fixture
//!    served from wiremock, revoked leaf verdict.
//!
//! Independent oracle: pyca/cryptography for the cert / CRL fixtures
//! (committed under `tests/fixtures/`); wiremock's request matchers
//! for the HTTP-shape assertions.
//!
//! These tests are gated on the `client-reqwest-async` feature so they
//! only compile when the async reference HTTP backend is available.
//! Tokio is dragged in by `client-reqwest-async` and the
//! `#[tokio::test]` macro drives each test.

#![cfg(all(feature = "client-reqwest-async", feature = "crl"))]

use async_trait::async_trait;
use der::{Decode, Encode};
use pkix_path::DefaultVerifier;
use pkix_revocation::Error as RevError;
use pkix_revocation_http::{
    clients::reqwest::ReqwestFetcher, AsyncHttpCrlFetcher, AsyncRevocationChecker,
    AsyncRevocationFetcher, FetchError, FetchRequest, FetchResponse,
};
use x509_cert::ext::pkix::crl::dp::DistributionPoint;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName, GeneralNames};
use x509_cert::ext::pkix::CrlDistributionPoints;
use x509_cert::Certificate;

const CA: &[u8] = include_bytes!("fixtures/http-ca.der");
const LEAF_GOOD: &[u8] = include_bytes!("fixtures/http-leaf-good.der");
const LEAF_REVOKED: &[u8] = include_bytes!("fixtures/http-leaf-revoked.der");
const CRL_REVOKES_2: &[u8] = include_bytes!("fixtures/http-crl-revokes-2.der");
const CRL_EMPTY: &[u8] = include_bytes!("fixtures/http-crl-empty.der");

/// Validation timestamp inside the test CRL's thisUpdate / nextUpdate
/// window. Same value as the sync suite.
const NOW: u64 = 1_780_272_000;

fn parse_cert(b: &[u8]) -> Certificate {
    Certificate::from_der(b).unwrap()
}

// ---------------------------------------------------------------------------
// Section 1 — ReqwestFetcher behaviour against wiremock
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reqwest_get_returns_2xx_body() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/some.crl"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/pkix-crl")
                .set_body_bytes(b"\x30\x82\x00\x10".as_slice()),
        )
        .expect(1)
        .mount(&server)
        .await;

    let url = format!("{}/some.crl", server.uri());
    let f = ReqwestFetcher::new();
    let resp = f.fetch(&FetchRequest::get(&url)).await.unwrap();

    assert_eq!(resp.bytes, b"\x30\x82\x00\x10");
    assert_eq!(resp.content_type.as_deref(), Some("application/pkix-crl"));
}

#[tokio::test]
async fn reqwest_post_sends_body_and_content_type() {
    use wiremock::matchers::{body_bytes, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/ocsp"))
        .and(header("content-type", "application/ocsp-request"))
        .and(body_bytes(b"hello".as_slice()))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/ocsp-response")
                .set_body_bytes(b"\x30\x03\x0a\x01\x00".as_slice()),
        )
        .expect(1)
        .mount(&server)
        .await;

    let url = format!("{}/ocsp", server.uri());
    let f = ReqwestFetcher::new();
    let resp = f
        .fetch(&FetchRequest::post(
            &url,
            b"hello",
            "application/ocsp-request",
        ))
        .await
        .unwrap();

    assert_eq!(resp.bytes, b"\x30\x03\x0a\x01\x00");
    assert_eq!(
        resp.content_type.as_deref(),
        Some("application/ocsp-response")
    );
}

#[tokio::test]
async fn reqwest_non_2xx_returns_http_status() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/missing.crl"))
        .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
        .mount(&server)
        .await;

    let url = format!("{}/missing.crl", server.uri());
    let f = ReqwestFetcher::new();
    let err = f.fetch(&FetchRequest::get(&url)).await.unwrap_err();
    match err {
        FetchError::HttpStatus(404) => {}
        other => panic!("expected HttpStatus(404), got {other:?}"),
    }
}

#[tokio::test]
async fn reqwest_response_body_cap_triggers_too_large() {
    // Server returns 256 bytes; cap the fetcher at 100. Must yield TooLarge.
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let big_body = vec![0u8; 256];
    Mock::given(method("GET"))
        .and(path("/big"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(big_body))
        .mount(&server)
        .await;

    let url = format!("{}/big", server.uri());
    let f = ReqwestFetcher::new().with_max_response_size(100);
    let err = f.fetch(&FetchRequest::get(&url)).await.unwrap_err();
    match err {
        FetchError::TooLarge => {}
        other => panic!("expected TooLarge, got {other:?}"),
    }
}

#[tokio::test]
async fn reqwest_response_at_exact_cap_is_accepted() {
    // Body length == cap must succeed. The reqwest streaming path uses
    // saturating-add chunk accounting; if it has an off-by-one,
    // this test catches it.
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let body = vec![0xabu8; 100];
    Mock::given(method("GET"))
        .and(path("/atcap"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;

    let url = format!("{}/atcap", server.uri());
    let f = ReqwestFetcher::new().with_max_response_size(100);
    let resp = f.fetch(&FetchRequest::get(&url)).await.unwrap();
    assert_eq!(resp.bytes.len(), 100);
}

// ---------------------------------------------------------------------------
// Section 2 — AsyncHttpCrlFetcher multi-CDP fallback (closure-mock fetcher)
// ---------------------------------------------------------------------------

/// Async per-URL mock fetcher. Direct port of the sync `PerUrlMock`.
struct PerUrlMock {
    responses: Vec<(String, Result<Vec<u8>, u16>)>,
}

#[async_trait]
impl AsyncRevocationFetcher for PerUrlMock {
    async fn fetch(&self, req: &FetchRequest<'_>) -> Result<FetchResponse, FetchError> {
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

/// Replace the CDP extension on a parsed cert. Direct port of the sync
/// helper — same DER manipulation.
fn rewrite_cdp_to_urls(mut cert: Certificate, urls: &[&str]) -> Certificate {
    use der::asn1::Ia5String;

    let mut dps: Vec<DistributionPoint> = Vec::with_capacity(urls.len());
    for u in urls {
        let gn = GeneralName::UniformResourceIdentifier(Ia5String::new(*u).unwrap());
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

#[tokio::test]
async fn async_crl_multi_cdp_first_fails_second_succeeds() {
    let leaf = rewrite_cdp_to_urls(
        parse_cert(LEAF_GOOD),
        &[
            "http://primary.example.com/test.crl",
            "http://secondary.example.com/test.crl",
        ],
    );

    let f = PerUrlMock {
        responses: vec![
            ("http://primary.example.com/test.crl".to_string(), Err(503)),
            (
                "http://secondary.example.com/test.crl".to_string(),
                Ok(CRL_EMPTY.to_vec()),
            ),
        ],
    };
    let h = AsyncHttpCrlFetcher::new(f, DefaultVerifier, NOW);
    h.check_revocation(&leaf, &parse_cert(CA)).await.unwrap();
}

#[tokio::test]
async fn async_crl_multi_cdp_all_fail_surfaces_aggregated_error() {
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
    let h = AsyncHttpCrlFetcher::new(f, DefaultVerifier, NOW);
    let err = h
        .check_revocation(&leaf, &parse_cert(CA))
        .await
        .unwrap_err();
    match err {
        RevError::RevocationFetchFailed { description } => {
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
// Section 3 — AsyncHttpCrlFetcher + ReqwestFetcher full integration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn async_crl_full_integration_reqwest_against_wiremock_revoked_leaf_yields_revoked() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/crl"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/pkix-crl")
                .set_body_bytes(CRL_REVOKES_2),
        )
        .mount(&server)
        .await;

    let mock_url = format!("{}/crl", server.uri());
    let leaf = rewrite_cdp_to_urls(parse_cert(LEAF_REVOKED), &[&mock_url]);

    let h = AsyncHttpCrlFetcher::new(ReqwestFetcher::new(), DefaultVerifier, NOW);
    let err = h
        .check_revocation(&leaf, &parse_cert(CA))
        .await
        .unwrap_err();
    assert!(
        matches!(err, RevError::Revoked { .. }),
        "expected Revoked, got {err:?}"
    );
}

#[tokio::test]
async fn async_crl_full_integration_good_leaf_returns_ok() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/empty.crl"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/pkix-crl")
                .set_body_bytes(CRL_EMPTY),
        )
        .mount(&server)
        .await;

    let mock_url = format!("{}/empty.crl", server.uri());
    let leaf = rewrite_cdp_to_urls(parse_cert(LEAF_GOOD), &[&mock_url]);

    let h = AsyncHttpCrlFetcher::new(ReqwestFetcher::new(), DefaultVerifier, NOW);
    h.check_revocation(&leaf, &parse_cert(CA)).await.unwrap();
}
