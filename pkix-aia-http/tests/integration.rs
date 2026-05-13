//! Integration tests for `pkix-aia-http`.
//!
//! `HttpFetcher` against a real local HTTP server (mockito).
//! Verifies the trait-impl behaviour that the unit tests in
//! `src/lib.rs` deliberately defer to here: HTTP method, response
//! body capture, status code mapping, and the response-size cap.
//!
//! These tests are sync-only; they drive mockito's blocking server
//! the same way `pkix-revocation-http/tests/integration.rs` does.
//!
//! Independent oracle: mockito's request matchers (verified via
//! `mock.assert()`) for the HTTP-shape assertions; bytes echoed
//! verbatim from the mock body for the payload assertions.

use pkix_aia::{AiaError, AiaFetcher};
use pkix_aia_http::{HttpFetcher, DEFAULT_MAX_RESPONSE_SIZE};

// A small DER-shaped byte blob the mock returns. We do not assert
// X.509 validity — that is the caller's job — only that
// `HttpFetcher::fetch` round-trips the body verbatim.
const FAKE_DER: &[u8] = b"\x30\x82\x00\x10\x01\x02\x03\x04";

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

#[test]
fn fetch_returns_2xx_body_verbatim() {
    let mut server = mockito::Server::new();
    let mock = server
        .mock("GET", "/intermediate.crt")
        .with_status(200)
        .with_header("content-type", "application/pkix-cert")
        .with_body(FAKE_DER)
        .create();

    let url = format!("{}/intermediate.crt", server.url());
    let f = HttpFetcher::new();
    let bytes = f.fetch(&url).expect("2xx fetch must succeed");

    mock.assert();
    assert_eq!(bytes, FAKE_DER);
}

#[test]
fn fetch_returns_2xx_body_with_no_content_type_header() {
    // Some CA endpoints serve AIA bytes without a Content-Type
    // header. The fetcher returns the body verbatim; classification
    // is the caller's job.
    let mut server = mockito::Server::new();
    let mock = server
        .mock("GET", "/no-ct.crt")
        .with_status(200)
        .with_body(FAKE_DER)
        .create();

    let url = format!("{}/no-ct.crt", server.url());
    let f = HttpFetcher::new();
    let bytes = f.fetch(&url).unwrap();

    mock.assert();
    assert_eq!(bytes, FAKE_DER);
}

// ---------------------------------------------------------------------------
// Status code mapping
// ---------------------------------------------------------------------------

#[test]
fn fetch_404_maps_to_http_status() {
    let mut server = mockito::Server::new();
    let mock = server.mock("GET", "/missing.crt").with_status(404).create();

    let url = format!("{}/missing.crt", server.url());
    let f = HttpFetcher::new();
    let err = f.fetch(&url).unwrap_err();

    mock.assert();
    assert_eq!(err, AiaError::HttpStatus(404));
}

#[test]
fn fetch_500_maps_to_http_status() {
    let mut server = mockito::Server::new();
    let mock = server.mock("GET", "/broken.crt").with_status(500).create();

    let url = format!("{}/broken.crt", server.url());
    let f = HttpFetcher::new();
    let err = f.fetch(&url).unwrap_err();

    mock.assert();
    assert_eq!(err, AiaError::HttpStatus(500));
}

#[test]
fn fetch_503_maps_to_http_status() {
    // Service Unavailable is a common AIA-endpoint failure mode
    // (CA load balancer transient). Confirm it lands in the
    // distinguishable HttpStatus variant rather than a generic
    // IoFailure.
    let mut server = mockito::Server::new();
    let mock = server
        .mock("GET", "/overloaded.crt")
        .with_status(503)
        .create();

    let url = format!("{}/overloaded.crt", server.url());
    let f = HttpFetcher::new();
    let err = f.fetch(&url).unwrap_err();

    mock.assert();
    assert_eq!(err, AiaError::HttpStatus(503));
}

// ---------------------------------------------------------------------------
// Body cap
// ---------------------------------------------------------------------------

#[test]
fn fetch_rejects_oversized_body() {
    // Mock returns a 4 KiB body; we configure a 1 KiB cap. The
    // resulting error must carry the limit + the observed size.
    const CAP: usize = 1024;
    let mut server = mockito::Server::new();
    let oversized = vec![0u8; 4 * 1024];
    let mock = server
        .mock("GET", "/oversized.crt")
        .with_status(200)
        .with_body(oversized.clone())
        .create();

    let url = format!("{}/oversized.crt", server.url());
    let f = HttpFetcher::new().with_max_response_size(CAP);
    let err = f.fetch(&url).unwrap_err();

    mock.assert();
    match err {
        AiaError::ResponseTooLarge { limit, actual } => {
            assert_eq!(limit, CAP);
            assert!(
                actual > CAP,
                "actual ({actual}) must exceed cap ({CAP}) to fire the limit guard",
            );
        }
        other => panic!("expected ResponseTooLarge, got {other:?}"),
    }
}

#[test]
fn fetch_accepts_body_under_cap() {
    // Same setup as the oversized test but with a smaller body. The
    // fetch must succeed and return the body verbatim.
    let mut server = mockito::Server::new();
    let small = vec![0xAAu8; 512];
    let mock = server
        .mock("GET", "/small.crt")
        .with_status(200)
        .with_body(small.clone())
        .create();

    let url = format!("{}/small.crt", server.url());
    let f = HttpFetcher::new().with_max_response_size(1024);
    let bytes = f.fetch(&url).unwrap();

    mock.assert();
    assert_eq!(bytes, small);
}

// ---------------------------------------------------------------------------
// URI scheme handling
// ---------------------------------------------------------------------------

#[test]
fn fetch_rejects_ldap_scheme_before_any_network_io() {
    // No mock is registered: if HttpFetcher ever issued a request,
    // the URL would fail to resolve and we would get a transport
    // error, not UriUnsupported. The scheme check must short-circuit
    // synchronously.
    let f = HttpFetcher::new();
    let err = f.fetch("ldap://example.com/cn=ca").unwrap_err();
    match err {
        AiaError::UriUnsupported(uri) => assert_eq!(uri, "ldap://example.com/cn=ca"),
        other => panic!("expected UriUnsupported, got {other:?}"),
    }
}

#[test]
fn fetch_rejects_ftp_scheme_before_any_network_io() {
    let f = HttpFetcher::new();
    let err = f.fetch("ftp://example.com/ca.crt").unwrap_err();
    assert!(matches!(err, AiaError::UriUnsupported(_)));
}

#[test]
fn fetch_rejects_file_scheme_before_any_network_io() {
    let f = HttpFetcher::new();
    let err = f.fetch("file:///etc/ssl/ca.crt").unwrap_err();
    assert!(matches!(err, AiaError::UriUnsupported(_)));
}

// ---------------------------------------------------------------------------
// Defaults sanity
// ---------------------------------------------------------------------------

#[test]
fn default_max_response_size_is_one_mib() {
    assert_eq!(DEFAULT_MAX_RESPONSE_SIZE, 1024 * 1024);
}

// ---------------------------------------------------------------------------
// batch_fetch — exercise the trait's default impl through the type
// ---------------------------------------------------------------------------

#[test]
fn batch_fetch_preserves_per_uri_order_and_results() {
    let mut server = mockito::Server::new();
    let mock_a = server
        .mock("GET", "/a.crt")
        .with_status(200)
        .with_body(b"AAAA")
        .create();
    let mock_b = server.mock("GET", "/b.crt").with_status(404).create();
    let mock_c = server
        .mock("GET", "/c.crt")
        .with_status(200)
        .with_body(b"CCCC")
        .create();

    let url_a = format!("{}/a.crt", server.url());
    let url_b = format!("{}/b.crt", server.url());
    let url_c = format!("{}/c.crt", server.url());
    let uris = [url_a.as_str(), url_b.as_str(), url_c.as_str()];

    let f = HttpFetcher::new();
    let results = f.batch_fetch(&uris);

    mock_a.assert();
    mock_b.assert();
    mock_c.assert();

    assert_eq!(results.len(), 3);
    assert_eq!(results[0].as_ref().unwrap(), b"AAAA");
    assert_eq!(results[1], Err(AiaError::HttpStatus(404)));
    assert_eq!(results[2].as_ref().unwrap(), b"CCCC");
}
