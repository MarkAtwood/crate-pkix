//! SSRF policy of `AsyncHttpFetcher`, mirroring `review_ssrf.rs`.
//!
//! The async fetcher must refuse the same destinations the sync one does, for
//! the same reason: `caIssuers` URIs come from the *unvalidated* certificate
//! being verified, so any peer that can present a certificate chooses the URL
//! this process fetches. A loopback or RFC 1918 or link-local target — the
//! last covering `169.254.169.254`, cloud instance metadata — turns chain
//! building into a request-forgery primitive against the host's own network.
//!
//! These tests exist because a second implementation of a security policy is
//! where the policy quietly diverges. Shipping an async fetcher that was
//! merely *documented* to have the same policy would be worth very little.
//!
//! Offline: every server is a `std::net::TcpListener` on `127.0.0.1`, which is
//! also exactly the destination the policy must refuse.

#![cfg(feature = "client-reqwest-async")]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use pkix_aia::AiaError;
use pkix_aia_http::{AsyncAiaFetcher, AsyncHttpFetcher};

/// Spawns a one-shot HTTP/1.1 server answering `response`. Returns its port
/// and a counter of accepted connections.
///
/// The counter is the substantive assertion in the refusal tests: it proves
/// the policy refused *before connecting*, rather than fetching and then
/// discarding the result.
fn serve_once(response: Vec<u8>) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("local addr").port();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            counter.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(&response);
        }
    });
    (port, hits)
}

fn ok_body(body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

/// The default fetcher refuses a loopback target, and does not connect.
#[tokio::test]
async fn the_default_fetcher_refuses_a_loopback_target() {
    let (port, hits) = serve_once(ok_body(b"internal"));
    let fetcher = AsyncHttpFetcher::new().expect("client builds");

    let result = fetcher
        .fetch(&format!("http://127.0.0.1:{port}/ca.crt"))
        .await;

    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "the policy must refuse before connecting; got {result:?}"
    );
    assert!(
        matches!(result, Err(AiaError::DestinationNotAllowed(_))),
        "expected DestinationNotAllowed, got {result:?}"
    );
}

/// A name that resolves to loopback is refused too.
///
/// This is the case that makes resolution-time filtering necessary rather
/// than merely tidy: checking the host name first would pass `localhost`
/// through, and checking it *and then* connecting leaves a DNS-rebinding
/// window where the name resolves publicly at check time and internally at
/// connect time.
#[tokio::test]
async fn a_name_resolving_to_loopback_is_refused() {
    let (port, hits) = serve_once(ok_body(b"internal"));
    let fetcher = AsyncHttpFetcher::new().expect("client builds");

    let result = fetcher
        .fetch(&format!("http://localhost:{port}/ca.crt"))
        .await;

    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "a name resolving to loopback must be refused before connecting; got {result:?}"
    );
    assert!(
        matches!(result, Err(AiaError::DestinationNotAllowed(_))),
        "expected DestinationNotAllowed, got {result:?}"
    );
}

/// Link-local is refused, which covers cloud instance metadata at
/// `169.254.169.254` — the destination that makes AIA fetching interesting to
/// an attacker in the first place.
#[tokio::test]
async fn link_local_metadata_addresses_are_refused() {
    let fetcher = AsyncHttpFetcher::new().expect("client builds");
    let result = fetcher
        .fetch("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
        .await;
    assert!(
        matches!(result, Err(AiaError::DestinationNotAllowed(_))),
        "cloud metadata must be refused, got {result:?}"
    );
}

/// Private ranges are refused.
#[tokio::test]
async fn private_ranges_are_refused() {
    let fetcher = AsyncHttpFetcher::new().expect("client builds");
    for host in ["10.0.0.1", "172.16.0.1", "192.168.1.1"] {
        let result = fetcher.fetch(&format!("http://{host}/ca.crt")).await;
        assert!(
            matches!(result, Err(AiaError::DestinationNotAllowed(_))),
            "{host} must be refused, got {result:?}"
        );
    }
}

/// The opt-in escape hatch works, and is the only way to reach an internal
/// endpoint.
#[tokio::test]
async fn allow_private_destinations_is_the_opt_in() {
    let (port, hits) = serve_once(ok_body(b"internal"));
    let fetcher = AsyncHttpFetcher::allow_private_destinations().expect("client builds");

    let result = fetcher
        .fetch(&format!("http://127.0.0.1:{port}/ca.crt"))
        .await;

    assert_eq!(result.as_deref(), Ok(&b"internal"[..]));
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

/// Redirects are not followed.
///
/// RFC 5280 §4.2.2.1 names a URI to fetch, not a redirect chain to walk.
/// Following one would let the certificate's author point the fetch at an
/// internal address *after* the destination policy had approved the original
/// target, which would defeat every test above.
#[tokio::test]
async fn redirects_are_not_followed() {
    let (internal_port, internal_hits) = serve_once(ok_body(b"internal"));
    let redirect = format!(
        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{internal_port}/ca.crt\r\n\
         Content-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    let (redirect_port, redirect_hits) = serve_once(redirect);

    // The redirecting server is itself on loopback, so reach it through the
    // permissive fetcher; the point under test is the redirect, not the
    // policy.
    let fetcher = AsyncHttpFetcher::allow_private_destinations().expect("client builds");
    let result = fetcher
        .fetch(&format!("http://127.0.0.1:{redirect_port}/ca.crt"))
        .await;

    assert_eq!(
        redirect_hits.load(Ordering::SeqCst),
        1,
        "the 302 was fetched"
    );
    assert_eq!(
        internal_hits.load(Ordering::SeqCst),
        0,
        "the redirect target must not be fetched; got {result:?}"
    );
    assert_eq!(result, Err(AiaError::HttpStatus(302)));
}

/// A non-HTTP scheme is reported as unsupported rather than attempted, so the
/// chain-build layer can try another AIA entry.
#[tokio::test]
async fn non_http_schemes_are_unsupported() {
    let fetcher = AsyncHttpFetcher::new().expect("client builds");
    for uri in [
        "ldap://ca.example/cn=ca",
        "file:///etc/passwd",
        "ftp://ca.example/ca.crt",
    ] {
        assert_eq!(
            fetcher.fetch(uri).await,
            Err(AiaError::UriUnsupported(uri.to_owned())),
            "{uri} should be unsupported"
        );
    }
}

/// The response-size cap is enforced, and reports both the limit and what was
/// seen so a caller can tell a misconfigured cap from a hostile endpoint.
#[tokio::test]
async fn oversized_responses_are_refused() {
    let (port, _) = serve_once(ok_body(&vec![0x41; 4096]));
    let fetcher = AsyncHttpFetcher::allow_private_destinations()
        .expect("client builds")
        .with_max_response_size(1024);

    let result = fetcher
        .fetch(&format!("http://127.0.0.1:{port}/ca.crt"))
        .await;
    assert!(
        matches!(result, Err(AiaError::ResponseTooLarge { limit: 1024, .. })),
        "expected ResponseTooLarge with limit 1024, got {result:?}"
    );
}

/// A body exactly at the cap is accepted. Without this, an off-by-one in the
/// cap check would pass the oversized test above while rejecting valid
/// certificates.
#[tokio::test]
async fn a_response_exactly_at_the_cap_is_accepted() {
    let (port, _) = serve_once(ok_body(&vec![0x41; 1024]));
    let fetcher = AsyncHttpFetcher::allow_private_destinations()
        .expect("client builds")
        .with_max_response_size(1024);

    let result = fetcher
        .fetch(&format!("http://127.0.0.1:{port}/ca.crt"))
        .await;
    assert_eq!(result.map(|b| b.len()), Ok(1024));
}

/// `batch_fetch` runs concurrently rather than sequentially.
///
/// Three one-shot servers each sleep before answering. Run in sequence the
/// total would be about three times one delay; concurrently it is about one.
/// The threshold is loose enough not to be flaky on a loaded machine while
/// still failing a sequential implementation.
#[tokio::test]
async fn batch_fetch_runs_concurrently() {
    use std::time::{Duration, Instant};

    /// A server that waits before answering, so sequencing is observable.
    fn serve_slow(delay: Duration, body: &'static [u8]) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().expect("local addr").port();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                thread::sleep(delay);
                let _ = stream.write_all(&ok_body(body));
            }
        });
        port
    }

    let delay = Duration::from_millis(300);
    let ports: Vec<u16> = (0..3).map(|_| serve_slow(delay, b"cert")).collect();
    let uris: Vec<String> = ports
        .iter()
        .map(|p| format!("http://127.0.0.1:{p}/ca.crt"))
        .collect();
    let refs: Vec<&str> = uris.iter().map(String::as_str).collect();

    let fetcher = AsyncHttpFetcher::allow_private_destinations().expect("client builds");
    let started = Instant::now();
    let results = fetcher.batch_fetch(&refs).await;
    let elapsed = started.elapsed();

    assert_eq!(results.len(), 3, "batch_fetch must be index-aligned");
    for result in &results {
        assert_eq!(result.as_deref(), Ok(&b"cert"[..]));
    }
    assert!(
        elapsed < delay * 2,
        "three {delay:?} fetches took {elapsed:?}; a concurrent batch should \
         finish in roughly one delay, so this looks sequential"
    );
}
