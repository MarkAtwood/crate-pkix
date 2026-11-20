//! SSRF policy of `HttpFetcher` (RFC 5280 §4.2.2.1 caIssuers).
//!
//! caIssuers URIs come from the *unvalidated* certificate being verified
//! (`pkix-chain` extracts them before any signature on that cert has been
//! checked), so any peer that can present a certificate chooses the URL
//! this process GETs. The default fetcher must refuse loopback / RFC 1918
//! / link-local (169.254.169.254 cloud metadata) targets and must not
//! follow HTTP redirects.
//!
//! Offline: both servers are std `TcpListener`s on 127.0.0.1.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use pkix_aia::{AiaError, AiaFetcher};
use pkix_aia_http::HttpFetcher;

/// Spawn a one-shot HTTP/1.1 server answering `response` to the first
/// request. Returns (port, hit-counter).
fn serve_once(response: Vec<u8>) -> (u16, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    thread::spawn(move || {
        if let Ok((mut s, _)) = l.accept() {
            h.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let _ = s.write_all(&response);
        }
    });
    (port, hits)
}

fn ok_body(body: &[u8]) -> Vec<u8> {
    let mut r = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    r.extend_from_slice(body);
    r
}

/// The default `HttpFetcher` refuses a loopback target before connecting,
/// with `AiaError::DestinationNotAllowed`.
#[test]
fn review_default_fetcher_refuses_loopback_target() {
    let (port, hits) = serve_once(ok_body(b"internal-secret"));
    let r = HttpFetcher::new().fetch(&format!("http://127.0.0.1:{port}/admin"));
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "default fetcher connected to loopback target; result = {r:?}"
    );
    assert!(
        matches!(r, Err(AiaError::DestinationNotAllowed(_))),
        "{r:?}"
    );
}

/// A host name that resolves to loopback is refused too (the check runs
/// on resolved addresses, not on the URI text).
#[test]
fn review_default_fetcher_refuses_name_resolving_to_loopback() {
    let (port, hits) = serve_once(ok_body(b"internal-secret"));
    let r = HttpFetcher::new().fetch(&format!("http://localhost:{port}/admin"));
    assert_eq!(hits.load(Ordering::SeqCst), 0, "{r:?}");
    assert!(
        matches!(r, Err(AiaError::DestinationNotAllowed(_))),
        "{r:?}"
    );
}

/// The opt-in reaches internal targets (control for the tests above).
#[test]
fn review_allow_private_destinations_opt_in() {
    let (port, hits) = serve_once(ok_body(b"internal"));
    let r = HttpFetcher::new()
        .allow_private_destinations()
        .fetch(&format!("http://127.0.0.1:{port}/ca.crt"));
    assert_eq!(r.as_deref(), Ok(&b"internal"[..]));
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

/// Redirects are not followed (AIA objects are static; RFC 5280
/// §4.2.2.1 says the URI points at the object), so a public AIA host
/// cannot bounce the fetch to an internal address. Uses the private
/// opt-in so the redirect policy is tested independently of the
/// destination filter; the 3xx surfaces as `HttpStatus(302)`.
#[test]
fn review_default_fetcher_does_not_follow_redirects() {
    let (inner_port, inner_hits) = serve_once(ok_body(b"redirect-target"));
    let redirect = format!(
        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{inner_port}/internal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    let (outer_port, _) = serve_once(redirect);
    let r = HttpFetcher::new()
        .allow_private_destinations()
        .fetch(&format!("http://127.0.0.1:{outer_port}/ca.crt"));
    assert_eq!(
        inner_hits.load(Ordering::SeqCst),
        0,
        "redirect target was fetched; result = {:?}",
        r.as_ref().map(|b| String::from_utf8_lossy(b).into_owned())
    );
    assert_eq!(r, Err(AiaError::HttpStatus(302)));
}
