//! Review: the reference `UreqFetcher` used to follow HTTP redirects to any
//! host. A caller that vets the CDP/AIA URL before fetching (the crate docs
//! push host/scheme policy to the caller) cannot see the redirect target, so
//! `http://public-host/crl` → 302 → `http://127.0.0.1:<port>/internal` was
//! fetched. Now only same-origin redirects are followed. Local listeners only.
//!
//! Run: cargo test -p pkix-revocation-http --features client-ureq,crl --test review_ureq_redirect

#![cfg(feature = "client-ureq")]

use pkix_revocation_http::clients::ureq::{UreqFetcher, MAX_REDIRECTS};
use pkix_revocation_http::{FetchError, FetchRequest, RevocationFetcher};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;

fn serve_once(listener: TcpListener, response: String) {
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let _ = s.write_all(response.as_bytes());
        }
    });
}

/// Read one complete HTTP request: headers, then as many body bytes as
/// `Content-Length` announces.
///
/// A single `read` is not enough and the shortfall is a race, not a
/// constant. A `POST` is written as headers and then body, so whether one
/// `read` returns both depends on how the two land in the socket buffer;
/// a test asserting on the body off one `read` passes most of the time and
/// fails when the segments arrive apart. Reading to the announced length
/// removes the timing from the question.
fn read_request(s: &mut impl Read) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let headers_end = find(&buf, b"\r\n\r\n");
        if let Some(end) = headers_end {
            let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
            let want = head
                .split("content-length:")
                .nth(1)
                .and_then(|rest| rest.split("\r\n").next())
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if buf.len() >= end + 4 + want {
                return buf;
            }
        }
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => return buf,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

/// Answer each connection with the next response in `responses`, sending
/// the raw bytes of every request back over the returned channel.
///
/// Every response built below carries `Connection: close`, so exactly one
/// request arrives per accepted connection and the sequence stays in step
/// with the redirect chain.
fn serve_sequence(listener: TcpListener, responses: Vec<String>) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for response in responses {
            match listener.accept() {
                Ok((mut s, _)) => {
                    let _ = tx.send(read_request(&mut s));
                    let _ = s.write_all(response.as_bytes());
                }
                Err(_) => return,
            }
        }
    });
    rx
}

/// Byte offset of the first occurrence of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// True iff `needle` appears anywhere in `haystack`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    find(haystack, needle).is_some()
}

fn redirect_to(status: u16, location: &str) -> String {
    format!(
        "HTTP/1.1 {status} Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\n\
         Connection: close\r\n\r\n"
    )
}

fn ok_with(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[test]
fn review_ureq_fetcher_does_not_follow_redirect_to_other_host() {
    let internal = TcpListener::bind("127.0.0.1:0").unwrap();
    let internal_port = internal.local_addr().unwrap().port();
    let hit = Arc::new(AtomicBool::new(false));
    {
        let hit = hit.clone();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = internal.accept() {
                hit.store(true, Ordering::SeqCst);
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let _ = s.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\ninternal-secret",
                );
            }
        });
    }
    let public = TcpListener::bind("127.0.0.1:0").unwrap();
    let public_port = public.local_addr().unwrap().port();
    serve_once(
        public,
        format!(
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{internal_port}/latest/meta-data\r\n\
             Content-Length: 0\r\nConnection: close\r\n\r\n"
        ),
    );

    let url = format!("http://127.0.0.1:{public_port}/ca.crl");
    let r = UreqFetcher::new().fetch(&FetchRequest::get(&url));
    let followed = hit.load(Ordering::SeqCst);
    assert!(
        !followed,
        "redirect target (different authority) was fetched; body = {:?}",
        r.map(|x| String::from_utf8_lossy(&x.bytes).into_owned())
    );
}

#[test]
fn ureq_fetcher_follows_same_origin_redirect() {
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = server.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let responses = [
            "HTTP/1.1 302 Found\r\nLocation: /moved.crl\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_owned(),
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nmoved".to_owned(),
        ];
        for response in responses {
            if let Ok((mut s, _)) = server.accept() {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let _ = s.write_all(response.as_bytes());
            }
        }
    });

    let url = format!("http://127.0.0.1:{port}/ca.crl");
    let r = UreqFetcher::new()
        .fetch(&FetchRequest::get(&url))
        .expect("same-origin redirect");
    assert_eq!(r.bytes, b"moved");
}

#[test]
fn ureq_fetcher_cross_origin_redirect_is_http_status_error() {
    let public = TcpListener::bind("127.0.0.1:0").unwrap();
    let public_port = public.local_addr().unwrap().port();
    serve_once(
        public,
        "HTTP/1.1 301 Moved\r\nLocation: http://localhost:1/x\r\nContent-Length: 0\r\n\
         Connection: close\r\n\r\n"
            .to_owned(),
    );
    let url = format!("http://127.0.0.1:{public_port}/ca.crl");
    let r = UreqFetcher::new().fetch(&FetchRequest::get(&url));
    assert!(
        matches!(r, Err(pkix_revocation_http::FetchError::HttpStatus(301))),
        "{r:?}"
    );
}

/// An OCSP `POST` follows only a method-preserving redirect.
///
/// RFC 9110 §15.4.3 and §15.4.4 record that user agents have always
/// rewritten a 301 or 302 `POST` into a `GET`, which is exactly why
/// §15.4.8 and §15.4.9 exist: 307 and 308 mean "same method, same body".
/// An OCSP query is a `POST` whose body is the DER `OCSPRequest`
/// (RFC 6960 §A.1), so following a 302 means either dropping that body or
/// re-sending it under a method the responder never agreed to. Neither
/// can answer the question asked, and the rewrite-to-`GET` variant
/// retrieves some unrelated resource and hands its bytes to the OCSP
/// parser.
///
/// Nothing exercised the method half of the rule: every redirect test was
/// a `GET`, for which the whole `followable` term is true regardless.
#[test]
fn ureq_post_does_not_follow_a_302() {
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = server.local_addr().unwrap().port();
    let seen = serve_sequence(
        server,
        vec![redirect_to(302, "/moved"), ok_with("elsewhere")],
    );

    let url = format!("http://127.0.0.1:{port}/ocsp");
    let body = b"\x30\x03\x0a\x01\x00";
    let r = UreqFetcher::new().fetch(&FetchRequest::post(&url, body, "application/ocsp-request"));
    assert!(
        matches!(r, Err(FetchError::HttpStatus(302))),
        "a 302 does not preserve the POST method, so it must surface as the \
         3xx status rather than being followed: {r:?}"
    );

    let first = seen.recv().expect("the first request reached the server");
    assert!(
        contains(&first, b"POST /ocsp "),
        "{:?}",
        String::from_utf8_lossy(&first)
    );
    assert!(
        seen.try_recv().is_err(),
        "nothing may be requested after the refused 302"
    );
}

/// The method-preserving counterpart: a `POST` does follow a 307, and
/// carries the same body to the new location.
#[test]
fn ureq_post_follows_a_307_with_the_body_intact() {
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = server.local_addr().unwrap().port();
    let seen = serve_sequence(
        server,
        vec![redirect_to(307, "/moved"), ok_with("ocsp-response")],
    );

    let url = format!("http://127.0.0.1:{port}/ocsp");
    let body = b"\x30\x03\x0a\x01\x00";
    let r = UreqFetcher::new()
        .fetch(&FetchRequest::post(&url, body, "application/ocsp-request"))
        .expect("a 307 preserves the method and must be followed");
    assert_eq!(r.bytes, b"ocsp-response");

    let _first = seen.recv().expect("first request");
    let second = seen.recv().expect("the redirect target was requested");
    assert!(
        contains(&second, b"POST /moved "),
        "{:?}",
        String::from_utf8_lossy(&second)
    );
    assert!(
        contains(&second, body),
        "the DER OCSP request body must be re-sent verbatim"
    );
}

/// A same-origin redirect written as an absolute URL is followed.
///
/// RFC 9110 §10.2.2 lets `Location` be any URI reference, and real CAs
/// send more than one form. The resolver has to tell an absolute URL from
/// an absolute path from the protocol-relative `//host/x` form, because
/// each resolves against the base differently — and every existing test
/// sent `/moved.crl`, so a resolver that handled absolute paths and
/// mangled absolute URLs looked correct. The failure direction is a
/// refused fetch, which reads to an operator as an unreachable
/// distribution point rather than as a bug here.
#[test]
fn ureq_follows_a_same_origin_redirect_written_as_an_absolute_url() {
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = server.local_addr().unwrap().port();
    let absolute = format!("http://127.0.0.1:{port}/moved.crl");
    let seen = serve_sequence(server, vec![redirect_to(302, &absolute), ok_with("moved")]);

    let url = format!("http://127.0.0.1:{port}/ca.crl");
    let r = UreqFetcher::new()
        .fetch(&FetchRequest::get(&url))
        .expect("an absolute same-origin Location must be followed");
    assert_eq!(r.bytes, b"moved");

    let _first = seen.recv().expect("first request");
    let second = seen.recv().expect("the redirect target was requested");
    assert!(
        contains(&second, b"GET /moved.crl "),
        "{:?}",
        String::from_utf8_lossy(&second)
    );
}

/// The walk is bounded at exactly [`MAX_REDIRECTS`] hops.
///
/// A responder redirecting in a cycle would otherwise hold one validation
/// open for as long as it cared to keep answering, and the per-request
/// timeout does not bound that: every hop is a fresh request with a fresh
/// timeout. The hop count is the only thing making one check finite.
///
/// Both sides of the boundary are asserted, because a chain far from the
/// limit distinguishes nothing. A two-hop chain succeeds whether the
/// comparison is `<` or `<=`, and whether the counter advances by one or
/// never moves at all — the last of which is an unbounded walk. So a
/// chain of exactly `MAX_REDIRECTS` hops must still deliver the body, and
/// one hop more must be refused with the 3xx status.
#[test]
fn ureq_follows_exactly_max_redirects_hops_and_no_more() {
    let hops = MAX_REDIRECTS as usize;

    // Exactly MAX_REDIRECTS redirects, then the body.
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = server.local_addr().unwrap().port();
    let mut responses: Vec<String> = (1..=hops)
        .map(|i| redirect_to(302, &format!("/r{i}")))
        .collect();
    responses.push(ok_with("arrived"));
    let seen = serve_sequence(server, responses);

    let url = format!("http://127.0.0.1:{port}/ca.crl");
    let r = UreqFetcher::new()
        .fetch(&FetchRequest::get(&url))
        .expect("a chain of exactly MAX_REDIRECTS hops must be followed");
    assert_eq!(r.bytes, b"arrived");
    for hop in 0..=hops {
        seen.recv()
            .unwrap_or_else(|_| panic!("hop {hop} of the chain was requested"));
    }

    // One hop more: refused, and the final target never requested.
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = server.local_addr().unwrap().port();
    let mut responses: Vec<String> = (1..=hops + 1)
        .map(|i| redirect_to(302, &format!("/r{i}")))
        .collect();
    responses.push(ok_with("too-far"));
    let seen = serve_sequence(server, responses);

    let url = format!("http://127.0.0.1:{port}/ca.crl");
    let r = UreqFetcher::new().fetch(&FetchRequest::get(&url));
    assert!(
        matches!(r, Err(FetchError::HttpStatus(302))),
        "hop {} exceeds MAX_REDIRECTS and must surface as the 3xx status: {r:?}",
        hops + 1
    );
    let mut requested = 0;
    while seen.try_recv().is_ok() {
        requested += 1;
    }
    assert_eq!(
        requested,
        hops + 1,
        "the initial request plus MAX_REDIRECTS follows, and nothing beyond"
    );
}
