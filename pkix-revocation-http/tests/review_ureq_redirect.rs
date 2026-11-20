//! Review: the reference `UreqFetcher` used to follow HTTP redirects to any
//! host. A caller that vets the CDP/AIA URL before fetching (the crate docs
//! push host/scheme policy to the caller) cannot see the redirect target, so
//! `http://public-host/crl` → 302 → `http://127.0.0.1:<port>/internal` was
//! fetched. Now only same-origin redirects are followed. Local listeners only.
//!
//! Run: cargo test -p pkix-revocation-http --features client-ureq,crl --test review_ureq_redirect

#![cfg(feature = "client-ureq")]

use pkix_revocation_http::clients::ureq::UreqFetcher;
use pkix_revocation_http::{FetchRequest, RevocationFetcher};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
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
