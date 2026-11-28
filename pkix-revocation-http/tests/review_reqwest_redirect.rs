//! Review: the reference `ReqwestFetcher` used reqwest's default redirect
//! policy (up to 10 redirects, any origin), so a vetted CDP/AIA URL could be
//! redirected to an internal host. Now only same-origin redirects are
//! followed. Two wiremock servers on 127.0.0.1 have different ports, hence
//! different origins. Local listeners only.
//!
//! Run: cargo test -p pkix-revocation-http --features client-reqwest-async --test review_reqwest_redirect

#![cfg(feature = "client-reqwest-async")]

use pkix_revocation_http::clients::reqwest::ReqwestFetcher;
use pkix_revocation_http::{AsyncRevocationFetcher, FetchError, FetchRequest};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn reqwest_fetcher_does_not_follow_cross_origin_redirect() {
    let internal = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"internal-secret".as_slice()))
        .expect(0)
        .mount(&internal)
        .await;
    let public = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ca.crl"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", format!("{}/latest/meta-data", internal.uri())),
        )
        .mount(&public)
        .await;

    let url = format!("{}/ca.crl", public.uri());
    let r = ReqwestFetcher::new().fetch(&FetchRequest::get(&url)).await;
    assert!(matches!(r, Err(FetchError::HttpStatus(302))), "{r:?}");
    internal.verify().await;
}

#[tokio::test]
async fn reqwest_fetcher_follows_same_origin_redirect() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ca.crl"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "/moved.crl"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/moved.crl"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"moved".as_slice()))
        .mount(&server)
        .await;

    let url = format!("{}/ca.crl", server.uri());
    let r = ReqwestFetcher::new()
        .fetch(&FetchRequest::get(&url))
        .await
        .expect("same-origin redirect");
    assert_eq!(r.bytes, b"moved");
}

#[test]
fn reqwest_fetcher_try_new_builds() {
    ReqwestFetcher::try_new().expect("default client builds");
}

/// The policy follows at most [`MAX_REDIRECTS`] hops, and the hop after
/// that is an error rather than a follow.
///
/// A responder redirecting in a cycle would otherwise hold a task open
/// for as long as it kept answering; the per-request timeout does not
/// bound it, because each hop is a fresh request with a fresh timeout.
/// Both sides of the boundary are needed. The existing tests are two hops
/// long, and a two-hop chain is followed whether the comparison against
/// the limit is strict or off by one in either direction — so a chain of
/// exactly `MAX_REDIRECTS` hops must still deliver the body, and one hop
/// more must not.
///
/// Exceeding the limit surfaces differently from a cross-origin refusal:
/// the policy calls `attempt.error(..)`, which reqwest reports as a
/// request error, so it arrives as [`FetchError::Transport`] rather than
/// as the 3xx status. That is the right shape — there is no single status
/// to report for a chain that never terminated.
#[tokio::test]
async fn reqwest_follows_exactly_max_redirects_hops_and_no_more() {
    use pkix_revocation_http::clients::reqwest::MAX_REDIRECTS;

    /// Mount `hops` chained redirects at `/r1`..`/r{hops}` plus a final
    /// body at `/end`, with `/ca.crl` entering the chain.
    async fn chain(hops: usize) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ca.crl"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/r1"))
            .mount(&server)
            .await;
        for i in 1..=hops {
            let next = if i == hops {
                "/end".to_string()
            } else {
                format!("/r{}", i + 1)
            };
            Mock::given(method("GET"))
                .and(path(format!("/r{i}")))
                .respond_with(ResponseTemplate::new(302).insert_header("location", next))
                .mount(&server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/end"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"arrived".as_slice()))
            .mount(&server)
            .await;
        server
    }

    // `/ca.crl` is the first hop, so MAX_REDIRECTS hops means
    // MAX_REDIRECTS - 1 further redirects before the body.
    let at_limit = chain(MAX_REDIRECTS - 1).await;
    let r = ReqwestFetcher::new()
        .fetch(&FetchRequest::get(&format!("{}/ca.crl", at_limit.uri())))
        .await
        .expect("a chain of exactly MAX_REDIRECTS hops must be followed");
    assert_eq!(r.bytes, b"arrived");

    let over_limit = chain(MAX_REDIRECTS).await;
    let r = ReqwestFetcher::new()
        .fetch(&FetchRequest::get(&format!("{}/ca.crl", over_limit.uri())))
        .await;
    assert!(
        matches!(r, Err(FetchError::Transport(_))),
        "one hop past MAX_REDIRECTS must be refused by the policy: {r:?}"
    );
}

/// `with_client` uses the caller's client, redirect policy included.
///
/// The rustdoc says so, and points the caller at
/// `same_origin_redirect_policy` to keep the origin rule if they want it.
/// Nothing observed it: the only field a test could read is the body cap,
/// which `with_client` sets to the same default as `new`, so a
/// `with_client` that discarded the client and rebuilt a default fetcher
/// was indistinguishable — and silently reinstated redirect-following for
/// a caller who had deliberately turned it off.
///
/// A client with `Policy::none()` is the discriminating case: the default
/// fetcher follows this same-origin redirect, so a fetcher that kept the
/// caller's client reports the 302 and one that replaced it returns the
/// redirect target's body.
#[tokio::test]
async fn with_client_keeps_the_callers_redirect_policy() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ca.crl"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "/moved.crl"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/moved.crl"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"followed".as_slice()))
        .mount(&server)
        .await;
    let url = format!("{}/ca.crl", server.uri());

    let no_redirects = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client builds");
    let r = ReqwestFetcher::with_client(no_redirects)
        .fetch(&FetchRequest::get(&url))
        .await;
    assert!(
        matches!(r, Err(FetchError::HttpStatus(302))),
        "with_client must keep Policy::none(), which does not follow the \
         redirect: {r:?}"
    );

    // Control: the default fetcher does follow it, so the assertion above
    // is about the policy and not about the server.
    let r = ReqwestFetcher::new()
        .fetch(&FetchRequest::get(&url))
        .await
        .expect("the default same-origin policy follows this redirect");
    assert_eq!(r.bytes, b"followed");
}
