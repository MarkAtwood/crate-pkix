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
