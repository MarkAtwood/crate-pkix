//! The destination policy on the async backend.
//!
//! Parity with `destination_policy.rs`. Asserted separately because the two
//! backends use different resolvers — `ureq`'s `Resolver` and `reqwest`'s
//! `Resolve` — and a guard applied to only one of them would leave the async
//! path open while the sync path looked covered.

#![cfg(feature = "client-reqwest")]

use pkix_mta_sts_http::{AsyncPolicyFetcher, FetchError, FetcherConfig};

#[tokio::test]
async fn a_loopback_policy_host_is_refused() {
    let fetcher = AsyncPolicyFetcher::new();
    match fetcher.fetch("localhost").await {
        Err(FetchError::DestinationRefused(msg)) => {
            assert!(msg.contains("non-public"), "and why it refused: {msg}");
        }
        other => panic!("expected a destination refusal for a loopback policy host, got {other:?}"),
    }
}

#[tokio::test]
async fn with_the_guard_disabled_the_fetch_is_attempted() {
    let fetcher = AsyncPolicyFetcher::with_config(FetcherConfig {
        refuse_non_public_addresses: false,
        ..FetcherConfig::default()
    });
    let got = fetcher.fetch("localhost").await;
    assert!(
        !matches!(got, Err(FetchError::DestinationRefused(_))),
        "with the guard off nothing should be refused on address grounds; got {got:?}"
    );
    assert!(got.is_err(), "nothing is listening: {got:?}");
}

#[tokio::test]
async fn the_guard_is_on_by_default() {
    assert!(
        AsyncPolicyFetcher::new()
            .config()
            .refuse_non_public_addresses
    );
}
