//! The destination policy, end to end, with no server.
//!
//! §3.3 fetches from `mta-sts.` prepended to a recipient domain, so a sender
//! is made to contact a host chosen by whoever it sends mail to. These tests
//! exercise the real fetch path: the refusal happens inside the resolver the
//! HTTP client calls, before any connection, so no listener is needed.
//!
//! `mta-sts.localhost` resolves to loopback on a normal system, which is
//! exactly the address an attacker would want a sender steered at.

#![cfg(feature = "client-ureq")]

use pkix_mta_sts_http::{FetchError, FetcherConfig, PolicyFetcher};

/// A loopback policy host is refused, not contacted.
///
/// The test that matters for SSRF. If this returned `Transport` instead, the
/// request would have been attempted — and against `localhost` that is a
/// connection to the sender's own machine.
#[test]
fn a_loopback_policy_host_is_refused() {
    let fetcher = PolicyFetcher::new();
    match fetcher.fetch("localhost") {
        Err(FetchError::DestinationRefused(msg)) => {
            assert!(
                msg.contains("mta-sts.localhost"),
                "the refusal should name the host it refused: {msg}"
            );
            assert!(msg.contains("non-public"), "and why it refused: {msg}");
        }
        other => panic!("expected a destination refusal for a loopback policy host, got {other:?}"),
    }
}

/// With the guard off, the fetch is attempted instead of refused.
///
/// The complement, and the test that proves the refusal above came from the
/// guard rather than from the host simply being unreachable. Here the request
/// proceeds and fails as transport or TLS, which is a different error.
#[test]
fn with_the_guard_disabled_the_fetch_is_attempted() {
    let fetcher = PolicyFetcher::with_config(FetcherConfig {
        refuse_non_public_addresses: false,
        ..FetcherConfig::default()
    });
    let got = fetcher.fetch("localhost");
    assert!(
        !matches!(got, Err(FetchError::DestinationRefused(_))),
        "with the guard off nothing should be refused on address grounds; got {got:?}"
    );
    assert!(
        got.is_err(),
        "nothing is listening, so it should still fail: {got:?}"
    );
}

/// The guard is on by default.
///
/// Asserted because a default that silently flipped would disable the SSRF
/// protection for every caller that never looked at the config.
#[test]
fn the_guard_is_on_unless_a_caller_turns_it_off() {
    assert!(PolicyFetcher::new().config().refuse_non_public_addresses);
    assert!(
        PolicyFetcher::default()
            .config()
            .refuse_non_public_addresses
    );
}
