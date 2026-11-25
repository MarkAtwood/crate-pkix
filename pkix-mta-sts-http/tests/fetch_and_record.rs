//! `fetch_and_record` keeps §3.3's backoff fed.
//!
//! The helper exists because the bookkeeping after a fetch is easy to omit
//! and omitting it fails silently: the sender keeps retrying a failing policy
//! host on every delivery attempt, which is the cascading failure against
//! resource-constrained recipients that §3.3 asks senders to avoid. Nothing
//! looks broken from the sender's side, so these tests check the recording
//! rather than trusting it.

#![cfg(feature = "client-ureq")]

use pkix_mta_sts::{in_backoff, InMemoryPolicyStore, PolicyStore};
use pkix_mta_sts_http::{fetch_and_record, FetchError, PolicyFetcher};

const NOW: u64 = 1_700_000_000;
const BACKOFF: u64 = 300;

/// A failed fetch is recorded, so the next attempt is rate-limited.
///
/// `mta-sts.localhost` resolves to loopback and is refused by the destination
/// policy, which is a fetch failure like any other — §3.3's limit is on
/// attempts, not on a particular cause.
#[test]
fn a_failed_fetch_is_recorded_for_the_backoff() {
    let fetcher = PolicyFetcher::new();
    let store = InMemoryPolicyStore::new();

    assert!(
        !in_backoff(&store, "localhost", "abc123", NOW, BACKOFF),
        "nothing has failed yet"
    );

    let got = fetch_and_record(&fetcher, &store, "localhost", "abc123", NOW);
    assert!(
        matches!(got, Err(FetchError::DestinationRefused(_))),
        "expected the loopback policy host to be refused, got {got:?}"
    );

    assert_eq!(
        store.last_fetch_failure("localhost", "abc123"),
        Some(NOW),
        "the failure must be recorded, or the backoff never engages"
    );
    assert!(
        in_backoff(&store, "localhost", "abc123", NOW + 60, BACKOFF),
        "and the next attempt inside the window is now rate-limited"
    );
}

/// The failure is recorded against the id the fetch was for.
///
/// §3.3's limit is per version id, so recording it against the wrong key
/// would either rate-limit a policy that never failed or fail to rate-limit
/// the one that did.
#[test]
fn the_failure_is_recorded_against_the_fetched_id() {
    let fetcher = PolicyFetcher::new();
    let store = InMemoryPolicyStore::new();
    let _ = fetch_and_record(&fetcher, &store, "localhost", "abc123", NOW);

    assert_eq!(store.last_fetch_failure("localhost", "abc123"), Some(NOW));
    assert_eq!(
        store.last_fetch_failure("localhost", "def456"),
        None,
        "a different id must not be rate-limited by this failure"
    );
    assert_eq!(
        store.last_fetch_failure("other.example", "abc123"),
        None,
        "nor a different domain"
    );
}

/// A failed fetch stores no policy.
#[test]
fn a_failed_fetch_caches_nothing() {
    let fetcher = PolicyFetcher::new();
    let store = InMemoryPolicyStore::new();
    let _ = fetch_and_record(&fetcher, &store, "localhost", "abc123", NOW);
    assert_eq!(store.policy_count(), 0);
    assert_eq!(store.get("localhost"), None);
}

/// A later failure replaces the recorded instant, extending the window.
///
/// Otherwise the window would be measured from the first failure ever seen,
/// and a host failing continuously would come out of backoff and stay out.
#[test]
fn a_later_failure_moves_the_window_forward() {
    let fetcher = PolicyFetcher::new();
    let store = InMemoryPolicyStore::new();

    let _ = fetch_and_record(&fetcher, &store, "localhost", "abc123", NOW);
    let past = NOW + BACKOFF;
    assert!(
        !in_backoff(&store, "localhost", "abc123", past, BACKOFF),
        "the first window has elapsed"
    );

    let _ = fetch_and_record(&fetcher, &store, "localhost", "abc123", past);
    assert_eq!(store.last_fetch_failure("localhost", "abc123"), Some(past));
    assert!(
        in_backoff(&store, "localhost", "abc123", past + 60, BACKOFF),
        "the second failure starts a new window"
    );
}
