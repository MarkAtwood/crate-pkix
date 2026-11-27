//! The policy store, §3.3's fetch backoff, and §5's pre-bounce check.

#![cfg(feature = "std")]

use pkix_mta_sts::discovery::{
    DiscoveryPlan, StsTxtRecord, TxtError, SUGGESTED_FETCH_BACKOFF_SECS,
};
use pkix_mta_sts::{
    in_backoff, newer_policy_published, note_failed_fetch, plan_with_store, record_fetched_policy,
    DiscoveryConfig, InMemoryPolicyStore, PolicyStore, StsPolicy,
};

const NOW: u64 = 1_700_000_000;
const DAY: u64 = 86_400;
const DOMAIN: &str = "example.com";

fn week_policy() -> StsPolicy {
    StsPolicy::parse("version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n")
        .expect("parses")
}

fn txt(id: &str) -> StsTxtRecord {
    StsTxtRecord::parse(&format!("v=STSv1; id={id};")).expect("parses")
}

/// Proactive refresh off, so the backoff is what is under test.
fn no_refresh() -> DiscoveryConfig {
    DiscoveryConfig {
        refresh_interval_secs: u64::MAX,
        ..DiscoveryConfig::default()
    }
}

// ---------------------------------------------------------------------------
// Round trip
// ---------------------------------------------------------------------------

/// A fetched policy goes in, comes back, and is applied.
///
/// The baseline the rest of the file depends on: if a store could not return
/// what was put in it, every cache rule below would pass for the wrong
/// reason.
#[test]
fn a_policy_survives_a_round_trip_and_is_then_applied() {
    let store = InMemoryPolicyStore::new();
    assert_eq!(store.policy_count(), 0);

    record_fetched_policy(&store, DOMAIN, week_policy(), "abc123", NOW);
    assert_eq!(store.policy_count(), 1);

    let got = store.get(DOMAIN).expect("the policy was stored");
    assert_eq!(got.policy(), &week_policy());
    assert_eq!(got.id(), "abc123");
    assert_eq!(got.fetched_at_unix(), NOW);

    assert_eq!(
        plan_with_store(&store, DOMAIN, Ok(&txt("abc123")), NOW + 60, &no_refresh()),
        DiscoveryPlan::UseCached,
        "a stored policy with a matching id needs no fetch"
    );
}

/// `get` returns an expired entry rather than hiding it.
///
/// §3.3 treats "nothing cached" and "cached but expired" differently, so a
/// store that filtered expired entries would make that distinction
/// unavailable to `plan_with_store`.
#[test]
fn get_returns_an_expired_entry_without_judging_it() {
    let store = InMemoryPolicyStore::new();
    record_fetched_policy(&store, DOMAIN, week_policy(), "abc123", NOW - 10 * DAY);

    let got = store.get(DOMAIN).expect("still present");
    assert!(
        !got.is_live_at(NOW),
        "and expired, which is the caller's to see"
    );
}

/// Domains are kept apart.
#[test]
fn policies_are_keyed_per_domain() {
    let store = InMemoryPolicyStore::new();
    record_fetched_policy(&store, "a.example", week_policy(), "aaa", NOW);
    record_fetched_policy(&store, "b.example", week_policy(), "bbb", NOW);

    assert_eq!(
        store.get("a.example").map(|c| c.id().to_owned()).as_deref(),
        Some("aaa")
    );
    assert_eq!(
        store.get("b.example").map(|c| c.id().to_owned()).as_deref(),
        Some("bbb")
    );
    assert_eq!(store.get("c.example"), None);
}

#[test]
fn invalidate_removes_only_the_named_domain() {
    let store = InMemoryPolicyStore::new();
    record_fetched_policy(&store, "a.example", week_policy(), "aaa", NOW);
    record_fetched_policy(&store, "b.example", week_policy(), "bbb", NOW);

    store.invalidate("a.example");
    assert_eq!(store.get("a.example"), None);
    assert!(store.get("b.example").is_some());
}

// ---------------------------------------------------------------------------
// §3.3 fetch backoff
// ---------------------------------------------------------------------------

/// "implementers SHOULD limit further attempts to a period of five minutes
/// or longer per version ID".
///
/// The test that matters: a second attempt inside the window does not fetch.
#[test]
fn a_second_attempt_inside_the_backoff_window_does_not_fetch() {
    let store = InMemoryPolicyStore::new();
    let config = no_refresh();

    // Nothing cached, a usable record: the first attempt fetches.
    assert_eq!(
        plan_with_store(&store, DOMAIN, Ok(&txt("abc123")), NOW, &config),
        DiscoveryPlan::Fetch
    );

    // It failed.
    note_failed_fetch(&store, DOMAIN, "abc123", NOW);

    // Inside the window, no fetch — and with nothing cached, no policy.
    assert_eq!(
        plan_with_store(&store, DOMAIN, Ok(&txt("abc123")), NOW + 60, &config),
        DiscoveryPlan::NoPolicy,
        "§3.3 limits retries to five minutes per version id"
    );
}

/// Past the window, it fetches again.
#[test]
fn past_the_backoff_window_a_fetch_is_attempted_again() {
    let store = InMemoryPolicyStore::new();
    note_failed_fetch(&store, DOMAIN, "abc123", NOW);

    assert_eq!(
        plan_with_store(
            &store,
            DOMAIN,
            Ok(&txt("abc123")),
            NOW + SUGGESTED_FETCH_BACKOFF_SECS,
            &no_refresh()
        ),
        DiscoveryPlan::Fetch,
        "the window has elapsed"
    );
}

/// The backoff is per version id, as §3.3 words it.
///
/// A domain that publishes a new policy after a failure must be fetched at
/// once: the previous failure says nothing about the new policy, and making
/// a sender wait would delay exactly the update the domain published to fix
/// the problem.
#[test]
fn the_backoff_is_per_version_id_so_a_new_id_fetches_immediately() {
    let store = InMemoryPolicyStore::new();
    note_failed_fetch(&store, DOMAIN, "abc123", NOW);

    assert!(in_backoff(
        &store,
        DOMAIN,
        "abc123",
        NOW + 60,
        SUGGESTED_FETCH_BACKOFF_SECS
    ));
    assert!(
        !in_backoff(
            &store,
            DOMAIN,
            "def456",
            NOW + 60,
            SUGGESTED_FETCH_BACKOFF_SECS
        ),
        "a different id has not failed"
    );
    assert_eq!(
        plan_with_store(&store, DOMAIN, Ok(&txt("def456")), NOW + 60, &no_refresh()),
        DiscoveryPlan::Fetch,
        "a newly published policy is fetched at once"
    );
}

/// The backoff is per domain too.
#[test]
fn the_backoff_does_not_leak_between_domains() {
    let store = InMemoryPolicyStore::new();
    note_failed_fetch(&store, "a.example", "abc123", NOW);
    assert!(!in_backoff(
        &store,
        "b.example",
        "abc123",
        NOW + 60,
        SUGGESTED_FETCH_BACKOFF_SECS
    ));
}

/// A suppressed fetch still applies a live cached policy.
///
/// §3.3: "if no 'live' policy can be discovered via DNS or fetched via
/// HTTPS, but a valid (non-expired) policy exists in the sender's cache, the
/// sender MUST apply that cached policy." A fetch the sender declined to
/// attempt is a fetch that did not happen.
#[test]
fn a_suppressed_fetch_still_applies_a_live_cached_policy() {
    let store = InMemoryPolicyStore::new();
    record_fetched_policy(&store, DOMAIN, week_policy(), "old111", NOW - DAY);
    note_failed_fetch(&store, DOMAIN, "new222", NOW);

    assert_eq!(
        plan_with_store(&store, DOMAIN, Ok(&txt("new222")), NOW + 60, &no_refresh()),
        DiscoveryPlan::UseCached,
        "the id moved on and the refetch is rate-limited, but a valid \
         non-expired policy is still what §3.3 says to apply — applying \
         nothing is what an attacker suppressing the fetch wants"
    );
}

/// A suppressed fetch with an expired cache yields no policy.
#[test]
fn a_suppressed_fetch_with_an_expired_cache_yields_no_policy() {
    let store = InMemoryPolicyStore::new();
    record_fetched_policy(&store, DOMAIN, week_policy(), "old111", NOW - 10 * DAY);
    note_failed_fetch(&store, DOMAIN, "new222", NOW);

    assert_eq!(
        plan_with_store(&store, DOMAIN, Ok(&txt("new222")), NOW + 60, &no_refresh()),
        DiscoveryPlan::NoPolicy
    );
}

/// A zero backoff disables the limit.
#[test]
fn a_zero_backoff_disables_the_limit() {
    let store = InMemoryPolicyStore::new();
    note_failed_fetch(&store, DOMAIN, "abc123", NOW);
    assert!(!in_backoff(&store, DOMAIN, "abc123", NOW, 0));
    assert_eq!(
        plan_with_store(
            &store,
            DOMAIN,
            Ok(&txt("abc123")),
            NOW,
            &DiscoveryConfig {
                refresh_interval_secs: u64::MAX,
                fetch_backoff_secs: 0,
            }
        ),
        DiscoveryPlan::Fetch
    );
}

/// A clock behind the recorded failure holds off rather than retrying.
#[test]
fn a_clock_behind_the_recorded_failure_holds_off() {
    let store = InMemoryPolicyStore::new();
    note_failed_fetch(&store, DOMAIN, "abc123", NOW);
    assert!(
        in_backoff(
            &store,
            DOMAIN,
            "abc123",
            NOW - 1,
            SUGGESTED_FETCH_BACKOFF_SECS
        ),
        "an unmeasurable interval should hold off — the backoff protects the \
         recipient, and waiting only delays a refresh"
    );
}

/// The backoff never suppresses a decision that was not a fetch.
#[test]
fn the_backoff_does_not_disturb_a_non_fetch_decision() {
    let store = InMemoryPolicyStore::new();
    record_fetched_policy(&store, DOMAIN, week_policy(), "abc123", NOW);
    note_failed_fetch(&store, DOMAIN, "abc123", NOW);

    assert_eq!(
        plan_with_store(&store, DOMAIN, Ok(&txt("abc123")), NOW + 60, &no_refresh()),
        DiscoveryPlan::UseCached,
        "the cache was live and the id matched, so no fetch was wanted anyway"
    );
}

/// §3.1's rule survives the store: an unusable TXT record keeps the cache.
#[test]
fn an_unusable_txt_record_still_keeps_a_live_cached_policy() {
    let store = InMemoryPolicyStore::new();
    record_fetched_policy(&store, DOMAIN, week_policy(), "abc123", NOW - DAY);

    assert_eq!(
        plan_with_store(
            &store,
            DOMAIN,
            Err(&TxtError::NoStsRecord),
            NOW,
            &no_refresh()
        ),
        DiscoveryPlan::UseCached
    );
}

// ---------------------------------------------------------------------------
// §5 pre-bounce check
// ---------------------------------------------------------------------------

/// A changed id is a new policy, which §5 requires checking for.
///
/// "A message delivery attempt MUST NOT be permanently failed until the
/// sender has first checked for the presence of a new policy."
#[test]
fn a_changed_id_is_a_newer_policy() {
    let store = InMemoryPolicyStore::new();
    record_fetched_policy(&store, DOMAIN, week_policy(), "old111", NOW);
    assert!(newer_policy_published(&store, DOMAIN, Ok(&txt("new222"))));
    assert!(!newer_policy_published(&store, DOMAIN, Ok(&txt("old111"))));
}

/// An unusable TXT record is NOT a new policy, so it does not license a
/// bounce.
///
/// §3.1 is explicit that an absent record does not even remove the cached
/// policy; it certainly does not count as the domain having published
/// something new.
#[test]
fn an_unusable_txt_record_is_not_a_newer_policy() {
    let store = InMemoryPolicyStore::new();
    record_fetched_policy(&store, DOMAIN, week_policy(), "old111", NOW);
    for err in [
        TxtError::NoStsRecord,
        TxtError::MissingId,
        TxtError::MultipleStsRecords(2),
    ] {
        assert!(
            !newer_policy_published(&store, DOMAIN, Err(&err)),
            "{err:?} is not a new policy"
        );
    }
}

/// With nothing cached, any usable record is newer than nothing.
#[test]
fn with_nothing_cached_a_usable_record_is_newer() {
    let store = InMemoryPolicyStore::new();
    assert!(newer_policy_published(&store, DOMAIN, Ok(&txt("abc123"))));
    assert!(!newer_policy_published(
        &store,
        DOMAIN,
        Err(&TxtError::NoStsRecord)
    ));
}

// ---------------------------------------------------------------------------
// Housekeeping
// ---------------------------------------------------------------------------

/// Pruning drops failure records and leaves policies alone.
///
/// Deliberate asymmetry: a failure record is useful only for the length of
/// the backoff, while a cached policy past its `max_age` is still what §3.3
/// falls back on, and dropping one is the action §3.1 warns against.
#[test]
fn pruning_drops_failures_and_keeps_policies() {
    let store = InMemoryPolicyStore::new();
    record_fetched_policy(&store, DOMAIN, week_policy(), "abc123", NOW - 10 * DAY);
    note_failed_fetch(&store, DOMAIN, "abc123", NOW - DAY);
    note_failed_fetch(&store, DOMAIN, "def456", NOW);
    assert_eq!(store.failure_count(), 2);

    store.prune_failures_before(NOW - 60);
    assert_eq!(store.failure_count(), 1, "the day-old failure is gone");
    assert_eq!(store.last_fetch_failure(DOMAIN, "abc123"), None);
    assert_eq!(store.last_fetch_failure(DOMAIN, "def456"), Some(NOW));
    assert_eq!(
        store.policy_count(),
        1,
        "an expired policy is kept — §3.3 still falls back on it"
    );
}

#[test]
fn clear_drops_everything() {
    let store = InMemoryPolicyStore::new();
    record_fetched_policy(&store, DOMAIN, week_policy(), "abc123", NOW);
    note_failed_fetch(&store, DOMAIN, "abc123", NOW);
    store.clear();
    assert_eq!(store.policy_count(), 0);
    assert_eq!(store.failure_count(), 0);
}

/// The default config carries §3.3's suggested intervals.
#[test]
fn the_default_config_uses_the_rfc_suggestions() {
    let c = DiscoveryConfig::default();
    assert_eq!(c.fetch_backoff_secs, 300, "§3.3 suggests five minutes");
    assert_eq!(
        c.refresh_interval_secs, 86_400,
        "§3.3 suggests once per day"
    );
}

/// A store is usable through a shared reference across threads.
///
/// `&self` methods and `Send + Sync` exist so one store serves many delivery
/// threads; asserted rather than assumed, since a store that forced
/// serialisation would be a bottleneck on the delivery path.
#[test]
fn a_store_is_shared_across_threads() {
    use std::sync::Arc;
    let store = Arc::new(InMemoryPolicyStore::new());
    let handles: Vec<_> = (0..8)
        .map(|i| {
            let s = Arc::clone(&store);
            std::thread::spawn(move || {
                let domain = format!("d{i}.example");
                record_fetched_policy(&*s, &domain, week_policy(), "abc123", NOW);
                assert!(s.get(&domain).is_some());
            })
        })
        .collect();
    for h in handles {
        h.join().expect("no thread should panic");
    }
    assert_eq!(store.policy_count(), 8);
}

/// A proactive refresh suppressed by the backoff still uses the cache.
///
/// The subtle path: the cache is live and its id matches, but the policy is
/// old enough that §3.3 wants a refresh, and the refresh is rate-limited.
/// The answer must be `UseCached` rather than `NoPolicy` — a declined
/// refresh is not a reason to stop applying a policy that is still valid.
#[test]
fn a_refresh_suppressed_by_the_backoff_still_uses_the_cache() {
    let store = InMemoryPolicyStore::new();
    record_fetched_policy(&store, DOMAIN, week_policy(), "abc123", NOW - 2 * DAY);
    let config = DiscoveryConfig::default(); // refresh once per day

    // Without a recorded failure, it refreshes with fallback.
    assert_eq!(
        plan_with_store(&store, DOMAIN, Ok(&txt("abc123")), NOW, &config),
        DiscoveryPlan::RefreshButUseCachedIfUnavailable
    );

    // With one, the refresh is suppressed and the live policy still applies.
    note_failed_fetch(&store, DOMAIN, "abc123", NOW);
    assert_eq!(
        plan_with_store(&store, DOMAIN, Ok(&txt("abc123")), NOW + 60, &config),
        DiscoveryPlan::UseCached,
        "a declined refresh must not stop a still-valid policy being applied"
    );
}

// ---------------------------------------------------------------------------
// The blanket impl for `&S`
// ---------------------------------------------------------------------------

/// A store that records which methods were called on it.
///
/// The blanket `impl PolicyStore for &S` is five one-line forwards. Each
/// can be replaced by a no-op, or by `None`, without any test noticing:
/// the suite builds stores by value, so the forwards have no caller. A
/// `put` that dropped its argument would make a caller holding a borrow
/// re-fetch every policy forever, and a `get` answering `None` would do
/// the same while looking like a cold cache.
#[derive(Default)]
struct Recording {
    inner: InMemoryPolicyStore,
    calls: std::sync::Mutex<Vec<&'static str>>,
}

impl Recording {
    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().expect("not poisoned").clone()
    }
    fn note(&self, what: &'static str) {
        self.calls.lock().expect("not poisoned").push(what);
    }
}

impl PolicyStore for Recording {
    fn get(&self, policy_domain: &str) -> Option<pkix_mta_sts::discovery::CachedPolicy> {
        self.note("get");
        self.inner.get(policy_domain)
    }
    fn put(&self, policy_domain: &str, policy: pkix_mta_sts::discovery::CachedPolicy) {
        self.note("put");
        self.inner.put(policy_domain, policy);
    }
    fn invalidate(&self, policy_domain: &str) {
        self.note("invalidate");
        self.inner.invalidate(policy_domain);
    }
    fn note_fetch_failure(&self, policy_domain: &str, policy_id: &str, at_unix: u64) {
        self.note("note_fetch_failure");
        self.inner
            .note_fetch_failure(policy_domain, policy_id, at_unix);
    }
    fn last_fetch_failure(&self, policy_domain: &str, policy_id: &str) -> Option<u64> {
        self.note("last_fetch_failure");
        self.inner.last_fetch_failure(policy_domain, policy_id)
    }
}

/// Calls all five methods through an opaque `S: PolicyStore`.
///
/// Opaque is the point. Written as `store.get(..)` on a concrete
/// `&Recording`, method resolution auto-derefs and reaches
/// `Recording::get` directly, so the blanket impl is never selected --
/// which is what the first version of this test did, leaving all seven
/// of its mutants alive under a test that looked like it covered them.
/// Inside a generic function the compiler has no concrete type to deref
/// through and must use `<S as PolicyStore>`, so passing `&Recording`
/// as `S` selects the impl under test.
fn exercise<S: PolicyStore>(store: S, cached: pkix_mta_sts::discovery::CachedPolicy) {
    assert_eq!(store.get(DOMAIN), None, "nothing cached yet");
    store.put(DOMAIN, cached);
    let got = store
        .get(DOMAIN)
        .expect("put through the borrow is visible");
    assert_eq!(got.id(), "id1", "and carried its argument");

    assert_eq!(store.last_fetch_failure(DOMAIN, "id1"), None);
    store.note_fetch_failure(DOMAIN, "id1", NOW);
    assert_eq!(
        store.last_fetch_failure(DOMAIN, "id1"),
        Some(NOW),
        "the failure instant forwarded too"
    );

    store.invalidate(DOMAIN);
    assert_eq!(store.get(DOMAIN), None, "invalidate reached the store");
}

/// A `&S` forwards every method to the store it borrows.
///
/// Called through the reference, so each of the five forwards is the
/// path under test. Both halves matter: the recording store proves the
/// call arrived, and reading the value back proves the argument did too
/// -- a `put` that forwarded nothing would still be recorded by a test
/// that only counted calls.
#[test]
fn a_borrowed_store_forwards_every_method() {
    let owned = Recording::default();
    let cached = pkix_mta_sts::discovery::CachedPolicy::new(week_policy(), "id1".into(), NOW);

    // `S` binds to `&Recording`, so every call inside goes through
    // `impl PolicyStore for &S` rather than through an auto-deref.
    exercise(&owned, cached);

    assert_eq!(
        owned.calls(),
        vec![
            "get",
            "put",
            "get",
            "last_fetch_failure",
            "note_fetch_failure",
            "last_fetch_failure",
            "invalidate",
            "get",
        ],
        "every call arrived at the borrowed store, in order"
    );
}
