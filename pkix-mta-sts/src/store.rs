//! Policy cache storage and RFC 8461 §3.3's fetch backoff.
//!
//! [`crate::discovery::plan`] decides whether a fetch is needed given a
//! cached policy. This module is where that policy is kept, and where the
//! §3.3 rule that limits retries after a failure lives.
//!
//! The two belong together because both are keyed state about the same pair.
//! A cached policy is keyed by policy domain; §3.3's backoff is "per version
//! ID", so by policy domain and id. Separate stores keyed the same way would
//! be two places to get the key wrong.
//!
//! # Storage is the caller's, and the trait is why
//!
//! The workspace does not depend on a filesystem or an OS, so this crate
//! cannot ship the persistent store a real MTA wants. [`PolicyStore`] is the
//! seam: implement it over whatever a deployment already has — a database, a
//! shared key-value store, a file — and the §3.3 and §5.1 rules come from
//! [`plan_with_store`] rather than being reimplemented alongside it.
//!
//! [`InMemoryPolicyStore`] (feature `std`) is a complete implementation, not
//! a stub. It survives for the life of the process, which covers a
//! long-running MTA, and it makes the whole mechanism testable without
//! storage. What it does not survive is a restart — and since MTA-STS's
//! protection comes from holding a policy across the moment an attacker
//! shows up, a process that restarts often wants something durable.

use alloc::string::String;

use crate::discovery::{
    plan, CachedPolicy, DiscoveryPlan, StsTxtRecord, TxtError, SUGGESTED_FETCH_BACKOFF_SECS,
    SUGGESTED_REFRESH_INTERVAL_SECS,
};

/// Where a sender keeps fetched policies and recent fetch failures.
///
/// Methods take `&self` rather than `&mut self`, so one store can be shared
/// across delivery threads without the caller holding a lock of its own. An
/// implementation handles its own synchronisation, as
/// [`InMemoryPolicyStore`] does.
///
/// `Send + Sync` is required for the same reason (AGENTS.md non-negotiable
/// #6): a store that could not cross threads would force every MTA to
/// serialise deliveries behind it.
///
/// # Time is passed in, never read
///
/// No method reads a clock. Every instant arrives as a `now_unix` argument,
/// so an offline replay or an audit gets the same answer on every run — the
/// same discipline as `pkix-path` and `pkix-revocation-http`.
pub trait PolicyStore: Send + Sync {
    /// The cached policy for `policy_domain`, whatever its age.
    ///
    /// Returns the entry without judging it: whether it is still live is
    /// [`CachedPolicy::is_live_at`], which needs an instant this method is
    /// not given. A store that filtered expired entries here would make
    /// [`plan_with_store`] unable to tell "nothing cached" from "cached but
    /// expired", and §3.3 treats those differently.
    fn get(&self, policy_domain: &str) -> Option<CachedPolicy>;

    /// Store a freshly fetched policy, replacing any entry for the domain.
    fn put(&self, policy_domain: &str, policy: CachedPolicy);

    /// Forget the cached policy for `policy_domain`.
    ///
    /// Note that neither an unusable TXT record nor a failed fetch is a
    /// reason to call this — §3.1 and §3.3 both say a cached policy survives
    /// those. It is for an operator explicitly clearing a domain.
    fn invalidate(&self, policy_domain: &str);

    /// Record that fetching the policy for `(policy_domain, policy_id)`
    /// failed at `at_unix`.
    ///
    /// Called on every failure, whatever the cause, because §3.3's limit is
    /// on attempts rather than on any particular error.
    fn note_fetch_failure(&self, policy_domain: &str, policy_id: &str, at_unix: u64);

    /// When fetching `(policy_domain, policy_id)` last failed.
    ///
    /// `None` if it has not failed, or if the store has forgotten.
    /// Forgetting is permitted: it makes a sender retry sooner than §3.3
    /// suggests, which is a politeness failure rather than a safety one.
    fn last_fetch_failure(&self, policy_domain: &str, policy_id: &str) -> Option<u64>;
}

/// Blanket impl so a `&S` is a store, for callers holding a borrow.
impl<S: PolicyStore + ?Sized> PolicyStore for &S {
    fn get(&self, policy_domain: &str) -> Option<CachedPolicy> {
        (**self).get(policy_domain)
    }
    fn put(&self, policy_domain: &str, policy: CachedPolicy) {
        (**self).put(policy_domain, policy);
    }
    fn invalidate(&self, policy_domain: &str) {
        (**self).invalidate(policy_domain);
    }
    fn note_fetch_failure(&self, policy_domain: &str, policy_id: &str, at_unix: u64) {
        (**self).note_fetch_failure(policy_domain, policy_id, at_unix);
    }
    fn last_fetch_failure(&self, policy_domain: &str, policy_id: &str) -> Option<u64> {
        (**self).last_fetch_failure(policy_domain, policy_id)
    }
}

/// Timing policy for discovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiscoveryConfig {
    /// How long a cached policy may sit before a proactive refresh (§3.3).
    ///
    /// Default [`SUGGESTED_REFRESH_INTERVAL_SECS`]. `u64::MAX` disables
    /// proactive refresh, which is conformant but leaves the §10 window as
    /// wide as `max_age`.
    pub refresh_interval_secs: u64,

    /// Minimum interval between fetch attempts for one version id (§3.3).
    ///
    /// Default [`SUGGESTED_FETCH_BACKOFF_SECS`]. `0` disables the backoff,
    /// which §3.3 asks senders not to do: the limit exists "to avoid
    /// overwhelming resource-constrained recipients with cascading
    /// failures", so it protects the recipient rather than the sender.
    pub fetch_backoff_secs: u64,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            refresh_interval_secs: SUGGESTED_REFRESH_INTERVAL_SECS,
            fetch_backoff_secs: SUGGESTED_FETCH_BACKOFF_SECS,
        }
    }
}

/// Decide what to do, consulting a store for both the cache and the backoff.
///
/// [`plan`] applied to whatever `store` holds, then §3.3's retry limit: a
/// fetch suppressed by the backoff becomes [`DiscoveryPlan::UseCached`] if
/// anything live is cached, and [`DiscoveryPlan::NoPolicy`] otherwise.
///
/// # The case worth stating
///
/// When the backoff suppresses a fetch and the cached policy is live but was
/// fetched for a **different** id, this still reports `UseCached`.
///
/// That looks wrong and is not. §3.3: "if no 'live' policy can be discovered
/// via DNS or fetched via HTTPS, but a valid (non-expired) policy exists in
/// the sender's cache, the sender MUST apply that cached policy." A policy
/// whose id has moved on is still a valid non-expired policy the domain
/// published, and the alternative is applying nothing — which is what an
/// attacker suppressing the fetch wants. The id tells a sender the cache is
/// stale and worth replacing; it does not make the cached policy unsafe.
///
/// # Errors
///
/// None. Every failure mode is a [`DiscoveryPlan`] variant, because §3.3 has
/// a sender act on all of them rather than surfacing them.
#[must_use]
pub fn plan_with_store<S: PolicyStore + ?Sized>(
    store: &S,
    policy_domain: &str,
    txt: Result<&StsTxtRecord, &TxtError>,
    now_unix: u64,
    config: &DiscoveryConfig,
) -> DiscoveryPlan {
    let cached = store.get(policy_domain);
    let decided = plan(cached.as_ref(), txt, now_unix, config.refresh_interval_secs);

    let wants_fetch = matches!(
        decided,
        DiscoveryPlan::Fetch | DiscoveryPlan::RefreshButUseCachedIfUnavailable
    );
    if !wants_fetch {
        return decided;
    }

    // §3.3's retry limit applies per version id, so it needs the id a fetch
    // would be for. With no usable TXT record there is no id and nothing to
    // rate-limit against; `plan` cannot have asked for a fetch in that case
    // anyway, since an unusable record never yields Fetch.
    let Ok(record) = txt else {
        return decided;
    };

    if !in_backoff(
        store,
        policy_domain,
        record.id(),
        now_unix,
        config.fetch_backoff_secs,
    ) {
        return decided;
    }

    // Suppressed. Fall back exactly as a failed fetch would.
    match cached {
        Some(c) if c.is_live_at(now_unix) => DiscoveryPlan::UseCached,
        _ => DiscoveryPlan::NoPolicy,
    }
}

/// Whether a fetch for `(policy_domain, policy_id)` is inside §3.3's backoff.
///
/// A clock behind the recorded failure yields `true` — hold off rather than
/// retry on an unmeasurable interval, since the backoff protects the
/// recipient and the cost of waiting is a delayed refresh.
#[must_use]
pub fn in_backoff<S: PolicyStore + ?Sized>(
    store: &S,
    policy_domain: &str,
    policy_id: &str,
    now_unix: u64,
    backoff_secs: u64,
) -> bool {
    if backoff_secs == 0 {
        return false;
    }
    let Some(failed_at) = store.last_fetch_failure(policy_domain, policy_id) else {
        return false;
    };
    match now_unix.checked_sub(failed_at) {
        Some(elapsed) => elapsed < backoff_secs,
        None => true,
    }
}

/// Whether the domain has published a policy newer than what is cached.
///
/// RFC 8461 §5, which §5.1 step 3 repeats:
///
/// > A message delivery attempt MUST NOT be permanently failed until the
/// > sender has first checked for the presence of a new policy (as indicated
/// > by the "id" field in the "_mta-sts" TXT record). If a new policy is not
/// > found, existing rules for the case of temporary message delivery
/// > failures apply.
///
/// So a sender about to bounce a message held up by an `enforce` policy must
/// re-check DNS first — the domain may have fixed its policy since, and
/// bouncing on a policy it has already replaced is a false negative the
/// sender can avoid.
///
/// # Why this is a function and not just documentation
///
/// Deciding to bounce is the MTA's, and this crate does not own it. But the
/// *question* the RFC requires asking first is exactly `id != cached id`,
/// and leaving it as prose means every caller rediscovers it from §5 —
/// including the detail that an absent or unusable TXT record is **not** a
/// new policy, so it does not license a bounce either.
///
/// `txt` is a freshly performed lookup. Passing a cached TXT answer would
/// defeat the point, which is to consult DNS at bounce time.
#[must_use]
pub fn newer_policy_published<S: PolicyStore + ?Sized>(
    store: &S,
    policy_domain: &str,
    txt: Result<&StsTxtRecord, &TxtError>,
) -> bool {
    let Ok(record) = txt else {
        // No usable record is not a new policy. §3.1 is explicit that it does
        // not even remove the cached one.
        return false;
    };
    match store.get(policy_domain) {
        Some(cached) => cached.id() != record.id(),
        // Nothing cached and a usable record: whatever it names is newer than
        // nothing, and the sender should fetch before bouncing.
        None => true,
    }
}

/// Record a failed fetch, for §3.3's backoff.
///
/// A thin wrapper over [`PolicyStore::note_fetch_failure`] that exists to be
/// named at the call site, so the reason for recording it stays visible.
pub fn note_failed_fetch<S: PolicyStore + ?Sized>(
    store: &S,
    policy_domain: &str,
    policy_id: &str,
    now_unix: u64,
) {
    store.note_fetch_failure(policy_domain, policy_id, now_unix);
}

/// Store a fetched policy against the id it was fetched for.
///
/// Pairs with [`note_failed_fetch`]: one of the two follows every fetch, and
/// naming both keeps a caller from storing a policy without its id.
pub fn record_fetched_policy<S: PolicyStore + ?Sized>(
    store: &S,
    policy_domain: &str,
    policy: crate::StsPolicy,
    policy_id: &str,
    fetched_at_unix: u64,
) {
    store.put(
        policy_domain,
        CachedPolicy::new(policy, String::from(policy_id), fetched_at_unix),
    );
}

// ---------------------------------------------------------------------------
// In-memory implementation
// ---------------------------------------------------------------------------

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
mod in_memory {
    use super::{CachedPolicy, PolicyStore};
    use alloc::string::String;
    use std::collections::HashMap;
    use std::sync::RwLock;

    /// A complete [`PolicyStore`] held in process memory.
    ///
    /// Not a stub: it survives for the life of the process, which covers a
    /// long-running MTA, and it makes discovery testable without storage.
    /// What it does not survive is a restart — and since MTA-STS's protection
    /// comes from holding a policy across the moment an attacker appears, a
    /// process that restarts often wants something durable instead.
    ///
    /// Unbounded. One entry per policy domain a sender has fetched from, plus
    /// one failure record per `(domain, id)` attempted; both are small, and a
    /// sender that delivers to unbounded domains should
    /// [`clear`](Self::clear) periodically or implement the trait over a
    /// store with eviction.
    ///
    /// Locking is `RwLock`, following `pkix-revocation-http`'s cache: reads
    /// dominate, and the contention a delivery path sees is not worth another
    /// dependency.
    #[derive(Debug, Default)]
    pub struct InMemoryPolicyStore {
        policies: RwLock<HashMap<String, CachedPolicy>>,
        failures: RwLock<HashMap<(String, String), u64>>,
    }

    impl InMemoryPolicyStore {
        /// An empty store.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// How many policies are cached.
        #[must_use]
        pub fn policy_count(&self) -> usize {
            self.policies.read().unwrap().len()
        }

        /// How many failure records are held.
        #[must_use]
        pub fn failure_count(&self) -> usize {
            self.failures.read().unwrap().len()
        }

        /// Drop everything.
        pub fn clear(&self) {
            self.policies.write().unwrap().clear();
            self.failures.write().unwrap().clear();
        }

        /// Drop failure records older than `before_unix`.
        ///
        /// Failure records are only useful for the length of the backoff, so
        /// a long-running sender can discard them without affecting any
        /// decision. Cached policies are *not* pruned here, because a policy
        /// past its `max_age` is still the thing §3.3 has a sender fall back
        /// on once it is refreshed, and because dropping it is the one action
        /// §3.1 warns against doing casually.
        pub fn prune_failures_before(&self, before_unix: u64) {
            self.failures
                .write()
                .unwrap()
                .retain(|_, at| *at >= before_unix);
        }
    }

    impl PolicyStore for InMemoryPolicyStore {
        fn get(&self, policy_domain: &str) -> Option<CachedPolicy> {
            self.policies.read().unwrap().get(policy_domain).cloned()
        }

        fn put(&self, policy_domain: &str, policy: CachedPolicy) {
            self.policies
                .write()
                .unwrap()
                .insert(String::from(policy_domain), policy);
        }

        fn invalidate(&self, policy_domain: &str) {
            self.policies.write().unwrap().remove(policy_domain);
        }

        fn note_fetch_failure(&self, policy_domain: &str, policy_id: &str, at_unix: u64) {
            self.failures.write().unwrap().insert(
                (String::from(policy_domain), String::from(policy_id)),
                at_unix,
            );
        }

        fn last_fetch_failure(&self, policy_domain: &str, policy_id: &str) -> Option<u64> {
            self.failures
                .read()
                .unwrap()
                .get(&(String::from(policy_domain), String::from(policy_id)))
                .copied()
        }
    }

    const _: fn() = || {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<InMemoryPolicyStore>();
    };
}

#[cfg(feature = "std")]
pub use in_memory::InMemoryPolicyStore;
