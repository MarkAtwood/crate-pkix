//! Where the fetchers get "now" from.
//!
//! Every revocation decision is a statement about a moment: a CRL is
//! live between `thisUpdate` and `nextUpdate`, an OCSP response between
//! its own pair. `pkix-revocation`'s checkers take that moment as a
//! `now_unix` argument rather than reading a clock, which keeps them
//! sans-IO and makes their tests reproducible.
//!
//! The HTTP fetchers inherited the same shape, taking `now_unix` once at
//! construction. That is right for a fetcher built per validation and
//! wrong for one built once and kept, which is how a server uses it: the
//! timestamp freezes, and from then on the fetcher judges freshness
//! against the moment the process started. A CRL that expired last week
//! still looks live, so stale revocation data is accepted indefinitely —
//! silently, because nothing about the result says the clock is wrong.
//!
//! [`TimeSource`] is the fix. A fetcher holds a clock rather than a
//! timestamp and asks it once per revocation check.

use core::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// A source of the current time as seconds since the Unix epoch.
///
/// Implement this to drive the fetchers from a clock the consumer
/// already owns — a coarse cached clock updated on a timer, a clock
/// slewed to a trusted time service, or a test clock that advances on
/// command. Pass it with
/// [`HttpCrlFetcher::with_time_source`](crate::HttpCrlFetcher::with_time_source)
/// or its siblings.
///
/// `Send + Sync` because the fetchers are shared across validation
/// threads.
pub trait TimeSource: Send + Sync {
    /// The current time, in seconds since the Unix epoch.
    ///
    /// Called once per revocation check. An implementation should be
    /// cheap: it sits in the path of every certificate validated.
    fn now_unix(&self) -> u64;
}

impl<T: TimeSource + ?Sized> TimeSource for Arc<T> {
    fn now_unix(&self) -> u64 {
        (**self).now_unix()
    }
}

/// Reads the operating system clock on every call.
///
/// # Before the epoch
///
/// A system clock set before 1970 cannot be expressed as a `u64` of
/// seconds since the epoch, and this type reports `0` for it. That
/// direction is deliberate: `0` puts "now" before the `thisUpdate` of
/// every CRL and OCSP response in existence, and
/// `pkix_revocation::CrlChecker` rejects `now_unix < thisUpdate` as
/// `CrlExpired`. A nonsensical clock therefore produces a revocation
/// failure rather than an acceptance, which is the only safe way to be
/// wrong.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SystemClock;

impl TimeSource for SystemClock {
    fn now_unix(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
}

/// How a fetcher obtains the current time.
///
/// Crate-private so the public types keep their shape: a fetcher is
/// `HttpCrlFetcher<F, V>`, not `HttpCrlFetcher<F, V, T>`. The variants
/// correspond to the three constructors.
#[derive(Clone)]
pub(crate) enum Clock {
    /// One fixed instant, from `new(.., now_unix)`.
    Fixed(u64),
    /// The operating system clock, read per check.
    System,
    /// A clock the consumer supplied.
    Custom(Arc<dyn TimeSource>),
}

impl Clock {
    /// The current time according to this clock.
    pub(crate) fn now_unix(&self) -> u64 {
        match self {
            Self::Fixed(t) => *t,
            Self::System => SystemClock.now_unix(),
            Self::Custom(src) => src.now_unix(),
        }
    }
}

impl fmt::Debug for Clock {
    /// Names the variant. A `Fixed` clock prints its timestamp because
    /// that is exactly what a test wants to see; a custom clock is
    /// opaque, since `TimeSource` does not require `Debug`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fixed(t) => f.debug_tuple("Fixed").field(t).finish(),
            Self::System => f.write_str("System"),
            Self::Custom(_) => f.write_str("Custom(..)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A clock the test drives by hand — the shape a consumer needs for
    /// deterministic tests of their own.
    struct StepClock(AtomicU64);

    impl TimeSource for StepClock {
        fn now_unix(&self) -> u64 {
            self.0.fetch_add(100, Ordering::Relaxed)
        }
    }

    #[test]
    fn a_fixed_clock_never_moves() {
        let clock = Clock::Fixed(1_780_272_000);
        assert_eq!(clock.now_unix(), 1_780_272_000);
        assert_eq!(clock.now_unix(), 1_780_272_000);
    }

    /// The whole point of the trait: a clock that moves is observed to
    /// move, rather than being sampled once and frozen.
    #[test]
    fn a_custom_clock_is_re_read_on_every_call() {
        let clock = Clock::Custom(Arc::new(StepClock(AtomicU64::new(1_000))));
        assert_eq!(clock.now_unix(), 1_000);
        assert_eq!(clock.now_unix(), 1_100);
        assert_eq!(clock.now_unix(), 1_200);
    }

    #[test]
    fn the_system_clock_reports_a_plausible_present() {
        // 2020-01-01 < now < 2100-01-01. Wide enough that a CI machine
        // with a skewed clock still passes, narrow enough to catch a
        // unit mix-up (milliseconds would blow the upper bound).
        let now = Clock::System.now_unix();
        assert!(
            (1_577_836_800..4_102_444_800).contains(&now),
            "system clock reported {now}, which is not seconds since the epoch"
        );
    }

    /// `Arc<dyn TimeSource>` must forward to the inner clock rather than
    /// resolving to some blanket default, so a consumer can hand a
    /// boxed clock straight to `with_time_source`.
    #[test]
    fn arc_forwards_to_the_inner_clock() {
        let direct = StepClock(AtomicU64::new(500));
        assert_eq!(direct.now_unix(), 500);

        let boxed: Arc<dyn TimeSource> = Arc::new(StepClock(AtomicU64::new(500)));
        assert_eq!(boxed.now_unix(), 500, "Arc must delegate, not substitute");
        assert_eq!(boxed.now_unix(), 600, "and must delegate again, not cache");
    }

    #[test]
    fn debug_names_the_variant_without_leaking_a_custom_clock() {
        assert_eq!(format!("{:?}", Clock::Fixed(42)), "Fixed(42)");
        assert_eq!(format!("{:?}", Clock::System), "System");
        let custom = Clock::Custom(Arc::new(SystemClock));
        assert_eq!(format!("{custom:?}"), "Custom(..)");
    }
}
