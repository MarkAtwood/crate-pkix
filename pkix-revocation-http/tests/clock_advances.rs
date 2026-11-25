//! A long-lived fetcher must notice that time has passed.
//!
//! `HttpCrlFetcher::new(.., now_unix)` freezes the instant every check is
//! judged against. For a fetcher built per validation that is correct and
//! reproducible. For one built at startup and shared for the life of a
//! process — the ordinary server shape — it means revocation freshness is
//! judged against the moment the process started: a CRL that expired
//! weeks ago still looks live, and stale revocation data is accepted
//! indefinitely with nothing in the result to say so.
//!
//! These tests contrast the two constructors against the same fixture.
//! `tests/fixtures/review/base-crl.der` has thisUpdate 2026-01-01 and
//! nextUpdate 2027-01-01, so it is live at `INSIDE_WINDOW` and expired at
//! `AFTER_WINDOW`.
//!
//! Run: cargo test -p pkix-revocation-http --features crl --test clock_advances

#![cfg(feature = "crl")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use der::Decode as _;
use pkix_path::{DefaultVerifier, TrustAnchor};
use pkix_revocation::{Error as RevError, RevocationChecker};
use pkix_revocation_http::{
    FetchError, FetchRequest, FetchResponse, HttpCrlFetcher, RevocationFetcher, TimeSource,
};
use x509_cert::Certificate;

/// 2026-06-01T00:00:00Z — inside the fixture CRL's validity window.
const INSIDE_WINDOW: u64 = 1_780_272_000;
/// 2027-01-15T00:00:00Z — past the fixture CRL's nextUpdate.
const AFTER_WINDOW: u64 = 1_800_000_000;

fn fx(name: &str) -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/review/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn cert(name: &str) -> Certificate {
    Certificate::from_der(&fx(name)).expect("fixture certificate parses")
}

/// Serves the same CRL for every request.
struct Fixed(Vec<u8>);

impl RevocationFetcher for Fixed {
    fn fetch(&self, _req: &FetchRequest<'_>) -> Result<FetchResponse, FetchError> {
        Ok(FetchResponse {
            bytes: self.0.clone(),
            content_type: None,
        })
    }
}

/// Reports `INSIDE_WINDOW` for the first check and `AFTER_WINDOW` for
/// every one after it: a process that starts while the CRL is live and
/// keeps running past its expiry.
struct ClockThatPasses {
    calls: AtomicUsize,
}

impl ClockThatPasses {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
        }
    }
}

impl TimeSource for ClockThatPasses {
    fn now_unix(&self) -> u64 {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            INSIDE_WINDOW
        } else {
            AFTER_WINDOW
        }
    }
}

fn anchor() -> TrustAnchor {
    TrustAnchor::from_cert(cert("ca.der"))
}

/// The bug, pinned. A fetcher constructed with a fixed instant keeps
/// reporting the CRL as usable no matter how much time passes, because
/// the instant is the one baked in at construction.
///
/// This is the documented behaviour of `new`, not a defect in it — the
/// test exists so that the contrast with `with_time_source` below is
/// visible, and so that `new` cannot silently acquire clock-reading
/// behaviour that tests depend on it not having.
#[test]
fn a_fixed_instant_fetcher_never_sees_the_crl_expire() {
    let fetcher = HttpCrlFetcher::new(Fixed(fx("base-crl.der")), DefaultVerifier, INSIDE_WINDOW);
    let leaf = cert("leaf-serial2.der");

    // serial 2 is revoked by the fixture CRL.
    for attempt in 0..3 {
        let r = fetcher.check_revocation_against_anchor(&leaf, &anchor());
        assert!(
            matches!(r, Err(RevError::Revoked { .. })),
            "attempt {attempt}: a pinned fetcher must keep using the same instant, got {r:?}"
        );
    }
}

/// The fix. The same fetcher driven by a clock that advances past the
/// CRL's nextUpdate stops accepting it, because the clock is consulted
/// per check rather than once at construction.
#[test]
fn a_clock_driven_fetcher_sees_the_crl_expire() {
    let fetcher = HttpCrlFetcher::with_time_source(
        Fixed(fx("base-crl.der")),
        DefaultVerifier,
        Arc::new(ClockThatPasses::new()),
    );
    let leaf = cert("leaf-serial2.der");

    // First check: inside the window, so the CRL is usable and reports
    // serial 2 as revoked.
    let first = fetcher.check_revocation_against_anchor(&leaf, &anchor());
    assert!(
        matches!(first, Err(RevError::Revoked { .. })),
        "the first check is inside the CRL's window, got {first:?}"
    );

    // Second check: the clock has moved past nextUpdate. The same CRL
    // must now be rejected as expired rather than silently trusted.
    let second = fetcher.check_revocation_against_anchor(&leaf, &anchor());
    assert!(
        matches!(second, Err(RevError::CrlExpired)),
        "once the clock passes nextUpdate the CRL must be rejected as \
         expired, not accepted; got {second:?}"
    );
}

/// `with_system_clock` must judge against the real present.
///
/// Asserting a specific verdict here would pin the test to the calendar:
/// the fixture CRL is live until 2027-01-01, so a test expecting
/// `CrlExpired` passes only after that date and a test expecting
/// `Revoked` only before it. Instead this compares `with_system_clock`
/// against a fetcher pinned to the time the test itself reads, which is
/// the actual contract and holds on any date.
///
/// A clock stuck at `0`, or frozen at some unrelated instant, would
/// disagree with the pinned fetcher and fail this.
#[test]
fn a_system_clock_fetcher_agrees_with_one_pinned_to_the_current_time() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the test host's clock is after the Unix epoch")
        .as_secs();

    let on_system_clock =
        HttpCrlFetcher::with_system_clock(Fixed(fx("base-crl.der")), DefaultVerifier);
    let pinned_to_now = HttpCrlFetcher::new(Fixed(fx("base-crl.der")), DefaultVerifier, now);

    let leaf = cert("leaf-serial2.der");
    let from_system = on_system_clock.check_revocation_against_anchor(&leaf, &anchor());
    let from_pinned = pinned_to_now.check_revocation_against_anchor(&leaf, &anchor());

    assert_eq!(
        format!("{from_system:?}"),
        format!("{from_pinned:?}"),
        "with_system_clock must behave as if pinned to the present; a clock          stuck at 0 or frozen elsewhere would diverge here"
    );

    // And the shared verdict must be a real determination rather than a
    // fetch failure, which would make the comparison above vacuous.
    assert!(
        matches!(
            from_system,
            Err(RevError::Revoked { .. }) | Err(RevError::CrlExpired) | Ok(())
        ),
        "expected a determination from the fixture CRL, got {from_system:?}"
    );
}

/// Each check samples the clock once, not once per candidate URL.
///
/// Certificates advertise several distribution points. If the clock were
/// read inside the per-URL loop, two CRLs considered in the same check
/// could be judged against different instants, and a check that straddled
/// a nextUpdate boundary could accept one and reject another for reasons
/// having nothing to do with the CRLs.
#[test]
fn one_check_samples_the_clock_once() {
    struct CountingClock(AtomicUsize);
    impl TimeSource for CountingClock {
        fn now_unix(&self) -> u64 {
            self.0.fetch_add(1, Ordering::SeqCst);
            INSIDE_WINDOW
        }
    }

    let clock = Arc::new(CountingClock(AtomicUsize::new(0)));
    let fetcher = HttpCrlFetcher::with_time_source(
        Fixed(fx("base-crl.der")),
        DefaultVerifier,
        Arc::clone(&clock) as Arc<dyn TimeSource>,
    );

    let _ = fetcher.check_revocation_against_anchor(&cert("leaf-serial2.der"), &anchor());
    assert_eq!(
        clock.0.load(Ordering::SeqCst),
        1,
        "one revocation check must read the clock exactly once"
    );

    let _ = fetcher.check_revocation_against_anchor(&cert("leaf-serial2.der"), &anchor());
    assert_eq!(
        clock.0.load(Ordering::SeqCst),
        2,
        "a second check must read it again rather than reuse the first sample"
    );
}
