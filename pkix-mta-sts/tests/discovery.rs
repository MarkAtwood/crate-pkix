//! RFC 8461 §3.1 TXT records and the §3.3 / §5.1 cache rules.

use pkix_mta_sts::discovery::{
    plan, policy_host, policy_to_apply, policy_url, txt_name, CachedPolicy, DiscoveryPlan,
    StsTxtRecord, TxtError, MAX_POLICY_ID_LEN, SUGGESTED_REFRESH_INTERVAL_SECS,
};
use pkix_mta_sts::StsPolicy;

const DAY: u64 = 86_400;
const NOW: u64 = 1_700_000_000;

/// A policy with a one-week `max_age`, the RFC's own example value.
fn week_policy() -> StsPolicy {
    StsPolicy::parse("version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n")
        .expect("parses")
}

fn cached(id: &str, fetched_at: u64) -> CachedPolicy {
    CachedPolicy::new(week_policy(), String::from(id), fetched_at)
}

fn txt(text: &str) -> StsTxtRecord {
    StsTxtRecord::parse(text).expect("TXT record should parse")
}

/// Proactive refresh disabled, to isolate the rule under test.
const NO_REFRESH: u64 = u64::MAX;

// ---------------------------------------------------------------------------
// §3.1 TXT record parsing
// ---------------------------------------------------------------------------

/// The example record from §3.1, verbatim.
#[test]
fn the_rfc_example_txt_record_parses() {
    let r = txt("v=STSv1; id=20160831085700Z;");
    assert_eq!(r.id(), "20160831085700Z");
}

#[test]
fn a_trailing_semicolon_is_optional() {
    assert_eq!(txt("v=STSv1; id=abc123").id(), "abc123");
    assert_eq!(txt("v=STSv1; id=abc123;").id(), "abc123");
}

/// §3.1's ABNF admits `sts-extension`, so unknown fields are ignored.
#[test]
fn unknown_txt_fields_are_ignored_as_extensions() {
    assert_eq!(txt("v=STSv1; id=abc123; future_field=x").id(), "abc123");
}

/// The record MUST begin with the version field (§3.1).
#[test]
fn a_record_not_beginning_with_the_version_tag_is_not_an_sts_record() {
    for bad in [
        "id=abc123; v=STSv1",
        "v=spf1 include:example.com",
        "some other txt record",
        "",
        "v=STSv2; id=abc",
    ] {
        assert_eq!(
            StsTxtRecord::parse(bad),
            Err(TxtError::NoStsRecord),
            "{bad:?} must not be read as an MTA-STS TXT record"
        );
    }
}

/// `id` is required (§3.1).
#[test]
fn id_is_required() {
    assert_eq!(StsTxtRecord::parse("v=STSv1;"), Err(TxtError::MissingId));
    assert_eq!(StsTxtRecord::parse("v=STSv1"), Err(TxtError::MissingId));
}

/// §3.1: `sts-id = %s"id=" 1*32(ALPHA / DIGIT)` — letters and digits only.
#[test]
fn an_id_must_be_one_to_thirty_two_alphanumerics() {
    assert_eq!(txt("v=STSv1; id=a").id(), "a", "one character is enough");

    let max = "a".repeat(MAX_POLICY_ID_LEN);
    assert_eq!(txt(&format!("v=STSv1; id={max}")).id(), max);

    let over = "a".repeat(MAX_POLICY_ID_LEN + 1);
    assert_eq!(
        StsTxtRecord::parse(&format!("v=STSv1; id={over}")),
        Err(TxtError::InvalidId(over))
    );

    for bad in ["", "ab-cd", "ab_cd", "ab.cd", "ab cd", "abcé"] {
        assert_eq!(
            StsTxtRecord::parse(&format!("v=STSv1; id={bad}")),
            Err(TxtError::InvalidId(String::from(bad))),
            "id {bad:?} is not 1*32(ALPHA / DIGIT)"
        );
    }
}

// ---------------------------------------------------------------------------
// §3.1 selecting among several TXT records
// ---------------------------------------------------------------------------

/// Non-MTA-STS records at the same name are discarded, not fatal.
///
/// A domain publishing SPF or verification tokens at `_mta-sts` — or, far
/// more likely, a resolver returning them — must not break MTA-STS.
#[test]
fn other_txt_records_at_the_same_name_are_discarded() {
    let r = StsTxtRecord::select([
        "v=spf1 -all",
        "google-site-verification=xyz",
        "v=STSv1; id=abc123;",
    ])
    .expect("the one STS record is selected");
    assert_eq!(r.id(), "abc123");
}

/// Two MTA-STS records is ambiguous, and §3.1 refuses to guess.
///
/// "If the number of resulting records is not one... senders MUST assume the
/// recipient domain does not have an available MTA-STS Policy." Picking
/// either would defeat the id, whose entire job is telling a sender which
/// policy is current.
#[test]
fn two_sts_records_are_ambiguous_rather_than_resolved() {
    assert_eq!(
        StsTxtRecord::select(["v=STSv1; id=aaa;", "v=STSv1; id=bbb;"]),
        Err(TxtError::MultipleStsRecords(2))
    );
}

#[test]
fn no_sts_record_among_several_is_reported_as_none() {
    assert_eq!(
        StsTxtRecord::select(["v=spf1 -all", "unrelated"]),
        Err(TxtError::NoStsRecord)
    );
    assert_eq!(StsTxtRecord::select([]), Err(TxtError::NoStsRecord));
}

// ---------------------------------------------------------------------------
// §3.1 / §3.3: the two rules that make the cache protective
// ---------------------------------------------------------------------------

/// An unusable TXT record does NOT discard a live cached policy.
///
/// §3.1: "the absence of a usable TXT record is not by itself sufficient to
/// remove a sender's previously cached policy for the Policy Domain".
///
/// The security-critical direction. If this returned `NoPolicy`, an attacker
/// could strip up to a year of protection by suppressing one DNS answer —
/// precisely the downgrade MTA-STS exists to prevent.
#[test]
fn an_unusable_txt_record_does_not_discard_a_live_cached_policy() {
    let c = cached("abc123", NOW - DAY);
    for err in [
        TxtError::NoStsRecord,
        TxtError::MissingId,
        TxtError::MultipleStsRecords(2),
        TxtError::InvalidId(String::from("!!")),
    ] {
        assert_eq!(
            plan(Some(&c), Err(&err), NOW, NO_REFRESH),
            DiscoveryPlan::UseCached,
            "TXT failure {err:?} must not drop a live cached policy"
        );
    }
}

/// With no cache, an unusable TXT record does mean no policy.
#[test]
fn an_unusable_txt_record_with_no_cache_means_no_policy() {
    assert_eq!(
        plan(None, Err(&TxtError::NoStsRecord), NOW, NO_REFRESH),
        DiscoveryPlan::NoPolicy
    );
}

/// An expired cached policy is not applied, even though it exists.
#[test]
fn an_expired_cached_policy_is_not_applied() {
    let stale = cached("abc123", NOW - 10 * DAY); // max_age is 7 days
    assert!(!stale.is_live_at(NOW));
    assert_eq!(
        plan(Some(&stale), Err(&TxtError::NoStsRecord), NOW, NO_REFRESH),
        DiscoveryPlan::NoPolicy,
        "an expired policy is not a policy"
    );
    assert_eq!(
        plan(
            Some(&stale),
            Ok(&txt("v=STSv1; id=abc123;")),
            NOW,
            NO_REFRESH
        ),
        DiscoveryPlan::Fetch,
        "the id matches but the body expired, so refetch"
    );
}

/// A changed id means refetch, whatever the cached policy's age.
#[test]
fn a_changed_policy_id_forces_a_refetch() {
    let c = cached("abc123", NOW); // fetched this instant, maximally fresh
    assert!(c.is_live_at(NOW));
    assert_eq!(
        plan(Some(&c), Ok(&txt("v=STSv1; id=def456;")), NOW, NO_REFRESH),
        DiscoveryPlan::Fetch,
        "a new id means the cached body is stale however recent it is"
    );
}

/// A matching id and a live policy needs no fetch at all.
#[test]
fn a_matching_id_and_live_policy_uses_the_cache() {
    let c = cached("abc123", NOW - 60);
    assert_eq!(
        plan(Some(&c), Ok(&txt("v=STSv1; id=abc123;")), NOW, NO_REFRESH),
        DiscoveryPlan::UseCached
    );
}

/// No cache and a usable record: fetch.
#[test]
fn no_cache_and_a_usable_record_fetches() {
    assert_eq!(
        plan(None, Ok(&txt("v=STSv1; id=abc123;")), NOW, NO_REFRESH),
        DiscoveryPlan::Fetch
    );
}

// ---------------------------------------------------------------------------
// §3.3 proactive refresh
// ---------------------------------------------------------------------------

/// A live policy past the refresh interval is refreshed, with fallback.
///
/// §3.3: "MTAs SHOULD proactively refresh cached policies before they
/// expire". §10 gives the reason — an attacker who can block refresh
/// indefinitely eventually outlasts any cached policy, so refreshing early
/// shrinks the window they must control.
#[test]
fn a_live_policy_past_the_refresh_interval_is_refreshed_with_fallback() {
    let c = cached("abc123", NOW - 2 * DAY);
    assert!(c.is_live_at(NOW), "still inside its 7-day max_age");
    assert_eq!(
        plan(
            Some(&c),
            Ok(&txt("v=STSv1; id=abc123;")),
            NOW,
            SUGGESTED_REFRESH_INTERVAL_SECS
        ),
        DiscoveryPlan::RefreshButUseCachedIfUnavailable,
        "refresh, but the live policy still applies if the fetch fails"
    );
}

/// Inside the refresh interval, no fetch.
#[test]
fn a_recently_fetched_policy_is_not_refreshed() {
    let c = cached("abc123", NOW - 60);
    assert_eq!(
        plan(
            Some(&c),
            Ok(&txt("v=STSv1; id=abc123;")),
            NOW,
            SUGGESTED_REFRESH_INTERVAL_SECS
        ),
        DiscoveryPlan::UseCached
    );
}

/// Refresh and expiry are different questions.
///
/// A policy can be live and due for refresh at once — the state proactive
/// refresh exists to act on. If one predicate implied the other, one of them
/// would be redundant.
#[test]
fn liveness_and_refresh_due_are_independent() {
    let c = cached("abc123", NOW - 2 * DAY);
    assert!(c.is_live_at(NOW));
    assert!(c.is_due_for_refresh_at(NOW, DAY));
    assert!(!c.is_due_for_refresh_at(NOW, 3 * DAY));
}

/// A clock behind the fetch time refreshes rather than trusting the age.
#[test]
fn a_clock_behind_the_fetch_time_is_due_for_refresh() {
    let c = cached("abc123", NOW);
    assert!(
        c.is_due_for_refresh_at(NOW - 1, DAY),
        "an unmeasurable age should refresh — the cheap direction to be wrong"
    );
    assert!(!c.is_live_at(NOW - 1), "and it is not live either");
}

// ---------------------------------------------------------------------------
// §3.3: which policy to apply after the fetch
// ---------------------------------------------------------------------------

/// A failed fetch falls back to a live cached policy, as §3.3 requires.
///
/// "if no 'live' policy can be discovered via DNS or fetched via HTTPS, but a
/// valid (non-expired) policy exists in the sender's cache, the sender MUST
/// apply that cached policy."
#[test]
fn a_failed_fetch_falls_back_to_a_live_cached_policy() {
    let c = cached("abc123", NOW - DAY);
    let applied = policy_to_apply(None, Some(&c), NOW);
    assert_eq!(
        applied,
        Some(c.policy()),
        "a failed fetch MUST NOT discard a live cached policy"
    );
}

/// A failed fetch with no live cache means no policy, not refusal.
///
/// §3.3: "senders MUST continue with delivery as though the domain has not
/// implemented MTA-STS." Mail stays deliverable.
#[test]
fn a_failed_fetch_with_no_live_cache_means_no_policy_not_refusal() {
    assert!(policy_to_apply(None, None, NOW).is_none());

    let stale = cached("abc123", NOW - 10 * DAY);
    assert!(
        policy_to_apply(None, Some(&stale), NOW).is_none(),
        "an expired cached policy is not a fallback"
    );
}

/// A successful fetch wins over the cache.
#[test]
fn a_fetched_policy_takes_precedence_over_the_cache() {
    let fetched =
        StsPolicy::parse("version: STSv1\nmode: testing\nmx: new.example.com\nmax_age: 86400\n")
            .expect("parses");
    let c = cached("abc123", NOW);
    let applied = policy_to_apply(Some(&fetched), Some(&c), NOW).expect("some policy applies");
    assert_eq!(applied, &fetched);
    assert_ne!(applied, c.policy());
}

// ---------------------------------------------------------------------------
// §3.1 / §3.2 / §3.4 name construction
// ---------------------------------------------------------------------------

#[test]
fn the_txt_name_and_policy_url_follow_the_rfc() {
    assert_eq!(txt_name("example.com"), "_mta-sts.example.com");
    assert_eq!(
        policy_url("example.com"),
        "https://mta-sts.example.com/.well-known/mta-sts.txt"
    );
    assert_eq!(policy_host("example.com"), "mta-sts.example.com");
}

/// A trailing dot on an absolute domain name is not carried into the names.
#[test]
fn an_absolute_domain_name_does_not_produce_a_doubled_dot() {
    assert_eq!(txt_name("example.com."), "_mta-sts.example.com");
    assert_eq!(policy_host("example.com."), "mta-sts.example.com");
    assert_eq!(
        policy_url("example.com."),
        "https://mta-sts.example.com/.well-known/mta-sts.txt"
    );
}

/// §3.4: a subdomain's policy comes from the subdomain, never the parent.
///
/// "for mail sent to `user@mail.example.com`, the policy can be fetched only
/// from `mail.example.com`, not `example.com`." So the policy domain passes
/// through unchanged and is never shortened toward the parent zone.
#[test]
fn a_subdomain_policy_domain_is_never_shortened_to_its_parent() {
    assert_eq!(txt_name("mail.example.com"), "_mta-sts.mail.example.com");
    assert_eq!(
        policy_url("mail.example.com"),
        "https://mta-sts.mail.example.com/.well-known/mta-sts.txt"
    );
    assert_eq!(policy_host("mail.example.com"), "mta-sts.mail.example.com");
}
