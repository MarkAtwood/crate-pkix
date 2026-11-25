//! The TXT lookup: construction, the error bridge, and live queries.
//!
//! §3.1's selection rules are tested where they live, in `pkix-mta-sts`'s
//! `discovery` suite, against the character-string forms a resolver produces.
//! What is left here is this crate's own behaviour: that a failure feeds
//! `plan` without discarding a cached policy, and that a real lookup works.
//!
//! The live tests are marked `#[ignore]` so the suite stays offline by
//! default. Run them with `--ignored` when a network is available.

use pkix_mta_sts::discovery::{DiscoveryPlan, TxtError};
use pkix_mta_sts::{plan, CachedPolicy, StsPolicy};
use pkix_mta_sts_resolver::{LookupErrorKind, MtaStsResolver, ResolverError};

const NOW: u64 = 1_700_000_000;

fn week_policy() -> StsPolicy {
    StsPolicy::parse("version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n")
        .expect("parses")
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

#[test]
fn a_system_resolver_can_be_built() {
    assert!(
        MtaStsResolver::from_system().is_ok(),
        "the system resolver configuration should be readable"
    );
}

#[test]
fn explicit_name_servers_can_be_given() {
    let servers = ["1.1.1.1:53".parse().unwrap(), "8.8.8.8:53".parse().unwrap()];
    assert!(MtaStsResolver::from_name_servers(&servers).is_ok());
}

/// An empty name-server list is refused rather than silently useless.
///
/// A resolver with nowhere to ask would fail every lookup as a DNS error,
/// which §3.1 has a sender treat as "no policy" — so every domain would look
/// like it had not deployed MTA-STS, and nothing would appear broken.
#[test]
fn no_name_servers_is_an_error_not_a_silent_no_op() {
    assert!(matches!(
        MtaStsResolver::from_name_servers(&[]),
        Err(ResolverError::Construction(_))
    ));
}

// ---------------------------------------------------------------------------
// The error bridge: §3.1's rule must survive a lookup failure
// ---------------------------------------------------------------------------

/// A lookup failure fed through `as_txt_error` keeps a live cached policy.
///
/// The test that matters for this crate. §3.1: "the absence of a usable TXT
/// record is not by itself sufficient to remove a sender's previously cached
/// policy." A caller that translated a lookup failure into "no policy"
/// directly would strip up to a year of protection on one failed DNS query —
/// so `as_txt_error` exists to route the failure through `plan`, which
/// applies the rule.
#[tokio::test]
async fn a_lookup_failure_does_not_discard_a_live_cached_policy() {
    let resolver = MtaStsResolver::from_system().expect("builds");
    // A reserved TLD that cannot resolve (RFC 2606), so this is offline-safe.
    let err = resolver
        .lookup("nonexistent-mta-sts-probe.invalid")
        .await
        .expect_err("an .invalid domain has no policy");

    let cached = CachedPolicy::new(week_policy(), String::from("abc123"), NOW - 3600);
    assert_eq!(
        plan(Some(&cached), Err(err.as_txt_error()), NOW, u64::MAX),
        DiscoveryPlan::UseCached,
        "one failed lookup must not strip a cached policy"
    );
}

/// And with no cache, the same failure does mean no policy.
#[tokio::test]
async fn a_lookup_failure_with_no_cache_means_no_policy() {
    let resolver = MtaStsResolver::from_system().expect("builds");
    let err = resolver
        .lookup("nonexistent-mta-sts-probe.invalid")
        .await
        .expect_err("no policy");
    assert_eq!(
        plan(None, Err(err.as_txt_error()), NOW, u64::MAX),
        DiscoveryPlan::NoPolicy
    );
}

/// The kind distinguishes a missing policy from a broken resolver.
///
/// Identical for delivery, different for diagnosis: §3.3 asks senders to
/// "alert administrators... when such attempts fail", and an operator needs
/// to tell "this domain has no policy" from "our DNS is down".
#[tokio::test]
async fn the_error_kind_separates_no_policy_from_a_broken_resolver() {
    let resolver = MtaStsResolver::from_system().expect("builds");
    let err = resolver
        .lookup("nonexistent-mta-sts-probe.invalid")
        .await
        .expect_err("no policy");

    // Whichever it is, both map to the same TxtError for `plan`.
    assert_eq!(err.as_txt_error(), &TxtError::NoStsRecord);
    assert!(
        matches!(
            err.kind(),
            LookupErrorKind::NoRecords | LookupErrorKind::Dns(_)
        ),
        "an .invalid lookup is either an authoritative no-records or a DNS \
         failure, depending on the resolver; got {:?}",
        err.kind()
    );
}

/// The §3.1 ambiguity error explains itself rather than only counting.
///
/// An operator who publishes two MTA-STS TXT records sees no policy applied
/// and needs to know why; "2 records, which is ambiguous" is actionable where
/// a bare count is not.
#[test]
fn the_ambiguity_error_explains_itself() {
    let e = TxtError::MultipleStsRecords(2);
    let msg = e.to_string();
    assert!(msg.contains("ambiguous"), "{msg}");
    assert!(msg.contains("exactly one"), "{msg}");
}

// ---------------------------------------------------------------------------
// Live queries
// ---------------------------------------------------------------------------

/// A domain that publishes MTA-STS yields a usable record.
///
/// Gmail has published a policy since the RFC was new. Ignored by default so
/// the suite is offline; this asserts the wire format is handled, not that
/// Google keeps publishing.
#[tokio::test]
#[ignore = "requires network"]
async fn a_real_domain_yields_a_policy_id() {
    let resolver = MtaStsResolver::from_system().expect("builds");
    let record = resolver
        .lookup("gmail.com")
        .await
        .expect("gmail.com publishes an _mta-sts TXT record");
    assert!(
        !record.id().is_empty() && record.id().len() <= 32,
        "the id is 1*32(ALPHA / DIGIT): {:?}",
        record.id()
    );
    assert!(
        record.id().bytes().all(|b| b.is_ascii_alphanumeric()),
        "the id is alphanumeric: {:?}",
        record.id()
    );
}

/// A domain with no MTA-STS yields no record, not an error a caller must
/// special-case.
#[tokio::test]
#[ignore = "requires network"]
async fn a_domain_without_mta_sts_yields_no_record() {
    let resolver = MtaStsResolver::from_system().expect("builds");
    let err = resolver
        .lookup("example.com")
        .await
        .expect_err("example.com publishes no MTA-STS policy");
    assert_eq!(err.as_txt_error(), &TxtError::NoStsRecord);
}

/// §3.4: a subdomain is queried as itself, never as its parent.
///
/// "for mail sent to `user@mail.example.com`, the policy can be fetched only
/// from `mail.example.com`, not `example.com`." So a subdomain of a
/// policy-publishing domain must not inherit the parent's record.
#[tokio::test]
#[ignore = "requires network"]
async fn a_subdomain_does_not_inherit_its_parents_policy() {
    let resolver = MtaStsResolver::from_system().expect("builds");
    let parent = resolver.lookup("gmail.com").await;
    assert!(parent.is_ok(), "the parent publishes a policy");

    let sub = resolver
        .lookup("no-such-label.gmail.com")
        .await
        .expect_err("a subdomain must not inherit the parent's record");
    assert_eq!(sub.as_txt_error(), &TxtError::NoStsRecord);
}
