//! RFC 8461 §3.2 policy parsing and §4.1 MX matching.

use pkix_mta_sts::{Mode, PolicyError, PolicyOutcome, StsPolicy, MAX_AGE_LIMIT};

/// The example policy from RFC 8461 §3.2, verbatim.
const RFC_EXAMPLE: &str = "version: STSv1\r\n\
                           mode: enforce\r\n\
                           mx: mail.example.com\r\n\
                           mx: *.example.net\r\n\
                           mx: backupmx.example.com\r\n\
                           max_age: 604800\r\n";

fn policy(text: &str) -> StsPolicy {
    StsPolicy::parse(text).expect("policy should parse")
}

// ---------------------------------------------------------------------------
// §3.2 the RFC's own example
// ---------------------------------------------------------------------------

#[test]
fn the_rfc_example_policy_parses_as_written() {
    let p = policy(RFC_EXAMPLE);
    assert_eq!(p.mode(), Mode::Enforce);
    assert_eq!(p.max_age(), 604_800);
    assert_eq!(
        p.mx_patterns(),
        ["mail.example.com", "*.example.net", "backupmx.example.com"],
        "repeated mx lines accumulate in order"
    );
}

/// §3.2's narration of that example: mail "might be handled by MX
/// `mail.example.com` or any MX at `example.net`".
#[test]
fn the_rfc_example_permits_what_the_rfc_says_it_permits() {
    let p = policy(RFC_EXAMPLE);
    assert!(p.permits_mx("mail.example.com"));
    assert!(p.permits_mx("backupmx.example.com"));
    assert!(p.permits_mx("anything.example.net"));
    assert!(!p.permits_mx("example.com"), "not listed");
    assert!(!p.permits_mx("mail.example.org"), "different domain");
}

// ---------------------------------------------------------------------------
// §4.1 MX matching: "'*' may only be used to match the entire left-most label"
// ---------------------------------------------------------------------------

/// The three cases §4.1 spells out by name.
///
/// "Thus, the mx pattern `*.example.com` matches `mail.example.com` but not
/// `example.com` or `foo.bar.example.com`."
#[test]
fn the_wildcard_matches_exactly_one_label() {
    let p = policy("version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400\n");
    assert!(p.permits_mx("mail.example.com"), "one label: matches");
    assert!(!p.permits_mx("example.com"), "zero labels: no match");
    assert!(
        !p.permits_mx("foo.bar.example.com"),
        "two labels: no match — a wildcard is not a suffix match"
    );
}

/// A wildcard anywhere but the left-most label is not a wildcard.
#[test]
fn a_wildcard_in_a_later_label_is_not_honoured() {
    let p = policy("version: STSv1\nmode: enforce\nmx: mail.*.example.com\nmax_age: 86400\n");
    assert!(!p.permits_mx("mail.a.example.com"));
    assert!(!p.permits_mx("mail.example.com"));
}

/// A partial-label wildcard is not honoured either.
#[test]
fn a_partial_label_wildcard_is_not_honoured() {
    let p = policy("version: STSv1\nmode: enforce\nmx: mail*.example.com\nmax_age: 86400\n");
    assert!(!p.permits_mx("mail1.example.com"));
    assert!(!p.permits_mx("mail.example.com"));
}

/// Matching is case-insensitive; DNS names are.
#[test]
fn matching_ignores_ascii_case() {
    let p = policy("version: STSv1\nmode: enforce\nmx: Mail.Example.COM\nmax_age: 86400\n");
    assert!(p.permits_mx("mail.example.com"));
    assert!(p.permits_mx("MAIL.EXAMPLE.COM"));
}

/// Several patterns: any one matching is enough.
#[test]
fn any_matching_pattern_suffices() {
    let p = policy(RFC_EXAMPLE);
    assert!(
        p.permits_mx("backupmx.example.com"),
        "the third pattern matches even though the first two do not"
    );
}

// ---------------------------------------------------------------------------
// §3.2 required fields
// ---------------------------------------------------------------------------

#[test]
fn version_is_required() {
    let e = StsPolicy::parse("mode: enforce\nmx: a.example.com\nmax_age: 86400\n");
    assert_eq!(e, Err(PolicyError::MissingVersion));
}

#[test]
fn mode_is_required() {
    let e = StsPolicy::parse("version: STSv1\nmx: a.example.com\nmax_age: 86400\n");
    assert_eq!(e, Err(PolicyError::MissingMode));
}

#[test]
fn max_age_is_required() {
    let e = StsPolicy::parse("version: STSv1\nmode: enforce\nmx: a.example.com\n");
    assert_eq!(e, Err(PolicyError::MissingMaxAge));
}

/// §3.2: "Currently, only `STSv1` is supported."
#[test]
fn only_stsv1_is_supported() {
    let e = StsPolicy::parse("version: STSv2\nmode: enforce\nmx: a.example.com\nmax_age: 1\n");
    assert_eq!(
        e,
        Err(PolicyError::UnsupportedVersion(String::from("STSv2"))),
        "the value is carried so a caller can log what the domain published"
    );
}

#[test]
fn an_unknown_mode_is_rejected() {
    let e = StsPolicy::parse("version: STSv1\nmode: strict\nmx: a.example.com\nmax_age: 1\n");
    assert_eq!(e, Err(PolicyError::UnknownMode(String::from("strict"))));
}

/// §3.2: `mx` is "required at least once, except when mode is `none`".
#[test]
fn mx_is_required_unless_the_mode_is_none() {
    assert_eq!(
        StsPolicy::parse("version: STSv1\nmode: enforce\nmax_age: 86400\n"),
        Err(PolicyError::MissingMx)
    );
    assert_eq!(
        StsPolicy::parse("version: STSv1\nmode: testing\nmax_age: 86400\n"),
        Err(PolicyError::MissingMx)
    );
    let withdrawn = StsPolicy::parse("version: STSv1\nmode: none\nmax_age: 86400\n")
        .expect("mode none needs no mx — §8.3 uses it to withdraw MTA-STS");
    assert_eq!(withdrawn.mode(), Mode::None);
    assert!(withdrawn.mx_patterns().is_empty());
}

// ---------------------------------------------------------------------------
// §3.2 max_age bounds
// ---------------------------------------------------------------------------

/// "maximum value of 31557600" — the boundary itself is legal.
#[test]
fn max_age_accepts_its_stated_maximum() {
    let p = policy(&format!(
        "version: STSv1\nmode: enforce\nmx: a.example.com\nmax_age: {MAX_AGE_LIMIT}\n"
    ));
    assert_eq!(p.max_age(), MAX_AGE_LIMIT);
    assert_eq!(MAX_AGE_LIMIT, 31_557_600, "a Julian year, per §3.2");
}

#[test]
fn max_age_rejects_one_past_its_maximum() {
    let over = MAX_AGE_LIMIT + 1;
    assert_eq!(
        StsPolicy::parse(&format!(
            "version: STSv1\nmode: enforce\nmx: a.example.com\nmax_age: {over}\n"
        )),
        Err(PolicyError::InvalidMaxAge(over.to_string()))
    );
}

/// "plaintext non-negative integer seconds" — so not a negative, not a float,
/// not a duration string.
#[test]
fn max_age_rejects_anything_but_a_non_negative_integer() {
    for bad in ["-1", "1.5", "7d", "", "0x10", "6_048_00", "+604800"] {
        let text = format!("version: STSv1\nmode: enforce\nmx: a.example.com\nmax_age: {bad}\n");
        assert!(
            matches!(
                StsPolicy::parse(&text),
                Err(PolicyError::InvalidMaxAge(_) | PolicyError::MissingMaxAge)
            ),
            "max_age {bad:?} should be rejected"
        );
    }
}

/// Trailing whitespace after a value is legal, so it must not be rejected.
///
/// §3.2's ABNF is `sts-policy-field *WSP`, which explicitly permits it. This
/// is asserted rather than assumed because the obvious strict reading — that
/// a `max_age` value must be digits and nothing else — would reject a
/// conforming policy.
#[test]
fn trailing_whitespace_after_a_value_is_permitted_by_the_abnf() {
    let p = policy("version: STSv1 \nmode: enforce\t\nmx: a.example.com  \nmax_age: 604800 \n");
    assert_eq!(p.max_age(), 604_800);
    assert_eq!(p.mx_patterns(), ["a.example.com"]);
    assert_eq!(p.mode(), Mode::Enforce);
}

/// Zero is a non-negative integer and so is legal, though it expires at once.
#[test]
fn max_age_zero_parses_and_is_never_live() {
    let p = policy("version: STSv1\nmode: enforce\nmx: a.example.com\nmax_age: 0\n");
    assert_eq!(p.max_age(), 0);
    assert!(!p.is_live_at(1_000, 1_000), "age 0 is not < max_age 0");
}

// ---------------------------------------------------------------------------
// §3.2 ABNF: extensions, whitespace, line endings
// ---------------------------------------------------------------------------

/// The ABNF admits `sts-policy-extension`, so unknown keys are ignored.
///
/// A sender that rejected them would break on the first extension anyone
/// deploys, which is the opposite of what an extension point is for.
#[test]
fn unknown_fields_are_ignored_as_extensions() {
    let p = policy(
        "version: STSv1\nmode: enforce\nmx: a.example.com\nmax_age: 86400\n\
         future_field: whatever\nanother: 42\n",
    );
    assert_eq!(p.mode(), Mode::Enforce);
    assert_eq!(p.mx_patterns(), ["a.example.com"]);
}

/// Bare LF is accepted alongside CRLF.
///
/// The ABNF says CRLF, but a policy is served over HTTP by arbitrary web
/// servers and failing a domain over line endings would break deployments
/// that work everywhere else.
#[test]
fn both_crlf_and_lf_are_accepted() {
    let crlf = policy(RFC_EXAMPLE);
    let lf = policy(&RFC_EXAMPLE.replace("\r\n", "\n"));
    assert_eq!(crlf, lf);
}

#[test]
fn blank_lines_and_surrounding_whitespace_are_ignored() {
    let p = policy(
        "\n  version:  STSv1  \n\n\tmode:\tenforce\t\n\n  mx:  a.example.com  \n\nmax_age: 86400\n\n",
    );
    assert_eq!(p.mode(), Mode::Enforce);
    assert_eq!(p.max_age(), 86_400);
    assert_eq!(p.mx_patterns(), ["a.example.com"]);
}

#[test]
fn a_line_without_a_colon_is_malformed() {
    let e = StsPolicy::parse("version: STSv1\nthis is not a field\nmode: none\nmax_age: 1\n");
    assert_eq!(
        e,
        Err(PolicyError::MalformedLine(String::from(
            "this is not a field"
        )))
    );
}

/// Keys are matched case-insensitively.
#[test]
fn field_names_ignore_case() {
    let p = policy("VERSION: STSv1\nMode: Enforce\nMX: a.example.com\nMAX_AGE: 86400\n");
    assert_eq!(p.mode(), Mode::Enforce);
    assert_eq!(p.max_age(), 86_400);
}

/// An HTML error page served at the policy path must not parse as a policy.
///
/// §3.3 has senders validate the media type for exactly this reason; a
/// parser that accepted whatever came back would make that check the only
/// defence.
#[test]
fn an_html_error_page_is_not_a_policy() {
    assert!(StsPolicy::parse("<!DOCTYPE html>\n<html><body>404</body></html>\n").is_err());
}

// ---------------------------------------------------------------------------
// §5 policy application
// ---------------------------------------------------------------------------

#[test]
fn enforce_mode_forbids_delivery_to_a_non_matching_host() {
    let p = policy(RFC_EXAMPLE);
    let outcome = p.evaluate("evil.example.org");
    assert_eq!(outcome, PolicyOutcome::FailedEnforce);
    assert!(
        !outcome.mta_sts_permits_delivery(),
        "§5: MUST NOT deliver to hosts that fail MX matching"
    );
    assert!(outcome.is_validation_failure());
}

#[test]
fn testing_mode_permits_delivery_but_still_reports_a_failure() {
    let p = policy("version: STSv1\nmode: testing\nmx: a.example.com\nmax_age: 86400\n");
    let outcome = p.evaluate("evil.example.org");
    assert_eq!(outcome, PolicyOutcome::FailedTesting);
    assert!(
        outcome.mta_sts_permits_delivery(),
        "§5: deliver as though there were no MTA-STS validation failure"
    );
    assert!(
        outcome.is_validation_failure(),
        "it is still a failure — this is the distinction testing mode exists \
         to create, and what TLSRPT reports on"
    );
}

/// The two predicates differ exactly on `testing`.
///
/// If they agreed everywhere, one of them would be redundant and `testing`
/// mode would be unimplementable.
#[test]
fn the_delivery_decision_and_the_failure_fact_are_separate() {
    let testing = PolicyOutcome::FailedTesting;
    assert!(testing.mta_sts_permits_delivery() && testing.is_validation_failure());

    let enforce = PolicyOutcome::FailedEnforce;
    assert!(!enforce.mta_sts_permits_delivery() && enforce.is_validation_failure());

    let matched = PolicyOutcome::Matched;
    assert!(matched.mta_sts_permits_delivery() && !matched.is_validation_failure());
}

/// §5: mode `none` means "treat the Policy Domain as though it does not have
/// any active policy".
#[test]
fn mode_none_has_no_active_policy_and_permits_nothing() {
    let p = policy("version: STSv1\nmode: none\nmx: a.example.com\nmax_age: 86400\n");
    assert_eq!(p.evaluate("a.example.com"), PolicyOutcome::NoActivePolicy);
    assert_eq!(
        p.evaluate("evil.example.org"),
        PolicyOutcome::NoActivePolicy
    );
    assert!(
        !p.permits_mx("a.example.com"),
        "an mx list under mode none permits nothing; false is the safe answer"
    );
    assert!(
        p.evaluate("a.example.com").mta_sts_permits_delivery(),
        "no active policy raises no objection to delivery"
    );
    assert!(!p.evaluate("a.example.com").is_validation_failure());
}

#[test]
fn only_enforce_forbids_delivery_on_failure() {
    assert!(Mode::Enforce.forbids_delivery_on_failure());
    assert!(!Mode::Testing.forbids_delivery_on_failure());
    assert!(!Mode::None.forbids_delivery_on_failure());
}

#[test]
fn a_matching_host_in_enforce_mode_is_matched() {
    let p = policy(RFC_EXAMPLE);
    let outcome = p.evaluate("mail.example.com");
    assert_eq!(outcome, PolicyOutcome::Matched);
    assert!(outcome.mta_sts_permits_delivery());
    assert!(!outcome.is_validation_failure());
}

// ---------------------------------------------------------------------------
// §3.2 max_age runs "from the last policy fetch time"
// ---------------------------------------------------------------------------

#[test]
fn freshness_is_measured_from_the_fetch_time() {
    let p = policy("version: STSv1\nmode: enforce\nmx: a.example.com\nmax_age: 100\n");
    let fetched = 1_000_000;
    assert!(p.is_live_at(fetched, fetched), "age 0");
    assert!(p.is_live_at(fetched, fetched + 99), "one second to spare");
    assert!(
        !p.is_live_at(fetched, fetched + 100),
        "age == max_age expires"
    );
    assert!(!p.is_live_at(fetched, fetched + 10_000));
}

/// A clock behind the fetch time yields false rather than treating an
/// unmeasurable age as fresh.
///
/// The alternative — saturating the subtraction to zero — would make a
/// policy live indefinitely whenever the clock went backwards, which is the
/// wrong direction to fail for a cache whose whole purpose is bounding how
/// long a stale policy is honoured.
#[test]
fn a_clock_behind_the_fetch_time_is_not_fresh() {
    let p = policy("version: STSv1\nmode: enforce\nmx: a.example.com\nmax_age: 86400\n");
    assert!(!p.is_live_at(1_000_000, 999_999));
    assert!(!p.is_live_at(1_000_000, 0));
}

// ---------------------------------------------------------------------------
// The wildcard rule is pkix-identity's, not a second copy
// ---------------------------------------------------------------------------

/// `permits_mx` agrees with `pkix_identity::dns_name_matches_pattern`.
///
/// RFC 8461 §4.1 defines MX matching by reference to RFC 6125, so this crate
/// delegates rather than restating it. This test is the guard on that: if
/// anyone reimplements the rule here, the two will drift and this fails.
#[test]
fn mx_matching_delegates_to_the_shared_rfc6125_rule() {
    let cases = [
        ("*.example.com", "mail.example.com"),
        ("*.example.com", "example.com"),
        ("*.example.com", "a.b.example.com"),
        ("mail.example.com", "mail.example.com"),
        ("mail.example.com", "other.example.com"),
        ("*.com", "example.com"),
        ("MAIL.EXAMPLE.COM", "mail.example.com"),
    ];
    for (pattern, host) in cases {
        let p = policy(&format!(
            "version: STSv1\nmode: enforce\nmx: {pattern}\nmax_age: 1\n"
        ));
        assert_eq!(
            p.permits_mx(host),
            pkix_identity::dns_name_matches_pattern(pattern, host),
            "pattern {pattern:?} against {host:?} must match pkix-identity"
        );
    }
}

/// The ABNF caps `max_age` at ten digits, independently of its value cap.
///
/// Eleven digits is a malformed field even though the value would be rejected
/// by [`MAX_AGE_LIMIT`] anyway. Asserted so the grammar rule is not silently
/// dropped on the grounds that the value check subsumes it.
#[test]
fn max_age_rejects_more_than_ten_digits() {
    let e = StsPolicy::parse(
        "version: STSv1\nmode: enforce\nmx: a.example.com\nmax_age: 12345678901\n",
    );
    assert_eq!(
        e,
        Err(PolicyError::InvalidMaxAge(String::from("12345678901")))
    );
}

/// Case-insensitive keyword matching is a deliberate deviation from the ABNF.
///
/// §3.2 writes every keyword with RFC 7405's `%s` prefix, which means
/// case-sensitive, so `mode: Enforce` is strictly non-conforming. This crate
/// accepts it, because the alternative is reporting no policy at all — and a
/// sender with no policy applies no protection. Leniency yields enforce;
/// strictness yields plaintext.
///
/// A test rather than a comment, so the choice cannot be "fixed" into
/// strictness without someone reading the reason.
#[test]
fn miscased_keywords_are_honoured_rather_than_dropping_protection() {
    let p = policy("Version: STSv1\nMODE: Enforce\nMx: a.example.com\nMax_Age: 86400\n");
    assert_eq!(
        p.mode(),
        Mode::Enforce,
        "strict case matching would report no policy, and no policy means no \
         protection — the wrong direction to fail"
    );
}

/// A future version is still refused, which case-insensitivity does not
/// weaken: `STSv2` differs from `STSv1` in a digit, not in case.
#[test]
fn case_insensitivity_does_not_let_a_future_version_through() {
    assert!(
        StsPolicy::parse("version: stsv1\nmode: enforce\nmx: a.example.com\nmax_age: 1\n").is_ok()
    );
    assert_eq!(
        StsPolicy::parse("version: STSV2\nmode: enforce\nmx: a.example.com\nmax_age: 1\n"),
        Err(PolicyError::UnsupportedVersion(String::from("STSV2")))
    );
}
