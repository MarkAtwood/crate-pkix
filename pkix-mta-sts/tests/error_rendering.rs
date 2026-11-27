//! What `PolicyError` and `TxtError` say when something asks.
//!
//! Neither `Display` has a caller inside the crate: parsing returns the
//! error and rendering it is the caller's business. A sender that cannot
//! fetch or parse a domain's policy has to say why -- RFC 8461 §5 makes
//! that a routing decision, not a crash -- so these messages are the
//! operator-facing half of the whole crate, and a `Display` that writes
//! nothing still returns `Ok`.
//!
//! Each error is produced through the public parser rather than
//! constructed, so the variants here are the ones a caller receives.

use pkix_mta_sts::discovery::{StsTxtRecord, TxtError};
use pkix_mta_sts::{PolicyError, StsPolicy};

fn policy_error(text: &str) -> PolicyError {
    StsPolicy::parse(text).expect_err("this policy must not parse")
}

/// One of every `PolicyError`, with the input that produces it.
fn every_policy_error() -> Vec<(&'static str, PolicyError)> {
    vec![
        ("MissingVersion", policy_error("mode: none\nmax_age: 1\n")),
        (
            "UnsupportedVersion",
            policy_error("version: STSv2\nmode: none\nmax_age: 1\n"),
        ),
        ("MissingMode", policy_error("version: STSv1\nmax_age: 1\n")),
        (
            "UnknownMode",
            policy_error("version: STSv1\nmode: sideways\nmax_age: 1\n"),
        ),
        (
            "MissingMaxAge",
            policy_error("version: STSv1\nmode: none\n"),
        ),
        (
            "InvalidMaxAge",
            policy_error("version: STSv1\nmode: none\nmax_age: +1\n"),
        ),
        (
            "MissingMx",
            policy_error("version: STSv1\nmode: enforce\nmax_age: 1\n"),
        ),
        (
            "MalformedLine",
            policy_error("version: STSv1\nthis line has no colon\nmode: none\nmax_age: 1\n"),
        ),
    ]
}

/// One of every `TxtError`.
fn every_txt_error() -> Vec<(&'static str, TxtError)> {
    let err = |s: &str| StsTxtRecord::parse(s).expect_err("this record must not parse");
    vec![
        ("NoStsRecord", err("v=spf1 -all")),
        ("MissingId", err("v=STSv1;")),
        ("InvalidId", err("v=STSv1; id=not/valid;")),
        ("MalformedField", err("v=STSv1; id=abc; novalue;")),
    ]
}

/// Every `PolicyError` renders something, and no two render the same
/// thing.
///
/// An operator reading "policy has no mode field" can fix it; an empty
/// message, or one shared with another variant, tells them a policy
/// failed and nothing more.
#[test]
fn every_policy_error_renders_a_distinct_message() {
    let errors = every_policy_error();
    let rendered: Vec<String> = errors.iter().map(|(_, e)| format!("{e}")).collect();
    for ((name, _), text) in errors.iter().zip(&rendered) {
        assert!(!text.is_empty(), "PolicyError::{name} renders nothing");
    }
    for (i, a) in rendered.iter().enumerate() {
        for (j, b) in rendered.iter().enumerate().skip(i + 1) {
            assert_ne!(
                a, b,
                "PolicyError::{} and PolicyError::{} render the same message",
                errors[i].0, errors[j].0
            );
        }
    }
}

/// And every `TxtError` likewise.
///
/// These are the discovery-side failures, which decide whether a sender
/// treats a domain as having no policy or as having an unreadable one.
#[test]
fn every_txt_error_renders_a_distinct_message() {
    let errors = every_txt_error();
    let rendered: Vec<String> = errors.iter().map(|(_, e)| format!("{e}")).collect();
    for ((name, _), text) in errors.iter().zip(&rendered) {
        assert!(!text.is_empty(), "TxtError::{name} renders nothing");
    }
    for (i, a) in rendered.iter().enumerate() {
        for (j, b) in rendered.iter().enumerate().skip(i + 1) {
            assert_ne!(
                a, b,
                "TxtError::{} and TxtError::{} render the same message",
                errors[i].0, errors[j].0
            );
        }
    }
}

/// The messages name the value that was wrong.
///
/// A rendering that said only "invalid max_age" would leave an operator
/// grepping their own policy file for which field the sender objected
/// to. These three carry the offending text.
#[test]
fn the_messages_quote_what_was_wrong() {
    for (needle, err) in [
        (
            "STSv2",
            policy_error("version: STSv2\nmode: none\nmax_age: 1\n"),
        ),
        (
            "sideways",
            policy_error("version: STSv1\nmode: sideways\nmax_age: 1\n"),
        ),
        (
            "+1",
            policy_error("version: STSv1\nmode: none\nmax_age: +1\n"),
        ),
    ] {
        let text = format!("{err}");
        assert!(
            text.contains(needle),
            "the message must quote {needle:?}; got {text:?}"
        );
    }
}
