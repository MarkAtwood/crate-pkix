//! The §3.3 / §3.2 response rules, without a network.
//!
//! The status and media-type checks are shared by both backends precisely so
//! they cannot diverge, which makes them testable directly. The transport
//! behaviour that needs a live server — redirects not followed, the
//! destination policy — is in `live_server.rs`.

use pkix_mta_sts_http::{policy_request_url, well_known_path, FetchError, FetcherConfig};

// ---------------------------------------------------------------------------
// §3.3 status rules
// ---------------------------------------------------------------------------

/// A 3xx is reported as a refused redirect, not as a plain status.
///
/// §3.3: "HTTP 3xx redirects MUST NOT be followed." Reported distinctly
/// because it is a misconfiguration an operator can fix, and because a sender
/// seeing it must not conclude the domain has no policy.
#[test]
fn a_redirect_is_reported_as_refused_not_as_absent() {
    let e = FetchError::RedirectRefused(301);
    assert!(e.to_string().contains("forbids"), "{e}");
    assert_ne!(e, FetchError::HttpStatus(301));
}

// ---------------------------------------------------------------------------
// §3.2 media type
// ---------------------------------------------------------------------------

#[test]
fn the_default_config_applies_the_rfc_suggested_limits() {
    let c = FetcherConfig::default();
    assert_eq!(c.max_body_bytes, 64 * 1024, "§3.3 suggests 64 kilobytes");
    assert_eq!(c.timeout_secs, 60, "§3.3 suggests one minute");
    assert!(
        c.require_text_plain,
        "on by default although §3.2 words it as SHOULD"
    );
    assert!(
        c.refuse_non_public_addresses,
        "the destination policy is on by default"
    );
}

// ---------------------------------------------------------------------------
// §3.2 URL construction
// ---------------------------------------------------------------------------

#[test]
fn the_url_is_the_well_known_path_on_the_policy_host() {
    assert_eq!(
        policy_request_url("example.com"),
        "https://mta-sts.example.com/.well-known/mta-sts.txt"
    );
    assert_eq!(well_known_path(), "/.well-known/mta-sts.txt");
    assert!(
        policy_request_url("example.com").starts_with("https://"),
        "a policy is never fetched over plaintext HTTP"
    );
}

/// §3.4: a subdomain's policy host is built from the subdomain.
#[test]
fn a_subdomain_gets_its_own_policy_host() {
    assert_eq!(
        policy_request_url("mail.example.com"),
        "https://mta-sts.mail.example.com/.well-known/mta-sts.txt"
    );
}

// ---------------------------------------------------------------------------
// Error surface
// ---------------------------------------------------------------------------

/// A malformed policy keeps the parse error as its source.
///
/// So an operator sees which field was wrong rather than only that the fetch
/// failed, and the outer message does not repeat the inner one.
#[test]
fn a_malformed_policy_exposes_the_parse_error_as_its_source() {
    use std::error::Error as _;
    let inner = pkix_mta_sts::PolicyError::MissingMode;
    let e = FetchError::Malformed(inner.clone());
    assert_eq!(e.source().map(ToString::to_string), Some(inner.to_string()));
    assert!(
        !e.to_string().ends_with(&inner.to_string())
            || e.to_string().contains("not a valid policy"),
        "the outer message adds context rather than only restating the inner"
    );
}

/// A destination refusal is not a transport failure.
///
/// They call for different operator action: one is a misconfigured or hostile
/// recipient domain, the other is a network problem.
#[test]
fn a_destination_refusal_is_distinct_from_a_transport_failure() {
    let refused = FetchError::DestinationRefused(String::from("mta-sts.x.test"));
    let transport = FetchError::Transport(String::from("mta-sts.x.test"));
    assert_ne!(refused, transport);
    assert!(refused.to_string().contains("refused"));
}

// ---------------------------------------------------------------------------
// The shared checks, directly
// ---------------------------------------------------------------------------

/// §3.3: "only valid if the HTTP response code is 200 (OK)".
#[test]
fn check_status_accepts_only_200() {
    use pkix_mta_sts_http::check_status;
    assert_eq!(check_status(200), Ok(()));
    for code in [201, 204, 400, 403, 404, 410, 500, 502, 503] {
        assert_eq!(
            check_status(code),
            Err(FetchError::HttpStatus(code)),
            "HTTP {code} is not a policy"
        );
    }
}

/// Every 3xx is a refused redirect, not a plain status.
#[test]
fn check_status_reports_every_3xx_as_a_refused_redirect() {
    use pkix_mta_sts_http::check_status;
    for code in [300, 301, 302, 303, 307, 308, 399] {
        assert_eq!(
            check_status(code),
            Err(FetchError::RedirectRefused(code)),
            "HTTP {code} must be a refused redirect"
        );
    }
}

/// §3.2: "All parameters other than charset=utf-8 or charset=us-ascii are
/// ignored. Additional `Content-Type` parameters are also ignored."
#[test]
fn check_media_type_ignores_parameters() {
    use pkix_mta_sts_http::check_media_type;
    for ct in [
        "text/plain",
        "text/plain; charset=utf-8",
        "text/plain; charset=us-ascii",
        "text/plain;charset=UTF-8",
        "TEXT/PLAIN",
        "text/plain; boundary=x; charset=utf-8",
        "  text/plain  ",
    ] {
        assert_eq!(
            check_media_type(Some(ct), true),
            Ok(()),
            "{ct:?} is text/plain with parameters"
        );
    }
}

/// The types a hostile or misconfigured policy host would serve.
///
/// §3.2's reason for the check: a web server "that allows untrusted users to
/// host non-text content (typically, HTML or images) at a user-defined path"
/// is otherwise a way to publish a policy for a domain you do not control.
#[test]
fn check_media_type_refuses_non_text_types() {
    use pkix_mta_sts_http::check_media_type;
    for ct in [
        "text/html",
        "application/json",
        "image/png",
        "text/plain-ish",
        "application/octet-stream",
    ] {
        assert!(
            matches!(
                check_media_type(Some(ct), true),
                Err(FetchError::UnexpectedMediaType(_))
            ),
            "{ct:?} must be refused"
        );
    }
}

/// A missing Content-Type is accepted; refusing it would reject deployments
/// the RFC does not.
#[test]
fn check_media_type_accepts_an_absent_header() {
    use pkix_mta_sts_http::check_media_type;
    assert_eq!(check_media_type(None, true), Ok(()));
}

/// With the check relaxed, nothing is refused on type.
#[test]
fn check_media_type_can_be_relaxed() {
    use pkix_mta_sts_http::check_media_type;
    assert_eq!(check_media_type(Some("text/html"), false), Ok(()));
    assert_eq!(check_media_type(None, false), Ok(()));
}
