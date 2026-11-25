//! Telling a certificate failure from a network failure — RFC 8461 §3.3.
//!
//! The HTTPS certificate is an MTA-STS policy's **only** authentication: the
//! `_mta-sts` TXT record is unsigned and the policy body carries no
//! signature. So "the certificate did not validate" means the policy may have
//! been written by whoever is on the path, while "the connection was refused"
//! means the web server is down. RFC 8460 §4.3.2.2 reports them as
//! `sts-webpki-invalid` and `sts-policy-fetch-error`.
//!
//! Both directions are asserted. Recognising a bad certificate is only half
//! of it: a false positive would tell a domain its certificate is broken
//! whenever its policy host was unreachable, which is the harm that kept this
//! unimplemented until the detection could be shown not to misfire.
//!
//! The bad-certificate cases need a server presenting one, so they use
//! `badssl.com` and are `#[ignore]`d. Run with `cargo test -- --ignored`.

use pkix_mta_sts_http::{certificate_failure, FetchError};

const BAD_CERT_HOSTS: &[&str] = &["expired", "self-signed", "untrusted-root"];

// ---------------------------------------------------------------------------
// Negative direction: offline, and the one that matters most
// ---------------------------------------------------------------------------

/// A refused connection is not a certificate failure.
///
/// `mta-sts.localhost` resolves to loopback, so with the destination guard
/// off the connection is attempted and refused. Nothing presents a
/// certificate, so nothing may be said about one.
#[cfg(feature = "client-ureq")]
#[test]
fn a_refused_connection_is_not_a_certificate_failure() {
    use pkix_mta_sts_http::{FetcherConfig, PolicyFetcher};
    let fetcher = PolicyFetcher::with_config(FetcherConfig {
        refuse_non_public_addresses: false,
        ..FetcherConfig::default()
    });
    let got = fetcher.fetch("localhost");
    assert!(
        !matches!(got, Err(FetchError::TlsValidation(_))),
        "a refused connection must not be reported as a certificate \
         failure — it would send an operator after a certificate that is \
         fine; got {got:?}"
    );
    assert!(got.is_err(), "nothing is listening: {got:?}");
}

/// A destination refusal is not a certificate failure either.
///
/// This one never reaches TLS at all, so a detector that fired here would be
/// matching on something unrelated to the handshake.
#[cfg(feature = "client-ureq")]
#[test]
fn a_destination_refusal_is_not_a_certificate_failure() {
    use pkix_mta_sts_http::PolicyFetcher;
    let got = PolicyFetcher::new().fetch("localhost");
    assert!(
        matches!(got, Err(FetchError::DestinationRefused(_))),
        "expected a destination refusal, got {got:?}"
    );
}

/// A name that does not resolve is not a certificate failure.
#[cfg(feature = "client-ureq")]
#[test]
#[ignore = "requires network"]
fn an_unresolvable_host_is_not_a_certificate_failure() {
    use pkix_mta_sts_http::PolicyFetcher;
    let got = PolicyFetcher::new().fetch("no-such-mta-sts-host.invalid");
    assert!(
        !matches!(got, Err(FetchError::TlsValidation(_))),
        "a DNS failure must not be reported as a certificate failure: {got:?}"
    );
    assert!(got.is_err());
}

// ---------------------------------------------------------------------------
// Positive direction: a server presenting a certificate that does not validate
// ---------------------------------------------------------------------------

/// Every class of bad certificate is recognised, on the sync backend.
///
/// `badssl.com` serves certificates that are expired, self-signed and signed
/// by an untrusted root. The determination under test is
/// `certificate_failure`, driven from a real `ureq` error, which is the same
/// function the fetcher uses.
#[cfg(feature = "client-ureq")]
#[test]
#[ignore = "requires network"]
fn the_sync_backend_recognises_a_bad_certificate() {
    for case in BAD_CERT_HOSTS {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(20)))
            .build()
            .into();
        let url = format!("https://{case}.badssl.com/");
        let Err(e) = agent.get(&url).call() else {
            panic!("{case}.badssl.com should not have validated");
        };
        // ureq buries the rustls error in Error::Io's payload.
        let found = if let ureq::Error::Io(io) = &e {
            io.get_ref().and_then(|i| certificate_failure(i))
        } else {
            certificate_failure(&e)
        };
        assert!(
            found.is_some(),
            "{case}.badssl.com must be recognised as a certificate failure; \
             the error was {e}"
        );
    }
}

/// The async backend recognises the same cases.
///
/// Asserted separately because `reqwest` does not preserve the `rustls` type
/// — the detection falls back to rustls's own message there — so a change
/// that worked for `ureq` could silently leave the async path unable to
/// report `sts-webpki-invalid`.
#[cfg(feature = "client-reqwest")]
#[tokio::test]
#[ignore = "requires network"]
async fn the_async_backend_recognises_a_bad_certificate() {
    for case in BAD_CERT_HOSTS {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .expect("client builds");
        let url = format!("https://{case}.badssl.com/");
        let Err(e) = client.get(&url).send().await else {
            panic!("{case}.badssl.com should not have validated");
        };
        assert!(
            certificate_failure(&e).is_some(),
            "{case}.badssl.com must be recognised on the async backend too; \
             the error was {e}"
        );
    }
}

/// A valid certificate is not a certificate failure.
///
/// The control for the tests above: without it they would pass against a
/// determination that called everything a certificate failure.
#[cfg(feature = "client-ureq")]
#[test]
#[ignore = "requires network"]
fn a_valid_certificate_is_not_a_failure() {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(20)))
        .build()
        .into();
    if let Err(e) = agent.get("https://www.google.com/").call() {
        let found = if let ureq::Error::Io(io) = &e {
            io.get_ref().and_then(|i| certificate_failure(i))
        } else {
            certificate_failure(&e)
        };
        assert!(
            found.is_none(),
            "a host with a valid certificate must not be a certificate \
             failure: {found:?}"
        );
    }
}

/// A refused connection yields no certificate determination, offline.
///
/// The negative direction on the determination itself rather than through a
/// fetch, so it holds without a network.
#[cfg(feature = "client-ureq")]
#[test]
fn a_connection_error_yields_no_certificate_determination() {
    let io = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "connection refused");
    assert_eq!(certificate_failure(&io), None);

    let dns = std::io::Error::new(std::io::ErrorKind::NotFound, "failed to lookup address");
    assert_eq!(certificate_failure(&dns), None);
}

/// The fallback marker is specific enough not to catch unrelated text.
///
/// `certificate_failure` falls back to rustls's `"invalid peer certificate"`
/// prefix because `reqwest` discards the type. That fallback is the fragile
/// part, so this pins what it does and does not match.
#[cfg(feature = "client-ureq")]
#[test]
fn the_fallback_marker_does_not_match_unrelated_errors() {
    for text in [
        "connection refused",
        "certificate",
        "peer certificate",
        "invalid peer",
        "dns error: failed to lookup address information",
        "tls handshake eof",
    ] {
        let io = std::io::Error::other(text);
        assert_eq!(
            certificate_failure(&io),
            None,
            "{text:?} must not be read as a certificate failure"
        );
    }
    // And the real message is matched.
    let real = std::io::Error::other("invalid peer certificate: UnknownIssuer");
    assert!(certificate_failure(&real).is_some());
}

// ---------------------------------------------------------------------------
// The variant is distinct from the one it was split out of
// ---------------------------------------------------------------------------

#[test]
fn a_certificate_failure_is_distinct_from_a_transport_failure() {
    let cert = FetchError::TlsValidation(String::from("invalid peer certificate: UnknownIssuer"));
    let transport = FetchError::Transport(String::from("invalid peer certificate: UnknownIssuer"));
    assert_ne!(
        cert, transport,
        "the whole point of the split is that these are different events"
    );
    assert!(cert.to_string().contains("certificate"), "{cert}");
}
