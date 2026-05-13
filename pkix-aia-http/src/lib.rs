#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, unreachable_pub)]
#![warn(missing_docs)]

//! # pkix-aia-http
//!
//! Reference synchronous HTTP fetcher for
//! [`pkix-aia`](https://docs.rs/pkix-aia)'s
//! [`AiaFetcher`] trait.
//!
//! AIA (Authority Information Access, RFC 5280 §4.2.2.1) is the
//! extension that carries `caIssuers` URIs pointing at the
//! certificate's issuer. Chain-build code can follow these URIs to
//! fetch missing intermediates when the caller-supplied chain is
//! incomplete. This crate plugs an HTTP transport into the
//! [`AiaFetcher`] trait so the chain-build flow in `pkix-chain`
//! can resolve `caIssuers` URIs whose scheme is `http://` or
//! `https://`.
//!
//! ## Quick start
//!
//! ```no_run
//! use pkix_aia::AiaFetcher;
//! use pkix_aia_http::HttpFetcher;
//!
//! let fetcher = HttpFetcher::new();
//! let der_bytes = fetcher.fetch("http://ca.example/intermediate.crt")?;
//! println!("fetched {} bytes", der_bytes.len());
//! # Ok::<(), pkix_aia::AiaError>(())
//! ```
//!
//! ## Design parallel: `pkix-revocation-http`
//!
//! This crate intentionally mirrors `pkix-revocation-http`'s
//! `UreqFetcher` shape: the same `ureq` dependency, the same
//! response-size cap pattern, the same HTTPS-via-rustls feature
//! configuration, the same "construct once, fetch many times"
//! idiom. Callers running both crates in the same process can
//! configure a custom `ureq::Agent` once and pass it to both
//! fetchers via the `with_agent` builders, sharing connection
//! pools.
//!
//! The split into a separate crate per use case
//! (`pkix-revocation-http` for CRL / OCSP, `pkix-aia-http` for AIA)
//! follows the workspace's one-callback-per-crate convention. The
//! revocation and AIA seams in `pkix-chain` are independent: a
//! caller can use AIA without revocation, revocation without AIA,
//! or both. Each adapter crate is independently optional.
//!
//! ## What is fetched
//!
//! [`HttpFetcher::fetch`] issues a synchronous HTTP `GET` against
//! the supplied `uri`. The response body is returned verbatim as
//! `Vec<u8>`; parsing the bytes as a DER X.509 certificate is the
//! caller's responsibility (typically delegated to
//! `pkix-path-builder` or `pkix-chain`).
//!
//! Non-HTTP URI schemes (e.g. `ldap://`, `ftp://`) return
//! [`AiaError::UriUnsupported`] immediately, before any network
//! I/O.
//!
//! ## Limits
//!
//! - **Body size cap** — responses larger than
//!   [`DEFAULT_MAX_RESPONSE_SIZE`] (1 MiB) are rejected with
//!   [`AiaError::ResponseTooLarge`]. Override via
//!   [`HttpFetcher::with_max_response_size`]. Real-world
//!   intermediate CA certs are typically well under 4 KiB; 1 MiB is
//!   a generous fail-closed default for an untrusted endpoint.
//! - **Timeout** — `ureq`'s built-in agent timeouts apply. Construct
//!   a custom [`ureq::Agent`] with explicit timeouts and pass via
//!   [`HttpFetcher::with_agent`] if you need a specific bound.
//! - **No retry, no backoff, no caching** — these are caller-side
//!   concerns. Wrap [`HttpFetcher`] with a caching layer
//!   (`pkix-aia`'s rustdoc has a `CachingFetcher` worked example)
//!   or retry adapter as needed.
//! - **HTTPS via rustls** — workspace pin
//!   `ureq = { features = ["rustls"] }`. Consumers with custom TLS
//!   requirements (PSK, client auth at the AIA endpoint, exotic
//!   trust roots) should construct their own [`ureq::Agent`] and
//!   inject via [`HttpFetcher::with_agent`].
//!
//! ## # Limitations
//!
//! - Synchronous only. An async parallel (mirroring
//!   `pkix-revocation-http`'s `AsyncHttpCrlFetcher` /
//!   `AsyncHttpOcspFetcher`) is filed as PKIX-zkjb.5.1, deferred
//!   until consumer demand surfaces.
//! - No LDAP transport. RFC 5280 §4.2.2.1 permits any URI scheme in
//!   AIA `accessLocation` `GeneralName`s; in practice HTTP and HTTPS
//!   dominate. An `ldap://` fetcher could ship as a sibling
//!   `pkix-aia-ldap` crate if demand surfaces.
//! - No HTTP/2 connection pooling tuning beyond `ureq::Agent`'s
//!   defaults. Sharing an agent across many fetches (the default
//!   when you construct one [`HttpFetcher`] and keep it) reuses
//!   connections; per-request tuning is not exposed.
//!
//! Tracked as PKIX-zkjb.5 in the project beads.

use std::io::Read;
use std::time::Duration;

use pkix_aia::{AiaError, AiaFetcher};

/// Default cap on a single response body's size, in bytes.
///
/// 1 MiB. Real-world intermediate CA certificates are well under
/// 4 KiB; the generous default leaves headroom for unusual bundles
/// (e.g. a server that returns a `application/pkcs7-mime` `certs-only`
/// SignedData wrapping multiple certs) without enabling
/// denial-of-service through unbounded body growth. Callers can
/// raise the cap via [`HttpFetcher::with_max_response_size`] if
/// their environment has unusually large issuer-cert blobs.
pub const DEFAULT_MAX_RESPONSE_SIZE: usize = 1024 * 1024;

/// Default per-request timeout.
///
/// 10 seconds. AIA fetches happen in the synchronous path of chain
/// validation; a long stall blocks the caller. The 10-second default
/// is generous enough for slow CA endpoints and tight enough that a
/// dead endpoint surfaces as [`AiaError::Timeout`] rather than
/// stalling the calling thread indefinitely.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// HTTP transport backed by `ureq`.
///
/// `HttpFetcher` is a thin adapter from [`pkix_aia::AiaFetcher`]
/// onto a [`ureq::Agent`]. It performs synchronous HTTP `GET`
/// against the
/// caller-supplied URI, bounds response body size, and translates
/// `ureq` failure modes into [`AiaError`] variants.
///
/// Construct with [`HttpFetcher::new`] for sensible defaults, or
/// [`HttpFetcher::with_agent`] to inject a pre-configured
/// [`ureq::Agent`] (custom TLS config, proxies, additional
/// timeouts, etc.).
///
/// `HttpFetcher` is `Send + Sync`; a single instance can be shared
/// across threads. The underlying agent reuses HTTP connections, so
/// keeping one instance per process is more efficient than
/// constructing a fresh one per fetch.
#[derive(Debug, Clone)]
pub struct HttpFetcher {
    agent: ureq::Agent,
    max_response_size: usize,
}

impl Default for HttpFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpFetcher {
    /// Build a fetcher with the default `ureq::Agent`, a 1 MiB body
    /// cap, and a 10-second per-request timeout.
    #[must_use]
    pub fn new() -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(DEFAULT_TIMEOUT))
            .build()
            .into();
        Self {
            agent,
            max_response_size: DEFAULT_MAX_RESPONSE_SIZE,
        }
    }

    /// Build a fetcher around a pre-configured `ureq::Agent`.
    ///
    /// Use this when you need a custom TLS config, proxies,
    /// connection-pool tuning, or non-default timeouts. The agent is
    /// used as-is; this fetcher does not override its settings.
    #[must_use]
    pub fn with_agent(agent: ureq::Agent) -> Self {
        Self {
            agent,
            max_response_size: DEFAULT_MAX_RESPONSE_SIZE,
        }
    }

    /// Override the maximum response body size in bytes.
    ///
    /// Responses larger than `n` bytes are rejected with
    /// [`AiaError::ResponseTooLarge`] before the buffer can grow
    /// unboundedly. `0` is accepted and
    /// means "reject any body"; only useful as a degenerate test
    /// setting.
    #[must_use]
    pub const fn with_max_response_size(mut self, n: usize) -> Self {
        self.max_response_size = n;
        self
    }

    /// Borrow the underlying `ureq::Agent` for inspection or
    /// connection-pool reuse across sibling fetchers (e.g. sharing
    /// the same agent with a `pkix_revocation_http::UreqFetcher`).
    #[must_use]
    pub fn agent(&self) -> &ureq::Agent {
        &self.agent
    }
}

impl AiaFetcher for HttpFetcher {
    fn fetch(&self, uri: &str) -> Result<Vec<u8>, AiaError> {
        // Reject non-HTTP schemes up front. RFC 5280 §4.2.2.1 allows
        // any GeneralName in accessLocation; HTTP-only fetchers
        // signal "I cannot handle this URI" via UriUnsupported so
        // the chain-build layer can try other AIA entries or fall
        // through.
        if !is_http_scheme(uri) {
            return Err(AiaError::UriUnsupported(uri.to_owned()));
        }

        let response = self.agent.get(uri).call().map_err(map_ureq_err)?;

        // ureq returns Err for non-2xx by default (http_status_as_error
        // is on). Reaching here means a 2xx. Capture status anyway
        // as defensive coding — a server could conceivably reply 1xx.
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(AiaError::HttpStatus(status));
        }

        // Read the body with a hard byte cap. Take(limit + 1) lets
        // us distinguish "exactly limit bytes" from "more than
        // limit bytes" — without the +1 the reader would happily
        // return `limit` bytes and we could not tell whether the
        // server stopped or we truncated.
        let limit = self.max_response_size;
        let mut reader = response.into_body().into_reader();
        let mut bytes = Vec::with_capacity(limit.min(8192));
        let read_count = (&mut reader)
            .take((limit as u64).saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|e| AiaError::IoFailure {
                kind: e.kind(),
                message: e.to_string(),
            })?;

        if read_count > limit {
            return Err(AiaError::ResponseTooLarge {
                limit,
                actual: read_count,
            });
        }

        Ok(bytes)
    }
}

/// Return `true` when `uri` begins with `http://` or `https://`,
/// case-insensitively (RFC 3986 §3.1: scheme is case-insensitive).
fn is_http_scheme(uri: &str) -> bool {
    let lower = uri.split_once(':').map(|(scheme, _)| scheme);
    matches!(lower, Some(s) if s.eq_ignore_ascii_case("http") || s.eq_ignore_ascii_case("https"))
}

/// Translate a `ureq::Error` into an [`AiaError`].
///
/// `ureq` 3.x surfaces HTTP error statuses as
/// `Error::StatusCode(code)` when `http_status_as_error` is on (the
/// default). All other failures — DNS resolution, connection
/// refused, TLS handshake, body decode — surface through
/// [`AiaError::IoFailure`]. Per-request timeouts surface as
/// [`AiaError::Timeout`].
fn map_ureq_err(e: ureq::Error) -> AiaError {
    match e {
        ureq::Error::StatusCode(code) => AiaError::HttpStatus(code),
        ureq::Error::Timeout(_) => AiaError::Timeout,
        other => AiaError::IoFailure {
            kind: std::io::ErrorKind::Other,
            message: other.to_string(),
        },
    }
}

// ---------------------------------------------------------------------------
// Send + Sync invariant (AGENTS.md non-negotiable #6 / PKIX-2l0v.2)
// ---------------------------------------------------------------------------

const _: fn() = || {
    fn _assert_send_sync<T: Send + Sync>() {}
    _assert_send_sync::<HttpFetcher>();
};

// ---------------------------------------------------------------------------
// Compile-shape and constructor tests
// ---------------------------------------------------------------------------
//
// End-to-end behavioural verification (HTTP responses, body caps in
// flight, status mapping, timeout enforcement) lives in
// `tests/integration.rs` because it requires a live local HTTP
// server. The tests here just prove that the type compiles,
// implements the trait, and that constructors honour their inputs.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_constructor_uses_default_max_size() {
        let f = HttpFetcher::new();
        assert_eq!(f.max_response_size, DEFAULT_MAX_RESPONSE_SIZE);
    }

    #[test]
    fn default_trait_returns_same_as_new() {
        let a = HttpFetcher::default();
        let b = HttpFetcher::new();
        assert_eq!(a.max_response_size, b.max_response_size);
    }

    #[test]
    fn with_max_response_size_overrides() {
        let f = HttpFetcher::new().with_max_response_size(123);
        assert_eq!(f.max_response_size, 123);
    }

    #[test]
    fn with_max_response_size_accepts_zero() {
        // Degenerate but legal: a fetcher that rejects any non-empty
        // body. Useful only for tests that want to assert the cap
        // mechanism fires.
        let f = HttpFetcher::new().with_max_response_size(0);
        assert_eq!(f.max_response_size, 0);
    }

    #[test]
    fn impls_aia_fetcher() {
        // Compile-only: HttpFetcher must satisfy the AiaFetcher trait
        // that pkix-chain's Verifier struct will hold via its third
        // generic (PKIX-zkjb.9).
        fn _accepts<F: AiaFetcher>(_: &F) {}
        let f = HttpFetcher::new();
        _accepts(&f);
    }

    #[test]
    fn is_http_scheme_accepts_http_and_https() {
        assert!(is_http_scheme("http://ca.example/intermediate.crt"));
        assert!(is_http_scheme("https://ca.example/intermediate.crt"));
        // RFC 3986: scheme is case-insensitive.
        assert!(is_http_scheme("HTTP://ca.example/intermediate.crt"));
        assert!(is_http_scheme("HTTPS://ca.example/intermediate.crt"));
        assert!(is_http_scheme("HtTp://ca.example/intermediate.crt"));
    }

    #[test]
    fn is_http_scheme_rejects_others() {
        assert!(!is_http_scheme("ldap://ca.example/cn=ca"));
        assert!(!is_http_scheme("ftp://ca.example/ca.crt"));
        assert!(!is_http_scheme("file:///etc/ssl/ca.crt"));
        assert!(!is_http_scheme(
            "data:application/x-x509-ca-cert;base64,..."
        ));
        // Missing scheme entirely.
        assert!(!is_http_scheme("ca.example/intermediate.crt"));
        // Empty string.
        assert!(!is_http_scheme(""));
        // Bare colon.
        assert!(!is_http_scheme(":"));
    }

    #[test]
    fn fetch_rejects_non_http_scheme_without_network_io() {
        let f = HttpFetcher::new();
        // ldap:// must short-circuit to UriUnsupported before any
        // network I/O happens. We do not need a live server for
        // this assertion; the scheme check rejects synchronously.
        let err = f.fetch("ldap://ca.example/cn=ca").unwrap_err();
        match err {
            AiaError::UriUnsupported(uri) => {
                assert_eq!(uri, "ldap://ca.example/cn=ca");
            }
            other => panic!("expected UriUnsupported, got {other:?}"),
        }
    }
}
