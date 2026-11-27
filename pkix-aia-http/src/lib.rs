#![cfg_attr(docsrs, feature(doc_cfg))]
// `AsyncHttpFetcher` and `GuardedAsyncResolver` are gated on
// `client-reqwest-async`, and linked from documentation gated only on
// `async` — so `--features async` alone cannot resolve them. Same shape
// and same reasoning as the attribute at the top of `pkix-path`: the
// links keep working on docs.rs, which builds all features, and the
// lint stays denied wherever it can tell a gated item from a typo.
#![cfg_attr(
    not(feature = "client-reqwest-async"),
    allow(rustdoc::broken_intra_doc_links)
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

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
//! **The mirroring stops at destination policy, and that is the one place
//! it matters.** This crate refuses non-public destinations by default (see
//! "Destination policy (SSRF)" below); `pkix-revocation-http` applies no
//! destination policy at all, leaving it to the caller's fetcher. Both
//! choices are deliberate — this crate owns its transport and so can own a
//! policy, while that crate's transport is a caller-supplied trait — but a
//! reader who has absorbed how similar the two crates are is exactly the
//! reader who will assume the defaults match. They do not. See that crate's
//! "Security considerations" section before fetching CRLs or OCSP
//! server-side.
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
//! ## Destination policy (SSRF)
//!
//! caIssuers URIs are read from certificates that have not been
//! validated yet, so any peer able to present a certificate chooses
//! the URL this process fetches. [`HttpFetcher::new`] therefore:
//!
//! - **refuses internal destinations** — after DNS resolution, every
//!   resolved address that is unspecified, loopback, private
//!   (RFC 1918), shared (RFC 6598), link-local (including
//!   169.254.169.254 cloud metadata), multicast, broadcast/reserved,
//!   IPv6 ULA (`fc00::/7`) or site-local, or an IPv4-mapped /
//!   IPv4-compatible / NAT64 (`64:ff9b::/96`) IPv6 address embedding one
//!   of those, is dropped; if none remain the fetch fails with
//!   [`AiaError::DestinationNotAllowed`]. Checking the resolved
//!   addresses (not the host name) and connecting only to the checked
//!   addresses also defeats DNS rebinding;
//! - **does not follow redirects** — a 3xx surfaces as
//!   [`AiaError::HttpStatus`], so a public host cannot bounce the fetch
//!   to an internal one;
//! - **ignores `HTTP_PROXY`-style environment proxies**, since through
//!   a proxy the resolver would only see the proxy's address.
//!
//! Deployments that legitimately publish AIA objects on internal
//! addresses opt out with [`HttpFetcher::allow_private_destinations`].
//! An agent injected via [`HttpFetcher::with_agent`] is used as-is: its
//! redirect, proxy, and destination behaviour is the caller's
//! responsibility.
//!
//! The filter uses `ureq`'s `unversioned` resolver API, which `ureq`
//! does not cover by semver; a `ureq` minor upgrade may require
//! adjusting [`GuardedResolver`].
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
//! ## Limitations
//!
//! - Synchronous by default. The `async` and `client-reqwest-async`
//!   features add `AsyncAiaFetcher`, the async analogue of `AiaFetcher`,
//!   and `AsyncHttpFetcher`, its `reqwest`-backed reference
//!   implementation. Both are off by default, so a synchronous consumer
//!   pays nothing for them.
//! - No LDAP transport. RFC 5280 §4.2.2.1 permits any URI scheme in
//!   AIA `accessLocation` `GeneralName`s; in practice HTTP and HTTPS
//!   dominate. An `ldap://` fetcher could ship as a sibling
//!   `pkix-aia-ldap` crate if demand surfaces.
//! - No connection-pool tuning beyond `ureq::Agent`'s
//!   defaults. Sharing an agent across many fetches (the default
//!   when you construct one [`HttpFetcher`] and keep it) reuses
//!   connections; per-request tuning is not exposed.
//!

// Async trait family. Gated so a sync-only consumer pays no async-trait
// machinery; the async traits deliberately live here rather than in the
// no_std `pkix-aia` core. See the module's own documentation.
#[cfg(feature = "async")]
mod async_fetcher;

#[cfg(feature = "async")]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
pub use async_fetcher::{AsyncAiaFetcher, NoAsyncAiaFetcher, SyncAsAsync};

#[cfg(feature = "client-reqwest-async")]
#[cfg_attr(docsrs, doc(cfg(feature = "client-reqwest-async")))]
pub use async_fetcher::{AsyncHttpFetcher, GuardedAsyncResolver};

use std::io::Read;
use std::time::Duration;

use pkix_aia::{AiaError, AiaFetcher};
use ureq::unversioned::transport::DefaultConnector;

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
/// Construct with [`HttpFetcher::new`] for sensible defaults
/// (including the destination policy described in the crate docs), or
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
    /// Build a fetcher with a 1 MiB body cap, a 10-second per-request
    /// timeout, no redirect following, no environment proxy, and the
    /// internal-destination filter (see the crate-level "Destination
    /// policy" section).
    #[must_use]
    pub fn new() -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(DEFAULT_TIMEOUT))
            .max_redirects(0)
            .proxy(None)
            .build();
        let agent = ureq::Agent::with_parts(config, DefaultConnector::new(), GuardedResolver);
        Self {
            agent,
            max_response_size: DEFAULT_MAX_RESPONSE_SIZE,
        }
    }

    /// Disable the internal-destination filter.
    ///
    /// Replaces the agent with one that has the same timeout and
    /// no-redirect settings but resolves names with `ureq`'s default
    /// resolver (and honours environment proxies), so loopback, private
    /// and link-local targets are fetched. Use only when every
    /// certificate whose caIssuers URIs reach this fetcher comes from a
    /// trusted source, or when the AIA repository is itself internal;
    /// also used by tests that serve AIA objects from `127.0.0.1`.
    /// Discards any agent injected with [`HttpFetcher::with_agent`].
    #[must_use]
    pub fn allow_private_destinations(mut self) -> Self {
        self.agent = ureq::Agent::config_builder()
            .timeout_global(Some(DEFAULT_TIMEOUT))
            .max_redirects(0)
            .build()
            .into();
        self
    }

    /// Build a fetcher around a pre-configured `ureq::Agent`.
    ///
    /// Use this when you need a custom TLS config, proxies,
    /// connection-pool tuning, or non-default timeouts. The agent is
    /// used as-is; this fetcher does not override its settings. In
    /// particular the destination filter and the no-redirect policy of
    /// [`HttpFetcher::new`] do **not** apply: `ureq`'s default agent
    /// follows up to 10 redirects and connects anywhere. Configure
    /// `max_redirects(0)` and a filtering resolver yourself if the agent
    /// can be reached through untrusted certificates.
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
            // The io::ErrorKind goes into the message rather than its own
            // field: it is log material, and a field that four of five
            // construction sites filled with `Other` was not something a
            // caller could act on. See AiaError::IoFailure.
            .map_err(|e| AiaError::IoFailure(format!("{:?}: {e}", e.kind())))?;

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
pub(crate) fn is_http_scheme(uri: &str) -> bool {
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
    if let ureq::Error::Io(io) = &e {
        if let Some(refused) = io
            .get_ref()
            .and_then(|i| i.downcast_ref::<RefusedDestination>())
        {
            return AiaError::DestinationNotAllowed(refused.0.clone());
        }
    }
    match e {
        ureq::Error::StatusCode(code) => AiaError::HttpStatus(code),
        ureq::Error::Timeout(_) => AiaError::Timeout,
        other => AiaError::IoFailure(other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Destination policy
// ---------------------------------------------------------------------------
//
// Extracted to `pkix-net-guard` when MTA-STS policy fetching needed the same
// policy. The address classification is subtle -- NAT64, IPv4-mapped and
// IPv4-compatible forms, RFC 6598 shared space -- and a second copy of it
// would be a divergence hazard on code whose whole job is refusing a request.
// Re-exported here so this crate's public API is unchanged.

pub use pkix_net_guard::GuardedResolver;
use pkix_net_guard::RefusedDestination;
// Used by the reqwest-backed resolver in async_fetcher.rs, which is behind a
// feature; importing it unconditionally is an unused import without that.
#[cfg(feature = "client-reqwest-async")]
pub(crate) use pkix_net_guard::is_public;

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
