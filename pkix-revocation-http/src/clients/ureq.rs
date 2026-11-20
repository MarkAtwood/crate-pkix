//! Reference sync HTTP client implementation backed by [`ureq`].
//!
//! `ureq` is chosen as the reference sync backend for this crate because:
//!
//! - it is pure-Rust (no `openssl-sys` C dep complexity);
//! - it pulls in a small, focused dep tree compared to `reqwest::blocking`
//!   (which mounts a tokio runtime and the full `hyper` client just to
//!   serve a synchronous front-end);
//! - it fits this crate's MSRV (`1.87`).
//!
//! HTTPS support is enabled via the `rustls` feature on `ureq`, configured
//! at the workspace level.
//!
//! # Redirects
//!
//! CDP / AIA URLs come from certificates, so they are attacker-influenced.
//! A caller that vets the URL before fetching (host / scheme policy is a
//! deployment decision, see the crate docs) only ever sees the *first* URL,
//! so [`UreqFetcher::new`] does not let `ureq` follow redirects itself.
//! Instead [`RevocationFetcher::fetch`] follows at most [`MAX_REDIRECTS`]
//! redirects that stay on the same origin (scheme, host and port); a
//! redirect to any other origin is not followed and surfaces as
//! [`FetchError::HttpStatus`] with the 3xx code. `GET` follows 301, 302,
//! 303, 307 and 308; `POST` (OCSP) follows only 307 / 308, which preserve
//! the method and body. Consumers who need a custom TLS configuration,
//! proxy, or connection pool should construct their own
//! [`ureq::Agent`] and pass it via [`UreqFetcher::with_agent`].

use crate::{FetchError, FetchMethod, FetchRequest, FetchResponse, RevocationFetcher};
use std::io::Read;
use std::time::Duration;

/// Default cap on a single response body's size in bytes (10 MiB).
///
/// This is a deliberately conservative default that comfortably covers
/// typical CRL files (well under 10 MiB even for very large CAs) and
/// OCSP responses (usually well under 1 KiB). Callers in environments
/// with unusually large CRLs can raise the cap via
/// [`UreqFetcher::with_max_response_size`].
const DEFAULT_MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024;

/// Default per-request timeout.
///
/// 30 seconds. CRL and OCSP fetches may involve large responses or
/// slow CA responders, so the default is more generous than
/// `pkix-aia-http`'s 10-second default. A hanging responder will
/// surface as a transport error rather than blocking the calling
/// thread indefinitely. Callers needing a different bound can
/// construct a custom [`ureq::Agent`] with their preferred timeout
/// and pass it via [`UreqFetcher::with_agent`].
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum number of same-origin redirects [`UreqFetcher`] follows for one
/// request (see the module-level "Redirects" section).
pub const MAX_REDIRECTS: u32 = 10;

/// HTTP transport backed by `ureq`.
///
/// `UreqFetcher` is a thin adapter from this crate's [`RevocationFetcher`]
/// trait onto a `ureq::Agent`. It performs synchronous HTTP `GET` (for
/// CRL fetches) and `POST` (for OCSP queries), bounds response body size,
/// and translates `ureq` failure modes into [`FetchError`] variants.
#[derive(Debug, Clone)]
pub struct UreqFetcher {
    agent: ::ureq::Agent,
    max_response_size: usize,
}

impl Default for UreqFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl UreqFetcher {
    /// Build a fetcher with the default `ureq::Agent`, a 10 MiB body
    /// cap, a 30-second per-request timeout, and same-origin-only
    /// redirect following (module docs, "Redirects").
    #[must_use]
    pub fn new() -> Self {
        let agent: ::ureq::Agent = ::ureq::Agent::config_builder()
            .timeout_global(Some(DEFAULT_TIMEOUT))
            // Redirects are followed by `fetch` itself so the target's
            // origin can be checked; ureq must hand back the 3xx response.
            .max_redirects(0)
            .build()
            .into();
        Self {
            agent,
            max_response_size: DEFAULT_MAX_RESPONSE_SIZE,
        }
    }

    /// Build a fetcher around a pre-configured `ureq::Agent`.
    ///
    /// Use this when you need custom TLS config, connection pool tuning,
    /// proxies, or timeouts. The agent is used as-is; this fetcher does
    /// not override its settings.
    ///
    /// **Redirects:** an agent that follows redirects itself (ureq's
    /// default is up to 10, to any origin) bypasses this fetcher's
    /// same-origin rule, because `fetch` never sees the 3xx response.
    /// Configure the agent with `.max_redirects(0)` to keep it.
    #[must_use]
    pub fn with_agent(agent: ::ureq::Agent) -> Self {
        Self {
            agent,
            max_response_size: DEFAULT_MAX_RESPONSE_SIZE,
        }
    }

    /// Override the maximum response body size in bytes.
    ///
    /// Responses larger than `n` bytes are rejected with
    /// [`FetchError::TooLarge`] before the buffer can grow unboundedly.
    /// `0` is accepted and means "reject any body" — only useful as a
    /// degenerate test-mode setting.
    #[must_use]
    pub const fn with_max_response_size(mut self, n: usize) -> Self {
        self.max_response_size = n;
        self
    }
}

impl RevocationFetcher for UreqFetcher {
    fn fetch(&self, req: &FetchRequest<'_>) -> Result<FetchResponse, FetchError> {
        // Issue the request with the appropriate method, following
        // same-origin redirects only (module docs, "Redirects").
        let mut url = req.url.to_owned();
        let mut redirects = 0;
        let response = loop {
            let response = match &req.method {
                FetchMethod::Get => self.agent.get(&url).call(),
                FetchMethod::Post { body, content_type } => self
                    .agent
                    .post(&url)
                    .header("Content-Type", *content_type)
                    .send(*body),
            }
            .map_err(map_ureq_err)?;

            let status = response.status();
            if !status.is_redirection() {
                break response;
            }
            let method_preserving = matches!(status.as_u16(), 307 | 308);
            let followable = matches!(req.method, FetchMethod::Get) || method_preserving;
            let next = response
                .headers()
                .get(::ureq::http::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|location| same_origin_target(&url, location));
            match next {
                Some(next) if followable && redirects < MAX_REDIRECTS => {
                    redirects += 1;
                    url = next;
                }
                _ => return Err(FetchError::HttpStatus(status.as_u16())),
            }
        };

        // ureq returns an Err for non-2xx by default (when
        // http_status_as_error is on, the default), so reaching here
        // means a 2xx. Capture the status anyway as defensive coding —
        // the server could conceivably reply 1xx or have unusual
        // behaviour.
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            // Defensive: should not normally fire because ureq's
            // default Error::StatusCode path catches it.
            return Err(FetchError::HttpStatus(status));
        }

        // Capture the response Content-Type for callers who want to
        // sanity-check (e.g. expect "application/pkix-crl" for CRLs or
        // "application/ocsp-response" for OCSP). We accept all values
        // verbatim; loose responders are common in the wild.
        let content_type = response
            .headers()
            .get(::ureq::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        // Read the body with a hard byte cap. Take(limit + 1) lets us
        // detect "exceeded limit" by checking whether read went over
        // `max_response_size` — without this trick we couldn't
        // distinguish "exactly limit bytes" from "more than limit
        // bytes".
        let limit = self.max_response_size;
        let mut reader = response.into_body().into_reader();
        let mut bytes = Vec::with_capacity(limit.min(8192));
        let limited_read = (&mut reader)
            .take((limit as u64).saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|e| FetchError::Transport(Box::new(e)))?;

        if limited_read > limit {
            return Err(FetchError::TooLarge);
        }

        Ok(FetchResponse {
            bytes,
            content_type,
        })
    }
}

/// Resolve a redirect `location` against `base` and return it only if it
/// has the same origin (scheme, host, port — default ports made explicit)
/// as `base`. Absolute URLs and absolute paths (`/x`) are supported;
/// anything else (relative paths, scheme-relative `//host/x`, unparsable
/// values) is refused.
fn same_origin_target(base: &str, location: &str) -> Option<String> {
    use ::ureq::http::Uri;

    fn origin(u: &Uri) -> Option<(String, String, u16)> {
        let scheme = u.scheme_str()?.to_ascii_lowercase();
        let port = match (u.port_u16(), scheme.as_str()) {
            (Some(p), _) => p,
            (None, "http") => 80,
            (None, "https") => 443,
            (None, _) => return None,
        };
        Some((scheme, u.host()?.to_ascii_lowercase(), port))
    }

    let base: Uri = base.parse().ok()?;
    let target: Uri = if location.starts_with('/') && !location.starts_with("//") {
        format!("{}://{}{location}", base.scheme_str()?, base.authority()?)
            .parse()
            .ok()?
    } else {
        location.parse().ok()?
    };
    let same = origin(&base)? == origin(&target)?;
    same.then(|| target.to_string())
}

/// Map a `ureq::Error` into our [`FetchError`].
///
/// `ureq` 3.x reports HTTP error responses as `Error::StatusCode(code)`
/// when `http_status_as_error` is enabled (the default). All other
/// failure modes — DNS, connection refused, TLS handshake, body decode
/// — fall under `Transport`.
fn map_ureq_err(e: ::ureq::Error) -> FetchError {
    match e {
        ::ureq::Error::StatusCode(code) => FetchError::HttpStatus(code),
        other => FetchError::Transport(Box::new(other)),
    }
}

#[cfg(test)]
mod tests {
    //! Compile-shape and constructor tests.
    //!
    //! End-to-end behavioural verification (HTTP responses, body caps in
    //! flight, content-type capture) lives in the mock-server integration
    //! test suite tracked under PKIX-a1yc.9 — it requires a local HTTP
    //! server which is dev-only infrastructure. Here we just prove the
    //! type compiles, implements the trait, and constructors honour
    //! their inputs.
    use super::*;

    #[test]
    fn default_constructor_uses_default_max_size() {
        let f = UreqFetcher::new();
        assert_eq!(f.max_response_size, DEFAULT_MAX_RESPONSE_SIZE);
    }

    #[test]
    fn default_trait_returns_same_as_new() {
        let a = UreqFetcher::default();
        let b = UreqFetcher::new();
        assert_eq!(a.max_response_size, b.max_response_size);
    }

    #[test]
    fn with_max_response_size_overrides() {
        let f = UreqFetcher::new().with_max_response_size(123);
        assert_eq!(f.max_response_size, 123);
    }

    #[test]
    fn impls_revocation_fetcher() {
        // Compile-only: a UreqFetcher must satisfy the trait that the
        // CRL/OCSP fetchers expect. Wraps a function-call so the
        // unused-result lint stays quiet on a value we never invoke.
        fn _accepts<F: RevocationFetcher>(_: &F) {}
        let f = UreqFetcher::new();
        _accepts(&f);
    }
}
