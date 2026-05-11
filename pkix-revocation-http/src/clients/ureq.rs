//! Reference sync HTTP client implementation backed by [`ureq`].
//!
//! `ureq` is chosen as the reference sync backend for this crate because:
//!
//! - it is pure-Rust (no `openssl-sys` C dep complexity);
//! - it pulls in a small, focused dep tree compared to `reqwest::blocking`
//!   (which mounts a tokio runtime and the full `hyper` client just to
//!   serve a synchronous front-end);
//! - it fits this crate's MSRV (`1.73`).
//!
//! HTTPS support is enabled via the `rustls` feature on `ureq`, configured
//! at the workspace level. Consumers who need a custom TLS configuration,
//! proxy, or connection pool should construct their own
//! [`ureq::Agent`] and pass it via [`UreqFetcher::with_agent`].

use crate::{FetchError, FetchMethod, FetchRequest, FetchResponse, RevocationFetcher};
use std::io::Read;

/// Default cap on a single response body's size in bytes (10 MiB).
///
/// This is a deliberately conservative default that comfortably covers
/// typical CRL files (well under 10 MiB even for very large CAs) and
/// OCSP responses (usually well under 1 KiB). Callers in environments
/// with unusually large CRLs can raise the cap via
/// [`UreqFetcher::with_max_response_size`].
const DEFAULT_MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024;

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
    /// Build a fetcher with the default `ureq::Agent` and a 10 MiB body cap.
    #[must_use]
    pub fn new() -> Self {
        Self {
            agent: ::ureq::agent(),
            max_response_size: DEFAULT_MAX_RESPONSE_SIZE,
        }
    }

    /// Build a fetcher around a pre-configured `ureq::Agent`.
    ///
    /// Use this when you need custom TLS config, connection pool tuning,
    /// proxies, or timeouts. The agent is used as-is; this fetcher does
    /// not override its settings.
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
        // Issue the request with the appropriate method. ureq's
        // RequestBuilder::send / call return Result<Response, ureq::Error>.
        let response = match &req.method {
            FetchMethod::Get => self.agent.get(req.url).call(),
            FetchMethod::Post { body, content_type } => self
                .agent
                .post(req.url)
                .header("Content-Type", *content_type)
                .send(*body),
        }
        .map_err(map_ureq_err)?;

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
