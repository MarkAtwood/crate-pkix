//! Reference async HTTP client implementation backed by [`reqwest`].
//!
//! `reqwest` is chosen as the reference async backend because:
//!
//! - it is the most widely-used async HTTP client in the Rust ecosystem,
//!   matching how `ureq` is chosen for the sync side;
//! - its connection pool, redirect handling, and timeout machinery are
//!   battle-tested at the scale that real CRL / OCSP traffic hits;
//! - rustls feature gives us pure-Rust TLS without `openssl-sys`,
//!   matching the sync side's posture.
//!
//! # Runtime
//!
//! `reqwest::Client` requires a tokio runtime to drive its sockets;
//! consumers using this backend must run their `check_revocation` calls
//! from within a tokio-managed task. This crate itself does **not**
//! depend on tokio (the dependency is implicit via reqwest); consumers
//! who already use tokio for their async stack pay nothing extra, while
//! consumers using a different runtime should plug in their own
//! [`crate::AsyncRevocationFetcher`] impl rather than this reference.

use crate::{AsyncRevocationFetcher, FetchError, FetchMethod, FetchRequest, FetchResponse};
use async_trait::async_trait;
use std::time::Duration;

/// Default cap on a single response body's size in bytes (10 MiB).
///
/// Mirrors [`crate::clients::ureq::UreqFetcher`]'s default cap so the
/// sync and async backends behave the same out of the box.
const DEFAULT_MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024;

/// Default per-request timeout.
///
/// 30 seconds. Mirrors [`crate::clients::ureq::DEFAULT_TIMEOUT`] so
/// the sync and async backends behave the same out of the box. A
/// hanging CRL or OCSP responder will surface as a transport error
/// rather than tying up a task indefinitely. Callers needing a
/// different bound can construct a custom [`reqwest::Client`] with
/// their preferred timeout and pass it via
/// [`ReqwestFetcher::with_client`].
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// HTTP transport backed by `reqwest`'s async client.
///
/// Adapter from this crate's [`AsyncRevocationFetcher`] trait onto a
/// `reqwest::Client`. Performs async HTTP `GET` (for CRL fetches) and
/// `POST` (for OCSP queries), bounds response body size, and translates
/// `reqwest` failure modes into [`FetchError`] variants.
#[derive(Debug, Clone)]
pub struct ReqwestFetcher {
    client: ::reqwest::Client,
    max_response_size: usize,
}

impl Default for ReqwestFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl ReqwestFetcher {
    /// Build a fetcher with a default `reqwest::Client`, a 10 MiB body
    /// cap, and a 30-second per-request timeout.
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: ::reqwest::ClientBuilder::new()
                .timeout(DEFAULT_TIMEOUT)
                .build()
                .unwrap_or_default(),
            max_response_size: DEFAULT_MAX_RESPONSE_SIZE,
        }
    }

    /// Build a fetcher around a pre-configured `reqwest::Client`.
    ///
    /// Use this when you need custom TLS config, connection pool
    /// tuning, proxies, or timeouts. The client is used as-is.
    #[must_use]
    pub fn with_client(client: ::reqwest::Client) -> Self {
        Self {
            client,
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

#[async_trait]
impl AsyncRevocationFetcher for ReqwestFetcher {
    async fn fetch(&self, req: &FetchRequest<'_>) -> Result<FetchResponse, FetchError> {
        // Build the request. Same shape as UreqFetcher: GET for CRL,
        // POST with body + Content-Type for OCSP.
        let builder = match &req.method {
            FetchMethod::Get => self.client.get(req.url),
            FetchMethod::Post { body, content_type } => self
                .client
                .post(req.url)
                .header(::reqwest::header::CONTENT_TYPE, *content_type)
                .body(body.to_vec()),
        };

        // Send and check status. reqwest does NOT raise an error on
        // non-2xx by default (unlike ureq) — we must explicitly map
        // status to FetchError::HttpStatus.
        let resp = builder
            .send()
            .await
            .map_err(|e| FetchError::Transport(Box::new(e)))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(FetchError::HttpStatus(status.as_u16()));
        }

        // Capture Content-Type before consuming the body. reqwest's
        // HeaderValue::to_str returns Err on non-ASCII; we treat that
        // as "no Content-Type" rather than failing the fetch — real
        // responders sometimes set garbage headers and higher layers
        // already tolerate missing CT.
        let content_type = resp
            .headers()
            .get(::reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        // Bound the body. reqwest::Response::bytes() pulls the whole
        // body unbounded; to enforce a cap without buffering more than
        // necessary we stream via chunks. content_length() is a best-
        // effort hint and unreliable for chunked-encoded responses, so
        // we still check during the stream.
        let limit = self.max_response_size;
        if let Some(hint) = resp.content_length() {
            // Cheap early-reject: if the server promised more than
            // limit bytes, do not even start reading.
            if hint > (limit as u64) {
                return Err(FetchError::TooLarge);
            }
        }

        // Stream the body chunk-by-chunk, enforcing the cap. Standard
        // pattern: accumulate into Vec<u8>, abort if we exceed limit.
        use ::reqwest::Response;
        let mut resp: Response = resp;
        let mut bytes: Vec<u8> = Vec::with_capacity(limit.min(8192));
        loop {
            match resp.chunk().await {
                Ok(Some(chunk)) => {
                    if bytes.len().saturating_add(chunk.len()) > limit {
                        return Err(FetchError::TooLarge);
                    }
                    bytes.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(e) => {
                    return Err(FetchError::Transport(Box::new(e)));
                }
            }
        }

        Ok(FetchResponse {
            bytes,
            content_type,
        })
    }
}

#[cfg(test)]
mod tests {
    //! Compile-shape and constructor tests.
    //!
    //! End-to-end behavioural verification (HTTP responses, body caps in
    //! flight, content-type capture) lives in the integration test suite
    //! `tests/integration_async.rs` which uses wiremock to host a real
    //! local HTTP server. These unit tests just prove the type compiles,
    //! satisfies the trait, and constructors honour their inputs.
    use super::*;

    #[test]
    fn default_constructor_uses_default_max_size() {
        let f = ReqwestFetcher::new();
        assert_eq!(f.max_response_size, DEFAULT_MAX_RESPONSE_SIZE);
    }

    #[test]
    fn default_trait_returns_same_as_new() {
        let a = ReqwestFetcher::default();
        let b = ReqwestFetcher::new();
        assert_eq!(a.max_response_size, b.max_response_size);
    }

    #[test]
    fn with_max_response_size_overrides() {
        let f = ReqwestFetcher::new().with_max_response_size(123);
        assert_eq!(f.max_response_size, 123);
    }

    #[test]
    fn impls_async_revocation_fetcher() {
        // Compile-only: ReqwestFetcher must satisfy the trait that the
        // async CRL/OCSP fetchers expect.
        fn _accepts<F: AsyncRevocationFetcher>(_: &F) {}
        let f = ReqwestFetcher::new();
        _accepts(&f);
        // Must also be Send + Sync so it composes inside a multi-threaded
        // tokio runtime.
        fn _is_send_sync<T: Send + Sync>(_: &T) {}
        _is_send_sync(&f);
    }
}
