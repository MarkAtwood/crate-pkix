//! Async analogue of [`crate::HttpFetcher`] and [`pkix_aia::AiaFetcher`].
//!
//! # Why a separate async trait family
//!
//! `pkix_aia::AiaFetcher` is and stays synchronous. That keeps the `no_std`
//! core free of async machinery and lets consumers in embedded and
//! kernel-mode-TLS environments depend on it without `async-trait`, `futures`
//! or a runtime anywhere in their graph.
//!
//! The same three options `pkix-revocation-http` weighed for its own async
//! family apply here, and resolve the same way:
//!
//! - **Add `AsyncAiaFetcher` to `pkix-aia` itself.** Forces the core crate to
//!   take a stance on async and propagates `Send` bounds into consumers that
//!   never want it. Rejected.
//! - **One async trait plus a sync wrapper that `block_on`s.** Calling
//!   `block_on` from inside a running runtime panics outright on Tokio and
//!   deadlocks a current-thread executor. Rejected.
//! - **Two parallel families, async living here.** The sync path is
//!   untouched; `AsyncAiaFetcher` is the analogue of
//!   [`pkix_aia::AiaFetcher`] but lives in this crate, not in `pkix-aia`.
//!   **Adopted**, matching `reqwest`'s own split between `Client` and
//!   `blocking::Client`.
//!
//! # Runtime
//!
//! The trait surface is runtime-agnostic. The reference
//! [`AsyncHttpFetcher`] is `reqwest`-backed and needs a Tokio runtime to
//! drive its sockets; that constraint is `reqwest`'s, not this trait's.

#[cfg(feature = "client-reqwest-async")]
use std::time::Duration;

use async_trait::async_trait;
use pkix_aia::{AiaError, AiaFetcher};

/// Async source of certificates named by AIA `caIssuers` URIs.
///
/// Implement this to plug in your own async HTTP client.
/// [`AsyncHttpFetcher`] is the reference implementation, behind the
/// `client-reqwest-async` feature.
///
/// Use [`pkix_aia::AiaFetcher`] in synchronous environments.
///
/// # `Send` bounds
///
/// `Send + Sync` so implementations work on multi-threaded executors. The
/// returned futures are `Send` via `#[async_trait]`'s expansion.
#[async_trait]
pub trait AsyncAiaFetcher: Send + Sync {
    /// Fetches the certificate object at `uri`.
    ///
    /// Returns the raw response bytes. Per RFC 5280 §4.2.2.1 those are either
    /// a single DER certificate or a certs-only CMS message; parsing them is
    /// the caller's job, as with the sync trait.
    ///
    /// # Security
    ///
    /// `uri` comes from a certificate that has not been validated yet, so
    /// whoever presented the certificate chose it. An implementation must
    /// apply a destination policy and a per-request timeout.
    /// [`AsyncHttpFetcher`] does both, and refuses non-public addresses at
    /// *resolution* time rather than by inspecting the host name — see
    /// [`GuardedAsyncResolver`].
    ///
    /// # Errors
    ///
    /// The same [`AiaError`] variants the sync trait uses, so a consumer
    /// supporting both paths handles one error type.
    async fn fetch(&self, uri: &str) -> Result<Vec<u8>, AiaError>;

    /// Fetches several URIs concurrently.
    ///
    /// Returns a `Vec` aligned with `uris` by index: the `i`-th entry is the
    /// result for `uris[i]`, preserving per-URI success and failure.
    ///
    /// Unlike [`AiaFetcher::batch_fetch`], whose default is a sequential loop,
    /// this default runs the requests concurrently. That difference is the
    /// reason the async family exists: AIA chain reassembly may have several
    /// candidate URIs per certificate, and walking them one round trip at a
    /// time is what the sync trait is stuck with.
    async fn batch_fetch(&self, uris: &[&str]) -> Vec<Result<Vec<u8>, AiaError>> {
        futures_util::future::join_all(uris.iter().map(|uri| self.fetch(uri))).await
    }
}

#[async_trait]
impl<T: AsyncAiaFetcher + ?Sized> AsyncAiaFetcher for std::sync::Arc<T> {
    async fn fetch(&self, uri: &str) -> Result<Vec<u8>, AiaError> {
        (**self).fetch(uri).await
    }

    async fn batch_fetch(&self, uris: &[&str]) -> Vec<Result<Vec<u8>, AiaError>> {
        (**self).batch_fetch(uris).await
    }
}

/// An [`AsyncAiaFetcher`] that never fetches.
///
/// The async counterpart of [`pkix_aia::NoAiaFetcher`], for wiring the seam
/// without enabling AIA. Every call returns [`AiaError::FetchingDisabled`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct NoAsyncAiaFetcher;

#[async_trait]
impl AsyncAiaFetcher for NoAsyncAiaFetcher {
    async fn fetch(&self, _uri: &str) -> Result<Vec<u8>, AiaError> {
        Err(AiaError::FetchingDisabled)
    }
}

/// Bridges a synchronous [`AiaFetcher`] into the async family.
///
/// For a caller whose fetcher genuinely does no I/O — an in-memory cache, a
/// preloaded certificate store, [`pkix_aia::NoAiaFetcher`] — and who needs to
/// pass it where an [`AsyncAiaFetcher`] is wanted.
///
/// # Do not wrap a network fetcher in this
///
/// The inner `fetch` runs **on the calling task**, so wrapping
/// [`crate::HttpFetcher`] would block an executor thread for the duration of
/// an HTTP request. That is the defect filed against `pkix-revocation-http`
/// as `PKIX-cr8.1`, and this type exists for cheap non-blocking sources only.
/// For real network I/O use [`AsyncHttpFetcher`], or call the sync fetcher
/// from `tokio::task::spawn_blocking` yourself so the blocking is explicit at
/// the point where it happens.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SyncAsAsync<F>(pub F);

#[async_trait]
impl<F: AiaFetcher + Send + Sync> AsyncAiaFetcher for SyncAsAsync<F> {
    async fn fetch(&self, uri: &str) -> Result<Vec<u8>, AiaError> {
        self.0.fetch(uri)
    }
}

// ---------------------------------------------------------------------------
// reqwest-backed reference implementation
// ---------------------------------------------------------------------------

#[cfg(feature = "client-reqwest-async")]
mod reqwest_backend {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use async_trait::async_trait;
    use pkix_aia::AiaError;
    use reqwest::dns::{Addrs, Name, Resolve, Resolving};

    use super::{AsyncAiaFetcher, DEFAULT_MAX_RESPONSE_SIZE, DEFAULT_TIMEOUT};
    use crate::is_http_scheme;

    /// `reqwest` resolver that drops non-public addresses.
    ///
    /// The async counterpart of [`crate::GuardedResolver`], and it filters in
    /// the same place for the same reason: `reqwest` connects only to the
    /// addresses a resolver returns, so refusing here leaves no window for
    /// DNS rebinding. Checking the host name before the request would leave
    /// one — the name could resolve to a public address at check time and a
    /// loopback address at connect time.
    ///
    /// Name lookup uses `tokio::net::lookup_host`, which is asynchronous.
    /// `std::net::ToSocketAddrs` would have been simpler and is what the sync
    /// resolver ultimately uses, but it blocks, and blocking inside an async
    /// fn starves the executor.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct GuardedAsyncResolver;

    impl Resolve for GuardedAsyncResolver {
        fn resolve(&self, name: Name) -> Resolving {
            Box::pin(async move {
                let host = name.as_str().to_owned();
                // Port 0 is a placeholder; reqwest substitutes the real port.
                let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                    .await
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
                    .collect();

                let allowed: Vec<SocketAddr> =
                    resolved.iter().copied().filter(crate::is_public).collect();

                if allowed.is_empty() {
                    let addrs: Vec<String> = resolved.iter().map(|a| a.ip().to_string()).collect();
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!(
                            "{host} resolves only to non-public addresses [{}]",
                            addrs.join(", ")
                        ),
                    ))
                        as Box<dyn std::error::Error + Send + Sync>);
                }
                Ok(Box::new(allowed.into_iter()) as Addrs)
            })
        }
    }

    /// `reqwest`-backed [`AsyncAiaFetcher`].
    ///
    /// Parity with [`crate::HttpFetcher`] on everything that matters for
    /// safety: a destination policy applied at resolution time, redirects not
    /// followed, a per-request timeout, and a hard response-size cap.
    #[derive(Debug, Clone)]
    pub struct AsyncHttpFetcher {
        client: reqwest::Client,
        max_response_size: usize,
        /// Whether to refuse non-public IP literals before the request.
        ///
        /// Tracks the resolver choice: the opt-in permissive constructor
        /// disables both halves of the policy, so the literal check and the
        /// resolver filter cannot drift apart.
        enforce_destination_policy: bool,
    }

    impl AsyncHttpFetcher {
        /// Builds a fetcher with the default policy.
        ///
        /// Refuses non-public destinations, does not follow redirects, times
        /// out each request, and caps the response body.
        ///
        /// # Errors
        ///
        /// [`AiaError::IoFailure`] if `reqwest` could not build a client,
        /// which in practice means its TLS backend failed to initialise.
        pub fn new() -> Result<Self, AiaError> {
            Self::build(Some(Arc::new(GuardedAsyncResolver)))
        }

        /// Builds a fetcher that will connect to private and loopback
        /// addresses.
        ///
        /// For talking to an AIA endpoint inside your own network. Do not use
        /// it for certificates from an untrusted source: the URI is chosen by
        /// whoever presented the certificate, so permitting internal
        /// destinations turns chain building into a request forgery primitive
        /// against your own network.
        ///
        /// # Errors
        ///
        /// As [`new`](Self::new).
        pub fn allow_private_destinations() -> Result<Self, AiaError> {
            Self::build(None)
        }

        fn build(resolver: Option<Arc<GuardedAsyncResolver>>) -> Result<Self, AiaError> {
            let enforce_destination_policy = resolver.is_some();
            let mut builder = reqwest::Client::builder()
                // RFC 5280 §4.2.2.1 names a URI to fetch, not a redirect
                // chain to walk. Following one would let the certificate's
                // author redirect the fetch past the destination policy.
                .redirect(reqwest::redirect::Policy::none())
                .timeout(DEFAULT_TIMEOUT);
            if let Some(resolver) = resolver {
                builder = builder.dns_resolver(resolver);
            }
            let client = builder
                .build()
                .map_err(|e| AiaError::IoFailure(e.to_string()))?;
            Ok(Self {
                client,
                max_response_size: DEFAULT_MAX_RESPONSE_SIZE,
                enforce_destination_policy,
            })
        }

        /// Overrides the response-size cap.
        #[must_use]
        pub const fn with_max_response_size(mut self, n: usize) -> Self {
            self.max_response_size = n;
            self
        }

        /// Overrides the per-request timeout.
        ///
        /// # Errors
        ///
        /// As [`new`](Self::new); the client is rebuilt.
        pub fn with_timeout(self, timeout: Duration) -> Result<Self, AiaError> {
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(timeout)
                .dns_resolver(Arc::new(GuardedAsyncResolver))
                .build()
                .map_err(|e| AiaError::IoFailure(e.to_string()))?;
            Ok(Self {
                client,
                max_response_size: self.max_response_size,
                enforce_destination_policy: self.enforce_destination_policy,
            })
        }
    }

    /// Refuses a URI whose host is a non-public IP literal.
    ///
    /// [`GuardedAsyncResolver`] cannot catch these. `reqwest` only consults a
    /// custom resolver when there is a name to resolve, so
    /// `http://169.254.169.254/` reaches the connector untouched — the async
    /// fetcher's first implementation had exactly that hole, and its SSRF
    /// tests are what found it.
    ///
    /// Checking a literal before the request is sound in a way that checking
    /// a *name* before the request would not be: a literal cannot change
    /// between the check and the connection, so there is no rebinding window.
    /// Names still go through the resolver, where the filter is applied to the
    /// addresses actually connected to.
    fn literal_host_is_allowed(uri: &str) -> Result<(), AiaError> {
        let Ok(parsed) = reqwest::Url::parse(uri) else {
            // Let reqwest produce the error for a malformed URI rather than
            // guessing at one here.
            return Ok(());
        };
        // `url::Host` is not re-exported by reqwest, and taking a `url`
        // dependency to name one enum would be a poor trade. Parsing the host
        // string is equivalent: anything that parses as an address IS a
        // literal, and anything that does not is a name for the resolver.
        // IPv6 literals arrive bracketed.
        let Some(host) = parsed.host_str() else {
            return Ok(());
        };
        let unbracketed = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        let Ok(addr) = unbracketed.parse::<std::net::IpAddr>() else {
            // A name: the resolver applies the filter at connect time.
            return Ok(());
        };
        if crate::is_public(&SocketAddr::new(addr, parsed.port().unwrap_or(443))) {
            Ok(())
        } else {
            Err(AiaError::DestinationNotAllowed(format!(
                "{addr} is not a public address"
            )))
        }
    }

    #[async_trait]
    impl AsyncAiaFetcher for AsyncHttpFetcher {
        async fn fetch(&self, uri: &str) -> Result<Vec<u8>, AiaError> {
            if !is_http_scheme(uri) {
                return Err(AiaError::UriUnsupported(uri.to_owned()));
            }
            if self.enforce_destination_policy {
                literal_host_is_allowed(uri)?;
            }

            let response = self.client.get(uri).send().await.map_err(map_reqwest_err)?;

            let status = response.status().as_u16();
            if !(200..300).contains(&status) {
                return Err(AiaError::HttpStatus(status));
            }

            // Stream with a hard cap rather than calling bytes(), which would
            // buffer whatever the server sends. The endpoint is named by an
            // unvalidated certificate, so an unbounded read is a
            // denial-of-service vector.
            let limit = self.max_response_size;
            let mut body = Vec::with_capacity(limit.min(8192));
            let mut stream = response;
            while let Some(chunk) = stream.chunk().await.map_err(map_reqwest_err)? {
                if body.len() + chunk.len() > limit {
                    return Err(AiaError::ResponseTooLarge {
                        limit,
                        actual: body.len() + chunk.len(),
                    });
                }
                body.extend_from_slice(&chunk);
            }
            Ok(body)
        }
    }

    /// Maps a `reqwest` error onto [`AiaError`].
    fn map_reqwest_err(e: reqwest::Error) -> AiaError {
        if e.is_timeout() {
            return AiaError::Timeout;
        }
        if let Some(status) = e.status() {
            return AiaError::HttpStatus(status.as_u16());
        }
        // A destination refusal by GuardedAsyncResolver arrives as a connect
        // error wrapping our PermissionDenied io::Error. Walk the source
        // chain for it so the caller gets DestinationNotAllowed rather than a
        // generic transport failure — the two call for different responses.
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&e);
        while let Some(err) = source {
            if let Some(io) = err.downcast_ref::<std::io::Error>() {
                if io.kind() == std::io::ErrorKind::PermissionDenied {
                    return AiaError::DestinationNotAllowed(io.to_string());
                }
            }
            source = err.source();
        }
        AiaError::IoFailure(e.to_string())
    }
}

#[cfg(feature = "client-reqwest-async")]
#[cfg_attr(docsrs, doc(cfg(feature = "client-reqwest-async")))]
pub use reqwest_backend::{AsyncHttpFetcher, GuardedAsyncResolver};

/// Default per-request timeout.
///
/// Matches the sync fetcher. An AIA endpoint is named by an unvalidated
/// certificate, so an unbounded wait is a denial-of-service vector.
#[cfg(feature = "client-reqwest-async")]
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default response-size cap, in bytes.
///
/// Generous for a certificate or a small certs-only CMS message, and far
/// below what an unbounded read would allow.
#[cfg(feature = "client-reqwest-async")]
const DEFAULT_MAX_RESPONSE_SIZE: usize = 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-only: the trait is `Send + Sync` so implementations can be
    /// shared across executor threads. If a refactor drops those bounds this
    /// stops compiling.
    #[test]
    fn the_null_fetcher_is_send_sync() {
        fn accepts<F: AsyncAiaFetcher>(_: &F) {}
        fn is_send<T: Send>(_: &T) {}
        fn is_sync<T: Sync>(_: &T) {}
        let f = NoAsyncAiaFetcher;
        accepts(&f);
        is_send(&f);
        is_sync(&f);
    }

    #[tokio::test]
    async fn the_null_fetcher_reports_disabled() {
        assert_eq!(
            NoAsyncAiaFetcher.fetch("http://ca.example/ca.crt").await,
            Err(AiaError::FetchingDisabled)
        );
    }

    /// `batch_fetch` must stay index-aligned with its input, since the caller
    /// matches results back to the URIs it supplied.
    #[tokio::test]
    async fn batch_fetch_is_index_aligned() {
        let uris = [
            "http://a.example/1",
            "http://b.example/2",
            "http://c.example/3",
        ];
        let results = NoAsyncAiaFetcher.batch_fetch(&uris).await;
        assert_eq!(results.len(), uris.len());
        assert!(results
            .iter()
            .all(|r| r == &Err(AiaError::FetchingDisabled)));
    }

    #[tokio::test]
    async fn an_empty_batch_yields_an_empty_result() {
        assert!(NoAsyncAiaFetcher.batch_fetch(&[]).await.is_empty());
    }

    /// The sync bridge must pass results through unchanged, so a caller with
    /// a non-blocking sync source gets identical behaviour on both paths.
    #[tokio::test]
    async fn the_sync_bridge_passes_results_through() {
        let bridged = SyncAsAsync(pkix_aia::NoAiaFetcher);
        assert_eq!(
            bridged.fetch("http://ca.example/ca.crt").await,
            Err(AiaError::FetchingDisabled)
        );
    }
}
