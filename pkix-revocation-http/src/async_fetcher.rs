//! Async analogues of [`crate::RevocationFetcher`], the per-cert
//! [`pkix_revocation::RevocationChecker`], and the [`crate::HttpCrlFetcher`]
//! / [`crate::HttpOcspFetcher`] wrappers.
//!
//! # Design — why a separate async trait family (Option C)
//!
//! `pkix-revocation::RevocationChecker` is and stays a synchronous trait.
//! That keeps the core revocation crate free of async machinery and lets
//! consumers in `no_std`-style environments (kernel-mode TLS, embedded)
//! depend on it without pulling in tokio / async-trait / futures.
//!
//! When designing the async story we considered three shapes (see the
//! parent bead PKIX-a1yc.10):
//!
//! - **A. Add `AsyncRevocationChecker` into `pkix-revocation` itself.**
//!   Forces the core crate to take a stance on async machinery and
//!   propagates `async-trait` / `Send` bounds into every consumer,
//!   including those that never want async. Rejected.
//! - **B. One async fetcher trait, sync `HttpCrlFetcher` that
//!   `block_on`s.** Calling `block_on` from inside a running async
//!   runtime is a well-known footgun (deadlocks the executor). Rejected.
//! - **C. Two parallel families, async lives in
//!   `pkix-revocation-http`.** Sync code path is unchanged.
//!   `AsyncRevocationFetcher` is the async analogue of the existing sync
//!   `RevocationFetcher`. `AsyncRevocationChecker` is the async analogue
//!   of `pkix_revocation::RevocationChecker` but lives here, NOT in
//!   `pkix-revocation`. `AsyncHttpCrlFetcher` / `AsyncHttpOcspFetcher`
//!   implement `AsyncRevocationChecker`. Mirrors how `reqwest` ships
//!   separate `Client` (async) and `blocking::Client` (sync) types.
//!   **Adopted.**
//!
//! # Stability
//!
//! Everything in this module is gated behind the crate-level `async`
//! feature. The reference [`reqwest`]-backed
//! [`AsyncRevocationFetcher`][crate::AsyncRevocationFetcher] impl is
//! additionally gated behind `client-reqwest-async` so consumers picking
//! a different async HTTP client (hyper, isahc-async, custom) do not
//! pay for reqwest in their dep graph.
//!
//! # Runtime
//!
//! The trait surface here is runtime-agnostic — it returns
//! `impl Future + Send`. Consumers drive the futures with their chosen
//! runtime (`tokio`, `async-std`, `smol`, ...). The reference reqwest
//! backend requires a tokio runtime to actually drive its sockets; that
//! constraint is reqwest's, not ours.
//!
//! # Verification runs on the calling task, and can block it for tens of
//! milliseconds
//!
//! Only the fetches are asynchronous. Once bytes arrive, this module
//! decodes the CRL or OCSP response and verifies its signature
//! synchronously, inside the `async fn`, on whatever executor thread is
//! polling the future. Nothing yields during that work, so the thread
//! runs no other task until it finishes.
//!
//! How long that is depends almost entirely on CRL size, and the range
//! is wide. Measured on one x86-64 machine with a release build,
//! verifying an RSA-2048-signed CRL and looking one serial up in it:
//!
//! | revoked entries | CRL size  | per verification |
//! |-----------------|-----------|------------------|
//! | 1 000           | 20 KiB    | 0.4 ms           |
//! | 20 000          | 410 KiB   | 7.8 ms           |
//! | 100 000         | 2.1 MiB   | 34 ms            |
//!
//! Signature verification is a small constant; the cost is dominated by
//! DER-decoding the revoked-certificate list, so it grows with the
//! number of entries. Large-CA CRLs reach the bottom row. (Reproduce
//! with `examples/crl_verify_cost.rs`.)
//!
//! A multi-threaded executor runs one worker per core by default, so a
//! 34 ms verification stalls every other task assigned to that worker
//! for 34 ms — latency that shows up on requests having nothing to do
//! with the certificate being validated.
//!
//! ## Why this module does not fix it for you
//!
//! Moving the work off the executor means handing it to a blocking pool,
//! and every such pool belongs to a specific runtime
//! (`tokio::task::spawn_blocking`, `async_global_executor::spawn_blocking`,
//! ...). Calling one here would make this crate depend on a runtime and
//! impose that choice on consumers who picked a different one — the same
//! objection that ruled out shape B above. So the decision stays with
//! the consumer, who knows which runtime is running.
//!
//! ## Doing it yourself
//!
//! The split is already available in public API, because the I/O half
//! and the CPU half are separate public pieces:
//!
//! - [`crate::extract_cdp_http_urls`] / [`crate::extract_aia_http_urls`]
//!   read the URLs off the certificate (no I/O, microseconds).
//! - Your own HTTP client fetches them (I/O, `await`).
//! - [`pkix_revocation::CrlChecker`] / [`pkix_revocation::OcspChecker`]
//!   do the decode and verify (CPU, no I/O) and own their inputs.
//!
//! Because the checkers take owned bytes and borrow only the
//! certificates, the CPU half moves to a blocking pool cleanly. With
//! tokio:
//!
//! ```ignore
//! let urls = pkix_revocation_http::extract_cdp_http_urls(cert)?;
//! let bytes = my_client.get(&urls[0]).await?;   // I/O on the executor
//!
//! // Clone what the closure needs so it can outlive this frame, then
//! // verify on the blocking pool instead of the executor thread.
//! let (cert, issuer, verifier) = (cert.clone(), issuer.clone(), verifier.clone());
//! let verdict = tokio::task::spawn_blocking(move || {
//!     let checker = pkix_revocation::CrlChecker::new(bytes, now_unix, verifier)?;
//!     checker.check_revocation(&cert, &issuer)
//! })
//! .await
//! .expect("the verification closure does not panic")?;
//! ```
//!
//! Implement [`AsyncRevocationChecker`] over that and the rest of the
//! workspace uses it exactly as it uses the wrappers here.
//!
//! The wrappers in this module remain the right choice when CRLs are
//! small, when OCSP is used instead (a single-response OCSP answer is
//! orders of magnitude cheaper to verify than a large CRL), or when the
//! executor is not shared with latency-sensitive work.

#[cfg(feature = "ocsp")]
use crate::OcspHashAlg;
use crate::{FetchError, FetchRequest, FetchResponse};
use async_trait::async_trait;
use pkix_path::TrustAnchor;
use x509_cert::Certificate;

/// Async analogue of [`crate::RevocationFetcher`].
///
/// Implement this trait to plug in your own async HTTP client. The
/// fetcher is invoked by [`AsyncHttpCrlFetcher`] and
/// [`AsyncHttpOcspFetcher`] with a [`FetchRequest`] whose method
/// indicates whether to perform a `GET` (for CRL fetches) or a `POST`
/// carrying a DER-encoded OCSP request (per RFC 6960 §A.1).
///
/// Use [`crate::RevocationFetcher`] for synchronous environments.
///
/// # `Send` bounds
///
/// The trait is `Send` so impls can be used from multi-threaded async
/// runtimes (tokio's multi-threaded scheduler, async-std). The returned
/// future is also `Send` via `#[async_trait]`'s default expansion.
///
/// # Errors
///
/// The `Result` mirrors the sync trait so consumers can reuse the same
/// [`FetchError`] handling. Transport-level errors live in the
/// `FetchError::Transport` boxed-error variant; the boxed error is
/// `Send + Sync` so it crosses task boundaries cleanly.
#[async_trait]
pub trait AsyncRevocationFetcher: Send + Sync {
    /// Issue an HTTP request and return the response.
    ///
    /// # Errors
    ///
    /// Returns [`FetchError::Transport`] on network or transport failure,
    /// [`FetchError::HttpStatus`] on a non-2xx HTTP response, or
    /// [`FetchError::TooLarge`] if the response body exceeds the
    /// implementation's configured size limit.
    async fn fetch(&self, req: &FetchRequest<'_>) -> Result<FetchResponse, FetchError>;
}

/// Async analogue of [`pkix_revocation::RevocationChecker`].
///
/// Lives in `pkix-revocation-http` (not `pkix-revocation`) so the core
/// revocation crate stays sync-only and async-machinery-free. See the
/// module-level "why a separate async trait family" notes for rationale.
///
/// The method signatures mirror [`pkix_revocation::RevocationChecker`]
/// exactly — same arguments, same `pkix_revocation::Result`, same
/// per-cert + against-anchor split — so consumers that want both async
/// and sync support can write thin parallel implementations.
///
/// # Implementing this trait
///
/// Implementors MUST provide `check_revocation`. As with the sync
/// trait, `check_revocation_against_anchor` defaults to `Ok(())`. The
/// same security caveat applies: forgetting to override the
/// anchor-aware method silently skips revocation for the
/// anchor-issued certificate. Override it if your threat model requires
/// full-chain coverage.
#[async_trait]
pub trait AsyncRevocationChecker: Send + Sync {
    /// Check whether `cert` has been revoked.
    ///
    /// See [`pkix_revocation::RevocationChecker::check_revocation`] for
    /// the contract; this is the async equivalent.
    ///
    /// # Errors
    ///
    /// Returns any [`pkix_revocation::Error`] variant the underlying
    /// revocation source surfaces. Network and parse failures are
    /// reported as [`pkix_revocation::Error::RevocationFetchFailed`].
    async fn check_revocation(
        &self,
        cert: &Certificate,
        issuer: &Certificate,
    ) -> pkix_revocation::Result<()>;

    /// Check whether `cert` (issued directly by a trust anchor) has
    /// been revoked.
    ///
    /// Defaults to `Ok(())`. Override to enforce revocation against the
    /// anchor-issued certificate; see the security note on
    /// [`pkix_revocation::RevocationChecker::check_revocation_against_anchor`].
    ///
    /// # Errors
    ///
    /// The default implementation always returns `Ok(())`; override
    /// this method to enable error-returning revocation checks.
    async fn check_revocation_against_anchor(
        &self,
        _cert: &Certificate,
        _anchor: &TrustAnchor,
    ) -> pkix_revocation::Result<()> {
        Ok(())
    }
}

/// Async analogue of [`crate::HttpCrlFetcher`].
///
/// Reads `CRLDistributionPoints` from each certificate, fetches the
/// CRL via the provided [`AsyncRevocationFetcher`], and delegates to
/// [`pkix_revocation::CrlChecker`] using the supplied
/// [`pkix_path::SignatureVerifier`] to verify the CRL signature.
///
/// Verifier dispatch is synchronous because signature verification
/// does not block on I/O; only the URL fetches are async.
///
/// See [RFC 5280 §4.2.1.13](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13).
#[cfg(feature = "crl")]
#[cfg_attr(docsrs, doc(cfg(all(feature = "async", feature = "crl"))))]
#[derive(Clone, Debug)]
pub struct AsyncHttpCrlFetcher<F, V> {
    pub(crate) fetcher: F,
    pub(crate) verifier: V,
    pub(crate) clock: crate::time::Clock,
}

#[cfg(feature = "crl")]
impl<F, V> AsyncHttpCrlFetcher<F, V> {
    /// Create a new `AsyncHttpCrlFetcher` pinned to one instant.
    ///
    /// - `fetcher`  — async HTTP transport implementation
    /// - `verifier` — signature verifier passed to each on-demand
    ///   [`pkix_revocation::CrlChecker`]
    /// - `now_unix` — the instant every check is judged against, as
    ///   seconds since the Unix epoch
    ///
    /// # Lifetime of `now_unix`
    ///
    /// Fixed for the life of the fetcher, which matters more here than
    /// on the sync side: an async fetcher is almost always built once
    /// and shared by a server for the life of the process, so this
    /// constructor would freeze freshness at startup. Use
    /// [`with_system_clock`](Self::with_system_clock) unless the fixed
    /// instant is what you want, as it is in tests.
    pub const fn new(fetcher: F, verifier: V, now_unix: u64) -> Self {
        Self {
            fetcher,
            verifier,
            clock: crate::time::Clock::Fixed(now_unix),
        }
    }

    /// Create a new `AsyncHttpCrlFetcher` that reads the system clock
    /// once per revocation check.
    pub const fn with_system_clock(fetcher: F, verifier: V) -> Self {
        Self {
            fetcher,
            verifier,
            clock: crate::time::Clock::System,
        }
    }

    /// Create a new `AsyncHttpCrlFetcher` driven by a caller-supplied
    /// clock. See [`crate::TimeSource`].
    pub fn with_time_source(
        fetcher: F,
        verifier: V,
        source: std::sync::Arc<dyn crate::TimeSource>,
    ) -> Self {
        Self {
            fetcher,
            verifier,
            clock: crate::time::Clock::Custom(source),
        }
    }
}

/// Async analogue of [`crate::HttpOcspFetcher`].
///
/// Reads `AuthorityInfoAccess` from each certificate, POSTs a
/// DER-encoded OCSP request via the provided
/// [`AsyncRevocationFetcher`] (per RFC 6960 §A.1), and delegates to
/// [`pkix_revocation::OcspChecker`] using the supplied
/// [`pkix_path::SignatureVerifier`] to verify the response signature.
#[cfg(feature = "ocsp")]
#[cfg_attr(docsrs, doc(cfg(all(feature = "async", feature = "ocsp"))))]
#[derive(Clone, Debug)]
pub struct AsyncHttpOcspFetcher<F, V> {
    pub(crate) fetcher: F,
    pub(crate) verifier: V,
    pub(crate) clock: crate::time::Clock,
    pub(crate) hash_alg: OcspHashAlg,
}

#[cfg(feature = "ocsp")]
impl<F, V> AsyncHttpOcspFetcher<F, V> {
    /// Create a new `AsyncHttpOcspFetcher` pinned to one instant.
    ///
    /// - `fetcher`  — async HTTP transport implementation
    /// - `verifier` — signature verifier passed to each on-demand
    ///   [`pkix_revocation::OcspChecker`]
    /// - `now_unix` — the instant every check is judged against, as
    ///   seconds since the Unix epoch
    ///
    /// The `CertID.hashAlgorithm` defaults to [`OcspHashAlg::Sha256`];
    /// override via [`AsyncHttpOcspFetcher::with_hash_alg`].
    ///
    /// # Lifetime of `now_unix`
    ///
    /// Fixed for the life of the fetcher; see
    /// [`AsyncHttpCrlFetcher::new`] for why that is usually wrong for a
    /// long-lived async fetcher.
    #[must_use]
    pub const fn new(fetcher: F, verifier: V, now_unix: u64) -> Self {
        Self {
            fetcher,
            verifier,
            clock: crate::time::Clock::Fixed(now_unix),
            hash_alg: OcspHashAlg::Sha256,
        }
    }

    /// Create a new `AsyncHttpOcspFetcher` that reads the system clock
    /// once per revocation check.
    #[must_use]
    pub const fn with_system_clock(fetcher: F, verifier: V) -> Self {
        Self {
            fetcher,
            verifier,
            clock: crate::time::Clock::System,
            hash_alg: OcspHashAlg::Sha256,
        }
    }

    /// Create a new `AsyncHttpOcspFetcher` driven by a caller-supplied
    /// clock. See [`crate::TimeSource`].
    #[must_use]
    pub fn with_time_source(
        fetcher: F,
        verifier: V,
        source: std::sync::Arc<dyn crate::TimeSource>,
    ) -> Self {
        Self {
            fetcher,
            verifier,
            clock: crate::time::Clock::Custom(source),
            hash_alg: OcspHashAlg::Sha256,
        }
    }

    /// Override the OCSP `CertID.hashAlgorithm`.
    ///
    /// Default is SHA-256 because nearly all responders deployed today
    /// support it. Use SHA-1 only for compatibility with very old
    /// responders.
    #[must_use]
    pub const fn with_hash_alg(mut self, alg: OcspHashAlg) -> Self {
        self.hash_alg = alg;
        self
    }
}

#[cfg(test)]
mod tests {
    //! Trait-shape tests for the async family. These mirror the trait-shape
    //! tests in `lib.rs::tests` (sync side) and do not exercise any I/O.
    //! Behavioural verification lives in the per-impl modules
    //! (`async_crl.rs`, `async_ocsp.rs`) and the integration test suite.

    use super::*;

    /// Stand-in async fetcher: every call returns a fixed error. Proves
    /// the trait has the right shape and is `Send + Sync`.
    struct NullAsyncFetcher;

    #[async_trait]
    impl AsyncRevocationFetcher for NullAsyncFetcher {
        async fn fetch(&self, _req: &FetchRequest<'_>) -> Result<FetchResponse, FetchError> {
            Err(FetchError::HttpStatus(503))
        }
    }

    /// Compile-only: the trait is `Send + Sync`-bound so impls can be
    /// shared across tokio worker threads. If a future refactor drops
    /// those bounds this stops compiling.
    #[test]
    fn async_fetcher_is_send_sync() {
        fn _accepts<F: AsyncRevocationFetcher>(_: &F) {}
        let f = NullAsyncFetcher;
        _accepts(&f);
        // Send + Sync witnesses.
        fn _is_send<T: Send>(_: &T) {}
        fn _is_sync<T: Sync>(_: &T) {}
        _is_send(&f);
        _is_sync(&f);
    }

    #[cfg(feature = "crl")]
    #[test]
    fn async_http_crl_fetcher_constructs() {
        struct DummyVerifier;
        let _f: AsyncHttpCrlFetcher<NullAsyncFetcher, DummyVerifier> =
            AsyncHttpCrlFetcher::new(NullAsyncFetcher, DummyVerifier, 0);
    }

    #[cfg(feature = "ocsp")]
    #[test]
    fn async_http_ocsp_fetcher_constructs() {
        struct DummyVerifier;
        let _f: AsyncHttpOcspFetcher<NullAsyncFetcher, DummyVerifier> =
            AsyncHttpOcspFetcher::new(NullAsyncFetcher, DummyVerifier, 0);
    }

    #[cfg(feature = "ocsp")]
    #[test]
    fn async_http_ocsp_fetcher_with_hash_alg_overrides() {
        struct DummyVerifier;
        let f = AsyncHttpOcspFetcher::new(NullAsyncFetcher, DummyVerifier, 0)
            .with_hash_alg(OcspHashAlg::Sha1);
        assert!(matches!(f.hash_alg, OcspHashAlg::Sha1));
    }

    /// Default-impl shape: a type can implement `AsyncRevocationChecker`
    /// by providing only `check_revocation`, inheriting the trait's
    /// `check_revocation_against_anchor` default. This is purely a
    /// compile-time check; the actual `Ok(())`-from-default behaviour is
    /// exercised end-to-end in the per-impl modules where real
    /// `AsyncHttpCrlFetcher` / `AsyncHttpOcspFetcher` types rely on it.
    #[test]
    fn checker_can_omit_anchor_method() {
        struct NullChecker;
        #[async_trait]
        impl AsyncRevocationChecker for NullChecker {
            async fn check_revocation(
                &self,
                _cert: &Certificate,
                _issuer: &Certificate,
            ) -> pkix_revocation::Result<()> {
                Ok(())
            }
            // Intentionally NOT overriding check_revocation_against_anchor.
        }
        fn _accepts<C: AsyncRevocationChecker>(_: &C) {}
        _accepts(&NullChecker);
    }
}
