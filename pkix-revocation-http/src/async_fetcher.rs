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
    pub(crate) now_unix: u64,
}

#[cfg(feature = "crl")]
impl<F, V> AsyncHttpCrlFetcher<F, V> {
    /// Create a new `AsyncHttpCrlFetcher`.
    ///
    /// - `fetcher`  — async HTTP transport implementation
    /// - `verifier` — signature verifier passed to each on-demand
    ///   [`pkix_revocation::CrlChecker`]
    /// - `now_unix` — current time as seconds since the Unix epoch
    pub const fn new(fetcher: F, verifier: V, now_unix: u64) -> Self {
        Self {
            fetcher,
            verifier,
            now_unix,
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
    pub(crate) now_unix: u64,
    pub(crate) hash_alg: OcspHashAlg,
}

#[cfg(feature = "ocsp")]
impl<F, V> AsyncHttpOcspFetcher<F, V> {
    /// Create a new `AsyncHttpOcspFetcher`.
    ///
    /// - `fetcher`  — async HTTP transport implementation
    /// - `verifier` — signature verifier passed to each on-demand
    ///   [`pkix_revocation::OcspChecker`]
    /// - `now_unix` — current time as seconds since the Unix epoch
    ///
    /// The `CertID.hashAlgorithm` defaults to [`OcspHashAlg::Sha256`];
    /// override via [`AsyncHttpOcspFetcher::with_hash_alg`].
    #[must_use]
    pub const fn new(fetcher: F, verifier: V, now_unix: u64) -> Self {
        Self {
            fetcher,
            verifier,
            now_unix,
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
