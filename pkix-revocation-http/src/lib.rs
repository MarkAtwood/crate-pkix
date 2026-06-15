#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! Online CRL and OCSP fetching for [`pkix_revocation`].
//!
//! Extends `pkix-revocation` with the ability to fetch revocation data from
//! URLs found in certificates (`CRLDistributionPoints`,
//! `AuthorityInfoAccess`), rather than requiring the caller to supply
//! pre-fetched DER bytes.
//!
//! # Design
//!
//! The [`RevocationFetcher`] trait abstracts the HTTP transport so callers
//! can supply `reqwest`, `ureq`, `hyper`, or any other client. The concrete
//! fetchers ([`HttpCrlFetcher`], [`HttpOcspFetcher`]) implement
//! [`pkix_revocation::RevocationChecker`] by fetching on demand and
//! delegating to the underlying `CrlChecker` / `OcspChecker`.
//!
//! Requests are described by [`FetchRequest`] (URL + method) so a single
//! trait method covers both HTTP `GET` (CRL fetch) and HTTP `POST` (OCSP
//! query, which carries a DER-encoded request body and a fixed content
//! type per RFC 6960 §A.1).
//!
//! # Async (feature `async`)
//!
//! An async parallel of the trait family lives behind the `async`
//! feature: [`AsyncRevocationFetcher`], [`AsyncRevocationChecker`],
//! [`AsyncHttpCrlFetcher`], [`AsyncHttpOcspFetcher`]. The async
//! [`AsyncRevocationChecker`] is defined in this crate (NOT in
//! `pkix-revocation`) so the core revocation crate stays sync-only and
//! free of `async-trait` machinery. The async API mirrors the sync API
//! exactly — same arguments, same error type, same per-cert +
//! against-anchor split — so consumers can write thin parallel impls
//! for both flavours when needed. See [`AsyncRevocationFetcher`] for
//! the architectural rationale (we considered three shapes; landed on
//! "two parallel families").
//!
//! A reference [`AsyncRevocationFetcher`] backed by `reqwest`'s async
//! client lives at [`crate::clients::reqwest::ReqwestFetcher`] behind
//! the `client-reqwest-async` feature. Consumers using a different
//! async HTTP backend (hyper, isahc-async, custom) implement
//! [`AsyncRevocationFetcher`] themselves and pay no reqwest cost.
//!
//! # Spec references
//!
//! - RFC 5280 §4.2.1.13 — `CRLDistributionPoints` extension
//! - RFC 5280 §4.2.2.1  — `AuthorityInfoAccess` extension
//! - RFC 5280 §6.3      — CRL validation algorithm
//! - RFC 6960 §4.1, §A.1 — OCSP request and HTTP transport
//!
//! # Caching (feature-gated)
//!
//! [`CachedHttpCrlFetcher`] and [`CachedHttpOcspFetcher`] wrap their
//! uncached counterparts with a pluggable [`RevocationCache`] so repeat
//! validations within a CRL's / OCSP response's freshness window do not
//! re-hit the network. The reference [`InMemoryCache`] is unbounded;
//! consumers needing eviction implement [`RevocationCache`] over their
//! preferred backing store (e.g. `moka`, Redis). See PKIX-a1yc.7.
//!
//! # Status
//!
//! Tracked under PKIX-a1yc. The trait surface, the concrete
//! [`pkix_revocation::RevocationChecker`] impls for sync CRL / OCSP
//! fetching, and the in-memory cache layer are in place. Online HTTP
//! fetchers (`clients::ureq::UreqFetcher`,
//! `clients::reqwest::ReqwestFetcher`) are gated behind their
//! respective `client-*` features.
//!
//! # Limitations
//!
//! - **No bundled HTTP client by default.** Enabling the `crl` or `ocsp`
//!   feature gives you the [`RevocationFetcher`] trait and the wrapper
//!   structs that implement [`pkix_revocation::RevocationChecker`] over
//!   that trait. You supply the actual transport. Reference clients are
//!   gated behind `client-ureq` (sync, rustls-backed HTTPS) and
//!   `client-reqwest-async` (async, requires `async` feature and an
//!   async runtime).
//! - **No retry / backoff policy.** Network failure handling — retry,
//!   exponential backoff, jitter, circuit-breaking — is the caller's
//!   choice and lives in the supplied [`RevocationFetcher`] implementation.
//! - **Async runtime is caller-supplied.** When `client-reqwest-async` is
//!   enabled, the futures returned by the reference reqwest fetcher are
//!   not bound to any specific runtime. Callers drive them with tokio,
//!   async-std, smol, or any other executor.
//! - **Cache shape is intentionally minimal.** The shipped [`InMemoryCache`]
//!   is unbounded by design (lint-scope decision is to keep the reference
//!   cache trivially correct). Production deployments needing eviction
//!   (LRU, TTL bounded by memory pressure) implement [`RevocationCache`]
//!   over `moka`, Redis, or any backing store they prefer.
//! - **No CDP / AIA URI filtering.** This crate fetches whichever URI is
//!   in the certificate's [`CRLDistributionPoints`] or
//!   [`AuthorityInfoAccess`] extension. Restrictions on which hosts /
//!   schemes are acceptable for revocation fetches (e.g., enforcing
//!   HTTPS or blocking private-network URIs) are a deployment-policy
//!   decision and stay outside this crate.
//!
//! [`CRLDistributionPoints`]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.13
//! [`AuthorityInfoAccess`]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.1

// In-memory cache + cached wrappers (PKIX-a1yc.7). Gated on either
// `crl` or `ocsp` because the trait itself is shared but the wrapper
// structs and parsing helpers each live behind their protocol feature.
#[cfg(any(feature = "crl", feature = "ocsp"))]
mod cache;
pub mod clients;
#[cfg(feature = "crl")]
mod crl;
mod extract;
#[cfg(feature = "ocsp")]
mod ocsp;
#[cfg(feature = "ocsp")]
mod ocsp_request;

// Async trait family (PKIX-a1yc.10). Gated on the `async` feature so the
// default build profile is unchanged. Sub-impls reuse the per-protocol
// feature flags (`crl`, `ocsp`) so an async build can opt into one
// protocol without the other.
#[cfg(all(feature = "async", feature = "crl"))]
mod async_crl;
#[cfg(feature = "async")]
mod async_fetcher;
#[cfg(all(feature = "async", feature = "ocsp"))]
mod async_ocsp;

#[cfg(all(feature = "async", feature = "crl"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "async", feature = "crl"))))]
pub use async_fetcher::AsyncHttpCrlFetcher;
#[cfg(all(feature = "async", feature = "ocsp"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "async", feature = "ocsp"))))]
pub use async_fetcher::AsyncHttpOcspFetcher;
#[cfg(feature = "async")]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
pub use async_fetcher::{AsyncRevocationChecker, AsyncRevocationFetcher};

#[cfg(feature = "crl")]
#[cfg_attr(docsrs, doc(cfg(feature = "crl")))]
pub use cache::CachedHttpCrlFetcher;
#[cfg(feature = "ocsp")]
#[cfg_attr(docsrs, doc(cfg(feature = "ocsp")))]
pub use cache::CachedHttpOcspFetcher;
#[cfg(any(feature = "crl", feature = "ocsp"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "crl", feature = "ocsp"))))]
pub use cache::{
    CachedCrl, CachedOcspResponse, CrlCacheKey, InMemoryCache, OcspCacheKey, RevocationCache,
};
pub use extract::{extract_aia_http_urls, extract_cdp_http_urls, AiaUrls};

/// `Content-Type` for an OCSP request body, per RFC 6960 §A.1.
#[cfg(feature = "ocsp")]
pub(crate) const OCSP_REQUEST_CT: &str = "application/ocsp-request";
#[cfg(feature = "ocsp")]
#[cfg_attr(docsrs, doc(cfg(feature = "ocsp")))]
pub use ocsp_request::{build_ocsp_request, BuildError, OcspHashAlg, OcspRequestBytes};

/// Errors returned by the URL-extraction helpers
/// ([`extract_cdp_http_urls`], [`extract_aia_http_urls`]).
///
/// Lives at the crate root so future helpers (e.g., the OCSP request
/// builder in PKIX-a1yc.4) can share the same error type without forcing
/// callers to import a sub-module.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExtractError {
    /// The certificate had the requested extension but its value did not
    /// decode as the expected ASN.1 structure.
    Der(der::Error),
}

impl core::fmt::Display for ExtractError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Der(e) => write!(f, "extension DER decode error: {e}"),
        }
    }
}

impl std::error::Error for ExtractError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Der(e) => Some(e),
        }
    }
}

impl From<der::Error> for ExtractError {
    fn from(e: der::Error) -> Self {
        Self::Der(e)
    }
}

/// HTTP transport for fetching revocation data.
///
/// Implement this trait to plug in your own HTTP client (`reqwest` blocking,
/// `ureq`, `hyper` with a sync wrapper, etc.). The fetcher is invoked by
/// [`HttpCrlFetcher`] and [`HttpOcspFetcher`] with a [`FetchRequest`] whose
/// method indicates whether to perform a `GET` (for CRL fetches) or a
/// `POST` carrying a DER-encoded OCSP request (per RFC 6960 §A.1).
///
/// The trait is intentionally synchronous. An async analogue is tracked
/// under PKIX-a1yc.10.
pub trait RevocationFetcher {
    /// Issue an HTTP request and return the response.
    ///
    /// # Errors
    ///
    /// Returns [`FetchError::Transport`] on network or transport failure,
    /// [`FetchError::HttpStatus`] on a non-2xx HTTP response, or
    /// [`FetchError::TooLarge`] if the response body exceeds the
    /// implementation's configured size limit.
    fn fetch(&self, req: &FetchRequest<'_>) -> Result<FetchResponse, FetchError>;
}

/// A single HTTP request to a revocation-data endpoint.
///
/// Constructed via [`FetchRequest::get`] or [`FetchRequest::post`]. The
/// borrow lifetime keeps URL and body slices in place without forcing the
/// fetcher implementation to clone them; impls that need owned values
/// (e.g. for spawning to a background runtime) clone explicitly.
#[derive(Debug)]
pub struct FetchRequest<'a> {
    /// Absolute HTTP/HTTPS URL of the resource.
    ///
    /// Callers SHOULD reject non-HTTP schemes during URL extraction
    /// (PKIX-a1yc.2 / PKIX-a1yc.3) so fetcher impls can assume a valid
    /// `http://` or `https://` URL here.
    pub url: &'a str,
    /// HTTP method and (for `POST`) request body.
    pub method: FetchMethod<'a>,
}

impl<'a> FetchRequest<'a> {
    /// Build a `GET` request — used for CRL fetches.
    #[must_use]
    pub const fn get(url: &'a str) -> Self {
        Self {
            url,
            method: FetchMethod::Get,
        }
    }

    /// Build a `POST` request — used for OCSP queries.
    ///
    /// `body` is the DER-encoded OCSP request; `content_type` is the
    /// `Content-Type` header value (`application/ocsp-request` per
    /// RFC 6960 §A.1).
    #[must_use]
    pub const fn post(url: &'a str, body: &'a [u8], content_type: &'a str) -> Self {
        Self {
            url,
            method: FetchMethod::Post { body, content_type },
        }
    }
}

/// HTTP method for a [`FetchRequest`].
#[derive(Debug)]
#[non_exhaustive]
pub enum FetchMethod<'a> {
    /// HTTP `GET` (for CRL fetches).
    Get,
    /// HTTP `POST` with a request body and `Content-Type` (for OCSP
    /// queries).
    Post {
        /// Request body bytes (DER-encoded `OCSPRequest`).
        body: &'a [u8],
        /// Value of the `Content-Type` request header.
        content_type: &'a str,
    },
}

/// Response from a successful [`RevocationFetcher::fetch`] call.
///
/// `bytes` are the raw response body. `content_type` is the response
/// `Content-Type` header verbatim (or `None` if the transport did not
/// report one); higher layers may sanity-check it (`application/pkix-crl`
/// for CRLs, `application/ocsp-response` for OCSP) but MUST NOT make it
/// fatal — many real-world responders set incorrect or missing headers.
#[derive(Debug)]
pub struct FetchResponse {
    /// Raw response body bytes.
    pub bytes: Vec<u8>,
    /// Response `Content-Type` header value, if reported by the transport.
    pub content_type: Option<String>,
}

/// Errors returned by [`RevocationFetcher::fetch`].
///
/// `Clone`, `PartialEq`, and `Eq` are intentionally not derived: the
/// [`Transport`](FetchError::Transport) variant carries a
/// `Box<dyn std::error::Error + Send + Sync>` which does not implement those
/// traits. This is the documented exception to the workspace-wide error
/// derive convention.
#[derive(Debug)]
#[non_exhaustive]
pub enum FetchError {
    /// Network or transport error.
    Transport(Box<dyn std::error::Error + Send + Sync + 'static>),
    /// HTTP error response (non-2xx status).
    HttpStatus(u16),
    /// Response body exceeded the configured size limit.
    TooLarge,
}

impl core::fmt::Display for FetchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport error: {e}"),
            Self::HttpStatus(code) => write!(f, "HTTP {code}"),
            Self::TooLarge => f.write_str("response too large"),
        }
    }
}

impl std::error::Error for FetchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

/// Will implement [`pkix_revocation::RevocationChecker`] once fetching is wired up.
///
/// Reads `CRLDistributionPoints` from each certificate, fetches the
/// CRL via the provided [`RevocationFetcher`], and delegates to
/// [`pkix_revocation::CrlChecker`] using the supplied
/// [`pkix_path::SignatureVerifier`] to verify the CRL signature.
///
/// The `V` generic mirrors `CrlChecker<V>` in `pkix-revocation`:
/// the verifier is moved into the on-demand `CrlChecker` instance per
/// request, so any `V: pkix_path::SignatureVerifier + Clone` works.
///
/// See [RFC 5280 §4.2.1.13](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13).
///
/// # Status
///
/// The struct holds its fields; the [`pkix_revocation::RevocationChecker`]
/// impl lands with PKIX-a1yc.5.
#[cfg(feature = "crl")]
#[cfg_attr(docsrs, doc(cfg(feature = "crl")))]
#[derive(Clone, Debug)]
pub struct HttpCrlFetcher<F, V> {
    pub(crate) fetcher: F,
    pub(crate) verifier: V,
    pub(crate) now_unix: u64,
}

#[cfg(feature = "crl")]
impl<F, V> HttpCrlFetcher<F, V> {
    /// Create a new `HttpCrlFetcher`.
    ///
    /// - `fetcher`   — HTTP transport implementation
    /// - `verifier`  — signature verifier passed to each on-demand
    ///   [`pkix_revocation::CrlChecker`]
    /// - `now_unix`  — current time as seconds since the Unix epoch
    ///
    /// The `SignatureVerifier` and `RevocationFetcher` trait bounds are
    /// applied at the [`pkix_revocation::RevocationChecker`] impl site
    /// (PKIX-a1yc.5), matching the bound-placement style of
    /// [`pkix_revocation::CrlChecker`].
    pub const fn new(fetcher: F, verifier: V, now_unix: u64) -> Self {
        Self {
            fetcher,
            verifier,
            now_unix,
        }
    }
}

/// Will implement [`pkix_revocation::RevocationChecker`] once fetching is wired up.
///
/// Reads `AuthorityInfoAccess` from each certificate, sends a DER-encoded
/// OCSP request via the provided [`RevocationFetcher`] (HTTP `POST` with
/// `Content-Type: application/ocsp-request` per RFC 6960 §A.1), and
/// delegates to [`pkix_revocation::OcspChecker`] using the supplied
/// [`pkix_path::SignatureVerifier`] to verify the response signature.
///
/// See [RFC 5280 §4.2.2.1](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.2.1)
/// and [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960).
///
/// # Status
///
/// The struct holds its fields; the [`pkix_revocation::RevocationChecker`]
/// impl lands with PKIX-a1yc.6.
#[cfg(feature = "ocsp")]
#[cfg_attr(docsrs, doc(cfg(feature = "ocsp")))]
#[derive(Clone, Debug)]
pub struct HttpOcspFetcher<F, V> {
    pub(crate) fetcher: F,
    pub(crate) verifier: V,
    pub(crate) now_unix: u64,
    pub(crate) hash_alg: OcspHashAlg,
}

#[cfg(feature = "ocsp")]
impl<F, V> HttpOcspFetcher<F, V> {
    /// Create a new `HttpOcspFetcher`.
    ///
    /// - `fetcher`   — HTTP transport implementation
    /// - `verifier`  — signature verifier passed to each on-demand
    ///   [`pkix_revocation::OcspChecker`]
    /// - `now_unix`  — current time as seconds since the Unix epoch
    ///
    /// The `CertID.hashAlgorithm` defaults to [`OcspHashAlg::Sha256`];
    /// override via [`HttpOcspFetcher::with_hash_alg`].
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
    /// responders that have not been updated to RFC 6960's
    /// SHA-2-family permission.
    #[must_use]
    pub const fn with_hash_alg(mut self, alg: OcspHashAlg) -> Self {
        self.hash_alg = alg;
        self
    }
}

#[cfg(test)]
mod tests {
    //! Trait-shape tests.
    //!
    //! These do not exercise any HTTP, crypto, or DER logic — they verify
    //! that the trait + types compose coherently and that the constructors
    //! accept the types we expect. The first impl child (PKIX-a1yc.5)
    //! adds the behavioural tests.

    use super::*;

    /// Stand-in fetcher: every call returns a fixed error. Used to prove
    /// the trait has the right shape.
    struct NullFetcher;

    impl RevocationFetcher for NullFetcher {
        fn fetch(&self, _req: &FetchRequest<'_>) -> Result<FetchResponse, FetchError> {
            Err(FetchError::HttpStatus(503))
        }
    }

    #[test]
    fn fetch_request_get_shape() {
        let req = FetchRequest::get("http://example.com/crl.der");
        match req.method {
            FetchMethod::Get => {}
            FetchMethod::Post { .. } => panic!("expected GET, got POST"),
        }
        assert_eq!(req.url, "http://example.com/crl.der");
    }

    #[test]
    fn fetch_request_post_shape() {
        let body = b"\x30\x00";
        let req = FetchRequest::post("http://example.com/ocsp", body, "application/ocsp-request");
        match req.method {
            FetchMethod::Post {
                body: b,
                content_type,
            } => {
                assert_eq!(b, body);
                assert_eq!(content_type, "application/ocsp-request");
            }
            FetchMethod::Get => panic!("expected POST, got GET"),
        }
    }

    #[test]
    fn null_fetcher_returns_status_error() {
        let f = NullFetcher;
        let err = f.fetch(&FetchRequest::get("http://x/")).unwrap_err();
        match err {
            FetchError::HttpStatus(503) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn fetch_error_display_includes_source_for_transport() {
        // FetchError::Transport must surface its inner error via std::error::Error::source,
        // and Display should mention the inner message — important so log output of a fetch
        // failure tells the operator *what* went wrong, not just "transport error".
        let inner: Box<dyn std::error::Error + Send + Sync> = "connection refused".into();
        let err = FetchError::Transport(inner);
        let s = format!("{err}");
        assert!(
            s.contains("connection refused"),
            "Display should include inner message: {s}"
        );
        assert!(
            std::error::Error::source(&err).is_some(),
            "Transport should expose source()"
        );
    }

    #[cfg(feature = "crl")]
    #[test]
    fn http_crl_fetcher_constructs_with_verifier() {
        // Compile-only check: the struct gains a V generic that propagates through
        // the const-fn constructor unchanged.
        struct DummyVerifier;
        let _f: HttpCrlFetcher<NullFetcher, DummyVerifier> =
            HttpCrlFetcher::new(NullFetcher, DummyVerifier, 0);
    }

    #[cfg(feature = "ocsp")]
    #[test]
    fn http_ocsp_fetcher_constructs_with_verifier() {
        struct DummyVerifier;
        let _f: HttpOcspFetcher<NullFetcher, DummyVerifier> =
            HttpOcspFetcher::new(NullFetcher, DummyVerifier, 0);
    }
}
