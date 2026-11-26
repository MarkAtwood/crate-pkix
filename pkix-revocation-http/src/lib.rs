#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
// This crate's documentation is written for the whole crate, and most of
// what it describes is behind a feature. The narrative below names
// HttpCrlFetcher, the async trait family, the cache types and the
// reference clients, all of which are gated; under a narrower feature
// selection those items do not exist and the links to them cannot
// resolve. `cargo doc --no-default-features` reported 33 such errors.
//
// The alternatives were both worse. Demoting the links to plain code
// spans would cost every reader on docs.rs -- which builds with
// all-features -- a working link, to spare a configuration nobody
// publishes documentation from. Making the prose itself conditional
// means rewriting about forty lines of `//!` into
// `#![cfg_attr(feature = "...", doc = "...")]`, with the escaping that
// implies, and leaves the crate docs painful to edit thereafter.
//
// So the lint is allowed only where it cannot distinguish a gated item
// from a mistake, and stays denied where it can. That loses no signal: a
// genuinely mistyped link is broken with every feature enabled too, and
// the all-features doc build is what the quality gate runs under
// RUSTDOCFLAGS=-D warnings.
//
// `async` is absent from the list deliberately -- `client-reqwest-async`
// enables it, so requiring that one covers it.
#![cfg_attr(
    not(all(
        feature = "crl",
        feature = "ocsp",
        feature = "client-ureq",
        feature = "client-reqwest-async"
    )),
    allow(rustdoc::broken_intra_doc_links)
)]

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
//! `pkix_revocation::RevocationChecker` by fetching on demand and
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
//! # Security considerations
//!
//! **This crate applies no destination policy. Read this before using it
//! server-side.**
//!
//! Revocation URLs are not configuration. A `CRLDistributionPoints` or
//! `AuthorityInfoAccess` extension is a field of the certificate being
//! validated, and that certificate's signature has not been checked at the
//! point its URLs are read. So whoever presents a certificate chooses the
//! URLs this process fetches.
//!
//! A certificate carrying `http://169.254.169.254/latest/meta-data/` or
//! `http://10.0.0.1/` in its CDP or AIA extension will therefore have those
//! fetched, by default, with no complaint. On a cloud instance the first of
//! those is the instance-metadata service and may return credentials; on a
//! corporate network the second probes hosts the attacker cannot otherwise
//! reach. This is server-side request forgery, with the certificate as the
//! attacker's input.
//!
//! ## What this crate does guarantee
//!
//! - **HTTP and HTTPS only.** URI extraction drops every other
//!   scheme, case-insensitively, so `file://`, `ldap://` and `gopher://`
//!   URIs in a certificate are never fetched.
//! - **Same-origin redirects only.** The reference clients override their
//!   libraries' defaults to refuse a redirect that changes scheme, host or
//!   port — `reqwest`'s own default follows up to ten redirects to any
//!   origin. A URL a caller has vetted therefore cannot be redirected past
//!   that vetting; a cross-origin redirect surfaces as
//!   [`FetchError::HttpStatus`] with the 3xx code. Tested on both clients,
//!   asserting the redirect target was never contacted.
//! - **Bounded responses and a 30-second default timeout**, so a hostile
//!   endpoint cannot exhaust memory or hang a validation indefinitely.
//!
//! Those bound what an attacker can do *through* a fetch. They do not bound
//! *where* a fetch goes.
//!
//! ## What you must do
//!
//! Decide which destinations are acceptable, and enforce it. Two places work:
//!
//! 1. **In your [`RevocationFetcher`] or [`AsyncRevocationFetcher`]**, which
//!    is the seam this crate leaves open for exactly this purpose. Refuse the
//!    request before it reaches the transport.
//! 2. **Before calling**, by vetting the URL yourself. The same-origin
//!    redirect guarantee above is what makes this sound rather than
//!    theatre — a vetted origin stays vetted.
//!
//! Filtering by hostname before connecting is weaker than it looks: a name
//! can resolve to a public address when you check it and a loopback address
//! when the connection is made. Filtering at DNS resolution, so the decision
//! applies to the addresses actually connected to, closes that window.
//!
//! ## Why this differs from `pkix-aia-http`, which looks like a sibling
//!
//! `pkix-aia-http` fetches `caIssuers` URIs from the same unvalidated
//! certificates, for the same chain-building purpose — and it **refuses
//! non-public destinations by default**, at DNS resolution time, with an
//! opt-in escape hatch.
//!
//! The two crates therefore ship opposite defaults for the same threat. That
//! is deliberate on each side: `pkix-aia-http` owns its transport and so can
//! own a policy, while this crate's transport is a caller-supplied trait and
//! a policy baked in here would be one the caller cannot see or override.
//! Both positions are defensible; the combination is a trap.
//!
//! **Do not carry an assumption from one crate to the other.** If you learnt
//! that AIA fetching is SSRF-safe out of the box, revocation fetching is not.
//!
//! Tracked as PKIX-rm8.57.
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
//! re-hit the network. The reference [`InMemoryCache`] reclaims on
//! demand via [`prune_expired`](InMemoryCache::prune_expired) rather
//! than on a timer; consumers wanting a hard ceiling implement
//! [`RevocationCache`] over their preferred backing store (e.g. `moka`,
//! Redis).
//!
//! # Features
//!
//! Protocol and transport are separate axes, and **a transport feature
//! on its own does not give you a working fetcher**. `client-ureq`
//! enables the [`UreqFetcher`](clients::ureq::UreqFetcher) transport,
//! but [`HttpCrlFetcher`] and [`HttpOcspFetcher`] — the types that turn a
//! transport into a `pkix_revocation::RevocationChecker` — are gated
//! on `crl` and `ocsp`. Enabling only `client-ureq` therefore leaves you
//! holding a transport with nothing to plug it into.
//!
//! | Feature | Gives you |
//! |---|---|
//! | `crl` | [`HttpCrlFetcher`], CRL side of the cache |
//! | `ocsp` | [`HttpOcspFetcher`], OCSP request building, OCSP side of the cache |
//! | `client-ureq` | [`UreqFetcher`](clients::ureq::UreqFetcher), a sync rustls-backed transport |
//! | `async` | [`AsyncRevocationFetcher`] / [`AsyncRevocationChecker`] and the async wrappers |
//! | `client-reqwest-async` | [`ReqwestFetcher`](clients::reqwest::ReqwestFetcher); implies `async` |
//!
//! So the smallest useful combinations are:
//!
//! ```toml
//! # Sync CRL + OCSP over the bundled transport
//! pkix-revocation-http = { version = "0.2", features = ["crl", "ocsp", "client-ureq"] }
//!
//! # CRL only, your own transport
//! pkix-revocation-http = { version = "0.2", features = ["crl"] }
//!
//! # Async, both protocols, bundled transport
//! pkix-revocation-http = { version = "0.2", features = ["crl", "ocsp", "client-reqwest-async"] }
//! ```
//!
//! ## Why `client-ureq` does not imply `crl` and `ocsp`
//!
//! Because Cargo features are additive and cannot be subtracted. If
//! `client-ureq` pulled in both protocols, a consumer who wants CRLs and
//! not OCSP would have no way to say so: they would get `x509-ocsp`,
//! `sha1` and `sha2` in their dependency graph with no opt-out. Keeping
//! the axes orthogonal costs one more feature in `Cargo.toml` and keeps
//! that choice the consumer's.
//!
//! # Limitations
//!
//! - **No bundled HTTP client by default.** Enabling the `crl` or `ocsp`
//!   feature gives you the [`RevocationFetcher`] trait and the wrapper
//!   structs that implement `pkix_revocation::RevocationChecker` over
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
//! - **The reference cache evicts only when asked.** [`InMemoryCache`]
//!   spawns no threads and reads no clock, so nothing runs an eviction
//!   pass on its own; call
//!   [`prune_expired`](InMemoryCache::prune_expired) from a maintenance
//!   tick and watch [`len`](InMemoryCache::len).
//! - **No CDP / AIA URI filtering.** This crate fetches whichever URI is
//!   in the certificate's [`CRLDistributionPoints`] or
//!   [`AuthorityInfoAccess`] extension. **See "Security considerations"
//!   above** — this is the limitation most likely to matter, and it
//!   differs from `pkix-aia-http`'s default.
//!
//! [`CRLDistributionPoints`]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.13
//! [`AuthorityInfoAccess`]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.1

#[cfg(test)]
#[path = "../tests/support/raw_cert.rs"]
pub(crate) mod raw_cert;

// In-memory cache + cached wrappers. Gated on either `crl` or `ocsp`
// because the trait is shared but the wrapper structs and parsing helpers
// each live behind their protocol feature. Without the gate the module
// compiles with no feature enabled and every item in it is dead, which
// `-D warnings` rejects: the attribute used to sit on `raw_cert` above,
// where it did nothing, while the re-exports below were gated correctly.
#[cfg(any(feature = "crl", feature = "ocsp"))]
mod cache;
pub mod clients;
#[cfg(feature = "crl")]
mod crl;
mod extract;
// Gated for the same reason `cache` is: with no protocol feature there are
// no fetchers to hold a clock, so `Clock` and its accessor are dead and
// `-D warnings` rejects them.
#[cfg(feature = "ocsp")]
mod ocsp;
#[cfg(feature = "ocsp")]
mod ocsp_request;
#[cfg(any(feature = "crl", feature = "ocsp"))]
mod time;

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
#[cfg(any(feature = "crl", feature = "ocsp"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "crl", feature = "ocsp"))))]
pub use time::{SystemClock, TimeSource};

/// Default cap on how many of a certificate's revocation URLs one check
/// will try.
///
/// A certificate's `cRLDistributionPoints` and `authorityInfoAccess`
/// extensions can list any number of URLs, and a revocation check walks
/// them in order until one yields a determinative verdict. Without a cap,
/// the time one check can take is (URLs listed) × (per-request timeout),
/// and that check runs inside `pkix_chain::verify_chain` with no way for
/// the caller to bound it. A certificate advertising 500 dead
/// distribution points against a 10-second timeout stalls a single path
/// validation for well over an hour.
///
/// The cap only bites when URLs are *failing*: the loop returns on the
/// first determinative verdict, so a certificate whose first
/// distribution point answers is unaffected no matter how many more it
/// lists.
///
/// # Why eight
///
/// Eight is four times the largest count observed in a census of 773
/// certificates — the workspace's test corpora (734, including a host
/// trust store) plus the full chains served by twelve major sites across
/// the major commercial CAs (39). The maximum in both samples was two
/// HTTP `cRLDistributionPoints` URLs and one HTTP OCSP responder URL;
/// the overwhelming majority carried one of each. Eight therefore leaves
/// room for a CA publishing the same CRL under several hostnames for
/// redundancy, several times over, while still bounding the worst case.
///
/// Raise or lower it per fetcher with
/// [`HttpCrlFetcher::with_max_urls_per_check`] and its siblings.
///
/// Gated on a protocol feature because without one there is no fetcher
/// to cap.
///
/// # What this does not bound
///
/// Wall-clock latency. The cap bounds the *number* of attempts, not how
/// long any one of them takes; a single hung request is the transport's
/// timeout to enforce, and the reference clients configure one. An
/// overall deadline for a whole check would bound the accumulation
/// directly, but it cannot interrupt a request already in flight, so it
/// complements a cap rather than replacing it. Not implemented.
#[cfg(any(feature = "crl", feature = "ocsp"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "crl", feature = "ocsp"))))]
pub const DEFAULT_MAX_URLS_PER_CHECK: usize = 8;

/// Build the "every URL failed" error shared by all six check paths.
///
/// `advertised` is how many URLs the certificate listed and `attempted`
/// how many the cap allowed. When those differ the message says so:
/// otherwise an operator reads "all 8 URL(s) failed" for a certificate
/// that listed 500 and concludes the certificate advertises eight.
#[cfg(any(feature = "crl", feature = "ocsp"))]
pub(crate) fn all_urls_failed(
    attempted: usize,
    advertised: usize,
    failures: &[String],
) -> pkix_revocation::Error {
    let description = if attempted == advertised {
        format!("all {advertised} URL(s) failed: {}", failures.join("; "))
    } else {
        format!(
            "all {attempted} of {advertised} URL(s) failed (capped at \
             {attempted} per check; raise with with_max_urls_per_check): {}",
            failures.join("; ")
        )
    };
    pkix_revocation::Error::RevocationFetchFailed { description }
}

/// `Content-Type` for an OCSP request body, per RFC 6960 §A.1.
#[cfg(feature = "ocsp")]
pub(crate) const OCSP_REQUEST_CT: &str = "application/ocsp-request";
#[cfg(feature = "ocsp")]
#[cfg_attr(docsrs, doc(cfg(feature = "ocsp")))]
pub use ocsp_request::{
    build_ocsp_request, build_ocsp_request_for_anchor, BuildError, OcspHashAlg, OcspRequestBytes,
};

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
/// The trait is intentionally synchronous, so that a consumer with no
/// async runtime pays for none. [`AsyncRevocationFetcher`] is the async
/// analogue, behind the `async` feature.
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

/// `pkix_revocation::RevocationChecker` driven by HTTP CRL fetches.
///
/// Reads `CRLDistributionPoints` from each certificate, fetches the
/// CRL via the provided [`RevocationFetcher`], and delegates to
/// `pkix_revocation::CrlChecker` using the supplied
/// `pkix_path::SignatureVerifier` to verify the CRL signature.
///
/// The `V` generic mirrors `CrlChecker<V>` in `pkix-revocation`:
/// the verifier is moved into the on-demand `CrlChecker` instance per
/// request, so any `V: pkix_path::SignatureVerifier + Clone` works.
///
/// # A verifier that is not `Clone`
///
/// The `Clone` bound is real — a fresh checker is built per candidate
/// URL — but it does not exclude a verifier that cannot be duplicated,
/// such as one owning a hardware token handle or an open session.
/// `pkix-path` forwards `SignatureVerifier` through shared references
/// and through `Arc`, so pass the verifier by one of those instead of by
/// value:
///
/// - `HttpCrlFetcher::new(fetcher, &verifier, now)` makes `V = &V`,
///   which is `Copy`: the bound is satisfied and nothing is duplicated.
///   Right for a fetcher scoped to one validation.
/// - `HttpCrlFetcher::new(fetcher, Arc::new(verifier), now)` makes
///   `V = Arc<V>`, whose clone is a refcount bump. Right for a fetcher
///   held for the life of a process, where there is no borrow to hold.
///
/// See [RFC 5280 §4.2.1.13](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13).
///
/// # Choosing a constructor
///
/// [`new`](Self::new) pins the fetcher to one instant and
/// [`with_system_clock`](Self::with_system_clock) reads the clock per
/// check. Pick the second for a fetcher that outlives a single
/// validation; see [`new`](Self::new) for what the first one freezes.
#[cfg(feature = "crl")]
#[cfg_attr(docsrs, doc(cfg(feature = "crl")))]
#[derive(Clone, Debug)]
pub struct HttpCrlFetcher<F, V> {
    pub(crate) fetcher: F,
    pub(crate) verifier: V,
    pub(crate) clock: crate::time::Clock,
    pub(crate) max_urls: usize,
}

#[cfg(feature = "crl")]
impl<F, V> HttpCrlFetcher<F, V> {
    /// Create a new `HttpCrlFetcher` pinned to one instant.
    ///
    /// - `fetcher`   — HTTP transport implementation
    /// - `verifier`  — signature verifier passed to each on-demand
    ///   `pkix_revocation::CrlChecker`
    /// - `now_unix`  — the instant every check is judged against, as
    ///   seconds since the Unix epoch
    ///
    /// # Lifetime of `now_unix`
    ///
    /// `now_unix` is fixed for the life of the fetcher. That is correct
    /// for a fetcher built per validation, and for reproducible tests,
    /// but a fetcher built once and kept — the usual server shape —
    /// will judge CRL freshness against this instant forever, accepting
    /// CRLs that expired long ago. Use
    /// [`with_system_clock`](Self::with_system_clock) for a long-lived
    /// fetcher.
    ///
    /// The `SignatureVerifier` and `RevocationFetcher` trait bounds are
    /// applied at the `pkix_revocation::RevocationChecker` impl site,
    /// matching the bound-placement style of
    /// `pkix_revocation::CrlChecker`.
    pub const fn new(fetcher: F, verifier: V, now_unix: u64) -> Self {
        Self {
            fetcher,
            verifier,
            clock: crate::time::Clock::Fixed(now_unix),
            max_urls: crate::DEFAULT_MAX_URLS_PER_CHECK,
        }
    }

    /// Create a new `HttpCrlFetcher` that reads the system clock once
    /// per revocation check.
    ///
    /// The right constructor for a fetcher held for the life of a
    /// process. Each check asks the clock, so a CRL that expires while
    /// the fetcher is alive is seen to expire.
    pub const fn with_system_clock(fetcher: F, verifier: V) -> Self {
        Self {
            fetcher,
            verifier,
            clock: crate::time::Clock::System,
            max_urls: crate::DEFAULT_MAX_URLS_PER_CHECK,
        }
    }

    /// Create a new `HttpCrlFetcher` driven by a caller-supplied clock.
    ///
    /// For a consumer that already owns a clock — one slewed to a
    /// trusted time service, a coarse clock updated on a timer, or a
    /// test clock advanced by hand. Consulted once per revocation
    /// check; see [`TimeSource`].
    pub fn with_time_source(
        fetcher: F,
        verifier: V,
        source: std::sync::Arc<dyn TimeSource>,
    ) -> Self {
        Self {
            fetcher,
            verifier,
            clock: crate::time::Clock::Custom(source),
            max_urls: crate::DEFAULT_MAX_URLS_PER_CHECK,
        }
    }

    /// Cap how many of the certificate's revocation URLs one check will
    /// try, overriding [`crate::DEFAULT_MAX_URLS_PER_CHECK`].
    ///
    /// URLs are tried in the order the certificate lists them and the
    /// check returns on the first determinative verdict, so this only
    /// bites when URLs are failing. See the constant for why the default
    /// is what it is, and for what the cap does not bound.
    ///
    /// `0` attempts no URL at all, so any certificate advertising a
    /// distribution point yields
    /// `pkix_revocation::Error::RevocationFetchFailed`. That is not
    /// clamped to `1`: quietly doing something other than what the
    /// caller asked for is worse than doing the useless thing they did
    /// ask for. To skip revocation entirely use
    /// `pkix_revocation::NoRevocation`.
    #[must_use]
    pub const fn with_max_urls_per_check(mut self, max: usize) -> Self {
        self.max_urls = max;
        self
    }
}

/// `pkix_revocation::RevocationChecker` driven by HTTP OCSP requests.
///
/// Reads `AuthorityInfoAccess` from each certificate, sends a DER-encoded
/// OCSP request via the provided [`RevocationFetcher`] (HTTP `POST` with
/// `Content-Type: application/ocsp-request` per RFC 6960 §A.1), and
/// delegates to `pkix_revocation::OcspChecker` using the supplied
/// `pkix_path::SignatureVerifier` to verify the response signature.
///
/// See [RFC 5280 §4.2.2.1](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.2.1)
/// and [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960).
///
/// # Choosing a constructor
///
/// As [`HttpCrlFetcher`]: [`new`](Self::new) pins one instant,
/// [`with_system_clock`](Self::with_system_clock) reads the clock per
/// check.
#[cfg(feature = "ocsp")]
#[cfg_attr(docsrs, doc(cfg(feature = "ocsp")))]
#[derive(Clone, Debug)]
pub struct HttpOcspFetcher<F, V> {
    pub(crate) fetcher: F,
    pub(crate) verifier: V,
    pub(crate) clock: crate::time::Clock,
    pub(crate) hash_alg: OcspHashAlg,
    pub(crate) max_urls: usize,
}

#[cfg(feature = "ocsp")]
impl<F, V> HttpOcspFetcher<F, V> {
    /// Create a new `HttpOcspFetcher` pinned to one instant.
    ///
    /// - `fetcher`   — HTTP transport implementation
    /// - `verifier`  — signature verifier passed to each on-demand
    ///   `pkix_revocation::OcspChecker`
    /// - `now_unix`  — the instant every check is judged against, as
    ///   seconds since the Unix epoch
    ///
    /// The `CertID.hashAlgorithm` defaults to [`OcspHashAlg::Sha256`];
    /// override via [`HttpOcspFetcher::with_hash_alg`].
    ///
    /// # Lifetime of `now_unix`
    ///
    /// Fixed for the life of the fetcher; see
    /// [`HttpCrlFetcher::new`] for why that matters and
    /// [`with_system_clock`](Self::with_system_clock) for the
    /// long-lived alternative.
    #[must_use]
    pub const fn new(fetcher: F, verifier: V, now_unix: u64) -> Self {
        Self {
            fetcher,
            verifier,
            clock: crate::time::Clock::Fixed(now_unix),
            hash_alg: OcspHashAlg::Sha256,
            max_urls: crate::DEFAULT_MAX_URLS_PER_CHECK,
        }
    }

    /// Create a new `HttpOcspFetcher` that reads the system clock once
    /// per revocation check.
    ///
    /// The right constructor for a fetcher held for the life of a
    /// process.
    #[must_use]
    pub const fn with_system_clock(fetcher: F, verifier: V) -> Self {
        Self {
            fetcher,
            verifier,
            clock: crate::time::Clock::System,
            hash_alg: OcspHashAlg::Sha256,
            max_urls: crate::DEFAULT_MAX_URLS_PER_CHECK,
        }
    }

    /// Create a new `HttpOcspFetcher` driven by a caller-supplied clock.
    ///
    /// See [`TimeSource`].
    #[must_use]
    pub fn with_time_source(
        fetcher: F,
        verifier: V,
        source: std::sync::Arc<dyn TimeSource>,
    ) -> Self {
        Self {
            fetcher,
            verifier,
            clock: crate::time::Clock::Custom(source),
            hash_alg: OcspHashAlg::Sha256,
            max_urls: crate::DEFAULT_MAX_URLS_PER_CHECK,
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

    /// Cap how many of the certificate's OCSP responder URLs one check
    /// will try, overriding [`crate::DEFAULT_MAX_URLS_PER_CHECK`].
    ///
    /// See [`crate::HttpCrlFetcher::with_max_urls_per_check`] for the
    /// semantics, including what `0` means.
    #[must_use]
    pub const fn with_max_urls_per_check(mut self, max: usize) -> Self {
        self.max_urls = max;
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
