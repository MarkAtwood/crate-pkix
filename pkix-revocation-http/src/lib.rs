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
//! # Spec references
//!
//! - RFC 5280 §4.2.1.13 — CRLDistributionPoints extension
//! - RFC 5280 §4.2.2.1  — AuthorityInfoAccess extension
//! - RFC 5280 §6.3       — CRL validation algorithm
//!
//! # Limitations
//!
//! Not yet implemented. See PKIX-58m.

/// Pluggable HTTP transport for fetching revocation data.
///
/// Implement this trait to supply your own HTTP client (reqwest, ureq, etc.).
/// The fetcher is called with a URL extracted from the certificate's
/// CRLDistributionPoints or AuthorityInfoAccess extension.
pub trait RevocationFetcher {
    /// Fetch the resource at `url` and return the raw response bytes.
    ///
    /// The caller will interpret the bytes as DER-encoded CRL or OCSP response
    /// depending on context.
    fn fetch(&self, url: &str) -> std::result::Result<Vec<u8>, FetchError>;
}

/// Errors returned by [`RevocationFetcher::fetch`].
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
            FetchError::Transport(e) => write!(f, "transport error: {e}"),
            FetchError::HttpStatus(code) => write!(f, "HTTP {code}"),
            FetchError::TooLarge => f.write_str("response too large"),
        }
    }
}

impl std::error::Error for FetchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FetchError::Transport(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

/// A [`pkix_revocation::RevocationChecker`] that fetches CRLs on demand.
///
/// Reads [`CRLDistributionPoints`][cdp] from each certificate, fetches the
/// CRL via the provided [`RevocationFetcher`], and delegates to
/// [`pkix_revocation::CrlChecker`].
///
/// [cdp]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13
///
/// # Limitations
///
/// Not yet implemented (PKIX-58m).
#[cfg(feature = "crl")]
#[allow(dead_code)] // fields used once HttpCrlFetcher is implemented
pub struct HttpCrlFetcher<F> {
    fetcher: F,
    now_unix: u64,
}

#[cfg(feature = "crl")]
impl<F: RevocationFetcher> HttpCrlFetcher<F> {
    /// Create a new `HttpCrlFetcher`.
    ///
    /// - `fetcher`   — HTTP transport implementation
    /// - `now_unix`  — current time as seconds since the Unix epoch
    pub fn new(fetcher: F, now_unix: u64) -> Self {
        Self { fetcher, now_unix }
    }
}

/// A [`pkix_revocation::RevocationChecker`] that fetches OCSP responses on demand.
///
/// Reads [`AuthorityInfoAccess`][aia] from each certificate, sends an OCSP
/// request via the provided [`RevocationFetcher`], and delegates to
/// [`pkix_revocation::OcspChecker`].
///
/// [aia]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.2.1
///
/// # Limitations
///
/// Not yet implemented (PKIX-58m).
#[cfg(feature = "ocsp")]
#[allow(dead_code)] // fields used once HttpOcspFetcher is implemented
pub struct HttpOcspFetcher<F> {
    fetcher: F,
    now_unix: u64,
}

#[cfg(feature = "ocsp")]
impl<F: RevocationFetcher> HttpOcspFetcher<F> {
    /// Create a new `HttpOcspFetcher`.
    ///
    /// - `fetcher`   — HTTP transport implementation
    /// - `now_unix`  — current time as seconds since the Unix epoch
    pub fn new(fetcher: F, now_unix: u64) -> Self {
        Self { fetcher, now_unix }
    }
}
