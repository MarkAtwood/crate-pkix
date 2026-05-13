#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, unreachable_pub)]
#![warn(missing_docs)]

//! # pkix-aia
//!
//! Authority Information Access (AIA) fetcher trait and types for
//! `pkix-chain`, per
//! [RFC 5280 §4.2.2.1](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.2.1).
//!
//! AIA is the extension that carries `caIssuers` URIs pointing at the
//! certificate's issuer. Chain-build code can follow these URIs to
//! fetch missing intermediate certificates when the caller-supplied
//! chain is incomplete.
//!
//! This crate ships only the *trait surface*: the [`AiaError`] type
//! (this release), the `AiaFetcher` trait (planned, tracked at
//! `PKIX-zkjb.3`), and the `NoAiaFetcher` zero-cost default
//! (planned, tracked at `PKIX-zkjb.4`). Real HTTP fetching lives in
//! a separate adapter crate (`pkix-aia-http`, planned, tracked at
//! `PKIX-zkjb.5`).
//!
//! ## Architectural placement
//!
//! ```text
//! pkix-chain  ----+------>  pkix-aia          (trait + error + no-op default)
//!                 |
//!                 +------>  pkix-aia-http     (real HTTP fetcher adapter)
//! ```
//!
//! `pkix-chain`'s `Verifier` struct holds an `A: AiaFetcher` generic
//! parameter that defaults to `NoAiaFetcher`. Callers who do not
//! need AIA fetching see no API change; callers who do can plug in
//! any `AiaFetcher` implementation, including HTTP adapters shipped
//! by separate crates or in-process caching wrappers.
//!
//! ## `no_std` and feature flags
//!
//! The default build is `no_std + alloc`. Enabling the `std` feature
//! unlocks the [`AiaError::IoFailure`] variant (whose
//! `kind: std::io::ErrorKind` field requires `std::io`) and the
//! `std::error::Error` impl. Enabling `serde` derives
//! `serde::Serialize` / `serde::Deserialize` on [`AiaError`]; with
//! both `std + serde` the `IoFailure` variant round-trips its
//! `kind` field through a crate-private label helper.
//!
//! Per AGENTS.md non-negotiable #6, [`AiaError`] is
//! `Clone + Debug + PartialEq + Eq + Send + Sync` (compile-time
//! asserted) and is `#[non_exhaustive]`. No embedded `std::io::Error`
//! handle (it is not `Clone + Eq + Serialize`); the variant uses the
//! `IoFailure { kind, message }` shape mandated by PKIX-2l0v.1 D3.
//!
//! ## Status
//!
//! Initial release: [`AiaError`] only. The `AiaFetcher` trait and
//! `NoAiaFetcher` default land in subsequent point releases that
//! ship alongside this one in the same workspace.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// AiaError
// ---------------------------------------------------------------------------

/// Failure modes for `AiaFetcher` implementations.
///
/// The trait surface returns `Result<Vec<u8>, AiaError>` for both the
/// single-URI `fetch` path and the per-URI entries of a `batch_fetch`
/// call (both methods land in `PKIX-zkjb.3`). A caller's chain-build
/// layer translates a non-fatal `AiaError` into a chain-build
/// failure — typically "could not retrieve missing intermediate" —
/// and continues to the next candidate path if one is available.
///
/// The variant set is `#[non_exhaustive]` so future adapters can
/// surface additional error categories (DNS resolution, TLS
/// validation of the AIA endpoint itself, etc.) without breaking
/// downstream pattern matches.
///
/// # Invariants (AGENTS.md non-negotiable #6)
///
/// - `Clone + Debug + PartialEq + Eq` — `derive`d.
/// - `Send + Sync` — auto-derived; compile-time asserted at the
///   bottom of this module.
/// - No embedded `std::io::Error`. Transport-level I/O failures
///   surface through the [`AiaError::IoFailure`] variant whose
///   `kind: std::io::ErrorKind` plus owned `message: String`
///   capture the relevant information in a `Clone + Eq + Serialize`
///   shape.
/// - `#[non_exhaustive]`.
/// - Behind the `serde` feature: `Serialize + Deserialize`.
///
/// # Variants and adapter semantics
///
/// | Variant | When |
/// |---------|------|
/// | [`FetchingDisabled`](Self::FetchingDisabled) | `NoAiaFetcher` (PKIX-zkjb.4) and any fetcher that has been wired in but is intentionally off. |
/// | [`HttpStatus`](Self::HttpStatus) | The remote endpoint responded with a non-2xx status. Carries the numeric status. |
/// | [`ResponseTooLarge`](Self::ResponseTooLarge) | Caller-side size cap exceeded. Carries the configured `limit` and the observed `actual` byte count. |
/// | [`MalformedCertificate`](Self::MalformedCertificate) | Fetched bytes did not parse as a DER X.509 [`Certificate`]. Caller-provided diagnostic in the inner `String`. |
/// | [`Timeout`](Self::Timeout) | Fetch did not complete within the adapter's configured deadline. |
/// | [`UriUnsupported`](Self::UriUnsupported) | A `caIssuers` URI used a scheme the fetcher does not handle (e.g. `ldap://` against an HTTP-only fetcher). Carries the offending URI (or its scheme). |
/// | [`IoFailure`](Self::IoFailure) | (requires `std`) Lower-level transport error from the I/O substrate. `kind` is the `std::io::ErrorKind`; `message` is a human-readable description. |
///
/// [`Certificate`]: https://docs.rs/x509-cert/latest/x509_cert/struct.Certificate.html
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum AiaError {
    /// Fetching is intentionally disabled at this layer.
    ///
    /// Emitted by `NoAiaFetcher` (PKIX-zkjb.4) and by any fetcher
    /// that has been wired in but is intentionally off (for example,
    /// a kill-switch configuration). The chain-build layer treats
    /// this as "no AIA available; rely on the caller-supplied
    /// chain".
    FetchingDisabled,

    /// The remote endpoint responded with a non-success HTTP status.
    ///
    /// Carries the numeric status code (e.g. `404`, `503`).
    /// Tuple variant for ergonomic pattern matching:
    ///
    /// ```
    /// # use pkix_aia::AiaError;
    /// let e = AiaError::HttpStatus(404);
    /// matches!(e, AiaError::HttpStatus(404));
    /// ```
    HttpStatus(u16),

    /// The fetcher refused to load a response that exceeded its
    /// configured size cap.
    ///
    /// Adapters MUST cap response size — accepting arbitrary-size
    /// bytes from an untrusted endpoint is a denial-of-service
    /// vector. The cap is adapter-side configuration; this variant
    /// surfaces both the cap and the actual observed size so callers
    /// can decide whether to raise the cap or treat the response as
    /// hostile.
    ResponseTooLarge {
        /// Caller-side size limit, in bytes.
        limit: usize,
        /// Observed response size at the point the limit was
        /// exceeded, in bytes.
        actual: usize,
    },

    /// Fetched bytes did not parse as a DER-encoded X.509 certificate.
    ///
    /// The inner `String` is an adapter-side diagnostic suitable for
    /// logging. Parsing the bytes is the chain-build layer's job;
    /// when it fails, the adapter wraps the parse error into this
    /// variant so the chain-build layer can either skip this URI or
    /// surface a "no usable intermediate retrieved" failure.
    MalformedCertificate(String),

    /// The fetcher did not complete within its configured deadline.
    ///
    /// Unit variant — no diagnostic data beyond the variant tag.
    /// Adapters that need to surface per-URI timing details can
    /// extend the error type in their own adapter-specific result
    /// shape; the workspace trait surface keeps the timeout
    /// signal opaque.
    Timeout,

    /// A `caIssuers` URI used a scheme this fetcher cannot handle.
    ///
    /// The inner `String` is typically the offending URI or its
    /// scheme (e.g. `"ldap://example.com/cn=ca"` or `"ldap"`).
    /// Per RFC 5280 §4.2.2.1, AIA `accessLocation` is a `GeneralName`,
    /// so URI is the most common shape but not the only one. HTTP-only
    /// fetchers surface non-HTTP URIs through this variant.
    UriUnsupported(String),

    /// Lower-level transport I/O failure.
    ///
    /// Requires the `std` feature: the `kind` field is
    /// [`std::io::ErrorKind`], which is part of `std::io`. Real
    /// network-fetching adapters (e.g. `pkix-aia-http`, planned)
    /// all require `std` anyway, so `no_std` consumers — which can
    /// only meaningfully use `NoAiaFetcher` — never see this
    /// variant.
    ///
    /// The shape is `{ kind, message }` rather than
    /// `std::io::Error` directly: `std::io::Error` is not
    /// `Clone + PartialEq + Eq + Serialize`, which would block
    /// AGENTS.md non-negotiable #6. The `os_error` numeric code is
    /// not preserved; in practice the `kind` plus a free-form
    /// human-readable `message` carries the same diagnostic value
    /// for log consumers.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    IoFailure {
        /// I/O error category from `std::io`.
        #[cfg_attr(feature = "serde", serde(with = "io_error_kind_serde"))]
        kind: std::io::ErrorKind,
        /// Free-form human-readable description; suitable for logs.
        message: String,
    },
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

impl core::fmt::Display for AiaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::FetchingDisabled => f.write_str("AIA fetching is disabled"),
            Self::HttpStatus(code) => write!(f, "AIA fetch returned HTTP status {code}"),
            Self::ResponseTooLarge { limit, actual } => write!(
                f,
                "AIA response exceeded size cap: limit {limit} bytes, observed {actual} bytes",
            ),
            Self::MalformedCertificate(msg) => {
                write!(f, "AIA-fetched bytes did not parse as a certificate: {msg}")
            }
            Self::Timeout => f.write_str("AIA fetch timed out"),
            Self::UriUnsupported(uri) => write!(f, "AIA URI scheme not supported: {uri}"),
            #[cfg(feature = "std")]
            Self::IoFailure { kind, message } => {
                write!(f, "AIA fetch I/O failure ({kind:?}): {message}")
            }
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for AiaError {}

// ---------------------------------------------------------------------------
// io::ErrorKind serde label round-trip
// ---------------------------------------------------------------------------

/// `serde` round-trip helper for [`std::io::ErrorKind`].
///
/// Serializes as a string label (e.g. `"NotFound"`, `"TimedOut"`)
/// drawn from the variant name. Deserializes by matching the label
/// against a static table; unknown labels round-trip to
/// `std::io::ErrorKind::Other`, which matches the way the standard
/// library treats unrecognized OS-level errors.
///
/// `std::io::ErrorKind` is `#[non_exhaustive]` upstream, so this
/// helper covers the variants stable since Rust 1.45 plus the
/// expansions in 1.74 (`InvalidFilename`, `ArgumentListTooLong`,
/// etc.). Variants added in newer stdlib releases that the helper
/// does not yet recognize serialize as `"Other"`. The MSRV floor
/// for the workspace is 1.73, so we only need to recognize the
/// variants stable through that release in the serializer; the
/// deserializer's `_ => Other` fallback handles forward-compat.
#[cfg(all(feature = "std", feature = "serde"))]
mod io_error_kind_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::io::ErrorKind;

    pub(super) fn serialize<S>(kind: &ErrorKind, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // The `Debug` representation for `ErrorKind` is the variant
        // name (e.g. "NotFound", "PermissionDenied"). It is stable
        // across stdlib releases — variant names do not change — and
        // it lines up with the labels we accept in `deserialize`.
        let label = label_for(*kind);
        serializer.serialize_str(label)
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<ErrorKind, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <&str>::deserialize(deserializer)?;
        Ok(kind_for(s))
    }

    /// Map an `ErrorKind` to a stable string label.
    ///
    /// Variants added after Rust 1.73 (the workspace MSRV floor)
    /// fall through the wildcard arm to `"Other"`. The catch-all is
    /// intentional: it preserves forward-compatibility with newer
    /// stdlib releases, at the cost of folding rare variants into
    /// the generic bucket on the wire.
    fn label_for(kind: ErrorKind) -> &'static str {
        match kind {
            ErrorKind::NotFound => "NotFound",
            ErrorKind::PermissionDenied => "PermissionDenied",
            ErrorKind::ConnectionRefused => "ConnectionRefused",
            ErrorKind::ConnectionReset => "ConnectionReset",
            ErrorKind::ConnectionAborted => "ConnectionAborted",
            ErrorKind::NotConnected => "NotConnected",
            ErrorKind::AddrInUse => "AddrInUse",
            ErrorKind::AddrNotAvailable => "AddrNotAvailable",
            ErrorKind::BrokenPipe => "BrokenPipe",
            ErrorKind::AlreadyExists => "AlreadyExists",
            ErrorKind::WouldBlock => "WouldBlock",
            ErrorKind::InvalidInput => "InvalidInput",
            ErrorKind::InvalidData => "InvalidData",
            ErrorKind::TimedOut => "TimedOut",
            ErrorKind::WriteZero => "WriteZero",
            ErrorKind::Interrupted => "Interrupted",
            ErrorKind::Unsupported => "Unsupported",
            ErrorKind::UnexpectedEof => "UnexpectedEof",
            ErrorKind::OutOfMemory => "OutOfMemory",
            ErrorKind::Other => "Other",
            // Future variants (`#[non_exhaustive]`) round-trip to "Other".
            _ => "Other",
        }
    }

    /// Map a label back to an `ErrorKind`.
    ///
    /// Unknown labels resolve to `ErrorKind::Other`. This mirrors the
    /// standard library's behavior when classifying OS errors it does
    /// not recognize.
    fn kind_for(label: &str) -> ErrorKind {
        match label {
            "NotFound" => ErrorKind::NotFound,
            "PermissionDenied" => ErrorKind::PermissionDenied,
            "ConnectionRefused" => ErrorKind::ConnectionRefused,
            "ConnectionReset" => ErrorKind::ConnectionReset,
            "ConnectionAborted" => ErrorKind::ConnectionAborted,
            "NotConnected" => ErrorKind::NotConnected,
            "AddrInUse" => ErrorKind::AddrInUse,
            "AddrNotAvailable" => ErrorKind::AddrNotAvailable,
            "BrokenPipe" => ErrorKind::BrokenPipe,
            "AlreadyExists" => ErrorKind::AlreadyExists,
            "WouldBlock" => ErrorKind::WouldBlock,
            "InvalidInput" => ErrorKind::InvalidInput,
            "InvalidData" => ErrorKind::InvalidData,
            "TimedOut" => ErrorKind::TimedOut,
            "WriteZero" => ErrorKind::WriteZero,
            "Interrupted" => ErrorKind::Interrupted,
            "Unsupported" => ErrorKind::Unsupported,
            "UnexpectedEof" => ErrorKind::UnexpectedEof,
            "OutOfMemory" => ErrorKind::OutOfMemory,
            _ => ErrorKind::Other,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn label_round_trip_covers_recognized_variants() {
            // For each label this helper produces, deserializing it
            // back must yield the original kind. Cross-check via the
            // matching `label_for` -> `kind_for` round-trip; the
            // table is the oracle.
            let cases: &[(ErrorKind, &str)] = &[
                (ErrorKind::NotFound, "NotFound"),
                (ErrorKind::PermissionDenied, "PermissionDenied"),
                (ErrorKind::ConnectionRefused, "ConnectionRefused"),
                (ErrorKind::ConnectionReset, "ConnectionReset"),
                (ErrorKind::ConnectionAborted, "ConnectionAborted"),
                (ErrorKind::NotConnected, "NotConnected"),
                (ErrorKind::AddrInUse, "AddrInUse"),
                (ErrorKind::AddrNotAvailable, "AddrNotAvailable"),
                (ErrorKind::BrokenPipe, "BrokenPipe"),
                (ErrorKind::AlreadyExists, "AlreadyExists"),
                (ErrorKind::WouldBlock, "WouldBlock"),
                (ErrorKind::InvalidInput, "InvalidInput"),
                (ErrorKind::InvalidData, "InvalidData"),
                (ErrorKind::TimedOut, "TimedOut"),
                (ErrorKind::WriteZero, "WriteZero"),
                (ErrorKind::Interrupted, "Interrupted"),
                (ErrorKind::Unsupported, "Unsupported"),
                (ErrorKind::UnexpectedEof, "UnexpectedEof"),
                (ErrorKind::OutOfMemory, "OutOfMemory"),
                (ErrorKind::Other, "Other"),
            ];
            for (kind, expected_label) in cases {
                assert_eq!(label_for(*kind), *expected_label, "label_for({kind:?})");
                assert_eq!(
                    kind_for(expected_label),
                    *kind,
                    "kind_for({expected_label:?})"
                );
            }
        }

        #[test]
        fn unknown_label_resolves_to_other() {
            // Forward-compat contract: any label we do not recognize
            // resolves to `ErrorKind::Other`. The deserializer must
            // not reject the input, otherwise upgrading stdlib
            // versions (which can rename variants in `Debug`) would
            // brick existing on-disk caches.
            assert_eq!(kind_for("DefinitelyNotAVariant"), ErrorKind::Other);
            assert_eq!(kind_for(""), ErrorKind::Other);
            // Whitespace handling: we do not trim. Callers feeding
            // mangled labels are out of contract; we still resolve
            // to Other rather than panic.
            assert_eq!(kind_for(" NotFound "), ErrorKind::Other);
        }
    }
}

// ---------------------------------------------------------------------------
// AiaFetcher trait
// ---------------------------------------------------------------------------

/// Trait for fetching certificate DER bytes by URI.
///
/// `AiaFetcher` is the seam where chain-build code asks an adapter to
/// resolve a `caIssuers` URI from
/// [RFC 5280 §4.2.2.1](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.2.1)
/// into the DER-encoded bytes of the referenced certificate.
///
/// # Contract
///
/// The trait is intentionally minimal: a single required method,
/// [`fetch`](Self::fetch), and a default-impl batch entry point,
/// [`batch_fetch`](Self::batch_fetch), that loops to `fetch`.
///
/// - **`&self` receiver.** Fetchers take `&self`, not `&mut self`.
///   This admits caching wrappers using interior mutability (e.g.
///   `core::cell::RefCell` for single-threaded scenarios,
///   `std::sync::Mutex` or `std::sync::RwLock` for shared concurrent
///   access) without the trait surface having to acknowledge them.
///   See the doctest below for a worked example.
///
/// - **Synchronous.** The core trait is synchronous. Async adapters
///   live in separate crates (e.g. a future async variant in
///   `pkix-aia-async`) and expose their own trait shape. Keeping
///   the core trait sync means the workspace stays runtime-agnostic
///   and avoids forcing every `pkix-chain` consumer to choose a
///   runtime.
///
/// - **Raw bytes, not parsed certificates.** Returns
///   `Result<Vec<u8>, AiaError>` of certificate DER. Parsing the
///   bytes into an `x509_cert::Certificate` is the chain-build
///   layer's job. The fetcher is a dumb-bytes-fetch surface; an
///   adapter that knows how to parse can still parse internally,
///   but the trait surface deliberately stays at the byte level so
///   parser failures can be classified one way (the consumer's
///   parse step) and transport failures another (this trait).
///
/// - **No timeout parameter.** Per-request timeouts are an adapter
///   concern, configured at construction time on the concrete
///   fetcher. The trait surface does not expose a deadline argument;
///   adapters that need one set it via their own builder API.
///
/// - **`batch_fetch` may pipeline.** The default-impl is a sequential
///   loop over `fetch`. Implementers MAY override `batch_fetch` to
///   pipeline requests (HTTP/2 multiplexing, connection-pool
///   parallelism, etc.) when doing so produces a real speedup.
///   The return shape is `Vec<Result<_, _>>` aligned by index with
///   `uris`: per-URI success/failure is preserved even when some
///   subset of the batch fails.
///
/// # Thread-safety expectation
///
/// `AiaFetcher` does not require `Send + Sync` as super-traits; that
/// would prevent legitimate single-threaded impls (e.g. `RefCell`-
/// backed caches). Implementers SHOULD be `Send + Sync` whenever
/// they can — chain-build code in `pkix-chain` calls fetchers
/// through `&dyn AiaFetcher`, and trait objects stored in a
/// `Verifier` shared across threads require `Send + Sync` to be
/// useful in concurrent server code. When this is the intent,
/// declare the bound at the use site (e.g. `&'a dyn AiaFetcher`
/// with an inner type that is auto-`Send + Sync`, or
/// `Arc<dyn AiaFetcher + Send + Sync>` for owned trait objects).
///
/// # Errors
///
/// All failure modes surface through [`AiaError`]. See its
/// per-variant rustdoc for adapter semantics.
///
/// # Example: caching wrapper
///
/// The `&self` receiver admits cache layering without any change
/// to the trait surface. The example below wraps any
/// [`AiaFetcher`] in a memoizing cache keyed by URI. It uses
/// `alloc::collections::BTreeMap` and `core::cell::RefCell` for
/// portability across `no_std + alloc` targets; production code
/// targeting `std` should prefer `std::sync::Mutex<HashMap<_, _>>`
/// (which is `Sync`) for shared concurrent access.
///
/// ```
/// extern crate alloc;
///
/// use alloc::collections::BTreeMap;
/// use alloc::string::{String, ToString};
/// use alloc::vec::Vec;
/// use core::cell::RefCell;
///
/// use pkix_aia::{AiaError, AiaFetcher};
///
/// /// Caching wrapper over any [`AiaFetcher`]. URIs already in the
/// /// cache return the stored result without delegating to the
/// /// inner fetcher. The inner result — success or failure — is
/// /// what gets cached; the wrapper treats every `AiaError` as
/// /// "the inner fetcher said no for this URI" and records it,
/// /// which is appropriate for callers who don't want to retry
/// /// fast-failing URIs.
/// pub struct CachingFetcher<F: AiaFetcher> {
///     inner: F,
///     cache: RefCell<BTreeMap<String, Result<Vec<u8>, AiaError>>>,
/// }
///
/// impl<F: AiaFetcher> CachingFetcher<F> {
///     pub fn new(inner: F) -> Self {
///         Self { inner, cache: RefCell::new(BTreeMap::new()) }
///     }
/// }
///
/// impl<F: AiaFetcher> AiaFetcher for CachingFetcher<F> {
///     fn fetch(&self, uri: &str) -> Result<Vec<u8>, AiaError> {
///         // Interior mutability via `RefCell` keeps `fetch` on
///         // `&self`. The trait surface never sees the borrow.
///         if let Some(cached) = self.cache.borrow().get(uri) {
///             return cached.clone();
///         }
///         let fresh = self.inner.fetch(uri);
///         self.cache.borrow_mut().insert(uri.to_string(), fresh.clone());
///         fresh
///     }
/// }
///
/// // Demonstration: a stub inner fetcher and a single cached call.
/// struct AlwaysDisabled;
/// impl AiaFetcher for AlwaysDisabled {
///     fn fetch(&self, _uri: &str) -> Result<Vec<u8>, AiaError> {
///         Err(AiaError::FetchingDisabled)
///     }
/// }
///
/// let cache = CachingFetcher::new(AlwaysDisabled);
/// // First call: delegates to the inner fetcher and records the result.
/// assert_eq!(cache.fetch("http://ca.example/ca.crt"),
///            Err(AiaError::FetchingDisabled));
/// // Second call: returns the cached failure, no inner delegation.
/// assert_eq!(cache.fetch("http://ca.example/ca.crt"),
///            Err(AiaError::FetchingDisabled));
/// ```
pub trait AiaFetcher {
    /// Fetch the DER-encoded certificate at `uri`.
    ///
    /// Returns the raw response bytes on success. Parsing them as
    /// an X.509 certificate is the caller's job.
    ///
    /// # Errors
    ///
    /// All failure modes surface through [`AiaError`]:
    ///
    /// - [`AiaError::FetchingDisabled`] for fetchers that are
    ///   intentionally off (e.g. `NoAiaFetcher`, planned at
    ///   PKIX-zkjb.4).
    /// - [`AiaError::UriUnsupported`] for URIs whose scheme this
    ///   fetcher does not handle.
    /// - [`AiaError::HttpStatus`], [`AiaError::Timeout`],
    ///   [`AiaError::ResponseTooLarge`], or
    ///   [`AiaError::IoFailure`] (under `std`) for transport-level
    ///   issues.
    /// - [`AiaError::MalformedCertificate`] if the adapter
    ///   pre-parsed the response and the bytes do not look like a
    ///   DER certificate. Adapters that return the bytes verbatim
    ///   leave that classification to the caller.
    fn fetch(&self, uri: &str) -> Result<Vec<u8>, AiaError>;

    /// Fetch multiple URIs in a single call.
    ///
    /// Returns a `Vec` aligned with `uris` by index: the `i`-th
    /// entry is the result for `uris[i]`. Per-URI success or
    /// failure is preserved.
    ///
    /// The default-impl is a sequential loop over [`fetch`](Self::fetch).
    /// Implementers MAY override this to pipeline requests
    /// (HTTP/2 multiplexing, connection-pool parallelism, etc.)
    /// when their transport supports it; the loop is the floor,
    /// not the ceiling.
    ///
    /// Adapters that fail the entire batch on the first error
    /// SHOULD instead return `Err(...)` in the relevant slot and
    /// continue processing remaining URIs. Whole-batch atomic
    /// failure is not a contract anyone relies on; per-URI errors
    /// are what callers act on.
    fn batch_fetch(&self, uris: &[&str]) -> Vec<Result<Vec<u8>, AiaError>> {
        uris.iter().map(|uri| self.fetch(uri)).collect()
    }
}

// ---------------------------------------------------------------------------
// Send + Sync invariant (AGENTS.md non-negotiable #6 / PKIX-2l0v.2)
// ---------------------------------------------------------------------------

// Compile-time assertion that `AiaError` is `Send + Sync`. A future
// variant that breaks this invariant (e.g. an `Rc<T>` or raw-pointer
// field) fails the workspace build immediately, not a runtime test.
// Pattern is the workspace standard recorded in memory
// `send-sync-invariant-in-pkix-workspace-pkix-2l0v`.
const _: fn() = || {
    fn _assert_send_sync<T: Send + Sync>() {}
    _assert_send_sync::<AiaError>();
};

// ---------------------------------------------------------------------------
// Inline tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "std")]
    use alloc::format;
    use alloc::string::ToString;

    #[test]
    fn display_fetching_disabled() {
        assert_eq!(
            AiaError::FetchingDisabled.to_string(),
            "AIA fetching is disabled"
        );
    }

    #[test]
    fn display_http_status() {
        assert_eq!(
            AiaError::HttpStatus(503).to_string(),
            "AIA fetch returned HTTP status 503"
        );
    }

    #[test]
    fn display_response_too_large() {
        assert_eq!(
            AiaError::ResponseTooLarge {
                limit: 65_536,
                actual: 131_072,
            }
            .to_string(),
            "AIA response exceeded size cap: limit 65536 bytes, observed 131072 bytes",
        );
    }

    #[test]
    fn display_malformed_certificate() {
        assert_eq!(
            AiaError::MalformedCertificate("expected SEQUENCE got SET".into()).to_string(),
            "AIA-fetched bytes did not parse as a certificate: expected SEQUENCE got SET",
        );
    }

    #[test]
    fn display_timeout() {
        assert_eq!(AiaError::Timeout.to_string(), "AIA fetch timed out");
    }

    #[test]
    fn display_uri_unsupported() {
        assert_eq!(
            AiaError::UriUnsupported("ldap://ca.example.com".into()).to_string(),
            "AIA URI scheme not supported: ldap://ca.example.com",
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn display_io_failure() {
        let e = AiaError::IoFailure {
            kind: std::io::ErrorKind::ConnectionRefused,
            message: "connection refused by 10.0.0.1:443".into(),
        };
        // Use `{kind:?}` in the impl, so the rendered label is the
        // Debug spelling of the variant. Pin the exact format so a
        // stdlib change to ErrorKind::Debug surfaces here, not in
        // downstream log scrapers.
        assert_eq!(
            format!("{e}"),
            "AIA fetch I/O failure (ConnectionRefused): connection refused by 10.0.0.1:443",
        );
    }

    #[test]
    fn clone_and_eq_unit_variants() {
        assert_eq!(
            AiaError::FetchingDisabled,
            AiaError::FetchingDisabled.clone()
        );
        assert_eq!(AiaError::Timeout, AiaError::Timeout.clone());
    }

    #[test]
    fn clone_and_eq_carrying_variants() {
        let a = AiaError::HttpStatus(404);
        assert_eq!(a, a.clone());
        let b = AiaError::ResponseTooLarge {
            limit: 1024,
            actual: 2048,
        };
        assert_eq!(b, b.clone());
        let c = AiaError::MalformedCertificate("parse error at offset 7".into());
        assert_eq!(c, c.clone());
        let d = AiaError::UriUnsupported("ldap".into());
        assert_eq!(d, d.clone());
    }

    #[test]
    fn distinct_variants_are_not_equal() {
        assert_ne!(AiaError::FetchingDisabled, AiaError::Timeout);
        assert_ne!(AiaError::HttpStatus(404), AiaError::HttpStatus(503));
        assert_ne!(
            AiaError::UriUnsupported("ldap".into()),
            AiaError::UriUnsupported("file".into()),
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn io_failure_clone_and_eq() {
        let a = AiaError::IoFailure {
            kind: std::io::ErrorKind::TimedOut,
            message: "deadline exceeded".into(),
        };
        assert_eq!(a, a.clone());
        let b = AiaError::IoFailure {
            kind: std::io::ErrorKind::TimedOut,
            message: "different message".into(),
        };
        assert_ne!(a, b);
        let c = AiaError::IoFailure {
            kind: std::io::ErrorKind::NotFound,
            message: "deadline exceeded".into(),
        };
        assert_ne!(a, c);
    }

    // -----------------------------------------------------------------------
    // AiaFetcher trait
    // -----------------------------------------------------------------------

    use alloc::vec;
    use core::cell::Cell;

    /// Test-only fetcher that records every URI it is asked about
    /// and returns a deterministic per-URI result. Demonstrates
    /// that `&self` is sufficient for non-trivial impls.
    struct RecordingFetcher {
        /// Increments on every call to `fetch`. Demonstrates &self
        /// interior mutability via `Cell` without a Mutex.
        call_count: Cell<usize>,
    }

    impl RecordingFetcher {
        fn new() -> Self {
            Self {
                call_count: Cell::new(0),
            }
        }
    }

    impl AiaFetcher for RecordingFetcher {
        fn fetch(&self, uri: &str) -> Result<Vec<u8>, AiaError> {
            self.call_count.set(self.call_count.get() + 1);
            // Echo the URI bytes back as the "DER" — not a real
            // certificate, but the trait surface is byte-level so
            // any deterministic mapping is sufficient for behavioural
            // tests.
            if uri.starts_with("http://") || uri.starts_with("https://") {
                Ok(uri.as_bytes().to_vec())
            } else {
                Err(AiaError::UriUnsupported(uri.into()))
            }
        }
    }

    #[test]
    fn fetch_records_each_call() {
        let f = RecordingFetcher::new();
        let r = f.fetch("http://ca.example/ca.crt").expect("ok");
        assert_eq!(r, b"http://ca.example/ca.crt".to_vec());
        assert_eq!(f.call_count.get(), 1);

        let _ = f.fetch("http://ca.example/ca.crt");
        let _ = f.fetch("http://ca.example/ca.crt");
        assert_eq!(f.call_count.get(), 3);
    }

    #[test]
    fn fetch_classifies_unsupported_scheme() {
        let f = RecordingFetcher::new();
        let r = f.fetch("ldap://ca.example/cn=ca");
        assert_eq!(
            r,
            Err(AiaError::UriUnsupported("ldap://ca.example/cn=ca".into())),
        );
        assert_eq!(f.call_count.get(), 1);
    }

    #[test]
    fn batch_fetch_default_impl_iterates_each_uri() {
        let f = RecordingFetcher::new();
        let uris: &[&str] = &[
            "http://ca.example/a.crt",
            "ldap://ca.example/b",
            "https://ca.example/c.crt",
        ];
        let results = f.batch_fetch(uris);
        assert_eq!(results.len(), 3);
        assert_eq!(results[0], Ok(b"http://ca.example/a.crt".to_vec()));
        assert_eq!(
            results[1],
            Err(AiaError::UriUnsupported("ldap://ca.example/b".into())),
        );
        assert_eq!(results[2], Ok(b"https://ca.example/c.crt".to_vec()));
        // Default-impl is sequential: one call per URI.
        assert_eq!(f.call_count.get(), 3);
    }

    #[test]
    fn batch_fetch_empty_input_returns_empty_output() {
        let f = RecordingFetcher::new();
        let empty: &[&str] = &[];
        let results = f.batch_fetch(empty);
        assert!(results.is_empty());
        // No calls should have happened.
        assert_eq!(f.call_count.get(), 0);
    }

    #[test]
    fn batch_fetch_preserves_order() {
        // Per-index alignment is part of the trait contract. A
        // pipelining override MUST preserve this ordering.
        let f = RecordingFetcher::new();
        let uris: &[&str] = &["http://a", "http://b", "http://c"];
        let results = f.batch_fetch(uris);
        let expected = vec![
            Ok(b"http://a".to_vec()),
            Ok(b"http://b".to_vec()),
            Ok(b"http://c".to_vec()),
        ];
        assert_eq!(results, expected);
    }

    /// A trivially-overridden `batch_fetch` that records its
    /// invocation count. Verifies overrides take precedence over
    /// the default-impl.
    struct OverriddenBatchFetcher {
        batch_calls: Cell<usize>,
    }

    impl AiaFetcher for OverriddenBatchFetcher {
        fn fetch(&self, _uri: &str) -> Result<Vec<u8>, AiaError> {
            // Should never be called by tests below; if it is, the
            // override didn't dispatch.
            unreachable!("override should not delegate to fetch")
        }

        fn batch_fetch(&self, uris: &[&str]) -> Vec<Result<Vec<u8>, AiaError>> {
            self.batch_calls.set(self.batch_calls.get() + 1);
            uris.iter().map(|_| Err(AiaError::Timeout)).collect()
        }
    }

    #[test]
    fn batch_fetch_override_takes_precedence() {
        let f = OverriddenBatchFetcher {
            batch_calls: Cell::new(0),
        };
        let results = f.batch_fetch(&["http://a", "http://b"]);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0], Err(AiaError::Timeout));
        assert_eq!(results[1], Err(AiaError::Timeout));
        assert_eq!(f.batch_calls.get(), 1);
    }
}
