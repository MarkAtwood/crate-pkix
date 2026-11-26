#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! # pkix-dane-resolver
//!
//! DNSSEC-validating resolution of DANE TLSA records.
//!
//! Fetches TLSA records, validates the DNSSEC chain over them, and returns
//! them as a [`TlsaResponse`] paired with the [`DnssecStatus`] they arrived
//! under — the form [`pkix-dane`](pkix_dane)'s matching functions consume.
//! This crate does the I/O; `pkix-dane` does the comparison; neither does the
//! other's job.
//!
//! ## Async only, deliberately
//!
//! There is no synchronous reference resolver here, and that is a decision
//! rather than an omission.
//!
//! Hickory, the DNS stack this is built on, is async. A synchronous facade
//! over it would have to either call `block_on` — which panics outright when
//! invoked from inside a Tokio runtime, and deadlocks a current-thread
//! executor — or own a background thread running its own runtime, the
//! `reqwest::blocking` pattern. The second works, but it hides an executor
//! behind a signature that looks like an ordinary blocking call, and the
//! caller who gets bitten is never the author who chose it. Avoiding exactly
//! that is what async is for.
//!
//! So the synchronous path does not resolve. It takes records as data:
//!
//! ```text
//! async caller:   let response = resolver.resolve(&name).await?;
//!                 verify_dane_ee(&cert, &response)?;          // sync, pure
//!
//! sync caller:    // obtain a TlsaResponse out of band — a cache, a
//!                 // scheduled job, a config file, your own DNS code —
//!                 verify_dane_ee(&cert, &response)?;          // same call
//! ```
//!
//! `pkix-dane`'s matching functions are pure functions over
//! `(certificate, TlsaResponse)` and perform no I/O, so resolution and
//! verification were always separable. A sync consumer whose TLSA source
//! genuinely is synchronous — a cache, a prevalidated store — implements
//! [`pkix_dane::TlsaResolver`] over it; that trait exists for them.
//!
//! ## The trust anchor is yours to supply
//!
//! [`HickoryTlsaResolver`] requires DNSSEC trust anchors and ships none. A
//! root key is a root of trust, and this workspace does not bake those in:
//! `pkix-path` ships no root program's certificate list, and `pkix-truststore`
//! takes DER bytes without asking where they came from. IANA's root anchors
//! are available as data from [`pkix-dnssec-anchor`], versioned independently
//! so a key-signing-key roll is a `cargo update` rather than a release of this
//! crate.
//!
//! Nothing here reads a file or consults the operating system for trust.
//!
//! ## Validation is done here, not trusted from upstream
//!
//! The resolver validates signatures itself. An upstream recursive resolver's
//! `AD` bit is a claim made by a host on the network path, not proof of
//! anything, and believing it would reduce DANE to the security of the link to
//! that host.
//!
//! Which server to *ask* is a different question, and does come from the
//! environment — see [`config`]. That is configuration discovery, not a trust
//! decision: no trust flows from the choice of server, because the answer is
//! validated regardless of who returned it.
//!
//! ## What a successful return means
//!
//! `Ok` means DNS answered and the answer's DNSSEC state was determined. It
//! does **not** mean the records are usable. A
//! [`Bogus`](DnssecStatus::Bogus) response is a successful determination that
//! validation failed, and the caller must treat it differently from a
//! timeout: bogus means do not fall back to PKIX, while a timeout leaves that
//! policy choice open. `Err` is reserved for not learning the answer at all.
//!
//! ## Zones mid algorithm rollover
//!
//! A zone may publish a DNSKEY algorithm the parent has no DS for. RFC
//! 6840 §5.11 allows it — "it is possible to add algorithms at the
//! DNSKEY that aren't in the DS record" — and it is what an operator
//! sees partway through an algorithm rollover, while new keys are
//! published and the parent's DS set has not caught up.
//!
//! Such a zone's answers carry signatures this resolver cannot chain,
//! sitting beside data that validates perfectly well under the algorithm
//! the DS does cover. Those answers come back
//! [`Secure`](DnssecStatus::Secure), from the data, as §5.11 requires:
//! "Validators SHOULD accept any single valid path ... and they MUST NOT
//! insist that all algorithms signaled in the DNSKEY RRset work."
//!
//! This is called out because getting it wrong is quiet. Folding those
//! unchainable signatures into the answer's status yields
//! [`Indeterminate`](DnssecStatus::Indeterminate), which folds into
//! "insecure" for every consumer, so under RFC 7672 DANE simply stops
//! applying to a correctly signed zone with nothing reporting an error.
//! This crate had that bug; `debian.org` is the zone that exposed it.
//!
//! [`pkix-dnssec-anchor`]: https://docs.rs/pkix-dnssec-anchor

use std::sync::Arc;

use async_trait::async_trait;
use pkix_dane::{DaneError, TlsaName, TlsaResponse};

pub mod config;

mod hickory;
/// Async SMTP DANE discovery (RFC 7672 §2.2).
pub mod smtp;

pub use config::{upstream_from_environment, UpstreamConfig};
pub use hickory::HickoryTlsaResolver;
pub use smtp::{AsyncSmtpDiscovery, SmtpDiscovery, SmtpDiscoveryStep};

// Re-exported so a consumer need not depend on pkix-dane directly just to
// name the types this crate returns.
pub use pkix_dane::{DnssecStatus, TlsaRecord};

// ---------------------------------------------------------------------------
// AsyncTlsaResolver
// ---------------------------------------------------------------------------

/// Async source of DNSSEC-validated TLSA records.
///
/// The async analogue of [`pkix_dane::TlsaResolver`], living here rather than
/// in `pkix-dane` so that `no_std` crate takes on no async machinery and its
/// consumers inherit no `Send` bounds. That placement follows the pattern
/// settled for `pkix-revocation-http`'s `AsyncRevocationChecker`.
///
/// Implement this to plug in your own validating resolver.
/// [`HickoryTlsaResolver`] is the reference implementation.
///
/// # Caching
///
/// TLSA records carry DNS TTLs, so caching them is an expected deployment
/// pattern and this trait is shaped to admit a wrapper: `&self` receivers let
/// an implementation hold interior-mutable state, and [`TlsaResponse`] is
/// `Clone + PartialEq` and serde-serializable behind a feature, so a cached
/// value can be stored and replayed. No cache ships here — AGENTS.md
/// non-negotiable #6 requires the workspace to *admit* caches, not to build
/// them.
///
/// # `Send` bounds
///
/// `Send + Sync` so implementations work on multi-threaded executors. The
/// returned futures are `Send` via `#[async_trait]`'s expansion.
#[async_trait]
pub trait AsyncTlsaResolver: Send + Sync {
    /// Looks up the TLSA records at `name` and validates the DNSSEC chain
    /// over the answer.
    ///
    /// A successful return describes what DNS said, including the cases where
    /// it said nothing useful: a [`Secure`](DnssecStatus::Secure) response
    /// with no records is an authenticated denial — the domain has signed a
    /// statement that it publishes no TLSA record — and a
    /// [`Bogus`](DnssecStatus::Bogus) response is a determination that
    /// validation failed. Both are information, not errors.
    ///
    /// # Errors
    ///
    /// - [`DaneError::ResolutionDisabled`] from a resolver that is wired in
    ///   but intentionally off.
    /// - [`DaneError::ResolutionFailed`] when the lookup could not be
    ///   completed: timeout, transport failure, `SERVFAIL`, or an answer that
    ///   could not be parsed.
    async fn resolve(&self, name: &TlsaName) -> Result<TlsaResponse, DaneError>;

    /// Looks up several names concurrently.
    ///
    /// Returns a `Vec` aligned with `names` by index. The default
    /// implementation joins the per-name futures, so a transport that can
    /// pipeline queries does so without an override — which is the point of
    /// the async family: the sync trait's equivalent can only loop.
    ///
    /// Callers use this for RFC 7671 §7 CNAME candidates and for several
    /// services of one host.
    async fn batch_resolve(&self, names: &[TlsaName]) -> Vec<Result<TlsaResponse, DaneError>> {
        futures_util::future::join_all(names.iter().map(|name| self.resolve(name))).await
    }
}

#[async_trait]
impl<T: AsyncTlsaResolver + ?Sized> AsyncTlsaResolver for Arc<T> {
    async fn resolve(&self, name: &TlsaName) -> Result<TlsaResponse, DaneError> {
        (**self).resolve(name).await
    }

    async fn batch_resolve(&self, names: &[TlsaName]) -> Vec<Result<TlsaResponse, DaneError>> {
        (**self).batch_resolve(names).await
    }
}

/// An [`AsyncTlsaResolver`] that never resolves anything.
///
/// The async counterpart of [`pkix_dane::NoTlsaResolver`], for wiring the seam
/// without enabling DANE. Every call returns
/// [`DaneError::ResolutionDisabled`]; no I/O and no DNS dependency is reached.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct NoAsyncTlsaResolver;

#[async_trait]
impl AsyncTlsaResolver for NoAsyncTlsaResolver {
    async fn resolve(&self, _name: &TlsaName) -> Result<TlsaResponse, DaneError> {
        Err(DaneError::ResolutionDisabled)
    }
}

// ---------------------------------------------------------------------------
// ResolverError
// ---------------------------------------------------------------------------

/// Failure modes for building a resolver.
///
/// Distinct from [`DaneError`], which covers resolution and matching. These
/// are construction-time problems: a resolver that cannot be built has not
/// failed to look anything up.
///
/// # Invariants (AGENTS.md non-negotiable #6)
///
/// `Clone + Debug + PartialEq + Eq`, `Send + Sync`, `#[non_exhaustive]`. No
/// embedded handle; upstream error detail is flattened to an owned `String`,
/// since `hickory`'s error types are neither `Clone` nor `Eq`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResolverError {
    /// No DNSSEC trust anchor was supplied.
    ///
    /// A validating resolver with no anchor can determine nothing: every
    /// answer would be [`Indeterminate`](DnssecStatus::Indeterminate). This
    /// is refused at construction rather than producing a resolver that
    /// silently never validates. Supply IANA's anchors from
    /// `pkix-dnssec-anchor`, or your own.
    NoTrustAnchor,

    /// A supplied trust anchor carried no public key.
    ///
    /// IANA publishes some historical anchors as a digest only, with no
    /// `DNSKEY`. Such an anchor cannot seed a validator, which needs the key
    /// to verify the root's self-signature. Filter to anchors with key
    /// material — `pkix-dnssec-anchor`'s `CURRENT` set all carry it.
    AnchorWithoutPublicKey {
        /// The anchor's identifier, if it had one, else its key tag rendered
        /// as a string.
        anchor: String,
    },

    /// A supplied trust anchor used a DNSSEC algorithm this build cannot
    /// verify with.
    AnchorAlgorithmUnsupported {
        /// The DNSSEC algorithm number.
        algorithm: u8,
    },

    /// Upstream DNS server configuration could not be determined.
    ///
    /// Neither the environment override nor the system configuration yielded
    /// a usable server. The inner `String` is a diagnostic for logs.
    UpstreamUnavailable(String),

    /// The resolver could not be constructed.
    ///
    /// A transport or configuration failure inside the DNS stack. The inner
    /// `String` is a diagnostic for logs; it is unstructured because the
    /// caller's recourse does not depend on which internal step failed.
    Construction(String),
}

impl core::fmt::Display for ResolverError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoTrustAnchor => f.write_str(
                "no DNSSEC trust anchor supplied; a validating resolver cannot \
                 determine anything without one",
            ),
            Self::AnchorWithoutPublicKey { anchor } => {
                write!(f, "trust anchor {anchor} carries no public key")
            }
            Self::AnchorAlgorithmUnsupported { algorithm } => {
                write!(f, "DNSSEC algorithm {algorithm} is not supported")
            }
            Self::UpstreamUnavailable(diagnostic) => {
                write!(f, "no usable upstream DNS server: {diagnostic}")
            }
            Self::Construction(diagnostic) => {
                write!(f, "could not build the resolver: {diagnostic}")
            }
        }
    }
}

impl std::error::Error for ResolverError {}

// ---------------------------------------------------------------------------
// Non-negotiable #6 compile-time assertions
// ---------------------------------------------------------------------------

const _: fn() = || {
    fn _assert_send_sync<T: Send + Sync>() {}
    _assert_send_sync::<ResolverError>();
    _assert_send_sync::<NoAsyncTlsaResolver>();
    _assert_send_sync::<UpstreamConfig>();

    fn _assert_cache_friendly<T: Clone + core::fmt::Debug + PartialEq + Eq>() {}
    _assert_cache_friendly::<ResolverError>();
};
