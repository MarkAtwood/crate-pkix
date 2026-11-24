#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! High-level X.509 certificate chain verification.
//!
//! Combines [`pkix_path`] (signature validation, RFC 5280 §6) with
//! [`pkix_revocation`] (CRL/OCSP) into a single ergonomic API.
//!
//! For fine-grained control — custom backends, per-cert revocation policy,
//! `no_std` constraints — use the component crates directly.
//!
//! **`std` only.** This crate depends on `pkix-path/std` and
//! `pkix-revocation/std`. Use [`pkix_path`] directly for `no_std` environments.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use pkix_chain::{
//!     verify_chain, DefaultVerifier, NoAiaFetcher, NoRevocation, TrustAnchor, ValidationPolicy,
//! };
//! use x509_cert::Certificate;
//!
//! # fn demo(chain: Vec<Certificate>, anchors: Vec<TrustAnchor>) -> Result<(), pkix_chain::Error> {
//! let policy = ValidationPolicy::new(1_700_000_000);
//!
//! let result = verify_chain(
//!     &chain,             // &[Certificate], leaf first
//!     &anchors,           // &[TrustAnchor]
//!     &policy,
//!     &DefaultVerifier,   // impl SignatureVerifier
//!     &NoRevocation,      // or a CrlChecker / OcspChecker
//!     &NoAiaFetcher,      // or an `AiaFetcher` from `pkix-aia-http`
//! )?;
//! # let _ = result;
//! # Ok(())
//! # }
//! ```
//!
//! # Reusable verifier
//!
//! For workloads that validate many chains against the same trust state,
//! [`Verifier`] packages the slow-changing inputs once and exposes
//! [`Verifier::verify_one`] and [`Verifier::verify_batch`]:
//!
//! ```rust,no_run
//! use pkix_chain::{DefaultVerifier, NoRevocation, TrustAnchor, ValidationPolicy, Verifier};
//! use x509_cert::Certificate;
//!
//! # fn demo(chains: Vec<Vec<Certificate>>, anchors: Vec<TrustAnchor>) -> Result<(), pkix_chain::Error> {
//! let policy = ValidationPolicy::new(1_700_000_000);
//! // `new_no_aia` wires `NoAiaFetcher` as the default fetcher,
//! // matching the historical "caller supplies the complete chain"
//! // behaviour. For real AIA fetching pass an `AiaFetcher` to
//! // `Verifier::new` instead.
//! let verifier = Verifier::new_no_aia(&anchors, &DefaultVerifier, &NoRevocation, &policy);
//!
//! let refs: Vec<&[Certificate]> = chains.iter().map(|c| c.as_slice()).collect();
//! let results = verifier.verify_batch(&refs);
//! # let _ = results;
//! # Ok(())
//! # }
//! ```
//!
//! The free function [`verify_chain`] is a thin wrapper around
//! [`Verifier::verify_one`]; both are zero-cost over the other.
//!
//! # Limitations
//!
//! - **Caller supplies the chain.** This crate validates a caller-ordered
//!   `&[Certificate]`. Path building from an unordered bag of certificates
//!   lives in `pkix-path-builder`.
//! - **AIA chain reassembly.** [`Verifier`] is generic over an
//!   `A: AiaFetcher` parameter that defaults to [`NoAiaFetcher`], and
//!   the [`verify_chain`] free function takes an `AiaFetcher` argument.
//!   When the caller-supplied chain is incomplete, the verifier extracts
//!   `id-ad-caIssuers` URIs from the orphaned cert's `AuthorityInfoAccess`
//!   extension, calls [`AiaFetcher::batch_fetch`], adds successfully
//!   parsed responses to a candidate pool, and re-runs
//!   [`pkix_path_builder::build_first_valid_path`]. The fetch loop walks
//!   up to [`AIA_MAX_DEPTH`] missing-intermediate levels; beyond that
//!   [`Error::AiaDepthExceeded`] surfaces. Because caIssuers URIs come
//!   from not-yet-validated certificates, fetching is bounded by
//!   [`AiaConfig`] (URIs per cert, total fetches, deadline). With [`NoAiaFetcher`] the
//!   first fetch returns [`AiaError::FetchingDisabled`] and the
//!   verifier surfaces [`Error::Aia`] without performing any I/O. The
//!   use-case wrappers (`verify_tls_server` and friends) accept an
//!   `A: AiaFetcher` parameter; pass [`NoAiaFetcher`] to disable fetching
//!   or supply a real fetcher for automatic chain reassembly.
//! - **Revocation is caller-supplied.** Online CRL / OCSP fetching is
//!   handled by `pkix-revocation-http`; this crate accepts any
//!   `RevocationChecker` impl — including `NoRevocation` for the
//!   zero-cost "I'll handle revocation myself" path.
//! - **`std` only.** Uses `pkix-path/std` and `pkix-revocation/std`. For
//!   `no_std` validation, use `pkix-path` directly with a `no_std`
//!   `SignatureVerifier`.
//! - **Algorithm coverage tracks `pkix-path`.** Bundled `SignatureVerifier`
//!   backends cover RSA-PKCS1v15-SHA-{256,384,512}, ECDSA-P-256-SHA-256,
//!   and (with the `p384` feature) ECDSA-P-384-SHA-384. Ed25519, P-521,
//!   and RSA-PSS are tracked under `PKIX-gphz`.
//! - **Use-case wrappers are fully generic.** `verify_tls_server`,
//!   `verify_tls_client_dns`, `verify_tls_client_mailbox`,
//!   `verify_smime_signer`, `verify_smime_recipient`, `verify_code_signer`,
//!   `verify_time_stamper`, and `verify_ocsp_responder` compose chain
//!   validation with the matching `pkix-identity` binding and
//!   `pkix-profiles` EKU rules. Niche cases (e.g. attribute-certificate
//!   verification, CT-anchored validation, DANE TLSA matching) are out
//!   of scope for this crate and live in `pkix-ac`, `pkix-ct`, and
//!   `pkix-dane` respectively.

pub use pkix_aia::{self, AiaError, AiaFetcher, NoAiaFetcher};
pub use pkix_identity::{self, IdentityError, MailboxName, ServerName};
pub use pkix_path::{
    self, DefaultVerifier, Profile, SignatureVerifier, TrustAnchor, ValidatedPath,
    ValidationPolicy, VerificationError, VerificationErrorKind,
};
pub use pkix_path_builder;
#[cfg(feature = "crl")]
#[cfg_attr(docsrs, doc(cfg(feature = "crl")))]
pub use pkix_revocation::CrlChecker;
#[cfg(feature = "ocsp")]
#[cfg_attr(docsrs, doc(cfg(feature = "ocsp")))]
pub use pkix_revocation::OcspChecker;
pub use pkix_revocation::{self, NoRevocation, RevocationChecker};

use std::borrow::Cow;
use x509_cert::Certificate;

mod aia_extract;
mod aia_response;

/// Maximum number of AIA-fetch iterations performed during chain reassembly.
///
/// Each iteration calls [`AiaFetcher::batch_fetch`] on the caIssuers URIs of
/// the certificates whose issuers are missing from the working cert pool,
/// then re-runs [`pkix_path_builder::build_first_valid_path`]. Without a cap,
/// a fetched intermediate that itself references a missing issuer (etc.)
/// would loop indefinitely. The cap stops the loop and surfaces
/// [`Error::AiaDepthExceeded`].
///
/// Five matches the bead-stated default for `PKIX-zkjb.7` and is generous
/// for real-world PKIs (cross-signed roots add at most one intermediate
/// hop beyond the operating CA's own intermediate; intermediate-of-an-
/// intermediate-of-an-intermediate is exceedingly rare).
///
/// This is the default for [`AiaConfig::max_depth`].
pub const AIA_MAX_DEPTH: usize = 5;

// DANE composition. Gated on `dane`, which is default-on: the gate pulls
// only the no_std pkix-dane crate, so the API surface costs a consumer
// nothing until they also enable `dane-resolver`.
// I/O-free core of AIA chain reassembly, shared by the sync and async
// verify paths so the AIA bounds exist in exactly one place.
mod aia_build;

#[cfg(feature = "dane")]
#[cfg_attr(docsrs, doc(cfg(feature = "dane")))]
pub mod dane;

#[cfg(feature = "dane")]
#[cfg_attr(docsrs, doc(cfg(feature = "dane")))]
pub use dane::{verify_tls_server_dane, DaneConfig, DaneFailurePolicy, TlsAuthorization};

/// Limits on AIA `caIssuers` chain reassembly in [`Verifier::verify_one`].
///
/// caIssuers URIs are read from certificates that have not been validated
/// yet, so whoever presents a certificate decides what the verifier
/// fetches. These limits bound the work one verification can cause. The
/// defaults are conservative: real chains need one or two fetches.
///
/// Set via [`Verifier::with_aia_config`]. [`verify_chain`] and the
/// use-case wrappers use [`AiaConfig::default`].
///
/// `#[non_exhaustive]`: construct with [`AiaConfig::new`] / `Default` and
/// adjust the public fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct AiaConfig {
    /// Maximum number of fetch rounds (missing-intermediate levels).
    /// Exhaustion surfaces [`Error::AiaDepthExceeded`]. Default:
    /// [`AIA_MAX_DEPTH`].
    pub max_depth: usize,
    /// Maximum number of caIssuers URIs followed per certificate, in the
    /// order they appear in its `AuthorityInfoAccess` extension. Default: 2.
    pub max_uris_per_cert: usize,
    /// Maximum number of fetches per [`Verifier::verify_one`] call, across
    /// all rounds. When more URIs remain unfetched and no path was found,
    /// [`Error::AiaFetchLimitExceeded`] surfaces. Default: 8.
    pub max_total_fetches: usize,
    /// Maximum number of certificates taken from one certs-only CMS
    /// response; further entries are ignored. Default: 16.
    pub max_certs_per_response: usize,
    /// Overall wall-clock budget for AIA fetching in one
    /// [`Verifier::verify_one`] call, checked before each fetch round.
    /// A round already in progress is not interrupted, so the worst case
    /// is this deadline plus one round (at most
    /// [`max_total_fetches`](Self::max_total_fetches) times the
    /// fetcher's per-request timeout). Exceeding it surfaces
    /// [`Error::AiaDeadlineExceeded`]. `None` disables the check.
    /// Default: 30 seconds.
    pub deadline: Option<std::time::Duration>,
}

impl AiaConfig {
    /// Construct a config with the default limits.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_depth: AIA_MAX_DEPTH,
            max_uris_per_cert: 2,
            max_total_fetches: 8,
            max_certs_per_response: 16,
            deadline: Some(std::time::Duration::from_secs(30)),
        }
    }
}

impl Default for AiaConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Combined error type for chain verification.
///
/// Wraps path validation errors ([`pkix_path::Error`]),
/// revocation checking errors ([`pkix_revocation::Error`]), and identity
/// binding errors ([`pkix_identity::IdentityError`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Error {
    /// RFC 5280 path validation failed.
    Path(pkix_path::Error),
    /// Revocation checking failed.
    Revocation(pkix_revocation::Error),
    /// Cert-side identity binding failed (hostname or mailbox SAN match).
    ///
    /// Only produced by the use-case wrappers (`verify_tls_server`,
    /// `verify_smime_signer`, …). The lower-level [`verify_chain`] and
    /// [`verify_chain_default`] entry points do not perform identity
    /// binding and never return this variant.
    Identity(pkix_identity::IdentityError),
    /// A wrapper-side post-validation profile check failed.
    ///
    /// Used by use-case wrappers for spec-mandated invariants that the
    /// lower-level [`ValidationPolicy`] cannot express directly — for
    /// example, RFC 3161 §2.3's requirement that a TSA certificate's
    /// `ExtendedKeyUsage` extension be marked critical and contain only
    /// `id-kp-timeStamping`.
    ///
    /// `reason` is a fixed-string description suitable for logging and
    /// diagnostic display. It is not parsed by the engine; pattern-match
    /// on the variant rather than the inner string.
    ProfileViolation {
        /// Fixed-string description of which profile invariant was violated.
        ///
        /// `Cow<'static, str>` rather than `&'static str` so the serde
        /// deserialize path can yield an owned `String` without leaking
        /// memory. Producers always supply `Cow::Borrowed` from a
        /// `&'static str` literal; the `Cow::Owned` variant arises only
        /// on the deserialize path.
        reason: std::borrow::Cow<'static, str>,
    },
    /// An RFC 6960 §4.2.2.2 OCSP-responder delegation check failed.
    ///
    /// Produced only by [`verify_ocsp_responder`]. Distinct from
    /// [`Error::ProfileViolation`] so callers can programmatically
    /// distinguish "the responder cert was not delegated by the
    /// expected issuer" from other profile-level failures.
    ///
    /// Two failure modes both surface as this variant:
    ///
    /// 1. **DN mismatch** — the responder cert's issuer DN does not
    ///    equal the supplied `issuer`'s subject DN under RFC 4518.
    /// 2. **Signature binding failure** — the responder cert's
    ///    signature does not verify under the supplied `issuer`'s SPKI.
    ///    The cryptographic binding is required by RFC 6960 §4.2.2.2;
    ///    DN equality alone admits a DN-twin attack in cross-signed
    ///    topologies (two CAs with colliding names but different keys).
    ///
    /// `reason` is a fixed-string description suitable for logging and
    /// diagnostic display. It is not parsed by the engine; pattern-match
    /// on the variant rather than the inner string.
    OcspDelegation {
        /// Fixed-string description of which delegation invariant was violated.
        ///
        /// See [`Error::ProfileViolation::reason`] for why the field is
        /// `Cow<'static, str>` rather than `&'static str`.
        reason: std::borrow::Cow<'static, str>,
    },
    /// AIA fetching failed during chain reassembly.
    ///
    /// Surfaced when the caller-supplied chain was incomplete (a cert's
    /// issuer is not in the chain and not a trust anchor) and every
    /// caIssuers URI followed (within [`AiaConfig`]) either could not be
    /// fetched or returned no usable CA certificate (neither a DER
    /// `Certificate` nor a certs-only CMS message containing one).
    /// With the default [`NoAiaFetcher`] this manifests as
    /// `Error::Aia(AiaError::FetchingDisabled)` on the first incomplete
    /// chain.
    ///
    /// Carries the underlying [`pkix_aia::AiaError`] from the last
    /// fetch attempt; earlier failures are dropped because the chain
    /// builder iterates URIs in caller-supplied order and only the
    /// final blocker determines the outcome.
    Aia(pkix_aia::AiaError),
    /// DANE verification failed.
    ///
    /// Either DANE was required and could not be satisfied — a `Bogus`
    /// DNSSEC status, which fails under every policy, or an
    /// undeterminable one under a strict policy — or usable TLSA records
    /// existed and the certificate matched none of them. The latter is
    /// the genuine DANE authentication failure: the domain stated which
    /// certificate it uses and this is not it.
    #[cfg(feature = "dane")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dane")))]
    Dane(pkix_dane::DaneError),
    /// Path reassembly via [`pkix_path_builder`] failed.
    ///
    /// Surfaced when the caller-supplied chain plus any AIA-fetched
    /// intermediates do not form a valid path to a trust anchor under
    /// the active [`ValidationPolicy`]. The underlying
    /// [`pkix_path_builder::Error`] distinguishes "no topologically
    /// valid path" from "valid topology but every candidate was rejected
    /// by `pkix_path::validate_path`".
    PathBuild(pkix_path_builder::Error),
    /// The AIA-fetch recursion cap was reached without closing the chain.
    ///
    /// Bounded at [`AiaConfig::max_depth`] (default [`AIA_MAX_DEPTH`])
    /// iterations to prevent unbounded
    /// fetching when each fetched intermediate itself has a missing
    /// issuer. Distinct from [`Error::Aia`] (which surfaces the
    /// underlying network/format failure) and from [`Error::PathBuild`]
    /// (which would have surfaced if the builder ran out of candidates
    /// inside a single iteration).
    AiaDepthExceeded,
    /// [`AiaConfig::max_total_fetches`] fetches were made without closing
    /// the chain, and further caIssuers URIs remained.
    AiaFetchLimitExceeded {
        /// The configured fetch cap.
        limit: usize,
    },
    /// [`AiaConfig::deadline`] elapsed before the chain was closed.
    AiaDeadlineExceeded,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Path(e) => write!(f, "path validation: {e}"),
            Self::Revocation(e) => write!(f, "revocation: {e}"),
            Self::Identity(e) => write!(f, "identity binding: {e}"),
            Self::ProfileViolation { reason } => write!(f, "profile violation: {reason}"),
            Self::OcspDelegation { reason } => write!(f, "ocsp responder delegation: {reason}"),
            Self::Aia(e) => write!(f, "aia fetch: {e}"),
            #[cfg(feature = "dane")]
            Self::Dane(e) => write!(f, "dane: {e}"),
            Self::PathBuild(e) => write!(f, "path build: {e}"),
            Self::AiaDepthExceeded => write!(f, "aia fetch recursion cap reached"),
            Self::AiaFetchLimitExceeded { limit } => {
                write!(f, "aia fetch limit reached ({limit} fetches)")
            }
            Self::AiaDeadlineExceeded => write!(f, "aia fetch deadline exceeded"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Path(e) => Some(e),
            Self::Revocation(e) => Some(e),
            Self::Identity(e) => Some(e),
            Self::Aia(e) => Some(e),
            #[cfg(feature = "dane")]
            Self::Dane(e) => Some(e),
            Self::PathBuild(e) => Some(e),
            Self::ProfileViolation { .. }
            | Self::OcspDelegation { .. }
            | Self::AiaDepthExceeded
            | Self::AiaFetchLimitExceeded { .. }
            | Self::AiaDeadlineExceeded => None,
        }
    }
}

impl From<pkix_path::Error> for Error {
    fn from(e: pkix_path::Error) -> Self {
        Self::Path(e)
    }
}

impl From<pkix_revocation::Error> for Error {
    fn from(e: pkix_revocation::Error) -> Self {
        Self::Revocation(e)
    }
}

impl From<pkix_identity::IdentityError> for Error {
    fn from(e: pkix_identity::IdentityError) -> Self {
        Self::Identity(e)
    }
}

impl From<pkix_aia::AiaError> for Error {
    fn from(e: pkix_aia::AiaError) -> Self {
        Self::Aia(e)
    }
}

impl From<pkix_path_builder::Error> for Error {
    fn from(e: pkix_path_builder::Error) -> Self {
        Self::PathBuild(e)
    }
}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Verify a certificate chain using the default `RustCrypto` signature backends.
///
/// Convenience wrapper around [`verify_chain`] that uses [`DefaultVerifier`]
/// (RSA-PKCS1v15-SHA-256 and ECDSA-P-256-SHA-256) for signature verification
/// and [`NoAiaFetcher`] for AIA fetching (i.e. no fetching — the caller must
/// supply the complete chain). Callers who want a custom signature backend
/// or a real [`AiaFetcher`] should call [`verify_chain`] directly.
///
/// # Errors
///
/// Returns `Err(Error)` for any validation failure. See [`Error`] in `pkix_path`
/// and `pkix_revocation` for the full list of failure conditions.
pub fn verify_chain_default<R>(
    chain: &[Certificate],
    anchors: &[TrustAnchor],
    policy: &ValidationPolicy,
    revocation: &R,
) -> crate::Result<ValidatedPath>
where
    R: RevocationChecker,
{
    verify_chain(
        chain,
        anchors,
        policy,
        &DefaultVerifier,
        revocation,
        &NoAiaFetcher,
    )
}

/// Verify a certificate chain with signature validation and revocation checking.
///
/// This is the primary high-level API. For direct control over path validation
/// (e.g., custom trust anchor selection, partial chains), use
/// [`pkix_path::validate_path`] directly.
///
/// # Arguments
///
/// - `chain`      — leaf-first certificate chain; `chain[0]` is the subject cert
/// - `anchors`    — trust anchors; validation succeeds when the chain reaches one
/// - `policy`     — validation policy (time, max depth, key usage enforcement)
/// - `verifier`   — signature verification backend (`RustCrypto` default or custom)
/// - `revocation` — revocation checker; use [`NoRevocation`] for offline/embedded
/// - `aia`        — AIA fetcher; use [`NoAiaFetcher`] for the historical
///   "caller supplies the complete chain" behaviour. When a non-trivial
///   fetcher is supplied and the caller-supplied chain is incomplete,
///   the verifier walks the leaf's `id-ad-caIssuers` URIs to retrieve
///   the missing intermediate(s) before path-building. See
///   [`Verifier::verify_one`] for the full chain-reassembly contract.
///
/// # Errors
///
/// Returns `Err` if path validation fails (signature, validity, chain linkage,
/// policy) or if revocation checking indicates a revoked certificate.
///
/// # Revocation coverage
///
/// Every certificate in `chain` is revocation-checked:
///
/// - `chain[i]` where `chain[i+1]` exists: checked via
///   [`RevocationChecker::check_revocation`] with `chain[i+1]` as the issuer.
/// - The last cert in `chain` (issued directly by the trust anchor): checked via
///   [`RevocationChecker::check_revocation_against_anchor`].
///
/// The **default implementation** of `check_revocation_against_anchor` returns
/// `Ok(())` (skip). `NoRevocation` inherits this default and skips the check.
/// `CrlChecker` and `OcspChecker` both **override** this method and actively
/// verify the pre-loaded CRL or OCSP response against the anchor's identity.
/// For full-chain revocation coverage with a custom checker, override
/// `check_revocation_against_anchor`, or include the issuing CA certificate as
/// the last element of `chain` so it is covered by `check_revocation` as a
/// normal intermediate.
pub fn verify_chain<V, R, A>(
    chain: &[Certificate],
    anchors: &[TrustAnchor],
    policy: &ValidationPolicy,
    verifier: &V,
    revocation: &R,
    aia: &A,
) -> crate::Result<ValidatedPath>
where
    V: SignatureVerifier,
    R: RevocationChecker,
    A: AiaFetcher,
{
    Verifier::new(anchors, verifier, revocation, policy, aia).verify_one(chain)
}

/// Reusable verifier holding prepared validation state.
///
/// `Verifier` packages the slow-changing inputs to chain verification —
/// trust anchors, signature verifier, revocation checker, and
/// validation policy — into a single value that can validate one or
/// many certificate chains.
///
/// This is the primary entry point for callers that validate multiple
/// chains against the same trust state. The free function
/// [`verify_chain`] delegates to [`Verifier::verify_one`] and is
/// preserved for single-call use.
///
/// # Lifetimes
///
/// All inputs are borrowed; the verifier holds references with the
/// same lifetime `'a`. Typical use is to construct trust anchors and
/// the validation policy once, then build a verifier on each batch.
///
/// # Cache friendliness
///
/// Per workspace policy (AGENTS.md non-negotiable #6) the verifier is
/// itself a small, stateless handle. Caches and memoisation belong in
/// caller-side wrappers around [`Verifier::verify_one`] or in the
/// [`SignatureVerifier`] / [`RevocationChecker`] implementations
/// themselves, both of which preserve the per-call interface needed
/// for such layering.
pub struct Verifier<'a, V: SignatureVerifier, R: RevocationChecker, A: AiaFetcher = NoAiaFetcher> {
    anchors: &'a [TrustAnchor],
    sig_verifier: &'a V,
    rev_checker: &'a R,
    policy: &'a ValidationPolicy,
    aia: &'a A,
    aia_config: AiaConfig,
}

impl<V: SignatureVerifier, R: RevocationChecker, A: AiaFetcher> core::fmt::Debug
    for Verifier<'_, V, R, A>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Verifier")
            .field("anchors_len", &self.anchors.len())
            .field("policy", self.policy)
            .field("aia_config", &self.aia_config)
            .finish_non_exhaustive()
    }
}

impl<'a, V, R> Verifier<'a, V, R, NoAiaFetcher>
where
    V: SignatureVerifier,
    R: RevocationChecker,
{
    /// Construct a verifier that does not fetch missing intermediates via AIA.
    ///
    /// Convenience constructor that wires [`NoAiaFetcher`] as the fetcher,
    /// matching the historical "caller supplies the complete chain"
    /// semantics. Callers who want a real [`AiaFetcher`] should use
    /// [`Verifier::new`] and pass an explicit fetcher reference.
    pub fn new_no_aia(
        anchors: &'a [TrustAnchor],
        sig_verifier: &'a V,
        rev_checker: &'a R,
        policy: &'a ValidationPolicy,
    ) -> Self {
        // `&NoAiaFetcher` here is static-promoted: the type is `Copy`
        // and `!Drop` and the value is a constexpr, so the borrow is
        // `&'static NoAiaFetcher`, which coerces into the generic `'a`.
        Self::new(anchors, sig_verifier, rev_checker, policy, &NoAiaFetcher)
    }
}

impl<'a, V, R, A> Verifier<'a, V, R, A>
where
    V: SignatureVerifier,
    R: RevocationChecker,
    A: AiaFetcher,
{
    /// Construct a verifier from its components.
    pub fn new(
        anchors: &'a [TrustAnchor],
        sig_verifier: &'a V,
        rev_checker: &'a R,
        policy: &'a ValidationPolicy,
        aia: &'a A,
    ) -> Self {
        Self {
            anchors,
            sig_verifier,
            rev_checker,
            policy,
            aia,
            aia_config: AiaConfig::new(),
        }
    }

    /// Replace the AIA reassembly limits (default [`AiaConfig::default`]).
    #[must_use]
    pub fn with_aia_config(mut self, config: AiaConfig) -> Self {
        self.aia_config = config;
        self
    }

    /// Borrow the `AiaFetcher` this verifier holds.
    ///
    /// Exposed for diagnostic purposes; callers debugging chain-build
    /// failures can inspect which fetcher is wired in.
    pub fn aia(&self) -> &A {
        self.aia
    }

    /// Verify a single certificate chain.
    ///
    /// Performs full RFC 5280 §6 path validation (signatures, validity,
    /// chain linkage, policy) followed by revocation checking on every
    /// cert in the chain, matching the semantics of [`verify_chain`].
    ///
    /// # Chain reassembly
    ///
    /// When the caller-supplied chain is positionally complete (each cert
    /// links to the next and the last cert is issued by an anchor),
    /// validation runs directly on the supplied ordering and revocation
    /// checks use the supplied chain.
    ///
    /// When the supplied chain has a break (a cert's issuer is not the
    /// next cert in the chain or any trust anchor) and the configured
    /// [`AiaFetcher`] is not [`NoAiaFetcher`], the verifier extracts
    /// `id-ad-caIssuers` URIs from the orphaned cert's
    /// `AuthorityInfoAccess` extension, fetches the referenced DER blobs,
    /// adds them to a candidate pool, and re-runs
    /// [`pkix_path_builder::build_first_valid_path`]. The fetch loop
    /// repeats up to [`AIA_MAX_DEPTH`] times to walk multi-level gaps
    /// (intermediate-of-an-intermediate); beyond that
    /// [`Error::AiaDepthExceeded`] is surfaced. Revocation checks run on
    /// the reassembled chain rather than the caller-supplied ordering.
    ///
    /// Fetching follows the [`AiaConfig`] limits (see
    /// [`Verifier::with_aia_config`]): only certs on a potential path from
    /// the leaf whose issuer is missing are asked for URIs, at most
    /// [`AiaConfig::max_uris_per_cert`] each and
    /// [`AiaConfig::max_total_fetches`] in total, within
    /// [`AiaConfig::deadline`]. Responses may be a DER certificate or a
    /// certs-only CMS message (RFC 5280 §4.2.2.1); only CA certificates not
    /// already in the pool are added.
    ///
    /// The slow path runs whenever the supplied ordering fails with
    /// `ChainBroken`, `NoTrustedPath`, `SignatureInvalid`,
    /// `SignatureNotVerified` or `PathTooLong`, including with
    /// [`NoAiaFetcher`]: the supplied certs are then treated as an
    /// unordered bag and re-built with [`pkix_path_builder`]. If that
    /// fails and the orphaned cert has caIssuers URIs, [`NoAiaFetcher`]
    /// returns [`AiaError::FetchingDisabled`] without doing any I/O and
    /// the function surfaces [`Error::Aia`]; with no URIs to follow it
    /// surfaces `Error::PathBuild(NoPathFound)`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if path validation fails or revocation indicates a
    /// revoked certificate. AIA-fetch failures surface as [`Error::Aia`];
    /// path-builder failures with the augmented pool surface as
    /// [`Error::PathBuild`]; running out of fetch iterations surfaces as
    /// [`Error::AiaDepthExceeded`], running out of fetches as
    /// [`Error::AiaFetchLimitExceeded`], and running out of time as
    /// [`Error::AiaDeadlineExceeded`].
    ///
    /// # Revocation coverage
    ///
    /// Identical to [`verify_chain`]:
    ///
    /// - `chain[i]` where `chain[i + 1]` exists: checked via
    ///   [`RevocationChecker::check_revocation`] with `chain[i + 1]` as
    ///   the issuer.
    /// - The last cert in the validated chain (issued directly by the
    ///   trust anchor): checked via
    ///   [`RevocationChecker::check_revocation_against_anchor`].
    pub fn verify_one(&self, chain: &[Certificate]) -> crate::Result<ValidatedPath> {
        // Fast path: try the caller-supplied positional chain first. This
        // preserves the historical zero-overhead behaviour for callers who
        // supply a complete chain and lets cert-correctness failures
        // (expired leaf, wrong KU, name-constraint violation) surface
        // directly without ever attempting AIA fetching that cannot help.
        match pkix_path::validate_path(chain, self.anchors, self.policy, self.sig_verifier) {
            Ok(validated) => {
                self.run_revocation_checks(chain, &validated)?;
                return Ok(validated);
            }
            Err(e) if is_aia_recoverable(&e) => {
                // Fall through to AIA-augmented chain reassembly.
            }
            Err(e) => return Err(Error::Path(e)),
        }

        // Slow path: build a chain from the supplied certs plus any we can
        // pull in via the caIssuers AIA URIs. Revocation runs against the
        // reassembled chain.
        let built = self.build_with_aia(chain)?;
        let validated =
            pkix_path::validate_path(&built, self.anchors, self.policy, self.sig_verifier)?;
        self.run_revocation_checks(&built, &validated)?;
        Ok(validated)
    }

    /// Revocation-check every cert in `chain` against the next-up
    /// issuer (cert or anchor). Factored out of [`Self::verify_one`] so
    /// the fast and slow paths share one implementation.
    fn run_revocation_checks(
        &self,
        chain: &[Certificate],
        validated: &ValidatedPath,
    ) -> crate::Result<()> {
        for (i, cert) in chain.iter().enumerate() {
            if i + 1 < chain.len() {
                self.rev_checker.check_revocation(cert, &chain[i + 1])?;
            } else {
                // Last cert: issued directly by the trust anchor. CrlChecker
                // / OcspChecker override this; NoRevocation inherits the
                // default Ok(()) skip.
                self.rev_checker
                    .check_revocation_against_anchor(cert, &self.anchors[validated.anchor_index])?;
            }
        }
        Ok(())
    }

    /// Iteratively augment the candidate pool via AIA `caIssuers` fetches
    /// until [`pkix_path_builder::build_first_valid_path`] finds a chain
    /// or one of the [`AiaConfig`] limits is reached.
    ///
    /// `supplied_chain` is leaf-first; `supplied_chain[0]` is the EE the
    /// builder targets. All certs in the supplied chain seed the pool
    /// (the caller's ordering is treated as a candidate set, not a fixed
    /// path) so a partially-ordered chain with the right intermediates
    /// in the wrong slots still resolves without any AIA fetches.
    ///
    /// # Fetch discipline
    ///
    /// caIssuers URIs come from certificates that have not been validated
    /// yet, so every fetch is attacker-steerable. To keep the work bounded:
    ///
    /// - only certs on a potential path from the leaf (the leaf, plus CA
    ///   certs reachable from it by issuer-name links) whose issuer is not
    ///   yet available are asked for their URIs ([`orphans_on_paths`]);
    /// - at most [`AiaConfig::max_uris_per_cert`] URIs per cert, at most
    ///   [`AiaConfig::max_total_fetches`] fetches per call, each URI once;
    /// - the [`AiaConfig::deadline`] is checked before every fetch round;
    /// - only CA certificates that are not already pooled are added from a
    ///   response, at most [`AiaConfig::max_certs_per_response`] of them.
    ///
    /// All of that bookkeeping lives in [`crate::aia_build`], shared with the
    /// async verify path so each bound exists in exactly one place; two
    /// copies of a cap drifting would be a security regression rather than a
    /// maintenance annoyance. What remains here is the loop that performs the
    /// fetches.
    fn build_with_aia(&self, supplied_chain: &[Certificate]) -> crate::Result<Vec<Certificate>> {
        use crate::aia_build::{AiaBuildState, AiaBuilder, AiaStep};

        let leaf = supplied_chain
            .first()
            .ok_or(Error::PathBuild(pkix_path_builder::Error::NoPathFound))?;

        let builder = AiaBuilder {
            anchors: self.anchors,
            sig_verifier: self.sig_verifier,
            policy: self.policy,
            config: &self.aia_config,
        };
        let mut state = AiaBuildState::new(supplied_chain, &self.aia_config);

        loop {
            match builder.next_step(&mut state, leaf) {
                AiaStep::Built(built) => return Ok(built),
                AiaStep::Failed(e) => return Err(e),
                AiaStep::Fetch(uris) => {
                    let refs: Vec<&str> = uris.iter().map(String::as_str).collect();
                    let results = self.aia.batch_fetch(&refs);
                    if let Some(e) = builder.absorb(&mut state, results, uris.len()) {
                        return Err(e);
                    }
                }
            }
        }
    }

    /// Verify many certificate chains, returning per-chain results.
    ///
    /// Each chain is verified independently against the same trust
    /// state; failures in one chain do not abort the others. The
    /// returned vector has the same length as `chains` with results in
    /// matching order.
    ///
    /// This is a sequential loop over [`Verifier::verify_one`]; the
    /// chains do not share any per-validation state. Callers requiring
    /// cross-chain caching (memoised path-builder candidates,
    /// revocation lookups, etc.) should layer that on top of
    /// `verify_one` or inside their [`SignatureVerifier`] /
    /// [`RevocationChecker`] implementations.
    pub fn verify_batch(&self, chains: &[&[Certificate]]) -> Vec<crate::Result<ValidatedPath>> {
        chains.iter().map(|chain| self.verify_one(chain)).collect()
    }
}

/// Verify a certificate chain for TLS server use.
///
/// Composes [`verify_chain`] with [`pkix_identity::verify_dns_name`] in a
/// single call. The leaf certificate `chain[0]` must both validate as a
/// chain against `anchors` under `profile.policy(now_unix)` **and** carry a
/// Subject Alternative Name entry matching `name`.
///
/// Signatures are checked with the caller-supplied `verifier`
/// ([`DefaultVerifier`] for the bundled RustCrypto backends), and missing
/// intermediates are fetched through `aia` ([`NoAiaFetcher`] to disable)
/// under the default [`AiaConfig`] limits. Callers needing other AIA limits
/// should use [`Verifier::with_aia_config`] and call
/// [`pkix_identity::verify_dns_name`] themselves.
///
/// # Arguments
///
/// - `chain`      — leaf-first certificate chain; `chain[0]` is the server cert
/// - `anchors`    — trust anchors; validation succeeds when the chain reaches one
/// - `name`       — pre-parsed server identity (construct via
///   [`ServerName::dns_name`] or [`ServerName::ip_address`])
/// - `profile`    — profile supplying the [`ValidationPolicy`] for `now_unix`;
///   typically [`pkix_profiles::BasicTlsProfile`] or
///   `pkix_profiles_cabf::WebPkiProfile`
/// - `now_unix`   — current time, seconds since the Unix epoch
/// - `verifier`   — signature verification backend ([`DefaultVerifier`] for standard algorithms)
/// - `revocation` — revocation checker (use [`NoRevocation`] for offline)
/// - `aia`        — AIA fetcher (use [`NoAiaFetcher`] when the caller supplies the full chain)
///
/// # Order of operations
///
/// Path validation runs first. A chain that fails RFC 5280 §6.1 (expired,
/// broken signature, missing intermediate, policy violation) returns
/// [`Error::Path`] regardless of whether the leaf's SAN would have matched.
/// Identity binding runs only after path validation succeeds. This ordering
/// matches the behaviour callers expect from `rustls`/`webpki` and prevents
/// leaking SAN-match information about untrusted certificates.
///
/// # Errors
///
/// - [`Error::Path`] — RFC 5280 path validation failed.
/// - [`Error::Revocation`] — a cert in the chain was revoked or the
///   revocation source was unusable.
/// - [`Error::Identity`] — path validation succeeded but the leaf's SAN did
///   not contain an entry matching `name` (or the SAN extension was
///   missing/malformed).
#[allow(clippy::too_many_arguments)]
pub fn verify_tls_server<V, P, R, A>(
    chain: &[Certificate],
    anchors: &[TrustAnchor],
    name: &ServerName<'_>,
    profile: &P,
    now_unix: u64,
    verifier: &V,
    revocation: &R,
    aia: &A,
) -> crate::Result<ValidatedPath>
where
    V: SignatureVerifier,
    P: Profile,
    R: RevocationChecker,
    A: AiaFetcher,
{
    let policy = profile.policy(now_unix);
    let validated = verify_chain(chain, anchors, &policy, verifier, revocation, aia)?;
    debug_assert!(!chain.is_empty(), "verify_chain must reject empty chains");
    pkix_identity::verify_dns_name(&chain[0], name)?;
    Ok(validated)
}

/// Verify a certificate chain for TLS client authentication with an
/// optional DNS-name identity binding.
///
/// Composes [`verify_chain`] with an optional call to
/// [`pkix_identity::verify_dns_name`] in a single call. The leaf
/// certificate `chain[0]` must validate as a chain against `anchors`
/// under `profile.policy(now_unix)`. When `identity` is `Some(name)`,
/// the leaf must additionally carry a Subject Alternative Name entry
/// (`dNSName` or `iPAddress`) matching `name`.
///
/// `identity` is `Option<&ServerName<'_>>` because TLS client-auth
/// callers fall into two camps: service-to-service mTLS deployments
/// that pin a DNS or IP identity in the SAN, and callers that want
/// path-only validation (e.g. servers willing to accept any client
/// the trust anchors vouched for, even though the actual identity is
/// then read elsewhere — typically from the Subject DN). The latter
/// pass `None`.
///
/// The mailbox-flavored sibling [`verify_tls_client_mailbox`] covers
/// personal-S/MIME-style client certs that bind an RFC 5322 mailbox
/// in `rfc822Name` SAN entries; see PKIX-fmtv.11.2.1 for the
/// two-function rationale.
///
/// The client-vs-server distinction is encoded in the caller-supplied
/// [`Profile`]'s `ValidationPolicy` (EKU `id-kp-clientAuth` vs
/// `id-kp-serverAuth`).
///
/// # Arguments
///
/// - `chain`      — leaf-first certificate chain; `chain[0]` is the client cert
/// - `anchors`    — trust anchors; validation succeeds when the chain reaches one
/// - `identity`   — `Some(name)` to bind a DNS or IP identity from the leaf's
///   SAN; `None` to skip identity binding and validate the path only
/// - `profile`    — profile supplying the [`ValidationPolicy`] for `now_unix`;
///   the profile must require the `id-kp-clientAuth` EKU for production use
/// - `now_unix`   — current time, seconds since the Unix epoch
/// - `verifier`   — signature verification backend ([`DefaultVerifier`] for standard algorithms)
/// - `revocation` — revocation checker (use [`NoRevocation`] for offline)
/// - `aia`        — AIA fetcher (use [`NoAiaFetcher`] when the caller supplies the full chain)
///
/// # Order of operations
///
/// Path validation runs first. A chain that fails RFC 5280 §6.1
/// (expired, broken signature, missing intermediate, policy violation)
/// returns [`Error::Path`] regardless of whether the leaf's SAN would
/// have matched. Identity binding runs only after path validation
/// succeeds and only when `identity` is `Some(_)`.
///
/// # Errors
///
/// - [`Error::Path`] — RFC 5280 path validation failed.
/// - [`Error::Revocation`] — a cert in the chain was revoked or the
///   revocation source was unusable.
/// - [`Error::Identity`] — `identity` was `Some(_)`, path validation
///   succeeded, but the leaf's SAN did not contain an entry matching
///   the supplied `ServerName` (or the SAN extension was
///   missing/malformed).
#[allow(clippy::too_many_arguments)]
pub fn verify_tls_client_dns<V, P, R, A>(
    chain: &[Certificate],
    anchors: &[TrustAnchor],
    identity: Option<&ServerName<'_>>,
    profile: &P,
    now_unix: u64,
    verifier: &V,
    revocation: &R,
    aia: &A,
) -> crate::Result<ValidatedPath>
where
    V: SignatureVerifier,
    P: Profile,
    R: RevocationChecker,
    A: AiaFetcher,
{
    let policy = profile.policy(now_unix);
    let validated = verify_chain(chain, anchors, &policy, verifier, revocation, aia)?;
    if let Some(name) = identity {
        debug_assert!(!chain.is_empty(), "verify_chain must reject empty chains");
        pkix_identity::verify_dns_name(&chain[0], name)?;
    }
    Ok(validated)
}

/// Verify a certificate chain for TLS client authentication with an
/// optional mailbox identity binding.
///
/// Companion to [`verify_tls_client_dns`] for personal-S/MIME-style
/// client certificates whose identity binds in `rfc822Name` (RFC 5280
/// §4.2.1.6) or `otherName(SmtpUTF8Mailbox)` (RFC 8398) SAN entries.
/// When `identity` is `Some(mailbox)`, the leaf must carry a SAN entry
/// matching the supplied [`MailboxName`]; when `identity` is `None`,
/// identity binding is skipped and only the path is validated.
///
/// The split between [`verify_tls_client_dns`] and
/// [`verify_tls_client_mailbox`] was chosen over a single `Option<&dyn
/// Identity>` API to preserve type discipline at the call site
/// (PKIX-fmtv.11.2.1). The caller picks the function name that
/// communicates the binding shape it intends to enforce.
///
/// The client-vs-server distinction is encoded in the caller-supplied
/// [`Profile`]'s `ValidationPolicy` (EKU `id-kp-clientAuth`).
///
/// # Arguments
///
/// - `chain`      — leaf-first certificate chain; `chain[0]` is the client cert
/// - `anchors`    — trust anchors; validation succeeds when the chain reaches one
/// - `identity`   — `Some(mailbox)` to bind a mailbox identity from the leaf's
///   SAN; `None` to skip identity binding and validate the path only
/// - `profile`    — profile supplying the [`ValidationPolicy`] for `now_unix`;
///   the profile must require the `id-kp-clientAuth` EKU for production use
/// - `now_unix`   — current time, seconds since the Unix epoch
/// - `verifier`   — signature verification backend ([`DefaultVerifier`] for standard algorithms)
/// - `revocation` — revocation checker (use [`NoRevocation`] for offline)
/// - `aia`        — AIA fetcher (use [`NoAiaFetcher`] when the caller supplies the full chain)
///
/// # Order of operations
///
/// Path validation runs first (see [`verify_tls_client_dns`] for the
/// rationale). Identity binding runs only after path validation
/// succeeds and only when `identity` is `Some(_)`.
///
/// # Errors
///
/// - [`Error::Path`] — RFC 5280 path validation failed.
/// - [`Error::Revocation`] — a cert in the chain was revoked or the
///   revocation source was unusable.
/// - [`Error::Identity`] — `identity` was `Some(_)`, path validation
///   succeeded, but the leaf's SAN did not contain an entry matching
///   the supplied `MailboxName` (or the SAN extension was
///   missing/malformed).
#[allow(clippy::too_many_arguments)]
pub fn verify_tls_client_mailbox<V, P, R, A>(
    chain: &[Certificate],
    anchors: &[TrustAnchor],
    identity: Option<&MailboxName<'_>>,
    profile: &P,
    now_unix: u64,
    verifier: &V,
    revocation: &R,
    aia: &A,
) -> crate::Result<ValidatedPath>
where
    V: SignatureVerifier,
    P: Profile,
    R: RevocationChecker,
    A: AiaFetcher,
{
    let policy = profile.policy(now_unix);
    let validated = verify_chain(chain, anchors, &policy, verifier, revocation, aia)?;
    if let Some(mailbox) = identity {
        debug_assert!(!chain.is_empty(), "verify_chain must reject empty chains");
        pkix_identity::verify_mailbox(&chain[0], mailbox)?;
    }
    Ok(validated)
}

/// Verify a certificate chain for S/MIME signer use.
///
/// Composes [`verify_chain`] with [`pkix_identity::verify_mailbox`] in a
/// single call. The leaf certificate `chain[0]` must both validate as a
/// chain against `anchors` under `profile.policy(now_unix)` **and** carry a
/// Subject Alternative Name entry (`rfc822Name` or `otherName(SmtpUTF8Mailbox)`)
/// matching `mailbox`.
///
/// The signer-vs-recipient distinction is encoded in the caller-supplied
/// [`Profile`]'s `ValidationPolicy`: signer profiles require KeyUsage
/// `digitalSignature`, recipient profiles require `keyEncipherment`. The
/// wrapper body is byte-identical to [`verify_smime_recipient`]; the
/// distinct function name lets callers communicate intent at the call site.
///
/// # Arguments
///
/// - `chain`      — leaf-first certificate chain; `chain[0]` is the signer cert
/// - `anchors`    — trust anchors; validation succeeds when the chain reaches one
/// - `mailbox`    — pre-parsed mailbox (construct via [`MailboxName::parse`])
/// - `profile`    — profile supplying the [`ValidationPolicy`] for `now_unix`;
///   typically [`pkix_profiles::BasicSmimeProfile`] or a CA/B-Forum S/MIME tier
/// - `now_unix`   — current time, seconds since the Unix epoch
/// - `verifier`   — signature verification backend ([`DefaultVerifier`] for standard algorithms)
/// - `revocation` — revocation checker (use [`NoRevocation`] for offline)
/// - `aia`        — AIA fetcher (use [`NoAiaFetcher`] when the caller supplies the full chain)
///
/// # Order of operations
///
/// Path validation runs first. A chain that fails RFC 5280 §6.1 returns
/// [`Error::Path`] regardless of whether the leaf's SAN would have matched.
/// Identity binding runs only after path validation succeeds.
///
/// # Errors
///
/// - [`Error::Path`] — RFC 5280 path validation failed.
/// - [`Error::Revocation`] — a cert in the chain was revoked or the
///   revocation source was unusable.
/// - [`Error::Identity`] — path validation succeeded but the leaf's SAN did
///   not contain an entry matching `mailbox` (or the SAN extension was
///   missing/malformed).
#[allow(clippy::too_many_arguments)]
pub fn verify_smime_signer<V, P, R, A>(
    chain: &[Certificate],
    anchors: &[TrustAnchor],
    mailbox: &MailboxName<'_>,
    profile: &P,
    now_unix: u64,
    verifier: &V,
    revocation: &R,
    aia: &A,
) -> crate::Result<ValidatedPath>
where
    V: SignatureVerifier,
    P: Profile,
    R: RevocationChecker,
    A: AiaFetcher,
{
    let policy = profile.policy(now_unix);
    let validated = verify_chain(chain, anchors, &policy, verifier, revocation, aia)?;
    debug_assert!(!chain.is_empty(), "verify_chain must reject empty chains");
    pkix_identity::verify_mailbox(&chain[0], mailbox)?;
    Ok(validated)
}

/// Verify a certificate chain for S/MIME recipient use.
///
/// Identical mechanics to [`verify_smime_signer`]; see that function's
/// rustdoc for arguments, ordering, and errors. The two wrappers differ
/// only in name so callers can communicate signer-vs-recipient intent at
/// the call site. The key-usage distinction (`digitalSignature` for signer,
/// `keyEncipherment` for recipient) is encoded in the caller-supplied
/// [`Profile`].
#[allow(clippy::too_many_arguments)]
pub fn verify_smime_recipient<V, P, R, A>(
    chain: &[Certificate],
    anchors: &[TrustAnchor],
    mailbox: &MailboxName<'_>,
    profile: &P,
    now_unix: u64,
    verifier: &V,
    revocation: &R,
    aia: &A,
) -> crate::Result<ValidatedPath>
where
    V: SignatureVerifier,
    P: Profile,
    R: RevocationChecker,
    A: AiaFetcher,
{
    let policy = profile.policy(now_unix);
    let validated = verify_chain(chain, anchors, &policy, verifier, revocation, aia)?;
    debug_assert!(!chain.is_empty(), "verify_chain must reject empty chains");
    pkix_identity::verify_mailbox(&chain[0], mailbox)?;
    Ok(validated)
}

/// Verify a certificate chain for code-signing use.
///
/// Thin composition of [`verify_chain`] under a [`Profile`] that requires
/// the `id-kp-codeSigning` Extended Key Usage. Code-signing certificates
/// do not carry a caller-supplied identity target (no hostname, no mailbox)
/// so the wrapper does not perform identity binding — the EKU requirement
/// is encoded entirely in `profile.policy(now_unix)`.
///
/// # Arguments
///
/// - `chain`      — leaf-first certificate chain; `chain[0]` is the signer cert
/// - `anchors`    — trust anchors; validation succeeds when the chain reaches one
/// - `profile`    — profile supplying the [`ValidationPolicy`] for `now_unix`;
///   typically [`pkix_profiles::BasicCodeSigningProfile`] or
///   `pkix_profiles_cabf::CodeSigningProfile` for the CA/B Forum BR overlay
/// - `now_unix`   — current time, seconds since the Unix epoch
/// - `verifier`   — signature verification backend ([`DefaultVerifier`] for standard algorithms)
/// - `revocation` — revocation checker (use [`NoRevocation`] for offline)
/// - `aia`        — AIA fetcher (use [`NoAiaFetcher`] when the caller supplies the full chain)
///
/// # Errors
///
/// - [`Error::Path`] — RFC 5280 path validation failed (including the
///   profile's `id-kp-codeSigning` EKU requirement not being met).
/// - [`Error::Revocation`] — a cert in the chain was revoked or the
///   revocation source was unusable.
pub fn verify_code_signer<V, P, R, A>(
    chain: &[Certificate],
    anchors: &[TrustAnchor],
    profile: &P,
    now_unix: u64,
    verifier: &V,
    revocation: &R,
    aia: &A,
) -> crate::Result<ValidatedPath>
where
    V: SignatureVerifier,
    P: Profile,
    R: RevocationChecker,
    A: AiaFetcher,
{
    let policy = profile.policy(now_unix);
    verify_chain(chain, anchors, &policy, verifier, revocation, aia)
}

/// Verify a certificate chain for Time Stamping Authority (TSA) use.
///
/// Composes [`verify_chain`] under the caller-supplied [`Profile`] with two
/// additional RFC 3161 post-validation checks on the leaf certificate:
///
/// 1. **`ExtendedKeyUsage` shape (RFC 3161 §2.3)** — the EKU extension is:
///    - **present** (covered by `profile.policy(now_unix).required_leaf_eku`),
///    - **marked critical**, and
///    - **contains only** `id-kp-timeStamping` (no other EKU values).
///
/// 2. **`KeyUsage` shape (RFC 3161 §2.1 #10 / OpenSSL `-purpose
///    timestampsign`)** — the TSA's key is "generated exclusively for this
///    purpose," which a signing-only KU shape reflects. When the
///    `KeyUsage` extension is present it MUST contain only
///    `digitalSignature` and/or `nonRepudiation`; any of
///    `keyEncipherment`, `dataEncipherment`, `keyAgreement`,
///    `keyCertSign`, `cRLSign`, `encipherOnly`, or `decipherOnly` is
///    forbidden. The check is skipped if `KeyUsage` is absent (RFC 5280
///    §4.2.1.3 does not require it on EE certs).
///
/// The EKU presence check is enforced inside [`verify_chain`] via the
/// profile's `required_leaf_eku`. The remaining checks run after
/// `verify_chain` returns and fail with [`Error::ProfileViolation`] when
/// violated.
///
/// # Arguments
///
/// - `chain`      — leaf-first certificate chain; `chain[0]` is the TSA cert
/// - `anchors`    — trust anchors; validation succeeds when the chain reaches one
/// - `profile`    — profile supplying the [`ValidationPolicy`] for `now_unix`;
///   typically [`pkix_profiles::BasicTimeStampingProfile`]
/// - `now_unix`   — current time, seconds since the Unix epoch
/// - `verifier`   — signature verification backend ([`DefaultVerifier`] for standard algorithms)
/// - `revocation` — revocation checker (use [`NoRevocation`] for offline)
/// - `aia`        — AIA fetcher (use [`NoAiaFetcher`] when the caller supplies the full chain)
///
/// # Errors
///
/// - [`Error::Path`] — RFC 5280 path validation failed (including the
///   profile's `id-kp-timeStamping` EKU presence requirement).
/// - [`Error::Revocation`] — a cert in the chain was revoked.
/// - [`Error::ProfileViolation`] — path validation succeeded but the leaf
///   cert's EKU extension is not marked critical, contains EKU values
///   other than `id-kp-timeStamping`, or its `KeyUsage` extension is
///   present and asserts a bit other than `digitalSignature` or
///   `nonRepudiation`.
pub fn verify_time_stamper<V, P, R, A>(
    chain: &[Certificate],
    anchors: &[TrustAnchor],
    profile: &P,
    now_unix: u64,
    verifier: &V,
    revocation: &R,
    aia: &A,
) -> crate::Result<ValidatedPath>
where
    V: SignatureVerifier,
    P: Profile,
    R: RevocationChecker,
    A: AiaFetcher,
{
    let policy = profile.policy(now_unix);
    let validated = verify_chain(chain, anchors, &policy, verifier, revocation, aia)?;
    debug_assert!(!chain.is_empty(), "verify_chain must reject empty chains");
    enforce_timestamping_eku_critical_and_sole(&chain[0])?;
    enforce_timestamping_ku_shape(&chain[0])?;
    Ok(validated)
}

/// Verify a certificate chain for delegated OCSP responder use.
///
/// Composes [`verify_chain`] under a [`Profile`] that requires the
/// `id-kp-OCSPSigning` Extended Key Usage with two RFC 6960 §4.2.2.2
/// post-validation checks specific to OCSP responder certs:
///
/// 1. **Delegation** — the responder cert at `chain[0]` MUST be issued
///    by the specific `issuer` argument (RFC 4518 string-prep DN
///    equality between `chain[0].tbs.issuer` and `issuer.tbs.subject`).
///    The signature half is already enforced by [`verify_chain`] when
///    `chain[1]` is supplied; the DN check additionally pins the
///    delegation to a caller-named CA.
/// 2. **`id-pkix-ocsp-nocheck`** — when the responder cert at
///    `chain[0]` carries the `id-pkix-ocsp-nocheck` extension
///    (OID 1.3.6.1.5.5.7.48.1.5, RFC 6960 §4.2.2.2.1), the caller's
///    `revocation` checker is bypassed for `chain[0]` only.
///    Otherwise infinite-loop avoidance would force the caller to ship
///    a custom checker. Revocation on every other cert in the chain
///    runs normally.
///
/// # Scope: delegated responders only
///
/// This wrapper handles delegated OCSP responder certs (RFC 6960
/// §4.2.2.2: a separate end-entity cert signed by the CA, carrying
/// `id-kp-OCSPSigning`). The CA-direct case — where the CA signs OCSP
/// responses with its own CA key, with no separate responder cert —
/// is not an "OCSP responder validation" problem at the API surface
/// and is not handled here. CA-direct callers validate the CA cert
/// itself with [`verify_chain`] using a profile that does not require
/// `id-kp-OCSPSigning` (a normal CA cert does not carry that EKU).
///
/// # Worked example — CA-direct alternative
///
/// ```rust,no_run
/// use pkix_chain::{
///     verify_chain, DefaultVerifier, NoAiaFetcher, NoRevocation, TrustAnchor,
/// };
/// use pkix_profiles::{Profile, Rfc5280Profile};
/// use x509_cert::Certificate;
///
/// # fn demo(ca_cert: Certificate, anchors: Vec<TrustAnchor>, now: u64)
/// #     -> Result<(), pkix_chain::Error> {
/// // CA-direct OCSP: the CA cert itself signs OCSP responses. Validate
/// // it as a normal cert with verify_chain (no OCSP-Signing EKU required).
/// let policy = Rfc5280Profile.policy(now);
/// let _ = verify_chain(
///     &[ca_cert],
///     &anchors,
///     &policy,
///     &DefaultVerifier,
///     &NoRevocation,
///     &NoAiaFetcher,
/// )?;
/// # Ok(())
/// # }
/// ```
///
/// # Arguments
///
/// - `chain`      — leaf-first certificate chain; `chain[0]` is the responder cert
/// - `anchors`    — trust anchors; validation succeeds when the chain reaches one
/// - `issuer`     — the CA cert whose status the responder asserts; must DN-match
///   `chain[0]`'s issuer field
/// - `profile`    — profile supplying the [`ValidationPolicy`] for `now_unix`;
///   typically [`pkix_profiles::BasicOcspResponderProfile`]
/// - `now_unix`   — current time, seconds since the Unix epoch
/// - `verifier`   — signature verification backend ([`DefaultVerifier`] for standard algorithms)
/// - `revocation` — revocation checker (use [`NoRevocation`] for offline);
///   bypassed for `chain[0]` when the responder cert carries
///   `id-pkix-ocsp-nocheck`
/// - `aia`        — AIA fetcher (use [`NoAiaFetcher`] when the caller supplies the full chain)
///
/// # Errors
///
/// - [`Error::Path`] — RFC 5280 path validation failed (including the
///   profile's `id-kp-OCSPSigning` EKU presence check).
/// - [`Error::Revocation`] — a cert in the chain other than `chain[0]`
///   was revoked, or `chain[0]` was revoked without the
///   `id-pkix-ocsp-nocheck` extension being present.
/// - [`Error::OcspDelegation`] — the responder cert was not delegated
///   by the supplied `issuer`. Two failure modes: (a) the responder
///   cert's issuer DN does not match `issuer.subject`, or (b) the
///   responder cert's signature does not verify under `issuer`'s SPKI.
///   The cryptographic binding (b) is required by RFC 6960 §4.2.2.2 —
///   DN equality alone admits a DN-twin attack in cross-signed
///   topologies.
#[allow(clippy::too_many_arguments)]
pub fn verify_ocsp_responder<V, P, R, A>(
    chain: &[Certificate],
    anchors: &[TrustAnchor],
    issuer: &Certificate,
    profile: &P,
    now_unix: u64,
    verifier: &V,
    revocation: &R,
    aia: &A,
) -> crate::Result<ValidatedPath>
where
    V: SignatureVerifier,
    P: Profile,
    R: RevocationChecker,
    A: AiaFetcher,
{
    if chain.is_empty() {
        return Err(Error::OcspDelegation {
            reason: Cow::Borrowed("OCSP responder chain must contain at least the responder cert"),
        });
    }

    // RFC 6960 §4.2.2.2.1: if chain[0] carries id-pkix-ocsp-nocheck, the
    // responder cert itself MUST NOT be revocation-checked (otherwise a
    // recursive OCSP loop is required).
    let bypass_revocation_on_leaf = has_ocsp_no_check(&chain[0]);
    let shim = NoCheckShim {
        inner: revocation,
        leaf_id: if bypass_revocation_on_leaf {
            Some(LeafIdent::of(&chain[0]))
        } else {
            None
        },
    };

    let policy = profile.policy(now_unix);
    let validated = verify_chain(chain, anchors, &policy, verifier, &shim, aia)?;

    verify_responder_is_delegated_by(&chain[0], issuer)?;

    Ok(validated)
}

/// RFC 6960 §4.2.2.2: enforce that the responder cert at `chain[0]` is
/// delegated by `issuer`.
///
/// Two checks, in order:
///
/// 1. The responder cert's issuer DN must equal the issuer cert's
///    subject DN under RFC 4518 string prep. This is a cheap early
///    rejection — a responder whose name does not even claim to be
///    delegated by `issuer` is rejected without a signature op.
///
/// 2. The responder cert's signature must verify under `issuer`'s
///    SPKI over the responder's `TBSCertificate` bytes. This is the
///    cryptographic binding required by RFC 6960 §4.2.2.2 ("This
///    certificate MUST be issued directly by the CA that is identified
///    in the request").
///
/// DN equality alone is insufficient: in cross-signed CA topologies
/// (e.g. an intermediate cross-signed by two roots) two distinct CAs
/// can share an issuer DN, and an attacker who controls one such CA
/// can mint a responder cert that DN-matches the legitimate
/// `issuer` but is signed by a different key. Without the
/// cryptographic check, such a responder would be accepted as
/// delegated by `issuer` — giving the caller a confident "this
/// responder speaks for issuer X" answer when in fact it speaks for
/// issuer-DN-twin Y.
///
/// The signature verifier is [`DefaultVerifier`], matching the rest
/// of [`verify_ocsp_responder`]. If `issuer`'s SPKI uses an algorithm
/// not covered by [`DefaultVerifier`], the binding check surfaces as
/// [`Error::OcspDelegation`] — callers needing custom algorithms must
/// drop down to [`verify_chain`] and replicate the delegation check
/// against their own verifier.
fn verify_responder_is_delegated_by(
    responder: &Certificate,
    issuer: &Certificate,
) -> crate::Result<()> {
    use spki::der::referenced::OwnedToRef as _;

    // 1. Cheap DN gate.
    if !pkix_path::names_match(
        responder.tbs_certificate().issuer(),
        issuer.tbs_certificate().subject(),
    ) {
        return Err(Error::OcspDelegation {
            reason: Cow::Borrowed(
                "OCSP responder cert issuer DN does not match the supplied issuer's subject DN \
                 (RFC 6960 §4.2.2.2 delegation requirement)",
            ),
        });
    }

    // 2. Cryptographic binding: responder.signature must verify under
    //    issuer.spki over responder.tbs_certificate (re-encoded by
    //    `pkix_path::tbs_certificate_der`, which keeps validity times as
    //    parsed). This is the spec-correct delegation check; DN equality
    //    alone admits a DN-twin attack in cross-signed topologies.
    let tbs_der = pkix_path::tbs_certificate_der(responder).map_err(|_| Error::OcspDelegation {
        reason: Cow::Borrowed(
            "OCSP responder cert TBSCertificate re-encoding failed \
                 (cannot verify delegation signature)",
        ),
    })?;
    DefaultVerifier
        .verify_signature(
            responder.signature_algorithm().owned_to_ref(),
            issuer
                .tbs_certificate()
                .subject_public_key_info()
                .owned_to_ref(),
            &tbs_der,
            responder.signature().raw_bytes(),
        )
        .map_err(|_| Error::OcspDelegation {
            reason: Cow::Borrowed(
                "OCSP responder cert signature does not verify under the supplied issuer's \
                 public key (RFC 6960 §4.2.2.2: responder must be issued directly by the \
                 named CA — DN match without cryptographic binding is insufficient)",
            ),
        })?;
    Ok(())
}

/// Return `true` iff `cert` carries the `id-pkix-ocsp-nocheck`
/// extension (OID 1.3.6.1.5.5.7.48.1.5, RFC 6960 §4.2.2.2.1).
///
/// The extension is informational and carries no payload (DER `NULL`
/// is permitted by some implementations, empty `OCTET STRING` value is
/// the spec-compliant encoding). Presence alone is the signal; this
/// helper does not parse the value.
fn has_ocsp_no_check(cert: &Certificate) -> bool {
    const OID_OCSP_NO_CHECK: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.5");

    cert.tbs_certificate()
        .extensions()
        .is_some_and(|exts| exts.iter().any(|e| e.extn_id == OID_OCSP_NO_CHECK))
}

/// Stable identifier for the OCSP responder leaf cert, used by
/// [`NoCheckShim`] to recognize "this is the cert we should bypass
/// revocation on" inside the [`RevocationChecker`] callback.
///
/// The trait receives `&Certificate` without a chain index, so the
/// shim has to identify the leaf by content. RFC 5280 §4.1.2.2
/// requires the (issuer DN, serial number) pair to uniquely identify a
/// certificate within an issuer's scope, which is the strongest
/// stability guarantee available here without re-serializing the cert
/// to DER. The pair is compared via cheap derived equality on the
/// already-parsed `x509-cert` fields.
#[derive(Debug, Clone)]
struct LeafIdent<'a> {
    issuer: &'a x509_cert::name::Name,
    serial: &'a x509_cert::serial_number::SerialNumber,
}

impl<'a> LeafIdent<'a> {
    fn of(cert: &'a Certificate) -> Self {
        Self {
            issuer: cert.tbs_certificate().issuer(),
            serial: cert.tbs_certificate().serial_number(),
        }
    }

    fn matches(&self, cert: &Certificate) -> bool {
        // Byte-level DER equality via derived `PartialEq`. This is correct
        // here because both sides originate from the same parsed chain, so
        // the DER encoding is identical. This would NOT be correct for
        // cross-origin cert comparison, which requires RFC 4518 DN normalization.
        self.serial == cert.tbs_certificate().serial_number()
            && self.issuer == cert.tbs_certificate().issuer()
    }
}

/// `RevocationChecker` shim that short-circuits the check for the
/// designated OCSP responder leaf cert (RFC 6960 §4.2.2.2.1
/// `id-pkix-ocsp-nocheck`) and delegates every other call to the
/// caller-supplied checker.
///
/// Constructed with `leaf_id = None` to disable the bypass entirely,
/// which keeps the shim's behavior byte-equivalent to the inner
/// checker on chains that do not carry `id-pkix-ocsp-nocheck`.
#[derive(Debug, Clone)]
struct NoCheckShim<'a, R: RevocationChecker> {
    inner: &'a R,
    leaf_id: Option<LeafIdent<'a>>,
}

impl<R: RevocationChecker> RevocationChecker for NoCheckShim<'_, R> {
    fn check_revocation(
        &self,
        cert: &Certificate,
        issuer: &Certificate,
    ) -> pkix_revocation::Result<()> {
        if let Some(leaf) = &self.leaf_id {
            if leaf.matches(cert) {
                return Ok(());
            }
        }
        self.inner.check_revocation(cert, issuer)
    }

    fn check_revocation_against_anchor(
        &self,
        cert: &Certificate,
        anchor: &TrustAnchor,
    ) -> pkix_revocation::Result<()> {
        // A single-cert chain [responder] reaches this method instead of
        // check_revocation. Still honor the nocheck bypass.
        if let Some(leaf) = &self.leaf_id {
            if leaf.matches(cert) {
                return Ok(());
            }
        }
        self.inner.check_revocation_against_anchor(cert, anchor)
    }
}

/// RFC 3161 §2.3: enforce that the TSA certificate's `ExtendedKeyUsage`
/// extension is critical and contains only `id-kp-timeStamping`.
///
/// Returns [`Error::ProfileViolation`] with a fixed reason string on any
/// failure. Treats a missing extension as "not sole" (it cannot be sole
/// if it is not present) — but this case is normally caught earlier by
/// the profile's `required_leaf_eku` check inside `verify_chain`.
fn enforce_timestamping_eku_critical_and_sole(leaf: &Certificate) -> crate::Result<()> {
    use x509_cert::der::Decode as _;
    use x509_cert::ext::pkix::ExtendedKeyUsage;

    const OID_EXTENDED_KEY_USAGE: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("2.5.29.37");
    const ID_KP_TIME_STAMPING: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");

    let exts = leaf
        .tbs_certificate()
        .extensions()
        .ok_or(Error::ProfileViolation {
            reason: Cow::Borrowed("TSA certificate has no ExtendedKeyUsage extension"),
        })?;
    let ext = exts
        .iter()
        .find(|e| e.extn_id == OID_EXTENDED_KEY_USAGE)
        .ok_or(Error::ProfileViolation {
            reason: Cow::Borrowed("TSA certificate has no ExtendedKeyUsage extension"),
        })?;

    if !ext.critical {
        return Err(Error::ProfileViolation {
            reason: Cow::Borrowed(
                "TSA ExtendedKeyUsage extension must be marked critical (RFC 3161 §2.3)",
            ),
        });
    }

    let eku = ExtendedKeyUsage::from_der(ext.extn_value.as_bytes()).map_err(|_| {
        Error::ProfileViolation {
            reason: Cow::Borrowed("TSA ExtendedKeyUsage extension is malformed"),
        }
    })?;

    // RFC 3161 §2.3: timeStamping MUST be the sole EKU value.
    match eku.0.as_slice() {
        [oid] if *oid == ID_KP_TIME_STAMPING => Ok(()),
        [_] => Err(Error::ProfileViolation {
            reason: Cow::Borrowed(
                "TSA ExtendedKeyUsage must contain only id-kp-timeStamping (RFC 3161 §2.3)",
            ),
        }),
        _ => Err(Error::ProfileViolation {
            reason: Cow::Borrowed(
                "TSA ExtendedKeyUsage must contain only id-kp-timeStamping (RFC 3161 §2.3)",
            ),
        }),
    }
}

/// Enforce the RFC 3161 §2.1 (#10) "key generated exclusively for this
/// purpose" `KeyUsage` shape on a TSA certificate.
///
/// RFC 3161 §2.1 requires the TSA to "sign each time-stamp token using a
/// key generated exclusively for this purpose and have this property of
/// the key indicated on the corresponding certificate." A signing-only
/// key is reflected in `KeyUsage` by setting `digitalSignature` and/or
/// `nonRepudiation` (a.k.a. `contentCommitment`) and **no other** bits.
/// Any of `keyEncipherment`, `dataEncipherment`, `keyAgreement`,
/// `keyCertSign`, `cRLSign`, `encipherOnly`, or `decipherOnly` indicates
/// a key reused for non-signing purposes and is forbidden.
///
/// This is OpenSSL's `-purpose timestampsign` interpretation; it is a
/// stricter reading than the literal text of RFC 3161 §2.3 (which speaks
/// only of the EKU). The workspace adopts it on the strength of §2.1
/// (#10) and the consistent practice of OpenSSL and ETSI EN 319 422.
///
/// `KeyUsage` is **not** mandatory on EE certs per RFC 5280 §4.2.1.3
/// (it is "RECOMMENDED to be critical when present"). A TSA cert with
/// no `KeyUsage` extension passes this check — there are no forbidden
/// bits to find. This matches OpenSSL's behaviour empirically.
///
/// Returns [`Error::ProfileViolation`] with a fixed reason string when
/// the extension is present and carries any forbidden bit, or when the
/// extension value fails to decode.
fn enforce_timestamping_ku_shape(leaf: &Certificate) -> crate::Result<()> {
    use x509_cert::der::Decode as _;
    use x509_cert::ext::pkix::KeyUsage;

    const OID_KEY_USAGE: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("2.5.29.15");

    let Some(exts) = leaf.tbs_certificate().extensions() else {
        // No extensions at all → no KeyUsage → no constraint to violate.
        return Ok(());
    };
    let Some(ext) = exts.iter().find(|e| e.extn_id == OID_KEY_USAGE) else {
        // KeyUsage absent → no constraint to violate.
        return Ok(());
    };

    let ku =
        KeyUsage::from_der(ext.extn_value.as_bytes()).map_err(|_| Error::ProfileViolation {
            reason: Cow::Borrowed("TSA KeyUsage extension is malformed"),
        })?;

    // A TSA's key is signing-only. digitalSignature and nonRepudiation
    // (contentCommitment) are the two permitted bits; every other bit
    // indicates reuse for non-signing purposes and is rejected.
    if ku.key_encipherment()
        || ku.data_encipherment()
        || ku.key_agreement()
        || ku.key_cert_sign()
        || ku.crl_sign()
        || ku.encipher_only()
        || ku.decipher_only()
    {
        return Err(Error::ProfileViolation {
            reason: Cow::Borrowed(
                "TSA KeyUsage must contain only digitalSignature and/or nonRepudiation \
                 (RFC 3161 §2.1 #10; matches OpenSSL `-purpose timestampsign`)",
            ),
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Send + Sync compile-time assertions (AGENTS.md non-negotiable #6, PKIX-2l0v.2)
// ---------------------------------------------------------------------------

const _: fn() = || {
    fn _assert_send_sync<T: Send + Sync>() {}
    _assert_send_sync::<Error>();
};

/// `pkix_path::Error` variants that may be repairable by adding more
/// candidate intermediates to the path-builder pool.
///
/// `ChainBroken { index }` is the classic "missing intermediate" signal:
/// `chain[index].issuer` did not equal `chain[index + 1].subject`.
/// `NoTrustedPath` says the top of the chain does not match any anchor;
/// an AIA fetch on the topmost cert may produce a parent that does.
/// `SignatureInvalid { index }` is included because a wrong-but-DN-matching
/// intermediate in the pool can be displaced by a correctly-signed
/// alternative fetched via AIA; `SignatureNotVerified` likewise, since a
/// cross-certificate with a supported algorithm may exist.
/// `PathTooLong` is included because pkix-path rejects an over-long input
/// before looking at it; an unordered bag with extra certificates (an
/// S/MIME `SignedData.certificates` set, for example) can still contain a
/// valid path, which the budgeted path builder finds.
///
/// All other variants (`ValidityPeriod`, `KeyUsageMissing`,
/// `NameConstraintViolation`, `PolicyViolation`, `Der`, …) describe
/// cert-level defects that the chain-build seam cannot fix by adding more
/// certs, so they are propagated directly without ever invoking the
/// `AiaFetcher`.
fn is_aia_recoverable(e: &pkix_path::Error) -> bool {
    matches!(
        e,
        pkix_path::Error::ChainBroken { .. }
            | pkix_path::Error::NoTrustedPath
            | pkix_path::Error::SignatureInvalid { .. }
            | pkix_path::Error::SignatureNotVerified { .. }
            | pkix_path::Error::PathTooLong
    )
}

/// Does `child`'s signature verify under `issuer_spki`?
fn signed_by<V: SignatureVerifier>(
    child: &Certificate,
    issuer_spki: &spki::SubjectPublicKeyInfoOwned,
    verifier: &V,
) -> bool {
    use spki::der::referenced::OwnedToRef as _;
    let Ok(tbs) = pkix_path::tbs_certificate_der(child) else {
        return false;
    };
    verifier
        .verify_signature(
            child.signature_algorithm().owned_to_ref(),
            issuer_spki.owned_to_ref(),
            &tbs,
            child.signature().raw_bytes(),
        )
        .is_ok()
}

/// The certificates whose caIssuers URIs [`Verifier::build_with_aia`]
/// may follow: certs on a potential path from `leaf` whose issuer is not
/// yet available.
///
/// Walks from `leaf` through issuer links: a pool CA cert is an issuer of
/// `cur` when its subject matches `cur`'s issuer under RFC 4518 string
/// prep **and** its key verifies `cur`'s signature (so a same-name decoy
/// can neither stand in for the missing issuer and suppress the fetch,
/// nor pull its own URIs into the fetch set). A cert with no such pool
/// issuer and no anchor whose name matches and whose key verifies it is
/// an orphan. Certs unreachable from the leaf (e.g. unrelated certs in a
/// CMS bag, or junk added by an earlier fetch) are never asked for URIs.
fn orphans_on_paths<'p, V: SignatureVerifier>(
    leaf: &'p Certificate,
    pool: &'p pkix_path_builder::CertPool,
    anchors: &[TrustAnchor],
    verifier: &V,
) -> Vec<&'p Certificate> {
    let certs: Vec<&Certificate> = pool.iter().collect();
    let mut visited = vec![false; certs.len()];
    let mut queue: Vec<&Certificate> = vec![leaf];
    let mut orphans = Vec::new();
    while let Some(cur) = queue.pop() {
        let issuer = cur.tbs_certificate().issuer();
        let anchored = anchors.iter().any(|a| {
            pkix_path::names_match(&a.subject, issuer)
                && signed_by(cur, &a.subject_public_key_info, verifier)
        });
        let mut has_pool_issuer = false;
        for (idx, cand) in certs.iter().enumerate() {
            if *cand == cur
                || !pkix_path::names_match(cand.tbs_certificate().subject(), issuer)
                || !pkix_path::cert_is_ca(cand).unwrap_or(false)
                || !signed_by(
                    cur,
                    cand.tbs_certificate().subject_public_key_info(),
                    verifier,
                )
            {
                continue;
            }
            has_pool_issuer = true;
            if !visited[idx] {
                visited[idx] = true;
                queue.push(cand);
            }
        }
        if !anchored && !has_pool_issuer {
            orphans.push(cur);
        }
    }
    orphans
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Confirm `DefaultVerifier` re-export is the same type as `pkix_path::DefaultVerifier`.
    /// A function that accepts `DefaultVerifier` (crate re-export) must also accept
    /// `pkix_path::DefaultVerifier` — the compiler will enforce type identity.
    #[test]
    fn default_verifier_reexport_type_identity() {
        fn accepts(_v: DefaultVerifier) {}
        let v: pkix_path::DefaultVerifier = DefaultVerifier;
        accepts(v);
    }

    /// `Error::Identity` Display delegates to the inner `IdentityError`'s
    /// Display, prefixed with `"identity binding: "`. This test pins the
    /// behaviour so the prefix doesn't drift silently across refactors.
    #[test]
    fn error_identity_display_includes_prefix_and_inner() {
        let err = Error::Identity(IdentityError::NoMatchingSan);
        let rendered = format!("{err}");
        assert!(
            rendered.starts_with("identity binding: "),
            "expected `identity binding: ` prefix, got: {rendered:?}"
        );
        assert!(
            rendered.contains("no Subject Alternative Name entry matched the identity"),
            "expected inner IdentityError Display text, got: {rendered:?}"
        );
    }

    /// Every `Error` variant must produce non-empty Display output. Guards
    /// against accidentally adding a variant whose match arm forgets to
    /// write anything to the formatter.
    #[test]
    fn error_display_all_variants_non_empty() {
        // Constructing one instance of each variant covers the Error
        // arms; if a new top-level variant is added without updating
        // this list, the new variant will not be exercised here — but
        // both source enums are non_exhaustive so adding a new variant
        // is itself a soft signal to revisit Display coverage.
        let path_err = pkix_path::Error::NoTrustedPath;
        let revoc_err = pkix_revocation::Error::CrlExpired;
        let cases: &[Error] = &[
            Error::Path(path_err),
            Error::Revocation(revoc_err),
            Error::Identity(IdentityError::MissingSan),
            Error::Identity(IdentityError::MalformedSan),
            Error::Identity(IdentityError::MalformedInput),
            Error::ProfileViolation {
                reason: Cow::Borrowed("test violation"),
            },
            Error::OcspDelegation {
                reason: Cow::Borrowed("test delegation failure"),
            },
        ];
        for err in cases {
            let s = format!("{err}");
            assert!(!s.is_empty(), "Display produced empty string for {err:?}");
        }
    }

    /// `Error::source()` returns the wrapped error so callers can walk the
    /// chain with `std::error::Error::source`. Pinned for `Error::Identity`
    /// specifically because it was added in PKIX-fmtv.11.2 / .12.2 and the
    /// pattern is easy to forget.
    #[test]
    fn error_identity_source_returns_inner() {
        use std::error::Error as _;
        let err = Error::Identity(IdentityError::NoMatchingSan);
        let src = err.source().expect("Error::Identity must report a source");
        // Source's Display should match IdentityError's Display.
        assert_eq!(
            format!("{src}"),
            format!("{}", IdentityError::NoMatchingSan)
        );
    }
}
