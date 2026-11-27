#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
// `verify_attribute_cert` and the pkix_ac types it names only exist
// behind `attribute-certs`, and the crate docs link to them. With the
// feature off those items are gone, so a default-feature rustdoc run
// cannot resolve the links.
//
// Allowed only in that configuration, which loses no signal: a mistyped
// link is broken with the feature on too, and the quality gate's
// all-features doc build runs under RUSTDOCFLAGS=-D warnings. Same shape
// and same reasoning as the attributes in pkix-path, pkix-ct and
// pkix-revocation-http — docs.rs builds all features, so demoting these
// to code spans would cost every reader a working link to spare a
// configuration nobody publishes documentation from.
#![cfg_attr(
    not(feature = "attribute-certs"),
    allow(rustdoc::broken_intra_doc_links)
)]

//! High-level X.509 certificate chain verification.
//!
//! Combines [`pkix_path`] (signature validation, RFC 5280 §6) with
//! [`pkix_revocation`] (CRL/OCSP) into a single ergonomic API.
//!
//! For fine-grained control — custom backends, per-cert revocation policy,
//! `no_std` constraints — use the component crates directly.
//!
//! **`std` only.** This crate depends on `pkix-path/std` and
//! `pkix-revocation/std`. For `no_std` validation, use [`pkix_path`] directly
//! with a `no_std` `SignatureVerifier`.
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
//!   [`AiaConfig`] (URIs per cert, total fetches, deadline). With
//!   [`NoAiaFetcher`] the first fetch returns
//!   [`AiaError::FetchingDisabled`] and the verifier surfaces
//!   [`Error::Aia`] without performing any I/O.
//! - **Revocation is caller-supplied.** Online CRL / OCSP fetching is
//!   handled by `pkix-revocation-http`; this crate accepts any
//!   `RevocationChecker` impl — including `NoRevocation` for the
//!   zero-cost "I'll handle revocation myself" path.
//! - **Algorithm coverage tracks `pkix-path`.** The default feature set
//!   wires in RustCrypto backends for RSA — PKCS#1 v1.5 and RSASSA-PSS
//!   with SHA-256/384/512 — and ECDSA on P-256. The optional `p384`,
//!   `p521` and `ed25519` features add ECDSA on P-384 and P-521 and
//!   Ed25519; `rustcrypto` enables all of them.
//! - **Use-case wrappers.** `verify_tls_server`,
//!   `verify_tls_client_dns`, `verify_tls_client_mailbox`,
//!   `verify_smime_signer`, `verify_smime_recipient`, `verify_code_signer`,
//!   `verify_time_stamper`, and `verify_ocsp_responder` compose chain
//!   validation with the matching `pkix-identity` binding and
//!   `pkix-profiles` EKU rules, each taking the same `A: AiaFetcher`
//!   parameter as [`Verifier`].
//! - **Composed capabilities.** The mechanism for each lives in its own
//!   crate and the composition lives here, because composing is where
//!   the trust decisions are. DANE TLSA matching is on by default via
//!   the `dane` feature over `pkix-dane`; RFC 5755 attribute
//!   certificates come with `attribute-certs` over `pkix-ac`, through
//!   [`verify_attribute_cert`]. CT-anchored validation is not composed
//!   here and lives in `pkix-ct`.

// Upstream vocabulary, re-exported by name.
//
// This crate shares `pkix-path`'s types rather than wrapping them: every
// public entry point here takes a `TrustAnchor`, a `ValidationPolicy` and
// a `Profile`, so a caller holds those types whether or not this module
// re-exports them. Naming them is a convenience, and a deliberate,
// enumerable commitment.
//
// The lists used to include `self` — `pub use pkix_path::{self, ...}` —
// which republished each upstream crate's *entire* surface under
// `pkix_chain::`. That is a different and much larger promise: a caller
// could reach `pkix_chain::pkix_revocation::ocsp::OcspResponse`, so any
// rename anywhere in an upstream crate became a breaking change here,
// including to types this crate never consumes. The commitment is now
// what is written below and nothing more. A caller who wants the whole
// of an upstream crate should depend on it directly, which is honest
// about what they are coupling to.
//
// The three upstream error types are aliased because `Error` is taken
// three times over, and by this crate's own `Error` as well.
// `pkix-chain-simple` already names `pkix_path::Error as PathError` for
// the same reason.
// Re-exported for the same reason as the rest of this list:
// `verify_attribute_cert` takes a `&AttributeCertificate` and returns a
// `Targeting`, so without these a consumer cannot call it without adding
// `pkix-ac` to their own manifest and keeping its version in lockstep
// with this crate's.
//
// Both error types are renamed, for the same reason: this crate
// already has a `ProfileViolation` concept, and it is a different one.
// `Error::ProfileViolation { kind }` is a leaf-profile failure carrying
// a `ProfileViolationKind`, so an unrenamed re-export would put two
// public names side by side that look like they belong together and do
// not typecheck together.
//
// The error types come too. An earlier version re-exported only the two
// argument types, which left a consumer able to call the function and
// unable to match `Error::AttributeCert` — the one useful thing to do
// with what it returns. Every neighbouring re-export in this list
// includes its error type, and leaving these out broke that convention
// silently.
#[cfg(feature = "attribute-certs")]
#[cfg_attr(docsrs, doc(cfg(feature = "attribute-certs")))]
pub use pkix_ac::{
    AcRevocation, AttributeCertificate, Error as AttributeCertError,
    ProfileViolation as AttributeCertProfileViolation, Targeting,
};
pub use pkix_aia::{AiaError, AiaFetcher, NoAiaFetcher};
pub use pkix_identity::{IdentityError, MailboxName, ServerName};
pub use pkix_path::{
    DefaultVerifier, Error as PathError, Profile, SignatureVerifier, TrustAnchor, ValidatedPath,
    ValidationPolicy, VerificationError, VerificationErrorKind,
};
pub use pkix_path_builder::{CertPool, Error as PathBuildError};
#[cfg(feature = "crl")]
#[cfg_attr(docsrs, doc(cfg(feature = "crl")))]
pub use pkix_revocation::CrlChecker;
#[cfg(feature = "ocsp")]
#[cfg_attr(docsrs, doc(cfg(feature = "ocsp")))]
pub use pkix_revocation::OcspChecker;
pub use pkix_revocation::{
    Error as RevocationError, NoRevocation, Result as RevocationResult, RevocationChecker,
};

use x509_cert::Certificate;

mod aia_extract;
mod aia_response;

/// Maximum number of AIA-fetch rounds performed during chain reassembly.
///
/// Each round calls [`AiaFetcher::batch_fetch`] on the caIssuers URIs of
/// the certificates whose issuers are missing from the working cert pool,
/// then re-runs [`pkix_path_builder::build_first_valid_path`]. Without a cap,
/// a fetched intermediate that itself references a missing issuer (etc.)
/// would loop indefinitely. The cap stops the loop and surfaces
/// [`Error::AiaDepthExceeded`].
///
/// # What the number counts
///
/// Hops resolved, not rounds paid for. A chain whose every intermediate is
/// discoverable only from the caIssuers URI of the certificate below it
/// needs one round per intermediate, and a cap of `N` resolves exactly `N`
/// of them: the reassembly loop makes one more build attempt after its
/// last fetch, so the certificates that round brought in are consulted
/// rather than fetched and discarded. A chain needing `N + 1` fails with
/// [`Error::AiaDepthExceeded`]. Both ends of that boundary are tested.
///
/// # Why five
///
/// It is generous for real-world PKIs. A cross-signed root adds at most
/// one hop beyond the operating CA's own intermediate, so two or three is
/// the realistic maximum; an intermediate-of-an-intermediate-of-an-
/// intermediate is already unusual. Five leaves room for an unusual
/// hierarchy without letting a certificate chain of attacker-chosen depth
/// drive unbounded fetching.
///
/// This is the default for [`AiaConfig::max_depth`].
pub const AIA_MAX_DEPTH: usize = 5;

/// Default ceiling on the bytes of one caIssuers response that
/// `pkix-chain` will decode — [`AiaConfig::max_response_bytes`].
///
/// 256 KiB. Sized for a certs-only CMS bundle, not a single
/// certificate: this limit also covers a response carrying up to
/// [`AiaConfig::max_certs_per_response`] certificates (16 by default),
/// and a pathological certificate with many SANs reaches 16 KiB, so a
/// per-certificate ceiling would sit on top of legitimate traffic. A
/// typical single certificate is 1–4 KiB, a typical bundle under 16 KiB.
///
/// This is defence in depth, not the primary control. A transport
/// adapter caps the body as it reads it — `pkix-aia-http` does, and
/// reports [`pkix_aia::AiaError::ResponseTooLarge`] — which is the right
/// place, because it can stop reading. This limit exists because that
/// cap lives in an adapter and is per-fetcher configuration: a
/// caller-supplied fetcher, a cache wrapper, or a different transport
/// can simply not have one, and then nothing would bound what gets
/// handed to the DER parser.
pub const AIA_MAX_RESPONSE_BYTES: usize = 256 * 1024;

/// `serde(default)` for [`AiaConfig::max_response_bytes`]. A function
/// rather than `Default::default()` because the fail-safe value is the
/// documented cap, not zero — which would refuse every response.
#[cfg(feature = "serde")]
const fn default_max_response_bytes() -> usize {
    AIA_MAX_RESPONSE_BYTES
}

// DANE composition. Gated on `dane`, which is default-on: the gate pulls
// only the no_std pkix-dane crate, so the API surface costs a consumer
// nothing until they also enable `dane-resolver`.
// I/O-free core of chain verification. Public: it is how a caller on any
// runtime drives verification while owning every fetch itself.
pub mod sans_io;

#[cfg(feature = "dane")]
#[cfg_attr(docsrs, doc(cfg(feature = "dane")))]
pub mod dane;

#[cfg(feature = "dane")]
#[cfg_attr(docsrs, doc(cfg(feature = "dane")))]
pub mod smtp;

#[cfg(feature = "dane")]
#[cfg_attr(docsrs, doc(cfg(feature = "dane")))]
pub use dane::{verify_tls_server_dane, DaneConfig, DaneFailurePolicy, TlsAuthorization};

#[cfg(feature = "dane")]
#[cfg_attr(docsrs, doc(cfg(feature = "dane")))]
pub use smtp::{verify_smtp_server_dane, SmtpDaneFailure, SmtpDaneVerdict};

#[cfg(feature = "mta-sts")]
#[cfg_attr(docsrs, doc(cfg(feature = "mta-sts")))]
pub use smtp::{combine_smtp_transport_security, SmtpTransportDenial, SmtpTransportSecurity};

/// DNSSEC-validating TLSA resolution, re-exported under the
/// `dane-resolver` feature.
///
/// Re-exported rather than left as a dependency a consumer adds separately,
/// so that enabling `dane-resolver` is sufficient to obtain a resolver and
/// the version this crate was built against cannot drift from the one the
/// consumer picks.
#[cfg(feature = "dane-resolver")]
#[cfg_attr(docsrs, doc(cfg(feature = "dane-resolver")))]
pub use pkix_dane_resolver as dane_resolver;

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
    /// Maximum bytes of one caIssuers response that will be decoded.
    /// A larger response is refused with
    /// [`pkix_aia::AiaError::ResponseTooLarge`] before any parsing.
    /// Default: [`AIA_MAX_RESPONSE_BYTES`].
    ///
    /// Defence in depth behind the fetcher's own body cap — see
    /// [`AIA_MAX_RESPONSE_BYTES`] for why both exist.
    ///
    /// `#[serde(default)]` so an `AiaConfig` serialised before this
    /// field existed still deserialises, rather than failing with
    /// "missing field". The default is the fail-safe value, so an older
    /// stored config loads with the cap on rather than off.
    #[cfg_attr(feature = "serde", serde(default = "default_max_response_bytes"))]
    pub max_response_bytes: usize,
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
            max_response_bytes: AIA_MAX_RESPONSE_BYTES,
            deadline: Some(std::time::Duration::from_secs(30)),
        }
    }
}

impl Default for AiaConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Which profile invariant a certificate failed.
///
/// Replaces the fixed string [`Error::ProfileViolation`] used to carry.
/// That string was documented as "not parsed by the engine; pattern-match
/// on the variant rather than the inner string", which was honest about
/// the constraint and left callers with one bit of information — that
/// *some* profile rule was broken — for what is a many-way
/// classification. These are the ways.
///
/// Every variant today is an RFC 3161 time-stamping rule, because that is
/// the only profile with post-validation checks in this crate. The enum
/// is `#[non_exhaustive]` so other profiles can be added without a
/// breaking change; match with a `_` arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum ProfileViolationKind {
    /// RFC 3161 §2.3: the TSA certificate carries no `ExtendedKeyUsage`.
    TsaEkuMissing,
    /// RFC 3161 §2.3: `ExtendedKeyUsage` is present but not critical.
    TsaEkuNotCritical,
    /// The `ExtendedKeyUsage` extension could not be decoded.
    TsaEkuMalformed,
    /// RFC 3161 §2.3: `ExtendedKeyUsage` must contain `id-kp-timeStamping`
    /// and nothing else.
    TsaEkuNotSoleTimeStamping,
    /// The `KeyUsage` extension could not be decoded.
    TsaKeyUsageMalformed,
    /// RFC 3161 §2.1: `KeyUsage` must contain only `digitalSignature`
    /// and/or `nonRepudiation`.
    TsaKeyUsageNotSigningOnly,
}

impl core::fmt::Display for ProfileViolationKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::TsaEkuMissing => "TSA certificate has no ExtendedKeyUsage extension",
            Self::TsaEkuNotCritical => {
                "TSA ExtendedKeyUsage extension must be marked critical (RFC 3161 §2.3)"
            }
            Self::TsaEkuMalformed => "TSA ExtendedKeyUsage extension is malformed",
            Self::TsaEkuNotSoleTimeStamping => {
                "TSA ExtendedKeyUsage must contain only id-kp-timeStamping (RFC 3161 §2.3)"
            }
            Self::TsaKeyUsageMalformed => "TSA KeyUsage extension is malformed",
            Self::TsaKeyUsageNotSigningOnly => {
                "TSA KeyUsage must contain only digitalSignature and/or nonRepudiation \
                 (RFC 3161 §2.1 #10; matches OpenSSL `-purpose timestampsign`)"
            }
        };
        f.write_str(s)
    }
}

/// Which RFC 6960 §4.2.2.2 delegation requirement an OCSP responder
/// certificate failed.
///
/// Replaces the fixed string [`Error::OcspDelegation`] used to carry, for
/// the same reason as [`ProfileViolationKind`]. The distinction that
/// matters most here is the last two: a DN that does not match is a
/// configuration error, while a DN that matches whose signature does not
/// verify is the DN-twin attack the binding exists to detect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum OcspDelegationKind {
    /// The supplied chain was empty, so there is no responder certificate.
    EmptyChain,
    /// RFC 6960 §4.2.2.2: the responder certificate's issuer DN does not
    /// match the supplied issuer's subject DN.
    IssuerDnMismatch,
    /// The responder certificate's `TBSCertificate` could not be
    /// re-encoded, so the delegation signature cannot be checked.
    TbsReencodeFailed,
    /// The responder certificate's signature does not verify under the
    /// supplied issuer's key.
    ///
    /// Distinct from [`IssuerDnMismatch`](Self::IssuerDnMismatch): the
    /// names agree and the cryptography does not, which is what a
    /// cross-signed DN twin looks like.
    SignatureNotVerified,
}

impl core::fmt::Display for OcspDelegationKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::EmptyChain => "OCSP responder chain must contain at least the responder cert",
            Self::IssuerDnMismatch => {
                "OCSP responder cert issuer DN does not match the supplied issuer's subject DN \
                 (RFC 6960 §4.2.2.2 delegation requirement)"
            }
            Self::TbsReencodeFailed => {
                "OCSP responder cert TBSCertificate re-encoding failed \
                 (cannot verify delegation signature)"
            }
            Self::SignatureNotVerified => {
                "OCSP responder cert signature does not verify under the supplied issuer's key \
                 — DN match without cryptographic binding is insufficient"
            }
        };
        f.write_str(s)
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
    /// RFC 5755 attribute certificate validation failed.
    ///
    /// Only produced by [`verify_attribute_cert`]. Carries the
    /// `pkix-ac` error, which names the rule. See that function's
    /// `# Errors` section rather than a list here — the list this doc
    /// used to carry went stale as rules were added, missing
    /// [`pkix_ac::Error::NotATarget`],
    /// [`SignatureAlgorithmMismatch`](pkix_ac::Error::SignatureAlgorithmMismatch)
    /// and
    /// [`UnsupportedCriticalExtension`](pkix_ac::Error::UnsupportedCriticalExtension).
    #[cfg(feature = "attribute-certs")]
    #[cfg_attr(docsrs, doc(cfg(feature = "attribute-certs")))]
    AttributeCert(pkix_ac::Error),
    /// A wrapper-side post-validation profile check failed.
    ///
    /// Used by use-case wrappers for spec-mandated invariants that the
    /// lower-level [`ValidationPolicy`] cannot express directly — for
    /// example, RFC 3161 §2.3's requirement that a TSA certificate's
    /// `ExtendedKeyUsage` extension be marked critical and contain only
    /// `id-kp-timeStamping`.
    ///
    /// `kind` says which invariant was broken, so it can be matched on.
    /// Construct with [`Error::profile_violation`].
    #[non_exhaustive]
    ProfileViolation {
        /// Which profile invariant was violated.
        kind: ProfileViolationKind,
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
    /// `kind` says which delegation requirement was broken, so it can be
    /// matched on. Construct with [`Error::ocsp_delegation`].
    #[non_exhaustive]
    OcspDelegation {
        /// Which delegation requirement was violated.
        kind: OcspDelegationKind,
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

impl Error {
    /// Builds [`Error::ProfileViolation`].
    ///
    /// The variant is `#[non_exhaustive]`, so it cannot be constructed
    /// with a struct literal outside this crate. That is deliberate — it
    /// leaves room to add context to the variant later without a breaking
    /// change — and it is why these constructors exist: tests, mocks and
    /// adapters still need to build one.
    #[must_use]
    pub const fn profile_violation(kind: ProfileViolationKind) -> Self {
        Self::ProfileViolation { kind }
    }

    /// Builds [`Error::OcspDelegation`]. See
    /// [`profile_violation`](Self::profile_violation) for why this exists.
    #[must_use]
    pub const fn ocsp_delegation(kind: OcspDelegationKind) -> Self {
        Self::OcspDelegation { kind }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Path(e) => write!(f, "path validation: {e}"),
            Self::Revocation(e) => write!(f, "revocation: {e}"),
            Self::Identity(e) => write!(f, "identity binding: {e}"),
            #[cfg(feature = "attribute-certs")]
            Self::AttributeCert(e) => write!(f, "attribute certificate: {e}"),
            Self::ProfileViolation { kind } => write!(f, "profile violation: {kind}"),
            Self::OcspDelegation { kind } => write!(f, "ocsp responder delegation: {kind}"),
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
            #[cfg(feature = "attribute-certs")]
            Self::AttributeCert(e) => Some(e),
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

#[cfg(feature = "attribute-certs")]
impl From<pkix_ac::Error> for Error {
    fn from(e: pkix_ac::Error) -> Self {
        Self::AttributeCert(e)
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
/// The **default implementation** of `check_revocation_against_anchor`
/// fails with `pkix_revocation::Error::AnchorCheckUnsupported`, so a custom
/// checker that implements only `check_revocation` is told it has a gap
/// rather than silently passing the certificate closest to the root.
/// `NoRevocation` overrides it to skip, because that is its purpose.
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
pub struct Verifier<'a, V, R, A = NoAiaFetcher> {
    anchors: &'a [TrustAnchor],
    sig_verifier: &'a V,
    rev_checker: &'a R,
    policy: &'a ValidationPolicy,
    aia: &'a A,
    aia_config: AiaConfig,
}

/// `Verifier` is a bundle of borrows plus a `Copy` config, so copying one
/// is free and cannot fail.
///
/// Written out rather than derived on purpose. `#[derive(Clone, Copy)]`
/// on a generic struct adds `V: Clone`/`V: Copy` bounds, which would be
/// wrong here: the struct holds `&V`, not `V`, and a shared reference is
/// `Copy` whatever it points at. Deriving would have denied `Copy` to
/// every verifier that is not itself `Copy`, for no reason.
///
/// These impls carry no bounds at all, not even the capability traits.
/// A `Verifier` whose parameters implement nothing is a useless value —
/// there is no way to construct one, since `new` requires the traits —
/// but it is still `Copy`, and saying so keeps the obligation where it
/// belongs: on the constructors and the methods, not on the type.
impl<V, R, A> Clone for Verifier<'_, V, R, A> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<V, R, A> Copy for Verifier<'_, V, R, A> {}

impl<V, R, A> core::fmt::Debug for Verifier<'_, V, R, A> {
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
        // What to check comes from `sans_io::revocation_targets`, so the sync
        // path and a caller driving the checks itself cannot disagree about
        // which certificates need checking.
        for target in crate::sans_io::revocation_targets(chain, self.anchors, validated) {
            match target {
                crate::sans_io::RevocationTarget::Issuer { cert, issuer } => {
                    self.rev_checker.check_revocation(cert, issuer)?;
                }
                // Issued directly by the trust anchor. CrlChecker and
                // OcspChecker override this; NoRevocation inherits the
                // default, which now fails closed.
                crate::sans_io::RevocationTarget::Anchor { cert, anchor } => {
                    self.rev_checker
                        .check_revocation_against_anchor(cert, anchor)?;
                }
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
    /// All of that bookkeeping lives in [`crate::sans_io`], shared with the
    /// async verify path so each bound exists in exactly one place; two
    /// copies of a cap drifting would be a security regression rather than a
    /// maintenance annoyance. What remains here is the loop that performs the
    /// fetches.
    fn build_with_aia(&self, supplied_chain: &[Certificate]) -> crate::Result<Vec<Certificate>> {
        self.chain_builder()
            .build_with(supplied_chain, |uris| self.aia.batch_fetch(uris))
    }

    /// The sans-I/O builder this verifier's configuration describes.
    ///
    /// Exposed so a caller holding a `Verifier` can drive reassembly on its
    /// own runtime rather than through the synchronous `aia` callback.
    #[must_use]
    pub fn chain_builder(&self) -> crate::sans_io::ChainBuilder<'_, V> {
        crate::sans_io::ChainBuilder {
            anchors: self.anchors,
            sig_verifier: self.sig_verifier,
            policy: self.policy,
            config: &self.aia_config,
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
/// **The signer-vs-recipient distinction is not enforced.** This wrapper's
/// body is byte-identical to [`verify_smime_recipient`]; the distinct name
/// lets callers record intent at the call site and nothing more. Passing a
/// recipient-only certificate here, or a signer-only certificate there,
/// returns the same answer either way.
///
/// This paragraph used to say the distinction was "encoded in the
/// caller-supplied `Profile`'s `ValidationPolicy`: signer profiles require
/// KeyUsage `digitalSignature`, recipient profiles require
/// `keyEncipherment`". No profile does that, and more to the point none
/// could: [`pkix_path::ValidationPolicy`] has no field for a required leaf
/// `KeyUsage`. Its `enforce_key_usage` governs `keyCertSign` on
/// intermediates per RFC 5280 §6.1.4(n), and leaf key usage is not checked
/// anywhere in `pkix-path`.
///
/// So a caller who needs RFC 8551 §4.4.2 key-usage separation must check
/// the leaf's `KeyUsage` themselves after this returns. Note that the
/// recipient side is not a single bit: RSA key transport needs
/// `keyEncipherment` while ECDH needs `keyAgreement`, so a check that
/// demands `keyEncipherment` alone rejects every ECDH recipient.
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
/// rustdoc for arguments, ordering, and errors.
///
/// **The two wrappers differ only in name.** The bodies are
/// byte-identical, and no key-usage distinction is applied — see
/// [`verify_smime_signer`] for why `ValidationPolicy` cannot currently
/// express one, and what a caller needing RFC 8551 §4.4.2 separation has
/// to do instead.
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
        return Err(Error::ocsp_delegation(OcspDelegationKind::EmptyChain));
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

    verify_responder_is_delegated_by(&chain[0], issuer, verifier)?;

    Ok(validated)
}

/// What an attribute certificate verification established — RFC 5755 §5.
///
/// Both certification paths are returned because both were validated and
/// a caller may need either: the holder's to know who presented the
/// credential, the authority's to know who granted it.
#[cfg(feature = "attribute-certs")]
#[cfg_attr(docsrs, doc(cfg(feature = "attribute-certs")))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedAttributeCert {
    /// The validated path of the entity that presented the AC.
    pub holder: ValidatedPath,
    /// The validated path of the Attribute Authority that issued it.
    pub authority: ValidatedPath,
    /// How the AC named this verifier — RFC 5755 §4.3.2. Either
    /// [`Untargeted`](pkix_ac::Targeting::Untargeted), meaning it
    /// carries no `targetInformation` and any verifier may use it, or
    /// [`Matched`](pkix_ac::Targeting::Matched). Never
    /// [`NotATarget`](pkix_ac::Targeting::NotATarget): §4.3.2 requires
    /// such an AC to be rejected, so it arrives as an error instead.
    pub targeting: pkix_ac::Targeting,
}

/// Verify an RFC 5755 attribute certificate, end to end.
///
/// This is the composition `pkix-ac` deliberately does not do: that
/// crate takes no trust anchors and validates no certification path, so
/// on its own it will happily check a signature against whatever
/// authority certificate it is handed. Here both paths are validated
/// first, which is what makes the answer mean anything.
///
/// # What is checked, against RFC 5755 §5
///
/// In the order it happens, which is not RFC 5755's numbering — an
/// earlier version of this list used the numbering and so put the
/// targeting check three steps from where it runs:
///
/// 1. **Rule 1** — the holder's certificate path. `holder_chain[0]` is
///    the entity presenting the AC, and its whole path is validated.
/// 2. **Rule 2, path half** — the authority's certificate path.
///    `aa_chain[0]` is the Attribute Authority.
///
/// The rest is [`pkix_ac::AttributeCertificate::validate`], which this
/// calls rather than repeating:
///
/// 3. **Rule 3** — §4.5's profile on the authority's own certificate.
///    This is where a CA is refused as an authority.
/// 4. **Rule 7**, with the §4.2 and §4.3 profile — unsupported critical
///    extensions among them.
/// 5. **Rule 2, signature half**, with §4.2.8 and **rule 5**, the
///    evaluation time against the AC's validity, bounds inclusive.
/// 6. **§6** — the revocation scheme, per `ac_revocation`. With
///    [`AcRevocation::NeverRevokeOnly`] an AC lacking `noRevAvail` is
///    refused, which is what §6 requires of a verifier that checks no AC
///    revocation status — and this function checks none.
/// 7. **Holder binding** — the AC's holder field against
///    `holder_chain[0]`. An AC that is validly signed but names someone
///    else is refused.
/// 8. **Rule 6** — the targeting check, from `my_names` and
///    `my_groups`.
///
/// # `ac_revocation` is not `revocation`
///
/// This function takes both, and they answer different questions.
/// `revocation: &R` applies to the holder's and the authority's
/// public-key chains — it is the `RevocationChecker` used by
/// [`verify_chain`]. `ac_revocation` is about the attribute
/// certificate's OWN revocation status, which RFC 5755 §6 makes a
/// separate question with its own two schemes, and which nothing in
/// this crate answers.
///
/// So supplying a real `CrlChecker` or `OcspChecker` does not let
/// you pass [`AcRevocation::CallerChecks`]: that checker never looks at
/// the AC. Choosing `CallerChecks` on the strength of it is fail-open
/// on §6's MUST, which is the mistake this parameter exists to make
/// visible. This paragraph was lost when `AcRevocation` moved to
/// `pkix-ac`, where there is no `RevocationChecker` to contrast it
/// with.
///
/// # Rule 4 is yours
///
/// §5 rule 4 requires the AC issuer to be "directly trusted as an AC
/// issuer (by configuration or otherwise)", and no library can decide
/// that. Supplying `aa_chain` is the decision: a CA that your trust
/// anchors accept for TLS is **not** thereby an authority entitled to
/// grant roles, and nothing here can tell the difference between an
/// authority you chose and one an attacker chose for you.
///
/// §4.5 narrows the damage rather than fixing it. Because an AC issuer
/// may not be a CA, an ordinary CA certificate is refused as an
/// authority whatever `aa_chain` says — so the specific mistake of
/// reusing a PKI CA as an authority cannot happen silently. A non-CA
/// certificate chosen wrongly still can.
///
/// # Targeting is enforced, not reported
///
/// An AC targeted at somebody else is **refused**, with
/// [`pkix_ac::Error::NotATarget`]. RFC 5755 §4.3.2: "An (honest) AC
/// verifier who is not amongst the named servers/services MUST reject
/// the AC."
///
/// So [`ValidatedAttributeCert::targeting`] only ever holds
/// [`Untargeted`](pkix_ac::Targeting::Untargeted) or
/// [`Matched`](pkix_ac::Targeting::Matched) — it says which of those
/// applied, not whether to proceed. An earlier version returned
/// `NotATarget` as an `Ok` and left the choice to the caller; that is
/// fail-open on a MUST, because the obvious use of this function is
/// `let v = verify_attribute_cert(..)?` followed by granting the
/// attribute.
///
/// A caller who genuinely wants the verdict without the refusal — an
/// audit tool reporting on an AC not addressed to it, say — can call
/// [`pkix_ac::AttributeCertificate::check_targeting`] directly.
///
/// # Errors
///
/// - [`Error::Path`], [`Error::PathBuild`] or [`Error::Revocation`] from
///   either path validation, the holder's checked first.
/// - [`Error::AttributeCert`] for every RFC 5755 failure: a broken
///   profile rule, an expired AC, a bad signature, an authority that is
///   not the issuer named, a holder mismatch, or an AC targeted at
///   another verifier.
#[cfg(feature = "attribute-certs")]
#[cfg_attr(docsrs, doc(cfg(feature = "attribute-certs")))]
#[allow(clippy::too_many_arguments)]
pub fn verify_attribute_cert<V, P, R, A>(
    ac: &pkix_ac::AttributeCertificate,
    holder_chain: &[Certificate],
    aa_chain: &[Certificate],
    anchors: &[TrustAnchor],
    my_names: &[x509_cert::ext::pkix::name::GeneralName],
    my_groups: &[x509_cert::ext::pkix::name::GeneralName],
    ac_revocation: AcRevocation,
    profile: &P,
    now_unix: u64,
    verifier: &V,
    revocation: &R,
    aia: &A,
) -> crate::Result<ValidatedAttributeCert>
where
    V: SignatureVerifier,
    P: Profile,
    R: RevocationChecker,
    A: AiaFetcher,
{
    let policy = profile.policy(now_unix);

    // Rule 1, then rule 2's path half. Both before any AC check: an AC
    // signed by an authority whose own certificate is expired or revoked
    // establishes nothing, and reporting the AC's problems first would
    // send a caller after the wrong thing.
    let holder = verify_chain(holder_chain, anchors, &policy, verifier, revocation, aia)?;
    let authority = verify_chain(aa_chain, anchors, &policy, verifier, revocation, aia)?;

    debug_assert!(
        !holder_chain.is_empty() && !aa_chain.is_empty(),
        "verify_chain must reject empty chains"
    );
    let holder_cert = &holder_chain[0];
    let aa_cert = &aa_chain[0];

    // Everything §5 asks that does not need trust anchors, in one
    // call. This used to repeat the sequence here, which is how the two
    // entry points came to disagree about §6: the rule was added to
    // this function and not to `validate`. One sequence, one place.
    let targeting = ac.validate(
        aa_cert,
        holder_cert,
        now_unix,
        my_names,
        my_groups,
        ac_revocation,
        verifier,
    )?;

    Ok(ValidatedAttributeCert {
        holder,
        authority,
        targeting,
    })
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
/// The binding is checked with the caller's own `verifier`, the same
/// one [`verify_ocsp_responder`] hands to [`verify_chain`]. It used to
/// be [`DefaultVerifier`] regardless, justified in this comment as
/// "matching the rest of `verify_ocsp_responder`" — which was exactly
/// backwards, since the rest of that function has always used the
/// caller's verifier.
///
/// The divergence mattered in both directions. A verifier stricter
/// than [`DefaultVerifier`] — one refusing an algorithm by policy —
/// had its policy silently bypassed on the single check standing
/// between the caller and the DN-twin attack described above, which
/// is the worse direction. A verifier supporting an algorithm
/// [`DefaultVerifier`] does not would see a valid responder rejected
/// with [`Error::OcspDelegation`] even though the same key verified
/// the whole chain a line earlier.
///
/// If `issuer`'s SPKI uses an algorithm the supplied verifier does not
/// cover, the binding check still surfaces as [`Error::OcspDelegation`].
fn verify_responder_is_delegated_by<V: SignatureVerifier>(
    responder: &Certificate,
    issuer: &Certificate,
    verifier: &V,
) -> crate::Result<()> {
    use spki::der::referenced::OwnedToRef as _;

    // 1. Cheap DN gate.
    if !pkix_path::names_match(
        responder.tbs_certificate().issuer(),
        issuer.tbs_certificate().subject(),
    ) {
        return Err(Error::ocsp_delegation(OcspDelegationKind::IssuerDnMismatch));
    }

    // 2. Cryptographic binding: responder.signature must verify under
    //    issuer.spki over responder.tbs_certificate (re-encoded by
    //    `pkix_path::tbs_certificate_der`, which keeps validity times as
    //    parsed). This is the spec-correct delegation check; DN equality
    //    alone admits a DN-twin attack in cross-signed topologies.
    let tbs_der = pkix_path::tbs_certificate_der(responder)
        .map_err(|_| Error::ocsp_delegation(OcspDelegationKind::TbsReencodeFailed))?;
    verifier
        .verify_signature(
            responder.signature_algorithm().owned_to_ref(),
            issuer
                .tbs_certificate()
                .subject_public_key_info()
                .owned_to_ref(),
            &tbs_der,
            responder.signature().raw_bytes(),
        )
        .map_err(|_| Error::ocsp_delegation(OcspDelegationKind::SignatureNotVerified))?;
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

    // "no extensions at all" and "extensions present, no EKU among them"
    // are the same thing to a caller, so they share one arm rather than
    // two `ok_or`s carrying the same string. A certificate with no
    // extension block is treated as having an empty one.
    let ext = leaf
        .tbs_certificate()
        .extensions()
        .map_or(&[][..], |e| e.as_slice())
        .iter()
        .find(|e| e.extn_id == OID_EXTENDED_KEY_USAGE)
        .ok_or(Error::profile_violation(
            ProfileViolationKind::TsaEkuMissing,
        ))?;

    if !ext.critical {
        return Err(Error::profile_violation(
            ProfileViolationKind::TsaEkuNotCritical,
        ));
    }

    let eku = ExtendedKeyUsage::from_der(ext.extn_value.as_bytes())
        .map_err(|_| Error::profile_violation(ProfileViolationKind::TsaEkuMalformed))?;

    // RFC 3161 §2.3: timeStamping MUST be the sole EKU value. Everything
    // the guarded arm does not accept — a different single OID, several
    // OIDs, or none — fails for that one reason, so it is one arm.
    match eku.0.as_slice() {
        [oid] if *oid == ID_KP_TIME_STAMPING => Ok(()),
        _ => Err(Error::profile_violation(
            ProfileViolationKind::TsaEkuNotSoleTimeStamping,
        )),
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

    let ku = KeyUsage::from_der(ext.extn_value.as_bytes())
        .map_err(|_| Error::profile_violation(ProfileViolationKind::TsaKeyUsageMalformed))?;

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
        return Err(Error::profile_violation(
            ProfileViolationKind::TsaKeyUsageNotSigningOnly,
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Send + Sync compile-time assertions (AGENTS.md non-negotiable #6, PKIX-2l0v.2)
// ---------------------------------------------------------------------------

const _: fn() = || {
    fn _assert_send_sync<T: Send + Sync>() {}
    _assert_send_sync::<Error>();
    _assert_send_sync::<ValidatedPath>();

    // `Verifier` is `Copy` for EVERY parameter set, and the struct
    // carries no bounds at all (Rust API guideline C-STRUCT-BOUNDS: the
    // obligation belongs on the constructors and methods, not the type).
    //
    // Both halves are asserted with one type that implements nothing —
    // not `Copy`, not `Clone`, and none of the three capability traits.
    // It fails to compile if someone reinstates bounds on the struct, and
    // it fails if someone "tidies" the hand-written `Clone`/`Copy` into a
    // `#[derive]`, which would add the `V: Copy` bounds the struct does
    // not need, since it holds `&V` rather than `V`.
    struct ImplementsNothing;
    fn _assert_copy<T: Copy>() {}
    _assert_copy::<Verifier<'static, ImplementsNothing, ImplementsNothing, ImplementsNothing>>();

    // `Verifier` is public surface and `verify_batch` invites callers to
    // fan chains out across threads, so it has to be `Send + Sync` too.
    //
    // Stated generically rather than for a concrete instantiation because
    // the obvious one to name, `Verifier<DefaultVerifier, ..>`, exists only
    // when a signature backend feature is on; this holds for every
    // conforming parameter set and compiles in every configuration. The
    // bound is `Sync` and not `Send` on each parameter because the struct
    // holds `&'a V` rather than `V`, and `&T` is `Send` exactly when `T`
    // is `Sync`.
    fn _verifier_is_send_sync<'a, V: Sync + 'a, R: Sync + 'a, A: Sync + 'a>() {
        _assert_send_sync::<Verifier<'a, V, R, A>>();
    }
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
/// cross-certificate with a supported algorithm may exist. Both shapes of
/// wrong intermediate reach the fetch: one that chains to an anchor and
/// one that does not. (The second used to, and the first did not, because
/// the reassembly loop treated a complete-but-invalid candidate as a
/// finished chain and stopped.)
///
/// # Consequence for a chain that cannot be repaired
///
/// Admitting `SignatureInvalid` here means a chain whose signature is
/// simply wrong — a corrupted certificate, not a stale intermediate —
/// also reaches the AIA seam and spends fetches before failing. That is
/// the price of the recovery, and it is bounded by [`AiaConfig`]: the
/// depth cap, the total-fetch cap and the deadline all apply, and the
/// URIs come from certificates on candidate paths rather than from
/// anywhere in the pool. Callers who would rather fail fast than fetch
/// on a bad signature pass [`NoAiaFetcher`], which turns the attempt
/// into an immediate [`Error::Aia`].
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
            Error::profile_violation(ProfileViolationKind::TsaEkuMissing),
            Error::ocsp_delegation(OcspDelegationKind::SignatureNotVerified),
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
