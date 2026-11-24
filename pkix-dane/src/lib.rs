#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! # pkix-dane
//!
//! DANE TLSA record parsing and per-usage match logic, per
//! [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698),
//! [RFC 7218](https://www.rfc-editor.org/rfc/rfc7218) (the mnemonics) and
//! [RFC 7671](https://www.rfc-editor.org/rfc/rfc7671) (operational rules).
//!
//! DANE lets a domain operator state in DNS which certificate or trust anchor
//! their service uses, so a client can check the certificate against that
//! statement instead of — or in addition to — the public CA system. The
//! statement is a TLSA record, and DNSSEC is what makes it trustworthy.
//!
//! ## This crate does not do DNS
//!
//! Resolution and DNSSEC validation live behind the [`TlsaResolver`] trait,
//! whose reference implementation is the sibling `pkix-dane-resolver` crate.
//! Keeping them apart is what lets this crate be `no_std` and lets its
//! matching logic be tested without a network.
//!
//! ```text
//! pkix-chain ----+---->  pkix-dane           (types, matching, TlsaResolver)
//!                |
//!                +---->  pkix-dane-resolver  (DNSSEC resolution; std)
//! ```
//!
//! ## DNSSEC is not optional
//!
//! An unvalidated TLSA record is worse than none: it hands certificate choice
//! to whoever can answer a DNS query. So [`TlsaResponse`] carries the
//! [`DnssecStatus`] its records arrived under, and the verify functions refuse
//! anything but [`DnssecStatus::Secure`]. The four statuses are genuinely
//! different outcomes, not shades of failure — see [`DnssecStatus`].
//!
//! ## The four usages
//!
//! | Usage | Pins | PKIX also required? | Function |
//! |--|--|--|--|
//! | [`PkixTa`](TlsaUsage::PkixTa) (0) | a trust anchor | yes | [`verify_pkix_ta`] |
//! | [`PkixEe`](TlsaUsage::PkixEe) (1) | the end-entity cert | yes | [`verify_pkix_ee`] |
//! | [`DaneTa`](TlsaUsage::DaneTa) (2) | a trust anchor | no | [`verify_dane_ta`] |
//! | [`DaneEe`](TlsaUsage::DaneEe) (3) | the end-entity cert | no | [`verify_dane_ee`] |
//!
//! The end-entity usages match one certificate. The trust-anchor usages match
//! against a chain, since the record names an issuer above the leaf: usage 2
//! synthesizes a [`TrustAnchor`](https://docs.rs/pkix-path/latest/pkix_path/struct.TrustAnchor.html)
//! for the chain to validate to, and usage 0 constrains a chain that the
//! caller has already validated by other means.
//!
//! Each usage leaves a different obligation with the caller — usage 0 and 1
//! require PKIX validation alongside the match, usage 2 requires validating
//! against the returned anchor *instead of* the caller's trust store. Those
//! obligations are documented on each function and are not enforceable from
//! inside this crate, which sees neither a clock nor a trust store.
//!
//! ## Byte exactness
//!
//! TLSA matching is a comparison against octets a domain operator hashed from
//! their certificate file, so it must run over the certificate *as the peer
//! presented it*. [`PresentedCert`] carries those octets; the
//! [`selector`] module documents why re-encoding a parsed certificate is not
//! an acceptable substitute.
//!
//! ## `no_std` and feature flags
//!
//! The build is `no_std + alloc`; there is no `std` feature. [`DaneError`]
//! implements [`core::error::Error`] unconditionally, which `core` gained in
//! Rust 1.81 — below the workspace MSRV, so no feature is needed to offer it.
//! `serde` derives
//! `Serialize`/`Deserialize` on the record, response and error types, so
//! TLSA data can be cached across processes — records carry DNS TTLs, which
//! makes caching an expected deployment pattern (AGENTS.md non-negotiable #6).
//!
//! All public result types are `Clone + Debug + PartialEq + Eq` and
//! `Send + Sync`, asserted at the bottom of this module.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

pub mod name;
pub mod record;
pub mod selector;
mod verify;

pub use name::{TlsaName, TlsaProtocol};
pub use record::{TlsaMatchingType, TlsaRecord, TlsaSelector, TlsaUsage};
pub use selector::{matches, matches_spki, matching_records, PresentedCert};
pub use verify::{
    verify_dane_ee, verify_dane_ta, verify_pkix_ee, verify_pkix_ta, DaneTrustAnchor,
    TrustAnchorSource,
};

// ---------------------------------------------------------------------------
// DnssecStatus
// ---------------------------------------------------------------------------

/// The DNSSEC validation state a DNS answer arrived under.
///
/// These are the four outcomes of RFC 4035 validation, and they are four
/// *different* things rather than degrees of success. Collapsing them to a
/// boolean discards exactly the distinction a DANE failure-mode policy is
/// built on: whether DANE was absent, unavailable or under attack.
///
/// | Status | What it means | What a client does |
/// |--|--|--|
/// | [`Secure`](Self::Secure) | signatures validated to a configured trust anchor | apply DANE |
/// | [`Insecure`](Self::Insecure) | the zone is provably unsigned | no DANE; fall through to PKIX |
/// | [`Indeterminate`](Self::Indeterminate) | no chain of trust could be established | no DANE; fall through to PKIX |
/// | [`Bogus`](Self::Bogus) | signatures present and bad | **fail**; do not fall through |
///
/// [`Bogus`](Self::Bogus) is the one that must not be treated as "no DANE".
/// A signed zone whose signatures do not verify is the signature of an attack
/// or a serious misconfiguration; falling back to PKIX there would let an
/// attacker strip DANE by corrupting the answer
/// ([RFC 7671 §4.1](https://www.rfc-editor.org/rfc/rfc7671#section-4.1)).
///
/// # Authenticated denial
///
/// A [`Secure`](Self::Secure) response with no records is not the same as no
/// response: it is a signed statement that the domain publishes no TLSA
/// record, so DANE is deliberately absent. [`TlsaResponse::is_authenticated_denial`]
/// identifies that case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DnssecStatus {
    /// Validated: signatures chain to a trust anchor the resolver holds.
    Secure,
    /// Provably unsigned: an authenticated denial of DS existence shows the
    /// zone is not signed.
    Insecure,
    /// Unknown: no chain of trust reaches the answer, so it can be neither
    /// validated nor shown to be unsigned. A resolver with no trust anchors
    /// configured returns this for everything.
    Indeterminate,
    /// Validation failed: signatures exist and do not verify, are missing
    /// where required, or have expired.
    Bogus,
}

impl DnssecStatus {
    /// Whether records under this status may be used for DANE authentication.
    ///
    /// True only for [`Secure`](Self::Secure).
    #[must_use]
    pub const fn is_secure(self) -> bool {
        matches!(self, Self::Secure)
    }

    /// Whether this status permits falling back to ordinary PKIX validation.
    ///
    /// True for [`Insecure`](Self::Insecure) and
    /// [`Indeterminate`](Self::Indeterminate), where DANE is simply not
    /// available. **False for [`Bogus`](Self::Bogus)**, where falling back
    /// would let an attacker strip DANE by breaking the signatures.
    #[must_use]
    pub const fn permits_pkix_fallback(self) -> bool {
        matches!(self, Self::Insecure | Self::Indeterminate)
    }
}

// ---------------------------------------------------------------------------
// TlsaResponse
// ---------------------------------------------------------------------------

/// TLSA records together with the DNSSEC status they arrived under.
///
/// This is what a [`TlsaResolver`] returns, and why it returns this instead of
/// a bare `Vec<TlsaRecord>`: the records alone cannot distinguish the four
/// outcomes a DANE policy has to tell apart.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TlsaResponse {
    records: Vec<TlsaRecord>,
    dnssec: DnssecStatus,
}

impl TlsaResponse {
    /// Assembles a response from records and the status they arrived under.
    ///
    /// Resolvers must pass the status their validator actually determined.
    /// Reporting [`DnssecStatus::Secure`] for an unvalidated answer defeats
    /// the entire mechanism — the `AD` bit from an upstream recursive
    /// resolver is **not** sufficient grounds, since it is a claim by a host
    /// on the network path rather than a verified signature.
    #[must_use]
    pub const fn new(records: Vec<TlsaRecord>, dnssec: DnssecStatus) -> Self {
        Self { records, dnssec }
    }

    /// The records, in the order the resolver supplied them.
    ///
    /// Order carries no meaning in DNS; a client that matches against any
    /// record succeeds.
    #[must_use]
    pub fn records(&self) -> &[TlsaRecord] {
        &self.records
    }

    /// The DNSSEC status under which these records arrived.
    #[must_use]
    pub const fn dnssec(&self) -> DnssecStatus {
        self.dnssec
    }

    /// Whether this is a signed statement that no TLSA record exists.
    ///
    /// True for a [`Secure`](DnssecStatus::Secure) response carrying no
    /// records. The domain has authenticated the *absence* of DANE, which is a
    /// stronger statement than an unsigned answer: there is no DANE policy
    /// here and the client should use PKIX, confident that nothing was
    /// stripped.
    #[must_use]
    pub fn is_authenticated_denial(&self) -> bool {
        self.dnssec.is_secure() && self.records.is_empty()
    }

    /// Whether any record in the response is one this crate can evaluate.
    ///
    /// See [`TlsaRecord::is_usable`]. A response whose every record is
    /// unusable is treated by
    /// [RFC 7671 §17](https://www.rfc-editor.org/rfc/rfc7671#section-17) as if
    /// no TLSA record were published.
    #[must_use]
    pub fn has_usable_record(&self) -> bool {
        self.records.iter().any(TlsaRecord::is_usable)
    }

    /// The records carrying a given usage, usable or not.
    #[must_use]
    pub fn records_for_usage(&self, usage: TlsaUsage) -> Vec<&TlsaRecord> {
        self.records
            .iter()
            .filter(|record| record.usage() == usage)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// TlsaResolver
// ---------------------------------------------------------------------------

/// Source of DNSSEC-validated TLSA records.
///
/// This is the trust-domain callback for DANE, alongside `pkix-path`'s
/// `SignatureVerifier`, `pkix-revocation`'s `RevocationChecker` and
/// `pkix-aia`'s `AiaFetcher`. It is a trait rather than a concrete type so
/// that callers can wrap it — a TTL-respecting cache is the obvious wrapper,
/// and AGENTS.md non-negotiable #6 requires the seam stay open for exactly
/// that.
///
/// The trait is synchronous. The async analogue, `AsyncTlsaResolver`, lives in
/// `pkix-dane-resolver` behind its `async` feature and not here, so that this
/// `no_std` crate takes on no async machinery and `no_std` consumers inherit
/// no `Send` bounds. That placement follows the workspace's settled pattern
/// from `pkix-revocation-http`; in particular, no implementation should bridge
/// the two with `block_on`, which deadlocks when called from inside a running
/// runtime.
///
/// # Security
///
/// An implementation MUST validate DNSSEC signatures itself and report the
/// result truthfully in [`TlsaResponse::dnssec`]. Trusting the `AD` bit of an
/// upstream recursive resolver is not validation: it is a claim made by a host
/// on the network path, and believing it reduces DANE to the security of the
/// link to that host.
pub trait TlsaResolver {
    /// Looks up the TLSA records at `name`.
    ///
    /// A successful return describes what DNS said, including the cases where
    /// it said nothing: a [`Secure`](DnssecStatus::Secure) response with no
    /// records is an authenticated denial, which is information rather than
    /// failure. `Err` is reserved for not learning the answer at all.
    ///
    /// # Errors
    ///
    /// - [`DaneError::ResolutionDisabled`] from a resolver that is wired in
    ///   but intentionally off, such as [`NoTlsaResolver`].
    /// - [`DaneError::ResolutionFailed`] when the lookup could not be
    ///   completed: timeout, transport failure, `SERVFAIL`, or a malformed
    ///   answer.
    ///
    /// A [`Bogus`](DnssecStatus::Bogus) answer is **not** an error. It is a
    /// successful determination that validation failed, and the caller must
    /// act on it differently from a timeout: bogus means do not fall back to
    /// PKIX, while a timeout leaves the policy choice open.
    fn resolve(&self, name: &TlsaName) -> Result<TlsaResponse, DaneError>;

    /// Looks up several names in one call.
    ///
    /// Returns a `Vec` aligned with `names` by index. The default
    /// implementation is a sequential loop over [`resolve`](Self::resolve);
    /// implementations whose transport can pipeline queries should override it.
    /// Callers use this for RFC 7671 §7 CNAME candidates and for validating
    /// several services of one host at once.
    fn batch_resolve(&self, names: &[TlsaName]) -> Vec<Result<TlsaResponse, DaneError>> {
        names.iter().map(|name| self.resolve(name)).collect()
    }
}

/// A [`TlsaResolver`] that never resolves anything.
///
/// The zero-cost default for callers who do not want DANE, mirroring
/// `pkix-aia`'s `NoAiaFetcher`. Every call returns
/// [`DaneError::ResolutionDisabled`]; no I/O, no allocation beyond the `Err`
/// discriminant, and no DNS dependency anywhere in the dependency graph.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct NoTlsaResolver;

impl TlsaResolver for NoTlsaResolver {
    fn resolve(&self, _name: &TlsaName) -> Result<TlsaResponse, DaneError> {
        Err(DaneError::ResolutionDisabled)
    }
}

// ---------------------------------------------------------------------------
// DaneError
// ---------------------------------------------------------------------------

/// Failure modes for TLSA parsing, resolution and matching.
///
/// # Invariants (AGENTS.md non-negotiable #6)
///
/// - `Clone + Debug + PartialEq + Eq` — derived.
/// - `Send + Sync` — asserted at the bottom of this module.
/// - `#[non_exhaustive]`, so a later usage or resolver category can be added
///   without breaking downstream matches.
/// - Behind the `serde` feature: `Serialize + Deserialize`. No embedded
///   handle that cannot be cloned or serialized.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum DaneError {
    /// TLSA RDATA was shorter than its three-octet fixed header.
    ///
    /// Distinct from an unsupported field value: this is a malformed record,
    /// not a record describing something unimplemented, so it is an error
    /// rather than an unusable-and-skipped record.
    RecordTruncated {
        /// Length of the offending RDATA, in octets.
        len: usize,
    },

    /// The `SubjectPublicKeyInfo` could not be DER-encoded for a selector-1
    /// comparison.
    ///
    /// A property of the certificate rather than of any one record, so it
    /// fails the whole evaluation instead of counting as a non-match.
    SpkiEncodingFailed,

    /// A selector octet this crate cannot evaluate was reached directly.
    ///
    /// Not produced by the verify functions, which skip unusable records.
    /// Only [`PresentedCert::selected_content`] can return it, when called
    /// with an unassigned or private-use selector.
    SelectorUnsupported {
        /// The offending selector octet.
        octet: u8,
    },

    /// The records were not DNSSEC-validated, so they cannot authenticate
    /// anything.
    ///
    /// Carries the status so the caller can apply policy:
    /// [`DnssecStatus::permits_pkix_fallback`] distinguishes "DANE is absent,
    /// use PKIX" from [`Bogus`](DnssecStatus::Bogus), where falling back
    /// would let an attacker strip DANE.
    DnssecNotSecure {
        /// The status the resolver reported.
        status: DnssecStatus,
    },

    /// No record in the set carried the usage being verified.
    ///
    /// A record set with only usage 3 records, handed to
    /// [`verify_pkix_ee`], produces this. The caller's DANE policy decides
    /// what it means — typically "try the other usages before giving up".
    NoRecordsForUsage {
        /// The usage that was looked for.
        usage: TlsaUsage,
        /// How many records the set held in total.
        records_present: usize,
    },

    /// Records carried the right usage but none was evaluable.
    ///
    /// Per [RFC 7671 §17](https://www.rfc-editor.org/rfc/rfc7671#section-17)
    /// this is equivalent to the domain publishing no TLSA record at all: the
    /// client cannot act on records it does not understand, and must not fail
    /// the connection on their account alone.
    NoUsableRecords {
        /// The usage that was looked for.
        usage: TlsaUsage,
        /// How many records carried that usage.
        records_for_usage: usize,
    },

    /// Usable records existed and the certificate matched none of them.
    ///
    /// This is the real DANE authentication failure: the domain stated which
    /// certificate it uses, and this is not it.
    NoMatch {
        /// The usage that was verified.
        usage: TlsaUsage,
        /// How many usable records carrying that usage were compared.
        records_compared: usize,
    },

    /// A DANE-TA record claimed to carry a trust-anchor certificate and its
    /// association data did not parse as one.
    ///
    /// Only reachable for a record with selector [`TlsaSelector::Cert`] and
    /// matching type [`TlsaMatchingType::Full`], whose association data is
    /// supposed to be a DER certificate. The record is broken rather than
    /// non-matching, so this is an error and not a skip: a domain that
    /// publishes a malformed anchor has misconfigured DANE, and silently
    /// ignoring it would leave the operator with a connection that fails for
    /// no visible reason.
    MalformedAnchorCertificate,

    /// A trust-anchor certificate's `NameConstraints` extension could not be
    /// parsed.
    ///
    /// Fails closed. An anchor's name constraints bound what that anchor may
    /// vouch for, so treating an unparsable extension as "no constraints"
    /// would widen the anchor's authority precisely when its certificate looks
    /// malformed. RFC 5280 §4.2 requires rejecting an unparsable critical
    /// extension.
    AnchorNameConstraintsMalformed,

    /// Resolution is intentionally disabled at this layer.
    ///
    /// Returned by [`NoTlsaResolver`] and any resolver wired in but switched
    /// off. Callers read it as "no DANE configured", not as a failure.
    ResolutionDisabled,

    /// The lookup could not be completed.
    ///
    /// Timeout, transport failure, `SERVFAIL`, or an unparsable answer. The
    /// inner `String` is a resolver-side diagnostic for logs; it is not
    /// structured, because the caller's decision does not turn on which
    /// transport failure occurred — only on the fact that DNS did not answer.
    ResolutionFailed(String),

    /// The assembled TLSA owner name exceeded 253 octets.
    NameTooLong {
        /// Length of the assembled name, in octets.
        len: usize,
    },

    /// The host component was not a usable DNS name.
    ///
    /// Empty, an empty or over-long label, or a byte outside the permitted
    /// set. An internationalized name must be converted to A-label form by
    /// the caller before it can be queried.
    InvalidHost,

    /// The protocol component was not a usable DNS label.
    ///
    /// Empty, over-long, or not purely lowercase ASCII alphanumeric.
    InvalidProtocol,
}

impl core::fmt::Display for DaneError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RecordTruncated { len } => {
                write!(f, "TLSA RDATA is {len} octets, need at least 3")
            }
            Self::SpkiEncodingFailed => {
                f.write_str("could not DER-encode the SubjectPublicKeyInfo")
            }
            Self::SelectorUnsupported { octet } => {
                write!(f, "TLSA selector {octet} is not supported")
            }
            Self::DnssecNotSecure { status } => {
                write!(f, "TLSA records are not DNSSEC-secure (status: {status:?})")
            }
            Self::NoRecordsForUsage {
                usage,
                records_present,
            } => write!(
                f,
                "no TLSA record for usage {:?} among {records_present} record(s)",
                usage
            ),
            Self::NoUsableRecords {
                usage,
                records_for_usage,
            } => write!(
                f,
                "all {records_for_usage} TLSA record(s) for usage {usage:?} are unusable"
            ),
            Self::NoMatch {
                usage,
                records_compared,
            } => write!(
                f,
                "certificate matched none of {records_compared} TLSA record(s) for usage {usage:?}"
            ),
            Self::MalformedAnchorCertificate => {
                f.write_str("TLSA record's trust-anchor certificate is not valid DER")
            }
            Self::AnchorNameConstraintsMalformed => {
                f.write_str("trust-anchor certificate has malformed NameConstraints")
            }
            Self::ResolutionDisabled => f.write_str("TLSA resolution is disabled"),
            Self::ResolutionFailed(diagnostic) => {
                write!(f, "TLSA lookup failed: {diagnostic}")
            }
            Self::NameTooLong { len } => {
                write!(f, "TLSA owner name is {len} octets, limit is 253")
            }
            Self::InvalidHost => f.write_str("host is not a usable DNS name"),
            Self::InvalidProtocol => f.write_str("protocol is not a usable DNS label"),
        }
    }
}

impl core::error::Error for DaneError {}

// ---------------------------------------------------------------------------
// Non-negotiable #6 compile-time assertions
// ---------------------------------------------------------------------------

const _: fn() = || {
    fn _assert_send_sync<T: Send + Sync>() {}
    _assert_send_sync::<DaneError>();
    _assert_send_sync::<DnssecStatus>();
    _assert_send_sync::<TlsaResponse>();
    _assert_send_sync::<TlsaRecord>();
    _assert_send_sync::<TlsaName>();
    _assert_send_sync::<TlsaUsage>();
    _assert_send_sync::<TlsaSelector>();
    _assert_send_sync::<TlsaMatchingType>();
    _assert_send_sync::<NoTlsaResolver>();

    fn _assert_cache_friendly<T: Clone + core::fmt::Debug + PartialEq + Eq>() {}
    _assert_cache_friendly::<DaneError>();
    _assert_cache_friendly::<DnssecStatus>();
    _assert_cache_friendly::<TlsaResponse>();
    _assert_cache_friendly::<TlsaRecord>();
    _assert_cache_friendly::<TlsaName>();

    // DaneError implements core::error::Error with no feature enabled. This
    // is the property that let the `std` feature be deleted; asserting it
    // here means a future cfg could not quietly take it away again.
    fn _assert_error<E: core::error::Error>() {}
    _assert_error::<DaneError>();
    _assert_cache_friendly::<TrustAnchorSource>();
    _assert_send_sync::<TrustAnchorSource>();
};
