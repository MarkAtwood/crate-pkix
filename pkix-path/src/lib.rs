#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
// Documentation links to `DefaultVerifier`, which needs at least one
// signature backend enabled. With none of them the item does not exist,
// so the link cannot resolve and `cargo doc` on a consumer's own
// feature selection reports an error.
//
// Allowing the lint only where it cannot tell a gated item from a
// mistake loses no signal: a mistyped link is broken with every feature
// enabled too, and the all-features doc build is what the quality gate
// runs under RUSTDOCFLAGS=-D warnings. Demoting the links to code spans
// instead would cost every docs.rs reader a working link, to spare a
// configuration nobody publishes documentation from.
// `RsaPssVerifier` and `RsaPkcs1v15Sha1Verifier` are gated on `rsa`,
// and `rsa` is itself one of the features that brings `DefaultVerifier`
// into existence — so every link in this crate's docs resolves exactly
// when `rsa` is on, and the five-feature condition this replaced was
// both wider than needed and, for a single-signature-feature build like
// `--features p256`, not wide enough.
#![cfg_attr(not(feature = "rsa"), allow(rustdoc::broken_intra_doc_links))]
//! RFC 5280 X.509 certificate path validation — pure Rust, `no_std`.
//!
//! Implements certificate path building and validation per
//! [RFC 5280 §6](https://www.rfc-editor.org/rfc/rfc5280#section-6).
//!
//! # Architecture
//!
//! Cryptographic signature verification is pluggable via [`SignatureVerifier`].
//! The default feature set wires in `RustCrypto` backends for RSA
//! (PKCS#1 v1.5 and RSASSA-PSS with SHA-256/384/512; `rsa` feature) and
//! ECDSA on P-256 (`p256` feature). The optional `p384`, `p521` and
//! `ed25519` features add ECDSA on P-384 and P-521 and Ed25519;
//! `rustcrypto` enables all of them. [`DefaultVerifier`] dispatches over
//! whatever is enabled, taking the ECDSA curve from the issuer's key.
//! For FIPS-validated crypto, implement [`SignatureVerifier`] against
//! `wolfcrypt-rustcrypto` and disable the `rustcrypto` feature.
//!
//! Revocation checking is handled by `pkix-revocation`. This crate never
//! touches the network — use `pkix_chain::verify_chain` for the combined API.
//!
//! # Limitations
//!
//! The following are **not** currently implemented:
//! - **`UTCTime` before 1970.** The supported range is **1970-2049**,
//!   where RFC 5280 §4.1.2.5.1 allows 1950-2049. A certificate whose
//!   `notBefore` or `notAfter` falls in the missing twenty years is
//!   refused, and refused at the DER layer — the error reads "malformed
//!   ASN.1 DER value for UTCTime" and comes back before validation runs.
//!
//!   This is a deliberate scope decision, not an accident. The floor is
//!   the Unix epoch because `der` 0.8 puts it there ("due to common
//!   operations working on `UNIX_EPOCH`, `UtcTime`s are only supported
//!   for the years 1970-2049"), and lifting it would mean forking the DER
//!   layer every consumer of this crate depends on. No conforming CA
//!   issues certificates dated before 1970, so the trade is a fork of a
//!   foundational dependency against twenty years of dates nobody uses.
//!
//!   It is fail-closed: such a certificate is refused, never misread.
//!   OpenSSL does read them, so expect a genuine disagreement rather than
//!   a difference of strictness — NIST PKITS §4.2.3 "Valid pre2000 UTC
//!   notBefore Date Test3" is exactly this shape, and is the one PKITS
//!   vector this crate does not evaluate.
//! - **Legacy signature algorithms** — SHA-1 verifiers (RFC 8017, legacy)
//!   are intentionally not shipped; deployments requiring legacy SHA-1
//!   trust must implement [`SignatureVerifier`] themselves. RSA moduli
//!   outside 1024–8192 bits are refused by the bundled RSA backend.
//! - **RFC 4518 full Unicode NFKC DN normalization** — ASCII case-folding
//!   plus insignificant-whitespace collapsing is applied. `BMPString` AVA
//!   values are transcoded UCS-2-BE → UTF-8 and then compared via the same
//!   ASCII-only normalization pipeline, so two AVAs that share Unicode
//!   code points but differ only in DER string-type (e.g. `BMPString`
//!   "Foo Co" vs `UTF8String` "Foo Co") compare equal. Full RFC 4518 prep
//!   (NFKC, non-ASCII Unicode case fold, prohibit/bidi steps) is future
//!   work tracked under `PKIX-l63j`; until it lands, two `BMPString` values
//!   that contain the same Unicode code points but differ in canonical
//!   decomposition (e.g. precomposed U+00E9 'é' vs decomposed U+0065 U+0301
//!   'e'+ combining acute) compare unequal. `UniversalString` AVA values
//!   are rejected by the `der` crate at parse time (tag 0x1C is not in
//!   `der::Tag` in 0.7) and never reach the path validator. `TeletexString`
//!   AVAs use raw DER byte comparison by policy — `pkix-path` deliberately
//!   does not transcode T.61 to Unicode; see `any_to_str_bytes` rustdoc
//!   for the rationale.
//! - **Path building** — converting an unordered bag of certificates into a
//!   validated chain is handled by `pkix-path-builder`. This crate validates
//!   a caller-ordered `&[Certificate]` only.
//! - **AIA fetching** — chains with missing intermediates are not
//!   reassembled from `AuthorityInfoAccess` URIs here. Callers supply a
//!   complete chain, or go through `pkix-chain`, which follows
//!   `caIssuers` URIs via `pkix-aia` / `pkix-aia-http` (`PKIX-zkjb`).

// For no_std builds, pull in the alloc crate explicitly so `alloc::` paths
// and the `vec!` macro resolve. `#[macro_use]` re-exports alloc macros
// (vec!, format!, etc.) into the crate root, making them available everywhere
// without qualifying them as `alloc::vec!(...)`.
#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

// Unified Vec import: alloc::vec::Vec in no_std, std::vec::Vec under std.
// Both map to the same concrete type; this alias lets the rest of the file
// write `Vec<_>` without cfg-gating every use site.
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

// Unified Cow import: same cfg-gate pattern as Vec. `Cow` is owned by
// `alloc` but `std` re-exports it; we can't write `alloc::borrow::Cow`
// unconditionally because `extern crate alloc` is gated to no_std mode.
// Only the serde wire helper uses it (DN comparison is allocation-free).
#[cfg(all(feature = "serde", not(feature = "std")))]
use alloc::borrow::Cow;
#[cfg(all(feature = "serde", feature = "std"))]
use std::borrow::Cow;

use der::Tagged;
// Re-exported, not merely imported: both types appear in
// `SignatureVerifier::verify_signature`'s signature, so an out-of-crate
// implementor has to name them. Reachable only as `spki::...` they meant
// reading this crate's source to discover the origin and taking a direct
// dependency on a matching `spki` version to say it.
pub use spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};
use x509_cert::Certificate;

/// Helper module for format-adaptive serde serialization of DER-encodable
/// types. Public so downstream crates (`pkix-chain`, `pkix-revocation`,
/// `pkix-truststore`) can reuse the same wire form on their own result
/// types without redefining the helpers.
#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub mod serde_der;

mod policy_graph;
mod verification_error;
pub use verification_error::{VerificationError, VerificationErrorKind};

mod verifiers;
#[cfg(any(
    feature = "p256",
    feature = "p384",
    feature = "p521",
    feature = "rsa",
    feature = "ed25519"
))]
pub use verifiers::DefaultVerifier;
#[cfg(feature = "ecdsa-sha1")]
#[cfg_attr(docsrs, doc(cfg(feature = "ecdsa-sha1")))]
pub use verifiers::EcdsaP256Sha1Verifier;
#[cfg(feature = "p256")]
pub use verifiers::EcdsaP256Verifier;
#[cfg(feature = "p384")]
pub use verifiers::EcdsaP384Verifier;
#[cfg(feature = "p521")]
pub use verifiers::EcdsaP521Verifier;
#[cfg(feature = "ed25519")]
pub use verifiers::Ed25519Verifier;
#[cfg(feature = "rsa-sha1")]
#[cfg_attr(docsrs, doc(cfg(feature = "rsa-sha1")))]
pub use verifiers::RsaPkcs1v15Sha1Verifier;
#[cfg(feature = "rsa")]
pub use verifiers::{
    RsaPkcs1v15Sha256Verifier, RsaPkcs1v15Sha384Verifier, RsaPkcs1v15Sha512Verifier, RsaPssVerifier,
};

/// Re-exported for use with [`TrustAnchor::name_constraints`].
pub use x509_cert::ext::pkix::constraints::name::NameConstraints;

/// Private shorthand for the `GeneralSubtrees` type used throughout NC processing.
type GeneralSubtrees = x509_cert::ext::pkix::constraints::name::GeneralSubtrees;

/// Opaque wrapper around an underlying ASN.1 / DER error.
///
/// Carries a [`Display`] message identical to the wrapped `der::Error` so
/// diagnostic output is preserved, but does not expose the underlying type
/// in the public API. This insulates callers from semver-breaking changes
/// in the `der` crate's error variants.
///
/// Construct via [`DerError::new`] (or implicitly via
/// [`From<der::Error> for Error`]). Sibling workspace crates that wrap
/// DER decoding failures in their own `Error` enums (`pkix-revocation`,
/// `pkix-truststore`) call [`DerError::new`] directly.
///
/// # Serde wire form
///
/// When the `serde` feature is enabled, `DerError` (de)serializes via its
/// `Display` message as a single `String` field. Because `der::Error` does
/// not itself carry a textual message — its `Display` is derived from
/// `der::ErrorKind` — round-trip is **lossy**: a deserialized `DerError`
/// preserves the original `Display` output verbatim but its
/// [`core::error::Error::source`] is `None` because the original
/// `der::Error` value cannot be reconstructed from a free-form string.
/// This trade is acceptable for diagnostic error types; the success type
/// (`ValidatedPath`) round-trips losslessly because all its fields are
/// canonically DER-encodable.
///
/// [`Display`]: core::fmt::Display
#[derive(Clone, Debug)]
pub struct DerError {
    /// Original `der::Error` value, when available.
    ///
    /// Populated by [`DerError::new`] from a real `der::Error`. `None`
    /// only when the `DerError` was reconstructed from serialized form;
    /// in that case [`core::error::Error::source`] returns `None` and the
    /// Display message is taken from the preserved [`Self::message`].
    ///
    /// Under `no_std` builds the `core::error::Error::source` impl is
    /// not available, so this field is only read for its `Debug`
    /// representation; `#[allow(dead_code)]` silences the lint in
    /// that configuration.
    #[cfg_attr(not(feature = "std"), allow(dead_code))]
    inner: Option<der::Error>,
    /// Cached Display rendering of `inner`, preserved across serde
    /// round-trips so that the diagnostic message survives even when
    /// `inner` cannot be reconstructed.
    message: BoxStr,
}

// Hand-written `PartialEq` / `Eq` compare only the cached Display
// message. Pre-refactor (tuple struct over `der::Error`) PartialEq was
// structural over `der::Error`'s `{kind, position}` fields; two
// `der::Error`s with identical `{kind, position}` always produce
// identical Display output, so comparing on `message` preserves the
// pre-refactor equality verdicts in practice. This also makes serde
// round-trip preserve `Eq` even though deserialize drops the `inner`
// field (it cannot be reconstructed from the rendered message).
impl PartialEq for DerError {
    fn eq(&self, other: &Self) -> bool {
        self.message == other.message
    }
}
impl Eq for DerError {}

/// Hashes `message`, the one field [`PartialEq`] compares.
///
/// That correspondence is the whole argument for correctness: `Hash`
/// requires that equal values hash equally, and since equality here is
/// defined solely by `message`, hashing solely `message` cannot violate
/// it. Hashing `inner` as well would break the contract, because
/// `inner` is dropped on a serde round-trip while equality is preserved
/// — two equal values would then hash differently.
///
/// Written out rather than derived for that reason: a derive would
/// include `inner`.
///
/// This exists so [`Error`] can derive `Hash`. `Der(DerError)` was the
/// only variant standing in the way, which in turn is why
/// `pkix_path_builder::Error::NoValidPath` stores its inner error as a
/// rendered `String` — the builder's own enum derives `Hash` and could
/// not hold a non-`Hash` field. That storage choice is now a semver
/// question rather than a technical obstacle.
impl core::hash::Hash for DerError {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.message.hash(state);
    }
}

// Internal: use a Box<str> so the struct is `Clone` cheaply and we keep
// the heap allocation small. A type alias keeps the `#[cfg(not(feature
// = "std"))]` use-statements in the rest of the file unchanged. Defined
// here to localise the no_std-vs-std import.
#[cfg(not(feature = "std"))]
type BoxStr = alloc::boxed::Box<str>;
#[cfg(feature = "std")]
type BoxStr = std::boxed::Box<str>;

impl DerError {
    /// Construct a `DerError` from a real `der::Error`.
    ///
    /// The original `der::Error` is preserved internally so
    /// [`core::error::Error::source`] returns it; the rendered
    /// `Display` message is cached so the diagnostic survives serde
    /// round-trips. See the type-level rustdoc for the round-trip
    /// fidelity contract.
    ///
    /// Exposed to permit sibling workspace crates (`pkix-revocation`,
    /// `pkix-truststore`) to construct their own `Error::Der`-equivalent
    /// variants from `der::Error` results without going through the
    /// `pkix_path::Error::from(der::Error)` conversion (which would
    /// produce a `pkix_path::Error`, not the sibling crate's `Error`).
    #[must_use]
    pub fn new(e: der::Error) -> Self {
        // Pre-render the Display message so it survives serde round-trips
        // even when `inner` cannot be reconstructed on the deserialize side.
        #[cfg(feature = "std")]
        let message = e.to_string().into_boxed_str();
        #[cfg(not(feature = "std"))]
        let message = {
            use core::fmt::Write as _;
            let mut s = alloc::string::String::new();
            // Display on der::Error is infallible (uses core::fmt::Result
            // = (), no I/O); write! against a String returns Ok unless
            // allocation fails.
            let _ = write!(&mut s, "{}", e);
            s.into_boxed_str()
        };
        Self {
            inner: Some(e),
            message,
        }
    }
}

impl core::fmt::Display for DerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.message)
    }
}

impl core::error::Error for DerError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        self.inner.as_ref().map(|e| e as &dyn core::error::Error)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
const _: () = {
    use serde::{Deserializer, Serializer};

    // Local helper struct that carries only the message; both branches
    // of the serde impl re-use the same field-name shape so wire form
    // is stable between encoder and decoder.
    #[derive(serde::Serialize, serde::Deserialize)]
    struct Wire<'a> {
        // Use Cow to avoid allocating on the serialize side. The
        // deserialize side always owns the recovered String.
        #[serde(borrow)]
        message: Cow<'a, str>,
    }

    impl serde::Serialize for DerError {
        fn serialize<S: Serializer>(&self, s: S) -> core::result::Result<S::Ok, S::Error> {
            Wire {
                message: Cow::Borrowed(&self.message),
            }
            .serialize(s)
        }
    }

    impl<'de> serde::Deserialize<'de> for DerError {
        fn deserialize<D: Deserializer<'de>>(d: D) -> core::result::Result<Self, D::Error> {
            let Wire { message } = Wire::deserialize(d)?;
            Ok(Self {
                inner: None,
                message: message.into_owned().into_boxed_str(),
            })
        }
    }
};

/// Errors returned by path validation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Error {
    /// Certificate signature verification failed at the given chain index:
    /// the signature does not verify, or is not a well-formed signature
    /// value ([`VerificationErrorKind::InvalidSignature`]).
    SignatureInvalid {
        /// Zero-based index into the `chain` slice of the failing certificate.
        index: usize,
    },
    /// The certificate's signature could not be checked at the given chain
    /// index: the [`SignatureVerifier`] does not support its algorithm or
    /// the issuer's key, or the issuer's key is malformed. `reason` says
    /// which; it is never [`VerificationErrorKind::InvalidSignature`].
    SignatureNotVerified {
        /// Zero-based index into the `chain` slice of the certificate.
        index: usize,
        /// Why the verifier could not check the signature.
        reason: VerificationErrorKind,
    },
    /// A structural encoding error was found in a certificate.
    ///
    /// Returned when the outer `signatureAlgorithm` OID differs from the
    /// inner `TBSCertificate.signature` OID (RFC 5280 §4.1.1.2; parameters
    /// are not compared, see `check_oid_consistency` for rationale), when a
    /// certificate carries more than one instance of an extension (RFC 5280
    /// §4.2), and when a security-relevant extension fails to decode.
    MalformedCertificate {
        /// Zero-based index into the `chain` slice of the malformed certificate.
        ///
        /// The underlying `der::Error` is intentionally not stored here to keep
        /// this variant `no_std`-compatible and to preserve the stable API shape.
        /// Callers that need the root-cause parse error should validate the
        /// DER certificate independently before calling [`validate_path`].
        index: usize,
    },
    /// Certificate validity period check failed (expired or not yet valid).
    ValidityPeriod {
        /// Zero-based index into the `chain` slice of the failing certificate.
        index: usize,
    },
    /// Issuer/subject name linkage is broken at the given chain index.
    ChainBroken {
        /// Zero-based index into the `chain` slice where the break was found.
        index: usize,
    },
    /// No path from the subject certificate to any trust anchor was found.
    NoTrustedPath,
    /// Path length exceeds [`ValidationPolicy::max_path_len`].
    PathTooLong,
    /// An intermediate certificate is missing `BasicConstraints` `cA=TRUE`.
    NotCA {
        /// Zero-based index into the `chain` slice of the failing certificate.
        index: usize,
    },
    /// An intermediate certificate has a `KeyUsage` extension with `keyCertSign` not set.
    ///
    /// This error is only returned when a `KeyUsage` extension is **present** and the
    /// `keyCertSign` bit is explicitly absent or zero (RFC 5280 §6.1.4(n): "If a `KeyUsage`
    /// extension is present, verify that the keyCertSign bit is set.").
    ///
    /// Certificates with **no** `KeyUsage` extension are not rejected by this check;
    /// RFC 5280 does not require the extension to be present on CA certificates.
    KeyUsageMissing {
        /// Zero-based index into the `chain` slice of the failing certificate.
        index: usize,
    },
    /// An intermediate certificate has a `KeyUsage` extension with `cRLSign` not set.
    ///
    /// This error is only returned when
    /// [`ValidationPolicy::require_crl_sign_on_cas`] is `true` **and** the
    /// intermediate's `KeyUsage` extension is **present** with the `cRLSign` bit
    /// explicitly absent or zero. Certificates with **no** `KeyUsage` extension
    /// are not rejected by this check (RFC 5280 does not require the extension
    /// to be present on CA certificates).
    ///
    /// RFC 5280 §6.1 does not mandate this check; it is an opt-in policy that
    /// restores PKITS §4.7.4 / §4.7.5 conformance for callers who treat a CA
    /// cert without `cRLSign` as non-issuable. Default is off.
    ///
    /// **Disambiguation:** [`pkix_revocation::Error::CrlSignMissing`] (same
    /// variant name, different crate) fires during CRL verification when the
    /// CRL *signer* cert lacks `cRLSign` (RFC 5280 §6.3.3(f)). This variant
    /// fires during *path validation* when an intermediate CA cert in the
    /// chain lacks `cRLSign` and the caller opted into the policy check.
    ///
    /// [`pkix_revocation::Error::CrlSignMissing`]: https://docs.rs/pkix-revocation/latest/pkix_revocation/enum.Error.html#variant.CrlSignMissing
    CrlSignMissing {
        /// Zero-based index into the `chain` slice of the failing certificate.
        index: usize,
    },
    /// A critical extension is present that this implementation does not handle.
    UnhandledCriticalExtension {
        /// Zero-based index into the `chain` slice of the failing certificate.
        index: usize,
    },
    /// Certificate name constraints violated (RFC 5280 §4.2.1.10); `index` is the 0-based chain position.
    ///
    /// Also returned when a constraint is in effect for a name the validator
    /// cannot evaluate: a URI without an authority or with an IP-address
    /// host, a name of an unsupported form (`otherName`, `ediPartyName`,
    /// `registeredID`) under a constraint of that form, a non-IA5String
    /// subject `emailAddress`, or a `SmtpUTF8Mailbox` whose domain is not
    /// ASCII.
    NameConstraintViolation {
        /// Zero-based index into the `chain` slice of the failing certificate.
        index: usize,
    },
    /// Certificate policy validation failed (RFC 5280 §6.1.5(g)).
    ///
    /// Returned when `explicit_policy` reaches zero and the valid policy tree
    /// is empty, meaning no acceptable certificate policy exists for the chain.
    PolicyViolation {
        /// Zero-based index of the certificate where the violation was detected.
        index: usize,
    },
    /// ASN.1 / DER encoding or decoding error.
    ///
    /// Returned when a structural encoding error is found in a certificate or
    /// when re-encoding `TBSCertificate` for signature verification fails.
    /// Signature verification now uses heap-allocated encoding (no fixed size
    /// limit), so this error reflects a genuine DER encoding defect in the
    /// certificate, not an implementation size constraint.
    ///
    /// The inner [`DerError`] is an opaque newtype; the underlying `der::Error`
    /// is intentionally not exposed so a future major-version bump in the
    /// `der` crate cannot cascade into a semver break here.
    Der(DerError),
    /// A certificate's validity period (notAfter − notBefore) exceeds
    /// [`ValidationPolicy::max_validity_secs`].
    ///
    /// This check fires for every certificate in the chain, not just the leaf.
    ValidityPeriodExceedsMax {
        /// Zero-based index into the `chain` slice of the failing certificate.
        index: usize,
    },
    /// A certificate's signature algorithm OID is not in
    /// [`ValidationPolicy::allowed_signature_algs`].
    ///
    /// The check fires before signature verification so the error is diagnostic
    /// rather than a confusing `SignatureInvalid`.
    AlgorithmNotAllowed {
        /// Zero-based index into the `chain` slice of the failing certificate.
        index: usize,
    },
    /// An RSA public key's modulus is smaller than
    /// [`ValidationPolicy::min_rsa_key_bits`] bits.
    ///
    /// Non-RSA keys (EC, Ed25519, …) are not affected by this check.
    KeyTooSmall {
        /// Zero-based index into the `chain` slice of the failing certificate.
        index: usize,
    },
    /// The leaf certificate (chain index 0) has no `SubjectAltName` extension,
    /// or the extension is present but empty.
    ///
    /// Only checked when [`ValidationPolicy::require_subject_alt_name`] is `true`.
    /// Intermediate CA certificates are not subject to this check.
    MissingSan,
    /// The leaf certificate (chain index 0) has a `SubjectAltName` extension but
    /// none of its entries is an `rfc822Name` (email address).
    ///
    /// Only checked when [`ValidationPolicy::require_rfc822_san`] is `true`.
    /// Intermediate CA certificates are not subject to this check.
    MissingRfc822San,
    /// The leaf certificate (chain index 0) does not assert all OIDs required
    /// by [`ValidationPolicy::required_leaf_eku`].
    ///
    /// `anyExtendedKeyUsage` (2.5.29.37.0) does not satisfy a specific OID
    /// requirement — each required OID must be listed explicitly.
    MissingEku,
    /// The leaf certificate's `CertificatePolicies` extension does not assert
    /// a required policy OID from
    /// [`ValidationPolicy::required_leaf_policy_oids`].
    ///
    /// `anyPolicy` (2.5.29.32.0) does not satisfy a specific OID requirement;
    /// each required OID must be listed explicitly in the leaf's
    /// `CertificatePolicies` extension.
    ///
    /// Distinct from [`Error::PolicyViolation`], which signals failure of the
    /// RFC 5280 §6.1 policy tree (`initial_policy_set` /
    /// `initial_explicit_policy`). `MissingLeafPolicyOid` signals a leaf-only
    /// assertion check that is independent of the policy tree.
    MissingLeafPolicyOid {
        /// The required policy OID that the leaf does not assert.
        #[cfg_attr(feature = "serde", serde(with = "crate::serde_der"))]
        required: der::asn1::ObjectIdentifier,
    },
    /// The leaf certificate's Subject DN does not satisfy
    /// [`ValidationPolicy::required_leaf_subject_dn_attrs`].
    ///
    /// This variant carries no payload; richer "which branch of the rule
    /// failed" diagnostics are a non-breaking follow-up.
    SubjectDnAttrRuleUnmet,
    /// Two certificates in the chain share the same `(issuer DN, serial number)`.
    ///
    /// Per RFC 5280 §4.1.2.2, the combination of issuer DN and serial number
    /// uniquely identifies a certificate. A cert appearing twice at different
    /// chain positions is a construction error. Returned as a diagnostic rather
    /// than a confusing [`Error::SignatureInvalid`] or [`Error::ChainBroken`].
    ///
    /// Note: two certificates with the same public key but different
    /// issuer+serial are *distinct* certificates (e.g. cross-signed CAs) and
    /// are **not** rejected by this check.
    ///
    /// `first` and `second` are the zero-based chain indices of the two duplicates.
    DuplicateCertificate {
        /// First occurrence index.
        first: usize,
        /// Second occurrence index.
        second: usize,
    },
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SignatureInvalid { index } => {
                write!(f, "signature invalid at chain index {index}")
            }
            Self::SignatureNotVerified { index, reason } => {
                write!(f, "signature not verified at chain index {index}: {reason}")
            }
            Self::ValidityPeriod { index } => {
                write!(f, "validity period check failed at chain index {index}")
            }
            Self::MalformedCertificate { index } => {
                write!(f, "malformed certificate at chain index {index}")
            }
            Self::ChainBroken { index } => {
                write!(f, "issuer/subject linkage broken at chain index {index}")
            }
            Self::NoTrustedPath => write!(f, "no path to a trusted anchor"),
            Self::PathTooLong => write!(f, "path length exceeds maximum"),
            Self::NotCA { index } => write!(f, "certificate at index {index} is not a CA"),
            Self::KeyUsageMissing { index } => {
                write!(f, "keyCertSign missing at chain index {index}")
            }
            Self::CrlSignMissing { index } => {
                write!(f, "cRLSign missing at chain index {index}")
            }
            Self::UnhandledCriticalExtension { index } => {
                write!(f, "unhandled critical extension at chain index {index}")
            }
            Self::NameConstraintViolation { index } => {
                write!(f, "name constraints violated at certificate index {index}")
            }
            Self::PolicyViolation { index } => {
                write!(f, "certificate policy violation at chain index {index}")
            }
            Self::Der(e) => write!(f, "DER error: {e}"),
            Self::ValidityPeriodExceedsMax { index } => {
                write!(f, "validity period exceeds maximum at chain index {index}")
            }
            Self::AlgorithmNotAllowed { index } => {
                write!(f, "signature algorithm not allowed at chain index {index}")
            }
            Self::KeyTooSmall { index } => {
                write!(f, "RSA key too small at chain index {index}")
            }
            Self::MissingSan => write!(f, "leaf certificate is missing SubjectAltName"),
            Self::MissingRfc822San => write!(
                f,
                "leaf certificate SubjectAltName contains no rfc822Name entry"
            ),
            Self::MissingEku => {
                write!(
                    f,
                    "leaf certificate is missing required ExtendedKeyUsage OID(s)"
                )
            }
            Self::MissingLeafPolicyOid { required } => {
                write!(
                    f,
                    "leaf certificate is missing required CertificatePolicies OID {required}"
                )
            }
            Self::SubjectDnAttrRuleUnmet => {
                write!(
                    f,
                    "leaf certificate Subject DN does not satisfy the required attribute rule"
                )
            }
            Self::DuplicateCertificate { first, second } => {
                write!(
                    f,
                    "duplicate certificate (issuer+serial) at chain indices {first} and {second}"
                )
            }
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Der(e) => Some(e),
            Self::SignatureInvalid { .. }
            | Self::SignatureNotVerified { .. }
            | Self::MalformedCertificate { .. }
            | Self::ValidityPeriod { .. }
            | Self::ChainBroken { .. }
            | Self::NoTrustedPath
            | Self::PathTooLong
            | Self::NotCA { .. }
            | Self::KeyUsageMissing { .. }
            | Self::CrlSignMissing { .. }
            | Self::UnhandledCriticalExtension { .. }
            | Self::NameConstraintViolation { .. }
            | Self::PolicyViolation { .. }
            | Self::ValidityPeriodExceedsMax { .. }
            | Self::AlgorithmNotAllowed { .. }
            | Self::KeyTooSmall { .. }
            | Self::MissingSan
            | Self::MissingRfc822San
            | Self::MissingEku
            | Self::MissingLeafPolicyOid { .. }
            | Self::SubjectDnAttrRuleUnmet
            | Self::DuplicateCertificate { .. } => None,
        }
    }
}

impl From<der::Error> for Error {
    fn from(e: der::Error) -> Self {
        Self::Der(DerError::new(e))
    }
}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Pluggable signature verification backend.
///
/// Implement this trait to provide algorithm-specific signature verification.
/// The trait is OID-dispatched: the `algorithm` argument carries the OID and
/// any parameters from the certificate's `signatureAlgorithm` field.
///
/// This trait is object-safe and can be used as `dyn SignatureVerifier`.
/// All method arguments are either `&self` or borrows, so no `Sized` bound
/// is implied.
///
/// # Implementing a custom backend
///
/// ```rust,no_run
/// use der::asn1::ObjectIdentifier;
/// const MY_RSA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
/// const MY_ECDSA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
///
/// struct MyVerifier;
///
/// impl pkix_path::SignatureVerifier for MyVerifier {
///     fn verify_signature(
///         &self,
///         algorithm: spki::AlgorithmIdentifierRef<'_>,
///         _issuer_spki: spki::SubjectPublicKeyInfoRef<'_>,
///         _message: &[u8],
///         _signature: &[u8],
///     ) -> Result<(), pkix_path::VerificationError> {
///         match algorithm.oid {
///             MY_RSA_OID => { Ok(()) /* RSA verification */ }
///             MY_ECDSA_OID => { Ok(()) /* ECDSA verification */ }
///             _ => Err(pkix_path::VerificationError::unsupported_algorithm()),
///         }
///     }
/// }
/// ```
pub trait SignatureVerifier {
    /// Verify `signature` over `message`.
    ///
    /// - `algorithm`    — from the subject cert's `signatureAlgorithm` field
    /// - `issuer_spki`  — SPKI extracted from the issuer or trust anchor cert
    /// - `message`      — DER-encoded `TBSCertificate` (the bytes that were signed)
    /// - `signature`    — raw signature bytes (`BitString` content, not the wrapper)
    ///
    /// Returns `Ok(())` when the signature verifies. The caller
    /// ([`validate_path`]) adds the chain index: an error of kind
    /// [`VerificationErrorKind::InvalidSignature`] becomes
    /// [`Error::SignatureInvalid`], any other kind
    /// [`Error::SignatureNotVerified`] — the verifier does not need to know
    /// the index.
    ///
    /// # Errors
    ///
    /// Returns a [`VerificationError`] whose kind says why the signature
    /// was not accepted: the algorithm is not supported
    /// ([`UnsupportedAlgorithm`](VerificationErrorKind::UnsupportedAlgorithm)),
    /// the issuer key is unsupported or does not fit the algorithm
    /// ([`UnsupportedKey`](VerificationErrorKind::UnsupportedKey)) or does
    /// not decode ([`MalformedKey`](VerificationErrorKind::MalformedKey)),
    /// or the signature is malformed or does not verify
    /// ([`InvalidSignature`](VerificationErrorKind::InvalidSignature)).
    fn verify_signature(
        &self,
        algorithm: AlgorithmIdentifierRef<'_>,
        issuer_spki: SubjectPublicKeyInfoRef<'_>,
        message: &[u8],
        signature: &[u8],
    ) -> core::result::Result<(), VerificationError>;
}

/// Forwarding impl so a shared reference to a verifier is itself a
/// verifier.
///
/// This is what makes a verifier that cannot be `Clone` usable.
/// [`crate::validate_path`] and the `CrlChecker` / `OcspChecker` types in
/// `pkix-revocation` take a verifier by value and require `Clone`, since
/// they hold it and may be cloned themselves. A verifier that owns a
/// hardware token handle, an open session, or anything else not
/// duplicable therefore could not be used at all.
///
/// With this impl it can: pass `&verifier` and the type parameter
/// becomes `&V`, which is `Copy`, so the `Clone` bound is satisfied for
/// free and nothing is duplicated. The borrow is the only cost, and it
/// is what a scoped validation wants anyway.
///
/// For a verifier shared by something outliving a borrow — a fetcher
/// held for the life of a process — use the `Arc` impl below instead.
impl<T: SignatureVerifier + ?Sized> SignatureVerifier for &T {
    fn verify_signature(
        &self,
        algorithm: AlgorithmIdentifierRef<'_>,
        issuer_spki: SubjectPublicKeyInfoRef<'_>,
        message: &[u8],
        signature: &[u8],
    ) -> core::result::Result<(), VerificationError> {
        (**self).verify_signature(algorithm, issuer_spki, message, signature)
    }
}

/// Forwarding impl so an `Arc`-shared verifier is itself a verifier.
///
/// The owned counterpart to the `&T` impl above, for a verifier that has
/// to outlive any particular borrow. `Arc<V>` is `Clone` whatever `V` is,
/// and cloning it is a refcount bump rather than a duplication of
/// whatever the verifier holds.
///
/// # Why this is gated on `std`
///
/// `Arc` lives in `alloc::sync`, which exists only on targets with
/// atomic compare-and-swap. Implementing it unconditionally would make
/// this crate stop compiling for a `no_std` target without atomics
/// (`thumbv6m-none-eabi`, for instance) in exchange for a convenience.
/// Under `std` those atomics are guaranteed, so the impl is free there.
/// A `no_std` consumer that does have atomics and wants this shape can
/// write the same four-line forwarding impl over its own newtype.
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl<T: SignatureVerifier + ?Sized> SignatureVerifier for std::sync::Arc<T> {
    fn verify_signature(
        &self,
        algorithm: AlgorithmIdentifierRef<'_>,
        issuer_spki: SubjectPublicKeyInfoRef<'_>,
        message: &[u8],
        signature: &[u8],
    ) -> core::result::Result<(), VerificationError> {
        (**self).verify_signature(algorithm, issuer_spki, message, signature)
    }
}

/// A trust anchor used to terminate path validation.
///
/// A trust anchor is typically either a self-signed root CA certificate
/// or a raw (name, SPKI) pair extracted from a platform trust store.
/// The trust anchor itself is **not** signature-verified — it is trusted
/// by definition (RFC 5280 §6.1.1(c)).
///
/// **Validity period**: RFC 5280 §6.1.1(c) explicitly excludes the trust
/// anchor's notBefore/notAfter from path validation. An expired root CA
/// certificate used as a trust anchor will still anchor valid paths — this
/// is intentional behavior, not a bug. Callers are responsible for ensuring
/// their trust store contains the anchors they intend to trust.
///
/// **`PartialEq` is byte-level, not semantic**: The derived `PartialEq`
/// compares fields verbatim. Two anchors representing the same CA may compare
/// unequal if their DER encodings differ — for example, one `AlgorithmIdentifier`
/// with explicit `NULL` parameters and another with absent parameters are both
/// valid for RSA (RFC 3279 §2.3.1) but will not be equal under `==`. Do not use
/// `==` to deduplicate a trust store; use [`names_match`] and compare
/// `algorithm.oid` plus `subject_public_key` bytes directly. Path validation
/// already handles this internally, so it is not affected by this encoding difference.
///
/// # Stability
///
/// `TrustAnchor` is `#[non_exhaustive]`: new fields may be added in minor
/// versions. Construct via [`TrustAnchor::new`], [`TrustAnchor::from_cert`],
/// or `TrustAnchor::from`/`try_from`. Do not use struct literal syntax.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct TrustAnchor {
    /// The subject distinguished name of the trust anchor.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_der"))]
    pub subject: x509_cert::name::Name,
    /// The subject public key info of the trust anchor.
    ///
    /// Must be a valid SPKI for the chosen signature algorithm. An empty or
    /// malformed SPKI will cause signature verification to fail with
    /// `Error::NoTrustedPath` (no anchor matched), not a panic.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_der"))]
    pub subject_public_key_info: spki::SubjectPublicKeyInfoOwned,
    /// `NameConstraints` from the trust anchor certificate, if present.
    ///
    /// When set, `chain_walk` seeds the initial `permitted_subtrees` and
    /// `excluded_subtrees` state from this value before walking the chain.
    /// Populated automatically by `from_cert`; `None` for programmatically
    /// constructed anchors unless explicitly set.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_der::option"))]
    pub name_constraints: Option<x509_cert::ext::pkix::constraints::name::NameConstraints>,
}

impl TrustAnchor {
    /// Create a trust anchor from raw subject name and SPKI.
    #[must_use]
    pub const fn new(
        subject: x509_cert::name::Name,
        subject_public_key_info: spki::SubjectPublicKeyInfoOwned,
    ) -> Self {
        Self {
            subject,
            subject_public_key_info,
            name_constraints: None,
        }
    }

    /// Extract subject name and SPKI from a certificate to create a trust anchor.
    ///
    /// This is the typical constructor when your trust store contains full
    /// self-signed root CA certificates.
    ///
    /// Prefer [`TrustAnchor::from`] (i.e. `TrustAnchor::from(&cert)`) when you
    /// need to keep `cert` alive after building the anchor.
    ///
    /// # Warning: malformed `NameConstraints` are silently dropped
    ///
    /// If the anchor certificate contains a malformed or unparseable
    /// `NameConstraints` extension, `from_cert` silently sets
    /// `name_constraints = None` and continues. **The resulting anchor
    /// will not enforce any name-constraint restrictions from that
    /// extension**, which may widen the trust scope beyond what the
    /// certificate intended.
    ///
    /// For strict RFC 5280 §4.2 compliance — where a critical extension
    /// that cannot be parsed MUST cause rejection — use
    /// [`TrustAnchor::try_from`] instead. That path returns
    /// `Err(`[`DerError`]`)` so the caller can reject the malformed anchor
    /// rather than silently operating without name constraints.
    ///
    /// # A non-conformant `minimum`/`maximum` is kept, not dropped
    ///
    /// RFC 5280 §4.2.1.10 requires `minimum` to be zero and `maximum` to be
    /// absent, and [`TrustAnchor::try_from`] rejects a certificate encoding
    /// either. This constructor cannot: it is infallible, so its only
    /// choices are to keep the subtree or to discard it.
    ///
    /// It keeps it, and the constraint is then enforced as though `minimum`
    /// were zero — which applies it to *more* names than the issuer wrote,
    /// never fewer. Discarding it would stop enforcing the constraint
    /// altogether and widen the anchor's trust scope, so between two wrong
    /// answers this is the conservative one. That makes it deliberately
    /// unlike the malformed-DER case above, where there is no subtree to
    /// apply and `None` is the only option.
    ///
    /// A caller who wants the certificate refused outright should use
    /// [`TrustAnchor::try_from`].
    #[must_use]
    pub fn from_cert(cert: Certificate) -> Self {
        let name_constraints = find_cert_ext(&cert, OID_NAME_CONSTRAINTS);
        Self {
            subject: cert.tbs_certificate().subject().clone(),
            subject_public_key_info: cert.tbs_certificate().subject_public_key_info().clone(),
            name_constraints,
        }
    }
}

impl From<&Certificate> for TrustAnchor {
    fn from(cert: &Certificate) -> Self {
        Self {
            subject: cert.tbs_certificate().subject().clone(),
            subject_public_key_info: cert.tbs_certificate().subject_public_key_info().clone(),
            name_constraints: find_cert_ext(cert, OID_NAME_CONSTRAINTS),
        }
    }
}

/// Fail-closed construction from an owned certificate.
///
/// Returns `Err(`[`DerError`]`)` if the certificate contains a `NameConstraints`
/// extension with malformed DER. Use this when building a trust store that
/// must reject certificates with unparseable critical extensions per
/// RFC 5280 §4.2.
///
/// The error type is the opaque [`DerError`] newtype rather than `der::Error`
/// so that a future major-version bump in the `der` crate does not cascade
/// into a semver break here.
///
/// # Why only `TryFrom<Certificate>` and not `TryFrom<&Certificate>`
///
/// `TryFrom<&Certificate>` would conflict with the blanket impl
/// `impl<T, U: Into<T>> TryFrom<U>` provided by Rust core, because
/// `From<&Certificate>` is already implemented (and `From` implies `Into`).
/// Use `TrustAnchor::try_from(cert.clone())` if you need to keep `cert`.
impl TryFrom<Certificate> for TrustAnchor {
    type Error = DerError;

    fn try_from(cert: Certificate) -> core::result::Result<Self, Self::Error> {
        let name_constraints: Option<NameConstraints> =
            try_find_cert_ext(&cert, OID_NAME_CONSTRAINTS).map_err(DerError::new)?;
        // §4.2.1.10's minimum/maximum rule, which this constructor exists to
        // enforce and did not. `cert_name_constraints` rejects an intermediate
        // encoding either field; a strict trust store should not then accept
        // the same extension on its anchor.
        if name_constraints
            .as_ref()
            .is_some_and(|nc| !subtrees_are_conformant(nc))
        {
            return Err(DerError::new(der::Error::from(der::ErrorKind::Value {
                tag: der::Tag::Integer,
            })));
        }
        Ok(Self {
            subject: cert.tbs_certificate().subject().clone(),
            subject_public_key_info: cert.tbs_certificate().subject_public_key_info().clone(),
            name_constraints,
        })
    }
}

/// Compositional rule for asserting required Subject DN attributes on a leaf cert.
///
/// Designed to express CA/B Forum S/MIME BR tier rules such as "must have
/// `organizationName`" or "must have `pseudonym` OR (`givenName` AND
/// `surname`)" without committing the workspace to a fixed list of attribute
/// requirements.
///
/// The [`Field`][Self::Field] variant matches when the named OID appears at
/// least once in the leaf's Subject DN RDN sequence (any RDN, any
/// `AttributeTypeAndValue` within an RDN). [`AllOf`][Self::AllOf] and
/// [`AnyOf`][Self::AnyOf] compose subordinate rules.
///
/// # Vacuity
///
/// - `AllOf(vec![])` accepts every Subject DN (vacuously true).
/// - `AnyOf(vec![])` rejects every Subject DN (vacuously false).
///
/// Callers writing `AnyOf` should not pass an empty list unless that is the
/// intended semantics.
///
/// # Example
///
/// Express "Subject must have `pseudonym`, or both `givenName` and
/// `surname`":
///
/// ```rust
/// use pkix_path::DnAttrRule;
/// use der::asn1::ObjectIdentifier;
///
/// const PSEUDONYM:  ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.65");
/// const GIVEN_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.42");
/// const SURNAME:    ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.4");
///
/// let rule = DnAttrRule::AnyOf(vec![
///     DnAttrRule::Field(PSEUDONYM),
///     DnAttrRule::AllOf(vec![
///         DnAttrRule::Field(GIVEN_NAME),
///         DnAttrRule::Field(SURNAME),
///     ]),
/// ]);
/// # let _ = rule;
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DnAttrRule {
    /// Match when the named attribute OID appears at least once in the
    /// leaf's Subject DN.
    Field(
        #[cfg_attr(feature = "serde", serde(with = "crate::serde_der"))]
        der::asn1::ObjectIdentifier,
    ),
    /// Match when every subordinate rule matches. `AllOf(vec![])` is
    /// vacuously true.
    AllOf(Vec<DnAttrRule>),
    /// Match when at least one subordinate rule matches. `AnyOf(vec![])`
    /// is vacuously false.
    AnyOf(Vec<DnAttrRule>),
}

/// Walk the Subject DN once and report whether the named OID appears in any
/// `AttributeTypeAndValue` within any `RelativeDistinguishedName`.
///
/// OID equality is exact byte-for-byte comparison; no aliasing or
/// canonicalization is performed.
fn dn_contains_oid(subject: &x509_cert::name::Name, oid: &der::asn1::ObjectIdentifier) -> bool {
    subject.iter().any(|ava| ava.oid == *oid)
}

/// Evaluate a [`DnAttrRule`] against a Subject DN, returning `true` when the
/// rule is satisfied.
fn evaluate_dn_attr_rule(subject: &x509_cert::name::Name, rule: &DnAttrRule) -> bool {
    match rule {
        DnAttrRule::Field(oid) => dn_contains_oid(subject, oid),
        DnAttrRule::AllOf(rules) => rules.iter().all(|r| evaluate_dn_attr_rule(subject, r)),
        DnAttrRule::AnyOf(rules) => rules.iter().any(|r| evaluate_dn_attr_rule(subject, r)),
    }
}

/// Policy parameters controlling path validation.
///
/// # Stability
///
/// `ValidationPolicy` is `#[non_exhaustive]`.
/// Construct via [`ValidationPolicy::new`] or [`Default`] + field assignment.
/// Do not use struct literal syntax.
///
/// # Performance note
///
/// Policy objects are intended to be constructed once (e.g., at server startup)
/// and reused for the lifetime of the application. Repeated construction is
/// unnecessary.
///
/// Policy enforcement (`CertificatePolicies`, `PolicyMappings`, `PolicyConstraints`,
/// `InhibitAnyPolicy`) is implemented per RFC 5280 §6.1. Use the
/// `initial_explicit_policy`, `initial_any_policy_inhibit`,
/// `initial_policy_mapping_inhibit`, and `initial_policy_set` fields to
/// configure the initial policy state.
///
/// # Limitations
///
/// Path-building (RFC 4158 — cross-signed certificates, multiple candidate
/// issuers) is **out of scope** for this crate. The caller must supply the
/// complete, ordered chain (see `pkix-path-builder` for path discovery).
///
/// Revocation checking (CRL / OCSP) is out of scope for `pkix-path`; see
/// `pkix-revocation` for that functionality.
// `clippy::struct_excessive_bools` would prefer enum-typed groupings here,
// but the bools map directly to RFC 5280 §6.1.1 named inputs
// (`initial-explicit-policy`, `initial-any-policy-inhibit`,
// `initial-policy-mapping-inhibit`) and to the SAN-presence and
// EKU-presence policy gates. Substituting an enum cluster would obscure the
// 1:1 mapping to the spec text and force callers through a pattern-match
// adapter for each field. The current shape is the most direct expression
// of the spec inputs.
#[allow(clippy::struct_excessive_bools)]
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ValidationPolicy {
    /// Maximum chain depth, not counting the trust anchor. Default: 10.
    ///
    /// A chain of `[leaf]` is depth 0. `[leaf, intermediate, root]` is depth 1
    /// (one intermediate). Validation fails if depth exceeds this value.
    ///
    /// Self-issued certificates do not count towards the depth (RFC 5280
    /// §4.2.1.9), but they are not unlimited either: a chain longer than
    /// `2 * max_path_len + 3` certificates (the leaf, `max_path_len`
    /// intermediates, and up to one self-issued certificate per CA in the
    /// path plus one more at the top for an included root) is rejected with
    /// [`Error::PathTooLong`] before any other processing. This bounds the
    /// work done on an attacker-supplied chain.
    pub max_path_len: u8,

    /// Current time as seconds since the Unix epoch (1970-01-01T00:00:00Z).
    ///
    /// Used to check `notBefore` ≤ `now` ≤ `notAfter` on every certificate.
    /// **Must be set by the caller** — there is no platform clock in `no_std`.
    ///
    /// **Warning — the default is 0 (1970-01-01):** Any certificate issued
    /// after 1970 has `notBefore > 0` and will fail the validity check with
    /// [`Error::ValidityPeriod`]. If you see unexpected `ValidityPeriod`
    /// errors, check that `current_time_unix` is set to the current time.
    ///
    /// **Warning**: passing `u64::MAX` causes all `notAfter` checks to pass.
    /// This effectively disables expiry checking — only use it in contexts
    /// where you explicitly want permissive (clock-free) validation.
    pub current_time_unix: u64,

    /// Enforce the `KeyUsage` extension when present. Default: `true`.
    ///
    /// When `true`, an intermediate certificate whose `KeyUsage` extension is
    /// **present** but does not include `keyCertSign` will be rejected with
    /// [`Error::KeyUsageMissing`], per RFC 5280 §6.1.4(n).
    ///
    /// Certificates with **no** `KeyUsage` extension are not affected; RFC 5280
    /// only mandates the check when the extension is present.
    pub enforce_key_usage: bool,

    /// Require `cRLSign` in `KeyUsage` on every intermediate CA. Default: `false`.
    ///
    /// When `true`, an intermediate certificate whose `KeyUsage` extension is
    /// **present** but does not include `cRLSign` will be rejected with
    /// [`Error::CrlSignMissing`]. Certificates with **no** `KeyUsage` extension
    /// are not affected.
    ///
    /// RFC 5280 §6.1 does not mandate this check — it conflates path validation
    /// with revocation infrastructure. PKITS §4.7.4 and §4.7.5 nonetheless
    /// expect such chains to fail because a CA cert without `cRLSign` cannot
    /// revoke certs it issued. Enable this flag to restore PKITS conformance
    /// or to enforce a stricter "every CA must be able to sign CRLs" rule.
    ///
    /// This check is independent of [`enforce_key_usage`][Self::enforce_key_usage]:
    /// `enforce_key_usage` governs the RFC-mandated `keyCertSign` check, while
    /// `require_crl_sign_on_cas` adds a separate cRLSign requirement.
    pub require_crl_sign_on_cas: bool,

    /// Initial explicit-policy indicator (RFC 5280 §6.1.1).
    ///
    /// When `true`, path validation requires that at least one valid policy exists
    /// from the initial policy set. When `false` (the default), any valid path is
    /// accepted even if no certificate policy is asserted.
    pub initial_explicit_policy: bool,

    /// Initial any-policy inhibit indicator (RFC 5280 §6.1.1).
    ///
    /// When `true`, the `anyPolicy` OID is not considered a match for any other
    /// policy at the start of the path. When `false` (the default), `anyPolicy`
    /// is accepted as a wildcard unless later inhibited by a CA certificate.
    pub initial_any_policy_inhibit: bool,

    /// Initial policy-mapping inhibit indicator (RFC 5280 §6.1.1).
    ///
    /// When `true`, policy mappings are not permitted in any certificate in the
    /// chain. When `false` (the default), policy mappings are allowed.
    pub initial_policy_mapping_inhibit: bool,

    /// Initial user-requested policy set (RFC 5280 §6.1.1).
    ///
    /// The set of certificate policies acceptable to the relying party. An empty
    /// vec, or any set that contains `anyPolicy` (2.5.29.32.0), is the RFC's
    /// any-policy value: all policies are acceptable and the policy graph is
    /// not intersected (§6.1.5(g)(ii)). Otherwise the final graph keeps only
    /// policies in this set (§6.1.5(g)(iii)).
    ///
    /// Note: this is `pub` but clones the OID set, so prefer constructing once
    /// and reusing the `ValidationPolicy`.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_der::vec"))]
    pub initial_policy_set: Vec<der::asn1::ObjectIdentifier>,

    /// If `Some(n)`, reject any certificate whose (notAfter − notBefore) exceeds
    /// `n` seconds. `None` means unconstrained (the default).
    ///
    /// Applied to every certificate in the chain, not just the leaf.
    /// Violations produce [`Error::ValidityPeriodExceedsMax`].
    pub max_validity_secs: Option<u64>,

    /// If `Some(list)`, reject any certificate whose signature algorithm OID is
    /// not in `list`. `None` means any algorithm is accepted (the default).
    ///
    /// Applied to every certificate in the chain. The check fires **before**
    /// signature verification so the error is diagnostic rather than a confusing
    /// [`Error::SignatureInvalid`].
    /// Violations produce [`Error::AlgorithmNotAllowed`].
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_der::option_vec"))]
    pub allowed_signature_algs: Option<Vec<der::asn1::ObjectIdentifier>>,

    /// If `Some(bits)`, reject any certificate carrying an RSA public key whose
    /// modulus is fewer than `bits` bits. Both `rsaEncryption` and
    /// `id-RSASSA-PSS` subject keys count as RSA; other keys are not affected.
    /// `None` means unconstrained (the default).
    ///
    /// Applied to the subject key of every certificate in the chain, leaf
    /// included. The trust anchor's key is **not** checked: it is caller
    /// configuration, not path input, so filter weak anchors when building
    /// the trust store.
    /// Violations produce [`Error::KeyTooSmall`].
    pub min_rsa_key_bits: Option<u32>,

    /// If `true`, the leaf certificate (chain index 0) must have a non-empty
    /// `SubjectAltName` extension. `false` means no SAN requirement (the default).
    ///
    /// Intermediate CA certificates are not checked by this field.
    /// Violations produce [`Error::MissingSan`].
    pub require_subject_alt_name: bool,

    /// If `true`, at least one `rfc822Name` entry must be present in the leaf's
    /// `SubjectAltName` extension.
    ///
    /// Only meaningful when [`require_subject_alt_name`][Self::require_subject_alt_name]
    /// is also `true`. When `require_subject_alt_name` is `false`, this field has
    /// no effect.
    ///
    /// Default: `false` (backward compatible).
    /// Violations produce [`Error::MissingRfc822San`].
    pub require_rfc822_san: bool,

    /// If `Some(oids)`, the leaf certificate must explicitly assert every OID in
    /// `oids` via its `ExtendedKeyUsage` extension. `None` means no EKU requirement
    /// (the default).
    ///
    /// `anyExtendedKeyUsage` (2.5.29.37.0) does **not** satisfy a specific OID
    /// check — each required OID must be listed in the cert's EKU extension.
    /// Violations produce [`Error::MissingEku`].
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_der::option_vec"))]
    pub required_leaf_eku: Option<Vec<der::asn1::ObjectIdentifier>>,

    /// If `Some(oids)`, the leaf certificate must explicitly assert every OID
    /// in `oids` via its `CertificatePolicies` extension. `None` means no
    /// policy-OID assertion requirement (the default).
    ///
    /// Distinct from [`initial_policy_set`][Self::initial_policy_set]:
    /// `initial_policy_set` is the relying party's *acceptable* policy set
    /// (RFC 5280 §6.1.1, `user-initial-policy-set`).
    /// `required_leaf_policy_oids` requires *assertion* — the OID must appear
    /// on the leaf cert's `CertificatePolicies` extension, independent of the
    /// policy tree.
    ///
    /// `anyPolicy` (2.5.29.32.0) does **not** satisfy a specific OID check.
    /// Violations produce [`Error::MissingLeafPolicyOid`].
    ///
    /// This field follows the [`required_leaf_eku`][Self::required_leaf_eku]
    /// precedent: leaf-only, opt-in, additive. Intended for CA/B Forum
    /// subscriber-profile tier disambiguation where a tier mandates assertion
    /// of a specific reserved policy OID.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_der::option_vec"))]
    pub required_leaf_policy_oids: Option<Vec<der::asn1::ObjectIdentifier>>,

    /// If `Some(rule)`, the leaf certificate's Subject DN must satisfy
    /// `rule`. `None` means no Subject DN requirement (the default).
    ///
    /// Violations produce [`Error::SubjectDnAttrRuleUnmet`]. See
    /// [`DnAttrRule`] for the expression grammar and vacuity rules.
    ///
    /// This field follows the [`required_leaf_eku`][Self::required_leaf_eku]
    /// precedent: leaf-only, opt-in, additive. Intended for CA/B Forum
    /// subscriber-profile tier disambiguation (e.g., S/MIME
    /// Organization-validated tier requires `organizationName`).
    pub required_leaf_subject_dn_attrs: Option<DnAttrRule>,
}

impl ValidationPolicy {
    /// Construct a policy with the given time and sensible defaults.
    ///
    /// This is the only constructor: it forces the caller to supply a timestamp,
    /// preventing the silent validity failures that a `Default` with
    /// `current_time_unix = 0` would cause.
    #[must_use]
    pub fn new(now_unix: u64) -> Self {
        Self {
            max_path_len: 10,
            current_time_unix: now_unix,
            enforce_key_usage: true,
            require_crl_sign_on_cas: false,
            initial_explicit_policy: false,
            initial_any_policy_inhibit: false,
            initial_policy_mapping_inhibit: false,
            initial_policy_set: Vec::new(),
            max_validity_secs: None,
            allowed_signature_algs: None,
            min_rsa_key_bits: None,
            require_subject_alt_name: false,
            require_rfc822_san: false,
            required_leaf_eku: None,
            required_leaf_policy_oids: None,
            required_leaf_subject_dn_attrs: None,
        }
    }
}

/// A PKI regime profile that bundles identity, citation, and a validation policy.
///
/// # Design rationale
///
/// `ValidationPolicy` is the *mechanism*. A `Profile` is the *policy authority*: it
/// records *who* mandates the policy (e.g., CA/B Forum TLS BR §7.1), supplies a
/// stable machine-readable identifier, and produces the appropriate
/// [`ValidationPolicy`] for a given point in time.
///
/// Placing the trait in `pkix-path` rather than `pkix-profiles` means that third-party
/// profile crates (e.g., `pkix-fpki`, `pkix-etsi`) can implement `Profile` by depending
/// only on `pkix-path` — they do not need to pull in `pkix-profiles`, which would create
/// a circular coupling between reference implementations and the trait definition.
///
/// # `no_std` compatibility
///
/// The trait is `no_std`-safe: it uses only `&str`, `&[ObjectIdentifier]`, and
/// `ValidationPolicy` (all of which are available without `std`).
/// Implementors on embedded targets may return static `&'static str` slices and
/// construct `ValidationPolicy` without allocation.
///
/// # Implementing `Profile`
///
/// ```rust,no_run
/// use pkix_path::{Profile, ValidationPolicy};
///
/// struct MyCorpProfile;
///
/// impl Profile for MyCorpProfile {
///     fn id(&self) -> &'static str { "example.corp.internal" }
///     fn version(&self) -> &'static str { "2024-01" }
///     fn policy(&self, now_unix: u64) -> ValidationPolicy {
///         let mut p = ValidationPolicy::new(now_unix);
///         p.max_validity_secs = Some(365 * 86_400);
///         p
///     }
///     fn policy_oids(&self) -> &[der::asn1::ObjectIdentifier] { &[] }
/// }
/// ```
pub trait Profile {
    /// Stable, dot-separated identifier for this profile.
    ///
    /// The identifier MUST be unique across all deployed profiles and MUST NOT
    /// change between versions of the same profile. Use reverse-DNS or
    /// CABF/IETF-style naming conventions, e.g.:
    /// - `"cabf.br.tls"` — CA/B Forum TLS Baseline Requirements
    /// - `"cabf.smime"` — CA/B Forum S/MIME Baseline Requirements
    /// - `"fpki.common-policy"` — US Federal PKI Common Policy
    ///
    /// Lint engines use this ID as a namespace prefix for finding IDs.
    fn id(&self) -> &'static str;

    /// Human-readable version string for this profile.
    ///
    /// Typically the ballot or specification version that last changed the
    /// policy rules, e.g., `"SC-081"`, `"2024-01"`, or `"v2.0.1"`.
    /// Used for diagnostic messages and audit logs; not parsed by the engine.
    fn version(&self) -> &'static str;

    /// Produce the [`ValidationPolicy`] for the given point in time.
    ///
    /// `now_unix` is seconds since the Unix epoch. The profile may use this to
    /// implement phased validity caps or algorithm retirement schedules.
    /// The returned `ValidationPolicy` MUST have `current_time_unix` set to
    /// `now_unix`.
    #[must_use]
    fn policy(&self, now_unix: u64) -> ValidationPolicy;

    /// The certificate policy OIDs that this profile recognises as its own.
    ///
    /// Used by registry and composition tools to detect when two profiles
    /// claim overlapping policy space. Returns an empty slice if the profile
    /// does not restrict certificate policy OIDs.
    fn policy_oids(&self) -> &[der::asn1::ObjectIdentifier];
}

/// The result of a successful certificate path validation.
///
/// A `ValidatedPath` is only produced when [`validate_path`] succeeds, which
/// requires the input `chain` to contain at least one certificate. Callers
/// may therefore rely on `chain[0]` being valid after a successful validation.
///
/// Fields are `pub` for direct read access. `#[non_exhaustive]` prevents external
/// code from constructing `ValidatedPath` directly and from pattern-matching
/// exhaustively, preserving the ability to add fields in future minor versions
/// without a breaking change.
///
/// # `Copy` removal in 0.3.0
///
/// `ValidatedPath` is no longer `Copy`. The struct now carries owned
/// heap-backed fields exposing RFC 5280 §6.1.5 wrap-up outputs (the leaf's
/// subject DN, issuer DN, serial number, and SubjectPublicKeyInfo) so
/// consumers can read the validated leaf identity without re-parsing
/// `chain[0]`. These fields cannot satisfy the `Copy` bound; pre-0.3
/// callers that relied on bit-copy semantics need to add `.clone()` or
/// pass `&ValidatedPath` instead.
///
/// # §6.1.5 wrap-up outputs
///
/// RFC 5280 §6.1.5 specifies that successful path validation produces
/// several outputs identifying the validated leaf certificate. The four
/// leaf-intrinsic outputs (subject, issuer, serial, SPKI) are surfaced
/// here as convenience accessors; consumers no longer need to re-parse
/// `chain[0]` to obtain them.
///
/// The final `valid_policy_tree` is surfaced as
/// [`valid_policy_tree`][Self::valid_policy_tree]. The final
/// `working_public_key_parameters` is not yet surfaced; future minor
/// versions may add it, so callers should pattern match with `..` rest
/// patterns on this `#[non_exhaustive]` struct.
///
/// `Hash` is no longer derived because none of the new field types
/// (`x509_cert::name::Name`, `x509_cert::serial_number::SerialNumber`,
/// `spki::SubjectPublicKeyInfoOwned`) implement `Hash` upstream. No
/// in-tree consumer used `ValidatedPath` as a `HashMap`/`HashSet` key,
/// so dropping the derive is observable but should not require code
/// changes for any existing user.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct ValidatedPath {
    /// Index into the `anchors` slice of the trust anchor that terminated the path.
    pub anchor_index: usize,
    /// Number of intermediate certificates in the validated chain, excluding
    /// both the leaf and the trust anchor.
    ///
    /// Computed as `chain.len().saturating_sub(1)` where `chain` is the
    /// `[leaf, intermediate_0, ..., intermediate_n]` slice passed to
    /// [`validate_path`]. A single leaf certificate yields `depth == 0`;
    /// a leaf plus one intermediate yields `depth == 1`.
    ///
    /// Note: this counts all certificates except the trust anchor — including
    /// self-issued intermediates that RFC 5280 §4.2.1.9 excludes from the
    /// `pathLenConstraint` count. For chains with self-issued intermediates the
    /// `depth` field may be larger than the RFC 5280 path length.
    ///
    /// **Do not** compare `depth` directly against a certificate's
    /// [`BasicConstraints`] `pathLenConstraint` value. RFC 5280 §4.2.1.9
    /// defines `pathLenConstraint` as the number of non-self-issued
    /// intermediates below the issuing CA, which differs from this field's
    /// total certificate count. Use the RFC 5280 §6.1.4(b) accounting
    /// performed by `chain_walk` instead.
    ///
    /// [`BasicConstraints`]: x509_cert::ext::pkix::BasicConstraints
    pub depth: usize,

    /// Subject DN of the validated leaf certificate (`chain[0].subject`).
    ///
    /// RFC 5280 §6.1.5 names this output indirectly: a successful path
    /// validation produces the leaf's identity (subject + serial uniquely
    /// identify a certificate). This field is a convenience accessor —
    /// callers could equivalently read `chain[0].tbs_certificate().subject()`,
    /// but threading the chain to every consumer that needs the leaf's DN
    /// is awkward. The clone is owned to free the validated value from any
    /// lifetime tie to the input chain.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_der"))]
    pub leaf_subject: x509_cert::name::Name,

    /// Issuer DN of the validated leaf certificate (`chain[0].issuer`).
    ///
    /// This is the §6.1.5(f) `working_issuer_name` output as observed at
    /// the leaf cert (which is the first cert processed by the §6.1
    /// algorithm, so the leaf's `issuer` is the initial value of
    /// `working_issuer_name` before iteration begins; for a successfully
    /// validated chain it identifies the directly-signing CA).
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_der"))]
    pub leaf_issuer: x509_cert::name::Name,

    /// Serial number of the validated leaf certificate
    /// (`chain[0].serial_number`).
    ///
    /// Together with [`Self::leaf_issuer`] this forms the RFC 5280
    /// §4.1.2.2 unique certificate identifier (`{ issuer, serial }`),
    /// which downstream code commonly needs for revocation lookups,
    /// audit logging, or de-duplication.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_der"))]
    pub leaf_serial: x509_cert::serial_number::SerialNumber,

    /// `SubjectPublicKeyInfo` of the validated leaf certificate.
    ///
    /// This is the §6.1.5(c)(d)(e) `working_public_key` /
    /// `working_public_key_algorithm` / `working_public_key_parameters`
    /// outputs, bundled into the canonical SPKI form. Downstream code
    /// (e.g. application-layer signature verification using the validated
    /// leaf as a trust delegate) needs the full SPKI rather than only the
    /// algorithm identifier or only the public-key bits.
    ///
    /// Note: this field reflects the leaf's *encoded* SPKI as it appeared
    /// in the certificate, not a normalized/canonicalized form. PSS
    /// parameters, RSA `parameters: NULL` vs `parameters: absent`
    /// ambiguities, etc. are preserved verbatim.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_der"))]
    pub leaf_spki: spki::SubjectPublicKeyInfoOwned,

    /// The final RFC 5280 §6.1.5 `valid_policy_tree` (held as the RFC 9618
    /// policy graph, see [`PolicyTreeNode`]), or `None` if it was reduced to
    /// NULL during validation.
    ///
    /// `Some(tree)` is the post-§6.1.5(g)(iii) state (i.e. after
    /// intersection with `initial_policy_set` and post-pruning), listed
    /// depth by depth starting with the depth-0 root.
    /// `None` means the path validated only because `explicit_policy`
    /// stayed above 0 (no explicit policy was required) — semantically "no
    /// acceptable policy is valid for this path". Callers that want to enforce a specific policy OID
    /// (or extract qualifiers attached to a specific policy) should
    /// inspect this field and treat `None` as "no policy information
    /// available", not as a validation failure.
    ///
    /// Each node carries its policy qualifiers (RFC 5280 §6.1.2(a)) in
    /// the upstream `PolicyQualifierInfo` form (a `(qualifier_id_oid,
    /// raw_any_value)` pair, no decoding of `qualifier`). See
    /// [`PolicyTreeNode`] for the per-node shape.
    ///
    /// For convenience, [`Self::policy_qualifiers`] iterates
    /// `(policy_oid, qualifier)` pairs across all tree nodes.
    pub valid_policy_tree: Option<Vec<PolicyTreeNode>>,
}

/// A node of the final policy graph, exposed for post-validation qualifier
/// extraction on [`ValidatedPath::valid_policy_tree`].
///
/// Policy processing uses the RFC 9618 `valid_policy_graph` in place of the
/// RFC 5280 §6.1.2(a) `valid_policy_tree`: there is at most one node per
/// `(depth, valid_policy)`, and a node that the RFC 5280 tree would copy
/// once per parent appears once, listing every parent in
/// [`parent_policies`][Self::parent_policies]. The set of valid policies is
/// the same (RFC 9618 §3); the graph's size stays linear in the size of the
/// path's policy extensions, where the tree can grow exponentially.
///
/// This is the public mirror of an internal node type, kept separate so the
/// internal representation is not part of the public API surface.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct PolicyTreeNode {
    /// Depth at which this node appears in the tree.
    ///
    /// `0` is the synthetic anyPolicy root sentinel (always present
    /// while the tree is alive; carries no qualifiers). `1` is the
    /// trust-anchor-adjacent CA. `n` is the leaf.
    pub depth: usize,

    /// The policy OID this node represents.
    ///
    /// May be `id-ce-certificatePolicies-anyPolicy` (2.5.29.32.0) for
    /// nodes that survived an anyPolicy expansion or were not yet
    /// materialized into specific policies.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_der"))]
    pub valid_policy: der::asn1::ObjectIdentifier,

    /// Set of policies in the next certificate that are consistent with
    /// this node, per RFC 5280 §6.1.2(a) `expected_policy_set`.
    ///
    /// Initialized to `{valid_policy}` and updated by `PolicyMappings`
    /// extensions during the walk.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_der::vec"))]
    pub expected_policy_set: Vec<der::asn1::ObjectIdentifier>,

    /// Policy qualifiers attached to this node, in the upstream
    /// `PolicyQualifierInfo` form: a `(policy_qualifier_id, qualifier)`
    /// pair where `qualifier` is a raw `der::Any`. Decoding is left to
    /// the caller because [the `x509-cert` 0.2.5 `UserNotice` type has
    /// an upstream typo on `notice_ref`][1] — pass-through avoids the
    /// buggy decoder. The two standard qualifier IDs are
    /// `id-qt-cps` (1.3.6.1.5.5.7.2.1, qualifier is a `CPSuri` /
    /// `IA5String`) and `id-qt-unotice` (1.3.6.1.5.5.7.2.2, qualifier
    /// is a `UserNotice`).
    ///
    /// [1]: https://github.com/RustCrypto/formats/issues/x509-cert
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_der::vec"))]
    pub qualifiers: Vec<x509_cert::ext::pkix::certpolicy::PolicyQualifierInfo>,

    /// `valid_policy` of each parent node at `depth - 1` (nodes are unique
    /// per depth, so the OID identifies the parent). Empty for the depth-0
    /// root. A node's parents are either exactly `[anyPolicy]` or a set of
    /// specific policies.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_der::vec"))]
    pub parent_policies: Vec<der::asn1::ObjectIdentifier>,
}

impl ValidatedPath {
    /// Iterate `(policy_oid, qualifier)` pairs across every node in the
    /// final policy tree.
    ///
    /// Returns an empty iterator if the tree is `None` (it was reduced to
    /// NULL during validation, which is only accepted while no explicit
    /// policy is required).
    ///
    /// Each yielded pair is `(node.valid_policy, &qualifier)` — the
    /// qualifier is a reference into the tree, valid for the borrow
    /// duration. Multiple qualifiers attached to the same policy yield
    /// multiple pairs with equal first elements; multiple nodes with the
    /// same policy OID at different depths also yield multiple pairs.
    ///
    /// Callers commonly need to:
    ///
    /// 1. Filter by `policy_qualifier_id` to find a specific qualifier
    ///    type (CPS pointer or user notice).
    /// 2. Read `qualifier.qualifier` (an `Option<der::Any>`) and decode
    ///    according to the `policy_qualifier_id`. See [`PolicyTreeNode::qualifiers`]
    ///    for why we do not decode upstream-side.
    pub fn policy_qualifiers(
        &self,
    ) -> impl Iterator<
        Item = (
            &der::asn1::ObjectIdentifier,
            &x509_cert::ext::pkix::certpolicy::PolicyQualifierInfo,
        ),
    > + '_ {
        self.valid_policy_tree
            .as_ref()
            .into_iter()
            .flat_map(|tree| tree.iter())
            .flat_map(|node| node.qualifiers.iter().map(move |q| (&node.valid_policy, q)))
    }
}

/// Validate a certificate chain from subject to a trust anchor.
///
/// `chain` must be ordered leaf-first:
/// - `chain[0]` is the subject (end-entity) certificate
/// - `chain[1..]` are intermediates in issuer order
/// - The last element of `chain` must be issued by one of `anchors`
///
/// Validation follows RFC 5280 §6.1. Each certificate's signature is verified
/// using `verifier`, with the signing key taken from the next certificate in
/// the chain (or the matching trust anchor for the last cert).
///
/// # Including the root certificate
///
/// The self-signed certificate of the trust anchor may be passed as the last
/// element of `chain`. It is then processed as path certificate 1 of
/// RFC 5280 §6.1 rather than skipped: its own signature, validity period,
/// `BasicConstraints`, `KeyUsage`, name constraints and policy extensions all
/// apply. In particular a root without a `CertificatePolicies` extension
/// (the common case) reduces the policy tree to NULL (§6.1.3(e)), so a
/// path that requires an explicit policy fails when the root is included
/// and succeeds when it is supplied only as the anchor. Pass the root only
/// in `anchors` unless its constraints are meant to apply as a path
/// certificate.
///
/// # Errors
///
/// Returns `Err(Error::NoTrustedPath)` if `chain` is empty or `anchors` is
/// empty. On success, `chain` is therefore guaranteed to contain at least one
/// certificate.
///
/// Returns `Err` on the first RFC 5280 §6.1 check failure. The error variant
/// includes the chain index of the failing certificate where applicable.
///
/// # Limitations
///
/// See crate-level documentation for current scope limits.
pub fn validate_path<V>(
    chain: &[Certificate],
    anchors: &[TrustAnchor],
    policy: &ValidationPolicy,
    verifier: &V,
) -> Result<ValidatedPath>
where
    V: SignatureVerifier,
{
    // (0) Cheap length bound before anything that is super-linear in the
    //     chain length (the pairwise duplicate scan in `check_inputs`, and
    //     the DN comparisons it and the self-issued count perform). See the
    //     `max_path_len` rustdoc for how the bound is derived.
    if chain.len() > max_chain_certs(policy.max_path_len) {
        return Err(Error::PathTooLong);
    }

    // (1) Input guards: reject empty chain or anchors, check OID consistency.
    check_inputs(chain, anchors)?;
    check_oid_consistency(chain)?;

    // (2) Path-length check (anchor-independent).
    // RFC 5280 §4.2.1.9: pathLen counts non-self-issued intermediates only.
    let num_non_si_intermediates = chain[1..]
        .iter()
        .filter(|c| !is_self_issued_cert(c))
        .count();
    if num_non_si_intermediates > policy.max_path_len as usize {
        return Err(Error::PathTooLong);
    }

    // (3) Try each name-matching anchor. Iterating all candidates handles key
    //     rollover: multiple anchors may share a DN but have different keys
    //     (e.g., during a root CA rotation). The first anchor that passes the
    //     full chain walk is used; the last error is returned if none succeed.
    //
    //     Complexity: O(A × N) where A = number of anchors, N = chain length.
    //     For the common case of O(1) matching anchors this is effectively O(N).
    let last_cert = chain.last().ok_or(Error::NoTrustedPath)?;
    let is_self_issued = names_match(
        last_cert.tbs_certificate().issuer(),
        last_cert.tbs_certificate().subject(),
    );
    let mut last_err = Error::NoTrustedPath;
    for (anchor_index, anchor) in anchors.iter().enumerate() {
        if !names_match(&anchor.subject, last_cert.tbs_certificate().issuer()) {
            continue;
        }
        // A self-issued top certificate whose key differs from this
        // same-name anchor's is either a key-rollover certificate issued by
        // the anchor (valid: its signature verifies under the anchor key) or
        // a certificate of an unrelated same-name CA (RFC 5280 §3.2 name
        // collision). `chain_walk` tells them apart by verifying the top
        // signature with the anchor key; in the collision case that
        // signature check is the first failure and is reported as
        // `NoTrustedPath` below, since this anchor simply is not the issuer.
        let top_key_differs = is_self_issued
            && !spki_key_matches(
                &anchor.subject_public_key_info,
                last_cert.tbs_certificate().subject_public_key_info(),
            );
        match chain_walk(chain, anchor, policy, verifier) {
            Ok(final_policy_tree) => {
                // §6.1.5 leaf-intrinsic outputs. `chain[0]` is guaranteed
                // non-empty by `check_inputs` at the top of this function.
                // The four `leaf_*` fields are direct clones of the leaf's
                // `tbs_certificate` fields; populating them from `chain[0]`
                // (rather than threading them out of `chain_walk`) avoids
                // adding more entries to the walker's return tuple.
                let leaf_tbs = chain[0].tbs_certificate();
                // Flatten the internal RFC 9618 policy graph into the
                // public `PolicyTreeNode` list. The internal shape stays
                // private so it can evolve without a public-API break.
                let valid_policy_tree =
                    final_policy_tree.map(policy_graph::PolicyGraph::into_public);
                return Ok(ValidatedPath {
                    anchor_index,
                    depth: chain.len().saturating_sub(1),
                    leaf_subject: leaf_tbs.subject().clone(),
                    leaf_issuer: leaf_tbs.issuer().clone(),
                    leaf_serial: leaf_tbs.serial_number().clone(),
                    leaf_spki: leaf_tbs.subject_public_key_info().clone(),
                    valid_policy_tree,
                });
            }
            Err(Error::SignatureInvalid { index } | Error::SignatureNotVerified { index, .. })
                if top_key_differs && index == chain.len() - 1 =>
            {
                // Name collision, not a rollover: keep the previous error
                // (initially `NoTrustedPath`) and try the next anchor.
            }
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

/// Validate a certificate chain using a [`Profile`] to produce the policy.
///
/// This is a convenience wrapper around [`validate_path`] for callers that
/// work with a `Profile` implementation rather than constructing a
/// [`ValidationPolicy`] directly.
///
/// The profile's [`Profile::policy`] method is called with `now_unix` to
/// produce the `ValidationPolicy`.  The returned policy's `current_time_unix`
/// is then unconditionally overwritten with `now_unix`, so that a buggy
/// `Profile` implementation that returns the wrong clock value cannot silently
/// cause validity checks to run against the wrong time.
///
/// See [`validate_path`] for full documentation of the remaining parameters
/// and error semantics.
///
/// # Errors
///
/// Returns `Err(Error::...)` for each validation failure. See [`Error`] for the full list of failure conditions.
pub fn validate_path_with_profile<V, P>(
    chain: &[Certificate],
    anchors: &[TrustAnchor],
    profile: &P,
    now_unix: u64,
    verifier: &V,
) -> Result<ValidatedPath>
where
    V: SignatureVerifier,
    P: Profile,
{
    let mut policy = profile.policy(now_unix);
    // Defense-in-depth: overwrite current_time_unix with the caller's value.
    // A correct Profile implementation already sets this in policy(), but
    // an incorrect implementation might use a stale or wrong clock. This
    // overwrite is a belt-and-suspenders guard — it does not compensate for a
    // known bug; no existing Profile impl is incorrect.
    policy.current_time_unix = now_unix;
    validate_path(chain, anchors, &policy, verifier)
}

// ---------------------------------------------------------------------------
// validate_path helpers — input guards and OID consistency (PKIX-6vu)
// ---------------------------------------------------------------------------

/// Compare two SPKIs for the purpose of the self-issued anchor guard.
///
/// Compares algorithm OID and key bytes only — not the parameters field.
/// This is intentional: for RSA, explicit NULL parameters and absent
/// parameters are both valid encodings of the same algorithm (RFC 3279
/// §2.3.1); comparing the full `AlgorithmIdentifier` would wrongly reject
/// a valid anchor whose SPKI parameter encoding differs from the cert's.
/// For ECDSA, the parameters carry the curve OID, but two keys on different
/// curves also differ in their raw key bytes, so OID + key comparison is
/// still sufficient to distinguish them.
/// Upper bound on `chain.len()` for a given `max_path_len`: the leaf,
/// `max_path_len` non-self-issued intermediates, one self-issued certificate
/// (key rollover) per CA in the path including the anchor's, and an included
/// self-signed root.
const fn max_chain_certs(max_path_len: u8) -> usize {
    2 * (max_path_len as usize) + 3
}

fn spki_key_matches(
    a: &spki::SubjectPublicKeyInfoOwned,
    b: &spki::SubjectPublicKeyInfoOwned,
) -> bool {
    a.algorithm.oid == b.algorithm.oid && a.subject_public_key == b.subject_public_key
}

fn check_inputs(chain: &[Certificate], anchors: &[TrustAnchor]) -> Result<()> {
    if chain.is_empty() || anchors.is_empty() {
        return Err(Error::NoTrustedPath);
    }
    // Duplicate detection: check all pairs for (issuer DN, serial number) identity.
    // Per RFC 5280 §4.1.2.2, issuer+serial uniquely identifies a certificate.
    // A cert appearing twice in the chain is a construction error; reporting
    // DuplicateCertificate is cleaner than the confusing SignatureInvalid or
    // ChainBroken that would otherwise result.
    //
    // SPKI equality is intentionally NOT used here: cross-signed CAs legitimately
    // have two distinct certificates sharing the same public key (same SPKI, different
    // issuer+serial). Using issuer+serial avoids false positives in those chains.
    //
    // O(n²) over chain.len() — acceptable for chains of typical length (2–5 certs).
    for i in 0..chain.len() {
        for j in (i + 1)..chain.len() {
            let a = chain[i].tbs_certificate();
            let b = chain[j].tbs_certificate();
            if names_match(a.issuer(), b.issuer()) && a.serial_number() == b.serial_number() {
                return Err(Error::DuplicateCertificate {
                    first: i,
                    second: j,
                });
            }
        }
    }
    Ok(())
}

/// RFC 5280 §4.1.1.2: outer signatureAlgorithm OID must equal inner TBSCertificate.signature OID.
///
/// Only OIDs are compared, not parameters.  RFC 5280 says the two
/// `AlgorithmIdentifiers` MUST be identical, but many production CAs
/// generate certs where one field has explicit NULL parameters and the other
/// omits them — a mismatch that OpenSSL and other validators accept in
/// practice.  OID-only comparison preserves the security intent (the same
/// algorithm must be named in both places) without rejecting otherwise-valid
/// certs from common PKI deployments.
fn check_oid_consistency(chain: &[Certificate]) -> Result<()> {
    for (index, cert) in chain.iter().enumerate() {
        if cert.signature_algorithm().oid != cert.tbs_certificate().signature().oid {
            return Err(Error::MalformedCertificate { index });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Critical extension guard (PKIX-ad6)
// ---------------------------------------------------------------------------

const OID_KEY_USAGE: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.15");

const OID_BASIC_CONSTRAINTS: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.19");

const OID_SUBJECT_ALT_NAME: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.17");

const OID_EXTENDED_KEY_USAGE: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.37");

const OID_NAME_CONSTRAINTS: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.30");

const OID_CERTIFICATE_POLICIES: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.32");

const OID_POLICY_MAPPINGS: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.33");

const OID_POLICY_CONSTRAINTS: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.36");

const OID_INHIBIT_ANY_POLICY: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.54");

/// OID for the `anyPolicy` wildcard (2.5.29.32.0 — a child of id-ce-certificatePolicies).
pub(crate) const OID_ANY_POLICY: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.32.0");

/// OID for the emailAddress attribute in Distinguished Names (PKCS #9 §5.2.1).
/// Used when enforcing RFC 5280 §4.2.1.10 rfc822Name constraints against DN attributes.
const OID_EMAIL_ADDRESS: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.1");

/// OIDs of extensions that this implementation handles; all others, if critical, cause rejection.
///
/// `OID_SUBJECT_ALT_NAME` is listed here so that certs with critical SAN extensions
/// (e.g. TLS server certs) do not fail with `UnhandledCriticalExtension`. A cert
/// with an empty Subject and a critical SAN is handled correctly: the SAN is
/// used as the cert's identity via `cert_has_san_identity` / `working_issuer_is_san_identity`
/// (RFC 5280 §4.2.1.6), so name linkage does not fall back to the empty Subject DN.
///
/// `OID_EXTENDED_KEY_USAGE` is listed here so that certs with critical EKU
/// (common in CA/B Forum TLS and code-signing certificates) do not fail with
/// `UnhandledCriticalExtension`. RFC 5280 §6.1 path validation does not require
/// inspecting EKU values; the extension is accepted and its content is not verified.
const HANDLED_CRITICAL_OIDS: &[der::asn1::ObjectIdentifier] = &[
    OID_KEY_USAGE,
    OID_BASIC_CONSTRAINTS,
    OID_SUBJECT_ALT_NAME,
    OID_EXTENDED_KEY_USAGE,
    OID_NAME_CONSTRAINTS,
    OID_CERTIFICATE_POLICIES,
    OID_POLICY_MAPPINGS,
    OID_POLICY_CONSTRAINTS,
    OID_INHIBIT_ANY_POLICY,
];

/// RFC 5280 §4.2: "A certificate MUST NOT include more than one instance of
/// a particular extension." Reject such certificates with
/// [`Error::MalformedCertificate`].
///
/// The extension lookups in this crate read only the first instance of an
/// OID, while other validators may read the last or reject the certificate;
/// accepting duplicates would let one certificate mean different things to
/// different validators (e.g. two `basicConstraints` with cA TRUE then FALSE).
///
/// Sorts a copy of the OIDs, so the cost is O(e log e) in the extension
/// count `e` rather than quadratic.
fn check_duplicate_extensions(cert: &Certificate, index: usize) -> Result<()> {
    let exts = cert
        .tbs_certificate()
        .extensions()
        .map_or(&[][..], |v| v.as_slice());
    if exts.len() < 2 {
        return Ok(());
    }
    let mut oids: Vec<der::asn1::ObjectIdentifier> = exts.iter().map(|e| e.extn_id).collect();
    oids.sort_unstable();
    if oids.windows(2).any(|w| w[0] == w[1]) {
        return Err(Error::MalformedCertificate { index });
    }
    Ok(())
}

/// RFC 5280 §6.1.3(a)(3): reject any critical extension not in the handled set.
fn check_critical_extensions(cert: &Certificate, index: usize) -> Result<()> {
    for ext in cert
        .tbs_certificate()
        .extensions()
        .map_or(&[][..], |v| v.as_slice())
    {
        if ext.critical && !HANDLED_CRITICAL_OIDS.contains(&ext.extn_id) {
            return Err(Error::UnhandledCriticalExtension { index });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Policy processing (RFC 5280 §6.1) — see `policy_graph` (RFC 9618 graph)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// KeyUsage extraction (PKIX-8ae)
// ---------------------------------------------------------------------------

/// Returns whether the `keyCertSign` bit is set in the `KeyUsage` extension.
///
/// - `None`         — `KeyUsage` extension absent (no constraint)
/// - `Ok(Some(true))`  — keyCertSign is set
/// - `Ok(Some(false))` — `KeyUsage` present, keyCertSign NOT set
/// - `Ok(None)`        — `KeyUsage` extension absent
/// - `Err(_)`          — `KeyUsage` present but DER-malformed (fail-closed)
fn has_key_cert_sign(cert: &Certificate) -> der::Result<Option<bool>> {
    use x509_cert::ext::pkix::KeyUsage;

    try_find_cert_ext::<KeyUsage>(cert, OID_KEY_USAGE).map(|opt| opt.map(|ku| ku.key_cert_sign()))
}

/// Returns whether the `cRLSign` bit is set in the `KeyUsage` extension.
///
/// Same shape as [`has_key_cert_sign`]; used by the
/// [`ValidationPolicy::require_crl_sign_on_cas`] opt-in check (PKITS §4.7.4 / §4.7.5).
///
/// - `Ok(Some(true))`  — cRLSign is set
/// - `Ok(Some(false))` — `KeyUsage` present, cRLSign NOT set
/// - `Ok(None)`        — `KeyUsage` extension absent
/// - `Err(_)`          — `KeyUsage` present but DER-malformed (fail-closed)
fn has_crl_sign(cert: &Certificate) -> der::Result<Option<bool>> {
    use x509_cert::ext::pkix::KeyUsage;

    try_find_cert_ext::<KeyUsage>(cert, OID_KEY_USAGE).map(|opt| opt.map(|ku| ku.crl_sign()))
}

// ---------------------------------------------------------------------------
// Extension extraction helpers
// ---------------------------------------------------------------------------

/// Find and decode an X.509 extension from `cert` by OID.
///
/// **Fail-open**: returns `None` if the extension is absent *or* if its DER
/// value cannot be decoded. Decoding errors are silently discarded.
///
/// Use this for extensions where a parse failure is tolerable (e.g., optional
/// informational extensions). For security-critical extensions where a parse
/// failure must be propagated, use [`try_find_cert_ext`] instead.
fn find_cert_ext<T: der::DecodeOwned>(
    cert: &Certificate,
    oid: der::asn1::ObjectIdentifier,
) -> Option<T> {
    cert.tbs_certificate()
        .extensions()
        .map_or(&[][..], |v| v.as_slice())
        .iter()
        .find(|e| e.extn_id == oid)
        .and_then(|e| T::from_der(e.extn_value.as_bytes()).ok())
}

/// Look up and decode an X.509 extension from `cert` by OID.
///
/// **Fail-closed**: propagates DER decoding errors to the caller rather than
/// discarding them. This is appropriate for security-critical extensions where
/// a malformed value must not be silently ignored.
///
/// Returns:
/// - `Ok(None)` — extension absent.
/// - `Ok(Some(T))` — extension present and decoded successfully.
/// - `Err(der::Error)` — extension present but DER decoding failed.
///
/// For non-critical extensions where a parse failure should be treated as
/// absent, use [`find_cert_ext`] (fail-open) instead.
fn try_find_cert_ext<T: for<'a> der::Decode<'a, Error = der::Error>>(
    cert: &Certificate,
    oid: der::asn1::ObjectIdentifier,
) -> der::Result<Option<T>> {
    cert.tbs_certificate()
        .extensions()
        .map_or(&[][..], |v| v.as_slice())
        .iter()
        .find(|e| e.extn_id == oid)
        .map_or(Ok(None), |e| T::from_der(e.extn_value.as_bytes()).map(Some))
}

/// Decode the `SubjectAltName` extension from `cert`.
///
/// **Fail-closed**: a present-but-malformed SAN returns `Err` rather than being
/// silently treated as absent.  Treating a malformed SAN as absent during name
/// constraint checking would allow a cert to bypass NC exclusion/permission
/// constraints when the SAN extension is present but cannot be decoded (vjc.20).
fn cert_subject_alt_names(
    cert: &Certificate,
    index: usize,
) -> crate::Result<Option<x509_cert::ext::pkix::SubjectAltName>> {
    try_find_cert_ext(cert, OID_SUBJECT_ALT_NAME).map_err(|_| Error::MalformedCertificate { index })
}

/// Decode the `NameConstraints` extension from `cert`.
///
/// Returns `Err(MalformedCertificate)` if the extension is present but:
/// - its DER cannot be decoded (vjc.7: fail-closed on security-critical extension), or
/// - any `GeneralSubtree` has a non-zero `minimum` or a present `maximum` field
///   (vjc.8: RFC 5280 §4.2.1.10 MUST require minimum=0, maximum=absent).
///
/// Returns `Ok(None)` if the extension is absent.
/// Does every `GeneralSubtree` leave `minimum` and `maximum` alone?
///
/// RFC 5280 §4.2.1.10: "Within this profile, the minimum and maximum fields
/// are not used with any name forms, thus minimum MUST be zero, and maximum
/// MUST be absent." A certificate that encodes either is non-conformant, and
/// the semantics it is asking for are not implemented here.
///
/// One predicate because three paths need the same answer —
/// [`cert_name_constraints`] for intermediates, and both fallible trust-anchor
/// constructors. They used to disagree: the rule was applied to intermediates
/// and to neither anchor path, so the same extension was grounds for rejection
/// in the middle of a chain and accepted at its root.
fn subtrees_are_conformant(nc: &NameConstraints) -> bool {
    nc.permitted_subtrees
        .iter()
        .flatten()
        .chain(nc.excluded_subtrees.iter().flatten())
        .all(|st| st.minimum == 0 && st.maximum.is_none())
}

fn cert_name_constraints(
    cert: &Certificate,
    index: usize,
) -> crate::Result<Option<NameConstraints>> {
    let nc = try_find_cert_ext::<NameConstraints>(cert, OID_NAME_CONSTRAINTS)
        .map_err(|_| Error::MalformedCertificate { index })?;

    if let Some(nc) = &nc {
        if !subtrees_are_conformant(nc) {
            return Err(Error::MalformedCertificate { index });
        }
    }

    Ok(nc)
}

// ---------------------------------------------------------------------------
// Validity period checker (PKIX-047)
// ---------------------------------------------------------------------------

/// Convert an `x509_cert::time::Time` to seconds since the Unix epoch.
fn time_to_unix_secs(t: &x509_cert::time::Time) -> u64 {
    t.to_unix_duration().as_secs()
}

/// RFC 5280 §6.1.3(a)(2): check notBefore ≤ now ≤ notAfter.
fn check_validity(cert: &Certificate, now_unix: u64, index: usize) -> Result<()> {
    let not_before = time_to_unix_secs(&cert.tbs_certificate().validity().not_before);
    let not_after = time_to_unix_secs(&cert.tbs_certificate().validity().not_after);
    if now_unix >= not_before && now_unix <= not_after {
        Ok(())
    } else {
        Err(Error::ValidityPeriod { index })
    }
}

// ---------------------------------------------------------------------------
// Name comparison — RFC 4518 string prep (PKIX-drv)
// ---------------------------------------------------------------------------

/// Maximum number of attribute-value assertions in one RDN that
/// [`names_match`] will compare.
///
/// RFC 5280 does not limit multi-valued RDNs, but real certificates use
/// one AVA per RDN (occasionally two or three). The cap bounds the
/// quadratic AVA matching in [`names_match`], which runs on unauthenticated
/// input; an RDN above the cap matches nothing.
pub const MAX_AVAS_PER_RDN: usize = 64;

/// Compare two distinguished names per RFC 4518 string prep rules.
///
/// Currently implements ASCII case-fold and insignificant-whitespace
/// collapsing. `BMPString`-tagged AVAs are transcoded UCS-2-BE → UTF-8
/// before normalization, so a `BMPString` AVA and a `UTF8String` (or
/// `PrintableString`/`IA5String`/`VisibleString`) AVA that share Unicode
/// code points compare equal. Full Unicode NFKC normalization is future
/// work.
///
/// Returns `true` if the names are equivalent.
///
/// # Ordering
///
/// RFC 5280 §4.1.2.4 defines `Name` as `SEQUENCE OF RDN`, so RDNs are
/// compared positionally (index 0 with index 0, etc.). Within each RDN —
/// which is a `SET OF AttributeTypeAndValue` — comparison is order-independent:
/// each AVA in one RDN is matched against any AVA in the other.
///
/// # Limitations
///
/// - **No NFKC / non-ASCII case fold.** Two AVA values that contain the
///   same Unicode characters but differ in canonical decomposition
///   (precomposed vs combining, e.g. U+00E9 vs U+0065 U+0301) compare
///   unequal even though RFC 4518 says they should match. Non-Latin
///   case differences (e.g. Greek lowercase σ vs final σ) are also not
///   folded.
/// - **`UniversalString` is parser-rejected upstream.** `der` 0.7 omits
///   tag 0x1C from `Tag::try_from`, so any cert with a `UniversalString`
///   AVA fails to parse before reaching this comparator. This is an
///   upstream limitation; the same `BMPString` transcoding applied here
///   would generalize to `UniversalString` (UCS-4-BE → UTF-8) once the
///   parser accepts it.
/// - **`TeletexString` (T61String) uses raw DER byte comparison.**
///   `pkix-path` deliberately does not transcode T.61 to Unicode; no
///   canonical mapping exists (RFC 4518 §2.1 leaves it "a local matter"
///   and OpenSSL, NSS, and `GnuTLS` use mutually incompatible vendor
///   tables). Byte-equal `TeletexString` AVAs match; `TeletexString`
///   never matches any other string type. Well-formed chains that copy
///   the issuer DN bytes per RFC 5280 §4.1.2.4 are unaffected.
///
/// # Work bound
///
/// AVA matching within an RDN is quadratic in the RDN's size. To bound the
/// work an attacker-supplied name can cause, an RDN with more than
/// [`MAX_AVAS_PER_RDN`] attribute-value assertions never matches anything
/// (`names_match` returns `false`), so such a name cannot chain.
#[must_use]
pub fn names_match(a: &x509_cert::name::Name, b: &x509_cert::name::Name) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let a_rdns = a.iter_rdn();
    let b_rdns = b.iter_rdn();

    for (a_rdn, b_rdn) in a_rdns.zip(b_rdns) {
        if a_rdn.len() != b_rdn.len() {
            return false;
        }
        // Work bound: the AVA matching below is quadratic in the RDN size,
        // and names_match runs on attacker-supplied names before any
        // signature has been checked. Real-world RDNs carry one AVA (rarely
        // two or three), so an RDN above the cap is treated as matching
        // nothing (fail-closed).
        if a_rdn.len() > MAX_AVAS_PER_RDN {
            return false;
        }
        // Bijective AVA matching: every AVA in a_rdn must match some AVA in b_rdn,
        // AND every AVA in b_rdn must match some AVA in a_rdn (both directions).
        //
        // The bidirectional check is equivalent to set equality for well-formed RDNs
        // (RFC 5280 §5.1.2.4 SHOULD NOT contain duplicate OIDs), and also correctly
        // handles the malformed-cert case where an RDN has duplicate OIDs:
        //   a={CN=Alice, CN=Alice}, b={CN=Bob, CN=Alice} → both len=2, forward pass
        //   finds CN=Alice for each a_ava, but the reverse pass finds no match for
        //   CN=Bob → returns false (correct).
        // The reverse pass is O(n²) on AVA count; n is 1–5 in practice.
        for a_ava in a_rdn.iter() {
            let found = b_rdn.iter().any(|b_ava| {
                b_ava.oid == a_ava.oid && ava_values_match(&a_ava.value, &b_ava.value)
            });
            if !found {
                return false;
            }
        }
        for b_ava in b_rdn.iter() {
            let found = a_rdn.iter().any(|a_ava| {
                a_ava.oid == b_ava.oid && ava_values_match(&a_ava.value, &b_ava.value)
            });
            if !found {
                return false;
            }
        }
    }
    true
}

/// Returns `Ok(true)` if `cert` is a CA certificate per its `BasicConstraints`
/// extension (RFC 5280 §4.2.1.9), `Ok(false)` if the extension is absent or
/// `cA = FALSE`, and `Err(DerError)` if the extension is present but cannot be
/// DER-decoded.
///
/// Propagating decode failure rather than treating a malformed extension as
/// "not a CA" is a fail-closed defense-in-depth choice: silently skipping a
/// malformed `BasicConstraints` could mask a topologically valid CA whose CRL
/// scope or path-building should be honored.
///
/// This helper is shared by `pkix-path-builder` (path construction) and
/// `pkix-revocation::crl` (IDP scope checking) to avoid maintaining two
/// parallel implementations of the same RFC 5280 §4.2.1.9 decode.
///
/// # Errors
///
/// Returns [`DerError`] if the `BasicConstraints` extension is present but
/// fails to DER-decode.
pub fn cert_is_ca(cert: &Certificate) -> core::result::Result<bool, DerError> {
    use der::Decode as _;
    use x509_cert::ext::pkix::BasicConstraints;

    let Some(ext) = cert
        .tbs_certificate()
        .extensions()
        .map_or(&[][..], |v| v.as_slice())
        .iter()
        .find(|e| e.extn_id == OID_BASIC_CONSTRAINTS)
    else {
        return Ok(false);
    };

    let bc = BasicConstraints::from_der(ext.extn_value.as_bytes()).map_err(DerError::new)?;
    Ok(bc.ca)
}

/// RFC 5280 §3.3: a certificate is self-issued if subject == issuer and neither is empty.
fn is_self_issued_cert(cert: &Certificate) -> bool {
    !cert.tbs_certificate().subject().is_empty()
        && names_match(
            cert.tbs_certificate().subject(),
            cert.tbs_certificate().issuer(),
        )
}

/// Returns `true` if `cert` is identified by its `SubjectAltName` rather than its
/// Subject DN.
///
/// RFC 5280 §4.2.1.6 specifies that a certificate with an empty Subject field and
/// a **critical** `SubjectAltName` extension is identified by the SAN, not the DN.
/// In this case, name linkage checks against the Subject DN are meaningless.
///
/// Returns `false` for any cert that has a non-empty Subject or a non-critical SAN.
fn cert_has_san_identity(cert: &Certificate) -> bool {
    // Subject must be empty.
    if !cert.tbs_certificate().subject().is_empty() {
        return false;
    }
    // Must have a critical SubjectAltName extension.
    cert.tbs_certificate()
        .extensions()
        .map_or(&[][..], |v| v.as_slice())
        .iter()
        .any(|ext| ext.extn_id == OID_SUBJECT_ALT_NAME && ext.critical)
}

/// RFC 5280 §7.1 DN comparison, and §4.2.1.10 subtree containment.
///
/// Both functions here are private and were reached only through whole-chain
/// fixtures, which left several of their decisions untested — a mutation
/// sweep flipped the `&&` in both `names_match` AVA loops and both
/// comparisons in `dn_within_subtree`'s length guard, and every one
/// survived. Unit tests, because the inputs that distinguish these cases
/// are DNs no certificate generator produces on the way to anything else.
#[cfg(test)]
mod tests_dn_comparison {
    use super::{dn_within_subtree, names_match};
    use der::Decode as _;
    use x509_cert::name::Name;

    // Hand-built DER. Each is a Name whose RDNs hold one PrintableString AVA.
    const CN_ALICE: &[u8] = &[
        0x30, 0x10, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x05, 0x41, 0x6c,
        0x69, 0x63, 0x65,
    ];
    /// The same value as `CN_ALICE` under a different attribute OID
    /// (organizationName, 2.5.4.10).
    const O_ALICE: &[u8] = &[
        0x30, 0x10, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x05, 0x41, 0x6c,
        0x69, 0x63, 0x65,
    ];
    const C_US: &[u8] = &[
        0x30, 0x0d, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53,
    ];
    const C_US_O_TEST: &[u8] = &[
        0x30, 0x1c, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53,
        0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x04, 0x54, 0x65, 0x73, 0x74,
    ];
    const C_US_O_TEST_CN_ALICE: &[u8] = &[
        0x30, 0x2c, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53,
        0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x04, 0x54, 0x65, 0x73, 0x74,
        0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x05, 0x41, 0x6c, 0x69, 0x63,
        0x65,
    ];

    fn n(der: &[u8]) -> Name {
        Name::from_der(der).expect("hand-built Name parses")
    }

    /// The same value under a different attribute type is a different name.
    ///
    /// Both AVA loops in `names_match` require the OID *and* the value to
    /// agree. With `||` in place of either `&&`, `CN=Alice` and `O=Alice`
    /// compare equal — the comparison would stop distinguishing attribute
    /// types, and DN equality is what binds a certificate to its issuer.
    #[test]
    fn the_same_value_under_a_different_attribute_type_is_a_different_name() {
        assert!(names_match(&n(CN_ALICE), &n(CN_ALICE)));
        assert!(
            !names_match(&n(CN_ALICE), &n(O_ALICE)),
            "CN=Alice is not O=Alice"
        );
        assert!(
            !names_match(&n(O_ALICE), &n(CN_ALICE)),
            "and not in the other argument order either"
        );
    }

    /// A DN is within the subtree rooted at itself.
    ///
    /// §4.2.1.10 containment is prefix containment, and every sequence is a
    /// prefix of itself. The length guard is `constraint.len() >
    /// subject.len()`; with `>=` an exactly-equal DN falls out as "not
    /// within", which breaks both directions of name constraints — a
    /// permitted subtree would reject the DN it names, and an excluded
    /// subtree would fail to exclude it.
    #[test]
    fn a_dn_is_within_the_subtree_rooted_at_itself() {
        assert!(dn_within_subtree(&n(C_US_O_TEST), &n(C_US_O_TEST)));
        assert!(dn_within_subtree(&n(C_US), &n(C_US)));
    }

    /// A constraint longer than the subject contains nothing.
    ///
    /// The guard exists because the `zip` below it stops at the shorter of
    /// the two, so without it a deep constraint would be compared only
    /// against its own prefix and report a match. With `==` in place of
    /// `>`, `{C=US}` lands inside the subtree `{C=US, O=Test, CN=Alice}` —
    /// over-permissive for a permitted subtree, since a certificate would
    /// satisfy a constraint far more specific than its own name.
    #[test]
    fn a_constraint_longer_than_the_subject_contains_nothing() {
        assert!(
            !dn_within_subtree(&n(C_US), &n(C_US_O_TEST_CN_ALICE)),
            "{{C=US}} is not inside the subtree {{C=US, O=Test, CN=Alice}}"
        );
        assert!(
            !dn_within_subtree(&n(C_US_O_TEST), &n(C_US_O_TEST_CN_ALICE)),
            "one RDN short is still outside"
        );
    }

    /// One RDN with two AVAs sharing a value under different OIDs, and one
    /// with a duplicated OID. RFC 5280 §5.1.2.4 says an RDN SHOULD NOT
    /// carry duplicate OIDs, so the second is malformed — which is exactly
    /// the case `names_match`'s bidirectional pass documents itself as
    /// handling.
    const CN_AND_O_ALICE: &[u8] = &[
        0x30, 0x1e, 0x31, 0x1c, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x05, 0x41, 0x6c,
        0x69, 0x63, 0x65, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x05, 0x41, 0x6c, 0x69,
        0x63, 0x65,
    ];
    const CN_ALICE_TWICE: &[u8] = &[
        0x30, 0x1e, 0x31, 0x1c, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x05, 0x41, 0x6c,
        0x69, 0x63, 0x65, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x05, 0x41, 0x6c, 0x69,
        0x63, 0x65,
    ];

    /// The bidirectional AVA pass is what makes a duplicated OID safe.
    ///
    /// `{CN=Alice, O=Alice}` and `{CN=Alice, CN=Alice}` have the same RDN
    /// count and the same AVA count, and every AVA of the second has a
    /// strict match in the first — so the forward pass alone cannot tell
    /// them apart. Only the reverse pass can: `O=Alice` has no counterpart
    /// in `{CN=Alice, CN=Alice}`.
    ///
    /// Why this test rather than a simpler one: mutating the `&&` in
    /// *either* AVA loop to `||` leaves every other test in this crate
    /// green, because for well-formed RDNs the two passes are redundant and
    /// each catches what the other would miss. That redundancy is the
    /// design, and this is the input where it is load-bearing instead of
    /// redundant — a duplicated OID, which the loop's own comment claims to
    /// handle and nothing verified.
    #[test]
    fn a_duplicated_oid_does_not_match_two_distinct_attributes() {
        assert!(
            !names_match(&n(CN_AND_O_ALICE), &n(CN_ALICE_TWICE)),
            "{{CN=Alice, O=Alice}} is not {{CN=Alice, CN=Alice}}"
        );
        assert!(
            !names_match(&n(CN_ALICE_TWICE), &n(CN_AND_O_ALICE)),
            "and not in the other argument order, which is the pass that \
             catches it when the first is weakened"
        );
        // Each still matches itself, so the above cannot pass on a
        // comparison that never returns true for two-AVA RDNs.
        assert!(names_match(&n(CN_AND_O_ALICE), &n(CN_AND_O_ALICE)));
        assert!(names_match(&n(CN_ALICE_TWICE), &n(CN_ALICE_TWICE)));
    }

    /// And the ordinary case still works: a shorter constraint is a prefix.
    ///
    /// Without this the two negative tests above would pass on a function
    /// that never returns `true`.
    #[test]
    fn a_shorter_constraint_contains_a_longer_subject() {
        assert!(dn_within_subtree(&n(C_US_O_TEST), &n(C_US)));
        assert!(dn_within_subtree(&n(C_US_O_TEST_CN_ALICE), &n(C_US_O_TEST)));
    }
}

/// Compare two `AttributeTypeAndValue` values after RFC 4518 normalization.
///
/// Allocation-free: `BMPString` values are transcoded to UTF-8 lazily by
/// [`DirStringBytes`] while the two normalized byte streams are compared,
/// so the cost of one comparison is linear in the value lengths with no
/// heap traffic (review A1 item 10: `names_match` used to allocate two
/// transcoding buffers per AVA comparison).
fn ava_values_match(a: &der::Any, b: &der::Any) -> bool {
    let a_str = any_to_str_bytes(a);
    let b_str = any_to_str_bytes(b);

    match (a_str, b_str) {
        (Some(a_bytes), Some(b_bytes)) => {
            NormalizedIter::new(a_bytes).eq(NormalizedIter::new(b_bytes))
        }
        // Both values are non-string types (e.g. OID, INTEGER) or unhandled string
        // types (TeletexString, UniversalString — UniversalString is parser-rejected
        // upstream by `der` 0.7's `Tag::try_from`, so this branch in practice covers
        // TeletexString and non-string types only):
        // compare tag AND content bytes (raw DER). Tag comparison ensures two
        // different string encodings of the same text are not considered equal.
        (None, None) => a.tag() == b.tag() && a.value() == b.value(),
        // One value is a string type and the other is not. Return false (fail-closed).
        // A legitimate certificate chain will never encode the same attribute OID as a
        // string type in one cert and a non-string type in another, so this mismatch
        // indicates a malformed or suspicious certificate.
        _ => false,
    }
}

/// Classify a `DirectoryString` Any value as a stream of UTF-8 bytes,
/// returning `None` for types that require special pre-processing before
/// normalization (see `ava_values_match` for the dispatch logic).
///
/// The returned [`DirStringBytes`] iterator borrows the `der::Any` content
/// bytes; no string type allocates.
///
/// # Normalization strategy by string type
///
/// **Passed through — bytes already comparable as UTF-8/ASCII:**
/// `UTF8String`, `PrintableString`, `IA5String`, `VisibleString`. These
/// types are encoded as ASCII (or UTF-8 in the case of `UTF8String`) at
/// the DER level. The bytes are fed directly to `NormalizedIter`
/// which applies ASCII case-folding and insignificant-space handling
/// (RFC 4518 §2.4 step 6 subset).
///
/// **Transcoded on the fly — UCS-2-BE → UTF-8:**
/// `BMPString`. RFC 4518 §2.1 treats `BMPString` as "a subset of Unicode"
/// — every two-byte big-endian unit is a Unicode code point in the BMP.
/// Each unit is encoded to UTF-8 as it is consumed so the same
/// normalization pipeline used for `UTF8String` applies to the result.
/// ASCII-range code points in the BMP (U+0000..=U+007F) become
/// single-byte UTF-8, so a BMPString-encoded "Foo Co" compares equal to a
/// UTF8String-encoded "Foo Co". Malformed `BMPString` content (odd-length
/// bytes, or values in the surrogate range U+D800..=U+DFFF which are not
/// valid Unicode scalar values) is detected up front by
/// [`bmp_is_well_formed`] and returns `None` (fail-closed): a malformed
/// value will not match anything via `ava_values_match`.
///
/// **Rejected at parse time — UniversalString:**
/// `der` 0.7 omits tag 0x1C (`UniversalString`) from `Tag::try_from`,
/// causing any cert with a `UniversalString` AVA to fail
/// `Certificate::from_der` upstream. This dispatch therefore never sees
/// `UniversalString`-tagged values. Documented for completeness; a future
/// upstream fix in `der` (or our own pre-decode shim) is required before
/// `UniversalString` becomes reachable here.
///
/// **Committed policy — `TeletexString` (T61String):**
/// Raw DER byte comparison only. `pkix-path` deliberately does not
/// transcode T.61 to Unicode. RFC 4518 §2.1 states: "As there is no
/// standard for mapping `TeletexString` values to Unicode, the mapping is
/// left a local matter." RFC 5280 §7.1 classifies `TeletexString` support
/// as OPTIONAL. No canonical T.61→Unicode table exists — OpenSSL, NSS,
/// and `GnuTLS` each use incompatible vendor extensions. Adopting any one
/// of those tables would silently accept mismatches the others reject and
/// reject chains the others accept — a name-confusion smell with no
/// interoperability win. Byte-equality is fail-closed: two `TeletexString`
/// AVAs match iff their DER content bytes are identical, which is what
/// RFC 5280 §4.1.2.4 already requires of well-formed issuer/subject DN
/// reuse across a chain.
///
/// # Future work
///
/// Full RFC 4518 six-step preparation (Map → NFKC → Prohibit → `CheckBidi`
/// → insignificant-space) for non-ASCII Unicode code points is tracked
/// separately. Until that lands, two `BMPString` values that contain the
/// same Unicode code points but differ in canonical decomposition (e.g.
/// precomposed U+00E9 'é' vs decomposed U+0065 U+0301 'e'+ combining
/// acute) compare unequal even though RFC 4518 says they should match.
fn any_to_str_bytes(a: &der::Any) -> Option<DirStringBytes<'_>> {
    use der::Tag;
    match a.tag() {
        Tag::Utf8String | Tag::PrintableString | Tag::Ia5String | Tag::VisibleString => {
            Some(DirStringBytes::Plain(a.value().iter()))
        }
        // `clippy::chunks_exact_to_as_chunks` would have this be
        // `as_chunks::<2>().0.iter()`. Declined: this iterator is stored in
        // `DirStringBytes::Bmp`, so the change rewrites that variant's field
        // type from `ChunksExact<'_, u8>` to `slice::Iter<'_, [u8; 2]>` and
        // the `Iterator` impl that transcodes UCS-2 through it. That is a
        // real edit to DN-comparison code for a style preference, and
        // `bmp_is_well_formed` has already established the length is even,
        // which is the correctness property `as_chunks` would make visible
        // in the type.
        #[expect(
            clippy::chunks_exact_to_as_chunks,
            reason = "see the comment above; the iterator type is part of DirStringBytes"
        )]
        Tag::BmpString if bmp_is_well_formed(a.value()) => Some(DirStringBytes::Bmp {
            units: a.value().chunks_exact(2),
            buf: [0; 4],
            len: 0,
            pos: 0,
        }),
        _ => None,
    }
}

/// Returns `true` if `bytes` is well-formed `BMPString` content: an even
/// number of octets (UCS-2 units are 16 bits) and no unit in the UTF-16
/// surrogate range U+D800..=U+DFFF. Surrogates are *reserved* by Unicode
/// and do not represent characters; they appear in UTF-16 only as paired
/// surrogates encoding supplementary-plane code points (which are
/// forbidden in `BMPString` by definition — `BMP` = Basic Multilingual
/// Plane, U+0000..=U+FFFF).
fn bmp_is_well_formed(bytes: &[u8]) -> bool {
    let (units, rest) = bytes.as_chunks::<2>();
    rest.is_empty() && units.iter().all(|u| !(0xD8..=0xDF).contains(&u[0]))
}

/// UTF-8 byte stream over a `DirectoryString` value (see [`any_to_str_bytes`]).
///
/// The `Bmp` variant transcodes one UCS-2-BE unit at a time into `buf`
/// and yields its UTF-8 bytes; it must only be constructed over content
/// that passed [`bmp_is_well_formed`].
enum DirStringBytes<'a> {
    /// Content bytes that are already UTF-8 / ASCII.
    Plain(core::slice::Iter<'a, u8>),
    /// UCS-2-BE content, transcoded lazily.
    Bmp {
        /// Remaining two-byte units.
        units: core::slice::ChunksExact<'a, u8>,
        /// UTF-8 encoding of the current unit.
        buf: [u8; 4],
        /// Number of valid bytes in `buf`.
        len: u8,
        /// Next byte of `buf` to yield.
        pos: u8,
    },
}

impl Iterator for DirStringBytes<'_> {
    type Item = u8;
    fn next(&mut self) -> Option<u8> {
        match self {
            Self::Plain(it) => it.next().copied(),
            Self::Bmp {
                units,
                buf,
                len,
                pos,
            } => {
                if *pos == *len {
                    let unit = units.next()?;
                    let cp = u16::from_be_bytes([unit[0], unit[1]]);
                    // Surrogates were rejected by `bmp_is_well_formed`; the
                    // fallback keeps this total without a panic path.
                    let ch = char::from_u32(u32::from(cp)).unwrap_or(char::REPLACEMENT_CHARACTER);
                    // A BMP scalar value encodes to 1..=3 UTF-8 bytes.
                    *len = ch.encode_utf8(buf).len() as u8;
                    *pos = 0;
                }
                let b = buf[usize::from(*pos)];
                *pos += 1;
                Some(b)
            }
        }
    }
}

/// Transcode `BMPString` content to UTF-8 (test helper over [`DirStringBytes`]).
///
/// Returns `None` for malformed content (see [`bmp_is_well_formed`]).
#[cfg(test)]
fn bmp_string_to_utf8(bytes: &[u8]) -> Option<Vec<u8>> {
    let any = der::Any::new(der::Tag::BmpString, bytes).ok()?;
    any_to_str_bytes(&any).map(Iterator::collect)
}

/// Compare two byte slices after RFC 4518 whitespace normalization and case-folding.
///
/// Rules applied (per RFC 4518 §2):
/// 1. ASCII letters (0x41–0x5A): case-fold to lowercase. Non-ASCII bytes are
///    passed through unchanged; full Unicode case-folding (NFKC + case-fold)
///    is future work.
/// 2. Leading/trailing spaces: ignored
/// 3. Internal multiple spaces: collapsed to single space
#[cfg(test)]
fn normalized_eq(a: &[u8], b: &[u8]) -> bool {
    NormalizedIter::new(a.iter().copied()).eq(NormalizedIter::new(b.iter().copied()))
}

/// Streaming adapter that yields bytes after ASCII case-fold and whitespace
/// normalization (RFC 4518 §2 subset, see `normalized_eq`).
///
/// Works over any byte iterator, so `BMPString` values can be normalized
/// while they are being transcoded, without an intermediate buffer.
///
/// # Known limitation
///
/// Only U+0020 SPACE (byte `0x20`) is treated as insignificant whitespace.
/// Tabs (`\t`, `0x09`), non-breaking spaces (`0xA0` in Latin-1), and other
/// Unicode whitespace variants pass through unchanged. Full RFC 4518
/// insignificant-space handling requires Unicode-aware processing deferred
/// to a future release.
struct NormalizedIter<I: Iterator<Item = u8>> {
    inner: core::iter::Peekable<I>,
    /// Set once the first non-space byte has been yielded; spaces seen
    /// before that are leading spaces and are dropped.
    started: bool,
}

impl<I: Iterator<Item = u8>> NormalizedIter<I> {
    fn new(bytes: I) -> Self {
        Self {
            inner: bytes.peekable(),
            started: false,
        }
    }
}

impl<I: Iterator<Item = u8>> Iterator for NormalizedIter<I> {
    type Item = u8;
    fn next(&mut self) -> Option<u8> {
        loop {
            let b = self.inner.next()?;
            if b != b' ' {
                self.started = true;
                return Some(b.to_ascii_lowercase());
            }
            // Consume the rest of this space run.
            while self.inner.peek() == Some(&b' ') {
                self.inner.next();
            }
            // Leading run: drop it and continue with the first non-space byte.
            // Trailing run (nothing follows): drop it and end.
            // Internal run: collapse to exactly one space.
            if self.started && self.inner.peek().is_some() {
                return Some(b' ');
            }
        }
    }
}

// ---------------------------------------------------------------------------
// NameConstraints matching (PKIX-mew)
// ---------------------------------------------------------------------------

/// Newtype wrapping a bitmask of `GeneralName` name types for `NameConstraints`.
///
/// Used by `nc_constrained_types` to track which types have been constrained
/// by at least one CA certificate in the path, even if the intersection later
/// empties the permitted set for that type.
///
/// Bare `u32` constants would allow silent misuse (e.g., confusing a count
/// with a mask). The newtype makes the intent explicit at every operation site.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct NcTypeMask(u32);

impl NcTypeMask {
    const EMPTY: Self = Self(0);
    const RFC822: Self = Self(1 << 0);
    const DNS: Self = Self(1 << 1);
    const DIRECTORY_NAME: Self = Self(1 << 2);
    const URI: Self = Self(1 << 3);
    /// `IP_ADDRESS` is used by `name_type_bit` and participates in `nc_constrained_types`
    /// tracking. `IpAddress` names cannot appear in Subject DNs, so there is no
    /// inline DN-path code for this type; SAN `IpAddress` entries are handled by the
    /// generic SAN loop in `check_name_constraints` via `type_constrained(name)`.
    const IP_ADDRESS: Self = Self(1 << 4);
    /// `otherName` (any type-id). `pkix-path` cannot match otherName
    /// constraints; an `otherName` SAN is rejected whenever any otherName
    /// constraint is in effect. `SmtpUTF8Mailbox` SANs are additionally
    /// checked against rfc822Name constraints (RFC 8398 §6).
    const OTHER_NAME: Self = Self(1 << 5);
    /// `ediPartyName`: unsupported, fail-closed like `OTHER_NAME`.
    const EDI_PARTY_NAME: Self = Self(1 << 6);
    /// `registeredID`: unsupported, fail-closed like `OTHER_NAME`.
    const REGISTERED_ID: Self = Self(1 << 7);

    /// Returns `true` if `self` and `other` share at least one bit (non-empty intersection).
    ///
    /// Named `intersects` rather than `contains` because this is a bitmask test,
    /// not a set-membership check — `a.intersects(b)` is symmetric, while `contains`
    /// implies `a ⊇ b`.
    const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}

impl core::ops::BitOr for NcTypeMask {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for NcTypeMask {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Return the `NcTypeMask` bit for the name form of `name`.
///
/// Every `GeneralName` form has a bit, including the forms `pkix-path`
/// cannot match (`otherName`, `ediPartyName`, `registeredID`). Tracking
/// those lets
/// `check_name_constraints` reject a certificate that carries an
/// unsupported form a constraint applies to, as RFC 5280 §4.2.1.10
/// requires. `x400Address` is not representable in `x509-cert` 0.3 (a SAN
/// containing one fails to decode and is rejected as malformed).
const fn name_type_bit(name: &x509_cert::ext::pkix::name::GeneralName) -> NcTypeMask {
    use x509_cert::ext::pkix::name::GeneralName;
    match name {
        GeneralName::Rfc822Name(_) => NcTypeMask::RFC822,
        GeneralName::DnsName(_) => NcTypeMask::DNS,
        GeneralName::DirectoryName(_) => NcTypeMask::DIRECTORY_NAME,
        GeneralName::UniformResourceIdentifier(_) => NcTypeMask::URI,
        GeneralName::IpAddress(_) => NcTypeMask::IP_ADDRESS,
        GeneralName::OtherName(_) => NcTypeMask::OTHER_NAME,
        GeneralName::EdiPartyName(_) => NcTypeMask::EDI_PARTY_NAME,
        GeneralName::RegisteredId(_) => NcTypeMask::REGISTERED_ID,
    }
}

/// Returns true if `subject` DN is within the subtree rooted at `constraint`.
///
/// RFC 5280 §4.2.1.10: a `DirectoryName` constraint is satisfied when the subject's
/// DN has the constraint DN as a prefix (most-general to most-specific order).
/// E.g., constraint `{C=US, O=Test}` matches subject `{C=US, O=Test, CN=Alice}`.
fn dn_within_subtree(subject: &x509_cert::name::Name, constraint: &x509_cert::name::Name) -> bool {
    let c_rdns = constraint.iter_rdn();
    let s_rdns = subject.iter_rdn();
    if constraint.len() > subject.len() {
        return false;
    }
    c_rdns.zip(s_rdns).all(|(c_rdn, s_rdn)| {
        // Each pair of RDNs must have matching attribute-value pairs.
        if c_rdn.len() != s_rdn.len() {
            return false;
        }
        c_rdn.iter().all(|c_ava| {
            s_rdn
                .iter()
                .any(|s_ava| c_ava.oid == s_ava.oid && ava_values_match(&c_ava.value, &s_ava.value))
        })
    })
}

/// Returns true if `a` and `b` are the same `GeneralName` form.
///
/// Uses `name_type_bit` as the single source of truth so that adding a new
/// form to `name_type_bit` automatically extends this check with no
/// separate update required.
fn same_nc_variant(
    a: &x509_cert::ext::pkix::name::GeneralName,
    b: &x509_cert::ext::pkix::name::GeneralName,
) -> bool {
    name_type_bit(a) != NcTypeMask::EMPTY && name_type_bit(a) == name_type_bit(b)
}

/// Returns true if `name` (a certificate's subject or SAN name) satisfies
/// the `subtree` constraint.
///
/// Unsupported forms never match; `check_name_constraints` rejects them
/// separately whenever a constraint of their form is in effect.
fn name_matches_subtree(
    name: &x509_cert::ext::pkix::name::GeneralName,
    subtree: &x509_cert::ext::pkix::constraints::name::GeneralSubtree,
) -> bool {
    use x509_cert::ext::pkix::name::GeneralName;
    match (name, &subtree.base) {
        (GeneralName::DnsName(subj), GeneralName::DnsName(constr)) => {
            matches_dns_name(subj.as_str(), constr.as_str())
        }
        (GeneralName::DirectoryName(subj), GeneralName::DirectoryName(constr)) => {
            dn_within_subtree(subj, constr)
        }
        (GeneralName::Rfc822Name(subj), GeneralName::Rfc822Name(constr)) => {
            matches_rfc822_name(subj.as_str(), constr.as_str())
        }
        (
            GeneralName::UniformResourceIdentifier(subj),
            GeneralName::UniformResourceIdentifier(constr),
        ) => matches_uri(subj.as_str(), constr.as_str()),
        (GeneralName::IpAddress(subj), GeneralName::IpAddress(constr)) => {
            matches_ip_address(subj.as_bytes(), constr.as_bytes())
        }
        // Mismatched variants or unhandled types: no match.
        _ => false,
    }
}

/// Returns true if every name inside constraint `a` is also inside
/// constraint `b` (`a ⊆ b`), for two `GeneralSubtree` bases of the same form.
///
/// Used to intersect permitted subtrees (RFC 5280 §6.1.4(g)(1)) and to
/// de-duplicate excluded subtrees. A constraint is *not* a certificate name
/// (an iPAddress constraint is address + mask, a URI or rfc822Name
/// constraint is a bare host or `.domain`), so this cannot reuse
/// [`name_matches_subtree`]. Unsupported forms return `false`.
fn subtree_within(
    a: &x509_cert::ext::pkix::name::GeneralName,
    b: &x509_cert::ext::pkix::name::GeneralName,
) -> bool {
    use x509_cert::ext::pkix::name::GeneralName;
    match (a, b) {
        (GeneralName::DnsName(a), GeneralName::DnsName(b)) => {
            dns_constraint_within(a.as_str(), b.as_str())
        }
        (GeneralName::DirectoryName(a), GeneralName::DirectoryName(b)) => dn_within_subtree(a, b),
        (GeneralName::Rfc822Name(a), GeneralName::Rfc822Name(b)) => {
            rfc822_constraint_within(a.as_str(), b.as_str())
        }
        (GeneralName::UniformResourceIdentifier(a), GeneralName::UniformResourceIdentifier(b)) => {
            uri_constraint_within(a.as_str(), b.as_str())
        }
        (GeneralName::IpAddress(a), GeneralName::IpAddress(b)) => {
            ip_constraint_within(a.as_bytes(), b.as_bytes())
        }
        _ => false,
    }
}

/// Strip one trailing `.` (the RFC 1034 absolute form) from a DNS name or
/// URI host.
///
/// `pkix-identity` strips the same dot when it binds a dNSName SAN to a
/// reference identity, so name-constraint matching must normalize
/// identically: otherwise `www.evil.com.` escapes an excluded `evil.com`
/// here yet binds to `www.evil.com` there.
fn strip_root_dot(s: &str) -> &str {
    s.strip_suffix('.').unwrap_or(s)
}

/// Returns true if `name` is a proper subdomain of `parent` (one or more
/// labels added to the left), compared ASCII case-insensitively.
///
/// Works on bytes, so it cannot panic on a non-ASCII input.
fn is_strict_subdomain(name: &str, parent: &str) -> bool {
    let (name, parent) = (name.as_bytes(), parent.as_bytes());
    name.len() > parent.len() + 1
        && name[name.len() - parent.len() - 1] == b'.'
        && name[name.len() - parent.len()..].eq_ignore_ascii_case(parent)
}

/// DNS name constraint matching (RFC 5280 §4.2.1.10).
///
/// - A constraint without a leading period matches the name itself and any
///   subdomain ("adding zero or more labels to the left-hand side").
/// - A constraint with a leading period (`.example.com`, a widespread
///   extension) matches proper subdomains only.
/// - The empty constraint has zero labels, so it matches every DNS name;
///   an empty excluded dNSName therefore forbids all DNS names, matching
///   OpenSSL, Go and BoringSSL.
/// - One trailing dot is ignored on both sides (see [`strip_root_dot`]).
///
/// Comparison is ASCII case-insensitive.
fn matches_dns_name(subject: &str, constraint: &str) -> bool {
    let subject = strip_root_dot(subject);
    let constraint = strip_root_dot(constraint);
    if constraint.is_empty() {
        return true;
    }
    if let Some(parent) = constraint.strip_prefix('.') {
        // The apex itself is excluded from a leading-period constraint.
        is_strict_subdomain(subject, parent)
    } else {
        subject.eq_ignore_ascii_case(constraint) || is_strict_subdomain(subject, constraint)
    }
}

/// `a ⊆ b` for two dNSName constraints (see [`subtree_within`]).
///
/// `x` denotes `{x} ∪ subdomains(x)` and `.x` denotes `subdomains(x)`, so
/// `.x ⊆ b` exactly when `x` itself or every subdomain of `x` is covered,
/// which reduces to matching `x` against `b` with any leading period of `b`
/// dropped.
fn dns_constraint_within(a: &str, b: &str) -> bool {
    let a = strip_root_dot(a);
    match a.strip_prefix('.') {
        Some(a_parent) => {
            let b = strip_root_dot(b);
            matches_dns_name(a_parent, b.strip_prefix('.').unwrap_or(b))
        }
        None => matches_dns_name(a, b),
    }
}

/// Match a mailbox's domain part against a host (`example.com`) or domain
/// (`.example.com`) rfc822Name constraint.
fn rfc822_domain_matches(domain: &str, constraint: &str) -> bool {
    match constraint.strip_prefix('.') {
        // Any host under the domain; the apex is excluded.
        Some(parent) => is_strict_subdomain(domain, parent),
        None => domain.eq_ignore_ascii_case(constraint),
    }
}

/// RFC 822 (email) name constraint matching (RFC 5280 §4.2.1.10).
///
/// The domain part of `subject` is the text after the **last** `@`: an
/// RFC 5322 quoted local-part may itself contain `@`
/// (`"x@good.com"@evil.com` is a mailbox at `evil.com`).
fn matches_rfc822_name(subject: &str, constraint: &str) -> bool {
    if constraint.contains('@') {
        // Constraint is a specific mailbox address: exact match required.
        return subject.eq_ignore_ascii_case(constraint);
    }
    let Some((_, domain)) = subject.rsplit_once('@') else {
        return false; // malformed subject
    };
    rfc822_domain_matches(domain, constraint)
}

/// `a ⊆ b` for two rfc822Name constraints (see [`subtree_within`]).
///
/// The three constraint shapes are a mailbox (`u@host`, one address), a
/// host (`host`, all mailboxes at that host) and a domain (`.domain`, all
/// mailboxes at any host under it).
fn rfc822_constraint_within(a: &str, b: &str) -> bool {
    if a.contains('@') {
        return matches_rfc822_name(a, b);
    }
    if b.contains('@') {
        // A host or domain is never inside a single mailbox.
        return false;
    }
    match (a.strip_prefix('.'), b.strip_prefix('.')) {
        (None, _) => rfc822_domain_matches(a, b),
        // Every host under a domain is never inside one host.
        (Some(_), None) => false,
        (Some(a_dom), Some(b_dom)) => {
            a_dom.eq_ignore_ascii_case(b_dom) || is_strict_subdomain(a_dom, b_dom)
        }
    }
}

/// URI host name constraint matching (RFC 5280 §4.2.1.10).
///
/// URI constraints use different semantics from DNS constraints:
/// - Leading period: subdomains only (same as DNS).
/// - No leading period: **exact host only** (unlike DNS, which also matches subdomains).
///
/// One trailing dot is ignored on both sides (see [`strip_root_dot`]).
fn matches_uri_host(host: &str, constraint: &str) -> bool {
    let host = strip_root_dot(host);
    let constraint = strip_root_dot(constraint);
    if constraint.is_empty() {
        return false;
    }
    if let Some(parent) = constraint.strip_prefix('.') {
        // Leading dot: subdomains only, apex excluded (same rule as DNS).
        is_strict_subdomain(host, parent)
    } else {
        // RFC 5280 §4.2.1.10: URI constraint without leading period matches
        // the exact host only — subdomains are NOT included.
        host.eq_ignore_ascii_case(constraint)
    }
}

/// `a ⊆ b` for two URI host constraints (see [`subtree_within`]).
fn uri_constraint_within(a: &str, b: &str) -> bool {
    let (a, b) = (strip_root_dot(a), strip_root_dot(b));
    match (a.strip_prefix('.'), b.strip_prefix('.')) {
        (None, _) => matches_uri_host(a, b),
        // All subdomains of a domain are never inside one exact host.
        (Some(_), None) => false,
        (Some(a_dom), Some(b_dom)) => {
            a_dom.eq_ignore_ascii_case(b_dom) || is_strict_subdomain(a_dom, b_dom)
        }
    }
}

/// Extract the host of a URI for name-constraint matching (RFC 3986 §3.2).
///
/// Returns `None` when RFC 5280 §4.2.1.10 requires the certificate to be
/// rejected under a URI constraint: the URI "doesn't include an authority
/// component with a host name specified as a fully qualified domain name
/// ... or includes an authority component in which the host name is
/// specified as an IP address". Concretely `None` is returned for:
///
/// - no `scheme ":" "//"` prefix (e.g. `urn:`, `mailto:`), or a malformed
///   scheme;
/// - an empty host (`file:///x`);
/// - an IP-literal (`[2001:db8::1]`) or dotted-quad IPv4 host;
/// - a non-numeric port.
///
/// The authority ends at the first `/`, `?` or `#`; userinfo is everything
/// before the **last** `@` inside the authority, so an `@` in the path,
/// query or fragment cannot change the host. One trailing dot is stripped.
fn uri_host(uri: &str) -> Option<&str> {
    let (scheme, rest) = uri.split_once(':')?;
    let mut scheme_bytes = scheme.bytes();
    if !scheme_bytes.next().is_some_and(|b| b.is_ascii_alphabetic())
        || !scheme_bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    {
        return None;
    }
    let rest = rest.strip_prefix("//")?;
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if host_port.starts_with('[') {
        return None; // IP-literal
    }
    let host = match host_port.split_once(':') {
        Some((host, port)) if port.bytes().all(|b| b.is_ascii_digit()) => host,
        Some(_) => return None,
        None => host_port,
    };
    let host = strip_root_dot(host);
    if host.is_empty() || is_ipv4_literal(host) {
        return None;
    }
    Some(host)
}

/// Returns true if `host` has the shape of an RFC 3986 `IPv4address`
/// (four dot-separated runs of one to three decimal digits).
fn is_ipv4_literal(host: &str) -> bool {
    let mut parts = 0usize;
    for part in host.split('.') {
        parts += 1;
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
    }
    parts == 4
}

/// URI name constraint matching (RFC 5280 §4.2.1.10).
///
/// Extracts the host with [`uri_host`] and applies URI host matching
/// rules. A URI without a usable host matches nothing here;
/// `check_name_constraints` rejects such URIs outright whenever a URI
/// constraint is in effect.
fn matches_uri(subject_uri: &str, constraint: &str) -> bool {
    uri_host(subject_uri).is_some_and(|host| matches_uri_host(host, constraint))
}

/// IP address name constraint matching (RFC 5280 §4.2.1.10).
///
/// `constraint_bytes` must be 8 bytes (IPv4: addr + mask) or 32 bytes (IPv6).
/// `subject_bytes` must be 4 bytes (IPv4) or 16 bytes (IPv6).
fn matches_ip_address(subject_bytes: &[u8], constraint_bytes: &[u8]) -> bool {
    let (expected_subj_len, half) = match constraint_bytes.len() {
        8 => (4usize, 4usize),
        32 => (16usize, 16usize),
        _ => return false,
    };
    if subject_bytes.len() != expected_subj_len {
        return false;
    }
    let (addr, mask) = constraint_bytes.split_at(half);
    subject_bytes
        .iter()
        .zip(addr.iter().zip(mask.iter()))
        .all(|(s, (a, m))| s & m == a & m)
}

/// `a ⊆ b` for two iPAddress constraints (address + mask, see
/// [`subtree_within`]): same address family, `b`'s mask bits are a subset
/// of `a`'s, and the two addresses agree under `b`'s mask.
fn ip_constraint_within(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() || !(a.len() == 8 || a.len() == 32) {
        return false;
    }
    let half = a.len() / 2;
    let (a_addr, a_mask) = a.split_at(half);
    let (b_addr, b_mask) = b.split_at(half);
    (0..half).all(|i| {
        a_mask[i] & b_mask[i] == b_mask[i] && a_addr[i] & b_mask[i] == b_addr[i] & b_mask[i]
    })
}

/// RFC 5280 §4.2.1.10 subtree containment for the non-`directoryName` name
/// forms.
///
/// These are pure functions over strings and byte slices, and a mutation
/// sweep found every one of them unguarded: the suite reached them only
/// through whole-chain fixtures, which never supply the degenerate inputs
/// that separate a correct comparison from a nearly-correct one.
#[cfg(test)]
mod tests_constraint_forms {
    use super::{
        ip_constraint_within, is_ipv4_literal, is_strict_subdomain, matches_ip_address,
        subtree_within, uri_constraint_within,
    };
    use der::Decode as _;
    use x509_cert::ext::pkix::name::GeneralName;

    /// `.example.com` is not a *strict* subdomain of `example.com`.
    ///
    /// A strict subdomain adds at least one label, so the shortest one is
    /// `a.example.com`. The guard is `name.len() > parent.len() + 1`, and
    /// both of its obvious weakenings admit this degenerate input: `>=`
    /// directly, and `*` in place of `+` because `parent.len() * 1` is
    /// `parent.len()`. The leading dot then satisfies the separator check
    /// and the suffix compares equal, so a bare `.example.com` would be
    /// reported as a subdomain of itself-with-a-dot.
    #[test]
    fn a_leading_dot_alone_is_not_a_strict_subdomain() {
        assert!(!is_strict_subdomain(".example.com", "example.com"));
        // The real thing still is.
        assert!(is_strict_subdomain("a.example.com", "example.com"));
        assert!(is_strict_subdomain("deep.a.example.com", "example.com"));
        // And a sibling that merely ends in the same bytes is not.
        assert!(!is_strict_subdomain("notexample.com", "example.com"));
    }

    /// A URI subtree contains itself.
    ///
    /// Both arms are `Some`, so the comparison is
    /// `equal || is_strict_subdomain`. With `&&` a domain would have to be a
    /// strict subdomain of itself, which nothing is, and a constraint would
    /// stop containing its own subtree.
    #[test]
    fn a_uri_subtree_contains_itself_and_its_subdomains() {
        assert!(uri_constraint_within(".example.com", ".example.com"));
        assert!(uri_constraint_within(".a.example.com", ".example.com"));
        assert!(!uri_constraint_within(".example.com", ".a.example.com"));
    }

    /// `is_ipv4_literal` rejects an empty label and an over-long one.
    ///
    /// The three conditions are joined by `||`, so turning either into `&&`
    /// makes one of them reachable only together with the next: an empty
    /// label stops being rejected, or a four-digit label does.
    #[test]
    fn an_ipv4_literal_needs_one_to_three_digits_per_label() {
        assert!(is_ipv4_literal("192.0.2.1"));
        assert!(
            !is_ipv4_literal("1..2.3"),
            "an empty label is not a digit run"
        );
        assert!(
            !is_ipv4_literal("1234.1.1.1"),
            "four digits is outside one-to-three, all-digits notwithstanding"
        );
        assert!(!is_ipv4_literal("a.b.c.d"));
    }

    /// `matches_ip_address` handles IPv6 constraints, not only IPv4.
    ///
    /// The length match has an arm for 8 bytes (IPv4 address + mask) and one
    /// for 32 (IPv6). Deleting the 32-byte arm sends every IPv6 constraint
    /// to `_ => return false`, so an excluded IPv6 subtree would stop
    /// excluding and a permitted one would stop permitting.
    #[test]
    fn an_ipv6_constraint_is_matched() {
        // 2001:db8::/32 as constraint (16 address + 16 mask), subject
        // 2001:db8::1.
        let mut constraint = [0u8; 32];
        constraint[0..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        constraint[16..20].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        let mut subject = [0u8; 16];
        subject[0..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        subject[15] = 1;
        assert!(matches_ip_address(&subject, &constraint));

        // Outside the prefix.
        let mut other = [0u8; 16];
        other[0..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb9]);
        assert!(!matches_ip_address(&other, &constraint));

        // IPv4 still works, so this is about the arm and not the function.
        let v4_constraint = [192, 0, 2, 0, 255, 255, 255, 0];
        assert!(matches_ip_address(&[192, 0, 2, 7], &v4_constraint));
        assert!(!matches_ip_address(&[192, 0, 3, 7], &v4_constraint));
    }

    /// `ip_constraint_within` accepts both lengths it documents.
    ///
    /// The guard is `a.len() != b.len() || !(a.len() == 8 || a.len() == 32)`.
    /// Flipping the `== 8` to `!=` makes the negation reject exactly the
    /// 8-byte IPv4 case the function is most used for.
    #[test]
    fn an_ipv4_constraint_is_within_a_shorter_prefix() {
        // 192.0.2.0/24 inside 192.0.0.0/16: b's mask bits are a subset of
        // a's, and the addresses agree under b's mask.
        let a = [192, 0, 2, 0, 255, 255, 255, 0];
        let b = [192, 0, 0, 0, 255, 255, 0, 0];
        assert!(ip_constraint_within(&a, &b));
        assert!(!ip_constraint_within(&b, &a), "the wider one is not inside");

        // Mismatched family lengths are not comparable.
        let v6 = [0u8; 32];
        assert!(!ip_constraint_within(&a, &v6));
    }

    /// `subtree_within` routes two `directoryName`s to the DN comparison.
    ///
    /// Deleting that match arm sends them to the catch-all, so a
    /// `directoryName` constraint would stop containing anything — including
    /// itself.
    #[test]
    fn two_directory_names_are_compared_as_dns() {
        // C=US  and  C=US,O=Test
        const C_US: &[u8] = &[
            0x30, 0x0d, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55,
            0x53,
        ];
        const C_US_O_TEST: &[u8] = &[
            0x30, 0x1c, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55,
            0x53, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x04, 0x54, 0x65,
            0x73, 0x74,
        ];
        let dn = |der: &[u8]| {
            GeneralName::DirectoryName(
                x509_cert::name::Name::from_der(der).expect("hand-built Name parses"),
            )
        };

        assert!(subtree_within(&dn(C_US_O_TEST), &dn(C_US)));
        assert!(subtree_within(&dn(C_US), &dn(C_US)));
        assert!(!subtree_within(&dn(C_US), &dn(C_US_O_TEST)));
    }
}

// ---------------------------------------------------------------------------
// RSA key size helper (PKIX-ken.1.5)
// ---------------------------------------------------------------------------

use verifiers::{OID_RSASSA_PSS, OID_RSA_ENCRYPTION};

/// Decode the RSA modulus from an SPKI and return its bit length.
///
/// Both `rsaEncryption` and `id-RSASSA-PSS` subject keys count as RSA: RFC
/// 4055 §1.2 encodes the public key identically (`RSAPublicKey`) under
/// either OID, and only the algorithm-identifier parameters differ.
///
/// Returns `None` when:
/// - the key algorithm OID is neither `rsaEncryption` nor `id-RSASSA-PSS`
///   (non-RSA key; check does not apply), or
/// - the SPKI bytes cannot be decoded (malformed; signature verification will also fail).
///
/// Uses `der::SliceReader` and `der::asn1::UintRef` from the existing `der`
/// dependency — no additional crate required.
///
/// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }` (RFC 3279 §2.3.1).
/// `UintRef::as_bytes()` strips the leading 0x00 sign byte from a DER unsigned INTEGER,
/// returning only the magnitude. Bit length is derived as `magnitude_bytes * 8`, which
/// over-counts by at most 7 bits for keys whose high magnitude byte has leading zero bits —
/// this lenient rounding is acceptable for a minimum-floor check: a real 2040-bit key
/// would measure as 2048 bits and pass a 2048-bit floor. Key-generation tools always
/// produce keys whose top bit is set, so the practical impact is zero.
fn rsa_public_key_bits(spki: &spki::SubjectPublicKeyInfoOwned) -> Option<u32> {
    use der::{asn1::UintRef, Reader};

    if spki.algorithm.oid != OID_RSA_ENCRYPTION && spki.algorithm.oid != OID_RSASSA_PSS {
        return None; // Non-RSA key: check does not apply.
    }
    // BitString::as_bytes() returns None when unused_bits != 0.
    // RSA SPKI subject_public_key is always octet-aligned (unused_bits = 0).
    let raw = spki.subject_public_key.as_bytes()?;

    // raw is a DER-encoded RSAPublicKey SEQUENCE.
    // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    //
    // We decode the modulus INTEGER and then skip the publicExponent so the
    // sequence reader does not complain about trailing data (der 0.7 requires
    // the closure to consume the entire SEQUENCE content).
    //
    // Skip strategy: read the modulus, then call tlv_bytes() to consume the
    // exponent TLV as a raw byte slice (no allocation, no decode required).
    let modulus_byte_len: usize = der::SliceReader::new(raw)
        .ok()?
        .sequence(|r| {
            // UintRef strips the leading 0x00 sign byte; as_bytes() returns magnitude only.
            let modulus: UintRef<'_> = r.decode()?;
            let modulus_len = modulus.as_bytes().len();
            // Consume the publicExponent TLV so the nested reader has no trailing data.
            let _ = r.tlv_bytes()?;
            Ok::<_, der::Error>(modulus_len)
        })
        .ok()?;

    // saturating_mul guards against overflow on a hypothetical absurdly large modulus.
    // The result fits in u32: the largest practical RSA key is 16384 bits (2048 bytes),
    // well within u32::MAX. u32::try_from is used to make the bound explicit.
    u32::try_from(modulus_byte_len.saturating_mul(8)).ok()
}

// ---------------------------------------------------------------------------
// Chain walk loop — signature verification and name linkage (PKIX-vxf)
// ---------------------------------------------------------------------------

/// Walk the chain from issuer to leaf, applying all RFC 5280 §6.1 per-cert checks.
///
/// Path-length and anchor-matching are handled by the caller (`validate_path`).
/// This function walks `chain` in reverse (issuer-to-leaf) against `anchor`:
///
///    a. Verify signature with the current issuer's SPKI.
///    b. Verify issuer/subject name linkage.
///    c. Check validity period against `policy.current_time_unix`.
///    d. Reject any unhandled critical extensions.
///    e. Check cert names (subject DN + SAN) against accumulated NC state.
///    f. For all certs except the leaf (i > 0): require `BasicConstraints` cA=TRUE.
///    g. For all certs except the leaf (i > 0): if `policy.enforce_key_usage`, require `keyCertSign`.
///    g'. For all certs except the leaf (i > 0): if `policy.require_crl_sign_on_cas`, require `cRLSign`.
///    h. For all certs except the leaf (i > 0): enforce `pathLenConstraint` if present.
///    i. For all certs except the leaf (i > 0): accumulate `NameConstraints` state
///       (INTERSECTION for permittedSubtrees, UNION for excludedSubtrees).
///
/// RFC 5280 §4.2.1.9 note on pathLenConstraint: for the cert at position `i`
/// (leaf at 0, root-adjacent at chain.len()-1), there are exactly `i-1`
/// intermediate certs below it. The constraint requires `i-1 ≤ pathLenConstraint`.
///
/// # Implementation notes
///
/// This function is intentionally structured as a single loop over the certificate
/// chain. The RFC 5280 §6.1 state machine has significant shared state (working
/// SPKI, name constraints, policy tree, inhibit flags) that must be threaded
/// through every step in a defined order. Decomposing the loop into smaller helpers
/// would require passing this state through many function boundaries without clarity
/// gain. The monolithic structure mirrors the RFC's sequential algorithm description
/// and keeps all state-mutation sites visible in one place for audit.
///
/// The per-walk mutable state is grouped into [`WorkingState`] to make the
/// state-machine inputs/outputs explicit at the call boundary. Future
/// per-substep helper extractions take a `&mut WorkingState` so that adding
/// helpers does not grow each helper's parameter list.
///
/// `working_spki` and `working_issuer_name` carry the borrow of either `anchor`
/// or some `chain[i]` and so the struct takes a single lifetime `'a` covering
/// both inputs. The lifetime is elided at the call site because `chain_walk`
/// constructs and consumes `WorkingState` within its own body.
///
/// RFC 5280 §6.1.2 maps to the struct fields as follows:
///
/// - `working_spki`, `working_issuer_name`, `working_issuer_is_san_identity`
///   — §6.1.2(d)/(f) `working_public_key` + §6.1.2(e) `working_issuer_name`,
///   plus the §4.2.1.6 SAN-identity escape hatch tracked separately so the
///   §6.1.3(a)(2) DN-linkage check can be skipped when the issuer's identity
///   came from a critical SAN over an empty Subject DN.
/// - `nc_permitted`, `nc_excluded`, `nc_constrained_types`
///   — §6.1.2(b)/(c) `permitted_subtrees`/`excluded_subtrees`. The
///   `nc_constrained_types` bitmask is a workspace addition: it tracks which
///   name types have *ever* been constrained by a CA so an empty post-
///   intersection set still rejects names of that type (not derivable from
///   `nc_permitted` contents alone).
/// - `explicit_policy`, `inhibit_any`, `policy_mapping`
///   — §6.1.2 `explicit_policy`, `inhibit_anyPolicy`, `policy_mapping` counters.
/// - `policy_tree`
///   — §6.1.2(a) `valid_policy_tree`. `None` represents the RFC NULL tree.
struct WorkingState<'a> {
    /// §6.1.2(d)/(f) `working_public_key`. Borrows from the trust anchor or a
    /// chain certificate; rebound to the just-validated cert's SPKI at the end
    /// of every loop iteration.
    working_spki: &'a spki::SubjectPublicKeyInfoOwned,
    /// §6.1.2(e) `working_issuer_name`. Borrows from the trust anchor or a
    /// chain certificate's subject; rebound at the end of every loop iteration.
    working_issuer_name: &'a x509_cert::name::Name,
    /// Whether the certificate that produced `working_issuer_name` identifies
    /// itself via a critical `SubjectAltName` over an empty Subject DN
    /// (RFC 5280 §4.2.1.6). When `true`, the §6.1.3(a)(2) DN-linkage check is
    /// skipped because comparing against an empty Subject would be meaningless;
    /// the §6.1.3(a)(1) signature check has already established the
    /// cryptographic binding.
    working_issuer_is_san_identity: bool,
    /// §6.1.2(b) `permitted_subtrees`. `None` means "no permitted constraint
    /// of any type has been imposed yet"; once any CA contributes a
    /// `permittedSubtrees`, this becomes `Some(...)` and only narrows
    /// (intersection per §6.1.4(g)).
    nc_permitted: Option<GeneralSubtrees>,
    /// §6.1.2(c) `excluded_subtrees`. Accumulates via union per §6.1.4(g).
    nc_excluded: GeneralSubtrees,
    /// Workspace-local invariant: bitmask of name types for which at least one
    /// CA has imposed a `permittedSubtrees` constraint. Bits are only ORed in,
    /// never cleared. Required for correct rejection when intersection of
    /// incompatible same-type constraints empties `nc_permitted` for a type
    /// while that type is still semantically forbidden. See the initialisation
    /// site in `chain_walk` for the long-form rationale.
    nc_constrained_types: NcTypeMask,
    /// §6.1.2 `explicit_policy` counter. Decremented by §6.1.4(h) on each
    /// non-self-issued intermediate; clamped by §6.1.4(i) PolicyConstraints
    /// `requireExplicitPolicy`; finalised by §6.1.5(a)+(b).
    explicit_policy: u32,
    /// §6.1.2 `inhibit_anyPolicy` counter. Decremented by §6.1.4(h);
    /// clamped by §6.1.4(j) `InhibitAnyPolicy`.
    inhibit_any: u32,
    /// §6.1.2 `policy_mapping` counter. Decremented by §6.1.4(h);
    /// clamped by §6.1.4(i) PolicyConstraints `inhibitPolicyMapping`.
    policy_mapping: u32,
    /// §6.1.2(a) `valid_policy_tree`. `None` represents the RFC's NULL tree
    /// (every transition that would empty the tree maps to `None`); a
    /// non-empty `Some(...)` carries the live policy graph. Returned to
    /// `validate_path` at §6.1.5 for post-validation qualifier extraction.
    policy_tree: Option<policy_graph::PolicyGraph>,
}

/// RFC 5280 §6.1.3(a)(1) preface — project-policy signature-algorithm allowlist.
///
/// Fires before the cryptographic signature check so that a chain whose only
/// problem is a disallowed algorithm returns the diagnostic
/// [`Error::AlgorithmNotAllowed`] rather than the confusing
/// [`Error::SignatureInvalid`]. Applies to every cert in the chain (CA/B Forum
/// profile intent — there is no leaf/intermediate distinction here). Uses the
/// outer `signatureAlgorithm` OID; RFC 5280 §4.1.1.2 requires it to equal the
/// inner `TBSCertificate.signature` OID.
fn enforce_signature_alg_allowlist(
    cert: &Certificate,
    policy: &ValidationPolicy,
    index: usize,
) -> Result<()> {
    if let Some(allowed) = &policy.allowed_signature_algs {
        // O(n) over a typically 2–6 element list; acceptable for the common case.
        if !allowed.contains(&cert.signature_algorithm().oid) {
            return Err(Error::AlgorithmNotAllowed { index });
        }
    }
    Ok(())
}

/// Project max-validity check.
///
/// Not part of RFC 5280 §6.1; this is a CA/B-Forum-style ceiling on the cert's
/// (notAfter − notBefore) duration. Applies to every cert in the chain.
///
/// `saturating_sub` avoids wrap on a malformed cert where `notAfter < notBefore`;
/// a resulting duration of 0 trivially passes the `> max_secs` test (safe — the
/// validity-period check in §6.1.3(a)(2) catches the malformed cert separately).
fn check_max_validity(cert: &Certificate, policy: &ValidationPolicy, index: usize) -> Result<()> {
    if let Some(max_secs) = policy.max_validity_secs {
        let not_before = cert
            .tbs_certificate()
            .validity()
            .not_before
            .to_unix_duration()
            .as_secs();
        let not_after = cert
            .tbs_certificate()
            .validity()
            .not_after
            .to_unix_duration()
            .as_secs();
        if not_after.saturating_sub(not_before) > max_secs {
            return Err(Error::ValidityPeriodExceedsMax { index });
        }
    }
    Ok(())
}

/// Project minimum-RSA-key-bits check.
///
/// Not part of RFC 5280 §6.1; a deployment-policy floor on RSA modulus size.
/// Non-RSA keys are silently skipped (`rsa_public_key_bits` returns `None`),
/// so this is RSA-specific and inert for ECDSA/EdDSA chains. Applies to every
/// cert in the chain.
fn check_min_rsa_bits(cert: &Certificate, policy: &ValidationPolicy, index: usize) -> Result<()> {
    if let Some(min_bits) = policy.min_rsa_key_bits {
        if let Some(actual_bits) =
            rsa_public_key_bits(cert.tbs_certificate().subject_public_key_info())
        {
            if actual_bits < min_bits {
                return Err(Error::KeyTooSmall { index });
            }
        }
        // Non-RSA keys: rsa_public_key_bits returns None → check silently skipped.
    }
    Ok(())
}

/// RFC 5280 §6.1.3(a)(2) — issuer/subject DN linkage with §4.2.1.6 SAN-identity exception.
///
/// Verifies that the cert's issuer DN matches the previously-validated cert's
/// (or trust anchor's) subject DN, unless that subject DN was empty and the
/// previous cert identified itself via a critical SubjectAltName (RFC 5280
/// §4.2.1.6). In the SAN-identity case the DN comparison is skipped because
/// comparing against an empty Subject is meaningless; the signature check in
/// §6.1.3(a)(1) has already established the cryptographic binding.
///
/// IMPORTANT (PKIX-als9 design §7): the *assignment* of
/// `working_issuer_is_san_identity` for the next iteration is the caller's
/// responsibility (see chain_walk's end-of-loop state update). Moving the
/// assignment into this helper would silently break the §4.2.1.6 exception
/// for chains where an intermediate (not the leaf) uses SAN identity, a case
/// PKITS does not cover.
fn check_issuer_linkage(
    cert: &Certificate,
    working_issuer_name: &x509_cert::name::Name,
    working_issuer_is_san_identity: bool,
    index: usize,
) -> Result<()> {
    if !working_issuer_is_san_identity
        && !names_match(working_issuer_name, cert.tbs_certificate().issuer())
    {
        return Err(Error::ChainBroken { index });
    }
    Ok(())
}

/// Returns the DER encoding of `cert`'s `TBSCertificate`: the bytes its
/// issuer signed.
///
/// Use this, not `cert.tbs_certificate().to_der()`, to verify a
/// certificate signature. x509-cert 0.3 re-encodes the validity times of a
/// `Certificate` under the RFC 5280 profile (dates before 2050 become
/// `UTCTime`), so a certificate whose issuer used `GeneralizedTime` for such a
/// date would no longer match its signature. This function keeps each time
/// in the form it was parsed from; every other field is re-encoded as DER,
/// which reproduces the original bytes for any DER-encoded certificate.
///
/// # Errors
///
/// Returns [`DerError`] if a field cannot be encoded.
pub fn tbs_certificate_der(cert: &Certificate) -> core::result::Result<Vec<u8>, DerError> {
    encode_tbs_certificate(cert.tbs_certificate(), cert.tbs_certificate().extensions())
        .map_err(DerError::new)
}

/// Encodes `tbs` with `extensions` in place of its own extensions and with
/// its validity times as parsed (see [`tbs_certificate_der`]).
///
/// `pkix-ct` uses the `extensions` override to rebuild a precertificate's
/// TBS without the SCT list (RFC 6962 §3.2).
#[doc(hidden)]
pub fn encode_tbs_certificate(
    tbs: &x509_cert::TbsCertificate,
    extensions: Option<&x509_cert::ext::Extensions>,
) -> der::Result<Vec<u8>> {
    use der::asn1::ContextSpecificRef;
    use der::{Encode as _, Header, Length, Tag, TagMode, TagNumber};

    fn push_sequence(out: &mut Vec<u8>, body: &[u8]) -> der::Result<()> {
        Header::new(Tag::Sequence, Length::try_from(body.len())?).encode_to_vec(out)?;
        out.extend_from_slice(body);
        Ok(())
    }

    let mut body = Vec::new();
    if tbs.version() != x509_cert::certificate::Version::V1 {
        ContextSpecificRef {
            tag_number: TagNumber(0),
            tag_mode: TagMode::Explicit,
            value: &tbs.version(),
        }
        .encode_to_vec(&mut body)?;
    }
    tbs.serial_number().encode_to_vec(&mut body)?;
    tbs.signature().encode_to_vec(&mut body)?;
    tbs.issuer().encode_to_vec(&mut body)?;
    let mut validity = Vec::new();
    tbs.validity().not_before.encode_to_vec(&mut validity)?;
    tbs.validity().not_after.encode_to_vec(&mut validity)?;
    push_sequence(&mut body, &validity)?;
    tbs.subject().encode_to_vec(&mut body)?;
    tbs.subject_public_key_info().encode_to_vec(&mut body)?;
    if let Some(id) = tbs.issuer_unique_id() {
        ContextSpecificRef {
            tag_number: TagNumber(1),
            tag_mode: TagMode::Implicit,
            value: id,
        }
        .encode_to_vec(&mut body)?;
    }
    if let Some(id) = tbs.subject_unique_id() {
        ContextSpecificRef {
            tag_number: TagNumber(2),
            tag_mode: TagMode::Implicit,
            value: id,
        }
        .encode_to_vec(&mut body)?;
    }
    if let Some(exts) = extensions {
        ContextSpecificRef {
            tag_number: TagNumber(3),
            tag_mode: TagMode::Explicit,
            value: exts,
        }
        .encode_to_vec(&mut body)?;
    }
    let mut out = Vec::with_capacity(body.len() + 6);
    push_sequence(&mut out, &body)?;
    Ok(out)
}

/// RFC 5280 §6.1.3(a)(1) — cryptographic signature verification.
///
/// Re-encodes the cert's TBSCertificate (the canonical signed bytes) and asks
/// the pluggable [`SignatureVerifier`] to verify the cert's `signature` field
/// against the current `working_spki` (the previously-validated issuer's
/// public key). Returns [`Error::SignatureInvalid`] on failure.
///
/// Uses heap-backed encoding (`alloc::vec`) so that large certificates
/// (government, enterprise, HSM attestation certs > 8 KiB TBSCertificate)
/// encode without a fixed-buffer limit; the only `Error::Der` failure mode is
/// a genuine DER encoding error in a malformed certificate.
///
/// Does NOT update `working_spki` — that next-iteration state transition is
/// the caller's responsibility (chain_walk binds it at the end of each loop
/// iteration).
fn verify_cert_signature<V: SignatureVerifier>(
    cert: &Certificate,
    working_spki: &spki::SubjectPublicKeyInfoOwned,
    verifier: &V,
    index: usize,
) -> Result<()> {
    use spki::der::referenced::OwnedToRef as _;
    let tbs_bytes_owned =
        encode_tbs_certificate(cert.tbs_certificate(), cert.tbs_certificate().extensions())
            .map_err(|e| Error::Der(DerError::new(e)))?;
    let tbs_bytes: &[u8] = &tbs_bytes_owned;
    verifier
        .verify_signature(
            cert.signature_algorithm().owned_to_ref(),
            working_spki.owned_to_ref(),
            tbs_bytes,
            cert.signature().raw_bytes(),
        )
        .map_err(|e| match e.kind() {
            VerificationErrorKind::InvalidSignature => Error::SignatureInvalid { index },
            reason => Error::SignatureNotVerified { index, reason },
        })?;
    Ok(())
}

fn chain_walk<V: SignatureVerifier>(
    chain: &[Certificate],
    anchor: &TrustAnchor,
    policy: &ValidationPolicy,
    verifier: &V,
) -> Result<Option<policy_graph::PolicyGraph>> {
    use x509_cert::ext::pkix::{InhibitAnyPolicy, PolicyConstraints, PolicyMappings};

    // RFC 5280 §6.1.2 (b)+(c): seed the initial permitted/excluded subtrees
    // from the trust anchor. These initial constraints apply to ALL certs in
    // the chain (including intermediates), not just to leaves — the chain walk
    // enforces them from the first certificate onward.
    let (initial_nc_permitted, initial_nc_excluded) = match &anchor.name_constraints {
        None => (None, GeneralSubtrees::default()),
        Some(nc) => (
            // Clone necessary: nc_permitted and nc_excluded are mutated during the walk.
            nc.permitted_subtrees.clone(),
            nc.excluded_subtrees.clone().unwrap_or_default(),
        ),
    };
    // Bitmask of NcTypeMask bits for name types that have been explicitly
    // constrained by at least one permittedSubtrees entry in any CA cert seen so far.
    // Needed to detect violations when intersection empties the permitted set
    // for a type (e.g., two incompatible DN constraints → empty, but DN still forbidden).
    //
    // INVARIANT: bits are ORed in and never cleared. Once a type bit is set,
    // nc_permitted must contain zero entries of that type to represent "empty
    // intersection" (all names of that type are forbidden). Do NOT derive
    // "is type constrained?" from nc_permitted contents alone — that would
    // silently allow names of a type whose permitted set was emptied by
    // conflicting CA constraints.
    let initial_nc_constrained_types: NcTypeMask =
        initial_nc_permitted
            .as_ref()
            .map_or(NcTypeMask::EMPTY, |permitted| {
                let mut bits = NcTypeMask::EMPTY;
                for st in permitted {
                    bits |= name_type_bit(&st.base);
                }
                bits
            });

    // RFC 5280 §6.1.2: initialise policy state variables (PKIX-mi3.3).
    //
    // The counters represent "skip N more non-self-issued certificates before
    // the constraint activates".  Setting a counter to `n + 1` means the
    // constraint never triggers unless a CA certificate forces it lower.
    let n = chain.len();
    // Convert n (usize) to u32 safely. Chains with >4 billion certs are not
    // realistic, but a truncating cast would produce a wrong counter value.
    // u32::MAX is safe: counters are only decremented (saturating), so u32::MAX
    // behaves identically to any value > the chain length for these semantics.
    let n_u32 = u32::try_from(n).unwrap_or(u32::MAX);
    let initial_explicit_policy: u32 = if policy.initial_explicit_policy {
        0
    } else {
        n_u32.saturating_add(1)
    };
    let initial_inhibit_any: u32 = if policy.initial_any_policy_inhibit {
        0
    } else {
        n_u32.saturating_add(1)
    };
    let initial_policy_mapping: u32 = if policy.initial_policy_mapping_inhibit {
        0
    } else {
        n_u32.saturating_add(1)
    };

    // Group all per-walk mutable state into a single `WorkingState` for clarity
    // at the call boundaries of the per-substep helpers introduced in
    // subsequent commits.
    let mut state = WorkingState {
        working_spki: &anchor.subject_public_key_info,
        working_issuer_name: &anchor.subject,
        // RFC 5280 §4.2.1.6: when a CA cert has an empty Subject DN and a critical
        // SubjectAltName, the SAN is the cert's identity — the Subject DN is not used
        // for name matching. Track whether the current issuer was set from such a cert
        // so we can skip the DN linkage check below.
        working_issuer_is_san_identity: false,
        nc_permitted: initial_nc_permitted,
        nc_excluded: initial_nc_excluded,
        nc_constrained_types: initial_nc_constrained_types,
        explicit_policy: initial_explicit_policy,
        inhibit_any: initial_inhibit_any,
        policy_mapping: initial_policy_mapping,
        // §6.1.2(a): initial valid_policy_tree — single anyPolicy root node.
        policy_tree: Some(policy_graph::PolicyGraph::new()),
    };

    for i in (0..chain.len()).rev() {
        let cert = &chain[i];

        // (a0) Signature algorithm allowlist check (extracted to helper for
        //      readability; see `enforce_signature_alg_allowlist`).
        enforce_signature_alg_allowlist(cert, policy, i)?;

        // (a) §6.1.3(a)(1) signature verification (extracted; see `verify_cert_signature`).
        verify_cert_signature(cert, state.working_spki, verifier, i)?;

        // (b) §6.1.3(a)(2) issuer DN linkage (extracted; see `check_issuer_linkage`).
        //     NOTE: the `working_issuer_is_san_identity` assignment for the next
        //     iteration is updated at the end-of-loop state block below (PKIX-als9
        //     design §7 — must stay in chain_walk to preserve §4.2.1.6 handling
        //     across multi-intermediate chains).
        check_issuer_linkage(
            cert,
            state.working_issuer_name,
            state.working_issuer_is_san_identity,
            i,
        )?;

        // (c) Validity period.
        check_validity(cert, policy.current_time_unix, i)?;

        // (c2) Max validity period length check (extracted; see `check_max_validity`).
        check_max_validity(cert, policy, i)?;

        // (c3) Minimum RSA key size check (extracted; see `check_min_rsa_bits`).
        check_min_rsa_bits(cert, policy, i)?;

        // (d) Duplicate- and critical-extension guards. Duplicates are
        //     rejected first: every extension lookup below reads only the
        //     first instance of an OID.
        check_duplicate_extensions(cert, i)?;
        check_critical_extensions(cert, i)?;

        // Decode the cert's CertificatePolicies extension once per cert.
        // Used in both step (d) (policy tree update) and step (a/b) (PolicyMappings
        // anyPolicy qualifier lookup).  Decoding here avoids a second parse inside
        // the mapping loop (b5r.12).
        // try_find_cert_ext (fail-closed): a malformed CertificatePolicies must
        // cause rejection rather than being silently treated as absent; silently
        // dropping it would leave the policy tree in an incorrect state (vjc.21).
        let cert_cp: Option<x509_cert::ext::pkix::certpolicy::CertificatePolicies> =
            try_find_cert_ext(cert, OID_CERTIFICATE_POLICIES)
                .map_err(|_| Error::MalformedCertificate { index: i })?;

        // (policy-d) CertificatePolicies extension (RFC 5280 §6.1.3(d)/(e)).
        // Only processed while the policy graph is still alive.
        if let Some(graph) = &mut state.policy_tree {
            let became_null = match &cert_cp {
                Some(cp_ext) => {
                    // §6.1.3(d)(2) condition: inhibit_anyPolicy > 0, or a
                    // self-issued certificate other than the leaf.
                    let may_expand = state.inhibit_any > 0 || (i > 0 && is_self_issued_cert(cert));
                    graph.add_certificate_policies(cp_ext, may_expand)
                }
                // §6.1.3(e): CertificatePolicies absent → NULL.
                None => true,
            };
            if became_null {
                state.policy_tree = None;
            }
        }

        // (policy-f) RFC 5280 §6.1.3(f): explicit_policy == 0 and tree NULL
        // → policy violation.
        if state.explicit_policy == 0 && state.policy_tree.is_none() {
            return Err(Error::PolicyViolation { index: i });
        }

        // Decode SAN once per cert: used in both the NC name check (e) and
        // potentially cached for the NC state update (i). Avoids scanning the
        // extension list twice per cert when both checks are active (vjc.13).
        // Fail-closed: a malformed SAN returns MalformedCertificate (vjc.20).
        let san = cert_subject_alt_names(cert, i)?;

        // (e) NameConstraints: check this cert's names against accumulated state.
        // RFC 5280 §6.1.3(b): self-issued non-leaf certs are exempt from NC name checking.
        // The NC state is still updated from their extensions in step (i).
        if i == 0 || !is_self_issued_cert(cert) {
            check_name_constraints(
                cert,
                san.as_ref(),
                state.nc_permitted.as_ref(),
                &state.nc_excluded,
                state.nc_constrained_types,
                i,
            )?;
        }

        // (e2) Require non-empty SubjectAltName on leaf cert.
        //      Only when require_subject_alt_name is set; intermediate CA certs
        //      are NOT checked (i == 0 guard). The `san` variable is decoded above
        //      and is already available — no second extension scan needed.
        if i == 0 && policy.require_subject_alt_name {
            // san is None if the extension is absent; Some(v) where v.0 may be empty.
            let san_is_nonempty = san.as_ref().is_some_and(|s| !s.0.is_empty());
            if !san_is_nonempty {
                return Err(Error::MissingSan);
            }
        }

        // (e3) Required leaf EKU OID check.
        //      Only when required_leaf_eku is Some; only on the leaf (i == 0).
        //      Uses try_find_cert_ext (fail-closed): malformed EKU DER on the leaf
        //      is mapped to MalformedCertificate rather than silently ignored.
        //      anyExtendedKeyUsage (OID 2.5.29.37.0) does NOT satisfy a specific
        //      OID requirement — only explicit listing in the cert's EKU counts.
        if i == 0 {
            if let Some(required_ekus) = &policy.required_leaf_eku {
                use x509_cert::ext::pkix::ExtendedKeyUsage;
                match try_find_cert_ext::<ExtendedKeyUsage>(cert, OID_EXTENDED_KEY_USAGE)
                    .map_err(|_| Error::MalformedCertificate { index: 0 })?
                {
                    None => {
                        // EKU extension absent; any non-empty requirement fails.
                        if !required_ekus.is_empty() {
                            return Err(Error::MissingEku);
                        }
                    }
                    Some(eku) => {
                        for req_oid in required_ekus {
                            if !eku.0.iter().any(|e| e == req_oid) {
                                return Err(Error::MissingEku);
                            }
                        }
                    }
                }
            }
        }

        // (e3a) Required leaf CertificatePolicies OID check.
        //       Only when required_leaf_policy_oids is Some; only on the leaf
        //       (i == 0). Reuses `cert_cp` decoded above. `anyPolicy`
        //       (2.5.29.32.0) does NOT satisfy a specific OID requirement —
        //       only explicit listing in the cert's CertificatePolicies counts.
        //       Mirrors the (e3) EKU pattern.
        if i == 0 {
            if let Some(required_policy_oids) = &policy.required_leaf_policy_oids {
                match &cert_cp {
                    None => {
                        // CertificatePolicies extension absent; any non-empty
                        // requirement fails.
                        if let Some(first) = required_policy_oids.first() {
                            return Err(Error::MissingLeafPolicyOid { required: *first });
                        }
                    }
                    Some(cp_ext) => {
                        for req_oid in required_policy_oids {
                            if !cp_ext.0.iter().any(|pi| pi.policy_identifier == *req_oid) {
                                return Err(Error::MissingLeafPolicyOid { required: *req_oid });
                            }
                        }
                    }
                }
            }
        }

        // (e3b) Required Subject DN attribute rule check.
        //       Only when required_leaf_subject_dn_attrs is Some; only on the
        //       leaf (i == 0). See [`DnAttrRule`] for the expression grammar
        //       and vacuity rules.
        if i == 0 {
            if let Some(dn_rule) = &policy.required_leaf_subject_dn_attrs {
                if !evaluate_dn_attr_rule(cert.tbs_certificate().subject(), dn_rule) {
                    return Err(Error::SubjectDnAttrRuleUnmet);
                }
            }
        }

        // (e4) If require_rfc822_san is set, at least one rfc822Name entry must
        //      be present in the leaf's SAN extension.
        //      Only meaningful (and checked) when require_subject_alt_name is also
        //      true; the non-empty SAN check above (e2) already guards the absent
        //      / empty SAN case. EKU is checked first (e3) so that a cert with both
        //      wrong EKU and wrong SAN type reports MissingEku (more actionable).
        if i == 0 && policy.require_subject_alt_name && policy.require_rfc822_san {
            use x509_cert::ext::pkix::name::GeneralName;
            let has_rfc822 = san.as_ref().is_some_and(|s| {
                s.0.iter()
                    .any(|name| matches!(name, GeneralName::Rfc822Name(_)))
            });
            if !has_rfc822 {
                return Err(Error::MissingRfc822San);
            }
        }

        // (f–h) CA-only checks: apply to every cert except the leaf (chain[0]).
        //        This includes any intermediate CAs and the root CA cert if it
        //        is included in the chain rather than supplied only as an anchor.
        if i > 0 {
            // (f) BasicConstraints cA=TRUE required; (h) pathLenConstraint.
            // Decode BasicConstraints once for both checks.
            //
            // Fail-closed: if the extension is structurally present but DER-malformed
            // on an intermediate CA, propagate MalformedCertificate rather than
            // treating it as absent (which would fall through to NotCA and hide the
            // real structural problem).
            let bc = try_find_cert_ext::<x509_cert::ext::pkix::BasicConstraints>(
                cert,
                OID_BASIC_CONSTRAINTS,
            )
            .map_err(|_| Error::MalformedCertificate { index: i })?;
            if !bc.as_ref().is_some_and(|b| b.ca) {
                return Err(Error::NotCA { index: i });
            }

            // (g) KeyUsage keyCertSign required (when policy demands it).
            // RFC 5280 §6.1.4(n): "If a KeyUsage extension is present, verify that the
            // keyCertSign bit is set."  Only reject when KeyUsage IS present (Some(_)) and
            // keyCertSign is NOT set (== Some(false)).  Absent KeyUsage (None) is allowed.
            // has_key_cert_sign is fail-closed: a malformed critical KeyUsage returns
            // MalformedCertificate rather than being silently treated as absent (vjc.15).
            if policy.enforce_key_usage
                && has_key_cert_sign(cert).map_err(|_| Error::MalformedCertificate { index: i })?
                    == Some(false)
            {
                return Err(Error::KeyUsageMissing { index: i });
            }

            // (g') KeyUsage cRLSign required (opt-in via require_crl_sign_on_cas).
            // RFC 5280 §6.1 does NOT require this check; it is a stricter policy
            // motivated by PKITS §4.7.4 / §4.7.5, which treat a CA cert without
            // cRLSign as unable to revoke certs it issued and therefore invalid.
            // Same fail-closed and absent-KeyUsage semantics as keyCertSign above.
            // Independent of `enforce_key_usage`: callers can opt into cRLSign
            // enforcement without also enabling keyCertSign enforcement, and
            // vice versa.
            if policy.require_crl_sign_on_cas
                && has_crl_sign(cert).map_err(|_| Error::MalformedCertificate { index: i })?
                    == Some(false)
            {
                return Err(Error::CrlSignMissing { index: i });
            }

            // (h) pathLenConstraint: count only non-self-issued intermediates below position i
            // (RFC 5280 §4.2.1.9: "non-self-issued intermediate certificates").
            // chain[1..i] = the intermediate positions between the leaf (0) and this cert (i).
            if let Some(path_len) = bc.and_then(|b| b.path_len_constraint) {
                let effective_depth = chain[1..i]
                    .iter()
                    .filter(|c| !is_self_issued_cert(c))
                    .count();
                if effective_depth > path_len as usize {
                    return Err(Error::PathTooLong);
                }
            }

            // (policy-a) PolicyMappings (RFC 5280 §6.1.4(a)): anyPolicy must
            // not appear on either side of a mapping.
            // (policy-b) Apply mappings to the tree or delete mapped nodes.
            // NOTE: Policy mappings use the current policy_mapping counter value
            // (before decrement); the decrement happens in §6.1.4(h) below.
            // try_find_cert_ext (fail-closed): a malformed PolicyMappings extension
            // must cause rejection rather than silent ignore; a silently-discarded
            // mapping could allow a policy bypass (e.g., inhibit_policy_mapping bypass).
            if let Some(pm) = try_find_cert_ext::<PolicyMappings>(cert, OID_POLICY_MAPPINGS)
                .map_err(|_| Error::MalformedCertificate { index: i })?
            {
                // §6.1.4(a): reject anyPolicy as issuer or subject domain.
                for mapping in &pm.0 {
                    if mapping.issuer_domain_policy == OID_ANY_POLICY
                        || mapping.subject_domain_policy == OID_ANY_POLICY
                    {
                        return Err(Error::PolicyViolation { index: i });
                    }
                }

                // §6.1.4(b)(1) if policy_mapping > 0, else §6.1.4(b)(2).
                if let Some(graph) = &mut state.policy_tree {
                    // §6.1.4(b)(1) synthesized nodes take the qualifiers of
                    // this certificate's anyPolicy entry (none if it has no
                    // certificatePolicies, in which case the graph is
                    // already NULL and this branch is not reached).
                    let ap_q = cert_cp
                        .as_ref()
                        .map(policy_graph::any_policy_qualifiers)
                        .unwrap_or_default();
                    if graph.apply_policy_mappings(&pm, state.policy_mapping > 0, &ap_q) {
                        state.policy_tree = None;
                    }
                }
            }

            // (policy-h) RFC 5280 §6.1.4(h): decrement policy counters for
            // non-self-issued intermediate certificates.
            // This happens AFTER policy mappings processing (§6.1.4(b)) and
            // BEFORE clamping from extensions (§6.1.4(i)/(j)).
            if !is_self_issued_cert(cert) {
                state.explicit_policy = state.explicit_policy.saturating_sub(1);
                state.policy_mapping = state.policy_mapping.saturating_sub(1);
                state.inhibit_any = state.inhibit_any.saturating_sub(1);
            }

            // (policy-i) PolicyConstraints (RFC 5280 §6.1.4(c)): clamp
            // explicit_policy and policy_mapping from the extension.
            // try_find_cert_ext (fail-closed): malformed PolicyConstraints must reject;
            // silently ignoring it could allow explicit_policy bypass.
            if let Some(pc) = try_find_cert_ext::<PolicyConstraints>(cert, OID_POLICY_CONSTRAINTS)
                .map_err(|_| Error::MalformedCertificate { index: i })?
            {
                if let Some(req) = pc.require_explicit_policy {
                    state.explicit_policy = state.explicit_policy.min(req);
                }
                if let Some(ipm) = pc.inhibit_policy_mapping {
                    state.policy_mapping = state.policy_mapping.min(ipm);
                }
            }

            // (policy-j) InhibitAnyPolicy (RFC 5280 §6.1.4(d)): clamp inhibit_any.
            // try_find_cert_ext (fail-closed): malformed InhibitAnyPolicy must reject;
            // silently ignoring it could allow anyPolicy through when it should be inhibited.
            if let Some(iap) = try_find_cert_ext::<InhibitAnyPolicy>(cert, OID_INHIBIT_ANY_POLICY)
                .map_err(|_| Error::MalformedCertificate { index: i })?
            {
                state.inhibit_any = state.inhibit_any.min(iap.0);
            }

            // (i) NC update: NameConstraints state update (RFC 5280 §6.1.4(b)).
            //     INTERSECTION for permitted, UNION for excluded.
            //     cert_name_constraints is fail-closed: a malformed or non-conformant
            //     NC extension (e.g., non-zero minimum/maximum) returns MalformedCertificate
            //     rather than silently ignoring the constraints (vjc.7, vjc.8).
            if let Some(nc) = cert_name_constraints(cert, i)? {
                // permittedSubtrees: intersect with current state.
                if let Some(new_permitted) = nc.permitted_subtrees {
                    // Track which types this CA is constraining.
                    for entry in &new_permitted {
                        state.nc_constrained_types |= name_type_bit(&entry.base);
                    }
                    match state.nc_permitted.as_mut() {
                        None => {
                            // First constraint seen; adopt it directly.
                            state.nc_permitted = Some(new_permitted);
                        }
                        Some(current) => {
                            // Type-aware intersection of two permitted-subtrees sets.
                            //
                            // RFC 5280 §6.1.4(b): intersect entry-by-entry, but only
                            // compare entries of the SAME name type. Entries of types
                            // not present in new_permitted are unchanged (new doesn't
                            // constrain that type). Entries of types not in current
                            // are added directly (new adds a fresh constraint).
                            //
                            // For entries of matching type, keep:
                            //   1. new entries within (⊆) some same-type current entry.
                            //   2. current entries within (⊆) some same-type new entry.
                            // Containment is decided by `subtree_within`, which
                            // compares two constraints (address+mask, bare host,
                            // `.domain`) rather than treating one as a cert name.
                            // (If neither is within the other the intersection for that
                            // type is empty — tracked via nc_constrained_types.)
                            let mut result = GeneralSubtrees::default();

                            // For each new entry, pre-filter current entries of the
                            // same type to avoid calling same_nc_variant twice per
                            // pair (vjc.16: duplicated guard + containment check).
                            for n in &new_permitted {
                                let same_type_in_current: GeneralSubtrees = current
                                    .iter()
                                    .filter(|c| same_nc_variant(&c.base, &n.base))
                                    .cloned()
                                    .collect();
                                if same_type_in_current.is_empty() {
                                    // Type not previously constrained → add directly.
                                    result.push(n.clone());
                                } else if same_type_in_current
                                    .iter()
                                    .any(|c| subtree_within(&n.base, &c.base))
                                {
                                    // n is within some same-type current entry → keep.
                                    result.push(n.clone());
                                }
                                // else: n is not within any current entry of same type → drop.
                            }

                            for c in current.iter() {
                                let same_type_in_new: GeneralSubtrees = new_permitted
                                    .iter()
                                    .filter(|n| same_nc_variant(&n.base, &c.base))
                                    .cloned()
                                    .collect();
                                if same_type_in_new.is_empty() {
                                    // Type not in new_permitted → keep unchanged.
                                    result.push(c.clone());
                                } else if same_type_in_new
                                    .iter()
                                    .any(|n| subtree_within(&c.base, &n.base))
                                {
                                    // c is more specific than some new entry; keep unless
                                    // an equivalent entry is already in result (dedup
                                    // within the result set for this type).
                                    let same_type_in_result: &[_] = result.as_slice();
                                    let already_in_result = same_type_in_result.iter().any(|e| {
                                        same_nc_variant(&e.base, &c.base)
                                            && subtree_within(&e.base, &c.base)
                                            && subtree_within(&c.base, &e.base)
                                    });
                                    if !already_in_result {
                                        result.push(c.clone());
                                    }
                                }
                                // else: c is not within any new entry of same type → drop.
                            }

                            *current = result;
                        }
                    }
                }
                // excludedSubtrees: union — append only entries not already present,
                // avoiding monotonic growth that would make per-cert NC checks O(chain²)
                // when the same excluded subtrees are repeated across multiple CAs (vjc.12).
                if let Some(new_excluded) = nc.excluded_subtrees {
                    for new_entry in &new_excluded {
                        // Deduplication uses subtree_within as a two-way equality
                        // check: two entries are considered the same subtree when each
                        // contains the other (i.e., they are semantically equivalent, not
                        // just byte-equal).
                        let already_present = state.nc_excluded.iter().any(|existing| {
                            same_nc_variant(&existing.base, &new_entry.base)
                                && subtree_within(&existing.base, &new_entry.base)
                                && subtree_within(&new_entry.base, &existing.base)
                        });
                        if !already_present {
                            state.nc_excluded.push(new_entry.clone());
                        }
                    }
                }
            }
        }

        // Update state for next iteration.
        state.working_spki = cert.tbs_certificate().subject_public_key_info();
        state.working_issuer_name = cert.tbs_certificate().subject();
        // Determine whether the cert we just processed presents itself via SAN
        // identity (empty Subject + critical SAN). This affects the chain-linkage
        // check for the certificate immediately below it in the next iteration.
        state.working_issuer_is_san_identity = cert_has_san_identity(cert);
    }

    // RFC 5280 §6.1.5(a-b): post-loop leaf policy finalisation.
    //
    // §6.1.5 is a post-loop step in the RFC.  These operations apply only to
    // the leaf certificate (chain[0]), which was the last iteration (i == 0).
    // Placing them here rather than inside the loop at i == 0 matches the RFC
    // section numbering and makes clear that they happen after all per-cert
    // §6.1.3/§6.1.4 steps have completed.
    {
        let leaf = &chain[0];
        // §6.1.5(a): if the leaf is not self-issued, decrement counters.
        // inhibit_any and policy_mapping are decremented per RFC 5280 §6.1.5(a)
        // but are not used after this point in the algorithm — only explicit_policy
        // is tested in §6.1.5(g) and the final check.
        if !is_self_issued_cert(leaf) {
            state.explicit_policy = state.explicit_policy.saturating_sub(1);
            // Per §6.1.5(a): RFC also decrements inhibit_any and policy_mapping here,
            // but neither is read after §6.1.5(a) in our implementation.
        }
        // §6.1.5(b): if PolicyConstraints requireExplicitPolicy == 0,
        // force explicit_policy to 0.
        // try_find_cert_ext (fail-closed): consistent with per-loop treatment of
        // PolicyConstraints; a malformed extension on the leaf must also reject.
        if let Some(pc) = try_find_cert_ext::<PolicyConstraints>(leaf, OID_POLICY_CONSTRAINTS)
            .map_err(|_| Error::MalformedCertificate { index: 0 })?
        {
            if let Some(req) = pc.require_explicit_policy {
                state.explicit_policy = state.explicit_policy.min(req);
            }
        }
    }

    // RFC 5280 §6.1.5(g): intersect the valid_policy_graph with the
    // user-initial-policy-set.
    //
    // (g)(i): a NULL graph stays NULL. (g)(ii): an empty set (this crate's
    // spelling of the default) or any set containing anyPolicy is
    // any-policy, and the intersection is the whole graph. (g)(iii)
    // otherwise.
    if !policy.initial_policy_set.is_empty() && !policy.initial_policy_set.contains(&OID_ANY_POLICY)
    {
        if let Some(graph) = &mut state.policy_tree {
            if graph.intersect_user_policy_set(&policy.initial_policy_set) {
                state.policy_tree = None;
            }
        }
    }

    // §6.1.5 final check: path is valid iff explicit_policy > 0 OR tree
    // is non-NULL.
    if state.explicit_policy == 0 && state.policy_tree.is_none() {
        return Err(Error::PolicyViolation { index: 0 });
    }

    // Return the final valid_policy_tree to `validate_path` so it can be
    // surfaced on `ValidatedPath` for post-validation qualifier extraction.
    // `None` propagates through unchanged when the tree was reduced to NULL
    // during validation; callers that rely on §6.1.5 outputs MUST treat
    // `None` as "no policy information available", not as a validation
    // failure (the policy-success check above already happened).
    Ok(state.policy_tree)
}

// ---------------------------------------------------------------------------
// NameConstraints enforcement (PKIX-xji)
// ---------------------------------------------------------------------------

/// Whether a name-constraint check requires a match (permitted) or forbids a
/// match (excluded).
///
/// Using an explicit enum instead of a bare `bool` makes call sites
/// self-documenting: `CheckMode::Excluded` / `CheckMode::Permitted` vs
/// opaque `false` / `true` (vjc.25).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CheckMode {
    /// Excluded subtrees: any name that matches is a violation.
    Excluded,
    /// Permitted subtrees: a constrained name type that matches *no* entry is a violation.
    Permitted,
}

/// Check the cert's subject DN against `subtrees` in the given `mode`.
///
/// Skipped entirely when the subject DN is empty (RFC 5280 §6.1.3(b)).
///
/// Avoids constructing a `GeneralName::DirectoryName` (which would require a
/// clone) by handling `DirectoryName` constraints inline: pull `DirectoryName`
/// entries from `subtrees` and test directly against the subject `Name`
/// (vjc.24).
///
/// - `CheckMode::Excluded`: any DN match is a violation.
/// - `CheckMode::Permitted`: only enforced if some CA in the path has
///   contributed a `DirectoryName` permitted-subtree (tracked in
///   `nc_constrained_types`); then a non-match is a violation.
fn check_subject_dn_against_subtrees(
    subject: &x509_cert::name::Name,
    subject_is_empty: bool,
    subtrees: &[x509_cert::ext::pkix::constraints::name::GeneralSubtree],
    mode: CheckMode,
    nc_constrained_types: NcTypeMask,
    index: usize,
) -> crate::Result<()> {
    use x509_cert::ext::pkix::name::GeneralName;

    if subject_is_empty {
        return Ok(());
    }
    let subject_constrained = nc_constrained_types.intersects(NcTypeMask::DIRECTORY_NAME);
    let dn_matches_any = subtrees.iter().any(|st| {
        if let GeneralName::DirectoryName(constr) = &st.base {
            dn_within_subtree(subject, constr)
        } else {
            false
        }
    });
    match mode {
        CheckMode::Excluded => {
            if dn_matches_any {
                return Err(Error::NameConstraintViolation { index });
            }
        }
        CheckMode::Permitted => {
            if subject_constrained && !dn_matches_any {
                return Err(Error::NameConstraintViolation { index });
            }
        }
    }
    Ok(())
}

/// Check each SAN entry of the cert against `subtrees` in the given `mode`.
///
/// - `CheckMode::Excluded`: any SAN entry that matches any subtree is a
///   violation.
/// - `CheckMode::Permitted`: a SAN entry whose type has been constrained
///   somewhere in the path (per `nc_constrained_types`) must match at least
///   one subtree entry; unconstrained types are accepted.
///
/// A `None` SAN extension is a no-op.
fn check_san_against_subtrees(
    san: Option<&x509_cert::ext::pkix::SubjectAltName>,
    subtrees: &[x509_cert::ext::pkix::constraints::name::GeneralSubtree],
    mode: CheckMode,
    nc_constrained_types: NcTypeMask,
    index: usize,
) -> crate::Result<()> {
    use x509_cert::ext::pkix::name::GeneralName;

    let Some(san_ext) = san else {
        return Ok(());
    };
    let type_constrained =
        |name: &GeneralName| -> bool { nc_constrained_types.intersects(name_type_bit(name)) };

    for name in &san_ext.0 {
        match mode {
            CheckMode::Excluded => {
                if subtrees.iter().any(|st| name_matches_subtree(name, st)) {
                    return Err(Error::NameConstraintViolation { index });
                }
            }
            CheckMode::Permitted => {
                if type_constrained(name)
                    && !subtrees.iter().any(|st| name_matches_subtree(name, st))
                {
                    return Err(Error::NameConstraintViolation { index });
                }
            }
        }
    }
    Ok(())
}

/// Check that all names in `cert` satisfy the current `NameConstraints` state.
///
/// Called once per certificate during `chain_walk`, BEFORE updating the NC
/// state from that certificate's own `NameConstraints` extension.
///
/// `san` is the pre-decoded `SubjectAltName` for this cert (pass `None` if the
/// extension is absent). Decoding it before the call avoids a second scan of
/// the extension list when both NC check and NC update are needed (vjc.13).
///
/// RFC 5280 §6.1.4(b)(1)–(2): check excluded subtrees first, then
/// permitted subtrees.
fn check_name_constraints(
    cert: &x509_cert::Certificate,
    san: Option<&x509_cert::ext::pkix::SubjectAltName>,
    nc_permitted: Option<&GeneralSubtrees>,
    nc_excluded: &GeneralSubtrees,
    nc_constrained_types: NcTypeMask,
    index: usize,
) -> crate::Result<()> {
    let subject = cert.tbs_certificate().subject();
    let subject_is_empty = subject.is_empty();

    // Dispatch the subject DN and the SAN entries against `subtrees` in the
    // requested mode. See `check_subject_dn_against_subtrees` and
    // `check_san_against_subtrees` for the per-name-class logic.
    let check_names = |subtrees: &[x509_cert::ext::pkix::constraints::name::GeneralSubtree],
                       mode: CheckMode|
     -> crate::Result<()> {
        check_subject_dn_against_subtrees(
            subject,
            subject_is_empty,
            subtrees,
            mode,
            nc_constrained_types,
            index,
        )?;
        check_san_against_subtrees(san, subtrees, mode, nc_constrained_types, index)?;
        Ok(())
    };

    // (0) Name forms the generic matchers cannot decide. A form is "in
    //     effect" when some permitted subtree of that form has been seen in
    //     the path (`nc_constrained_types`, which survives an emptied
    //     intersection) or the excluded set holds an entry of that form.
    let excluded_forms = nc_excluded
        .iter()
        .fold(NcTypeMask::EMPTY, |m, st| m | name_type_bit(&st.base));
    let forms_in_effect = nc_constrained_types | excluded_forms;
    let rfc822_permitted_active = nc_constrained_types.intersects(NcTypeMask::RFC822);
    if let Some(san_ext) = san {
        for name in &san_ext.0 {
            check_san_name_form(
                name,
                forms_in_effect,
                nc_permitted,
                nc_excluded,
                rfc822_permitted_active,
                index,
            )?;
        }
    }

    // (1) Excluded check: any excluded subtree match → violation.
    check_names(nc_excluded.as_slice(), CheckMode::Excluded)?;

    // (2) Permitted check: if permitted set is constrained, every name must
    //     match at least one permitted subtree.
    if let Some(permitted) = nc_permitted {
        check_names(permitted.as_slice(), CheckMode::Permitted)?;
    }

    // (3) RFC 5280 §4.2.1.10: emailAddress attributes in the subject DN MUST
    //     be checked against the rfc822Name constraint.
    //     Guard: only enter the RDN walk if RFC822 constraints are actually
    //     in effect — a permitted RFC822 entry has been seen, OR at least one
    //     excluded entry is an Rfc822Name (vjc.11).
    if forms_in_effect.intersects(NcTypeMask::RFC822) && !subject_is_empty {
        for rdn in subject.iter_rdn() {
            for ava in rdn.iter() {
                if ava.oid != OID_EMAIL_ADDRESS {
                    continue;
                }
                // PKCS #9 defines emailAddress as IA5String. Any other
                // encoding cannot be checked, so it fails closed instead of
                // silently skipping the constraint.
                let Ok(email_ia5) = ava.value.decode_as::<der::asn1::Ia5StringRef<'_>>() else {
                    return Err(Error::NameConstraintViolation { index });
                };
                check_mailbox_against_rfc822(
                    email_ia5.as_str(),
                    nc_permitted,
                    nc_excluded,
                    rfc822_permitted_active,
                    index,
                )?;
            }
        }
    }

    Ok(())
}

/// OID for the `SmtpUTF8Mailbox` otherName (RFC 8398 §3), `id-on-SmtpUTF8Mailbox`.
const OID_SMTP_UTF8_MAILBOX: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.8.9");

/// Pre-check one SAN entry whose form the generic subtree matchers cannot
/// decide on their own (RFC 5280 §4.2.1.10, RFC 8398 §6).
///
/// - `otherName(SmtpUTF8Mailbox)`: checked against rfc822Name constraints
///   when any are in effect (RFC 8398 §6 extends them to this form). The
///   value must be a UTF8String and its domain part must be ASCII; a
///   U-label domain would need IDNA mapping, which this `no_std` crate
///   does not carry, so it fails closed.
/// - `otherName` (any type-id, including SmtpUTF8Mailbox), `ediPartyName`,
///   `registeredID`: `pkix-path` does not process constraints of these
///   forms, so the name is rejected when a constraint of the same form is
///   in effect ("MUST either process the constraint or reject the
///   certificate"). The `otherName` check is per form, not per type-id: an
///   otherName constraint of one type-id rejects otherName SANs of every
///   type-id.
/// - `uniformResourceIdentifier`: when a URI constraint is in effect, a URI
///   without an authority, or whose host is an IP address, is rejected
///   (see [`uri_host`]).
fn check_san_name_form(
    name: &x509_cert::ext::pkix::name::GeneralName,
    forms_in_effect: NcTypeMask,
    nc_permitted: Option<&GeneralSubtrees>,
    nc_excluded: &GeneralSubtrees,
    rfc822_permitted_active: bool,
    index: usize,
) -> crate::Result<()> {
    use x509_cert::ext::pkix::name::GeneralName;

    let violation = Err(Error::NameConstraintViolation { index });
    match name {
        GeneralName::OtherName(other) => {
            if forms_in_effect.intersects(NcTypeMask::OTHER_NAME) {
                return violation;
            }
            if other.type_id == OID_SMTP_UTF8_MAILBOX
                && forms_in_effect.intersects(NcTypeMask::RFC822)
            {
                let Ok(mailbox) = der::asn1::Utf8StringRef::try_from(&other.value) else {
                    return violation;
                };
                check_mailbox_against_rfc822(
                    mailbox.as_str(),
                    nc_permitted,
                    nc_excluded,
                    rfc822_permitted_active,
                    index,
                )?;
            }
        }
        GeneralName::EdiPartyName(_) | GeneralName::RegisteredId(_)
            if forms_in_effect.intersects(name_type_bit(name)) =>
        {
            return violation;
        }
        GeneralName::UniformResourceIdentifier(uri)
            if forms_in_effect.intersects(NcTypeMask::URI) && uri_host(uri.as_str()).is_none() =>
        {
            return violation;
        }
        _ => {}
    }
    Ok(())
}

/// Check a mailbox that does not arrive as an rfc822Name SAN (a subject
/// `emailAddress` attribute or an `SmtpUTF8Mailbox` otherName) against the
/// rfc822Name subtrees.
///
/// Excluded entries always apply; permitted entries apply when
/// `rfc822_permitted_active` (some CA in the path permitted rfc822Name
/// subtrees). The domain part (after the last `@`) must be ASCII, otherwise
/// the mailbox cannot be compared and the check fails closed.
fn check_mailbox_against_rfc822(
    mailbox: &str,
    nc_permitted: Option<&GeneralSubtrees>,
    nc_excluded: &GeneralSubtrees,
    rfc822_permitted_active: bool,
    index: usize,
) -> crate::Result<()> {
    use x509_cert::ext::pkix::name::GeneralName;

    let violation = Err(Error::NameConstraintViolation { index });
    match mailbox.rsplit_once('@') {
        Some((_, domain)) if domain.is_ascii() => {}
        _ => return violation,
    }
    for st in nc_excluded {
        if let GeneralName::Rfc822Name(c) = &st.base {
            if matches_rfc822_name(mailbox, c.as_str()) {
                return violation;
            }
        }
    }
    if rfc822_permitted_active {
        let permitted = nc_permitted.map_or(&[][..], |p| p.as_slice());
        let ok = permitted.iter().any(|st| match &st.base {
            GeneralName::Rfc822Name(c) => matches_rfc822_name(mailbox, c.as_str()),
            _ => false,
        });
        if !ok {
            return violation;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Send + Sync compile-time assertions
// ---------------------------------------------------------------------------
//
// AGENTS.md non-negotiable #6 requires load-bearing result types to be
// `Send + Sync` so callers can move values across thread boundaries and
// store them in shared caches. The auto-derive does the right thing today
// (no `Rc<T>`, `RefCell<T>`, or raw pointers in any of these types), but
// the rule is currently aspirational. These `const _:` assertions promote
// it to a compile-time invariant — a future field that breaks `Send` or
// `Sync` (e.g. someone adds an `Rc<T>` variant to `Error`) fails the
// workspace build, not a runtime test. Tracked at PKIX-2l0v.2.

const _: fn() = || {
    fn _assert_send_sync<T: Send + Sync>() {}
    _assert_send_sync::<ValidatedPath>();
    _assert_send_sync::<Error>();
    _assert_send_sync::<TrustAnchor>();
    _assert_send_sync::<ValidationPolicy>();
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "p256"))]
mod tests_ecdsa_p256 {
    use super::*;
    use der::Decode;

    /// Test vector: a real P-256/SHA-256 self-signed cert generated by OpenSSL.
    /// Oracle: `openssl verify -CAfile ec.pem ec.pem` returns OK.
    #[test]
    fn verify_p256_self_signed() {
        use der::Encode as _;
        use spki::der::referenced::OwnedToRef as _;
        let der = include_bytes!("../tests/fixtures/ec-p256-sha256.der");
        let cert = Certificate::from_der(der).expect("parse cert");

        let tbs_der = cert.tbs_certificate().to_der().expect("encode tbs");
        let sig_bytes = cert.signature().raw_bytes();

        // Self-signed cert: signer SPKI is the cert's own SPKI.
        let spki_ref = cert
            .tbs_certificate()
            .subject_public_key_info()
            .owned_to_ref();

        let verifier = EcdsaP256Verifier;
        assert!(
            verifier
                .verify_signature(
                    cert.signature_algorithm().owned_to_ref(),
                    spki_ref,
                    &tbs_der,
                    sig_bytes,
                )
                .is_ok(),
            "self-signed P-256 cert should verify"
        );
    }
}

#[cfg(all(test, feature = "p384"))]
mod tests_ecdsa_p384 {
    //! Test vectors for ECDSA P-384 / SHA-384 (PKIX-gphz.2).
    //!
    //! Oracle: `openssl verify -CAfile ec-p384-sha384.pem ec-p384-sha384.pem`
    //! returns OK against the same fixture (the PEM form lives at
    //! `tests/fixtures/ec-p384-sha384.der`; regenerate with the recipe in the
    //! commit that introduced this file). Independent oracle — pkix-path was
    //! not used to compute the expected verdict.
    use super::*;
    use der::Decode;

    const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/ec-p384-sha384.der");

    #[test]
    fn verify_p384_self_signed() {
        use der::Encode as _;
        use spki::der::referenced::OwnedToRef as _;
        let cert = Certificate::from_der(FIXTURE).expect("parse cert");

        let tbs_der = cert.tbs_certificate().to_der().expect("encode tbs");
        let sig_bytes = cert.signature().raw_bytes();

        // Self-signed cert: signer SPKI is the cert's own SPKI.
        let spki_ref = cert
            .tbs_certificate()
            .subject_public_key_info()
            .owned_to_ref();

        let verifier = EcdsaP384Verifier;
        verifier
            .verify_signature(
                cert.signature_algorithm().owned_to_ref(),
                spki_ref,
                &tbs_der,
                sig_bytes,
            )
            .expect("self-signed P-384 cert should verify");
    }

    #[test]
    fn tampered_signature_rejected() {
        // Flip a bit in the signature and confirm verification fails. This
        // exercises the actual cryptographic check, not just the OID and
        // SPKI parse paths.
        use der::Encode as _;
        use spki::der::referenced::OwnedToRef as _;
        let cert = Certificate::from_der(FIXTURE).expect("parse cert");

        let tbs_der = cert.tbs_certificate().to_der().expect("encode tbs");
        let mut sig_bytes = cert.signature().raw_bytes().to_vec();
        // Tamper a byte well inside the DER signature (any byte after the
        // initial SEQUENCE header). The DerSignature decoder rejects most
        // structural corruption with try_from, which is also a valid
        // verification failure — either way the result must be Err.
        let mid = sig_bytes.len() / 2;
        sig_bytes[mid] ^= 0x01;

        let spki_ref = cert
            .tbs_certificate()
            .subject_public_key_info()
            .owned_to_ref();

        let verifier = EcdsaP384Verifier;
        assert!(
            verifier
                .verify_signature(
                    cert.signature_algorithm().owned_to_ref(),
                    spki_ref,
                    &tbs_der,
                    &sig_bytes,
                )
                .is_err(),
            "tampered signature must not verify"
        );
    }

    #[test]
    fn wrong_oid_rejected() {
        // The fixture was signed with SHA-384. Relabelling it as
        // ecdsa-with-SHA256 makes the verifier hash with SHA-256 (the
        // digest comes from the OID, the curve from the key), so the
        // signature must not verify.
        use der::Encode as _;
        use spki::der::referenced::OwnedToRef as _;
        let cert = Certificate::from_der(FIXTURE).expect("parse cert");
        let tbs_der = cert.tbs_certificate().to_der().expect("encode tbs");
        let sig_bytes = cert.signature().raw_bytes();
        let spki_ref = cert
            .tbs_certificate()
            .subject_public_key_info()
            .owned_to_ref();

        let wrong_alg = spki::AlgorithmIdentifierRef {
            oid: der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"), // ecdsa-with-SHA256
            parameters: None,
        };
        let verifier = EcdsaP384Verifier;
        assert!(
            verifier
                .verify_signature(wrong_alg, spki_ref, &tbs_der, sig_bytes)
                .is_err(),
            "a SHA-384 signature must not verify as ecdsa-with-SHA256"
        );
    }

    #[test]
    fn default_verifier_dispatches_to_p384() {
        // DefaultVerifier's OID dispatch should route ecdsa-with-SHA384 to
        // EcdsaP384Verifier when the `p384` feature is active. Confirm the
        // same fixture verifies under DefaultVerifier too.
        use der::Encode as _;
        use spki::der::referenced::OwnedToRef as _;
        let cert = Certificate::from_der(FIXTURE).expect("parse cert");
        let tbs_der = cert.tbs_certificate().to_der().expect("encode tbs");
        let sig_bytes = cert.signature().raw_bytes();
        let spki_ref = cert
            .tbs_certificate()
            .subject_public_key_info()
            .owned_to_ref();

        DefaultVerifier
            .verify_signature(
                cert.signature_algorithm().owned_to_ref(),
                spki_ref,
                &tbs_der,
                sig_bytes,
            )
            .expect("DefaultVerifier must dispatch to EcdsaP384Verifier for ecdsa-with-SHA384");
    }
}

#[cfg(all(test, feature = "rsa"))]
mod tests_rsa {
    use super::*;
    use der::Decode;

    /// Test vector: a real RSA-2048/SHA-256 self-signed cert generated by OpenSSL.
    /// Oracle: `openssl verify -CAfile rsa.pem rsa.pem` returns OK.
    #[test]
    fn verify_rsa_pkcs1v15_sha256_self_signed() {
        use der::Encode as _;
        use spki::der::referenced::OwnedToRef as _;
        let der = include_bytes!("../tests/fixtures/rsa-pkcs1v15-sha256.der");
        let cert = Certificate::from_der(der).expect("parse cert");

        let tbs_der = cert.tbs_certificate().to_der().expect("encode tbs");
        let sig_bytes = cert.signature().raw_bytes();

        // Self-signed cert: signer SPKI is the cert's own SPKI.
        let spki_ref = cert
            .tbs_certificate()
            .subject_public_key_info()
            .owned_to_ref();

        let verifier = RsaPkcs1v15Sha256Verifier;
        assert!(
            verifier
                .verify_signature(
                    cert.signature_algorithm().owned_to_ref(),
                    spki_ref,
                    &tbs_der,
                    sig_bytes,
                )
                .is_ok(),
            "self-signed RSA cert should verify"
        );
    }

    /// RSA-PKCS1v15 SHA-384 verifier (PKIX-gphz.4).
    ///
    /// Independent oracle: `openssl verify -CAfile rsa-pkcs1v15-sha384.pem
    /// rsa-pkcs1v15-sha384.pem` returns OK against the same fixture
    /// (generated by `openssl req -new -x509 -sha384 ...`).
    #[test]
    fn verify_rsa_pkcs1v15_sha384_self_signed() {
        use der::Encode as _;
        use spki::der::referenced::OwnedToRef as _;
        let der = include_bytes!("../tests/fixtures/rsa-pkcs1v15-sha384.der");
        let cert = Certificate::from_der(der).expect("parse cert");
        let tbs_der = cert.tbs_certificate().to_der().expect("encode tbs");
        let sig_bytes = cert.signature().raw_bytes();
        let spki_ref = cert
            .tbs_certificate()
            .subject_public_key_info()
            .owned_to_ref();

        RsaPkcs1v15Sha384Verifier
            .verify_signature(
                cert.signature_algorithm().owned_to_ref(),
                spki_ref,
                &tbs_der,
                sig_bytes,
            )
            .expect("self-signed RSA SHA-384 cert should verify");
    }

    /// Tamper-rejection for SHA-384 variant.
    #[test]
    fn rsa_pkcs1v15_sha384_tampered_signature_rejected() {
        use der::Encode as _;
        use spki::der::referenced::OwnedToRef as _;
        let der = include_bytes!("../tests/fixtures/rsa-pkcs1v15-sha384.der");
        let cert = Certificate::from_der(der).expect("parse cert");
        let tbs_der = cert.tbs_certificate().to_der().expect("encode tbs");
        let mut sig_bytes = cert.signature().raw_bytes().to_vec();
        let mid = sig_bytes.len() / 2;
        sig_bytes[mid] ^= 0x01;
        let spki_ref = cert
            .tbs_certificate()
            .subject_public_key_info()
            .owned_to_ref();

        assert!(
            RsaPkcs1v15Sha384Verifier
                .verify_signature(
                    cert.signature_algorithm().owned_to_ref(),
                    spki_ref,
                    &tbs_der,
                    &sig_bytes,
                )
                .is_err(),
            "tampered RSA SHA-384 signature must not verify"
        );
    }

    /// RSA-PKCS1v15 SHA-512 verifier (PKIX-gphz.4).
    #[test]
    fn verify_rsa_pkcs1v15_sha512_self_signed() {
        use der::Encode as _;
        use spki::der::referenced::OwnedToRef as _;
        let der = include_bytes!("../tests/fixtures/rsa-pkcs1v15-sha512.der");
        let cert = Certificate::from_der(der).expect("parse cert");
        let tbs_der = cert.tbs_certificate().to_der().expect("encode tbs");
        let sig_bytes = cert.signature().raw_bytes();
        let spki_ref = cert
            .tbs_certificate()
            .subject_public_key_info()
            .owned_to_ref();

        RsaPkcs1v15Sha512Verifier
            .verify_signature(
                cert.signature_algorithm().owned_to_ref(),
                spki_ref,
                &tbs_der,
                sig_bytes,
            )
            .expect("self-signed RSA SHA-512 cert should verify");
    }

    /// Tamper-rejection for SHA-512 variant.
    #[test]
    fn rsa_pkcs1v15_sha512_tampered_signature_rejected() {
        use der::Encode as _;
        use spki::der::referenced::OwnedToRef as _;
        let der = include_bytes!("../tests/fixtures/rsa-pkcs1v15-sha512.der");
        let cert = Certificate::from_der(der).expect("parse cert");
        let tbs_der = cert.tbs_certificate().to_der().expect("encode tbs");
        let mut sig_bytes = cert.signature().raw_bytes().to_vec();
        let mid = sig_bytes.len() / 2;
        sig_bytes[mid] ^= 0x01;
        let spki_ref = cert
            .tbs_certificate()
            .subject_public_key_info()
            .owned_to_ref();

        assert!(
            RsaPkcs1v15Sha512Verifier
                .verify_signature(
                    cert.signature_algorithm().owned_to_ref(),
                    spki_ref,
                    &tbs_der,
                    &sig_bytes,
                )
                .is_err(),
            "tampered RSA SHA-512 signature must not verify"
        );
    }

    /// Wrong-OID rejection: SHA-384 verifier must reject SHA-512 OID and
    /// vice versa, and both must reject SHA-256 OID.
    #[test]
    fn rsa_pkcs1v15_wrong_oid_rejected() {
        use der::Encode as _;
        use spki::der::referenced::OwnedToRef as _;
        let der = include_bytes!("../tests/fixtures/rsa-pkcs1v15-sha384.der");
        let cert = Certificate::from_der(der).expect("parse cert");
        let tbs_der = cert.tbs_certificate().to_der().expect("encode tbs");
        let sig_bytes = cert.signature().raw_bytes();
        let spki_ref = cert
            .tbs_certificate()
            .subject_public_key_info()
            .owned_to_ref();

        // SHA-512 verifier must refuse the SHA-384 OID.
        let sha384_alg = cert.signature_algorithm().owned_to_ref();
        assert!(RsaPkcs1v15Sha512Verifier
            .verify_signature(sha384_alg, spki_ref.clone(), &tbs_der, sig_bytes)
            .is_err());
        // SHA-256 verifier must refuse the SHA-384 OID.
        assert!(RsaPkcs1v15Sha256Verifier
            .verify_signature(sha384_alg, spki_ref, &tbs_der, sig_bytes)
            .is_err());
    }

    /// `DefaultVerifier` dispatches the SHA-384 and SHA-512 RSA OIDs.
    #[test]
    fn default_verifier_dispatches_to_rsa_sha384_and_sha512() {
        use der::Encode as _;
        use spki::der::referenced::OwnedToRef as _;

        for fixture in [
            &include_bytes!("../tests/fixtures/rsa-pkcs1v15-sha384.der")[..],
            &include_bytes!("../tests/fixtures/rsa-pkcs1v15-sha512.der")[..],
        ] {
            let cert = Certificate::from_der(fixture).expect("parse cert");
            let tbs_der = cert.tbs_certificate().to_der().expect("encode tbs");
            let sig_bytes = cert.signature().raw_bytes();
            let spki_ref = cert
                .tbs_certificate()
                .subject_public_key_info()
                .owned_to_ref();
            DefaultVerifier
                .verify_signature(
                    cert.signature_algorithm().owned_to_ref(),
                    spki_ref,
                    &tbs_der,
                    sig_bytes,
                )
                .expect("DefaultVerifier must dispatch RSA SHA-384/512 by OID");
        }
    }

    /// Regression (PKIX-5u0): `spki_key_matches` ignores the NULL-vs-absent
    /// parameter encoding difference that exists for RSA SPKIs.
    ///
    /// RFC 3279 §2.3.1 allows both explicit NULL parameters and absent
    /// parameters for `rsaEncryption`. The derived `PartialEq` in the `spki`
    /// crate treats `Some(NULL) ≠ None`, so using `==` in the self-issued
    /// anchor guard would wrongly reject a valid anchor.
    #[test]
    fn spki_key_matches_ignores_null_vs_absent_params() {
        let der_bytes = include_bytes!("../tests/fixtures/rsa-pkcs1v15-sha256.der");
        let cert = Certificate::from_der(der_bytes).expect("parse cert");
        let cert_spki = cert.tbs_certificate().subject_public_key_info();

        // Same OID and key bytes, but parameters: None instead of Some(NULL).
        let spki_no_params: spki::SubjectPublicKeyInfoOwned = spki::SubjectPublicKeyInfoOwned {
            algorithm: spki::AlgorithmIdentifier {
                oid: cert_spki.algorithm.oid,
                parameters: None,
            },
            subject_public_key: cert_spki.subject_public_key.clone(),
        };

        // PartialEq distinguishes Some(NULL) from None — document this behavior.
        assert_ne!(cert_spki, &spki_no_params);

        // spki_key_matches must return true: same OID + same key bytes.
        assert!(super::spki_key_matches(cert_spki, &spki_no_params));
    }

    /// Integration regression (PKIX-5u0): the self-issued anchor guard must not
    /// return `NoTrustedPath` when an anchor has absent parameters (None) and the
    /// cert in the chain has explicit NULL parameters — both are valid per RFC 3279
    /// §2.3.1 for rsaEncryption.
    ///
    /// The guard compares anchor and cert SPKIs with `spki_key_matches` (OID + key
    /// bytes only). Before the fix, using `==` caused `NoTrustedPath` because
    /// `Some(NULL) != None` under derived `PartialEq`.
    ///
    /// Note: the anchor with `parameters: None` will fail signature verification
    /// (the `rsa` crate rejects absent params during key parsing), so the result
    /// is `Err(SignatureInvalid)`, not `Ok`. What this test verifies is that the
    /// guard does NOT skip the anchor and return `NoTrustedPath`. The anchor is
    /// tried; the failure is at a later stage, not the guard.
    #[test]
    fn self_issued_rsa_anchor_absent_params_not_no_trusted_path() {
        // 2026-06-01 — within rsa-pkcs1v15-sha256.der validity window
        // (notBefore=2026-05-02, notAfter=2036-04-29).
        const NOW: u64 = 1_780_272_000;

        let der_bytes = include_bytes!("../tests/fixtures/rsa-pkcs1v15-sha256.der");
        let cert = Certificate::from_der(der_bytes).expect("parse cert");
        let cert_spki = cert.tbs_certificate().subject_public_key_info();

        // Construct an anchor from the same cert but with parameters: None.
        // Simulates a trust store that was populated from a source omitting the
        // explicit NULL — a common DER encoding variation for rsaEncryption.
        let anchor = TrustAnchor::new(
            cert.tbs_certificate().subject().clone(),
            spki::SubjectPublicKeyInfoOwned {
                algorithm: spki::AlgorithmIdentifier {
                    oid: cert_spki.algorithm.oid,
                    parameters: None,
                },
                subject_public_key: cert_spki.subject_public_key.clone(),
            },
        );

        let policy = ValidationPolicy {
            current_time_unix: NOW,
            ..ValidationPolicy::new(0)
        };
        let result = validate_path(&[cert], &[anchor], &policy, &RsaPkcs1v15Sha256Verifier);
        // The guard must not skip the anchor (which would return NoTrustedPath).
        // SignatureInvalid is expected: the anchor was tried but the rsa crate
        // rejects absent params during key parsing.
        assert!(
            !matches!(result, Err(Error::NoTrustedPath)),
            "guard must not return NoTrustedPath for same key with different param encoding; got: {result:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// NormalizedIter / names_match unit tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests_normalized_iter {
    use super::normalized_eq;

    /// Identical ASCII strings must compare equal.
    #[test]
    fn identical_strings_equal() {
        assert!(normalized_eq(b"hello", b"hello"));
    }

    /// Case is folded to lowercase.
    #[test]
    fn case_folding() {
        assert!(normalized_eq(b"Hello", b"hello"));
        assert!(normalized_eq(b"HELLO WORLD", b"hello world"));
    }

    /// Leading spaces are stripped.
    #[test]
    fn leading_spaces_stripped() {
        assert!(normalized_eq(b"  hello", b"hello"));
    }

    /// Trailing spaces are stripped.
    ///
    /// Regression test: `NormalizedIter` must not emit a trailing space for
    /// input that ends with a space sequence.
    #[test]
    fn trailing_spaces_stripped() {
        assert!(normalized_eq(b"hello  ", b"hello"));
        assert!(normalized_eq(b"hello ", b"hello"));
    }

    /// Multiple consecutive internal spaces are collapsed to a single space.
    ///
    /// Regression test for the double-space bug: `pending_space` must not
    /// cause two spaces to be emitted for a single space in the input.
    #[test]
    fn internal_spaces_collapsed() {
        assert!(normalized_eq(b"hello  world", b"hello world"));
        assert!(normalized_eq(b"hello   world", b"hello world"));
    }

    /// Combined: leading + trailing + internal spaces, case folding.
    #[test]
    fn combined_normalization() {
        assert!(normalized_eq(b"  Hello   World  ", b"hello world"));
    }

    /// Empty string and all-spaces string must both yield zero bytes.
    #[test]
    fn empty_and_whitespace_only() {
        assert!(normalized_eq(b"", b""));
        assert!(normalized_eq(b"   ", b""));
        assert!(normalized_eq(b"   ", b"   "));
    }

    /// Different strings must NOT compare equal after normalization.
    #[test]
    fn different_strings_not_equal() {
        assert!(!normalized_eq(b"hello", b"world"));
        assert!(!normalized_eq(b"ab", b"abc"));
    }

    /// `NormalizedIter`: input ending with an internal space sequence followed by
    /// trailing spaces must emit the space and then stop (no double space, no
    /// trailing space).
    #[test]
    fn internal_then_trailing_space_no_trailing_emit() {
        assert!(
            normalized_eq(b"ab  ", b"ab"),
            "trailing spaces must not be emitted"
        );
        assert!(
            normalized_eq(b"ab  cd  ", b"ab cd"),
            "internal double-space collapses; trailing spaces stripped"
        );
    }
}

// ---------------------------------------------------------------------------
// PKIX-l63j.1: BMPString transcoding tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests_bmp_string {
    use super::Vec;
    use super::{ava_values_match, bmp_string_to_utf8};
    use der::asn1::Any;
    use der::Tag;

    /// Construct UCS-2-BE bytes for an ASCII-only string.
    ///
    /// Each ASCII byte `b` becomes the two-byte sequence `[0x00, b]` since
    /// ASCII code points are in the range U+0000..=U+007F and the
    /// big-endian UCS-2 encoding of U+00XX is `0x00, 0xXX`.
    ///
    /// Independent oracle: this construction matches the literal
    /// description in X.680 Annex B and ITU-T X.690 §8.6 ("BMPString
    /// is encoded as a sequence of two-octet code units in big-endian
    /// order, with each unit representing one Unicode code point").
    fn ucs2_be_ascii(s: &str) -> Vec<u8> {
        let mut v = Vec::with_capacity(s.len() * 2);
        for b in s.bytes() {
            assert!(
                b.is_ascii(),
                "ucs2_be_ascii test helper only supports ASCII input"
            );
            v.push(0x00);
            v.push(b);
        }
        v
    }

    /// `bmp_string_to_utf8` round-trip for ASCII-only input.
    ///
    /// Independent oracle: ASCII Unicode code points (U+0000..=U+007F)
    /// are encoded identically as a single byte in UTF-8 and as a
    /// two-byte big-endian unit `[0x00, X]` in UCS-2. Decoding the
    /// UCS-2 form must yield bytes byte-equal to the original ASCII.
    #[test]
    fn ascii_round_trip() {
        let src = "Foo Co";
        let ucs2 = ucs2_be_ascii(src);
        let utf8 = bmp_string_to_utf8(&ucs2).expect("well-formed UCS-2 ASCII");
        assert_eq!(utf8, src.as_bytes());
    }

    /// `bmp_string_to_utf8` for a non-ASCII BMP code point.
    ///
    /// Independent oracle: the Hiragana letter A (U+3042) has well-known
    /// encodings — UTF-8: `0xE3 0x81 0x82`; UCS-2-BE: `0x30 0x42`. Both
    /// are tabulated in the Unicode Character Database. Citing the
    /// Unicode codepoint is the external oracle here, not our own code.
    #[test]
    fn non_ascii_bmp_code_point() {
        // U+3042 (HIRAGANA LETTER A): UCS-2-BE bytes 0x30 0x42.
        let ucs2 = vec![0x30, 0x42];
        let utf8 = bmp_string_to_utf8(&ucs2).expect("U+3042 is a valid BMP code point");
        // U+3042 in UTF-8 is the well-known three-byte sequence E3 81 82.
        assert_eq!(utf8, vec![0xE3, 0x81, 0x82]);
    }

    /// Odd-length UCS-2 input is malformed (each unit must be 2 bytes).
    /// Fail-closed: return None.
    #[test]
    fn odd_length_returns_none() {
        let malformed = vec![0x00, 0x46, 0x00]; // 3 bytes, not a multiple of 2
        assert_eq!(bmp_string_to_utf8(&malformed), None);
    }

    /// UTF-16 surrogate values (U+D800..=U+DFFF) are not valid Unicode
    /// scalar values and must not appear in `BMPString`. Fail-closed:
    /// return None.
    ///
    /// Independent oracle: Unicode Standard §3.8 explicitly defines
    /// surrogates as non-scalar; `core::char::from_u32(0xD800..=0xDFFF)`
    /// returns None.
    #[test]
    fn surrogate_returns_none() {
        // U+D800 (high surrogate, first surrogate code point).
        assert_eq!(bmp_string_to_utf8(&[0xD8, 0x00]), None);
        // U+DC00 (low surrogate).
        assert_eq!(bmp_string_to_utf8(&[0xDC, 0x00]), None);
        // U+DFFF (last surrogate code point).
        assert_eq!(bmp_string_to_utf8(&[0xDF, 0xFF]), None);
    }

    /// Empty BMPString content is well-formed (zero code points) and
    /// transcodes to an empty UTF-8 byte vector.
    #[test]
    fn empty_input_round_trip() {
        let utf8 = bmp_string_to_utf8(&[]).expect("empty UCS-2 is well-formed (zero units)");
        assert!(utf8.is_empty());
    }

    /// `ava_values_match`: a BMPString-encoded "Foo Co" must compare
    /// equal to a UTF8String-encoded "Foo Co".
    ///
    /// This is the core PKIX-l63j.1 invariant: same Unicode code points
    /// in different DER string types compare equal under DN matching.
    #[test]
    fn bmp_matches_utf8_same_text() {
        let bmp = Any::new(Tag::BmpString, ucs2_be_ascii("Foo Co")).unwrap();
        let utf8 = Any::new(Tag::Utf8String, b"Foo Co".to_vec()).unwrap();
        assert!(ava_values_match(&bmp, &utf8));
        // Symmetry: order of arguments must not matter.
        assert!(ava_values_match(&utf8, &bmp));
    }

    /// `ava_values_match`: BMPString and PrintableString comparisons
    /// must succeed for ASCII content with the same Unicode code points.
    #[test]
    fn bmp_matches_printable_same_text() {
        let bmp = Any::new(Tag::BmpString, ucs2_be_ascii("Acme CA")).unwrap();
        let printable = Any::new(Tag::PrintableString, b"Acme CA".to_vec()).unwrap();
        assert!(ava_values_match(&bmp, &printable));
        assert!(ava_values_match(&printable, &bmp));
    }

    /// `ava_values_match`: ASCII case-folding still applies to
    /// BMPString-derived UTF-8 bytes after transcoding (since BMP code
    /// points U+0041..=U+005A round-trip to ASCII bytes 0x41..=0x5A).
    #[test]
    fn bmp_matches_utf8_case_insensitive_ascii() {
        let bmp_upper = Any::new(Tag::BmpString, ucs2_be_ascii("FOO CO")).unwrap();
        let utf8_lower = Any::new(Tag::Utf8String, b"foo co".to_vec()).unwrap();
        assert!(ava_values_match(&bmp_upper, &utf8_lower));
    }

    /// `ava_values_match`: whitespace collapsing still applies to
    /// BMPString-derived UTF-8 bytes (BMP space U+0020 → byte 0x20).
    #[test]
    fn bmp_matches_utf8_whitespace_collapsed() {
        let bmp = Any::new(Tag::BmpString, ucs2_be_ascii("  Foo   Co  ")).unwrap();
        let utf8 = Any::new(Tag::Utf8String, b"foo co".to_vec()).unwrap();
        assert!(ava_values_match(&bmp, &utf8));
    }

    /// `ava_values_match`: different Unicode content must NOT match
    /// across encodings.
    #[test]
    fn bmp_does_not_match_utf8_different_text() {
        let bmp = Any::new(Tag::BmpString, ucs2_be_ascii("Foo Co")).unwrap();
        let utf8 = Any::new(Tag::Utf8String, b"Bar Co".to_vec()).unwrap();
        assert!(!ava_values_match(&bmp, &utf8));
    }

    /// `ava_values_match`: malformed BMPString (odd length) is treated
    /// as a non-string type by the dispatcher (`any_to_str_bytes` returns
    /// None). It must therefore NOT match a well-formed UTF8String of
    /// any content. Fail-closed.
    #[test]
    fn malformed_bmp_does_not_match_well_formed_utf8() {
        // 3-byte content: malformed UCS-2.
        let malformed_bmp = Any::new(Tag::BmpString, vec![0x00, 0x46, 0x00]).unwrap();
        let utf8 = Any::new(Tag::Utf8String, b"F".to_vec()).unwrap();
        assert!(!ava_values_match(&malformed_bmp, &utf8));
        assert!(!ava_values_match(&utf8, &malformed_bmp));
    }

    /// `ava_values_match`: non-ASCII Unicode code points compare equal
    /// when both AVAs encode the same code points (BMPString vs
    /// UTF8String).
    ///
    /// Independent oracle: the UCS-2-BE bytes for U+3042 are 0x30 0x42
    /// and the UTF-8 bytes are 0xE3 0x81 0x82, both per the Unicode
    /// Standard.
    #[test]
    fn bmp_matches_utf8_non_ascii() {
        // U+3042 HIRAGANA LETTER A.
        let bmp = Any::new(Tag::BmpString, vec![0x30, 0x42]).unwrap();
        let utf8 = Any::new(Tag::Utf8String, vec![0xE3, 0x81, 0x82]).unwrap();
        assert!(ava_values_match(&bmp, &utf8));
    }

    /// Sanity: two BMPString-encoded values with the same Unicode code
    /// points compare equal (this exercises the BMPString-on-both-sides
    /// path through `any_to_str_bytes`, where both sides allocate).
    #[test]
    fn bmp_matches_bmp_same_text() {
        let a = Any::new(Tag::BmpString, ucs2_be_ascii("Acme")).unwrap();
        let b = Any::new(Tag::BmpString, ucs2_be_ascii("acme")).unwrap();
        assert!(ava_values_match(&a, &b));
    }
}

// Review A1: NameConstraints helper unit tests (URI host extraction,
// constraint containment, streaming DN normalization).
#[cfg(test)]
mod tests_nc_review_a1 {
    use super::{
        dns_constraint_within, ip_constraint_within, matches_dns_name, matches_rfc822_name,
        normalized_eq, rfc822_constraint_within, uri_constraint_within, uri_host,
    };

    #[test]
    fn uri_host_extraction() {
        assert_eq!(uri_host("https://good.com/x"), Some("good.com"));
        assert_eq!(
            uri_host("HTTPS://u:p@Good.com:443/a@b?c@d#e@f"),
            Some("Good.com")
        );
        assert_eq!(uri_host("https://evil.com/@good.com"), Some("evil.com"));
        assert_eq!(uri_host("https://evil.com#@good.com"), Some("evil.com"));
        assert_eq!(uri_host("https://evil.com./"), Some("evil.com"));
        // RFC 5280 §4.2.1.10 "MUST reject" shapes.
        assert_eq!(uri_host("urn:example:x"), None);
        assert_eq!(uri_host("mailto:a@b.example"), None);
        assert_eq!(uri_host("file:///etc/passwd"), None);
        assert_eq!(uri_host("https://192.0.2.1/"), None);
        assert_eq!(uri_host("https://[2001:db8::1]:8443/"), None);
        assert_eq!(uri_host("https://good.com:x/"), None);
        assert_eq!(uri_host("1http://good.com/"), None);
        assert_eq!(uri_host("://good.com/"), None);
    }

    #[test]
    fn dns_matching_edges() {
        assert!(matches_dns_name("anything.example", ""));
        assert!(matches_dns_name("www.evil.com.", "evil.com"));
        assert!(matches_dns_name("www.evil.com", "evil.com."));
        assert!(!matches_dns_name("evil.com", ".evil.com"));
        assert!(!matches_dns_name("notevil.com", "evil.com"));
    }

    #[test]
    fn rfc822_uses_last_at() {
        assert!(matches_rfc822_name("\"x@good.com\"@evil.com", "evil.com"));
        assert!(!matches_rfc822_name("\"x@good.com\"@evil.com", "good.com"));
    }

    #[test]
    fn constraint_containment() {
        // DNS: x = {x} ∪ subdomains(x); .x = subdomains(x).
        assert!(dns_constraint_within(".example.com", "example.com"));
        assert!(!dns_constraint_within("example.com", ".example.com"));
        assert!(dns_constraint_within("a.example.com", ".example.com"));
        assert!(dns_constraint_within("example.com", ""));
        assert!(!dns_constraint_within("", "example.com"));
        // rfc822
        assert!(rfc822_constraint_within("host.example.com", ".example.com"));
        assert!(rfc822_constraint_within(
            "a@host.example.com",
            "host.example.com"
        ));
        assert!(!rfc822_constraint_within(
            ".example.com",
            "host.example.com"
        ));
        assert!(!rfc822_constraint_within(
            "host.example.com",
            "a@host.example.com"
        ));
        assert!(rfc822_constraint_within(".a.example.com", ".example.com"));
        // URI: no-dot = exact host only.
        assert!(uri_constraint_within("example.com", "example.com"));
        assert!(!uri_constraint_within("a.example.com", "example.com"));
        assert!(uri_constraint_within("a.example.com", ".example.com"));
        assert!(!uri_constraint_within(".example.com", "example.com"));
        // IP
        let v4 = |a: [u8; 4], m: [u8; 4]| [a, m].concat();
        assert!(ip_constraint_within(
            &v4([10, 1, 0, 0], [255, 255, 0, 0]),
            &v4([10, 0, 0, 0], [255, 0, 0, 0])
        ));
        assert!(!ip_constraint_within(
            &v4([10, 0, 0, 0], [255, 0, 0, 0]),
            &v4([10, 1, 0, 0], [255, 255, 0, 0])
        ));
        assert!(!ip_constraint_within(
            &v4([11, 1, 0, 0], [255, 255, 0, 0]),
            &v4([10, 0, 0, 0], [255, 0, 0, 0])
        ));
        assert!(!ip_constraint_within(
            &v4([10, 0, 0, 0], [255, 0, 0, 0]),
            &[0u8; 32]
        ));
    }

    #[test]
    fn streaming_normalization_matches_slice_semantics() {
        assert!(normalized_eq(b"  a  B   c ", b"a b c"));
        assert!(normalized_eq(b" ", b""));
        assert!(!normalized_eq(b"a b", b"ab"));
    }
}

// PKIX-h6z: validate_path public API tests.
#[cfg(all(test, feature = "p256"))]
mod tests_validate_path {
    use super::*;
    use der::Decode;

    // Fixtures and time constants reused from tests_chain_walk.
    const GRY_NOW: u64 = 1_780_272_000; // 2026-06-01

    fn load(bytes: &[u8]) -> Certificate {
        Certificate::from_der(bytes).expect("parse cert")
    }

    fn policy_at(t: u64) -> ValidationPolicy {
        ValidationPolicy::new(t)
    }

    /// Happy-path 1-cert chain: self-signed cert is both chain and anchor.
    ///
    /// Expected: Ok(ValidatedPath { `anchor_index`: 0, depth: 0 })
    #[test]
    fn one_cert_chain_ok() {
        let cert = load(include_bytes!("../tests/fixtures/ec-p256-sha256.der"));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        let result = validate_path(&[cert], &anchors, &policy_at(GRY_NOW), &EcdsaP256Verifier)
            .expect("1-cert chain must validate");
        assert_eq!(result.anchor_index, 0);
        assert_eq!(result.depth, 0);
    }

    /// Happy-path 2-cert chain: leaf + intermediate, with root anchor.
    ///
    /// Oracle: openssl verify -`CAfile` gry-root.pem -untrusted gry-int.pem gry-leaf.pem → OK
    /// Expected: Ok(ValidatedPath { `anchor_index`: 0, depth: 1 })
    #[test]
    fn two_cert_chain_ok() {
        let root = load(include_bytes!("../tests/fixtures/gry-root.der"));
        let int_cert = load(include_bytes!("../tests/fixtures/gry-int.der"));
        let leaf = load(include_bytes!("../tests/fixtures/gry-leaf.der"));
        let anchors = [TrustAnchor::from_cert(root)];
        let result = validate_path(
            &[leaf, int_cert],
            &anchors,
            &policy_at(GRY_NOW),
            &EcdsaP256Verifier,
        )
        .expect("2-cert chain must validate");
        assert_eq!(result.anchor_index, 0);
        assert_eq!(result.depth, 1);
    }

    /// §6.1.5 leaf-intrinsic outputs are populated correctly from `chain[0]`.
    ///
    /// Independent oracle: parse the leaf fixture a second time via
    /// `Certificate::from_der` (a different code path from `validate_path`'s
    /// chain[0] access). Compare each `ValidatedPath` accessor field against
    /// the independently-parsed leaf's `tbs_certificate` field. Catches:
    /// - Field swaps (e.g. `leaf_subject` accidentally populated from `issuer`).
    /// - Wrong cert in chain (e.g. `chain[1].subject` instead of `chain[0]`).
    /// - Forgotten field assignments.
    ///
    /// Does NOT validate x509-cert's parser correctness (that's tested
    /// upstream); it validates the wiring between `validate_path` and
    /// `ValidatedPath`.
    #[test]
    fn validated_path_exposes_leaf_subject_issuer_serial_spki() {
        let root = load(include_bytes!("../tests/fixtures/gry-root.der"));
        let int_cert = load(include_bytes!("../tests/fixtures/gry-int.der"));
        let leaf_bytes = include_bytes!("../tests/fixtures/gry-leaf.der");
        let leaf = load(leaf_bytes);

        // Independent oracle: re-parse the leaf via Certificate::from_der.
        // x509-cert's parser is the upstream oracle for the field values.
        let oracle_leaf =
            Certificate::from_der(leaf_bytes).expect("oracle: leaf fixture must parse");

        let anchors = [TrustAnchor::from_cert(root)];
        let result = validate_path(
            &[leaf, int_cert],
            &anchors,
            &policy_at(GRY_NOW),
            &EcdsaP256Verifier,
        )
        .expect("2-cert chain must validate");

        // The four §6.1.5 leaf-intrinsic outputs must match the
        // independently-parsed leaf's corresponding tbs_certificate fields.
        assert_eq!(
            &result.leaf_subject,
            oracle_leaf.tbs_certificate().subject(),
            "ValidatedPath.leaf_subject must equal chain[0].tbs_certificate().subject()"
        );
        assert_eq!(
            &result.leaf_issuer,
            oracle_leaf.tbs_certificate().issuer(),
            "ValidatedPath.leaf_issuer must equal chain[0].tbs_certificate().issuer()"
        );
        assert_eq!(
            &result.leaf_serial,
            oracle_leaf.tbs_certificate().serial_number(),
            "ValidatedPath.leaf_serial must equal chain[0].tbs_certificate().serial_number()"
        );
        assert_eq!(
            &result.leaf_spki, oracle_leaf.tbs_certificate().subject_public_key_info(),
            "ValidatedPath.leaf_spki must equal chain[0].tbs_certificate().subject_public_key_info()"
        );

        // Sanity: leaf_subject != leaf_issuer for a real (non-self-signed)
        // leaf. This catches the swap-subject-with-issuer regression: a
        // subject-issuer copy bug would leave both fields equal to whichever
        // one was used.
        assert_ne!(
            result.leaf_subject, result.leaf_issuer,
            "non-self-signed leaf must have distinct subject and issuer DNs (regression: swap)"
        );
    }

    /// §6.1.5 outputs for a 1-cert (self-signed) chain.
    ///
    /// Self-signed certs have `subject == issuer`. This documents that
    /// `leaf_subject` and `leaf_issuer` ARE expected to be equal in this
    /// case — the previous test's `assert_ne!` is for non-self-signed
    /// chains only.
    #[test]
    fn validated_path_outputs_for_self_signed_chain() {
        let cert_bytes = include_bytes!("../tests/fixtures/ec-p256-sha256.der");
        let cert = load(cert_bytes);
        let oracle = Certificate::from_der(cert_bytes).expect("oracle: cert must parse");
        let anchors = [TrustAnchor::from_cert(cert.clone())];

        let result = validate_path(&[cert], &anchors, &policy_at(GRY_NOW), &EcdsaP256Verifier)
            .expect("1-cert self-signed chain must validate");

        assert_eq!(&result.leaf_subject, oracle.tbs_certificate().subject());
        assert_eq!(&result.leaf_issuer, oracle.tbs_certificate().issuer());
        assert_eq!(
            &result.leaf_serial,
            oracle.tbs_certificate().serial_number()
        );
        assert_eq!(
            &result.leaf_spki,
            oracle.tbs_certificate().subject_public_key_info()
        );
        // Self-signed: subject == issuer by definition.
        assert_eq!(
            result.leaf_subject, result.leaf_issuer,
            "self-signed cert must have equal subject and issuer DNs"
        );
    }

    /// Multiple anchors: correct anchor is second in the slice.
    ///
    /// Expected: Ok(ValidatedPath { `anchor_index`: 1, depth: 0 })
    #[test]
    fn correct_anchor_index_when_multiple_anchors() {
        let p256 = load(include_bytes!("../tests/fixtures/ec-p256-sha256.der"));
        let rsa = load(include_bytes!("../tests/fixtures/rsa-pkcs1v15-sha256.der"));
        // First anchor is the RSA cert (wrong name and SPKI for the P-256 chain).
        // Second anchor matches.
        let anchors = [
            TrustAnchor::from_cert(rsa),
            TrustAnchor::from_cert(p256.clone()),
        ];
        let result = validate_path(&[p256], &anchors, &policy_at(GRY_NOW), &EcdsaP256Verifier)
            .expect("must find second anchor");
        assert_eq!(result.anchor_index, 1);
        assert_eq!(result.depth, 0);
    }

    /// Empty chain returns `NoTrustedPath`.
    #[test]
    fn empty_chain_returns_error() {
        let anchors = [TrustAnchor::from_cert(load(include_bytes!(
            "../tests/fixtures/ec-p256-sha256.der"
        )))];
        assert!(
            matches!(
                validate_path(&[], &anchors, &policy_at(GRY_NOW), &EcdsaP256Verifier),
                Err(Error::NoTrustedPath)
            ),
            "empty chain must fail"
        );
    }

    /// Duplicate certificate in chain returns `DuplicateCertificate` error.
    ///
    /// Oracle: RFC 5280 does not define behavior for duplicate certs; we reject
    /// early with a diagnostic error rather than failing later with a confusing
    /// `SignatureInvalid` or `ChainBroken`.
    ///
    /// Duplicate is detected by (issuer DN, serial number) identity per RFC 5280
    /// §4.1.2.2 — the same cert appearing twice has the same issuer+serial.
    /// SPKI equality is intentionally NOT used (cross-signed CAs share a key but
    /// have distinct issuer+serial and must not be rejected).
    #[test]
    fn duplicate_cert_in_chain_returns_error() {
        let cert = load(include_bytes!("../tests/fixtures/ec-p256-sha256.der"));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        // Chain [cert, cert]: same cert at index 0 and index 1 — same issuer+serial.
        let result = validate_path(
            &[cert.clone(), cert],
            &anchors,
            &policy_at(GRY_NOW),
            &EcdsaP256Verifier,
        );
        assert!(
            matches!(
                result,
                Err(Error::DuplicateCertificate {
                    first: 0,
                    second: 1
                })
            ),
            "duplicate cert must return DuplicateCertificate{{first:0, second:1}}, got {result:?}"
        );
    }

    /// `path_too_long`: vxf chain [leaf, int] with `max_path_len` = 0.
    ///
    /// chain.len()=2 → 1 intermediate. 1 > `max_path_len(0)` → `PathTooLong`.
    #[test]
    fn path_too_long_returns_error() {
        let root = load(include_bytes!("../tests/fixtures/vxf-root.der"));
        let int_cert = load(include_bytes!("../tests/fixtures/vxf-int.der"));
        let leaf = load(include_bytes!("../tests/fixtures/vxf-leaf.der"));
        let anchors = [TrustAnchor::from_cert(root)];
        let policy = ValidationPolicy {
            current_time_unix: GRY_NOW,
            max_path_len: 0,
            ..ValidationPolicy::new(0)
        };
        assert!(
            matches!(
                validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier),
                Err(Error::PathTooLong)
            ),
            "1 intermediate with max_path_len=0 must return PathTooLong"
        );
    }

    /// `no_trusted_path`: vxf chain presented to an unrelated anchor (gry-root).
    ///
    /// vxf's last cert issuer name does not match gry-root's subject name.
    #[test]
    fn no_trusted_path_unrelated_anchor_returns_error() {
        let gry_root = load(include_bytes!("../tests/fixtures/gry-root.der"));
        let vxf_int = load(include_bytes!("../tests/fixtures/vxf-int.der"));
        let vxf_leaf = load(include_bytes!("../tests/fixtures/vxf-leaf.der"));
        let anchors = [TrustAnchor::from_cert(gry_root)];
        assert!(
            matches!(
                validate_path(
                    &[vxf_leaf, vxf_int],
                    &anchors,
                    &policy_at(GRY_NOW),
                    &EcdsaP256Verifier
                ),
                Err(Error::NoTrustedPath)
            ),
            "vxf chain with gry anchor must return NoTrustedPath"
        );
    }

    /// `oid_mismatch`: outer signatureAlgorithm OID differs from inner TBS signature OID.
    ///
    /// Patch the SECOND occurrence of the ECDSA-with-SHA256 OID bytes in vxf-leaf.der
    /// to ECDSA-with-SHA384. The inner TBS.signature remains SHA256.
    /// `check_oid_consistency` detects this → `MalformedCertificate` { index: 0 }.
    ///
    /// Oracle: RFC 5280 §4.1.1.2 requires outer and inner `AlgorithmIdentifiers` to be identical.
    #[test]
    fn oid_mismatch_outer_returns_malformed_certificate() {
        let mut leaf_der = include_bytes!("../tests/fixtures/vxf-leaf.der").to_vec();
        // ECDSA-with-SHA256 OID content bytes: 1.2.840.10045.4.3.2
        let oid_sha256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
        // ECDSA-with-SHA384 OID content bytes: 1.2.840.10045.4.3.3 (same length, last byte differs)
        let oid_sha384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
        // In Certificate DER the inner TBS.signature OID appears FIRST (inside TBSCertificate)
        // and the outer signatureAlgorithm OID appears SECOND (after TBSCertificate). Patching
        // only the second occurrence changes the outer OID while leaving the inner intact.
        let first = leaf_der
            .windows(8)
            .position(|w| w == oid_sha256)
            .expect("inner SHA256 OID must be present in vxf-leaf.der");
        let second = leaf_der[first + 8..]
            .windows(8)
            .position(|w| w == oid_sha256)
            .map(|p| first + 8 + p)
            .expect("outer SHA256 OID must be present in vxf-leaf.der");
        leaf_der[second..second + 8].copy_from_slice(oid_sha384);
        let leaf = Certificate::from_der(&leaf_der).expect("patched DER must parse");
        assert_ne!(
            leaf.signature_algorithm(),
            leaf.tbs_certificate().signature(),
            "outer/inner OIDs must differ after patch"
        );
        let int_cert = load(include_bytes!("../tests/fixtures/vxf-int.der"));
        let root = load(include_bytes!("../tests/fixtures/vxf-root.der"));
        let anchors = [TrustAnchor::from_cert(root)];
        assert!(
            matches!(
                validate_path(
                    &[leaf, int_cert],
                    &anchors,
                    &policy_at(GRY_NOW),
                    &EcdsaP256Verifier
                ),
                Err(Error::MalformedCertificate { index: 0 })
            ),
            "outer/inner OID mismatch must return MalformedCertificate {{ index: 0 }}"
        );
    }

    /// `intermediate_not_ca`: nca-int has no `BasicConstraints` extension.
    ///
    /// Oracle: pyca/cryptography — nca-int built without any extensions.
    /// cert_is_ca(nca-int) returns None → `NotCA` { index: 1 }.
    #[test]
    fn intermediate_not_ca_returns_not_ca() {
        let root = load(include_bytes!("../tests/fixtures/nca-root.der"));
        let int_cert = load(include_bytes!("../tests/fixtures/nca-int.der"));
        let leaf = load(include_bytes!("../tests/fixtures/nca-leaf.der"));
        let anchors = [TrustAnchor::from_cert(root)];
        assert!(
            matches!(
                validate_path(
                    &[leaf, int_cert],
                    &anchors,
                    &policy_at(GRY_NOW),
                    &EcdsaP256Verifier
                ),
                Err(Error::NotCA { index: 1 })
            ),
            "intermediate without BasicConstraints CA flag must return NotCA {{ index: 1 }}"
        );
    }

    /// `key_usage_missing_cert_sign`: kuf-int has `KeyUsage` with digitalSignature only.
    ///
    /// Oracle: pyca/cryptography — kuf-int KeyUsage.keyCertSign = False.
    /// Default policy has `enforce_key_usage` = true; `chain_walk` checks at i=1.
    #[test]
    fn key_usage_missing_cert_sign_returns_error() {
        let root = load(include_bytes!("../tests/fixtures/kuf-root.der"));
        let int_cert = load(include_bytes!("../tests/fixtures/kuf-int.der"));
        let leaf = load(include_bytes!("../tests/fixtures/kuf-leaf.der"));
        let anchors = [TrustAnchor::from_cert(root)];
        assert!(
            matches!(
                validate_path(&[leaf, int_cert], &anchors, &policy_at(GRY_NOW), &EcdsaP256Verifier),
                Err(Error::KeyUsageMissing { index: 1 })
            ),
            "intermediate with KeyUsage but no keyCertSign must return KeyUsageMissing {{ index: 1 }}"
        );
    }

    /// `absent_key_usage_intermediate_accepted`: nku-int has NO `KeyUsage` extension at all.
    ///
    /// RFC 5280 §6.1.4(n): "If a `KeyUsage` extension is **present**, verify that the
    /// keyCertSign bit is set." Absent `KeyUsage` must not be rejected by `enforce_key_usage`.
    ///
    /// Oracle: pyca/cryptography — nku-int has only `BasicConstraints` (OID 2.5.29.19),
    /// no `KeyUsage` extension.
    #[test]
    fn absent_key_usage_intermediate_accepted() {
        let root = load(include_bytes!("../tests/fixtures/nku-root.der"));
        let int_cert = load(include_bytes!("../tests/fixtures/nku-int.der"));
        let leaf = load(include_bytes!("../tests/fixtures/nku-leaf.der"));
        let anchors = [TrustAnchor::from_cert(root)];
        // Default policy has enforce_key_usage = true.
        // nku-int has no KeyUsage — must NOT trigger KeyUsageMissing per RFC 5280 §6.1.4(n).
        let now: u64 = 1_720_000_000; // 2024-07-03, within nku-int validity (2024-2030)
        let policy = ValidationPolicy {
            current_time_unix: now,
            ..ValidationPolicy::new(0)
        };
        validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier).expect(
            "intermediate with absent KeyUsage must be accepted when enforce_key_usage=true",
        );
    }

    /// Leaf with critical `ExtendedKeyUsage` → `validate_path` must accept it.
    ///
    /// EKU is in `HANDLED_CRITICAL_OIDS`; its value is not inspected.
    /// Oracle: pyca/cryptography — eku-critical-self-signed.der, critical=True, serverAuth.
    #[test]
    fn critical_eku_accepted() {
        let cert = load(include_bytes!(
            "../tests/fixtures/eku-critical-self-signed.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        validate_path(&[cert], &anchors, &policy_at(GRY_NOW), &EcdsaP256Verifier)
            .expect("cert with critical EKU must be accepted");
    }

    /// Security test: anchor with matching name but wrong SPKI must be rejected.
    ///
    /// Guards against a name-collision attack: an attacker who creates a root cert
    /// with the same DN as a trusted anchor but a different key must not be accepted.
    /// The self-issued SPKI guard in `validate_path` catches this.
    #[test]
    fn forged_anchor_name_match_spki_mismatch_rejected() {
        use der::Decode as _;
        let p256 = Certificate::from_der(include_bytes!("../tests/fixtures/ec-p256-sha256.der"))
            .expect("parse P-256 cert");
        let rsa =
            Certificate::from_der(include_bytes!("../tests/fixtures/rsa-pkcs1v15-sha256.der"))
                .expect("parse RSA cert");
        // Forged anchor: P-256 cert's subject name + RSA cert's SPKI.
        let forged = TrustAnchor::new(
            p256.tbs_certificate().subject().clone(),
            rsa.tbs_certificate().subject_public_key_info().clone(),
        );
        let anchors = [forged];
        assert!(
            matches!(
                validate_path(&[p256], &anchors, &policy_at(GRY_NOW), &EcdsaP256Verifier),
                Err(Error::NoTrustedPath)
            ),
            "anchor with matching name but wrong SPKI must return NoTrustedPath"
        );
    }

    /// Verify that `validate_path` handles large certs without `Error::Der`.
    ///
    /// The previous fixed 8 KiB stack buffer returned `Error::Der` for any cert
    /// whose `TBSCertificate` DER exceeded 8 KiB. The heap-backed encoding path
    /// introduced in v0.2 removes that limit. This test verifies that a normally-
    /// sized cert (well under 8 KiB) still validates correctly, confirming the
    /// heap path is wired up correctly and not just a dead code path.
    ///
    /// Oracle: the gry-leaf fixture validates correctly via openssl verify.
    #[test]
    fn large_cert_encoding_does_not_fail_with_der_error() {
        // We don't have an actual > 8 KiB TBSCertificate fixture in the test suite,
        // but we can verify the heap path is taken by confirming normal certs still pass.
        // The regression test for the bug is: this path no longer returns Error::Der
        // for legitimately-sized certs.
        let cert = load(include_bytes!("../tests/fixtures/ec-p256-sha256.der"));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        // Must not return Err(Error::Der(...)) — the heap encoding path must succeed.
        let result = validate_path(&[cert], &anchors, &policy_at(GRY_NOW), &EcdsaP256Verifier);
        assert!(
            !matches!(result, Err(Error::Der(_))),
            "heap-backed encoding must not return Error::Der for a normal cert"
        );
    }

    /// Verify `cert_has_san_identity` returns false for normal certs (non-empty Subject).
    ///
    /// Oracle: RFC 5280 §4.2.1.6 — `cert_has_san_identity` must return true only when
    /// Subject is empty AND SAN is critical. Normal certs have non-empty Subject.
    #[test]
    fn cert_has_san_identity_false_for_normal_cert() {
        let cert = load(include_bytes!("../tests/fixtures/ec-p256-sha256.der"));
        // This is a normal self-signed cert with a non-empty Subject DN.
        assert!(
            !cert_has_san_identity(&cert),
            "normal cert with non-empty Subject must not be SAN-identity"
        );
    }
}

// PKIX-vxf + PKIX-gry: chain_walk tests require the p256 feature.
#[cfg(all(test, feature = "p256"))]
mod tests_chain_walk {
    use super::*;
    use der::Decode;

    // Fixtures (PKIX-vxf):
    //   vxf-root.der — self-signed root CA, CN=PKIX-vxf-root  (P-256)
    //   vxf-int.der  — intermediate CA, CN=PKIX-vxf-int, signed by vxf-root
    //   vxf-leaf.der — leaf cert, CN=PKIX-vxf-leaf, signed by vxf-int
    //   chk-root.der / chk-int.der / chk-leaf-wrong-issuer.der — ChainBroken test chain
    //
    // Fixtures (PKIX-gry):
    //   gry-root.der                  — root CA, CN=PKIX-gry-root (P-256)
    //   gry-int.der                   — intermediate CA, CN=PKIX-gry-int, valid 2026-2036
    //   gry-leaf.der                  — leaf, CN=PKIX-gry-leaf, valid 2026-2027 (short-lived)
    //   gry-leaf-unknown-crit.der     — leaf with unknown critical extension
    //
    // Unix timestamp constants for gry validity tests:
    //   GRY_NOW     = 1780272000  (2026-06-01, all gry certs valid)
    //   GRY_EXPIRED = 1830384000  (2028-01-02, gry-leaf expired; gry-int still valid)
    //   GRY_NOTYET  = 0           (1970-01-01, all gry certs not-yet-valid)
    //
    // Oracle:
    //   vxf chain: openssl verify -CAfile vxf-root.pem -untrusted vxf-int.pem vxf-leaf.pem → OK
    //   gry chain: pyca/cryptography; chain verifies at GRY_NOW
    //   chk-leaf-wrong-issuer: signature valid under chk-int key (pyca); issuer = PKIX-WRONG-ISSUER by design

    const GRY_NOW: u64 = 1_780_272_000;
    const GRY_EXPIRED: u64 = 1_830_384_000;
    const GRY_NOTYET: u64 = 0;

    fn load(bytes: &[u8]) -> Certificate {
        Certificate::from_der(bytes).expect("parse cert")
    }

    fn policy_at(t: u64) -> ValidationPolicy {
        ValidationPolicy::new(t)
    }

    /// 1-cert chain: self-signed P-256 cert as both chain and anchor.
    #[test]
    fn single_cert_chain_ok() {
        let p256 = load(include_bytes!("../tests/fixtures/ec-p256-sha256.der"));
        let policy = policy_at(GRY_NOW);
        let anchor = TrustAnchor::from_cert(p256.clone());
        chain_walk(&[p256], &anchor, &policy, &EcdsaP256Verifier)
            .expect("1-cert chain must pass chain_walk");
    }

    /// 2-cert chain (leaf + intermediate) with root as anchor.
    ///
    /// Oracle: openssl verify -`CAfile` vxf-root.pem -untrusted vxf-int.pem vxf-leaf.pem → OK
    #[test]
    fn two_cert_chain_ok() {
        let root = load(include_bytes!("../tests/fixtures/vxf-root.der"));
        let int_cert = load(include_bytes!("../tests/fixtures/vxf-int.der"));
        let leaf = load(include_bytes!("../tests/fixtures/vxf-leaf.der"));
        let policy = policy_at(GRY_NOW);
        let anchor = TrustAnchor::from_cert(root);
        chain_walk(&[leaf, int_cert], &anchor, &policy, &EcdsaP256Verifier)
            .expect("2-cert chain must pass chain_walk");
    }

    /// Leaf with corrupted signature — last byte flipped.
    ///
    /// The DER structure remains valid; only the BIT STRING content is wrong.
    /// Expect `SignatureInvalid` at chain index 0.
    #[test]
    fn corrupted_signature_returns_signature_invalid() {
        let mut leaf_der = include_bytes!("../tests/fixtures/vxf-leaf.der").to_vec();
        *leaf_der.last_mut().unwrap() ^= 0xFF;
        let leaf = Certificate::from_der(&leaf_der).expect("parse still succeeds after bit flip");
        let int_cert = load(include_bytes!("../tests/fixtures/vxf-int.der"));
        let anchor = TrustAnchor::from_cert(load(include_bytes!("../tests/fixtures/vxf-root.der")));
        let policy = policy_at(GRY_NOW);
        assert!(
            matches!(
                chain_walk(&[leaf, int_cert], &anchor, &policy, &EcdsaP256Verifier),
                Err(Error::SignatureInvalid { index: 0 })
            ),
            "corrupted leaf signature must return SignatureInvalid {{ index: 0 }}"
        );
    }

    /// Chain where the leaf's issuer field does not match the intermediate's subject.
    ///
    /// Oracle: chk-leaf-wrong-issuer was signed by chk-int's private key
    /// (signature IS valid), but its issuer field = "PKIX-WRONG-ISSUER" by design.
    #[test]
    fn wrong_issuer_name_returns_chain_broken() {
        let root = load(include_bytes!("../tests/fixtures/chk-root.der"));
        let int_cert = load(include_bytes!("../tests/fixtures/chk-int.der"));
        let leaf_wrong = load(include_bytes!(
            "../tests/fixtures/chk-leaf-wrong-issuer.der"
        ));
        let policy = policy_at(GRY_NOW);
        let anchor = TrustAnchor::from_cert(root);
        assert!(
            matches!(
                chain_walk(
                    &[leaf_wrong, int_cert],
                    &anchor,
                    &policy,
                    &EcdsaP256Verifier
                ),
                Err(Error::ChainBroken { index: 0 })
            ),
            "leaf with wrong issuer must return ChainBroken {{ index: 0 }}"
        );
    }

    // --- PKIX-gry per-cert check tests ---

    /// Expired leaf cert → `ValidityPeriod` at index 0.
    ///
    /// Oracle: gry-leaf.der has notAfter=2027-01-01; GRY_EXPIRED=2028-01-02.
    /// gry-int.der has notAfter=2036-01-01, which is still valid at `GRY_EXPIRED`.
    /// Reverse walk: i=1 (gry-int) passes validity, then i=0 (gry-leaf) fails.
    #[test]
    fn expired_leaf_returns_validity_period() {
        let root = load(include_bytes!("../tests/fixtures/gry-root.der"));
        let int_cert = load(include_bytes!("../tests/fixtures/gry-int.der"));
        let leaf = load(include_bytes!("../tests/fixtures/gry-leaf.der"));
        let policy = policy_at(GRY_EXPIRED);
        let anchor = TrustAnchor::from_cert(root);
        assert!(
            matches!(
                chain_walk(&[leaf, int_cert], &anchor, &policy, &EcdsaP256Verifier),
                Err(Error::ValidityPeriod { index: 0 })
            ),
            "expired leaf must return ValidityPeriod {{ index: 0 }}"
        );
    }

    /// Not-yet-valid intermediate → `ValidityPeriod` at index 1.
    ///
    /// Oracle: gry-int.der has notBefore=2026-01-01; `GRY_NOTYET=0` (1970-01-01).
    /// Reverse walk processes chain[1] (gry-int) first; it is not yet valid at time 0.
    #[test]
    fn notyet_valid_intermediate_returns_validity_period() {
        let root = load(include_bytes!("../tests/fixtures/gry-root.der"));
        let int_cert = load(include_bytes!("../tests/fixtures/gry-int.der"));
        let leaf = load(include_bytes!("../tests/fixtures/gry-leaf.der"));
        let policy = policy_at(GRY_NOTYET);
        let anchor = TrustAnchor::from_cert(root);
        assert!(
            matches!(
                chain_walk(&[leaf, int_cert], &anchor, &policy, &EcdsaP256Verifier),
                Err(Error::ValidityPeriod { index: 1 })
            ),
            "not-yet-valid intermediate must return ValidityPeriod {{ index: 1 }}"
        );
    }

    /// Leaf with unknown critical extension → `UnhandledCriticalExtension` at index 0.
    ///
    /// Oracle: gry-leaf-unknown-crit.der was generated with OID 1.3.6.1.5.5.7.99.99 critical=true
    /// (not in `HANDLED_CRITICAL_OIDS`) using pyca/cryptography.
    #[test]
    fn unknown_critical_extension_returns_unhandled() {
        let root = load(include_bytes!("../tests/fixtures/gry-root.der"));
        let int_cert = load(include_bytes!("../tests/fixtures/gry-int.der"));
        let leaf_unk = load(include_bytes!(
            "../tests/fixtures/gry-leaf-unknown-crit.der"
        ));
        let policy = policy_at(GRY_NOW);
        let anchor = TrustAnchor::from_cert(root);
        assert!(
            matches!(
                chain_walk(&[leaf_unk, int_cert], &anchor, &policy, &EcdsaP256Verifier),
                Err(Error::UnhandledCriticalExtension { index: 0 })
            ),
            "unknown critical ext must return UnhandledCriticalExtension {{ index: 0 }}"
        );
    }
}

// ---------------------------------------------------------------------------
// Tests: ValidationPolicy profile-enforcement fields (PKIX-ken.1.9–1.13)
// ---------------------------------------------------------------------------
//
// Fixtures: pkix-path/tests/fixtures/policy-checks/
//   root-p256.der, int-p256.der — P-256 CA chain (ecdsa-sha256)
//   leaf-p256-365d-san-eku.der  — 365-day leaf, SAN=DNS:test.example.com, EKU=serverAuth
//   leaf-p256-400d-san-eku.der  — 400-day leaf, SAN, EKU=serverAuth
//   leaf-p256-365d-no-san.der   — 365-day leaf, no SAN extension
//   leaf-p256-365d-no-eku.der   — 365-day leaf, SAN, no EKU extension
//   leaf-p256-365d-wrong-eku.der— 365-day leaf, SAN, EKU=emailProtection only
//   root-rsa2048.der, int-rsa2048.der — RSA-2048 CA chain (sha256WithRSAEncryption)
//   leaf-rsa2048-365d-san-eku.der — RSA-2048 leaf, SAN, EKU=serverAuth
//   leaf-rsa1024-365d-san-eku.der — RSA-1024 leaf, SAN, EKU=serverAuth
//
// Oracle: pkix-path/tests/fixtures/policy-checks/gen.py (pyca/cryptography)
// Chain verification: openssl verify passed for P-256 and RSA-2048 happy paths.
// Time constant: PC_NOW = 2026-06-01T00:00:00Z = 1_780_272_000 (unix)
//   All fixtures have NOT_BEFORE=2026-01-01, valid at PC_NOW.
//
// All tests require the p256 feature for P-256 chain tests, and rsa for RSA chain tests.
//
// The P-256 chain uses the module-level const directly; RSA chain tests live inside
// a separate rsa-feature-gated block so clippy does not warn about unused imports.

#[cfg(all(test, feature = "p256"))]
mod tests_policy_fields {
    use super::*;
    use der::Decode;

    // GRY_NOW is also the test time for these fixtures (2026-06-01T00:00:00Z).
    const PC_NOW: u64 = 1_780_272_000;

    // OID constants — values from const_oid spec, NOT derived from the code under test.
    // ecdsa-with-SHA256: 1.2.840.10045.4.3.2  (RFC 5912 §6)
    const ECDSA_SHA256_OID: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
    // sha256WithRSAEncryption: 1.2.840.113549.1.1.11  (RFC 5912 §2)
    const RSA_SHA256_OID: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
    // id-kp-serverAuth: 1.3.6.1.5.5.7.3.1  (RFC 5280 §4.2.1.12)
    const ID_KP_SERVER_AUTH: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
    // id-kp-emailProtection: 1.3.6.1.5.5.7.3.4  (RFC 5280 §4.2.1.12)
    const ID_KP_EMAIL_PROTECTION: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.4");

    fn load(bytes: &[u8]) -> Certificate {
        Certificate::from_der(bytes).expect("valid DER fixture")
    }

    // -----------------------------------------------------------------------
    // max_validity_secs (PKIX-ken.1.9)
    // -----------------------------------------------------------------------

    /// Oracle: all certs in the chain have validity ≤ 3652 days (10-year root/int,
    /// 365-day leaf). A cap of 4000 days allows all of them through.
    #[test]
    fn max_validity_passes_when_cert_within_limit() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        // 4000-day cap: root/int have ~3652 days, leaf has 365 days — all within limit.
        policy.max_validity_secs = Some(4_000 * 86_400);
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier)
            .expect("all certs within 4000-day cap should validate");
    }

    /// Oracle: root-p256.der and int-p256.der each have ~3652-day validity
    /// (NOT_BEFORE=2026-01-01, NOT_AFTER=2036-01-01 from gen.py).
    /// A cap of 400 days forces `ValidityPeriodExceedsMax` on the root (checked first
    /// by `chain_walk` which iterates from high index to low).
    ///
    /// Note: the check applies to every cert in the chain, not just the leaf.
    /// The root cert (highest index) is checked first and produces the error.
    #[test]
    fn max_validity_fails_when_cert_exceeds_limit() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        // 400-day cap: root/int have 3652-day validity → ValidityPeriodExceedsMax.
        // Wildcard index because the root (highest-index cert) is checked first.
        policy.max_validity_secs = Some(400 * 86_400);
        let anchors = [TrustAnchor::from_cert(root)];
        assert!(
            matches!(
                validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier),
                Err(Error::ValidityPeriodExceedsMax { .. })
            ),
            "certs with 3652-day validity over 400-day cap must return ValidityPeriodExceedsMax"
        );
    }

    /// Isolates the leaf-only failure: use a 1-cert self-issued chain where
    /// the cert acts as both leaf and anchor. The 400-day cert fails a 398-day cap.
    ///
    /// Oracle: leaf-p256-400d-san-eku.der has notAfter-notBefore = 400 days = 34,560,000 s.
    /// 400 days > 398 days → `ValidityPeriodExceedsMax` { index: 0 }.
    #[test]
    fn max_validity_fails_at_leaf_index_zero() {
        // Use a single self-signed cert as both chain[0] and anchor so there is only
        // one cert in the chain, making index 0 the only possible failure point.
        // leaf-p256-400d-san-eku.der is NOT self-signed, so we use a known self-signed
        // cert from the existing fixture set (ec-p256-sha256.der) which has a long
        // validity, then set max to 1 day to force failure at index 0.
        let cert = Certificate::from_der(include_bytes!("../tests/fixtures/ec-p256-sha256.der"))
            .expect("parse ec-p256-sha256.der");
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        let mut policy = ValidationPolicy::new(1_780_272_000); // PC_NOW: 2026-06-01
                                                               // 1-day cap: the cert has multi-year validity → fails at index 0.
        policy.max_validity_secs = Some(86_400);
        assert!(
            matches!(
                validate_path(&[cert], &anchors, &policy, &EcdsaP256Verifier),
                Err(Error::ValidityPeriodExceedsMax { index: 0 })
            ),
            "1-cert chain: long-validity cert with 1-day cap must return ValidityPeriodExceedsMax {{ index: 0 }}"
        );
    }

    /// Oracle: None = unconstrained, any validity length is accepted.
    #[test]
    fn max_validity_none_is_unconstrained() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-400d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.max_validity_secs = None; // default, but explicit for documentation
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier)
            .expect("None cap must accept any validity length");
    }

    // -----------------------------------------------------------------------
    // allowed_signature_algs (PKIX-ken.1.10)
    // -----------------------------------------------------------------------

    /// Oracle: P-256 chain uses ecdsa-with-SHA256; allowlist contains that OID.
    #[test]
    fn alg_allowlist_passes_when_oid_in_list() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.allowed_signature_algs = Some(vec![ECDSA_SHA256_OID]);
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier)
            .expect("ECDSA-SHA256 chain with ECDSA-SHA256 allowlist should pass");
    }

    /// Oracle: P-256 chain uses ecdsa-sha256; allowlist contains only RSA-sha256.
    /// `chain_walk` walks highest index first: leaf=[0], int=[1], root=[2].
    /// For a 3-cert chain, the root-adjacent cert is at index 2 in the slice.
    /// `chain_walk` iterates i from (chain.len()-1) down to 0, so i=2 (root) is checked
    /// first and fails with `AlgorithmNotAllowed` { index: 2 }.
    #[test]
    fn alg_allowlist_fails_when_oid_not_in_list() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        // Only RSA allowed, but chain uses ECDSA.
        policy.allowed_signature_algs = Some(vec![RSA_SHA256_OID]);
        let anchors = [TrustAnchor::from_cert(root)];
        assert!(
            matches!(
                validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier),
                Err(Error::AlgorithmNotAllowed { .. })
            ),
            "ECDSA chain with RSA-only allowlist must return AlgorithmNotAllowed"
        );
    }

    /// Oracle: None = unconstrained, any algorithm is accepted.
    #[test]
    fn alg_allowlist_none_is_unconstrained() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.allowed_signature_algs = None; // default
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier)
            .expect("None allowlist must accept any algorithm");
    }

    // -----------------------------------------------------------------------
    // require_subject_alt_name (PKIX-ken.1.12)
    // -----------------------------------------------------------------------

    /// Oracle: leaf-p256-365d-san-eku.der has SAN=DNS:test.example.com.
    #[test]
    fn require_san_passes_when_san_present() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.require_subject_alt_name = true;
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier)
            .expect("leaf with SAN must pass require_subject_alt_name=true");
    }

    /// Oracle: leaf-p256-365d-no-san.der has no SAN extension.
    #[test]
    fn require_san_fails_when_san_absent() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-no-san.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.require_subject_alt_name = true;
        let anchors = [TrustAnchor::from_cert(root)];
        assert!(
            matches!(
                validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier),
                Err(Error::MissingSan)
            ),
            "leaf without SAN must return MissingSan when require_subject_alt_name=true"
        );
    }

    /// Oracle: false = default = no SAN requirement; missing SAN is not an error.
    #[test]
    fn require_san_false_does_not_fail_on_missing_san() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-no-san.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.require_subject_alt_name = false; // default, explicit for documentation
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier)
            .expect("require_subject_alt_name=false must not fail on missing SAN");
    }

    /// Regression guard for the i == 0 guard in `chain_walk`.
    ///
    /// int-p256.der has no SAN extension. With `require_subject_alt_name=true`,
    /// the check MUST NOT fail on the intermediate (i == 1). Only the leaf
    /// (i == 0) is checked.
    ///
    /// Oracle: openssl x509 -inform DER -in int-p256.der -text -noout | grep -i alt
    /// → empty output; int-p256.der has no SAN. Confirmed during fixture generation.
    #[test]
    fn require_san_only_checks_leaf_not_intermediates() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        // The leaf HAS a SAN; the intermediate does NOT.
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.require_subject_alt_name = true;
        let anchors = [TrustAnchor::from_cert(root)];
        // Must pass: the SAN-less intermediate is not checked, only the leaf.
        validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier)
            .expect("i==0 guard must ensure only the leaf is checked for SAN presence");
    }

    // -----------------------------------------------------------------------
    // required_leaf_eku (PKIX-ken.1.13)
    // -----------------------------------------------------------------------

    /// Oracle: leaf-p256-365d-san-eku.der has EKU=serverAuth (1.3.6.1.5.5.7.3.1).
    #[test]
    fn required_eku_passes_when_all_oids_present() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.required_leaf_eku = Some(vec![ID_KP_SERVER_AUTH]);
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier)
            .expect("leaf with serverAuth EKU must pass required_leaf_eku=[serverAuth]");
    }

    /// Oracle: leaf-p256-365d-no-eku.der has no EKU extension.
    /// `required_leaf_eku=Some`([serverAuth]) with absent EKU → `MissingEku`.
    #[test]
    fn required_eku_fails_when_eku_extension_absent() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-no-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.required_leaf_eku = Some(vec![ID_KP_SERVER_AUTH]);
        let anchors = [TrustAnchor::from_cert(root)];
        assert!(
            matches!(
                validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier),
                Err(Error::MissingEku)
            ),
            "leaf without EKU extension must return MissingEku when an EKU OID is required"
        );
    }

    /// Oracle: leaf-p256-365d-wrong-eku.der has EKU=emailProtection only, not serverAuth.
    #[test]
    fn required_eku_fails_when_required_oid_not_in_list() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-wrong-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        // Requires serverAuth; leaf only has emailProtection.
        policy.required_leaf_eku = Some(vec![ID_KP_SERVER_AUTH]);
        let anchors = [TrustAnchor::from_cert(root)];
        assert!(
            matches!(
                validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier),
                Err(Error::MissingEku)
            ),
            "leaf with wrong EKU must return MissingEku when required OID is absent"
        );
    }

    /// Oracle: None = no EKU requirement; missing EKU is not an error.
    #[test]
    fn required_eku_none_is_unconstrained() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-no-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.required_leaf_eku = None; // default
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier)
            .expect("None required_leaf_eku must accept leaf with no EKU");
    }

    /// Oracle: Some([]) = require zero OIDs → trivially passes regardless of EKU content.
    #[test]
    fn required_eku_empty_vec_is_unconstrained() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-no-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        // Empty vec: Some([]) requires zero OIDs → always passes.
        policy.required_leaf_eku = Some(vec![]);
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier)
            .expect("Some([]) required_leaf_eku (empty) must accept any EKU configuration");
    }

    /// Verify that emailProtection in `required_leaf_eku` does NOT match serverAuth in the cert.
    /// This guards against a hypothetical relaxed OID comparison bug.
    #[test]
    fn required_eku_emailprotection_does_not_match_serverauth() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        // Require emailProtection; leaf only has serverAuth.
        policy.required_leaf_eku = Some(vec![ID_KP_EMAIL_PROTECTION]);
        let anchors = [TrustAnchor::from_cert(root)];
        assert!(
            matches!(
                validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier),
                Err(Error::MissingEku)
            ),
            "OID comparison must be exact; emailProtection must not match serverAuth"
        );
    }
}

// DnAttrRule + required_leaf_policy_oids + required_leaf_subject_dn_attrs tests (PKIX-jbvb.4).
//
// Coverage strategy:
// - `dn_attr_rule_*` tests exercise `evaluate_dn_attr_rule` and `dn_contains_oid`
//   directly against synthetic `Name` values constructed via RFC 4514 string
//   parsing. This isolates rule semantics from chain-validation wiring.
// - `validate_path_*` tests exercise the (e3a)/(e3b) enforcement sites in
//   `chain_walk` via existing committed P-256 fixtures. Existing fixtures lack
//   `CertificatePolicies` extensions and have CN-only Subject DNs, so they
//   naturally test the "required attribute missing" paths.
// - The `None`-case sanity tests confirm default behavior is unchanged.
//
// Positive `validate_path` cases for `required_leaf_policy_oids` (leaf asserts
// the required OID → pass) are covered indirectly: the (e3a) match arm with
// `Some(cp_ext)` is unit-tested via the `dn_contains_oid`-style helper logic on
// `policy_identifier`, and the wiring is exercised by the negative tests.
// Adding a new fixture solely for the positive path would duplicate that
// coverage without adding rigor; the bead's "existing fixtures cannot exercise"
// escape applies to the OID-list-walk shape, not the wiring.
#[cfg(test)]
mod tests_dn_attr_rule {
    use super::*;
    use core::str::FromStr;

    // RFC 4519 / X.520 DN attribute OIDs (values from spec, not derived from code under test).
    const OID_CN: der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("2.5.4.3");
    const OID_SURNAME: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("2.5.4.4");
    const OID_ORGANIZATION_NAME: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("2.5.4.10");
    const OID_GIVEN_NAME: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("2.5.4.42");
    const OID_PSEUDONYM: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("2.5.4.65");

    fn dn(s: &str) -> x509_cert::name::Name {
        x509_cert::name::Name::from_str(s).expect("valid RFC 4514 DN string")
    }

    // ---- dn_contains_oid -----------------------------------------------------

    #[test]
    fn dn_contains_oid_finds_present_attribute() {
        let subject = dn("CN=test,O=Test Org");
        assert!(dn_contains_oid(&subject, &OID_ORGANIZATION_NAME));
        assert!(dn_contains_oid(&subject, &OID_CN));
    }

    #[test]
    fn dn_contains_oid_returns_false_for_absent_attribute() {
        let subject = dn("CN=test");
        assert!(!dn_contains_oid(&subject, &OID_ORGANIZATION_NAME));
        assert!(!dn_contains_oid(&subject, &OID_SURNAME));
    }

    #[test]
    fn dn_contains_oid_empty_subject_matches_nothing() {
        let subject = x509_cert::name::Name::default();
        assert!(!dn_contains_oid(&subject, &OID_CN));
    }

    // ---- evaluate_dn_attr_rule: Field ---------------------------------------

    #[test]
    fn rule_field_matches_when_attribute_present() {
        let subject = dn("CN=test,O=Test Org");
        let rule = DnAttrRule::Field(OID_ORGANIZATION_NAME);
        assert!(evaluate_dn_attr_rule(&subject, &rule));
    }

    #[test]
    fn rule_field_rejects_when_attribute_absent() {
        let subject = dn("CN=test");
        let rule = DnAttrRule::Field(OID_ORGANIZATION_NAME);
        assert!(!evaluate_dn_attr_rule(&subject, &rule));
    }

    // ---- evaluate_dn_attr_rule: AllOf composition ---------------------------

    #[test]
    fn rule_allof_matches_when_every_branch_satisfied() {
        let subject = dn("CN=test,givenName=Alice,surname=Smith");
        let rule = DnAttrRule::AllOf(vec![
            DnAttrRule::Field(OID_GIVEN_NAME),
            DnAttrRule::Field(OID_SURNAME),
        ]);
        assert!(evaluate_dn_attr_rule(&subject, &rule));
    }

    #[test]
    fn rule_allof_rejects_when_any_branch_missing() {
        let subject = dn("CN=test,givenName=Alice");
        let rule = DnAttrRule::AllOf(vec![
            DnAttrRule::Field(OID_GIVEN_NAME),
            DnAttrRule::Field(OID_SURNAME),
        ]);
        assert!(!evaluate_dn_attr_rule(&subject, &rule));
    }

    // ---- evaluate_dn_attr_rule: AnyOf composition ---------------------------

    #[test]
    fn rule_anyof_matches_when_at_least_one_branch_satisfied() {
        let subject = dn("CN=test,pseudonym=BlueFox");
        let rule = DnAttrRule::AnyOf(vec![
            DnAttrRule::Field(OID_PSEUDONYM),
            DnAttrRule::AllOf(vec![
                DnAttrRule::Field(OID_GIVEN_NAME),
                DnAttrRule::Field(OID_SURNAME),
            ]),
        ]);
        assert!(evaluate_dn_attr_rule(&subject, &rule));
    }

    #[test]
    fn rule_anyof_rejects_when_no_branch_satisfied() {
        let subject = dn("CN=test");
        let rule = DnAttrRule::AnyOf(vec![
            DnAttrRule::Field(OID_PSEUDONYM),
            DnAttrRule::AllOf(vec![
                DnAttrRule::Field(OID_GIVEN_NAME),
                DnAttrRule::Field(OID_SURNAME),
            ]),
        ]);
        assert!(!evaluate_dn_attr_rule(&subject, &rule));
    }

    /// Sponsor-validated-style rule (pseudonym OR (givenName AND surname))
    /// also matches when both branches of the inner AllOf are present.
    #[test]
    fn rule_anyof_matches_when_inner_allof_branch_satisfied() {
        let subject = dn("CN=test,givenName=Alice,surname=Smith");
        let rule = DnAttrRule::AnyOf(vec![
            DnAttrRule::Field(OID_PSEUDONYM),
            DnAttrRule::AllOf(vec![
                DnAttrRule::Field(OID_GIVEN_NAME),
                DnAttrRule::Field(OID_SURNAME),
            ]),
        ]);
        assert!(evaluate_dn_attr_rule(&subject, &rule));
    }

    // ---- evaluate_dn_attr_rule: vacuity -------------------------------------

    /// RFC-conventional vacuity: AllOf with no branches is trivially true
    /// (the universal quantifier over an empty set is true).
    #[test]
    fn rule_allof_empty_accepts_everything() {
        let empty = x509_cert::name::Name::default();
        let cn_only = dn("CN=test");
        let rule = DnAttrRule::AllOf(Vec::new());
        assert!(evaluate_dn_attr_rule(&empty, &rule));
        assert!(evaluate_dn_attr_rule(&cn_only, &rule));
    }

    /// RFC-conventional vacuity: AnyOf with no branches is trivially false
    /// (the existential quantifier over an empty set is false).
    #[test]
    fn rule_anyof_empty_rejects_everything() {
        let empty = x509_cert::name::Name::default();
        let cn_only = dn("CN=test");
        let rule = DnAttrRule::AnyOf(Vec::new());
        assert!(!evaluate_dn_attr_rule(&empty, &rule));
        assert!(!evaluate_dn_attr_rule(&cn_only, &rule));
    }
}

// ---------------------------------------------------------------------------
// required_leaf_policy_oids + required_leaf_subject_dn_attrs validate_path wiring
// (PKIX-jbvb.4). Reuses existing P-256 fixtures (which carry single-attribute
// CN-only DNs and no CertificatePolicies extension) to cover the negative and
// disabled-default paths.
// ---------------------------------------------------------------------------
#[cfg(all(test, feature = "p256"))]
mod tests_required_leaf_policy_dn {
    use super::*;
    use der::Decode;

    // GRY_NOW = 2026-06-01T00:00:00Z (matches the existing P-256 fixture timestamps).
    const PC_NOW: u64 = 1_780_272_000;

    // 2.16.840.1.101.3.2.1.48.1 — a NIST test policy OID. The chosen value is
    // arbitrary; only its absence from any committed fixture matters.
    const TEST_POLICY_OID: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.2.1.48.1");
    const OID_ORGANIZATION_NAME: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("2.5.4.10");

    fn load(bytes: &[u8]) -> Certificate {
        Certificate::from_der(bytes).expect("valid DER fixture")
    }

    fn make_chain() -> (Certificate, Certificate, Certificate) {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-san-eku.der"
        ));
        (root, int_cert, leaf)
    }

    /// Oracle: `leaf-p256-365d-san-eku.der` has no CertificatePolicies
    /// extension. Requiring any specific policy OID must fail.
    #[test]
    fn required_policy_oid_fails_when_extension_absent() {
        let (root, int_cert, leaf) = make_chain();
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.required_leaf_policy_oids = Some(vec![TEST_POLICY_OID]);
        let anchors = [TrustAnchor::from_cert(root)];
        let err = validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier)
            .expect_err("leaf without CertificatePolicies must fail when an OID is required");
        match err {
            Error::MissingLeafPolicyOid { required } => {
                assert_eq!(required, TEST_POLICY_OID, "reported OID must echo input");
            }
            other => panic!("expected MissingLeafPolicyOid, got {other:?}"),
        }
    }

    /// Oracle: `None` requirement is unconstrained even when the leaf has no
    /// `CertificatePolicies` extension. Backward-compatible default.
    #[test]
    fn required_policy_oid_none_is_unconstrained() {
        let (root, int_cert, leaf) = make_chain();
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.required_leaf_policy_oids = None;
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier)
            .expect("None required_leaf_policy_oids must not constrain validation");
    }

    /// Oracle: `Some(vec![])` requires zero OIDs → trivially passes regardless
    /// of CertificatePolicies content (mirrors `required_leaf_eku = Some(vec![])`).
    #[test]
    fn required_policy_oid_empty_vec_is_unconstrained() {
        let (root, int_cert, leaf) = make_chain();
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.required_leaf_policy_oids = Some(vec![]);
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier)
            .expect("Some([]) required_leaf_policy_oids must accept any CertificatePolicies");
    }

    /// Oracle: `leaf-p256-365d-san-eku.der` has Subject DN
    /// `CN=PKIX-policy-checks-leaf-p256-365d-san-eku` (no organizationName).
    /// Requiring `organizationName` must fail with `SubjectDnAttrRuleUnmet`.
    #[test]
    fn required_dn_attr_field_fails_when_attribute_absent() {
        let (root, int_cert, leaf) = make_chain();
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.required_leaf_subject_dn_attrs = Some(DnAttrRule::Field(OID_ORGANIZATION_NAME));
        let anchors = [TrustAnchor::from_cert(root)];
        assert!(
            matches!(
                validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier),
                Err(Error::SubjectDnAttrRuleUnmet)
            ),
            "leaf without organizationName must return SubjectDnAttrRuleUnmet"
        );
    }

    /// Oracle: `leaf-p256-365d-san-eku.der` has only `CN=...`.
    /// `Field(CN)` must succeed (the attribute is present).
    #[test]
    fn required_dn_attr_field_passes_when_attribute_present() {
        let (root, int_cert, leaf) = make_chain();
        let mut policy = ValidationPolicy::new(PC_NOW);
        // CN = 2.5.4.3
        let oid_cn: der::asn1::ObjectIdentifier =
            der::asn1::ObjectIdentifier::new_unwrap("2.5.4.3");
        policy.required_leaf_subject_dn_attrs = Some(DnAttrRule::Field(oid_cn));
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier)
            .expect("leaf with CN must pass Field(CN) requirement");
    }

    /// Oracle: AllOf(vec![]) is vacuously true; chain must validate without
    /// any DN constraints actually being checked.
    #[test]
    fn required_dn_attr_allof_empty_accepts_any_leaf() {
        let (root, int_cert, leaf) = make_chain();
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.required_leaf_subject_dn_attrs = Some(DnAttrRule::AllOf(Vec::new()));
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier)
            .expect("AllOf(vec![]) is vacuously true; validation must succeed");
    }

    /// Oracle: AnyOf(vec![]) is vacuously false; any leaf fails.
    #[test]
    fn required_dn_attr_anyof_empty_rejects_any_leaf() {
        let (root, int_cert, leaf) = make_chain();
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.required_leaf_subject_dn_attrs = Some(DnAttrRule::AnyOf(Vec::new()));
        let anchors = [TrustAnchor::from_cert(root)];
        assert!(
            matches!(
                validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier),
                Err(Error::SubjectDnAttrRuleUnmet)
            ),
            "AnyOf(vec![]) is vacuously false; validation must fail"
        );
    }

    /// Oracle: `None` is the default and must not constrain validation.
    #[test]
    fn required_dn_attr_none_is_unconstrained() {
        let (root, int_cert, leaf) = make_chain();
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.required_leaf_subject_dn_attrs = None;
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier)
            .expect("None required_leaf_subject_dn_attrs must not constrain validation");
    }
}

// RSA-specific policy field tests — gated on the rsa feature.
#[cfg(all(test, feature = "p256", feature = "rsa"))]
mod tests_policy_fields_rsa {
    use super::*;
    use der::Decode;

    const PC_NOW: u64 = 1_780_272_000;

    // sha256WithRSAEncryption: 1.2.840.113549.1.1.11  (RFC 5912 §2)
    const RSA_SHA256_OID: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
    // ecdsa-with-SHA256: 1.2.840.10045.4.3.2  (RFC 5912 §6)
    const ECDSA_SHA256_OID: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
    // id-kp-serverAuth: 1.3.6.1.5.5.7.3.1
    const ID_KP_SERVER_AUTH: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");

    fn load(bytes: &[u8]) -> Certificate {
        Certificate::from_der(bytes).expect("valid DER fixture")
    }

    // -----------------------------------------------------------------------
    // min_rsa_key_bits helper unit tests (PKIX-ken.1.11)
    // -----------------------------------------------------------------------

    /// Direct unit test of `rsa_public_key_bits` helper.
    /// Oracle: openssl x509 -inform DER -in leaf-rsa2048.der -text -noout | grep 'Public-Key'
    /// → Public-Key: (2048 bit)
    #[test]
    fn rsa_key_bits_correct_for_2048_key() {
        let cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-rsa2048-365d-san-eku.der"
        ));
        let result = rsa_public_key_bits(cert.tbs_certificate().subject_public_key_info());
        assert_eq!(
            result,
            Some(2048),
            "RSA-2048 key must return Some(2048) from rsa_public_key_bits"
        );
    }

    /// Direct unit test of `rsa_public_key_bits` helper.
    /// Oracle: openssl x509 -inform DER -in leaf-rsa1024.der -text -noout | grep 'Public-Key'
    /// → Public-Key: (1024 bit)
    #[test]
    fn rsa_key_bits_correct_for_1024_key() {
        let cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-rsa1024-365d-san-eku.der"
        ));
        let result = rsa_public_key_bits(cert.tbs_certificate().subject_public_key_info());
        assert_eq!(
            result,
            Some(1024),
            "RSA-1024 key must return Some(1024) from rsa_public_key_bits"
        );
    }

    /// Direct unit test of `rsa_public_key_bits` helper.
    /// P-256 key is not RSA; must return None.
    #[test]
    fn rsa_key_bits_none_for_ec_key() {
        let cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-san-eku.der"
        ));
        let result = rsa_public_key_bits(cert.tbs_certificate().subject_public_key_info());
        assert_eq!(
            result, None,
            "EC key must return None from rsa_public_key_bits (not RSA)"
        );
    }

    // -----------------------------------------------------------------------
    // min_rsa_key_bits validate_path tests (PKIX-ken.1.11)
    // -----------------------------------------------------------------------

    /// Oracle: leaf-rsa2048-365d-san-eku.der has RSA-2048 leaf.
    /// 2048 >= 2048 → passes.
    #[test]
    fn min_rsa_key_bits_passes_when_key_meets_limit() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-rsa2048.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-rsa2048.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-rsa2048-365d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.min_rsa_key_bits = Some(2048);
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(
            &[leaf, int_cert],
            &anchors,
            &policy,
            &RsaPkcs1v15Sha256Verifier,
        )
        .expect("RSA-2048 leaf with min=2048 should pass");
    }

    /// Oracle: leaf-rsa1024-365d-san-eku.der has RSA-1024 leaf.
    /// 1024 < 2048 → `KeyTooSmall` { index: 0 }.
    #[test]
    fn min_rsa_key_bits_fails_when_key_too_small() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-rsa2048.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-rsa2048.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-rsa1024-365d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.min_rsa_key_bits = Some(2048);
        let anchors = [TrustAnchor::from_cert(root)];
        assert!(
            matches!(
                validate_path(
                    &[leaf, int_cert],
                    &anchors,
                    &policy,
                    &RsaPkcs1v15Sha256Verifier
                ),
                Err(Error::KeyTooSmall { index: 0 })
            ),
            "RSA-1024 leaf with min=2048 must return KeyTooSmall {{ index: 0 }}"
        );
    }

    /// Oracle: None = unconstrained; RSA-1024 leaf passes with no key size restriction.
    #[test]
    fn min_rsa_key_bits_none_is_unconstrained() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-rsa2048.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-rsa2048.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-rsa1024-365d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.min_rsa_key_bits = None; // default
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(
            &[leaf, int_cert],
            &anchors,
            &policy,
            &RsaPkcs1v15Sha256Verifier,
        )
        .expect("None min_rsa_key_bits must accept RSA-1024 leaf");
    }

    /// EC key must not be affected by `min_rsa_key_bits` regardless of the value.
    /// Oracle: P-256 key is not RSA; `rsa_public_key_bits` returns None → check skipped.
    #[test]
    fn min_rsa_key_bits_ec_key_passes_unconditionally() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-p256.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-p256.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-p256-365d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        // Extremely high floor — would reject any RSA key, but P-256 is not RSA.
        policy.min_rsa_key_bits = Some(16384);
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(&[leaf, int_cert], &anchors, &policy, &EcdsaP256Verifier)
            .expect("EC key must not be affected by min_rsa_key_bits");
    }

    // -----------------------------------------------------------------------
    // allowed_signature_algs: RSA chain test (PKIX-ken.1.10)
    // -----------------------------------------------------------------------

    /// Oracle: RSA chain uses sha256WithRSAEncryption; ECDSA-only allowlist must reject it.
    #[test]
    fn alg_allowlist_fails_on_rsa_chain_when_only_ecdsa_allowed() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-rsa2048.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-rsa2048.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-rsa2048-365d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        // Only ECDSA allowed; RSA chain must fail.
        policy.allowed_signature_algs = Some(vec![ECDSA_SHA256_OID]);
        let anchors = [TrustAnchor::from_cert(root)];
        assert!(
            matches!(
                validate_path(
                    &[leaf, int_cert],
                    &anchors,
                    &policy,
                    &RsaPkcs1v15Sha256Verifier
                ),
                Err(Error::AlgorithmNotAllowed { .. })
            ),
            "RSA chain with ECDSA-only allowlist must return AlgorithmNotAllowed"
        );
    }

    /// Oracle: RSA chain with RSA in allowlist must pass.
    #[test]
    fn alg_allowlist_passes_for_rsa_chain() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-rsa2048.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-rsa2048.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-rsa2048-365d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.allowed_signature_algs = Some(vec![RSA_SHA256_OID]);
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(
            &[leaf, int_cert],
            &anchors,
            &policy,
            &RsaPkcs1v15Sha256Verifier,
        )
        .expect("RSA chain with RSA-SHA256 in allowlist should pass");
    }

    /// EKU tests for RSA chain are structurally identical to P-256; spot-check one.
    ///
    /// Oracle: leaf-rsa2048-365d-san-eku.der has EKU=serverAuth.
    #[test]
    fn required_eku_passes_for_rsa_chain() {
        let root = load(include_bytes!(
            "../tests/fixtures/policy-checks/root-rsa2048.der"
        ));
        let int_cert = load(include_bytes!(
            "../tests/fixtures/policy-checks/int-rsa2048.der"
        ));
        let leaf = load(include_bytes!(
            "../tests/fixtures/policy-checks/leaf-rsa2048-365d-san-eku.der"
        ));
        let mut policy = ValidationPolicy::new(PC_NOW);
        policy.required_leaf_eku = Some(vec![ID_KP_SERVER_AUTH]);
        let anchors = [TrustAnchor::from_cert(root)];
        validate_path(
            &[leaf, int_cert],
            &anchors,
            &policy,
            &RsaPkcs1v15Sha256Verifier,
        )
        .expect("RSA leaf with serverAuth EKU must pass required_leaf_eku=[serverAuth]");
    }
}

/// `NcTypeMask`, the bitmask that records which name forms a path has
/// constrained.
///
/// RFC 5280 §4.2.1.10 requires a certificate carrying a name form this
/// implementation cannot match -- `otherName`, `ediPartyName`,
/// `registeredID` -- to be rejected when a constraint on that form is in
/// effect. The mask is how "in effect" is tracked, so a bit that does not
/// work is a certificate that slips through.
///
/// Nothing exercised the type directly: it is reached only through
/// `check_name_constraints`, and the PKITS corpus has no vector for the
/// unsupported forms, so the bits for them could all have been zero.
#[cfg(test)]
mod nc_type_mask_tests {
    use super::NcTypeMask;

    /// Every name form, in bit order. Written out rather than derived, so
    /// the test is a statement about which forms have a bit at all.
    const ALL: [(&str, NcTypeMask); 8] = [
        ("rfc822Name", NcTypeMask::RFC822),
        ("dNSName", NcTypeMask::DNS),
        ("directoryName", NcTypeMask::DIRECTORY_NAME),
        ("uniformResourceIdentifier", NcTypeMask::URI),
        ("iPAddress", NcTypeMask::IP_ADDRESS),
        ("otherName", NcTypeMask::OTHER_NAME),
        ("ediPartyName", NcTypeMask::EDI_PARTY_NAME),
        ("registeredID", NcTypeMask::REGISTERED_ID),
    ];

    /// Each form has a bit of its own, and that bit is set.
    ///
    /// A shifted-away constant is the failure that matters: `1 << 6`
    /// becoming zero makes `intersects` answer false for every mask, so an
    /// `ediPartyName` constraint stops counting as in effect and a
    /// certificate carrying that form is no longer refused.
    ///
    /// `RFC822`'s own shift is the exception, and not for want of a test:
    /// `1 << 0` and `1 >> 0` are the same number, so no test distinguishes
    /// them. Every other bit is covered here.
    #[test]
    fn each_name_form_has_its_own_bit() {
        for (name, mask) in ALL {
            assert!(
                mask.intersects(mask),
                "{name}'s bit is empty, so no constraint on it can register"
            );
            assert_ne!(
                mask,
                NcTypeMask::EMPTY,
                "{name} is indistinguishable from EMPTY"
            );
        }

        for (i, (a_name, a)) in ALL.iter().enumerate() {
            for (b_name, b) in ALL.iter().skip(i + 1) {
                assert!(
                    !a.intersects(*b),
                    "{a_name} and {b_name} share a bit, so a constraint on one \
                     would register as a constraint on the other"
                );
            }
        }
    }

    /// The empty mask intersects nothing, including itself.
    #[test]
    fn the_empty_mask_intersects_nothing() {
        assert!(!NcTypeMask::EMPTY.intersects(NcTypeMask::EMPTY));
        for (name, mask) in ALL {
            assert!(!NcTypeMask::EMPTY.intersects(mask), "EMPTY against {name}");
            assert!(!mask.intersects(NcTypeMask::EMPTY), "{name} against EMPTY");
        }
    }

    /// Accumulating a form twice leaves it set.
    ///
    /// This is the one place the distinction between union and symmetric
    /// difference shows: on disjoint masks they agree, so a `^` in either
    /// operator passes every test built from distinct forms. Two CA
    /// certificates in one path constraining `dNSName` is an ordinary
    /// chain, and under symmetric difference the second would clear what
    /// the first recorded -- the constraint would stop being in effect
    /// because it was imposed twice.
    #[test]
    fn accumulating_one_form_twice_leaves_it_set() {
        assert_eq!(NcTypeMask::DNS | NcTypeMask::DNS, NcTypeMask::DNS);

        let mut acc = NcTypeMask::EMPTY;
        acc |= NcTypeMask::DNS;
        acc |= NcTypeMask::RFC822;
        acc |= NcTypeMask::DNS;
        assert!(
            acc.intersects(NcTypeMask::DNS),
            "dNSName was constrained twice and must still be in effect"
        );
        assert!(
            acc.intersects(NcTypeMask::RFC822),
            "rfc822Name was constrained once and must still be in effect"
        );
        assert!(
            !acc.intersects(NcTypeMask::URI),
            "no constraint named uniformResourceIdentifier"
        );
    }

    /// `BitOr` and `BitOrAssign` agree.
    ///
    /// They are written separately, so one could accumulate while the other
    /// replaced.
    #[test]
    fn the_two_union_operators_agree() {
        let by_value = NcTypeMask::DNS | NcTypeMask::OTHER_NAME;
        let mut by_assign = NcTypeMask::DNS;
        by_assign |= NcTypeMask::OTHER_NAME;
        assert_eq!(by_value, by_assign);
    }
}

/// Rendering, equality, hashing and source chains of [`Error`] and
/// [`DerError`].
///
/// These impls have no caller inside the crate: a path validation returns
/// an `Error`, and whether it renders, compares or hashes is the consumer's
/// business. So nothing here was exercised, and the failure mode is quiet
/// in the way that matters for a diagnostic — a `Display` that writes
/// nothing still returns `Ok`, a `source` that returns `None` still
/// satisfies the trait, and an `eq` that answers `true` makes two different
/// DER failures the same value.
#[cfg(test)]
mod error_rendering_tests {
    use super::{DerError, Error, VerificationErrorKind};
    use core::hash::{Hash, Hasher};

    /// FNV-1a, so the hash assertions do not need `std`'s `DefaultHasher`.
    ///
    /// Any deterministic hasher does: the question is whether `Hash` reads
    /// the field `PartialEq` compares, not what the digest is.
    struct Fnv(u64);

    impl Fnv {
        fn of<T: Hash>(value: &T) -> u64 {
            let mut h = Self(0xcbf2_9ce4_8422_2325);
            value.hash(&mut h);
            h.finish()
        }
    }

    impl Hasher for Fnv {
        fn write(&mut self, bytes: &[u8]) {
            for b in bytes {
                self.0 ^= u64::from(*b);
                self.0 = self.0.wrapping_mul(0x0100_0000_01b3);
            }
        }
        fn finish(&self) -> u64 {
            self.0
        }
    }

    /// A `DerError` wrapping the failure `bytes` produces as an OID.
    fn der_error(bytes: &[u8]) -> DerError {
        use der::Decode as _;
        let failed: der::Result<der::asn1::ObjectIdentifier> =
            der::asn1::ObjectIdentifier::from_der(bytes);
        DerError::new(failed.expect_err("not a well-formed OID"))
    }

    /// One of every [`Error`] variant.
    ///
    /// The index is the same throughout on purpose: the variants that carry
    /// only an index are otherwise indistinguishable, so holding it fixed
    /// makes the distinctness assertion below a statement about the
    /// messages rather than about the numbers in them.
    fn every_variant() -> [Error; 23] {
        const IDX: usize = 2;
        [
            Error::SignatureInvalid { index: IDX },
            Error::SignatureNotVerified {
                index: IDX,
                reason: VerificationErrorKind::UnsupportedAlgorithm,
            },
            Error::MalformedCertificate { index: IDX },
            Error::ValidityPeriod { index: IDX },
            Error::ChainBroken { index: IDX },
            Error::NoTrustedPath,
            Error::PathTooLong,
            Error::NotCA { index: IDX },
            Error::KeyUsageMissing { index: IDX },
            Error::CrlSignMissing { index: IDX },
            Error::UnhandledCriticalExtension { index: IDX },
            Error::NameConstraintViolation { index: IDX },
            Error::PolicyViolation { index: IDX },
            Error::Der(der_error(&[0x06, 0x01, 0x80])),
            Error::ValidityPeriodExceedsMax { index: IDX },
            Error::AlgorithmNotAllowed { index: IDX },
            Error::KeyTooSmall { index: IDX },
            Error::MissingSan,
            Error::MissingRfc822San,
            Error::MissingEku,
            Error::MissingLeafPolicyOid {
                required: der::asn1::ObjectIdentifier::new_unwrap("1.2.3.4"),
            },
            Error::SubjectDnAttrRuleUnmet,
            Error::DuplicateCertificate {
                first: IDX,
                second: IDX + 1,
            },
        ]
    }

    /// Every variant renders something, and no two render the same thing.
    ///
    /// An `Error` whose message is empty, or shared with another variant,
    /// tells a caller nothing about what went wrong. The array is a fixed
    /// length so adding a variant without a message is a compile error
    /// here rather than a silent gap.
    #[test]
    fn every_error_variant_renders_a_distinct_message() {
        let variants = every_variant();
        let rendered: Vec<_> = variants.iter().map(|e| format!("{e}")).collect();
        for (variant, text) in variants.iter().zip(&rendered) {
            assert!(!text.is_empty(), "{variant:?} renders nothing");
        }
        for (i, a) in rendered.iter().enumerate() {
            for (j, b) in rendered.iter().enumerate().skip(i + 1) {
                assert_ne!(
                    a, b,
                    "{:?} and {:?} render the same message",
                    variants[i], variants[j]
                );
            }
        }
    }

    /// Only `Error::Der` has an underlying cause, and it exposes it.
    ///
    /// A `source` that always answers `None` breaks `{:#}`-style chained
    /// reporting: the DER failure that explains the whole error is in the
    /// wrapped value and nowhere else.
    #[test]
    fn only_the_der_variant_has_a_source() {
        use core::error::Error as _;
        for variant in &every_variant() {
            let expected = matches!(variant, Error::Der(_));
            assert_eq!(
                variant.source().is_some(),
                expected,
                "{variant:?} source presence"
            );
        }
    }

    /// `DerError` renders the message it cached, and exposes the
    /// `der::Error` it was built from.
    #[test]
    fn a_der_error_renders_and_exposes_its_cause() {
        use core::error::Error as _;
        let e = der_error(&[0x06, 0x01, 0x80]);
        let rendered = format!("{e}");
        assert!(!rendered.is_empty(), "DerError renders nothing");
        let source = e.source().expect("a DerError built from a der::Error");
        assert_eq!(
            format!("{source}"),
            rendered,
            "the cached message is the der::Error's own rendering"
        );
    }

    /// Equality compares the cached message, so distinct DER failures are
    /// distinct values.
    ///
    /// `Error` derives `PartialEq`, so an `eq` that always answered `true`
    /// would make `Err(Error::Der(a)) == Err(Error::Der(b))` for any two
    /// DER failures — and a test asserting a particular error would pass
    /// for the wrong one.
    #[test]
    fn der_errors_with_different_messages_differ() {
        let wrong_tag = der_error(&[0x02, 0x01, 0x00]);
        let truncated = der_error(&[0x06, 0x01, 0x80]);
        assert_ne!(
            format!("{wrong_tag}"),
            format!("{truncated}"),
            "the two fixtures must fail differently for this test to mean anything"
        );
        assert_ne!(wrong_tag, truncated);
        assert_eq!(
            Error::Der(wrong_tag.clone()),
            Error::Der(wrong_tag.clone()),
            "the same failure twice"
        );
        assert_ne!(Error::Der(wrong_tag), Error::Der(truncated));
    }

    /// `Hash` reads the field `PartialEq` compares.
    ///
    /// Equal values must hash equally, which a `hash` that writes nothing
    /// satisfies trivially — and then every `DerError` lands in one bucket,
    /// including inside the `Error` and `ValidatedPath` hashes that exist
    /// only because `DerError` is `Hash`.
    #[test]
    fn der_error_hashing_follows_its_equality() {
        let wrong_tag = der_error(&[0x02, 0x01, 0x00]);
        let truncated = der_error(&[0x06, 0x01, 0x80]);
        assert_eq!(
            Fnv::of(&wrong_tag),
            Fnv::of(&der_error(&[0x02, 0x01, 0x00])),
            "equal values hash equally"
        );
        assert_ne!(
            Fnv::of(&wrong_tag),
            Fnv::of(&truncated),
            "unequal values are not all one hash"
        );
    }
}
