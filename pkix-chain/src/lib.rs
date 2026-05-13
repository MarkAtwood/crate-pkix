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
//! use pkix_chain::{verify_chain, DefaultVerifier, NoRevocation, TrustAnchor, ValidationPolicy};
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
//! let verifier = Verifier::new(&anchors, &DefaultVerifier, &NoRevocation, &policy);
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

pub use pkix_identity::{self, IdentityError, MailboxName, ServerName};
pub use pkix_path::{
    self, DefaultVerifier, Profile, SignatureVerifier, TrustAnchor, ValidatedPath, ValidationPolicy,
};
#[cfg(feature = "crl")]
#[cfg_attr(docsrs, doc(cfg(feature = "crl")))]
pub use pkix_revocation::CrlChecker;
#[cfg(feature = "ocsp")]
#[cfg_attr(docsrs, doc(cfg(feature = "ocsp")))]
pub use pkix_revocation::OcspChecker;
pub use pkix_revocation::{self, NoRevocation, RevocationChecker};

use x509_cert::Certificate;

/// Combined error type for chain verification.
///
/// Wraps path validation errors ([`pkix_path::Error`]),
/// revocation checking errors ([`pkix_revocation::Error`]), and identity
/// binding errors ([`pkix_identity::IdentityError`]).
#[derive(Clone, Debug, PartialEq, Eq)]
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
        reason: &'static str,
    },
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Path(e) => write!(f, "path validation: {e}"),
            Self::Revocation(e) => write!(f, "revocation: {e}"),
            Self::Identity(e) => write!(f, "identity binding: {e}"),
            Self::ProfileViolation { reason } => write!(f, "profile violation: {reason}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Path(e) => Some(e),
            Self::Revocation(e) => Some(e),
            Self::Identity(e) => Some(e),
            Self::ProfileViolation { .. } => None,
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

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Verify a certificate chain using the default `RustCrypto` signature backends.
///
/// Convenience wrapper around [`verify_chain`] that uses [`DefaultVerifier`]
/// (RSA-PKCS1v15-SHA-256 and ECDSA-P-256-SHA-256) so callers do not need to
/// construct a `SignatureVerifier` manually for the common case.
///
/// For a custom backend, call [`verify_chain`] directly.
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
    verify_chain(chain, anchors, policy, &DefaultVerifier, revocation)
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
pub fn verify_chain<V, R>(
    chain: &[Certificate],
    anchors: &[TrustAnchor],
    policy: &ValidationPolicy,
    verifier: &V,
    revocation: &R,
) -> crate::Result<ValidatedPath>
where
    V: SignatureVerifier,
    R: RevocationChecker,
{
    Verifier::new(anchors, verifier, revocation, policy).verify_one(chain)
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
pub struct Verifier<'a, V: SignatureVerifier, R: RevocationChecker> {
    anchors: &'a [TrustAnchor],
    sig_verifier: &'a V,
    rev_checker: &'a R,
    policy: &'a ValidationPolicy,
}

impl<'a, V, R> Verifier<'a, V, R>
where
    V: SignatureVerifier,
    R: RevocationChecker,
{
    /// Construct a verifier from its components.
    pub fn new(
        anchors: &'a [TrustAnchor],
        sig_verifier: &'a V,
        rev_checker: &'a R,
        policy: &'a ValidationPolicy,
    ) -> Self {
        Self {
            anchors,
            sig_verifier,
            rev_checker,
            policy,
        }
    }

    /// Verify a single certificate chain.
    ///
    /// Performs full RFC 5280 §6 path validation (signatures, validity,
    /// chain linkage, policy) followed by revocation checking on every
    /// cert in the chain, matching the semantics of [`verify_chain`].
    ///
    /// # Errors
    ///
    /// Returns `Err` if path validation fails or revocation indicates a
    /// revoked certificate.
    ///
    /// # Revocation coverage
    ///
    /// Identical to [`verify_chain`]:
    ///
    /// - `chain[i]` where `chain[i + 1]` exists: checked via
    ///   [`RevocationChecker::check_revocation`] with `chain[i + 1]` as
    ///   the issuer.
    /// - The last cert in `chain` (issued directly by the trust anchor):
    ///   checked via
    ///   [`RevocationChecker::check_revocation_against_anchor`].
    pub fn verify_one(&self, chain: &[Certificate]) -> crate::Result<ValidatedPath> {
        // First: full RFC 5280 §6 path validation (signatures, validity, chain linkage).
        let validated =
            pkix_path::validate_path(chain, self.anchors, self.policy, self.sig_verifier)?;

        // Then: revocation checking on each cert in the validated chain.
        // chain[i] was issued by chain[i+1]; the last cert was issued by the trust anchor.
        for (i, cert) in chain.iter().enumerate() {
            if i + 1 < chain.len() {
                self.rev_checker.check_revocation(cert, &chain[i + 1])?;
            } else {
                // Last cert: issued directly by the trust anchor.
                // CrlChecker/OcspChecker override this; NoRevocation inherits the
                // default Ok(()) skip.
                self.rev_checker
                    .check_revocation_against_anchor(cert, &self.anchors[validated.anchor_index])?;
            }
        }

        Ok(validated)
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
/// The signature verifier is hardwired to [`DefaultVerifier`]. Callers that
/// need a custom verifier should drop down to [`verify_chain`] and call
/// [`pkix_identity::verify_dns_name`] explicitly.
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
/// - `revocation` — revocation checker (use [`NoRevocation`] for offline)
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
pub fn verify_tls_server<P, R>(
    chain: &[Certificate],
    anchors: &[TrustAnchor],
    name: &ServerName<'_>,
    profile: &P,
    now_unix: u64,
    revocation: &R,
) -> crate::Result<ValidatedPath>
where
    P: Profile,
    R: RevocationChecker,
{
    let policy = profile.policy(now_unix);
    let validated = verify_chain(chain, anchors, &policy, &DefaultVerifier, revocation)?;
    pkix_identity::verify_dns_name(&chain[0], name)?;
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
/// The signature verifier is hardwired to [`DefaultVerifier`]. Callers that
/// need a custom verifier should drop down to [`verify_chain`] and call
/// [`pkix_identity::verify_mailbox`] explicitly.
///
/// # Arguments
///
/// - `chain`      — leaf-first certificate chain; `chain[0]` is the signer cert
/// - `anchors`    — trust anchors; validation succeeds when the chain reaches one
/// - `mailbox`    — pre-parsed mailbox (construct via [`MailboxName::parse`])
/// - `profile`    — profile supplying the [`ValidationPolicy`] for `now_unix`;
///   typically [`pkix_profiles::BasicSmimeProfile`] or a CA/B-Forum S/MIME tier
/// - `now_unix`   — current time, seconds since the Unix epoch
/// - `revocation` — revocation checker (use [`NoRevocation`] for offline)
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
pub fn verify_smime_signer<P, R>(
    chain: &[Certificate],
    anchors: &[TrustAnchor],
    mailbox: &MailboxName<'_>,
    profile: &P,
    now_unix: u64,
    revocation: &R,
) -> crate::Result<ValidatedPath>
where
    P: Profile,
    R: RevocationChecker,
{
    let policy = profile.policy(now_unix);
    let validated = verify_chain(chain, anchors, &policy, &DefaultVerifier, revocation)?;
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
pub fn verify_smime_recipient<P, R>(
    chain: &[Certificate],
    anchors: &[TrustAnchor],
    mailbox: &MailboxName<'_>,
    profile: &P,
    now_unix: u64,
    revocation: &R,
) -> crate::Result<ValidatedPath>
where
    P: Profile,
    R: RevocationChecker,
{
    let policy = profile.policy(now_unix);
    let validated = verify_chain(chain, anchors, &policy, &DefaultVerifier, revocation)?;
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
/// The signature verifier is hardwired to [`DefaultVerifier`]. Callers that
/// need a custom verifier should drop down to [`verify_chain`].
///
/// # Arguments
///
/// - `chain`      — leaf-first certificate chain; `chain[0]` is the signer cert
/// - `anchors`    — trust anchors; validation succeeds when the chain reaches one
/// - `profile`    — profile supplying the [`ValidationPolicy`] for `now_unix`;
///   typically [`pkix_profiles::BasicCodeSigningProfile`] or
///   `pkix_profiles_cabf::CodeSigningProfile` for the CA/B Forum BR overlay
/// - `now_unix`   — current time, seconds since the Unix epoch
/// - `revocation` — revocation checker (use [`NoRevocation`] for offline)
///
/// # Errors
///
/// - [`Error::Path`] — RFC 5280 path validation failed (including the
///   profile's `id-kp-codeSigning` EKU requirement not being met).
/// - [`Error::Revocation`] — a cert in the chain was revoked or the
///   revocation source was unusable.
pub fn verify_code_signer<P, R>(
    chain: &[Certificate],
    anchors: &[TrustAnchor],
    profile: &P,
    now_unix: u64,
    revocation: &R,
) -> crate::Result<ValidatedPath>
where
    P: Profile,
    R: RevocationChecker,
{
    let policy = profile.policy(now_unix);
    verify_chain(chain, anchors, &policy, &DefaultVerifier, revocation)
}

/// Verify a certificate chain for Time Stamping Authority (TSA) use.
///
/// Composes [`verify_chain`] under the caller-supplied [`Profile`] with the
/// additional RFC 3161 §2.3 enforcement that the leaf certificate's
/// `ExtendedKeyUsage` extension is:
///
/// - **present** (covered by `profile.policy(now_unix).required_leaf_eku`),
/// - **marked critical**, and
/// - **contains only** `id-kp-timeStamping` (no other EKU values).
///
/// The presence check is enforced inside [`verify_chain`] via the profile's
/// `required_leaf_eku`. The criticality and sole-EKU checks run after
/// `verify_chain` returns and fail with [`Error::ProfileViolation`] when
/// violated.
///
/// The signature verifier is hardwired to [`DefaultVerifier`]. Callers that
/// need a custom verifier should drop down to [`verify_chain`] and replicate
/// the post-validation EKU check.
///
/// # Arguments
///
/// - `chain`      — leaf-first certificate chain; `chain[0]` is the TSA cert
/// - `anchors`    — trust anchors; validation succeeds when the chain reaches one
/// - `profile`    — profile supplying the [`ValidationPolicy`] for `now_unix`;
///   typically [`pkix_profiles::BasicTimeStampingProfile`]
/// - `now_unix`   — current time, seconds since the Unix epoch
/// - `revocation` — revocation checker (use [`NoRevocation`] for offline)
///
/// # Errors
///
/// - [`Error::Path`] — RFC 5280 path validation failed (including the
///   profile's `id-kp-timeStamping` EKU presence requirement).
/// - [`Error::Revocation`] — a cert in the chain was revoked.
/// - [`Error::ProfileViolation`] — path validation succeeded but the leaf
///   cert's EKU extension is not marked critical, or contains EKU values
///   other than `id-kp-timeStamping`.
pub fn verify_time_stamper<P, R>(
    chain: &[Certificate],
    anchors: &[TrustAnchor],
    profile: &P,
    now_unix: u64,
    revocation: &R,
) -> crate::Result<ValidatedPath>
where
    P: Profile,
    R: RevocationChecker,
{
    let policy = profile.policy(now_unix);
    let validated = verify_chain(chain, anchors, &policy, &DefaultVerifier, revocation)?;
    enforce_timestamping_eku_critical_and_sole(&chain[0])?;
    Ok(validated)
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
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or(Error::ProfileViolation {
            reason: "TSA certificate has no ExtendedKeyUsage extension",
        })?;
    let ext = exts
        .iter()
        .find(|e| e.extn_id == OID_EXTENDED_KEY_USAGE)
        .ok_or(Error::ProfileViolation {
            reason: "TSA certificate has no ExtendedKeyUsage extension",
        })?;

    if !ext.critical {
        return Err(Error::ProfileViolation {
            reason: "TSA ExtendedKeyUsage extension must be marked critical (RFC 3161 §2.3)",
        });
    }

    let eku = ExtendedKeyUsage::from_der(ext.extn_value.as_bytes()).map_err(|_| {
        Error::ProfileViolation {
            reason: "TSA ExtendedKeyUsage extension is malformed",
        }
    })?;

    // RFC 3161 §2.3: timeStamping MUST be the sole EKU value.
    match eku.0.as_slice() {
        [oid] if *oid == ID_KP_TIME_STAMPING => Ok(()),
        [_] => Err(Error::ProfileViolation {
            reason: "TSA ExtendedKeyUsage must contain only id-kp-timeStamping (RFC 3161 §2.3)",
        }),
        _ => Err(Error::ProfileViolation {
            reason: "TSA ExtendedKeyUsage must contain only id-kp-timeStamping (RFC 3161 §2.3)",
        }),
    }
}

// ---------------------------------------------------------------------------
// Send + Sync compile-time assertions (AGENTS.md non-negotiable #6, PKIX-2l0v.2)
// ---------------------------------------------------------------------------

const _: fn() = || {
    fn _assert_send_sync<T: Send + Sync>() {}
    _assert_send_sync::<Error>();
};

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
                reason: "test violation",
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
