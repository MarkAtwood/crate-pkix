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
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Path(e) => write!(f, "path validation: {e}"),
            Self::Revocation(e) => write!(f, "revocation: {e}"),
            Self::Identity(e) => write!(f, "identity binding: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Path(e) => Some(e),
            Self::Revocation(e) => Some(e),
            Self::Identity(e) => Some(e),
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
    // First: full RFC 5280 §6 path validation (signatures, validity, chain linkage).
    let validated = pkix_path::validate_path(chain, anchors, policy, verifier)?;

    // Then: revocation checking on each cert in the validated chain.
    // chain[i] was issued by chain[i+1]; the last cert was issued by the trust anchor.
    for (i, cert) in chain.iter().enumerate() {
        if i + 1 < chain.len() {
            revocation.check_revocation(cert, &chain[i + 1])?;
        } else {
            // Last cert: issued directly by the trust anchor.
            // CrlChecker/OcspChecker override this; NoRevocation inherits the
            // default Ok(()) skip.
            revocation.check_revocation_against_anchor(cert, &anchors[validated.anchor_index])?;
        }
    }

    Ok(validated)
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
}
