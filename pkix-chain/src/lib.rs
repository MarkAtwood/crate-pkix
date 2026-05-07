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

pub use pkix_path::{
    self, DefaultVerifier, SignatureVerifier, TrustAnchor, ValidatedPath, ValidationPolicy,
};
#[cfg(feature = "crl")]
pub use pkix_revocation::CrlChecker;
#[cfg(feature = "ocsp")]
pub use pkix_revocation::OcspChecker;
pub use pkix_revocation::{self, NoRevocation, RevocationChecker};

use x509_cert::Certificate;

/// Combined error type for chain verification.
///
/// Wraps both path validation errors ([`pkix_path::Error`]) and
/// revocation checking errors ([`pkix_revocation::Error`]).
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// RFC 5280 path validation failed.
    Path(pkix_path::Error),
    /// Revocation checking failed.
    Revocation(pkix_revocation::Error),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Path(e) => write!(f, "path validation: {e}"),
            Error::Revocation(e) => write!(f, "revocation: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Path(e) => Some(e),
            Error::Revocation(e) => Some(e),
        }
    }
}

impl From<pkix_path::Error> for Error {
    fn from(e: pkix_path::Error) -> Self {
        Error::Path(e)
    }
}

impl From<pkix_revocation::Error> for Error {
    fn from(e: pkix_revocation::Error) -> Self {
        Error::Revocation(e)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Confirm DefaultVerifier re-export is the same type as pkix_path::DefaultVerifier.
    /// A function that accepts &DefaultVerifier (crate re-export) must also accept
    /// &pkix_path::DefaultVerifier — the compiler will enforce type identity.
    #[test]
    fn default_verifier_reexport_type_identity() {
        fn _accepts(_v: &DefaultVerifier) {}
        let _v: &pkix_path::DefaultVerifier = &DefaultVerifier;
        _accepts(_v);
    }
}
