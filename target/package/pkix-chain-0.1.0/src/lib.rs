#![cfg_attr(docsrs, feature(doc_auto_cfg))]
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
//! # Quick start
//!
//! ```rust,ignore
//! use pkix_chain::{verify_chain, NoRevocation, ValidationPolicy, TrustAnchor};
//!
//! let policy = ValidationPolicy {
//!     current_time_unix: /* seconds since Unix epoch */ 0,
//!     ..Default::default()
//! };
//!
//! let result = verify_chain(
//!     &chain,          // &[Certificate], leaf first
//!     &anchors,        // &[TrustAnchor]
//!     &policy,
//!     &my_verifier,    // impl SignatureVerifier
//!     &NoRevocation,   // or a CrlChecker / OcspChecker
//! )?;
//! ```

pub use pkix_path::{self, Error, Result, SignatureVerifier, TrustAnchor, ValidatedPath, ValidationPolicy};
pub use pkix_revocation::{self, NoRevocation, RevocationChecker};

use x509_cert::Certificate;

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
/// - `verifier`   — signature verification backend (RustCrypto default or custom)
/// - `revocation` — revocation checker; use [`NoRevocation`] for offline/embedded
///
/// # Errors
///
/// Returns `Err` if path validation fails (signature, validity, chain linkage,
/// policy) or if revocation checking indicates a revoked certificate.
pub fn verify_chain<V, R>(
    chain: &[Certificate],
    anchors: &[TrustAnchor],
    policy: &ValidationPolicy,
    verifier: &V,
    revocation: &R,
) -> Result<ValidatedPath>
where
    V: SignatureVerifier,
    R: RevocationChecker,
{
    // First: full RFC 5280 §6 path validation (signatures, validity, chain linkage).
    let validated = pkix_path::validate_path(chain, anchors, policy, verifier)?;

    // Then: revocation checking on each cert in the validated chain.
    // chain[i] was issued by chain[i+1]; the last cert was issued by the trust anchor.
    // We pass the issuer cert for each position; the trust anchor cert is used for
    // the last intermediate. Revocation of the trust anchor itself is not checked.
    for i in 0..chain.len() {
        let cert = &chain[i];
        // Issuer of chain[i] is chain[i+1], or the trust anchor for the last cert.
        // The trust anchor certificate is at anchors[validated.anchor_index].
        let issuer = chain
            .get(i + 1)
            .unwrap_or(&anchors[validated.anchor_index].certificate);
        revocation.check_revocation(cert, issuer)?;
    }

    Ok(validated)
}
