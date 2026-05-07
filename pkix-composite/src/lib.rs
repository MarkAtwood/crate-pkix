#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! Composite signature verifier for `pkix-path`.
//!
//! Implements [`pkix_path::SignatureVerifier`] for composite public keys and
//! signatures as defined in `draft-ietf-lamps-pq-composite-sigs`. A composite
//! signature combines a classical algorithm (RSA, ECDSA) with a post-quantum
//! algorithm (ML-DSA) into a single signature that is only valid if **both**
//! component signatures verify. This provides a hybrid transition strategy:
//! security is maintained as long as either algorithm remains unbroken.
//!
//! # Usage
//!
//! ```rust,ignore
//! use pkix_composite::CompositeVerifier;
//! use pkix_path::{DefaultVerifier, SignatureVerifier};
//! // wolfcrypt_pkix::WolfCryptVerifier for the PQ component
//!
//! let verifier = CompositeVerifier::new(DefaultVerifier, pq_verifier);
//! pkix_chain::verify_chain(&chain, &anchors, &policy, &verifier, &NoRevocation)?;
//! ```
//!
//! # Spec references
//!
//! - draft-ietf-lamps-pq-composite-sigs (see specs/draft-ietf-lamps-pq-composite-sigs-*.txt)
//! - FIPS 204 — ML-DSA
//!
//! # Limitations
//!
//! Not yet implemented. OIDs from the composite-sigs draft are subject to change
//! until the draft is published as an RFC.

use pkix_path::SignatureVerifier;
use signature::Error as SignatureError;
use spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};

/// A [`SignatureVerifier`] that requires both a classical and a post-quantum
/// component signature to verify successfully.
///
/// `C` is the classical verifier (e.g., `DefaultVerifier` or
/// `RsaPkcs1v15Sha256Verifier`). `P` is the post-quantum verifier (e.g.,
/// a `WolfCryptVerifier` or ML-DSA-specific verifier).
///
/// Both verifiers are called for every signature. The composite verification
/// succeeds only if both return `Ok(())`.
///
/// # Limitations
///
/// Not yet implemented (composite OID dispatch and SPKI/signature splitting
/// are pending). Currently returns `Err` for all inputs.
#[derive(Clone, Debug)]
pub struct CompositeVerifier<C, P> {
    #[allow(dead_code)]
    classical: C,
    #[allow(dead_code)]
    post_quantum: P,
}

impl<C, P> CompositeVerifier<C, P> {
    /// Create a new `CompositeVerifier` from a classical and a post-quantum component.
    #[deprecated = "pkix-composite is not yet implemented"]
    pub fn new(classical: C, post_quantum: P) -> Self {
        Self {
            classical,
            post_quantum,
        }
    }
}

impl<C: SignatureVerifier, P: SignatureVerifier> SignatureVerifier for CompositeVerifier<C, P> {
    fn verify_signature(
        &self,
        _algorithm: AlgorithmIdentifierRef<'_>,
        _issuer_spki: SubjectPublicKeyInfoRef<'_>,
        _message: &[u8],
        _signature: &[u8],
    ) -> core::result::Result<(), SignatureError> {
        // Not yet implemented: composite OID dispatch, SPKI component splitting,
        // and signature component splitting per draft-ietf-lamps-pq-composite-sigs.
        Err(SignatureError::new())
    }
}
