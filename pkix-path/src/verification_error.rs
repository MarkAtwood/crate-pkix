//! The error type of [`SignatureVerifier`](crate::SignatureVerifier).

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(feature = "std")]
use std::boxed::Box;

/// Why a [`SignatureVerifier`](crate::SignatureVerifier) did not accept a
/// signature.
///
/// `validate_path` reports [`InvalidSignature`](Self::InvalidSignature) as
/// [`Error::SignatureInvalid`](crate::Error::SignatureInvalid) and every
/// other kind as
/// [`Error::SignatureNotVerified`](crate::Error::SignatureNotVerified).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum VerificationErrorKind {
    /// The verifier does not implement the signature algorithm, or the
    /// algorithm's parameters are not ones it supports (for example
    /// RSASSA-PSS with SHA-1, or ECDSA parameters present).
    UnsupportedAlgorithm,
    /// The issuer's key is well-formed but not usable with this algorithm
    /// or verifier: a different key type, an unsupported curve or size, or
    /// key parameters that forbid the signature's parameters.
    UnsupportedKey,
    /// The issuer's `SubjectPublicKeyInfo` does not decode as a key of its
    /// declared type.
    MalformedKey,
    /// The signature is not a well-formed signature value or does not
    /// verify under the issuer's key.
    InvalidSignature,
}

impl core::fmt::Display for VerificationErrorKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::UnsupportedAlgorithm => "unsupported signature algorithm",
            Self::UnsupportedKey => "issuer key not usable with this signature algorithm",
            Self::MalformedKey => "malformed issuer public key",
            Self::InvalidSignature => "invalid signature",
        })
    }
}

/// Error returned by [`SignatureVerifier::verify_signature`].
///
/// Carries a [`VerificationErrorKind`] and, optionally, the backend error
/// that caused it, available through [`core::error::Error::source`].
///
/// [`SignatureVerifier::verify_signature`]: crate::SignatureVerifier::verify_signature
#[derive(Debug)]
pub struct VerificationError {
    kind: VerificationErrorKind,
    source: Option<Box<dyn core::error::Error + Send + Sync + 'static>>,
}

impl VerificationError {
    /// An error of the given kind with no underlying cause.
    #[must_use]
    pub const fn new(kind: VerificationErrorKind) -> Self {
        Self { kind, source: None }
    }

    /// An error of the given kind caused by `source`, typically the
    /// backend's own error.
    #[must_use]
    pub fn with_source(
        kind: VerificationErrorKind,
        source: impl core::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind,
            source: Some(Box::new(source)),
        }
    }

    /// Shorthand for [`VerificationErrorKind::UnsupportedAlgorithm`].
    #[must_use]
    pub const fn unsupported_algorithm() -> Self {
        Self::new(VerificationErrorKind::UnsupportedAlgorithm)
    }

    /// Shorthand for [`VerificationErrorKind::UnsupportedKey`].
    #[must_use]
    pub const fn unsupported_key() -> Self {
        Self::new(VerificationErrorKind::UnsupportedKey)
    }

    /// Shorthand for [`VerificationErrorKind::MalformedKey`].
    #[must_use]
    pub const fn malformed_key() -> Self {
        Self::new(VerificationErrorKind::MalformedKey)
    }

    /// Shorthand for [`VerificationErrorKind::InvalidSignature`].
    #[must_use]
    pub const fn invalid_signature() -> Self {
        Self::new(VerificationErrorKind::InvalidSignature)
    }

    /// What went wrong.
    #[must_use]
    pub const fn kind(&self) -> VerificationErrorKind {
        self.kind
    }
}

impl From<VerificationErrorKind> for VerificationError {
    fn from(kind: VerificationErrorKind) -> Self {
        Self::new(kind)
    }
}

impl core::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.kind, f)
    }
}

// `core::error::Error` is stable since Rust 1.81, below the workspace MSRV,
// so the impl does not need the `std` feature.
impl core::error::Error for VerificationError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|e| e as &(dyn core::error::Error + 'static))
    }
}
