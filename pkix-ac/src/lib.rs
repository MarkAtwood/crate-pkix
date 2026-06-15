#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! RFC 5755 X.509 attribute certificate validation.
//!
//! Attribute certificates (ACs) bind a set of attributes (roles, clearances,
//! group memberships) to a subject without containing a public key. They are
//! issued by an Attribute Authority (AA) and validated against a separate
//! PKI chain rooted in an AA trust anchor — distinct from the PKC trust
//! anchors used by `pkix-path`.
//!
//! # Relationship to `pkix-path`
//!
//! `pkix-path` validates public key certificates (PKCs). This crate validates
//! attribute certificates, using `pkix-path` to authenticate the Attribute
//! Authority's certification chain.
//!
//! # Spec references
//!
//! - RFC 5755 — An Internet Attribute Certificate Profile for Authorization
//! - RFC 5280 §6 — used to validate the AA's PKC chain
//!
//! # Limitations
//!
//! Not yet implemented.
//!
//! # Versioning
//!
//! Published as a `0.0.x` placeholder for a forthcoming `0.1.0` implementation.
//! While in `0.0.x`, the public API — including `Error` variant names — is
//! considered unstable and may change between patch releases. The variants
//! `AcParseError`, `AcSignatureInvalid`, and `AcExpired` were named
//! `ParseError`, `SignatureInvalid`, and `ValidityPeriod` in the unimplemented
//! `0.1.1` placeholder release.

extern crate alloc;

use alloc::vec::Vec;
use der::asn1::OctetString;
use x509_cert::name::Name;

/// An X.509 v2 Attribute Certificate as defined in RFC 5755 §4.1.
///
/// Unlike public key certificates, attribute certificates do not contain
/// a subject public key. They bind attributes to a subject identified by
/// a reference to their PKC (holder field).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AttributeCertificate {
    /// The DER-encoded attribute certificate bytes.
    pub der: Vec<u8>,
}

/// Identifies the holder of an attribute certificate.
///
/// Per RFC 5755 §4.1, the holder is identified by either a reference to
/// their PKC issuer and serial number, or by a digest of their PKC.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Holder {
    /// Issuer and serial number of the holder's PKC, if present.
    pub issuer_serial: Option<IssuerSerial>,
}

/// Issuer name and serial number pair, used to identify a PKC.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct IssuerSerial {
    /// The issuer's distinguished name.
    pub issuer: Name,
    /// The serial number as a raw byte string.
    pub serial: OctetString,
}

/// Errors returned by attribute certificate validation.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Error {
    /// DER parsing of the attribute certificate failed.
    AcParseError,
    /// The attribute certificate's signature did not verify.
    AcSignatureInvalid,
    /// The attribute certificate's validity period has expired or is not yet valid.
    AcExpired,
    /// The Attribute Authority's PKC chain could not be validated.
    AaPathInvalid(pkix_path::Error),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AcParseError => f.write_str("attribute certificate parse error"),
            Self::AcSignatureInvalid => f.write_str("attribute certificate signature invalid"),
            Self::AcExpired => f.write_str("attribute certificate validity period check failed"),
            Self::AaPathInvalid(e) => write!(f, "attribute authority path invalid: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::AaPathInvalid(e) => Some(e),
            _ => None,
        }
    }
}

const _: fn() = || {
    fn _assert_send_sync<T: Send + Sync>() {}
    _assert_send_sync::<Error>();
};

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Validate an attribute certificate against a set of Attribute Authority
/// trust anchors.
///
/// Validates:
/// - DER structure (RFC 5755 §4.1)
/// - Validity period against `now_unix`
/// - Signature against the AA's SPKI (AA chain validated via `pkix-path`)
///
/// # Errors
///
/// Returns one of the [`Error`] variants on validation failure:
/// - [`Error::AcParseError`] — the attribute certificate DER is malformed.
/// - [`Error::AcExpired`] — `now_unix` is outside the AC's validity window.
/// - [`Error::AcSignatureInvalid`] — the AC signature did not verify.
/// - [`Error::AaPathInvalid`] — the AA path validation failed.
///
/// # Limitations
///
/// Not yet implemented. Currently always returns
/// <code>[Error::AaPathInvalid]([pkix_path::Error::NoTrustedPath])</code>
/// until the RFC 5755 §5 validation algorithm is implemented.
pub const fn validate_attribute_cert(
    _ac: &AttributeCertificate,
    _aa_anchors: &[pkix_path::TrustAnchor],
    _now_unix: u64,
    _verifier: &impl pkix_path::SignatureVerifier,
) -> Result<()> {
    Err(Error::AaPathInvalid(pkix_path::Error::NoTrustedPath))
}
