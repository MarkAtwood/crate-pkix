#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! Cert-side identity matching: does this leaf certificate authorize this
//! name?
//!
//! This crate answers identity-binding questions for already-parsed
//! `x509-cert` [`Certificate`] values:
//!
//! - **DNS hostname** binding per RFC 6125 §6.4 (TLS server identity).
//! - **IP literal** binding (IPv4/IPv6 byte-equal SAN entry).
//! - **Mailbox** binding per RFC 5280 §4.2.1.6 and RFC 8398
//!   (S/MIME signer/recipient identity).
//!
//! It is pure: no chain context, no trust anchors, no revocation, no I/O.
//!
//! # Relationship to other workspace crates
//!
//! Identity matching is reused by several callers and split out so each
//! gets a focused dep:
//!
//! - [`pkix-chain`] composes path validation + identity matching in its
//!   `verify_tls_server` / `verify_smime_signer` wrappers.
//! - Future trust-store adapters ([`pkix-truststore-system`],
//!   [`pkix-truststore-pkcs11`]) use it to answer "what identities does
//!   this anchored cert claim?".
//! - ACME / TLS-ALPN-01 implementations use it for leaf-cert identity
//!   checks without paying for a full chain validator.
//!
//! Precedent for splitting identity matching from chain validation:
//! `rustls-pki-types::ServerName` + `webpki::SubjectNameRef`.
//!
//! # Scope discipline
//!
//! **In scope.** Server name parsing (DNS hostname + IP literal),
//! mailbox parsing (RFC 5322 / RFC 8398 SmtpUTF8Mailbox via otherName),
//! `verify_dns_name`, `verify_mailbox`, IDN A-label/U-label normalization,
//! and the wildcard/case-folding/IP-compare helpers those need internally.
//!
//! **Out of scope.**
//!
//! - **Name constraints matching.** Different semantics — constraint
//!   subset check, not target match. Lives in `pkix-path` as
//!   `dns_name_matches_constraint` and stays there.
//! - **DN canonicalization (RFC 4518 string prep).** Already in
//!   `pkix-path`; not duplicated here.
//! - **CSR parsing.** Not a verifier concern.
//! - **Public Suffix List enforcement (eTLD blocking).** Deliberately not
//!   included. Callers who need it pull in their own PSL crate. `webpki`
//!   makes the same choice; this crate follows.
//! - Anything that requires chain context or trust-anchor knowledge.
//!
//! # Spec references
//!
//! - RFC 6125 §6.4 — Server identity matching
//! - RFC 5280 §4.2.1.6 — Subject Alternative Name extension
//! - RFC 8398 — Internationalized Email Addresses in X.509 Certificates
//! - IDNA 2008 (RFC 5890–5894) — A-label / U-label conversion
//!
//! # Versioning
//!
//! `0.1.0` ships the public API surface with stub bodies that return
//! [`IdentityError::NotYetImplemented`]. The fillings land in
//! PKIX-fmtv.11 (`verify_dns_name`) and PKIX-fmtv.12 (`verify_mailbox`).
//! Constructor input validation also lands in those issues; today
//! `ServerName::dns_name`, `ServerName::ip_address`, and
//! `MailboxName::parse` accept any input and stash it.
//!
//! [`pkix-chain`]: https://docs.rs/pkix-chain
//! [`pkix-truststore-system`]: https://docs.rs/pkix-truststore-system
//! [`pkix-truststore-pkcs11`]: https://docs.rs/pkix-truststore-pkcs11
//! [`Certificate`]: x509_cert::Certificate

use core::marker::PhantomData;
use x509_cert::Certificate;

/// Parsed server identity: DNS hostname or IP literal.
///
/// Construct via [`ServerName::dns_name`] or [`ServerName::ip_address`].
/// Borrowed against the caller's input string for the lifetime `'a`.
///
/// The private representation is unspecified and will gain DNS-vs-IP
/// discrimination plus normalized storage in PKIX-fmtv.11.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ServerName<'a> {
    _borrow: PhantomData<&'a str>,
}

impl<'a> ServerName<'a> {
    /// Parse a DNS hostname.
    ///
    /// # Errors
    ///
    /// Will return [`IdentityError::MalformedInput`] for empty, overlong,
    /// or non-LDH inputs once PKIX-fmtv.11 fills in validation.
    /// Currently returns [`IdentityError::NotYetImplemented`] for any
    /// input — including valid ones — to avoid silently constructing a
    /// stub that compares against nothing.
    pub fn dns_name(_name: &'a str) -> Result<Self, IdentityError> {
        Err(IdentityError::NotYetImplemented)
    }

    /// Parse an IP address literal (IPv4 dotted-quad or IPv6 bracketed).
    ///
    /// # Errors
    ///
    /// Will return [`IdentityError::MalformedInput`] for inputs that do
    /// not parse as IPv4 or IPv6 once PKIX-fmtv.11 fills in validation.
    /// Currently returns [`IdentityError::NotYetImplemented`] for any
    /// input.
    pub fn ip_address(_ip: &'a str) -> Result<Self, IdentityError> {
        Err(IdentityError::NotYetImplemented)
    }
}

/// Parsed RFC 5322 / RFC 8398 mailbox.
///
/// Construct via [`MailboxName::parse`]. Borrowed against the caller's
/// input string for the lifetime `'a`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct MailboxName<'a> {
    _borrow: PhantomData<&'a str>,
}

impl<'a> MailboxName<'a> {
    /// Parse an RFC 5322 mailbox, optionally with an internationalized
    /// local-part (RFC 8398 SmtpUTF8Mailbox).
    ///
    /// # Errors
    ///
    /// Will return [`IdentityError::MalformedInput`] for inputs that do
    /// not parse as a mailbox once PKIX-fmtv.12 fills in validation.
    /// Currently returns [`IdentityError::NotYetImplemented`] for any
    /// input.
    pub fn parse(_mailbox: &'a str) -> Result<Self, IdentityError> {
        Err(IdentityError::NotYetImplemented)
    }
}

/// Identity-binding errors.
///
/// Variants will grow as PKIX-fmtv.11 and .12 land; this enum is
/// `#[non_exhaustive]` so additions are not API breaks.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentityError {
    /// Functionality scaffolded but not yet implemented. Returned by all
    /// of `pkix-identity` `0.1.0`. Tracked by PKIX-fmtv.11 / .12.
    NotYetImplemented,
    /// Input string did not parse as the expected identity form.
    MalformedInput,
    /// The certificate's Subject Alternative Name extension was present
    /// but contained no entry matching the requested identity.
    NoMatchingSan,
    /// The certificate did not carry a Subject Alternative Name extension.
    MissingSan,
}

impl core::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotYetImplemented => f.write_str("pkix-identity functionality not yet implemented"),
            Self::MalformedInput => f.write_str("malformed identity input"),
            Self::NoMatchingSan => f.write_str("no Subject Alternative Name entry matched the identity"),
            Self::MissingSan => f.write_str("certificate has no Subject Alternative Name extension"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IdentityError {}

/// Verify that `cert` authorizes `name` per RFC 6125 §6.4.
///
/// Walks `cert`'s Subject Alternative Name extension. Returns `Ok(())`
/// if any SAN entry matches `name`; otherwise [`IdentityError::NoMatchingSan`]
/// or [`IdentityError::MissingSan`].
///
/// Does **not** consult the certificate's Subject DN CN attribute — CN
/// fallback was deprecated by RFC 6125 §6.4.4 and is intentionally not
/// performed.
///
/// # Errors
///
/// See [`IdentityError`]. Currently always returns
/// [`IdentityError::NotYetImplemented`] until PKIX-fmtv.11 fills in the
/// body.
pub const fn verify_dns_name(
    _cert: &Certificate,
    _name: &ServerName<'_>,
) -> Result<(), IdentityError> {
    Err(IdentityError::NotYetImplemented)
}

/// Verify that `cert` authorizes `mailbox` per RFC 5280 §4.2.1.6 and
/// RFC 8398.
///
/// Walks `cert`'s Subject Alternative Name extension for `rfc822Name`
/// (ASCII mailbox) and `otherName` with the SmtpUTF8Mailbox OID
/// (internationalized mailbox). Returns `Ok(())` if any entry matches
/// `mailbox`; otherwise [`IdentityError::NoMatchingSan`] or
/// [`IdentityError::MissingSan`].
///
/// # Errors
///
/// See [`IdentityError`]. Currently always returns
/// [`IdentityError::NotYetImplemented`] until PKIX-fmtv.12 fills in the
/// body.
pub const fn verify_mailbox(
    _cert: &Certificate,
    _mailbox: &MailboxName<'_>,
) -> Result<(), IdentityError> {
    Err(IdentityError::NotYetImplemented)
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;

    #[test]
    fn server_name_dns_returns_not_yet_implemented() {
        assert_eq!(
            ServerName::dns_name("example.com").err(),
            Some(IdentityError::NotYetImplemented),
        );
    }

    #[test]
    fn server_name_ip_returns_not_yet_implemented() {
        assert_eq!(
            ServerName::ip_address("203.0.113.1").err(),
            Some(IdentityError::NotYetImplemented),
        );
    }

    #[test]
    fn mailbox_parse_returns_not_yet_implemented() {
        assert_eq!(
            MailboxName::parse("user@example.com").err(),
            Some(IdentityError::NotYetImplemented),
        );
    }

    #[test]
    fn identity_error_display_covers_all_variants() {
        // If a new variant is added without a Display arm, the Display
        // impl will fail to compile (it is an exhaustive match within
        // the crate). This test exercises every variant constructible
        // from the stub bodies plus those reserved for .11 / .12.
        for err in [
            IdentityError::NotYetImplemented,
            IdentityError::MalformedInput,
            IdentityError::NoMatchingSan,
            IdentityError::MissingSan,
        ] {
            let s = alloc::format!("{err}");
            assert!(!s.is_empty());
        }
    }
}
