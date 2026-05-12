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
//! `0.1.0` (PKIX-fmtv.21) shipped the public API surface with stub
//! bodies that returned [`IdentityError::NotYetImplemented`]. The
//! unreleased line on `main` (PKIX-fmtv.11.1) fills in
//! [`ServerName::dns_name`], [`ServerName::ip_address`], and
//! [`verify_dns_name`] with the RFC 6125 §6.4 hostname-binding
//! implementation. [`MailboxName::parse`] and [`verify_mailbox`] still
//! return [`IdentityError::NotYetImplemented`]; the fillings land in
//! PKIX-fmtv.12.
//!
//! [`pkix-chain`]: https://docs.rs/pkix-chain
//! [`pkix-truststore-system`]: https://docs.rs/pkix-truststore-system
//! [`pkix-truststore-pkcs11`]: https://docs.rs/pkix-truststore-pkcs11
//! [`Certificate`]: x509_cert::Certificate

extern crate alloc;

use alloc::borrow::Cow;
use alloc::vec::Vec;
use core::marker::PhantomData;
use der::{asn1::ObjectIdentifier, Decode as _};
use x509_cert::ext::pkix::{name::GeneralName, SubjectAltName};
use x509_cert::Certificate;

/// OID of the Subject Alternative Name extension (RFC 5280 §4.2.1.6).
const OID_SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");

/// Maximum length of a DNS name (RFC 1035 §2.3.4: 255 octets including
/// length bytes, ≤ 253 characters as a dotted string).
const DNS_NAME_MAX_LEN: usize = 253;

/// Maximum length of a single DNS label (RFC 1035 §2.3.4: 63 octets).
const DNS_LABEL_MAX_LEN: usize = 63;

/// Parsed server identity: DNS hostname or IP literal.
///
/// Construct via [`ServerName::dns_name`] or [`ServerName::ip_address`].
/// DNS names are normalized at parse time (lower-case ASCII, IDN inputs
/// converted to A-label form); IP literals are normalized to their
/// canonical 4- or 16-byte representation.
///
/// The `'a` lifetime borrows from the caller's input only when no
/// normalization was required (pure-ASCII lower-case DNS name, IP literal
/// whose canonical encoding is independent of the textual form).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ServerName<'a> {
    repr: ServerNameRepr<'a>,
}

#[derive(Debug, Clone)]
enum ServerNameRepr<'a> {
    /// Lower-cased, possibly A-label-converted DNS hostname.
    Dns(Cow<'a, str>),
    /// Canonical IPv4 (4 bytes) or IPv6 (16 bytes) octets.
    Ip(IpRepr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpRepr {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl IpRepr {
    fn as_bytes(&self) -> &[u8] {
        match self {
            Self::V4(b) => b,
            Self::V6(b) => b,
        }
    }
}

impl<'a> ServerName<'a> {
    /// Parse a DNS hostname.
    ///
    /// The input is validated and normalized:
    ///
    /// - Empty input, inputs longer than 253 octets, or labels longer
    ///   than 63 octets are rejected with [`IdentityError::MalformedInput`].
    /// - Pure-ASCII inputs are validated against the LDH (letter / digit /
    ///   hyphen) rule of RFC 1035 §2.3.1 (hyphens may not start or end a
    ///   label) and lower-cased.
    /// - Inputs containing non-ASCII code points are run through IDNA
    ///   2008 (RFC 5890) to produce the A-label form before storage.
    /// - A single trailing dot (absolute form) is accepted and stripped;
    ///   leading dots, embedded empty labels, and the bare string `"."` are
    ///   rejected.
    ///
    /// Bare wildcards (`"*.example.com"`) are **not** valid as a target
    /// identity — wildcards only make sense as SAN entries on a
    /// certificate. This function rejects any input containing `'*'`.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::MalformedInput`] for empty, overlong, or
    /// non-LDH inputs, and for inputs that fail IDNA 2008 conversion.
    pub fn dns_name(name: &'a str) -> Result<Self, IdentityError> {
        let normalized = normalize_dns_name(name)?;
        Ok(Self {
            repr: ServerNameRepr::Dns(normalized),
        })
    }

    /// Parse an IP address literal (IPv4 dotted-quad or IPv6, with or
    /// without surrounding brackets).
    ///
    /// IPv6 zone identifiers (the `%zone` suffix in RFC 6874) are not
    /// supported and cause [`IdentityError::MalformedInput`].
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::MalformedInput`] for inputs that do not
    /// parse as IPv4 or IPv6.
    pub fn ip_address(ip: &'a str) -> Result<Self, IdentityError> {
        let trimmed = ip
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .unwrap_or(ip);
        if trimmed.contains('%') {
            return Err(IdentityError::MalformedInput);
        }
        let parsed = parse_ip_literal(trimmed).ok_or(IdentityError::MalformedInput)?;
        Ok(Self {
            repr: ServerNameRepr::Ip(parsed),
        })
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
/// Variants will grow as PKIX-fmtv.12 lands; this enum is
/// `#[non_exhaustive]` so additions are not API breaks.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentityError {
    /// Functionality scaffolded but not yet implemented. Currently still
    /// returned by [`MailboxName::parse`] and [`verify_mailbox`].
    /// Tracked by PKIX-fmtv.12.
    NotYetImplemented,
    /// Input string did not parse as the expected identity form.
    MalformedInput,
    /// The certificate's Subject Alternative Name extension was present
    /// but contained no entry matching the requested identity.
    NoMatchingSan,
    /// The certificate did not carry a Subject Alternative Name extension.
    MissingSan,
    /// The certificate's Subject Alternative Name extension was present
    /// but could not be parsed.
    MalformedSan,
}

impl core::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotYetImplemented => {
                f.write_str("pkix-identity functionality not yet implemented")
            }
            Self::MalformedInput => f.write_str("malformed identity input"),
            Self::NoMatchingSan => {
                f.write_str("no Subject Alternative Name entry matched the identity")
            }
            Self::MissingSan => {
                f.write_str("certificate has no Subject Alternative Name extension")
            }
            Self::MalformedSan => {
                f.write_str("certificate Subject Alternative Name extension is malformed")
            }
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
/// Matching rules:
///
/// - DNS-name targets are compared against `GeneralName::DnsName` entries
///   case-insensitively. SAN entries may contain a single leftmost
///   wildcard label per RFC 6125 §6.4.3 (`*.foo.com` matches `a.foo.com`
///   but not `a.b.foo.com` or bare `foo.com`).
/// - IP-literal targets are compared against `GeneralName::IpAddress`
///   entries by byte-equal comparison of the canonical 4- or 16-octet
///   form.
///
/// Does **not** consult the certificate's Subject DN CN attribute — CN
/// fallback was deprecated by RFC 6125 §6.4.4 and is intentionally not
/// performed. A certificate that carries identity only in its CN is
/// rejected with [`IdentityError::MissingSan`].
///
/// # Errors
///
/// - [`IdentityError::MissingSan`] — the certificate has no SAN
///   extension at all.
/// - [`IdentityError::MalformedSan`] — the SAN extension is present but
///   cannot be parsed as a valid `SubjectAltName` SEQUENCE.
/// - [`IdentityError::NoMatchingSan`] — the SAN extension is present and
///   well-formed, but no entry matches the requested identity.
pub fn verify_dns_name(cert: &Certificate, name: &ServerName<'_>) -> Result<(), IdentityError> {
    let san = find_san(cert)?;
    match &name.repr {
        ServerNameRepr::Dns(target) => {
            for entry in san.0.iter() {
                if let GeneralName::DnsName(san_dns) = entry {
                    if matches_dns_san(san_dns.as_str(), target.as_ref()) {
                        return Ok(());
                    }
                }
            }
        }
        ServerNameRepr::Ip(target) => {
            for entry in san.0.iter() {
                if let GeneralName::IpAddress(san_ip) = entry {
                    if san_ip.as_bytes() == target.as_bytes() {
                        return Ok(());
                    }
                }
            }
        }
    }
    Err(IdentityError::NoMatchingSan)
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

// ---------------------------------------------------------------------------
// DNS name normalization
// ---------------------------------------------------------------------------

/// Normalize a DNS hostname target per RFC 6125 §6.4.
///
/// Pure-ASCII inputs are LDH-validated and lower-cased; non-ASCII
/// inputs are A-label-encoded via IDNA 2008.
fn normalize_dns_name(name: &str) -> Result<Cow<'_, str>, IdentityError> {
    if name.is_empty() {
        return Err(IdentityError::MalformedInput);
    }
    if name.contains('*') {
        // Wildcards are only meaningful as SAN entries on a cert, not as
        // a target identity to match against. RFC 6125 §7.2.
        return Err(IdentityError::MalformedInput);
    }
    // Strip a single trailing dot (absolute form, RFC 1035 §5.1).
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    if trimmed.is_empty() {
        return Err(IdentityError::MalformedInput);
    }
    if trimmed.is_ascii() {
        validate_ascii_dns(trimmed)?;
        if trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
            Ok(Cow::Owned(trimmed.to_ascii_lowercase()))
        } else {
            Ok(Cow::Borrowed(trimmed))
        }
    } else {
        // IDNA 2008 to_ascii: U-label → A-label.
        let ascii = idna::domain_to_ascii(trimmed).map_err(|_| IdentityError::MalformedInput)?;
        validate_ascii_dns(&ascii)?;
        Ok(Cow::Owned(ascii))
    }
}

/// Validate an already-ASCII DNS name against RFC 1035 LDH rules and
/// length limits. The input must not contain a trailing dot.
fn validate_ascii_dns(name: &str) -> Result<(), IdentityError> {
    if name.len() > DNS_NAME_MAX_LEN {
        return Err(IdentityError::MalformedInput);
    }
    let mut label_start = 0usize;
    let bytes = name.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'.' {
            let label = &bytes[label_start..i];
            validate_ascii_label(label)?;
            label_start = i + 1;
        }
    }
    validate_ascii_label(&bytes[label_start..])
}

fn validate_ascii_label(label: &[u8]) -> Result<(), IdentityError> {
    if label.is_empty() || label.len() > DNS_LABEL_MAX_LEN {
        return Err(IdentityError::MalformedInput);
    }
    if label[0] == b'-' || label[label.len() - 1] == b'-' {
        return Err(IdentityError::MalformedInput);
    }
    for &b in label {
        if !(b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
            // Underscore is non-LDH per RFC 1035 but widely tolerated;
            // RFC 6125 §6.4.2 does not require strict LDH rejection of
            // SAN entries on the matching path, but we apply the same
            // rule here for target normalization symmetry.
            return Err(IdentityError::MalformedInput);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// DNS SAN matching (RFC 6125 §6.4.3)
// ---------------------------------------------------------------------------

/// Returns true if `san_entry` (the value of a DNS-typed SAN entry on a
/// certificate) matches `target` (the already-normalized reference
/// identity).
///
/// The `target` is the output of [`normalize_dns_name`]: ASCII, lower-
/// case, no trailing dot. `san_entry` is the raw SAN bytes — possibly
/// mixed-case, possibly with an absolute-form trailing dot — and is
/// lower-cased / trimmed in place during comparison.
fn matches_dns_san(san_entry: &str, target: &str) -> bool {
    let san = san_entry.strip_suffix('.').unwrap_or(san_entry);
    if san.is_empty() {
        return false;
    }

    if let Some(rest) = san.strip_prefix("*.") {
        // RFC 6125 §6.4.3 rule 1: single leftmost wildcard label only.
        // Reject embedded wildcards (`*.foo.*.com`) — `rest` must not
        // itself contain a `*`.
        if rest.contains('*') || rest.is_empty() {
            return false;
        }
        // Reject bare `*` (no remaining labels) and `*.<TLD>` style
        // single-label suffixes — we conservatively require the
        // wildcard suffix to itself contain at least one label
        // separator, matching webpki / browsers' refusal to honor
        // wildcards on public-suffix-shaped suffixes. (Public suffix
        // list enforcement proper is out of scope per the crate
        // rustdoc, but the structural check is universally safe.)
        if !rest.contains('.') {
            return false;
        }
        // Match `target` = `<one-label>.<rest>` case-insensitively.
        let Some((first, rest_of_target)) = target.split_once('.') else {
            return false;
        };
        if first.is_empty() {
            return false;
        }
        // The wildcard replaces exactly one label — that label must not
        // itself contain a dot (already true: split_once stopped at the
        // first dot) and must be non-empty (already true).
        rest_of_target.eq_ignore_ascii_case(rest)
    } else if san.contains('*') {
        // Wildcards appearing anywhere other than the leftmost label
        // are not honored.
        false
    } else {
        san.eq_ignore_ascii_case(target)
    }
}

// ---------------------------------------------------------------------------
// IP literal parsing
// ---------------------------------------------------------------------------

fn parse_ip_literal(s: &str) -> Option<IpRepr> {
    if s.is_empty() {
        return None;
    }
    if s.contains(':') {
        parse_ipv6(s).map(IpRepr::V6)
    } else {
        parse_ipv4(s).map(IpRepr::V4)
    }
}

fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut count = 0usize;
    for part in s.split('.') {
        if count == 4 {
            return None;
        }
        // Reject leading zeros (e.g. "01.02.03.04") to match
        // pyca/cryptography's IPv4Address strictness and avoid the
        // octal-vs-decimal ambiguity inet_aton has historically caused.
        if part.is_empty() || (part.len() > 1 && part.starts_with('0')) {
            return None;
        }
        let value: u32 = part.parse().ok()?;
        if value > 255 {
            return None;
        }
        octets[count] = value as u8;
        count += 1;
    }
    (count == 4).then_some(octets)
}

fn parse_ipv6(s: &str) -> Option<[u8; 16]> {
    // Reject IPv4-in-IPv6 (e.g. ::ffff:192.0.2.1) for now — the canonical
    // 16-byte form is unambiguous so a future extension can add this
    // without API change. RFC 5952 strictness keeps the parser small.
    let mut groups: Vec<u16> = Vec::with_capacity(8);
    let mut zero_run_at: Option<usize> = None;
    let mut iter = s.split(':').peekable();
    // Handle leading "::"
    if s.starts_with("::") {
        zero_run_at = Some(0);
        // Consume the two empty leading segments produced by split.
        let _ = iter.next();
        let _ = iter.next();
        if s == "::" {
            return Some([0u8; 16]);
        }
    } else if s.starts_with(':') {
        // Single leading colon without `::` is malformed.
        return None;
    }
    while let Some(part) = iter.next() {
        if part.is_empty() {
            // Empty part = "::" elision.
            if zero_run_at.is_some() {
                // Multiple "::" runs not allowed.
                return None;
            }
            zero_run_at = Some(groups.len());
            // If we're at the trailing `::` (last component empty), peek
            // and stop.
            if iter.peek().is_none() {
                break;
            }
            continue;
        }
        if part.len() > 4 {
            return None;
        }
        let value = u16::from_str_radix(part, 16).ok()?;
        groups.push(value);
        if groups.len() > 8 {
            return None;
        }
    }
    let total = groups.len();
    let elided = 8usize.checked_sub(total)?;
    match zero_run_at {
        None => {
            if total != 8 {
                return None;
            }
            let mut out = [0u8; 16];
            for (i, g) in groups.iter().enumerate() {
                out[2 * i] = (g >> 8) as u8;
                out[2 * i + 1] = (g & 0xff) as u8;
            }
            Some(out)
        }
        Some(at) => {
            if total >= 8 {
                return None;
            }
            let mut out_groups = [0u16; 8];
            for (i, g) in groups[..at].iter().enumerate() {
                out_groups[i] = *g;
            }
            for (i, g) in groups[at..].iter().enumerate() {
                out_groups[at + elided + i] = *g;
            }
            let mut out = [0u8; 16];
            for (i, g) in out_groups.iter().enumerate() {
                out[2 * i] = (g >> 8) as u8;
                out[2 * i + 1] = (g & 0xff) as u8;
            }
            Some(out)
        }
    }
}

// ---------------------------------------------------------------------------
// SAN extension extraction
// ---------------------------------------------------------------------------

fn find_san(cert: &Certificate) -> Result<SubjectAltName, IdentityError> {
    let exts = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or(IdentityError::MissingSan)?;
    let ext = exts
        .iter()
        .find(|e| e.extn_id == OID_SUBJECT_ALT_NAME)
        .ok_or(IdentityError::MissingSan)?;
    SubjectAltName::from_der(ext.extn_value.as_bytes()).map_err(|_| IdentityError::MalformedSan)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // ServerName::dns_name
    // -----------------------------------------------------------------

    #[test]
    fn dns_name_accepts_simple() {
        let n = ServerName::dns_name("example.com").unwrap();
        match n.repr {
            ServerNameRepr::Dns(Cow::Borrowed(s)) => assert_eq!(s, "example.com"),
            _ => panic!("expected borrowed DNS name"),
        }
    }

    #[test]
    fn dns_name_lowercases_ascii() {
        let n = ServerName::dns_name("EXAMPLE.com").unwrap();
        match n.repr {
            ServerNameRepr::Dns(Cow::Owned(ref s)) => assert_eq!(s, "example.com"),
            _ => panic!("expected owned (lower-cased) DNS name"),
        }
    }

    #[test]
    fn dns_name_strips_trailing_dot() {
        let n = ServerName::dns_name("example.com.").unwrap();
        match n.repr {
            ServerNameRepr::Dns(Cow::Borrowed(s)) => assert_eq!(s, "example.com"),
            _ => panic!("expected borrowed DNS name without trailing dot"),
        }
    }

    #[test]
    fn dns_name_rejects_empty() {
        assert_eq!(
            ServerName::dns_name("").err(),
            Some(IdentityError::MalformedInput),
        );
        assert_eq!(
            ServerName::dns_name(".").err(),
            Some(IdentityError::MalformedInput),
        );
    }

    #[test]
    fn dns_name_rejects_leading_or_embedded_dot() {
        assert_eq!(
            ServerName::dns_name(".example.com").err(),
            Some(IdentityError::MalformedInput),
        );
        assert_eq!(
            ServerName::dns_name("foo..bar").err(),
            Some(IdentityError::MalformedInput),
        );
    }

    #[test]
    fn dns_name_rejects_wildcards() {
        // Wildcards belong on certs, not on target identities.
        assert_eq!(
            ServerName::dns_name("*.example.com").err(),
            Some(IdentityError::MalformedInput),
        );
        assert_eq!(
            ServerName::dns_name("*").err(),
            Some(IdentityError::MalformedInput),
        );
    }

    #[test]
    fn dns_name_rejects_hyphen_at_label_boundary() {
        assert_eq!(
            ServerName::dns_name("-bad.example.com").err(),
            Some(IdentityError::MalformedInput),
        );
        assert_eq!(
            ServerName::dns_name("bad-.example.com").err(),
            Some(IdentityError::MalformedInput),
        );
    }

    #[test]
    fn dns_name_rejects_overlong() {
        // 254 octets total (one over the limit).
        let long =
            "a".repeat(63) + "." + &"b".repeat(63) + "." + &"c".repeat(63) + "." + &"d".repeat(62);
        assert!(long.len() == 254);
        assert_eq!(
            ServerName::dns_name(&long).err(),
            Some(IdentityError::MalformedInput),
        );
        // Single label over 63 octets.
        let toolong_label = "x".repeat(64) + ".example.com";
        assert_eq!(
            ServerName::dns_name(&toolong_label).err(),
            Some(IdentityError::MalformedInput),
        );
    }

    #[test]
    fn dns_name_accepts_at_length_limit() {
        // 253 octets total (at the limit, RFC 1035 §2.3.4).
        // 63 + 1 + 63 + 1 + 63 + 1 + 61 = 253.
        let domain =
            "a".repeat(63) + "." + &"b".repeat(63) + "." + &"c".repeat(63) + "." + &"d".repeat(61);
        assert_eq!(domain.len(), 253);
        let n = ServerName::dns_name(&domain).unwrap();
        assert!(matches!(n.repr, ServerNameRepr::Dns(_)));
    }

    #[test]
    fn dns_name_idn_u_label_converted_to_a_label() {
        // bücher.example → xn--bcher-kva.example
        let n = ServerName::dns_name("bücher.example").unwrap();
        match n.repr {
            ServerNameRepr::Dns(Cow::Owned(ref s)) => assert_eq!(s, "xn--bcher-kva.example"),
            _ => panic!(
                "expected owned (A-label-converted) DNS name; got {:?}",
                n.repr
            ),
        }
    }

    // -----------------------------------------------------------------
    // ServerName::ip_address
    // -----------------------------------------------------------------

    #[test]
    fn ip_address_v4() {
        let n = ServerName::ip_address("192.0.2.1").unwrap();
        match n.repr {
            ServerNameRepr::Ip(IpRepr::V4([192, 0, 2, 1])) => {}
            _ => panic!("expected V4(192.0.2.1)"),
        }
    }

    #[test]
    fn ip_address_v4_rejects_octal_form() {
        assert!(ServerName::ip_address("192.000.2.01").is_err());
    }

    #[test]
    fn ip_address_v4_rejects_out_of_range() {
        assert!(ServerName::ip_address("256.0.0.1").is_err());
        assert!(ServerName::ip_address("1.2.3").is_err());
        assert!(ServerName::ip_address("1.2.3.4.5").is_err());
    }

    #[test]
    fn ip_address_v6() {
        let n = ServerName::ip_address("2001:db8::1").unwrap();
        let expected = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        match n.repr {
            ServerNameRepr::Ip(IpRepr::V6(bytes)) => assert_eq!(bytes, expected),
            _ => panic!("expected V6"),
        }
    }

    #[test]
    fn ip_address_v6_bracketed() {
        let n = ServerName::ip_address("[2001:db8::1]").unwrap();
        match n.repr {
            ServerNameRepr::Ip(IpRepr::V6(_)) => {}
            _ => panic!("expected V6 from bracketed form"),
        }
    }

    #[test]
    fn ip_address_v6_all_zero() {
        let n = ServerName::ip_address("::").unwrap();
        match n.repr {
            ServerNameRepr::Ip(IpRepr::V6(b)) => assert_eq!(b, [0u8; 16]),
            _ => panic!("expected V6 all-zero"),
        }
    }

    #[test]
    fn ip_address_v6_full() {
        let n = ServerName::ip_address("2001:db8:0:0:0:0:0:1").unwrap();
        let expected = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        match n.repr {
            ServerNameRepr::Ip(IpRepr::V6(b)) => assert_eq!(b, expected),
            _ => panic!("expected V6"),
        }
    }

    #[test]
    fn ip_address_rejects_zone_id() {
        assert!(ServerName::ip_address("fe80::1%eth0").is_err());
    }

    #[test]
    fn ip_address_rejects_malformed() {
        assert!(ServerName::ip_address("").is_err());
        assert!(ServerName::ip_address("not-an-ip").is_err());
        assert!(ServerName::ip_address("2001::db8::1").is_err()); // two `::`
        assert!(ServerName::ip_address("[2001:db8::1").is_err()); // missing ]
    }

    // -----------------------------------------------------------------
    // matches_dns_san pure-fn tests (RFC 6125 §6.4.3)
    // -----------------------------------------------------------------

    #[test]
    fn san_exact_match_case_insensitive() {
        assert!(matches_dns_san("Example.COM", "example.com"));
        assert!(matches_dns_san("example.com.", "example.com")); // SAN trailing dot tolerated
        assert!(!matches_dns_san("example.org", "example.com"));
    }

    #[test]
    fn san_wildcard_matches_single_label() {
        assert!(matches_dns_san("*.foo.com", "a.foo.com"));
        assert!(matches_dns_san("*.foo.com", "WWW.FOO.COM"));
        assert!(!matches_dns_san("*.foo.com", "a.b.foo.com"));
        assert!(!matches_dns_san("*.foo.com", "foo.com"));
    }

    #[test]
    fn san_wildcard_rejects_bare_asterisk() {
        assert!(!matches_dns_san("*", "anything.com"));
        assert!(!matches_dns_san("*.", "anything.com"));
    }

    #[test]
    fn san_wildcard_rejects_single_label_tld() {
        // Conservative structural rule (defense-in-depth against PSL gaps).
        assert!(!matches_dns_san("*.com", "anything.com"));
    }

    #[test]
    fn san_wildcard_rejects_embedded_wildcards() {
        assert!(!matches_dns_san("*.foo.*.com", "a.foo.b.com"));
        assert!(!matches_dns_san("foo.*.com", "foo.bar.com"));
        assert!(!matches_dns_san("f*o.example.com", "foo.example.com"));
        assert!(!matches_dns_san("*foo.example.com", "myfoo.example.com"));
    }

    // -----------------------------------------------------------------
    // IdentityError Display
    // -----------------------------------------------------------------

    #[test]
    fn identity_error_display_covers_all_variants() {
        for err in [
            IdentityError::NotYetImplemented,
            IdentityError::MalformedInput,
            IdentityError::NoMatchingSan,
            IdentityError::MissingSan,
            IdentityError::MalformedSan,
        ] {
            let s = alloc::format!("{err}");
            assert!(!s.is_empty());
        }
    }

    // -----------------------------------------------------------------
    // MailboxName + verify_mailbox still scaffolded (PKIX-fmtv.12)
    // -----------------------------------------------------------------

    #[test]
    fn mailbox_parse_still_not_yet_implemented() {
        assert_eq!(
            MailboxName::parse("user@example.com").err(),
            Some(IdentityError::NotYetImplemented),
        );
    }
}
