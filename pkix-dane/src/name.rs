//! TLSA owner-name construction.
//!
//! A TLSA record is published at a name derived from the transport port,
//! protocol and host of the service it describes, per
//! [RFC 6698 §3](https://www.rfc-editor.org/rfc/rfc6698#section-3):
//!
//! ```text
//! _<port>._<proto>.<hostname>
//! _443._tcp.www.example.com
//! _25._tcp.mail.example.com
//! ```
//!
//! This is string construction with no I/O, which is why it lives in this
//! `no_std` crate rather than in `pkix-dane-resolver`: it is testable without
//! a network, and a caller who brings their own resolver needs it just as much
//! as one who uses the reference resolver.

use alloc::string::String;
use alloc::vec::Vec;

use crate::DaneError;

/// Maximum length of a DNS name in presentation format, in octets.
///
/// The 255-octet ceiling is on the wire encoding, where each label costs a
/// length octet and the root costs one more. Checking the dotted string
/// against 253 is the standard conservative equivalent.
const MAX_NAME_LEN: usize = 253;

/// Maximum length of a single DNS label, in octets
/// ([RFC 1035 §2.3.4](https://www.rfc-editor.org/rfc/rfc1035#section-2.3.4)).
const MAX_LABEL_LEN: usize = 63;

// ---------------------------------------------------------------------------
// TlsaProtocol
// ---------------------------------------------------------------------------

/// Transport protocol component of a TLSA owner name.
///
/// RFC 6698 §3 gives the prefix as "the protocol name", lowercase, taken from
/// the set used by SRV records. The three that occur in practice are
/// enumerated; [`Other`](Self::Other) covers the rest without blocking a
/// caller on a variant this crate has not anticipated.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TlsaProtocol {
    /// TCP — every TLS-over-TCP service, which is nearly all of DANE.
    Tcp,
    /// UDP — DTLS services.
    Udp,
    /// SCTP.
    Sctp,
    /// Any other protocol label.
    ///
    /// Validated as a DNS label when the owner name is built, so a caller
    /// cannot inject a dot or an over-long label this way.
    Other(String),
}

impl TlsaProtocol {
    /// The protocol label, without the leading underscore.
    #[must_use]
    pub fn label(&self) -> &str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Sctp => "sctp",
            Self::Other(label) => label,
        }
    }
}

// ---------------------------------------------------------------------------
// TlsaName
// ---------------------------------------------------------------------------

/// The DNS owner name at which a service's TLSA records are published.
///
/// Built with [`new`](Self::new), which validates the result as a DNS name.
/// The rendered form is available from [`as_str`](Self::as_str).
///
/// # CNAME expansion is the resolver's problem
///
/// [RFC 7671 §7](https://www.rfc-editor.org/rfc/rfc7671#section-7) covers what
/// to do when the service host is a `CNAME`: the TLSA query should be made
/// against the fully-expanded name, and the original name is the fallback.
/// Deciding that requires actually resolving the host, so it belongs to the
/// resolver, not here. This type constructs an owner name from whatever host
/// it is given; a resolver implementing RFC 7671 §7 builds one `TlsaName` per
/// candidate host and queries them in order.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TlsaName {
    rendered: String,
}

impl TlsaName {
    /// Builds the owner name `_<port>._<proto>.<host>`.
    ///
    /// `host` may carry a trailing dot; it is preserved, since a
    /// fully-qualified name with the root label explicit is a legitimate thing
    /// to query for and dropping it would change the query.
    ///
    /// # Errors
    ///
    /// - [`DaneError::InvalidHost`] if `host` is empty, has an empty label
    ///   (`a..b`, or a leading dot), has a label longer than 63 octets, or
    ///   contains a byte outside the LDH set plus `_` and `*`.
    /// - [`DaneError::InvalidProtocol`] if the protocol label is empty, longer
    ///   than 63 octets, or not purely lowercase ASCII alphanumeric.
    /// - [`DaneError::NameTooLong`] if the assembled name exceeds 253 octets.
    ///
    /// # Examples
    ///
    /// ```
    /// use pkix_dane::{TlsaName, TlsaProtocol};
    ///
    /// let name = TlsaName::new(443, &TlsaProtocol::Tcp, "www.example.com")?;
    /// assert_eq!(name.as_str(), "_443._tcp.www.example.com");
    ///
    /// let smtp = TlsaName::new(25, &TlsaProtocol::Tcp, "mail.example.com.")?;
    /// assert_eq!(smtp.as_str(), "_25._tcp.mail.example.com.");
    /// # Ok::<(), pkix_dane::DaneError>(())
    /// ```
    pub fn new(port: u16, proto: &TlsaProtocol, host: &str) -> Result<Self, DaneError> {
        let proto_label = proto.label();
        validate_protocol_label(proto_label)?;
        validate_host(host)?;

        // "_" + up to 5 digits + "._" + proto + "." + host
        let mut rendered = String::with_capacity(9 + proto_label.len() + host.len());
        rendered.push('_');
        push_u16(&mut rendered, port);
        rendered.push_str("._");
        rendered.push_str(proto_label);
        rendered.push('.');
        rendered.push_str(host);

        if rendered.len() > MAX_NAME_LEN {
            return Err(DaneError::NameTooLong {
                len: rendered.len(),
            });
        }
        Ok(Self { rendered })
    }

    /// The owner name in DNS presentation format.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.rendered
    }
}

impl core::fmt::Display for TlsaName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.rendered)
    }
}

/// Appends `value`'s decimal form without leading zeros.
///
/// Hand-rolled rather than `write!` so that this crate needs no `fmt::Write`
/// import and cannot fail: a `u16` is at most five digits.
fn push_u16(out: &mut String, value: u16) {
    if value == 0 {
        out.push('0');
        return;
    }
    let mut digits = [0u8; 5];
    let mut n = value;
    let mut i = 0;
    while n > 0 {
        digits[i] = b'0' + u8::try_from(n % 10).expect("a decimal digit should fit in a u8");
        n /= 10;
        i += 1;
    }
    for &digit in digits[..i].iter().rev() {
        out.push(char::from(digit));
    }
}

/// Checks `label` as a protocol component: non-empty, within the label length
/// limit, lowercase ASCII alphanumeric.
///
/// Lowercase is required rather than normalized because RFC 6698 §3 writes the
/// prefixes in lowercase and silently rewriting a caller's input would hide a
/// bug in how they obtained it. DNS comparison is case-insensitive, so an
/// uppercase label would still resolve — but it would not match what the
/// caller believes they are querying.
fn validate_protocol_label(label: &str) -> Result<(), DaneError> {
    if label.is_empty() || label.len() > MAX_LABEL_LEN {
        return Err(DaneError::InvalidProtocol);
    }
    if !label
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return Err(DaneError::InvalidProtocol);
    }
    Ok(())
}

/// Checks `host` as a DNS name: non-empty, no empty labels, every label within
/// the length limit, every byte in the permitted set.
///
/// The permitted set is letters, digits, `-`, `_` and `*`. Underscore is
/// needed because service hosts in DANE deployments do carry underscore
/// labels; `*` is permitted so a caller can construct the owner name of a
/// wildcard record. Non-ASCII is refused outright: an internationalized name
/// must be converted to A-label form by the caller (with the `idna` crate, as
/// `pkix-identity` does) before it can be a DNS query name.
fn validate_host(host: &str) -> Result<(), DaneError> {
    if host.is_empty() {
        return Err(DaneError::InvalidHost);
    }
    // A single trailing dot is the explicit root label, not an empty label.
    let body = host.strip_suffix('.').unwrap_or(host);
    if body.is_empty() {
        return Err(DaneError::InvalidHost);
    }

    let labels: Vec<&str> = body.split('.').collect();
    for label in labels {
        if label.is_empty() || label.len() > MAX_LABEL_LEN {
            return Err(DaneError::InvalidHost);
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'*')
        {
            return Err(DaneError::InvalidHost);
        }
    }
    Ok(())
}
