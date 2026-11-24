//! TLSA resource-record types and wire-format parsing.
//!
//! The three one-octet selector fields are defined in
//! [RFC 6698 §2.1](https://www.rfc-editor.org/rfc/rfc6698#section-2.1);
//! the mnemonics used for their variants come from
//! [RFC 7218 §2](https://www.rfc-editor.org/rfc/rfc7218#section-2), which
//! exists precisely so that DANE discussions can say `DANE-EE` instead of
//! "certificate usage 3".

use alloc::vec::Vec;

use crate::DaneError;

/// Length of the fixed TLSA RDATA header: usage, selector, matching type.
const RDATA_HEADER_LEN: usize = 3;

/// SHA2-256 digest length, in octets.
pub(crate) const SHA256_LEN: usize = 32;

/// SHA2-512 digest length, in octets.
pub(crate) const SHA512_LEN: usize = 64;

// ---------------------------------------------------------------------------
// TlsaUsage
// ---------------------------------------------------------------------------

/// TLSA certificate usage — which assertion the record makes.
///
/// Per [RFC 6698 §2.1.1](https://www.rfc-editor.org/rfc/rfc6698#section-2.1.1),
/// with mnemonics from [RFC 7218 §2.1](https://www.rfc-editor.org/rfc/rfc7218#section-2.1).
/// The four assigned usages split along two axes: whether the record pins a
/// trust anchor or an end-entity certificate, and whether PKIX path validation
/// is additionally required.
///
/// |  | pins a trust anchor | pins the end-entity cert |
/// |--|--|--|
/// | **PKIX validation also required** | [`PkixTa`](Self::PkixTa) (0) | [`PkixEe`](Self::PkixEe) (1) |
/// | **PKIX validation bypassed** | [`DaneTa`](Self::DaneTa) (2) | [`DaneEe`](Self::DaneEe) (3) |
///
/// # Exhaustiveness
///
/// This enum is deliberately **not** `#[non_exhaustive]`: it covers all 256
/// octet values, so a `match` over it is total and no caller can silently
/// forget a usage. That matters more here than forward-compatibility
/// insulation, because failing to handle a usage in security-critical matching
/// code is the worse outcome.
///
/// The cost is that if IANA ever assigns a new usage, promoting it from
/// [`Unassigned`](Self::Unassigned) to a named variant is a breaking change.
/// That trade is deliberate and acceptable: the registry has been stable since
/// RFC 6698 (2012), and this workspace is pre-1.0, where breaking changes are
/// the mechanism for getting the design right rather than a cost to avoid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TlsaUsage {
    /// **PKIX-TA (0)** — CA constraint.
    ///
    /// The record pins a trust anchor that MUST appear in the validated
    /// chain, *and* the chain MUST also pass ordinary PKIX path validation
    /// against the client's own trust store. Strictly narrows PKIX; it cannot
    /// make an otherwise-invalid chain valid.
    PkixTa,

    /// **PKIX-EE (1)** — service certificate constraint.
    ///
    /// The record pins the end-entity certificate, *and* the chain MUST also
    /// pass ordinary PKIX path validation. Like [`PkixTa`](Self::PkixTa), it
    /// only narrows.
    PkixEe,

    /// **DANE-TA (2)** — trust anchor assertion.
    ///
    /// The record supplies a trust anchor. The chain MUST reach that anchor,
    /// but the anchor need not be in the client's trust store — DNSSEC
    /// vouches for it instead. This usage can make a chain valid that PKIX
    /// alone would reject.
    DaneTa,

    /// **DANE-EE (3)** — domain-issued certificate.
    ///
    /// The record pins the end-entity certificate directly. Chain building
    /// and PKIX path validation are bypassed entirely; DNSSEC is the sole
    /// source of trust.
    ///
    /// Per [RFC 7671 §5.1](https://www.rfc-editor.org/rfc/rfc7671#section-5.1),
    /// certificate expiration and the identity (name) check are **also**
    /// bypassed for this usage: the TLSA record is the binding, so the
    /// certificate's own validity dates and subject names are not consulted.
    DaneEe,

    /// An octet value IANA has not assigned (4–254).
    ///
    /// Per [RFC 7671 §17](https://www.rfc-editor.org/rfc/rfc7671#section-17),
    /// records carrying an unrecognized usage are *unusable* and must be
    /// ignored — not treated as a failure. A record set mixing unassigned and
    /// assigned usages still succeeds via the assigned ones.
    Unassigned(u8),

    /// The private-use value 255.
    ///
    /// Reserved by RFC 6698 for local experimentation. Treated as unusable by
    /// this crate's matching code; a caller with a private convention can
    /// inspect the record set itself.
    PrivateUse,
}

impl TlsaUsage {
    /// Decodes the one-octet wire value.
    ///
    /// Total: every octet maps to some variant.
    #[must_use]
    pub const fn from_octet(octet: u8) -> Self {
        match octet {
            0 => Self::PkixTa,
            1 => Self::PkixEe,
            2 => Self::DaneTa,
            3 => Self::DaneEe,
            255 => Self::PrivateUse,
            other => Self::Unassigned(other),
        }
    }

    /// Encodes back to the one-octet wire value.
    ///
    /// Round-trips with [`from_octet`](Self::from_octet) for every octet.
    #[must_use]
    pub const fn to_octet(self) -> u8 {
        match self {
            Self::PkixTa => 0,
            Self::PkixEe => 1,
            Self::DaneTa => 2,
            Self::DaneEe => 3,
            Self::PrivateUse => 255,
            Self::Unassigned(other) => other,
        }
    }

    /// Whether this usage requires the chain to also pass PKIX path
    /// validation against the client's own trust store.
    ///
    /// True for [`PkixTa`](Self::PkixTa) and [`PkixEe`](Self::PkixEe).
    #[must_use]
    pub const fn requires_pkix_validation(self) -> bool {
        matches!(self, Self::PkixTa | Self::PkixEe)
    }

    /// Whether this usage is one of the four IANA-assigned usages.
    ///
    /// False for [`Unassigned`](Self::Unassigned) and
    /// [`PrivateUse`](Self::PrivateUse), the two unusable cases.
    #[must_use]
    pub const fn is_assigned(self) -> bool {
        matches!(
            self,
            Self::PkixTa | Self::PkixEe | Self::DaneTa | Self::DaneEe
        )
    }
}

// ---------------------------------------------------------------------------
// TlsaSelector
// ---------------------------------------------------------------------------

/// TLSA selector — which part of the certificate the record is about.
///
/// Per [RFC 6698 §2.1.2](https://www.rfc-editor.org/rfc/rfc6698#section-2.1.2),
/// mnemonics from [RFC 7218 §2.2](https://www.rfc-editor.org/rfc/rfc7218#section-2.2).
///
/// See [`TlsaUsage`]'s exhaustiveness note; the same reasoning applies here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TlsaSelector {
    /// **Cert (0)** — the full DER-encoded certificate.
    ///
    /// The selected content is the complete `Certificate` encoding:
    /// `tbsCertificate` + `signatureAlgorithm` + `signatureValue`.
    ///
    /// # Byte exactness
    ///
    /// This crate hashes the certificate bytes **as presented by the peer**,
    /// never a re-encoding of a parsed certificate. See the
    /// [`selector`](crate::selector) module documentation for why that
    /// distinction is load-bearing rather than merely tidy.
    Cert,

    /// **SPKI (1)** — the DER-encoded `SubjectPublicKeyInfo`.
    ///
    /// Pinning the public key rather than the certificate lets the operator
    /// renew a certificate without republishing the TLSA record, provided the
    /// key is reused. [RFC 7671 §5](https://www.rfc-editor.org/rfc/rfc7671#section-5)
    /// recommends this selector for that reason.
    Spki,

    /// An octet value IANA has not assigned (2–254). Unusable; ignore.
    Unassigned(u8),

    /// The private-use value 255. Unusable; ignore.
    PrivateUse,
}

impl TlsaSelector {
    /// Decodes the one-octet wire value. Total.
    #[must_use]
    pub const fn from_octet(octet: u8) -> Self {
        match octet {
            0 => Self::Cert,
            1 => Self::Spki,
            255 => Self::PrivateUse,
            other => Self::Unassigned(other),
        }
    }

    /// Encodes back to the one-octet wire value.
    #[must_use]
    pub const fn to_octet(self) -> u8 {
        match self {
            Self::Cert => 0,
            Self::Spki => 1,
            Self::PrivateUse => 255,
            Self::Unassigned(other) => other,
        }
    }

    /// Whether this selector is one of the two IANA-assigned selectors.
    #[must_use]
    pub const fn is_assigned(self) -> bool {
        matches!(self, Self::Cert | Self::Spki)
    }
}

// ---------------------------------------------------------------------------
// TlsaMatchingType
// ---------------------------------------------------------------------------

/// TLSA matching type — how the selected content is compared.
///
/// Per [RFC 6698 §2.1.3](https://www.rfc-editor.org/rfc/rfc6698#section-2.1.3),
/// mnemonics from [RFC 7218 §2.3](https://www.rfc-editor.org/rfc/rfc7218#section-2.3).
///
/// See [`TlsaUsage`]'s exhaustiveness note; the same reasoning applies here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TlsaMatchingType {
    /// **Full (0)** — exact octet-for-octet match, no digest.
    ///
    /// The association data is the selected content itself. Used mainly with
    /// [`TlsaUsage::DaneTa`] to publish a whole trust-anchor certificate in
    /// DNS, so a client can validate a chain to an anchor it does not hold.
    Full,

    /// **SHA2-256 (1)** — SHA-256 digest of the selected content.
    ///
    /// Association data MUST be exactly 32 octets. RFC 6698 requires support
    /// for this matching type; it is the common choice in deployment.
    Sha256,

    /// **SHA2-512 (2)** — SHA-512 digest of the selected content.
    ///
    /// Association data MUST be exactly 64 octets.
    Sha512,

    /// An octet value IANA has not assigned (3–254). Unusable; ignore.
    Unassigned(u8),

    /// The private-use value 255. Unusable; ignore.
    PrivateUse,
}

impl TlsaMatchingType {
    /// Decodes the one-octet wire value. Total.
    #[must_use]
    pub const fn from_octet(octet: u8) -> Self {
        match octet {
            0 => Self::Full,
            1 => Self::Sha256,
            2 => Self::Sha512,
            255 => Self::PrivateUse,
            other => Self::Unassigned(other),
        }
    }

    /// Encodes back to the one-octet wire value.
    #[must_use]
    pub const fn to_octet(self) -> u8 {
        match self {
            Self::Full => 0,
            Self::Sha256 => 1,
            Self::Sha512 => 2,
            Self::PrivateUse => 255,
            Self::Unassigned(other) => other,
        }
    }

    /// The exact association-data length this matching type requires, or
    /// `None` for [`Full`](Self::Full) (variable) and the unusable variants.
    ///
    /// A digest matching type whose record carries a different length is
    /// unusable per
    /// [RFC 7671 §10](https://www.rfc-editor.org/rfc/rfc7671#section-10);
    /// [`TlsaRecord::is_usable`] applies this.
    #[must_use]
    pub const fn digest_len(self) -> Option<usize> {
        match self {
            Self::Sha256 => Some(SHA256_LEN),
            Self::Sha512 => Some(SHA512_LEN),
            Self::Full | Self::Unassigned(_) | Self::PrivateUse => None,
        }
    }

    /// Whether this matching type is one of the three IANA-assigned types.
    #[must_use]
    pub const fn is_assigned(self) -> bool {
        matches!(self, Self::Full | Self::Sha256 | Self::Sha512)
    }
}

// ---------------------------------------------------------------------------
// TlsaRecord
// ---------------------------------------------------------------------------

/// A single TLSA resource record.
///
/// Construct one with [`from_rdata`](Self::from_rdata) from DNS wire bytes, or
/// with [`new`](Self::new) from already-separated fields.
///
/// # DNSSEC is the caller's responsibility
///
/// A `TlsaRecord` carries no indication of whether it was DNSSEC-validated.
/// Nothing in this crate can tell a securely-obtained record from an attacker's
/// fabrication, and an unvalidated TLSA record is worse than no record at all:
/// it lets whoever controls the DNS answer choose the certificate. Callers
/// obtain records through a [`TlsaResolver`](crate::TlsaResolver), which
/// returns a [`TlsaResponse`](crate::TlsaResponse) pairing the records with the
/// [`DnssecStatus`](crate::DnssecStatus) under which they arrived, and the
/// verify functions require that status to be
/// [`Secure`](crate::DnssecStatus::Secure).
///
/// # Unusable records are ignored, not rejected
///
/// Parsing accepts any RDATA of at least three octets, including records whose
/// usage, selector or matching type this crate does not implement. Per
/// [RFC 7671 §17](https://www.rfc-editor.org/rfc/rfc7671#section-17) such
/// records are *unusable* and must be skipped rather than failing the
/// connection, so that a record set can carry both a usage the client
/// understands and one it does not. [`is_usable`](Self::is_usable) reports
/// which side of that line a record falls on.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TlsaRecord {
    usage: TlsaUsage,
    selector: TlsaSelector,
    matching_type: TlsaMatchingType,
    association_data: Vec<u8>,
}

impl TlsaRecord {
    /// Assembles a record from already-separated fields.
    ///
    /// Performs no validation: the result may be unusable (see
    /// [`is_usable`](Self::is_usable)). This constructor exists for resolvers
    /// whose DNS library hands back the fields pre-split, and for tests.
    #[must_use]
    pub const fn new(
        usage: TlsaUsage,
        selector: TlsaSelector,
        matching_type: TlsaMatchingType,
        association_data: Vec<u8>,
    ) -> Self {
        Self {
            usage,
            selector,
            matching_type,
            association_data,
        }
    }

    /// Parses a record from DNS RDATA wire format.
    ///
    /// The layout, per
    /// [RFC 6698 §2.1](https://www.rfc-editor.org/rfc/rfc6698#section-2.1), is
    /// three one-octet fields followed by variable-length association data:
    ///
    /// ```text
    ///  0        1        2        3 ...
    /// +--------+--------+--------+--------------------------------+
    /// | usage  | select | match  | certificate association data   |
    /// +--------+--------+--------+--------------------------------+
    /// ```
    ///
    /// # Errors
    ///
    /// [`DaneError::RecordTruncated`] if `rdata` is shorter than the
    /// three-octet header. Every other input parses: unrecognized field
    /// values become the `Unassigned` / `PrivateUse` variants and yield a
    /// record that [`is_usable`](Self::is_usable) reports as unusable, because
    /// RFC 7671 requires skipping such records rather than failing.
    pub fn from_rdata(rdata: &[u8]) -> Result<Self, DaneError> {
        if rdata.len() < RDATA_HEADER_LEN {
            return Err(DaneError::RecordTruncated { len: rdata.len() });
        }
        Ok(Self {
            usage: TlsaUsage::from_octet(rdata[0]),
            selector: TlsaSelector::from_octet(rdata[1]),
            matching_type: TlsaMatchingType::from_octet(rdata[2]),
            association_data: rdata[RDATA_HEADER_LEN..].to_vec(),
        })
    }

    /// Serializes back to DNS RDATA wire format.
    ///
    /// Round-trips with [`from_rdata`](Self::from_rdata).
    #[must_use]
    pub fn to_rdata(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RDATA_HEADER_LEN + self.association_data.len());
        out.push(self.usage.to_octet());
        out.push(self.selector.to_octet());
        out.push(self.matching_type.to_octet());
        out.extend_from_slice(&self.association_data);
        out
    }

    /// The certificate usage this record asserts.
    #[must_use]
    pub const fn usage(&self) -> TlsaUsage {
        self.usage
    }

    /// Which part of the certificate this record is about.
    #[must_use]
    pub const fn selector(&self) -> TlsaSelector {
        self.selector
    }

    /// How the selected content is compared.
    #[must_use]
    pub const fn matching_type(&self) -> TlsaMatchingType {
        self.matching_type
    }

    /// The certificate association data: a digest, or the selected content
    /// itself when the matching type is [`TlsaMatchingType::Full`].
    #[must_use]
    pub fn association_data(&self) -> &[u8] {
        &self.association_data
    }

    /// Whether this crate can evaluate this record.
    ///
    /// A record is usable when all three of these hold:
    ///
    /// - usage, selector and matching type are all IANA-assigned values —
    ///   unrecognized ones must be skipped per
    ///   [RFC 7671 §17](https://www.rfc-editor.org/rfc/rfc7671#section-17);
    /// - the association data is non-empty, since no selected content is ever
    ///   zero-length; and
    /// - for a digest matching type, the association data is exactly the
    ///   digest length, per
    ///   [RFC 7671 §10](https://www.rfc-editor.org/rfc/rfc7671#section-10).
    ///
    /// An unusable record is not an error. The verify functions skip them and
    /// only fail if *no* record in the set both was usable and matched.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        if !self.usage.is_assigned()
            || !self.selector.is_assigned()
            || !self.matching_type.is_assigned()
        {
            return false;
        }
        if self.association_data.is_empty() {
            return false;
        }
        match self.matching_type.digest_len() {
            Some(expected) => self.association_data.len() == expected,
            None => true,
        }
    }
}
