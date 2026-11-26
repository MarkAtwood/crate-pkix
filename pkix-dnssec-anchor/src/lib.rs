#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! # pkix-dnssec-anchor
//!
//! The IANA DNS root zone trust anchors, as data.
//!
//! This crate is nothing but IANA's published root key material and the
//! machinery to regenerate it. It performs no validation, makes no network
//! requests, reads no files, and has no dependencies. It exists so that a
//! DNSSEC validator — [`pkix-dane-resolver`] in this workspace — can be handed
//! a trust anchor without having an opinion of its own about what to trust.
//!
//! ## Why this is a separate crate
//!
//! A DNSSEC root key is a root of trust, the same kind of object as an X.509
//! trust anchor. This workspace does not bake those in: `pkix-path` ships no
//! root program's certificate list, `pkix-truststore` takes DER bytes without
//! asking where they came from, and OS trust stores live in the separate
//! `pkix-truststore-system` crate precisely so platform-specific acquisition
//! stays out of the core.
//!
//! Treating the DNSSEC root the same way buys three things:
//!
//! - **Auditability.** The anchors are their own artifact with their own
//!   provenance, reviewable without reading a resolver's source.
//! - **Independent updates.** When IANA rolls the key-signing key, this crate
//!   is released and consumers `cargo update`. They do not wait for a resolver
//!   release, and the resolver does not need one.
//! - **No ambient dependencies.** Nothing here touches the filesystem or the
//!   operating system, so a consumer's trust configuration is whatever they
//!   passed in and nothing else.
//!
//! The shape follows [`webpki-roots`], which does the same job for the Web
//! PKI.
//!
//! ## Provenance
//!
//! [`generated`]'s contents come from IANA's `root-anchors.xml`, converted by
//! `gen.sh`. That script verifies IANA's detached PKCS#7 signature over the
//! XML, against the ICANN certificate the signature chains to, **before**
//! generating anything, and fails closed if it does not verify. The XML, its
//! signature and the ICANN certificate are all committed under `iana/`, so a
//! release's provenance can be re-checked offline:
//!
//! ```text
//! openssl smime -verify -inform DER -in iana/root-anchors.p7s \
//!     -content iana/root-anchors.xml -CAfile iana/icannbundle.pem
//! ```
//!
//! Reviewing an update to this crate means re-running `./gen.sh` and diffing
//! the result, not trusting whoever edited the constants.
//!
//! ## Which anchors to use
//!
//! [`CURRENT`] holds the anchors that were unexpired when the file was
//! generated, and is what a validator wants. [`ALL`] additionally holds
//! withdrawn anchors, for auditing and for verifying historical material.
//!
//! IANA commonly lists more than one valid anchor at a time — a new
//! key-signing key is published well before the old one is withdrawn, so both
//! are valid during the overlap. A validator should accept a signature
//! chaining to **any** anchor in [`CURRENT`], not just the newest. Honouring
//! only one is an outage waiting for the roll to complete.
//!
//! ## Staleness is the one real hazard
//!
//! These are compiled-in constants, so a release of this crate is a snapshot,
//! and it goes stale on IANA's schedule rather than this workspace's.
//!
//! **The failure is quiet.** If IANA rolls the key-signing key and a consumer
//! does not update, DNSSEC validation stops succeeding — and under an
//! opportunistic DANE policy that is reported as "DNSSEC could not be
//! established" rather than as anything being wrong. A deployment can lose
//! DANE without noticing.
//!
//! Three things guard against that:
//!
//! 1. **A scheduled CI check.** `.github/workflows/iana-anchors.yml` runs
//!    `gen.sh --check` monthly: it fetches IANA's anchors, verifies their
//!    signature, and fails with a diff if the committed set no longer
//!    matches. This is the only guard that does not depend on a human
//!    remembering, which is why it exists.
//! 2. **Auditable source.** Every anchor in [`generated`] carries its IANA
//!    `KeyDigest` id, key tag and validity dates, so staleness is visible by
//!    reading the file rather than by comparison with an external source.
//! 3. **A caller-side escape hatch.** A consumer needing a new key before a
//!    release builds one with [`RootAnchor::new`] and passes it directly.
//!    Nothing here privileges the shipped anchors over a caller-supplied one.
//!
//! A consumer that must be exact about expiry should filter [`ALL`] through
//! [`RootAnchor::is_valid_at`] against the current time rather than trusting
//! [`CURRENT`], which is a snapshot and does not know about a withdrawal that
//! happened after generation.
//!
//! On the maintainer's side: a roll means `./gen.sh`,
//! `cargo test -p pkix-dnssec-anchor`, and a release of **this crate alone**.
//!
//! ## Supplying your own anchor
//!
//! A private DNSSEC root — a split-horizon enterprise zone, or a test root —
//! is built with [`RootAnchor::new`] and the `with_*` methods. IANA's keys
//! are shipped because they are the ones most people want.
//!
//! [`pkix-dane-resolver`]: https://docs.rs/pkix-dane-resolver
//! [`webpki-roots`]: https://docs.rs/webpki-roots

/// The anchors themselves, generated from IANA's signed `root-anchors.xml`.
///
/// Every item here is written by `gen.sh`; see the crate documentation for the
/// provenance chain. Prefer the [`CURRENT`] and [`ALL`] re-exports at the
/// crate root over naming the per-anchor constants, whose identifiers change
/// as IANA publishes and withdraws keys.
pub mod generated;

pub use generated::{ALL, CURRENT};

/// One DNSSEC trust anchor for the root zone.
///
/// Carries both forms IANA publishes: the delegation-signer digest
/// ([`digest`](Self::digest)) and the public key itself
/// ([`public_key`](Self::public_key)). A validator can bootstrap from either —
/// the digest requires fetching the root `DNSKEY` and checking it matches,
/// while the key can be used directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct RootAnchor {
    /// IANA's identifier for this key digest, such as `"Kmyv6jo"`.
    ///
    /// Stable across regenerations, which makes it the right thing to quote
    /// in a log line or a bug report. Empty for a caller-built anchor that was
    /// not given one.
    pub id: &'static str,

    /// DNSSEC key tag ([RFC 4034 §5.1](https://www.rfc-editor.org/rfc/rfc4034#section-5.1)).
    ///
    /// Not unique by construction: key tags are a 16-bit checksum and may
    /// collide. Use it to narrow candidates, never as the sole identifier.
    pub key_tag: u16,

    /// DNSSEC algorithm number ([RFC 4034 Appendix A.1](https://www.rfc-editor.org/rfc/rfc4034#appendix-A.1)).
    ///
    /// `8` is RSA/SHA-256, which every root KSK has used to date.
    pub algorithm: u8,

    /// Digest algorithm of [`digest`](Self::digest)
    /// ([RFC 4034 §5.1.4](https://www.rfc-editor.org/rfc/rfc4034#section-5.1.4)).
    ///
    /// `2` is SHA-256.
    pub digest_type: u8,

    /// The delegation-signer digest over the `DNSKEY`.
    ///
    /// This is what IANA treats as authoritative, and what a validator
    /// compares a fetched root `DNSKEY` against.
    pub digest: &'static [u8],

    /// The public key, as it appears in `DNSKEY` RDATA.
    ///
    /// Decoded from the base64 in IANA's XML. Empty when IANA published a
    /// digest without a key, which it did for its older entries.
    pub public_key: &'static [u8],

    /// `DNSKEY` flags ([RFC 4034 §2.1.1](https://www.rfc-editor.org/rfc/rfc4034#section-2.1.1)).
    ///
    /// `257` means the Zone Key and Secure Entry Point bits are set: a
    /// key-signing key.
    ///
    /// **`0` means IANA published no `Flags` element**, not that the flags are
    /// genuinely zero — zero is not a meaningful `DNSKEY` flag value. IANA's
    /// older entries are digest-only: the withdrawn 2010 anchor carries a key
    /// tag and a digest with no key material and no flags. Treat `0` as
    /// absent, and do not read
    /// [`is_key_signing_key`](Self::is_key_signing_key) as evidence about such
    /// an anchor either way.
    pub flags: u16,

    /// When IANA published this anchor, as an ISO 8601 timestamp, or `None`
    /// for an anchor with no lower validity bound.
    ///
    /// Every anchor IANA publishes carries one. `None` arises for an anchor a
    /// caller built with [`new`](Self::new) — a private DNSSEC root has no
    /// IANA publication date, and defaulting it to a sentinel string would
    /// make [`is_valid_at`](Self::is_valid_at) fail closed on an anchor the
    /// caller deliberately supplied.
    ///
    /// Kept as the string IANA wrote rather than parsed into a number, because
    /// this crate has no dependencies and no business shipping a date parser.
    pub valid_from: Option<&'static str>,

    /// When IANA withdrew this anchor, or `None` if it is still listed.
    pub valid_until: Option<&'static str>,
}

impl RootAnchor {
    /// Builds an anchor from the four fields a delegation signer needs.
    ///
    /// For supplying a trust anchor this crate does not ship: a private
    /// DNSSEC root for a split-horizon deployment, or a test root. The IANA
    /// anchors are available as [`CURRENT`] and [`ALL`] and do not need this.
    ///
    /// The result has no validity bounds, so
    /// [`is_valid_at`](Self::is_valid_at) accepts it at any time; add bounds
    /// with [`with_validity`](Self::with_validity) if the anchor has them.
    /// `flags` defaults to `257`, a key-signing key, and `id` to the empty
    /// string. Attach key material with
    /// [`with_public_key`](Self::with_public_key) — a validator that cannot
    /// fetch the zone's `DNSKEY` needs it.
    ///
    /// # Examples
    ///
    /// ```
    /// use pkix_dnssec_anchor::RootAnchor;
    ///
    /// let anchor = RootAnchor::new(12345, 8, 2, &[0xab; 32])
    ///     .with_id("corp-root")
    ///     .with_public_key(&[0xcd; 260]);
    ///
    /// assert_eq!(anchor.key_tag, 12345);
    /// assert!(anchor.is_key_signing_key());
    /// assert!(!anchor.is_withdrawn());
    /// ```
    #[must_use]
    pub const fn new(key_tag: u16, algorithm: u8, digest_type: u8, digest: &'static [u8]) -> Self {
        Self {
            id: "",
            key_tag,
            algorithm,
            digest_type,
            digest,
            public_key: &[],
            flags: 257,
            valid_from: None,
            valid_until: None,
        }
    }

    /// Attaches `DNSKEY` RDATA public-key bytes.
    #[must_use]
    pub const fn with_public_key(mut self, public_key: &'static [u8]) -> Self {
        self.public_key = public_key;
        self
    }

    /// Sets the `DNSKEY` flags, replacing the `257` default.
    #[must_use]
    pub const fn with_flags(mut self, flags: u16) -> Self {
        self.flags = flags;
        self
    }

    /// Sets an identifier for logs and diagnostics.
    #[must_use]
    pub const fn with_id(mut self, id: &'static str) -> Self {
        self.id = id;
        self
    }

    /// Sets the validity window, as ISO 8601 timestamps.
    ///
    /// See [`is_valid_at`](Self::is_valid_at) for the accepted forms and for
    /// what happens to one that cannot be parsed.
    #[must_use]
    pub const fn with_validity(
        mut self,
        valid_from: Option<&'static str>,
        valid_until: Option<&'static str>,
    ) -> Self {
        self.valid_from = valid_from;
        self.valid_until = valid_until;
        self
    }

    /// Whether this anchor had been withdrawn when the crate was generated.
    ///
    /// A withdrawn anchor must not be used to validate current DNS responses.
    #[must_use]
    pub const fn is_withdrawn(&self) -> bool {
        self.valid_until.is_some()
    }

    /// Whether this anchor is a key-signing key.
    ///
    /// True when the Secure Entry Point bit (`0x0001`) is set in
    /// [`flags`](Self::flags). The check exists so a caller filtering a mixed
    /// set does not have to know the bit layout.
    ///
    /// Returns `false` for a digest-only anchor whose [`flags`](Self::flags)
    /// are `0` because IANA published none — see that field. Every root KSK
    /// IANA has published *is* a key-signing key, so a `false` here means
    /// "not stated", not "not a KSK".
    #[must_use]
    pub const fn is_key_signing_key(&self) -> bool {
        self.flags & 0x0001 != 0
    }

    /// Whether this anchor's validity window contains `unix_secs`.
    ///
    /// Use this, rather than [`CURRENT`], when exactness matters: `CURRENT` is
    /// a snapshot taken when the crate was generated and does not know about a
    /// withdrawal that happened since.
    ///
    /// A bound of `None` is no bound: an anchor built with [`new`](Self::new)
    /// and given no validity window is accepted at any time, since a
    /// caller-supplied private root has no IANA dates.
    ///
    /// Returns `false` if a timestamp that is present cannot be parsed, which
    /// is the fail-closed direction — an anchor whose stated window cannot be
    /// established should not be trusted. Accepted forms are
    /// `2024-07-18T00:00:00Z`, the same with a `+00:00` or `-00:00` offset, or
    /// with the offset omitted. A non-UTC offset is refused rather than
    /// converted.
    #[must_use]
    pub fn is_valid_at(&self, unix_secs: i64) -> bool {
        if let Some(from) = self.valid_from {
            match parse_iso8601_secs(from) {
                Some(from) => {
                    if unix_secs < from {
                        return false;
                    }
                }
                None => return false,
            }
        }
        match self.valid_until {
            None => true,
            Some(until) => match parse_iso8601_secs(until) {
                Some(until) => unix_secs < until,
                None => false,
            },
        }
    }
}

/// Parses the restricted ISO 8601 form IANA uses into a Unix timestamp.
///
/// IANA writes `2024-07-18T00:00:00+00:00`. Only that shape is accepted:
/// a fixed-width date and time, with either a `+00:00` offset or a trailing
/// `Z`. A non-UTC offset is refused rather than converted, because every
/// timestamp IANA has published is UTC and silently handling a form that has
/// never occurred would be untested code on a trust path.
///
/// Returns `None` on anything unexpected. The caller treats that as "not
/// valid", so a parse failure fails closed.
fn parse_iso8601_secs(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if bytes.len() < 19 {
        return None;
    }
    // YYYY-MM-DDTHH:MM:SS
    if bytes[4] != b'-' || bytes[7] != b'-' || bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    if bytes[10] != b'T' && bytes[10] != b' ' {
        return None;
    }
    let suffix = &text[19..];
    if !(suffix.is_empty() || suffix == "Z" || suffix == "+00:00" || suffix == "-00:00") {
        return None;
    }

    let year = parse_num(&text[0..4])?;
    let month = parse_num(&text[5..7])?;
    let day = parse_num(&text[8..10])?;
    let hour = parse_num(&text[11..13])?;
    let minute = parse_num(&text[14..16])?;
    let second = parse_num(&text[17..19])?;

    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    Some(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// Parses a fixed-width run of ASCII digits.
fn parse_num(text: &str) -> Option<i64> {
    let mut value: i64 = 0;
    for byte in text.bytes() {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value * 10 + i64::from(byte - b'0');
    }
    Some(value)
}

/// Days from the Unix epoch to `y-m-d` in the proleptic Gregorian calendar.
///
/// Howard Hinnant's `days_from_civil`, which is branch-free over the leap-year
/// rules and exact for any year this will ever see. Hand-rolled because this
/// crate has no dependencies by design, and pulling in a date library to
/// compare two timestamps would undercut the point of shipping the anchors as
/// inert data.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

// ---------------------------------------------------------------------------
// Invariant assertions
// ---------------------------------------------------------------------------

const _: fn() = || {
    fn _assert_send_sync<T: Send + Sync>() {}
    _assert_send_sync::<RootAnchor>();

    fn _assert_cache_friendly<T: Clone + core::fmt::Debug + PartialEq + Eq>() {}
    _assert_cache_friendly::<RootAnchor>();
};
