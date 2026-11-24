//! Selector extraction and association-data comparison.
//!
//! Given a certificate as the peer presented it and a [`TlsaRecord`], this
//! module answers one question: does the record's certificate association data
//! match this certificate under the record's selector and matching type?
//! ([RFC 6698 §2.1.2–2.1.3](https://www.rfc-editor.org/rfc/rfc6698#section-2.1.2).)
//!
//! # Why this module insists on the bytes as received
//!
//! A TLSA record's association data is, in the common case, a digest that the
//! domain operator computed over their certificate file — effectively
//! `openssl x509 -outform DER | sha256sum`. For matching to work, the client
//! must hash *the same octets*. Not an equivalent certificate; the same
//! octets.
//!
//! That sounds automatic and is not. `x509-cert` 0.3 re-encodes a parsed
//! `Certificate` under the RFC 5280 profile, which normalizes validity times:
//! a date before 2050 is emitted as `UTCTime` even when the issuer wrote
//! `GeneralizedTime`. So for a certificate whose issuer used
//! `GeneralizedTime` for a pre-2050 date, `to_der()` on the parsed value does
//! **not** reproduce the bytes the peer sent. `pkix-path` hit exactly this
//! when verifying signatures and shipped
//! [`pkix_path::tbs_certificate_der`] as the workaround — but that function
//! covers only the `tbsCertificate`, and
//! [`TlsaSelector::Cert`] needs the whole certificate.
//!
//! Had this crate reached for `cert.to_der()`, such a certificate would hash
//! to a value that does not match its own correctly-published TLSA record: a
//! silent interop failure, visible only against the subset of CAs that emit
//! `GeneralizedTime` early — the same subset that produced the PKITS 4.2.4 and
//! 4.2.7 regressions during the `x509-cert` 0.3 migration.
//!
//! Hence [`PresentedCert`], which carries the received octets alongside the
//! parsed certificate, and hence the rule this module follows: for
//! [`TlsaSelector::Cert`], hash the received octets and never a re-encoding.
//!
//! [`pkix_path::tbs_certificate_der`]: https://docs.rs/pkix-path/latest/pkix_path/fn.tbs_certificate_der.html

use alloc::borrow::Cow;
use alloc::vec::Vec;

use der::Encode as _;
use sha2::Digest as _;
use x509_cert::Certificate;

use crate::record::{TlsaMatchingType, TlsaRecord, TlsaSelector};
use crate::DaneError;

// ---------------------------------------------------------------------------
// PresentedCert
// ---------------------------------------------------------------------------

/// A certificate paired with the exact octets it arrived as.
///
/// DANE matching is byte-exact, so it needs the certificate as received rather
/// than as re-encoded from a parsed value — see the
/// [module documentation](self) for the failure this prevents. In a TLS client
/// both halves are already at hand: the handshake delivers DER, and the caller
/// parses it to do anything else with it.
///
/// # Caller obligation
///
/// [`new`](Self::new) trusts that `der` and `parsed` describe the same
/// certificate; it cannot check this without re-encoding, which is the very
/// thing being avoided. Pairing a certificate with another certificate's bytes
/// produces matching results that are simply wrong — not unsafe, but wrong.
/// Construct a `PresentedCert` where the DER is parsed, so the two cannot
/// drift apart:
///
/// ```no_run
/// # use x509_cert::Certificate;
/// # use x509_cert::der::Decode as _;
/// # use pkix_dane::PresentedCert;
/// # fn example(wire_bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
/// let parsed = Certificate::from_der(wire_bytes)?;
/// let presented = PresentedCert::new(wire_bytes, &parsed);
/// # let _ = presented;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Debug)]
pub struct PresentedCert<'a> {
    der: &'a [u8],
    parsed: &'a Certificate,
}

impl<'a> PresentedCert<'a> {
    /// Pairs received certificate octets with their parsed form.
    ///
    /// See the [caller obligation](Self#caller-obligation) on keeping the two
    /// arguments in correspondence.
    #[must_use]
    pub const fn new(der: &'a [u8], parsed: &'a Certificate) -> Self {
        Self { der, parsed }
    }

    /// The certificate as received, octet for octet.
    #[must_use]
    pub const fn der(&self) -> &'a [u8] {
        self.der
    }

    /// The parsed certificate.
    #[must_use]
    pub const fn parsed(&self) -> &'a Certificate {
        self.parsed
    }

    /// Extracts the content named by `selector`.
    ///
    /// [`TlsaSelector::Cert`] borrows the received octets; [`TlsaSelector::Spki`]
    /// encodes the `SubjectPublicKeyInfo`, allocating.
    ///
    /// # Re-encoding caveat for `Spki`
    ///
    /// There is no way to obtain the `SubjectPublicKeyInfo`'s original octet
    /// range from `x509-cert`'s parsed representation, so the `Spki` arm
    /// re-encodes. Unlike the whole-certificate case this is sound for
    /// DER-conformant input: a `SubjectPublicKeyInfo` holds an algorithm
    /// identifier and a `BIT STRING`, with no `Time` field for the
    /// `UTCTime`/`GeneralizedTime` normalization to act on. A certificate
    /// whose SPKI used a non-canonical encoding would still be normalized on
    /// re-encode and could mismatch its TLSA record — but such a certificate
    /// is already malformed, and `x509-cert`'s parser is strict about DER.
    ///
    /// # Errors
    ///
    /// [`DaneError::SpkiEncodingFailed`] if the `SubjectPublicKeyInfo` cannot
    /// be re-encoded. [`DaneError::SelectorUnsupported`] if `selector` is not
    /// IANA-assigned; callers reaching this through [`matches()`] never see it,
    /// since unusable records are filtered first.
    pub fn selected_content(&self, selector: TlsaSelector) -> Result<Cow<'a, [u8]>, DaneError> {
        match selector {
            TlsaSelector::Cert => Ok(Cow::Borrowed(self.der)),
            TlsaSelector::Spki => {
                let spki = self
                    .parsed
                    .tbs_certificate()
                    .subject_public_key_info()
                    .to_der()
                    .map_err(|_| DaneError::SpkiEncodingFailed)?;
                Ok(Cow::Owned(spki))
            }
            TlsaSelector::Unassigned(octet) => Err(DaneError::SelectorUnsupported { octet }),
            TlsaSelector::PrivateUse => Err(DaneError::SelectorUnsupported { octet: 255 }),
        }
    }
}

// ---------------------------------------------------------------------------
// matches
// ---------------------------------------------------------------------------

/// Whether `record`'s association data matches `cert`.
///
/// Applies `record`'s selector to pick the content, then compares it to the
/// association data under `record`'s matching type: exact octets for
/// [`TlsaMatchingType::Full`], or a digest for
/// [`Sha256`](TlsaMatchingType::Sha256) / [`Sha512`](TlsaMatchingType::Sha512).
///
/// Returns `Ok(false)` — not an error — for a record that
/// [`TlsaRecord::is_usable`] rejects. An unusable record is a record this
/// client cannot evaluate, which RFC 7671 requires be skipped rather than
/// treated as a failure; "did not match" is how a skip reaches the caller.
///
/// # Non-constant-time comparison
///
/// The comparison is an ordinary `==` on byte slices and may short-circuit.
/// That is deliberate: both operands are public. The association data came
/// from a DNS record anyone can query, and the certificate came from a TLS
/// handshake anyone can perform. There is no secret for a timing side channel
/// to leak.
///
/// # Errors
///
/// [`DaneError::SpkiEncodingFailed`] if the record selects the
/// `SubjectPublicKeyInfo` and it cannot be encoded.
pub fn matches(record: &TlsaRecord, cert: &PresentedCert<'_>) -> Result<bool, DaneError> {
    if !record.is_usable() {
        return Ok(false);
    }

    let content = cert.selected_content(record.selector())?;
    let expected = record.association_data();

    let matched = match record.matching_type() {
        TlsaMatchingType::Full => content.as_ref() == expected,
        TlsaMatchingType::Sha256 => {
            let digest: [u8; crate::record::SHA256_LEN] =
                sha2::Sha256::digest(content.as_ref()).into();
            digest.as_slice() == expected
        }
        TlsaMatchingType::Sha512 => {
            let digest: [u8; crate::record::SHA512_LEN] =
                sha2::Sha512::digest(content.as_ref()).into();
            digest.as_slice() == expected
        }
        // Unreachable in practice: `is_usable` above rejects every
        // unassigned and private-use matching type. Handled as "no match"
        // rather than `unreachable!` so that a future change to `is_usable`
        // cannot turn a skippable record into a panic.
        TlsaMatchingType::Unassigned(_) | TlsaMatchingType::PrivateUse => false,
    };

    Ok(matched)
}

/// The subset of `records` that is usable and matches `cert`.
///
/// Convenience over [`matches()`] for callers that want to know *which* records
/// matched — for logging which TLSA record authorized a connection, or for
/// [`TlsaUsage::DaneTa`](crate::TlsaUsage::DaneTa) handling that needs the
/// matched record's association data.
///
/// # Errors
///
/// Propagates [`DaneError::SpkiEncodingFailed`] from [`matches()`]. A selector
/// that cannot be encoded is a property of the certificate, not of one record,
/// so it fails the whole call rather than being counted as a non-match.
pub fn matching_records<'r>(
    records: &'r [TlsaRecord],
    cert: &PresentedCert<'_>,
) -> Result<Vec<&'r TlsaRecord>, DaneError> {
    let mut out = Vec::new();
    for record in records {
        if matches(record, cert)? {
            out.push(record);
        }
    }
    Ok(out)
}

/// Whether `record` matches a bare `SubjectPublicKeyInfo`.
///
/// The companion to [`matches()`] for callers who hold an anchor's public key
/// but not its certificate. Only [`TlsaSelector::Spki`] records can be
/// evaluated this way; a [`TlsaSelector::Cert`] record returns `Ok(false)`,
/// since the certificate it describes is not available to hash.
///
/// # Why this exists
///
/// A trust store commonly keeps subject names and public keys rather than
/// whole certificates — `pkix_path::TrustAnchor` is exactly that shape, with a
/// `subject` and a `subject_public_key_info` and no certificate. A caller
/// evaluating [`verify_pkix_ta`](crate::verify_pkix_ta) against such an anchor
/// therefore cannot build a [`PresentedCert`] for it, and without this
/// function usage 0 would be unusable against the workspace's own trust-anchor
/// type.
///
/// Selector-0 records remain genuinely unmatchable against such an anchor: the
/// original certificate octets no longer exist, so the digest the domain
/// published cannot be reproduced. That is a property of the trust store, not
/// something this crate can work around — which is why this function reports
/// `Ok(false)` for them rather than pretending to an answer.
///
/// # `spki_der` must be the stored encoding
///
/// The same byte-exactness rule as the [module documentation](self) applies.
/// Pass the `SubjectPublicKeyInfo` as it was stored or received; a
/// `SubjectPublicKeyInfo` carries no `Time` field, so the normalization that
/// breaks whole-certificate re-encoding does not apply here, and re-encoding a
/// parsed anchor key is sound for DER-conformant input.
///
/// # Errors
///
/// Never returns `Err` today — the signature is `Result` so that a future
/// matching type requiring fallible work stays a non-breaking change, matching
/// [`matches()`]'s shape. Callers may treat `Err` as a non-match.
pub fn matches_spki(record: &TlsaRecord, spki_der: &[u8]) -> Result<bool, DaneError> {
    if !record.is_usable() || record.selector() != TlsaSelector::Spki {
        return Ok(false);
    }

    let expected = record.association_data();
    let matched = match record.matching_type() {
        TlsaMatchingType::Full => spki_der == expected,
        TlsaMatchingType::Sha256 => {
            let digest: [u8; crate::record::SHA256_LEN] = sha2::Sha256::digest(spki_der).into();
            digest.as_slice() == expected
        }
        TlsaMatchingType::Sha512 => {
            let digest: [u8; crate::record::SHA512_LEN] = sha2::Sha512::digest(spki_der).into();
            digest.as_slice() == expected
        }
        // Unreachable: `is_usable` rejects these. Treated as "no match"
        // rather than `unreachable!` for the same reason as in `matches()`.
        TlsaMatchingType::Unassigned(_) | TlsaMatchingType::PrivateUse => false,
    };

    Ok(matched)
}
