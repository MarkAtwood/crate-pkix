//! Per-usage verification entry points.
//!
//! One function per TLSA certificate usage. Each takes the certificate as the
//! peer presented it plus the resolver's [`TlsaResponse`], checks the DNSSEC
//! status, narrows the record set to its own usage, and reports which record
//! authorized the certificate.
//!
//! The end-entity usages ([`verify_dane_ee`], [`verify_pkix_ee`]) are pure
//! certificate matching. The trust-anchor usages ([`verify_dane_ta`],
//! [`verify_pkix_ta`]) match against a *chain* rather than one certificate,
//! because the record names an issuer somewhere above the leaf — and they
//! each leave a distinct obligation with the caller, documented on the
//! function.

use alloc::vec::Vec;

use pkix_path::TrustAnchor;
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

use crate::record::{TlsaMatchingType, TlsaRecord, TlsaSelector};
use crate::selector::{matches, PresentedCert};
use crate::{DaneError, TlsaResponse, TlsaUsage};

/// Verifies a certificate against the DANE-EE (usage 3) records in `response`.
///
/// DANE-EE is the strongest and simplest usage: the TLSA record names the
/// end-entity certificate, and DNSSEC vouches for the record. Chain building
/// and PKIX path validation play no part.
///
/// Returns the record that matched, so a caller can log which TLSA record
/// authorized the connection.
///
/// # What this deliberately does not check
///
/// Per [RFC 7671 §5.1](https://www.rfc-editor.org/rfc/rfc7671#section-5.1),
/// a DANE-EE match stands on its own. This function therefore does **not**
/// check:
///
/// - **the certificate's validity dates** — the TLSA record is the binding,
///   and its DNS TTL is the operator's expiry mechanism;
/// - **the subject name or SAN** — the owner name of the TLSA record already
///   ties the record to the service, so the certificate need not repeat it;
/// - **any chain, issuer or trust anchor** — a self-signed certificate is
///   entirely legitimate under this usage.
///
/// None of those omissions is a gap to be filled by the caller. Adding an
/// expiry or name check on top of a DANE-EE match would reject certificates
/// RFC 7671 requires be accepted. Callers wanting PKIX's guarantees as well
/// should use [`verify_pkix_ee`], which is the usage that means precisely
/// that.
///
/// # Errors
///
/// - [`DaneError::DnssecNotSecure`] if `response` is not
///   [`DnssecStatus::Secure`](crate::DnssecStatus::Secure). Checked first:
///   unvalidated records cannot authenticate anything, so matching against
///   them would be worse than useless.
/// - [`DaneError::NoRecordsForUsage`] if no record carries usage 3.
/// - [`DaneError::NoUsableRecords`] if usage-3 records exist but none is
///   evaluable (see [`TlsaRecord::is_usable`]). RFC 7671 §17 treats this as
///   equivalent to no TLSA record being published, so the caller's policy —
///   not this function — decides whether to fall back to PKIX.
/// - [`DaneError::NoMatch`] if usable records were compared and none matched.
///   This is the genuine authentication failure: the domain said which
///   certificate it uses, and this is not it.
/// - [`DaneError::SpkiEncodingFailed`] if a selector-1 record was reached and
///   the certificate's `SubjectPublicKeyInfo` could not be encoded.
pub fn verify_dane_ee<'r>(
    cert: &PresentedCert<'_>,
    response: &'r TlsaResponse,
) -> Result<&'r TlsaRecord, DaneError> {
    verify_end_entity(TlsaUsage::DaneEe, cert, response)
}

/// Verifies a certificate against the PKIX-EE (usage 1) records in `response`.
///
/// PKIX-EE names the end-entity certificate like
/// [`verify_dane_ee`], but adds rather than replaces: the certificate must
/// match a TLSA record **and** the chain must pass ordinary PKIX path
/// validation against the caller's own trust store. The usage can only narrow
/// what PKIX would accept; it cannot make an invalid chain valid.
///
/// Returns the record that matched.
///
/// # PKIX validation is the caller's half
///
/// This function performs only the TLSA match. It has no chain, no trust
/// anchors and no clock, so it cannot and does not validate a path. A caller
/// using usage 1 **must** also run path validation — `pkix-chain`'s
/// `verify_tls_server` or equivalent — and require both to succeed. Treating a
/// successful return here as sufficient would silently downgrade usage 1 to
/// usage 3, accepting expired certificates and untrusted issuers that the
/// domain's chosen usage says to reject.
///
/// Unlike [`verify_dane_ee`], the certificate's validity dates and names
/// *are* checked — by the path validation the caller runs, where RFC 5280
/// puts them.
///
/// # Errors
///
/// Identical to [`verify_dane_ee`], with `usage` reported as
/// [`TlsaUsage::PkixEe`]. See that function's error list.
pub fn verify_pkix_ee<'r>(
    cert: &PresentedCert<'_>,
    response: &'r TlsaResponse,
) -> Result<&'r TlsaRecord, DaneError> {
    verify_end_entity(TlsaUsage::PkixEe, cert, response)
}

/// Shared body of the two end-entity usages.
///
/// They differ only in which usage octet they select and in what the caller
/// must do alongside the match; the matching itself is identical, so it is
/// written once.
fn verify_end_entity<'r>(
    usage: TlsaUsage,
    cert: &PresentedCert<'_>,
    response: &'r TlsaResponse,
) -> Result<&'r TlsaRecord, DaneError> {
    let usable = usable_records_for_usage(usage, response)?;

    for record in &usable {
        if matches(record, cert)? {
            return Ok(record);
        }
    }

    Err(DaneError::NoMatch {
        usage,
        records_compared: usable.len(),
    })
}

// ---------------------------------------------------------------------------
// Trust-anchor usages
// ---------------------------------------------------------------------------

/// Where the trust anchor that satisfied a DANE-TA record came from.
///
/// The distinction is operationally meaningful rather than decorative. An
/// anchor taken from the peer's own chain is one the peer chose to send and a
/// DNSSEC-signed record then confirmed. An anchor carried inside the TLSA
/// record never passed through the peer at all: DNS is its sole source, so
/// the connection can succeed against a server that sends an incomplete
/// chain. Operators debugging a DANE deployment need to know which happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TrustAnchorSource {
    /// Matched a certificate the peer presented, at this index into the chain.
    ///
    /// Index 0 is the leaf. A DANE-TA record matching the leaf is legitimate:
    /// a server presenting a single self-signed certificate that the record
    /// names is its own anchor.
    PresentedChain {
        /// Position in the chain passed to [`verify_dane_ta`].
        chain_index: usize,
    },

    /// The anchor certificate was carried in the TLSA record itself.
    ///
    /// Only possible for a record with selector [`TlsaSelector::Cert`] and
    /// matching type [`TlsaMatchingType::Full`], whose association data *is*
    /// the DER certificate.
    TlsaRecord,
}

/// A trust anchor established by a DANE-TA (usage 2) record.
///
/// Returned by [`verify_dane_ta`]. The caller feeds [`anchor`](Self::anchor)
/// to path validation as the single permitted anchor; see
/// [`verify_dane_ta`] for why substituting the caller's own trust store
/// defeats the usage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaneTrustAnchor<'r> {
    anchor: TrustAnchor,
    record: &'r TlsaRecord,
    source: TrustAnchorSource,
}

impl<'r> DaneTrustAnchor<'r> {
    /// The trust anchor the chain must validate to.
    #[must_use]
    pub const fn anchor(&self) -> &TrustAnchor {
        &self.anchor
    }

    /// Consumes this value and returns the anchor, for passing to path
    /// validation by value.
    #[must_use]
    pub fn into_anchor(self) -> TrustAnchor {
        self.anchor
    }

    /// The TLSA record that established the anchor.
    #[must_use]
    pub const fn record(&self) -> &'r TlsaRecord {
        self.record
    }

    /// Where the anchor certificate came from.
    #[must_use]
    pub const fn source(&self) -> TrustAnchorSource {
        self.source
    }
}

/// Establishes a trust anchor from the DANE-TA (usage 2) records in `response`.
///
/// DANE-TA is the usage that lets a domain name an issuer the client has never
/// heard of. The record identifies a trust anchor; DNSSEC vouches for the
/// record; the peer's chain must then validate up to that anchor. Unlike
/// [`verify_dane_ee`], ordinary chain validation still happens — signatures,
/// validity periods, basic constraints and the identity check all apply. What
/// DANE-TA replaces is only the *source* of the anchor.
///
/// The anchor is looked for in two places, in this order:
///
/// 1. **The peer's presented chain.** Each certificate in `chain` is tested
///    against each usable usage-2 record. This is the ordinary case, and it is
///    tried first because a chain the peer sent is the chain the peer intends
///    to be validated.
/// 2. **The record itself.** A record with selector [`TlsaSelector::Cert`] and
///    matching type [`TlsaMatchingType::Full`] carries the anchor certificate
///    as its association data, so the anchor can be established even when the
///    server sends an incomplete chain. [`TrustAnchorSource`] reports which
///    of the two applied.
///
/// # The returned anchor replaces your trust store, it does not join it
///
/// Validating the chain against your usual anchors *plus* this one does not
/// implement DANE-TA — it implements "DANE-TA or any CA", which is weaker than
/// either. The domain's record says which issuer it uses; honouring it means
/// validating against that anchor **alone**. A caller that merges the returned
/// anchor into a general trust store has built something that accepts every
/// publicly-trusted certificate for the name, which is exactly what the
/// domain used DANE to stop.
///
/// # Name constraints are enforced, not ignored
///
/// The anchor is built through `TrustAnchor::try_from` rather than
/// `TrustAnchor::from_cert`, so a `NameConstraints` extension that does not
/// parse fails the call instead of silently yielding an anchor with no
/// constraints. RFC 5280 §4.2 requires rejecting an unparsable critical
/// extension, and an anchor's name constraints are the one thing limiting what
/// that anchor may vouch for — dropping them quietly would widen the anchor's
/// authority at exactly the moment its certificate looks malformed.
///
/// # Errors
///
/// - [`DaneError::DnssecNotSecure`] if `response` is not
///   [`DnssecStatus::Secure`](crate::DnssecStatus::Secure). Checked first.
/// - [`DaneError::NoRecordsForUsage`] if no record carries usage 2.
/// - [`DaneError::NoUsableRecords`] if usage-2 records exist but none is
///   evaluable.
/// - [`DaneError::NoMatch`] if usable usage-2 records were compared against
///   every certificate in `chain` and none matched, and no record carried a
///   usable embedded anchor certificate.
/// - [`DaneError::MalformedAnchorCertificate`] if a `Cert`/`Full` record's
///   association data does not parse as a DER certificate. The record claimed
///   to carry an anchor and does not, which is a broken record rather than a
///   non-match.
/// - [`DaneError::AnchorNameConstraintsMalformed`] if the anchor certificate's
///   `NameConstraints` extension cannot be parsed.
/// - [`DaneError::SpkiEncodingFailed`] if a selector-1 record was compared
///   against a certificate whose `SubjectPublicKeyInfo` could not be encoded.
pub fn verify_dane_ta<'r>(
    chain: &[PresentedCert<'_>],
    response: &'r TlsaResponse,
) -> Result<DaneTrustAnchor<'r>, DaneError> {
    let usable = usable_records_for_usage(TlsaUsage::DaneTa, response)?;

    // 1. An anchor the peer actually sent.
    for record in &usable {
        for (chain_index, cert) in chain.iter().enumerate() {
            if matches(record, cert)? {
                return Ok(DaneTrustAnchor {
                    anchor: anchor_from_cert(cert.parsed().clone())?,
                    record,
                    source: TrustAnchorSource::PresentedChain { chain_index },
                });
            }
        }
    }

    // 2. An anchor published in DNS, usable even if the peer sent nothing
    //    that chains to it.
    for record in &usable {
        if record.selector() == TlsaSelector::Cert
            && record.matching_type() == TlsaMatchingType::Full
        {
            let cert = Certificate::from_der(record.association_data())
                .map_err(|_| DaneError::MalformedAnchorCertificate)?;
            return Ok(DaneTrustAnchor {
                anchor: anchor_from_cert(cert)?,
                record,
                source: TrustAnchorSource::TlsaRecord,
            });
        }
    }

    Err(DaneError::NoMatch {
        usage: TlsaUsage::DaneTa,
        records_compared: usable.len(),
    })
}

/// Verifies a chain against the PKIX-TA (usage 0) records in `response`.
///
/// PKIX-TA constrains which CA may have issued the peer's certificate: some
/// certificate in the validated chain must match a usage-0 record, *and* the
/// chain must independently pass ordinary PKIX path validation against the
/// caller's own trust store. Like [`verify_pkix_ee`] it can only narrow what
/// PKIX accepts; it never adds an anchor.
///
/// Returns the record that matched.
///
/// # PKIX validation is the caller's half
///
/// This function matches records against certificates and nothing more. It has
/// no trust anchors and no clock, so it does not validate a path. A caller
/// using usage 0 **must** also run path validation and require both to
/// succeed; treating a successful return here as sufficient would downgrade
/// usage 0 to usage 2, accepting an issuer that the client's own trust store
/// rejects.
///
/// # Which certificates to pass
///
/// Pass the chain that validated, and include the trust anchor's certificate
/// if the record might name the anchor itself — which, for a usage whose point
/// is to constrain the CA, is the common case. `pkix-path`'s `ValidatedPath`
/// cannot supply these: it carries `anchor_index`, `depth` and leaf metadata,
/// not the certificates, and its `anchor_index` points into the caller's own
/// anchors slice. The certificates stay with the caller, so the caller is who
/// must hand them over.
///
/// A trust store that keeps only subject names and public keys rather than
/// whole certificates — `pkix_path::TrustAnchor` is that shape — cannot be
/// passed here at all, and cannot satisfy a selector-0 record in any case,
/// since the anchor's original DER no longer exists to be hashed. Match
/// selector-1 records against such an anchor with
/// [`matches_spki`](crate::matches_spki), which exists for exactly this
/// composition.
///
/// # Errors
///
/// Identical to [`verify_dane_ee`]'s, with `usage` reported as
/// [`TlsaUsage::PkixTa`]: [`DaneError::DnssecNotSecure`],
/// [`DaneError::NoRecordsForUsage`], [`DaneError::NoUsableRecords`],
/// [`DaneError::NoMatch`] and [`DaneError::SpkiEncodingFailed`].
pub fn verify_pkix_ta<'r>(
    chain: &[PresentedCert<'_>],
    response: &'r TlsaResponse,
) -> Result<&'r TlsaRecord, DaneError> {
    let usable = usable_records_for_usage(TlsaUsage::PkixTa, response)?;

    for record in &usable {
        for cert in chain {
            if matches(record, cert)? {
                return Ok(record);
            }
        }
    }

    Err(DaneError::NoMatch {
        usage: TlsaUsage::PkixTa,
        records_compared: usable.len(),
    })
}

/// Builds a [`TrustAnchor`] from `cert`, failing closed on malformed name
/// constraints.
///
/// `TrustAnchor::try_from` is used in preference to `TrustAnchor::from_cert`
/// because the latter maps an unparsable `NameConstraints` extension to
/// `None`, producing an unconstrained anchor. See [`verify_dane_ta`]'s note on
/// why that silence is unacceptable here.
fn anchor_from_cert(cert: Certificate) -> Result<TrustAnchor, DaneError> {
    TrustAnchor::try_from(cert).map_err(|_| DaneError::AnchorNameConstraintsMalformed)
}

/// Checks the DNSSEC status and returns the usable records carrying `usage`.
///
/// Shared preamble of all four verify functions: the status gate and the two
/// "nothing to compare against" cases, which are distinguished because a
/// caller's fallback policy depends on which occurred.
///
/// # Errors
///
/// [`DaneError::DnssecNotSecure`], [`DaneError::NoRecordsForUsage`] or
/// [`DaneError::NoUsableRecords`].
fn usable_records_for_usage<'r>(
    usage: TlsaUsage,
    response: &'r TlsaResponse,
) -> Result<Vec<&'r TlsaRecord>, DaneError> {
    if !response.dnssec().is_secure() {
        return Err(DaneError::DnssecNotSecure {
            status: response.dnssec(),
        });
    }

    let records = response.records();
    let for_usage: Vec<&'r TlsaRecord> = records
        .iter()
        .filter(|record| record.usage() == usage)
        .collect();

    if for_usage.is_empty() {
        return Err(DaneError::NoRecordsForUsage {
            usage,
            records_present: records.len(),
        });
    }

    let usable: Vec<&'r TlsaRecord> = for_usage
        .iter()
        .copied()
        .filter(|record| record.is_usable())
        .collect();

    if usable.is_empty() {
        return Err(DaneError::NoUsableRecords {
            usage,
            records_for_usage: for_usage.len(),
        });
    }

    Ok(usable)
}
