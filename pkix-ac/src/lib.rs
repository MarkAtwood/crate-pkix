#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! RFC 5755 X.509 attribute certificate validation.
//!
//! An attribute certificate binds attributes — a role, a group, a
//! clearance — to a holder, and carries no public key of its own. It is
//! issued by an Attribute Authority whose own certificate is an ordinary
//! public-key certificate.
//!
//! # What this crate does not do, and why
//!
//! It does not validate the Attribute Authority's certification path,
//! and it takes no trust anchors. The AA's chain is an ordinary
//! public-key chain, so validating it is [`pkix_path`]'s job and
//! composing the two is `pkix-chain`'s — the same seam that keeps
//! name matching free of chain context.
//!
//! [`AttributeCertificate::verify`] therefore takes the AA's certificate
//! and trusts the caller to have validated it. **Passing an unvalidated
//! certificate makes the answer meaningless**: the signature will check
//! out against whatever key is handed over, an attacker's included. Use
//! `pkix-chain`'s wrapper unless you are doing the path validation
//! yourself.
//!
//! # Attributes are parsed, not interpreted
//!
//! RFC 5755 §4.4 profiles six attribute types — `Role`, `Group`,
//! `Clearance`, `ChargingIdentity`, `AccessIdentity` and
//! `ServiceAuthenticationInfo` — and this crate hands all of them back
//! as an OID and a set of unparsed values. It does not decide what any
//! of them mean.
//!
//! That is deliberate. What a `Clearance` permits is security policy
//! belonging to the application: it turns on a policy identifier the
//! application owns, a lattice it defines, and often a classification
//! scheme this library has no business encoding. A library that
//! interpreted them would be guessing at an authorization decision on
//! the caller's behalf. Match on the attribute type and decode the
//! values your deployment understands.
//!
//! # Spec references
//!
//! - RFC 5755 — An Internet Attribute Certificate Profile for
//!   Authorization. §4.1 syntax, §4.2 profile rules, §4.4 attribute
//!   types, §5 validation.
//! - RFC 5280 §6 — used by the caller to validate the AA's chain.

extern crate alloc;

pub mod types;

use alloc::vec::Vec;

use der::referenced::OwnedToRef as _;
use der::{Decode as _, Encode as _};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::spki::SubjectPublicKeyInfoRef;
use x509_cert::Certificate;

use pkix_path::SignatureVerifier;

use types::{AttCertIssuer, Attribute, AttributeCertificateInner};

/// A parsed attribute certificate, keeping the bytes it was parsed from.
///
/// The original DER is retained because the signature is over the DER of
/// `acinfo`, and the only way to be certain which bytes those were is to
/// keep them. Re-encoding the parsed structure would rely on an encoder
/// reproducing its input — an assumption this workspace has already been
/// bitten by once, in `pkix-ct`.
#[derive(Clone, Debug)]
pub struct AttributeCertificate {
    der: Vec<u8>,
    inner: AttributeCertificateInner,
    /// Byte range of `acinfo` within `der`: the signed input.
    acinfo: core::ops::Range<usize>,
}

impl AttributeCertificate {
    /// Parse an attribute certificate.
    ///
    /// Accepts anything matching the RFC 5755 §4.1 syntax. It does not
    /// apply the §4.2 profile rules — call [`Self::check_profile`] for
    /// those — so that a non-conforming certificate can be read and
    /// reported on rather than refused as malformed.
    ///
    /// # Errors
    ///
    /// [`Error::ParseError`] if the bytes are not a well-formed
    /// attribute certificate, trailing data included.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let inner = AttributeCertificateInner::from_der(der).map_err(|_| Error::ParseError)?;
        let acinfo = acinfo_range(der).ok_or(Error::ParseError)?;
        Ok(Self {
            der: der.to_vec(),
            inner,
            acinfo,
        })
    }

    /// The bytes this was parsed from.
    #[must_use]
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }

    /// The DER of `acinfo` — the bytes the Attribute Authority signed.
    #[must_use]
    pub fn signed_bytes(&self) -> &[u8] {
        &self.der[self.acinfo.clone()]
    }

    /// The parsed structure, for fields this type does not expose
    /// directly.
    #[must_use]
    pub fn inner(&self) -> &AttributeCertificateInner {
        &self.inner
    }

    /// The attributes, in the order they appear.
    ///
    /// `attributes` is a `SEQUENCE OF`, so the order is part of the
    /// value and is preserved.
    #[must_use]
    pub fn attributes(&self) -> &[Attribute] {
        &self.inner.acinfo.attributes
    }

    /// Apply the RFC 5755 §4.2 profile rules.
    ///
    /// # Errors
    ///
    /// [`Error::ProfileViolation`] naming which rule failed.
    pub fn check_profile(&self) -> Result<()> {
        let info = &self.inner.acinfo;

        // §4.2.3: v1Form MUST NOT be used.
        let AttCertIssuer::V2Form(v2) = &info.issuer else {
            return Err(Error::ProfileViolation(ProfileViolation::IssuerV1Form));
        };
        // §4.2.3: issuerName MUST be present and carry exactly one name.
        match v2.issuer_name.as_deref() {
            None | Some([]) => {
                return Err(Error::ProfileViolation(ProfileViolation::IssuerNameMissing))
            }
            Some([_]) => {}
            Some(_) => {
                return Err(Error::ProfileViolation(
                    ProfileViolation::IssuerNameNotSingular,
                ))
            }
        }
        // §4.2.3: neither of these may appear in the v2 form.
        if v2.base_certificate_id.is_some() || v2.object_digest_info.is_some() {
            return Err(Error::ProfileViolation(ProfileViolation::IssuerExtraFields));
        }

        // §4.2.2: exactly one of baseCertificateID or entityName.
        let holder = &info.holder;
        match (
            holder.base_certificate_id.is_some(),
            holder.entity_name.is_some(),
        ) {
            (true, false) | (false, true) => {}
            (true, true) => return Err(Error::ProfileViolation(ProfileViolation::HolderAmbiguous)),
            (false, false) => return Err(Error::ProfileViolation(ProfileViolation::HolderMissing)),
        }
        if holder.object_digest_info.is_some() {
            return Err(Error::ProfileViolation(
                ProfileViolation::HolderObjectDigestInfo,
            ));
        }
        if let Some(names) = holder.entity_name.as_deref() {
            if names.len() != 1 {
                return Err(Error::ProfileViolation(
                    ProfileViolation::HolderNameNotSingular,
                ));
            }
        }

        // §4.1: at least one attribute, each with at least one value.
        if info.attributes.is_empty() {
            return Err(Error::ProfileViolation(ProfileViolation::NoAttributes));
        }
        if info.attributes.iter().any(|a| a.values.is_empty()) {
            return Err(Error::ProfileViolation(
                ProfileViolation::AttributeWithoutValues,
            ));
        }

        Ok(())
    }

    /// Verify the signature and the validity period.
    ///
    /// `aa_cert` is the Attribute Authority's certificate, and **the
    /// caller must already have validated its certification path** —
    /// this crate takes no trust anchors and checks none.
    ///
    /// Checks that the AC names `aa_cert`'s subject as its issuer, that
    /// `now_unix` falls inside the validity period, and that the
    /// signature verifies under `aa_cert`'s public key. The order
    /// decides only which error comes back first; none is skipped on
    /// the strength of another.
    ///
    /// # Errors
    ///
    /// - [`Error::IssuerMismatch`] — the AC's issuer is not `aa_cert`'s
    ///   subject, so this is not the certificate that issued it.
    /// - [`Error::NotYetValid`] / [`Error::Expired`] — `now_unix` is
    ///   outside `attrCertValidityPeriod`.
    /// - [`Error::SignatureInvalid`] — the signature did not verify.
    /// - [`Error::ProfileViolation`] — the issuer is in a form this
    ///   check cannot interpret; [`Self::check_profile`] gives the
    ///   precise reason.
    /// - [`Error::ParseError`] — `aa_cert`'s public key will not decode.
    pub fn verify<V: SignatureVerifier>(
        &self,
        aa_cert: &Certificate,
        now_unix: u64,
        verifier: &V,
    ) -> Result<()> {
        let info = &self.inner.acinfo;

        // The AC must name the certificate that signed it. Without this,
        // the signature check alone would accept an AC issued by one
        // authority and verified against another's certificate, if the
        // caller supplied the wrong one.
        let AttCertIssuer::V2Form(v2) = &info.issuer else {
            return Err(Error::ProfileViolation(ProfileViolation::IssuerV1Form));
        };
        let Some([GeneralName::DirectoryName(issuer_name)]) = v2.issuer_name.as_deref() else {
            return Err(Error::ProfileViolation(
                ProfileViolation::IssuerNameNotDirectoryName,
            ));
        };
        if issuer_name != aa_cert.tbs_certificate().subject() {
            return Err(Error::IssuerMismatch);
        }

        // RFC 5755 §4.1: both bounds are GeneralizedTime, with no
        // UTCTime alternative and no "no well-defined expiry" encoding,
        // so neither end is optional the way a public-key certificate's
        // can be.
        let not_before = info.validity.not_before_time.to_unix_duration().as_secs();
        let not_after = info.validity.not_after_time.to_unix_duration().as_secs();
        if now_unix < not_before {
            return Err(Error::NotYetValid);
        }
        if now_unix > not_after {
            return Err(Error::Expired);
        }

        let spki_der = aa_cert
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .map_err(|_| Error::ParseError)?;
        let spki = SubjectPublicKeyInfoRef::from_der(&spki_der).map_err(|_| Error::ParseError)?;
        let signature = self
            .inner
            .signature_value
            .as_bytes()
            .ok_or(Error::ParseError)?;

        verifier
            .verify_signature(
                self.inner.signature_algorithm.owned_to_ref(),
                spki,
                self.signed_bytes(),
                signature,
            )
            .map_err(|_| Error::SignatureInvalid)
    }

    /// Does this attribute certificate belong to the holder of
    /// `holder_cert`?
    ///
    /// RFC 5755 §4.2.2 lets the holder be named either by a reference to
    /// its public-key certificate — issuer and serial — or by name, and
    /// this checks whichever form the AC uses.
    ///
    /// Returns `false` rather than an error for a mismatch, since "this
    /// AC is not for this entity" is an ordinary answer. A holder form
    /// the profile forbids also returns `false`: it cannot be shown to
    /// match, and that is the safe reading.
    #[must_use]
    pub fn matches_holder(&self, holder_cert: &Certificate) -> bool {
        let holder = &self.inner.acinfo.holder;
        let tbs = holder_cert.tbs_certificate();

        if let Some(base) = &holder.base_certificate_id {
            let issuer_matches = matches!(
                base.issuer.as_slice(),
                [GeneralName::DirectoryName(name)] if name == tbs.issuer()
            );
            return issuer_matches && base.serial.as_bytes() == tbs.serial_number().as_bytes();
        }
        if let Some([GeneralName::DirectoryName(name)]) = holder.entity_name.as_deref() {
            return name == tbs.subject();
        }
        false
    }
}

/// Byte range of `acinfo` inside an attribute certificate's DER.
///
/// `acinfo` is the first element of the outer `SEQUENCE`, so this is a
/// walk of two headers. Taken as a range into the original bytes rather
/// than re-encoded, because those are the bytes that were signed.
fn acinfo_range(der: &[u8]) -> Option<core::ops::Range<usize>> {
    let (outer_value, outer_header) = header(der)?;
    let body = der.get(outer_header..outer_header.checked_add(outer_value)?)?;
    let (acinfo_value, acinfo_header) = header(body)?;
    let total = acinfo_header.checked_add(acinfo_value)?;
    if total > body.len() {
        return None;
    }
    Some(outer_header..outer_header + total)
}

/// `(value_len, header_len)` of the DER triple at the start of `input`.
///
/// Rejects non-minimal and over-long length encodings. The `der` crate's
/// parser rejects them too, so accepting them here could only produce a
/// byte range no Attribute Authority ever signed.
fn header(input: &[u8]) -> Option<(usize, usize)> {
    let first = *input.get(1)?;
    if first < 0x80 {
        return Some((first as usize, 2));
    }
    let count = (first & 0x7F) as usize;
    if count == 0 || count > 4 {
        return None;
    }
    let octets = input.get(2..2 + count)?;
    if octets[0] == 0 {
        return None;
    }
    let mut len = 0usize;
    for &b in octets {
        len = (len << 8) | b as usize;
    }
    if len < 0x80 {
        return None;
    }
    Some((len, 2 + count))
}

/// Which RFC 5755 §4.2 profile rule a certificate broke.
///
/// Separate from [`Error`] so a profile failure says which rule, not
/// merely that there was one. Several of these describe syntax the ASN.1
/// permits and the profile forbids, which is why parsing accepts them
/// and this rejects them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum ProfileViolation {
    /// §4.2.3: the issuer used `v1Form`.
    IssuerV1Form,
    /// §4.2.3: `issuerName` is absent or empty, though it is required.
    IssuerNameMissing,
    /// §4.2.3: `issuerName` carries more than one name.
    IssuerNameNotSingular,
    /// §4.2.3: `issuerName` is not a `directoryName`, the only form that
    /// can be compared against a certificate's subject.
    IssuerNameNotDirectoryName,
    /// §4.2.3: `baseCertificateID` or `objectDigestInfo` appeared in the
    /// v2 form, where neither is permitted.
    IssuerExtraFields,
    /// §4.2.2: the holder gives both `baseCertificateID` and
    /// `entityName`, so which identifies it is ambiguous.
    HolderAmbiguous,
    /// §4.2.2: the holder gives neither.
    HolderMissing,
    /// §4.2.2: the holder carries more than one name.
    HolderNameNotSingular,
    /// §4.1: the holder used `objectDigestInfo`, which this profile does
    /// not cover.
    HolderObjectDigestInfo,
    /// §4.1: `attributes` is empty, though one is required.
    NoAttributes,
    /// §4.1: an attribute carries no values, though one is required.
    AttributeWithoutValues,
}

impl core::fmt::Display for ProfileViolation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::IssuerV1Form => "issuer uses v1Form, which RFC 5755 §4.2.3 forbids",
            Self::IssuerNameMissing => "issuerName is absent or empty (RFC 5755 §4.2.3)",
            Self::IssuerNameNotSingular => "issuerName carries more than one name",
            Self::IssuerNameNotDirectoryName => "issuerName is not a directoryName",
            Self::IssuerExtraFields => {
                "v2Form carries baseCertificateID or objectDigestInfo, which §4.2.3 forbids"
            }
            Self::HolderAmbiguous => "holder gives both baseCertificateID and entityName",
            Self::HolderMissing => "holder gives neither baseCertificateID nor entityName",
            Self::HolderNameNotSingular => "holder carries more than one name",
            Self::HolderObjectDigestInfo => "holder uses objectDigestInfo, which is not profiled",
            Self::NoAttributes => "no attributes, though RFC 5755 §4.1 requires at least one",
            Self::AttributeWithoutValues => "an attribute carries no values",
        };
        f.write_str(s)
    }
}

/// Errors returned by attribute certificate validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Error {
    /// The bytes are not a well-formed RFC 5755 §4.1 attribute
    /// certificate, or a public key would not decode.
    ParseError,
    /// The syntax is valid but a profile rule was broken.
    ProfileViolation(ProfileViolation),
    /// The AC names an issuer that is not the subject of the Attribute
    /// Authority certificate it was checked against.
    IssuerMismatch,
    /// `now_unix` is before `notBeforeTime`.
    NotYetValid,
    /// `now_unix` is after `notAfterTime`.
    Expired,
    /// The signature did not verify under the AA's public key.
    SignatureInvalid,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ParseError => f.write_str("attribute certificate parse error"),
            Self::ProfileViolation(v) => write!(f, "RFC 5755 profile violation: {v}"),
            Self::IssuerMismatch => {
                f.write_str("attribute certificate was not issued by the supplied authority")
            }
            Self::NotYetValid => f.write_str("attribute certificate is not yet valid"),
            Self::Expired => f.write_str("attribute certificate has expired"),
            Self::SignatureInvalid => f.write_str("attribute certificate signature invalid"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

const _: fn() = || {
    fn _assert_send_sync<T: Send + Sync>() {}
    _assert_send_sync::<Error>();
    _assert_send_sync::<AttributeCertificate>();
};

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;
