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

use der::asn1::ObjectIdentifier;
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

        // §5 rule 7 and the §4.3 criticality rules. Called from here
        // rather than left for the caller to remember: a caller doing
        // the obvious thing — check the profile, then verify — would
        // otherwise skip the unsupported-critical-extension rule
        // entirely, which is the one extension rule that exists to
        // make a verifier refuse what it does not understand.
        self.check_extensions()
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

/// `id-pe-ac-auditIdentity` — RFC 5755 §4.3.1, `{ id-pe 4 }`.
/// Criticality MUST be TRUE; the value is 1 to 20 octets.
pub const ID_PE_AC_AUDIT_IDENTITY: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.4");

/// `id-ce-targetInformation` — RFC 5755 §4.3.2, `{ id-ce 55 }`.
/// Criticality MUST be TRUE.
pub const ID_CE_TARGET_INFORMATION: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.55");

/// `id-ce-noRevAvail` — RFC 5755 §4.3.6, `{ id-ce 56 }`.
/// Criticality MUST be FALSE.
pub const ID_CE_NO_REV_AVAIL: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.56");

/// `id-ce-authorityKeyIdentifier` — RFC 5755 §4.3.3.
pub const ID_CE_AUTHORITY_KEY_IDENTIFIER: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.5.29.35");

/// `id-ce-cRLDistributionPoints` — RFC 5755 §4.3.5.
pub const ID_CE_CRL_DISTRIBUTION_POINTS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.5.29.31");

/// `id-pe-authorityInfoAccess` — RFC 5755 §4.3.4.
pub const ID_PE_AUTHORITY_INFO_ACCESS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1");

/// Whether a verifier is among an attribute certificate's intended
/// targets — RFC 5755 §4.3.2 and §5 rule 6.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Targeting {
    /// No `targetInformation` extension, so the certificate is not
    /// targeted and any verifier may use it.
    Untargeted,
    /// The extension is present and this verifier is named by it, or
    /// belongs to a group it names.
    Matched,
    /// The extension is present and this verifier is not among the
    /// targets. The certificate is valid; it is not for this verifier.
    NotATarget,
}

impl AttributeCertificate {
    /// Does this certificate carry `noRevAvail` — RFC 5755 §4.3.6?
    ///
    /// Its presence is the issuer saying no revocation information will
    /// be made available, so a verifier should not go looking. Absence
    /// says nothing either way.
    #[must_use]
    pub fn no_revocation_available(&self) -> bool {
        self.extension(&ID_CE_NO_REV_AVAIL).is_some()
    }

    /// The `auditIdentity` value — RFC 5755 §4.3.1 — if present.
    ///
    /// An opaque identifier for audit logs, deliberately not the
    /// holder's name, so that logs can be correlated without recording
    /// who the holder was. Returned as bytes because that is all it is.
    #[must_use]
    pub fn audit_identity(&self) -> Option<&[u8]> {
        self.extension(&ID_PE_AC_AUDIT_IDENTITY)
            .map(|e| e.extn_value.as_bytes())
    }

    fn extension(&self, oid: &ObjectIdentifier) -> Option<&x509_cert::ext::Extension> {
        self.inner
            .acinfo
            .extensions
            .as_ref()?
            .iter()
            .find(|e| &e.extn_id == oid)
    }

    /// Apply RFC 5755 §5 rule 7 and the §4.3 criticality rules.
    ///
    /// Rule 7 is the security-relevant one: *"If the AC contains an
    /// unsupported critical extension, the AC MUST be rejected."* The
    /// RFC defines support as being able to parse the value and
    /// honouring a rejection the value implies, so a critical extension
    /// this crate does not know how to act on is grounds for refusal
    /// rather than something to step over.
    ///
    /// # Errors
    ///
    /// - [`Error::UnsupportedCriticalExtension`] — a critical extension
    ///   this crate cannot act on.
    /// - [`Error::ProfileViolation`] — an extension carries the wrong
    ///   criticality, or an `auditIdentity` of illegal length.
    pub fn check_extensions(&self) -> Result<()> {
        let Some(exts) = self.inner.acinfo.extensions.as_ref() else {
            return Ok(());
        };

        // §4.2: an extension must not appear twice. Two instances let
        // two implementations read one certificate differently, which is
        // the whole reason the rule exists.
        for (i, e) in exts.iter().enumerate() {
            if exts[i + 1..].iter().any(|o| o.extn_id == e.extn_id) {
                return Err(Error::ProfileViolation(
                    ProfileViolation::DuplicateExtension,
                ));
            }
        }

        for e in exts.iter() {
            match e.extn_id {
                // §4.3.1: criticality MUST be TRUE, value 1..=20 octets.
                ID_PE_AC_AUDIT_IDENTITY => {
                    if !e.critical {
                        return Err(Error::ProfileViolation(
                            ProfileViolation::AuditIdentityNotCritical,
                        ));
                    }
                    let len = e.extn_value.as_bytes().len();
                    if len == 0 || len > 20 {
                        return Err(Error::ProfileViolation(
                            ProfileViolation::AuditIdentityLength,
                        ));
                    }
                }
                // §4.3.2: criticality MUST be TRUE, and the value has to
                // parse or the extension is not supported.
                ID_CE_TARGET_INFORMATION => {
                    if !e.critical {
                        return Err(Error::ProfileViolation(
                            ProfileViolation::TargetInformationNotCritical,
                        ));
                    }
                    self.parse_targets()?;
                }
                // §4.3.6: criticality MUST be FALSE.
                ID_CE_NO_REV_AVAIL => {
                    if e.critical {
                        return Err(Error::ProfileViolation(
                            ProfileViolation::NoRevAvailCritical,
                        ));
                    }
                }
                // Profiled by §4.3.3/§4.3.4/§4.3.5 and not acted on
                // here: they assist a verifier in finding the issuer's
                // certificate or its revocation data, which is the
                // caller's job in this workspace. None of them may be
                // critical in a conforming AC, and if one is, the rule
                // below refuses it rather than this arm waving it
                // through.
                ID_CE_AUTHORITY_KEY_IDENTIFIER
                | ID_CE_CRL_DISTRIBUTION_POINTS
                | ID_PE_AUTHORITY_INFO_ACCESS => {
                    if e.critical {
                        return Err(Error::UnsupportedCriticalExtension(e.extn_id));
                    }
                }
                other => {
                    if e.critical {
                        return Err(Error::UnsupportedCriticalExtension(other));
                    }
                }
            }
        }
        Ok(())
    }

    /// The parsed `targetInformation` targets, flattened.
    ///
    /// §4.3.2 notes that X.509-2000 defines the extension as a
    /// `SEQUENCE OF Targets` while a conforming issuer emits exactly
    /// one `Targets`, and requires users to accept several and treat
    /// them "as if all Target elements had been found within one
    /// Targets element". So this flattens.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedCriticalExtension`] if the value does not
    /// parse: the extension is critical, and §5 defines support as
    /// including the ability to parse it.
    pub fn targets(&self) -> Result<Option<types::Targets>> {
        match self.extension(&ID_CE_TARGET_INFORMATION) {
            None => Ok(None),
            Some(_) => self.parse_targets().map(Some),
        }
    }

    fn parse_targets(&self) -> Result<types::Targets> {
        let ext = self
            .extension(&ID_CE_TARGET_INFORMATION)
            .ok_or(Error::ParseError)?;
        let bytes = ext.extn_value.as_bytes();
        // SEQUENCE OF Targets, each itself a SEQUENCE OF Target.
        let groups = Vec::<types::Targets>::from_der(bytes)
            .map_err(|_| Error::UnsupportedCriticalExtension(ID_CE_TARGET_INFORMATION))?;
        Ok(groups.into_iter().flatten().collect())
    }

    /// Is this verifier among the certificate's intended targets —
    /// RFC 5755 §5 rule 6?
    ///
    /// `my_names` are the names this verifier answers to and `my_groups`
    /// the groups it belongs to. Both come from the caller because the
    /// RFC leaves membership undefined: *"any given target 'knows' the
    /// names of the targetGroups to which it belongs or can otherwise
    /// determine its membership"*. A library cannot know whether it is
    /// a printer, or which DNS domain it is in, so it does not guess.
    ///
    /// An untargeted certificate returns [`Targeting::Untargeted`]
    /// rather than matching, so a caller cannot confuse "no restriction"
    /// with "I am a named target".
    ///
    /// # Errors
    ///
    /// - [`Error::ProfileViolation`] if a target uses `targetCert`,
    ///   which §4.3.2 says MUST NOT be used.
    /// - [`Error::UnsupportedCriticalExtension`] if the extension value
    ///   does not parse.
    pub fn check_targeting(
        &self,
        my_names: &[GeneralName],
        my_groups: &[GeneralName],
    ) -> Result<Targeting> {
        let Some(targets) = self.targets()? else {
            return Ok(Targeting::Untargeted);
        };
        let mut matched = false;
        for t in &targets {
            match t {
                types::Target::TargetName(n) => {
                    if my_names.contains(n) {
                        matched = true;
                    }
                }
                types::Target::TargetGroup(g) => {
                    if my_groups.contains(g) {
                        matched = true;
                    }
                }
                // Checked even after a match: a certificate carrying a
                // forbidden target is non-conforming whether or not this
                // verifier happens to be named elsewhere in the list.
                types::Target::TargetCert(_) => {
                    return Err(Error::ProfileViolation(ProfileViolation::TargetCertUsed))
                }
            }
        }
        Ok(if matched {
            Targeting::Matched
        } else {
            Targeting::NotATarget
        })
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

/// Check an Attribute Authority's own certificate — RFC 5755 §4.5.
///
/// §4.5 constrains the AC issuer's public-key certificate two ways, and
/// the second matters more than it looks:
///
/// - `keyUsage` "MUST NOT explicitly indicate that the AC issuer's
///   public key cannot be used to validate a digital signature", so a
///   `keyUsage` that is present and omits `digitalSignature` is a
///   refusal. An absent extension constrains nothing.
/// - **"An AC issuer MUST NOT also be a PKC Issuer. That is, an AC
///   issuer cannot be a CA as well."** So `basicConstraints.cA` must not
///   be TRUE.
///
/// RFC 5755 §5 rule 4 separately requires the AC issuer to be "directly
/// trusted as an AC issuer (by configuration or otherwise)" — a decision
/// no library can make for a caller. The obvious way to satisfy it by
/// accident is to validate the authority's certificate against the same
/// trust anchors used for everything else, and a CA trusted to issue TLS
/// certificates is not thereby trusted to grant roles.
///
/// Refusing CA certificates as authorities closes that by construction:
/// an ordinary CA has `cA` TRUE and cannot be used here whatever the
/// caller intended. The RFC gives its own reason — "to avoid confusion
/// regarding serial numbers and revocations" — but the authorization
/// consequence is the useful one.
///
/// This does not validate `aa_cert`'s certification path; that remains
/// the caller's, per the crate documentation.
///
/// # Errors
///
/// [`Error::ProfileViolation`] carrying [`ProfileViolation::IssuerIsACa`],
/// [`ProfileViolation::IssuerCannotSign`] or
/// [`ProfileViolation::IssuerExtensionMalformed`].
pub fn check_issuer_profile(aa_cert: &Certificate) -> Result<()> {
    const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
    const OID_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");

    let Some(exts) = aa_cert.tbs_certificate().extensions() else {
        // No extensions: no cA assertion and no keyUsage, so neither
        // §4.5 rule has anything to bite on.
        return Ok(());
    };

    if let Some(ext) = exts.iter().find(|e| e.extn_id == OID_BASIC_CONSTRAINTS) {
        let bc = x509_cert::ext::pkix::BasicConstraints::from_der(ext.extn_value.as_bytes())
            .map_err(|_| Error::ProfileViolation(ProfileViolation::IssuerExtensionMalformed))?;
        if bc.ca {
            return Err(Error::ProfileViolation(ProfileViolation::IssuerIsACa));
        }
    }

    if let Some(ext) = exts.iter().find(|e| e.extn_id == OID_KEY_USAGE) {
        let ku = x509_cert::ext::pkix::KeyUsage::from_der(ext.extn_value.as_bytes())
            .map_err(|_| Error::ProfileViolation(ProfileViolation::IssuerExtensionMalformed))?;
        if !ku.digital_signature() {
            return Err(Error::ProfileViolation(ProfileViolation::IssuerCannotSign));
        }
    }

    Ok(())
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
    /// §4.2: the same extension appears more than once.
    DuplicateExtension,
    /// §4.3.1: `auditIdentity` is not marked critical, though it must be.
    AuditIdentityNotCritical,
    /// §4.3.1: `auditIdentity` is empty or longer than 20 octets.
    AuditIdentityLength,
    /// §4.3.2: `targetInformation` is not marked critical, though it
    /// must be.
    TargetInformationNotCritical,
    /// §4.3.6: `noRevAvail` is marked critical, though it must not be.
    NoRevAvailCritical,
    /// §4.3.2: a target used `targetCert`, which MUST NOT be used.
    TargetCertUsed,
    /// §4.5: the Attribute Authority's certificate is a CA
    /// (`basicConstraints.cA` is TRUE). An AC issuer must not also be a
    /// PKC issuer.
    IssuerIsACa,
    /// §4.5: the Attribute Authority's `keyUsage` excludes
    /// `digitalSignature`, so its key may not be used to validate the
    /// signature it just made.
    IssuerCannotSign,
    /// §4.5: the Attribute Authority's `basicConstraints` or `keyUsage`
    /// extension will not decode.
    IssuerExtensionMalformed,
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
            Self::DuplicateExtension => "the same extension appears more than once",
            Self::AuditIdentityNotCritical => {
                "auditIdentity is not critical, though RFC 5755 §4.3.1 requires it to be"
            }
            Self::AuditIdentityLength => {
                "auditIdentity must be between 1 and 20 octets (RFC 5755 §4.3.1)"
            }
            Self::TargetInformationNotCritical => {
                "targetInformation is not critical, though RFC 5755 §4.3.2 requires it to be"
            }
            Self::NoRevAvailCritical => {
                "noRevAvail is critical, though RFC 5755 §4.3.6 requires it not to be"
            }
            Self::TargetCertUsed => "a target used targetCert, which RFC 5755 §4.3.2 forbids",
            Self::IssuerIsACa => {
                "the attribute authority's certificate is a CA, which RFC 5755 §4.5 forbids"
            }
            Self::IssuerCannotSign => {
                "the attribute authority's keyUsage excludes digitalSignature (RFC 5755 §4.5)"
            }
            Self::IssuerExtensionMalformed => {
                "the attribute authority's basicConstraints or keyUsage will not decode"
            }
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
    /// The attribute certificate names a different holder than the
    /// entity presenting it.
    ///
    /// [`AttributeCertificate::matches_holder`] answers this as a
    /// `bool`, because "not for this entity" is an ordinary answer. This
    /// variant exists for the composed check — RFC 5755 §5 rule 1 — where
    /// a mismatch is a failure rather than a question: an AC that is
    /// validly signed by a trusted authority but issued to somebody else
    /// grants the presenter nothing.
    HolderMismatch,
    /// A critical extension this crate cannot act on — RFC 5755 §5
    /// rule 7. Carries the offending OID so a caller can say which.
    UnsupportedCriticalExtension(
        #[cfg_attr(feature = "serde", serde(with = "oid_as_dotted_string"))] ObjectIdentifier,
    ),
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
            Self::HolderMismatch => {
                f.write_str("attribute certificate was issued to a different holder")
            }
            Self::UnsupportedCriticalExtension(oid) => {
                write!(f, "unsupported critical extension {oid}")
            }
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

/// Serialising an [`ObjectIdentifier`] as its dotted form.
///
/// `der`'s `ObjectIdentifier` implements neither serde trait and
/// `const-oid` ships no serde feature, so this does it by hand rather
/// than drop the OID from [`Error::UnsupportedCriticalExtension`] —
/// which would leave a caller told that *some* critical extension was
/// unsupported without being able to say which.
///
/// The dotted string is the representation to put on a wire: it is
/// stable, readable, and parses back. The internal byte encoding is an
/// implementation detail of the OID type.
#[cfg(feature = "serde")]
mod oid_as_dotted_string {
    use alloc::string::String;

    use der::asn1::ObjectIdentifier;
    use serde::de::Error as _;
    use serde::{Deserialize as _, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        oid: &ObjectIdentifier,
        s: S,
    ) -> core::result::Result<S::Ok, S::Error> {
        s.collect_str(oid)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> core::result::Result<ObjectIdentifier, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(D::Error::custom)
    }
}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;
