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

/// Which RFC 5755 §6 revocation scheme the caller supports for the
/// attribute certificate itself.
///
/// §6 defines two and requires a choice: "for AC users, the 'never
/// revoke' scheme MUST be supported, and the 'pointer in AC' scheme
/// SHOULD be supported. If only the 'never revoke' scheme is supported,
/// then all ACs that do not contain a noRevAvail extension, MUST be
/// rejected."
///
/// This lives here, rather than in `pkix-chain` where it started,
/// because [`AttributeCertificate::validate`] has to ask the same
/// question. It did not, which left two entry points disagreeing about
/// one MUST — and the one documented as the safe default was the
/// permissive one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum AcRevocation {
    /// Only the "never revoke" scheme, so an AC without `noRevAvail` is
    /// refused — the §6 MUST.
    ///
    /// The conservative choice, and the right one unless the caller
    /// really does establish AC revocation status. An AC with no
    /// `noRevAvail` is its issuer "implicitly stating that revocation
    /// status checks are supported", so honouring it without checking
    /// accepts a credential the issuer expected to be checkable.
    NeverRevokeOnly,
    /// The caller establishes the AC's revocation status itself, by
    /// whatever means — §6 permits "any source for AC revocation status
    /// information".
    ///
    /// An AC without `noRevAvail` is then accepted, because the caller
    /// has taken on the obligation §6 attaches to it. Nothing here can
    /// check that they have; this is the caller saying so.
    CallerChecks,
}

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
    /// One exception, which is not this crate's choice: `x509-cert`'s
    /// `SerialNumber` refuses more than 21 DER content octets while
    /// decoding, so an AC whose serial exceeds that is
    /// [`Error::ParseError`] here rather than
    /// [`ProfileViolation::SerialTooLong`] from `check_profile`. A
    /// grosser violation of §4.2.5 therefore reports as malformed where
    /// a narrower one reports as a profile failure. Noted rather than
    /// worked around: reaching it would mean giving up the typed serial
    /// for an `Any`, and both answers are refusals.
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

    /// Apply the RFC 5755 §4.2 and §4.3 profile rules, and §5 rule 7.
    ///
    /// **Not all of §5.** Pairing this with [`Self::verify`] — the
    /// obvious pair — leaves rule 3 ([`check_issuer_profile`]) and rule
    /// 6 ([`Self::check_targeting`]) unchecked. Use [`Self::validate`]
    /// unless you mean to run the parts yourself.
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
        // §4.2.3, which is four requirements in one sentence: the
        // issuerName "MUST contain one and only one GeneralName ...
        // which MUST contain a non-empty distinguished name in the
        // directoryName field". Checking only the count accepts a
        // dNSName, and checking only the form accepts an empty DN.
        match v2.issuer_name.as_deref() {
            None | Some([]) => {
                return Err(Error::ProfileViolation(ProfileViolation::IssuerNameMissing))
            }
            Some([GeneralName::DirectoryName(dn)]) => {
                if dn.is_empty() {
                    return Err(Error::ProfileViolation(ProfileViolation::IssuerNameEmptyDn));
                }
            }
            Some([_]) => {
                return Err(Error::ProfileViolation(
                    ProfileViolation::IssuerNameNotDirectoryName,
                ))
            }
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

        // §4.2.2. objectDigestInfo is checked first on purpose: a
        // holder carrying only objectDigestInfo has neither of the two
        // profiled forms, so the exactly-one check below would report
        // HolderMissing — true, but it names what is absent instead of
        // the unprofiled thing that is present, which is the part the
        // caller has to remove.
        let holder = &info.holder;
        if holder.object_digest_info.is_some() {
            return Err(Error::ProfileViolation(
                ProfileViolation::HolderObjectDigestInfo,
            ));
        }
        match (
            holder.base_certificate_id.is_some(),
            holder.entity_name.is_some(),
        ) {
            (true, false) | (false, true) => {}
            (true, true) => return Err(Error::ProfileViolation(ProfileViolation::HolderAmbiguous)),
            (false, false) => return Err(Error::ProfileViolation(ProfileViolation::HolderMissing)),
        }
        if let Some(names) = holder.entity_name.as_deref() {
            // Zero names and several names are different faults, and
            // reporting both as "more than one name" told a caller with
            // an `A1 00` entityName the opposite of what happened. The
            // issuer side already separated them; this did not. Zero is
            // also a `GeneralNames ::= SEQUENCE SIZE (1..MAX)`
            // violation in its own right.
            if names.is_empty() {
                return Err(Error::ProfileViolation(ProfileViolation::HolderNameEmpty));
            }
            if names.len() > 1 {
                return Err(Error::ProfileViolation(
                    ProfileViolation::HolderNameNotSingular,
                ));
            }
        }

        // §4.2.5: "AC issuers MUST force the serialNumber to be a
        // positive integer, that is, the sign bit in the DER encoding of
        // the INTEGER value MUST be zero", and "conformant ACs MUST NOT
        // contain serialNumber values longer than 20 octets".
        //
        // The first exists to remove "a potential ambiguity in mapping
        // between a string of octets and an integer value" — which is
        // precisely the mapping `matches_holder` relies on when it
        // compares serials as bytes, and that any issuer/serial audit
        // correlation relies on too.
        let serial = info.serial_number.as_bytes();
        if serial.first().is_some_and(|b| b & 0x80 != 0) {
            return Err(Error::ProfileViolation(ProfileViolation::SerialNotPositive));
        }
        // The magnitude, not the sign-padded encoding. §4.2.5 tells
        // issuers to add "a leading (leftmost) '00'H octet if necessary"
        // to force the sign bit clear, and then caps the *value* at 20
        // octets — so a conforming 20-octet serial whose top byte has
        // its high bit set is 21 DER content octets. Measuring those
        // rejected it, which is roughly half of all 20-octet serials.
        // `as_bytes` yields the DER content octets, sign padding and
        // all — NOT, as x509-cert's own doc comment claims, the value
        // "with all leading zeros stripped". It forwards to
        // `der::asn1::Int::as_bytes`, and `der`'s canonical check
        // rejects a leading `0x00` unless the next octet has its high
        // bit set, so at most one can ever be present and this strip is
        // exact. Were upstream's doc true, this arm would be dead and
        // the cap below would be measuring the wrong thing.
        let magnitude = match serial {
            [0x00, rest @ ..] => rest,
            other => other,
        };
        // Zero. §4.2.5 requires "a positive integer", and zero is not
        // one. It reaches here as content `00`: the sign test above
        // passes because the high bit is clear, and the strip leaves an
        // empty magnitude — which is the only way to get one, so this
        // is exactly the zero case.
        if magnitude.is_empty() {
            return Err(Error::ProfileViolation(ProfileViolation::SerialZero));
        }
        if magnitude.len() > 20 {
            return Err(Error::ProfileViolation(ProfileViolation::SerialTooLong));
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
        // §4.2.7: "For a given AC, each AttributeType OBJECT IDENTIFIER
        // in the sequence MUST be unique. That is, only one instance of
        // each attribute can occur in a single AC, but each instance can
        // be multi-valued."
        //
        // The same divergent-interpretation hazard as a duplicate
        // extension, and for once the consequence is concrete rather
        // than theoretical: given Role=auditor followed by Role=admin, a
        // consumer that reads the first match sees auditor and one that
        // reads the last sees admin. Multi-valued attributes are how the
        // RFC says to express several values, and they leave no such
        // room.
        for (i, a) in info.attributes.iter().enumerate() {
            if info.attributes[i + 1..]
                .iter()
                .any(|o| o.r#type == a.r#type)
            {
                return Err(Error::ProfileViolation(
                    ProfileViolation::DuplicateAttributeType,
                ));
            }
        }

        // §5 rule 7 and the §4.3 criticality rules. Called from here
        // rather than left for the caller to remember: a caller doing
        // the obvious thing — check the profile, then verify — would
        // otherwise skip the unsupported-critical-extension rule
        // entirely, which is the one extension rule that exists to
        // make a verifier refuse what it does not understand.
        self.check_extensions()
    }

    /// Verify the signature, §4.2.8 and the validity period.
    ///
    /// **Not all of §5.** See [`Self::validate`], which runs the rest —
    /// this does not check the §4.5 profile on `aa_cert`, the holder
    /// binding, or targeting.
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
        // RFC 5280 §7.1 DN comparison, not byte equality. Two
        // distinguished names can hold the same content and differ in
        // encoding — PrintableString against UTF8String, letter case,
        // insignificant whitespace — and X.501 says they are the same
        // name. `pkix_path::names_match` is what the chain walker uses
        // to link issuer to subject, so using it here keeps one workspace
        // to one answer: a name pkix-path linked cannot be a name
        // pkix-ac calls a mismatch.
        if !pkix_path::names_match(issuer_name, aa_cert.tbs_certificate().subject()) {
            return Err(Error::IssuerMismatch);
        }

        // §4.2.8: issuerUniqueID "MUST NOT be used unless it is also
        // used in the AC issuer's PKC, in which case it MUST be used".
        // Conditional on the authority's certificate, so it cannot live
        // in check_profile, which does not have one — this is the only
        // place that does.
        // The AA's OWN unique identifier, which in the AA's certificate
        // is `subjectUniqueID` — the AA is that certificate's subject.
        // This compared against `issuerUniqueID`, which identifies the
        // AA's *CA*, two hops from anything about this AC: it rejected
        // an ordinary AC carrying no issuerUniqueID whenever the AA's
        // own issuer happened to use one, and rejected an AC correctly
        // carrying the AA's identifier whenever it did not.
        //
        // And the values are compared, not just their presence —
        // "in which case it MUST be used" means used with the same
        // value, or the field identifies nothing.
        match (
            &info.issuer_unique_id,
            aa_cert.tbs_certificate().subject_unique_id(),
        ) {
            (None, None) => {}
            (Some(ac_uid), Some(aa_uid)) if ac_uid == aa_uid => {}
            _ => {
                return Err(Error::ProfileViolation(
                    ProfileViolation::IssuerUniqueIdMismatch,
                ))
            }
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

        // The outer signatureAlgorithm must match the one inside
        // acinfo, and this is not bookkeeping. acinfo is what was
        // signed, so acinfo.signature is covered by the signature and
        // the outer field is not: anybody on the path can rewrite the
        // outer one without invalidating anything. Verifying under it
        // would let them choose the algorithm the verification runs,
        // which is an algorithm-substitution surface.
        //
        // RFC 5280 §4.1.1.2 requires the equality for certificates —
        // "this field MUST contain the same algorithm identifier as the
        // signature field in the sequence tbsCertificate" — and RFC
        // 5755 §4.1 gives attribute certificates the same shape, so the
        // requirement carries over with the reasoning intact.
        if info.signature != self.inner.signature_algorithm {
            return Err(Error::SignatureAlgorithmMismatch);
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
                // The signed copy, deliberately. Equal to the outer one
                // by the check above; using this one means a future
                // edit that drops that check degrades the error message
                // rather than the security property.
                info.signature.owned_to_ref(),
                spki,
                self.signed_bytes(),
                signature,
            )
            .map_err(|_| Error::SignatureInvalid)
    }

    /// Everything RFC 5755 §5 asks of an attribute certificate, except
    /// the two certification paths.
    ///
    /// The single entry point. [`Self::check_profile`] and
    /// [`Self::verify`] each do part of §5, and a consumer calling the
    /// obvious pair of them skips rule 3 ([`check_issuer_profile`]) and
    /// rule 6 ([`Self::check_targeting`]) without being told — which
    /// means honouring an attribute certificate scoped to somebody
    /// else's service, a §4.3.2 MUST-reject. This exists so that
    /// omission is not the default shape.
    ///
    /// Runs, in order: the §4.5 profile on `aa_cert`; the §4.2/§4.3
    /// profile and §5 rule 7; the signature, §4.2.8 and the validity
    /// window; §6's revocation scheme per `ac_revocation`; the holder
    /// binding; and targeting.
    ///
    /// # What it still does not do
    ///
    /// **Neither certification path.** §5 rules 1 and 2 require the
    /// holder's and the authority's whole paths to be validated, and
    /// this crate takes no trust anchors — see the crate documentation.
    /// `pkix_chain::verify_attribute_cert` does both and then this.
    ///
    /// §5 rule 4 — that the issuer be "directly trusted as an AC issuer
    /// (by configuration or otherwise)" — remains the caller's.
    /// Supplying `aa_cert` is that decision.
    ///
    /// # Errors
    ///
    /// Any error from the calls it makes, in the order above —
    /// [`Error::ProfileViolation`], [`Error::IssuerMismatch`],
    /// [`Error::NotYetValid`], [`Error::Expired`],
    /// [`Error::SignatureInvalid`],
    /// [`Error::UnsupportedCriticalExtension`] or
    /// [`Error::ParseError`].
    ///
    /// Then the three this function raises itself, the predicates
    /// behind them returning `bool` rather than `Result`:
    /// [`Error::RevocationUnsupported`] when `ac_revocation` is
    /// [`AcRevocation::NeverRevokeOnly`] and the AC carries no
    /// `noRevAvail`, [`Error::HolderMismatch`] when the AC names
    /// someone other than `holder_cert`, and [`Error::NotATarget`] when the AC names targets and
    /// `my_names`/`my_groups` are not among them — §4.3.2's "an
    /// (honest) AC verifier who is not amongst the named
    /// servers/services MUST reject the AC".
    // Eight, counting &self. Consistent with `pkix-chain`'s use-case
    // wrappers, which carry the same allow: §5 needs both certificates,
    // the evaluation time, the verifier's own names and groups, the §6
    // scheme and a signature verifier, and bundling them into a context
    // struct would hide which of them the caller is being asked to
    // decide. The §6 parameter in particular is a decision that should
    // be visible at the call site.
    #[allow(clippy::too_many_arguments)]
    pub fn validate<V: SignatureVerifier>(
        &self,
        aa_cert: &Certificate,
        holder_cert: &Certificate,
        now_unix: u64,
        my_names: &[GeneralName],
        my_groups: &[GeneralName],
        ac_revocation: AcRevocation,
        verifier: &V,
    ) -> Result<Targeting> {
        check_issuer_profile(aa_cert)?;
        self.check_profile()?;
        self.verify(aa_cert, now_unix, verifier)?;

        // §6. This function establishes no AC revocation status, so
        // `NeverRevokeOnly` is what it supports, and an AC without
        // `noRevAvail` must be refused under it. Omitting this was the
        // whole hazard `validate` exists to remove, reproduced inside
        // `validate`: `pkix-chain`'s wrapper enforced the rule while
        // this did not.
        // A `match`, not an equality test: `AcRevocation` is
        // `#[non_exhaustive]`, and `== NeverRevokeOnly` would let a
        // third variant added later skip §6 silently with no compile
        // error. Fail-open by default is the failure mode this whole
        // parameter exists to prevent.
        match ac_revocation {
            AcRevocation::NeverRevokeOnly if !self.no_revocation_available() => {
                return Err(Error::RevocationUnsupported);
            }
            AcRevocation::NeverRevokeOnly | AcRevocation::CallerChecks => {}
        }

        if !self.matches_holder(holder_cert) {
            return Err(Error::HolderMismatch);
        }
        let targeting = self.check_targeting(my_names, my_groups)?;
        if targeting == Targeting::NotATarget {
            return Err(Error::NotATarget);
        }
        Ok(targeting)
    }

    /// Does this attribute certificate belong to the holder of
    /// `holder_cert`?
    ///
    /// RFC 5755 §4.2.2 lets the holder be named either by a reference to
    /// its public-key certificate — issuer and serial — or by name, and
    /// this checks whichever form the AC uses.
    ///
    /// An `entityName` matches either the certificate's subject or one
    /// of its `subjectAltName` values, as §4.2.2 requires. Checking only
    /// the subject would restrict the form to distinguished names, and
    /// an AC naming its holder by DNS name or mailbox has nowhere else
    /// to match — nor does one whose holder has an empty subject DN,
    /// which RFC 5280 requires a `subjectAltName` for.
    ///
    /// Names compare under RFC 5280 §7.1 via
    /// [`pkix_path::names_match`], not byte equality, so a holder whose
    /// distinguished name differs from the certificate's only in string
    /// type, letter case or insignificant whitespace still matches. That
    /// is the same comparator the chain walker uses, which is the point:
    /// a name `pkix-path` was willing to link must not be a name this
    /// function calls a mismatch.
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
                [GeneralName::DirectoryName(name)]
                    if pkix_path::names_match(name, tbs.issuer())
            );
            // §4.2.2: "The AC holder.baseCertificateID.issuerUID field
            // MUST only be used if the holder's PKC contains an
            // issuerUniqueID field. If both ... are present, the same
            // value MUST be present in both fields." Neither half was
            // checked, so an AC could carry a uid the holder's
            // certificate did not, or a different one, and still match.
            let uid_matches = match (&base.issuer_uid, tbs.issuer_unique_id()) {
                (None, _) => true,
                (Some(ac_uid), Some(pkc_uid)) => ac_uid == pkc_uid,
                (Some(_), None) => false,
            };
            // Serial numbers compare as DER INTEGERs, which have one
            // canonical encoding per value, so bytes are the value here.
            return issuer_matches
                && uid_matches
                && base.serial.as_bytes() == tbs.serial_number().as_bytes();
        }
        if let Some([name]) = holder.entity_name.as_deref() {
            // §4.2.2: "the entityName MUST be the same as the PKC
            // subject field OR ONE OF THE VALUES OF THE PKC
            // subjectAltName field extension (if present)".
            //
            // Only the subject was checked, which quietly restricted
            // this branch to directoryName entityNames: an AC naming
            // its holder by dNSName or rfc822Name — both ordinary, and
            // the only option when the subject is an empty DN, which
            // RFC 5280 requires a subjectAltName for — could never
            // match anything.
            if let GeneralName::DirectoryName(dn) = name {
                if pkix_path::names_match(dn, tbs.subject()) {
                    return true;
                }
            }
            return subject_alt_names(holder_cert)
                .is_some_and(|sans| sans.iter().any(|san| general_names_match(name, san)));
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
    ///
    /// **Presence only.** §4.3.6 gives the extension the syntax `NULL`,
    /// and this does not check the value —
    /// [`Self::check_extensions`] does. So on a certificate that has
    /// not been through `check_profile` or [`Self::validate`], a `true`
    /// here means the OID is present and not that the issuer made a
    /// well-formed "never revoke" assertion.
    #[must_use]
    pub fn no_revocation_available(&self) -> bool {
        self.extension(&ID_CE_NO_REV_AVAIL).is_some()
    }

    /// The `auditIdentity` value — RFC 5755 §4.3.1 — if present.
    ///
    /// An opaque identifier for audit logs, deliberately not the
    /// holder's name, so that logs can be correlated without recording
    /// who the holder was. Returned as the `OCTET STRING`'s contents —
    /// the value itself, with no ASN.1 header — because correlating on
    /// anything else would key on bytes specific to this implementation.
    ///
    /// `None` if the extension is absent or its value is not an
    /// `OCTET STRING`; [`Self::check_extensions`] refuses the latter
    /// outright.
    #[must_use]
    pub fn audit_identity(&self) -> Option<&[u8]> {
        let e = self.extension(&ID_PE_AC_AUDIT_IDENTITY)?;
        // The OCTET STRING's contents. `extn_value` is its DER, and
        // handing that back gave callers an ASN.1 header on the front of
        // an identifier they are meant to correlate logs on — bytes no
        // other implementation produces for the same AC.
        octet_string_value(e.extn_value.as_bytes())
    }

    fn extension(&self, oid: &ObjectIdentifier) -> Option<&x509_cert::ext::Extension> {
        self.inner
            .acinfo
            .extensions
            .as_ref()?
            .iter()
            .find(|e| &e.extn_id == oid)
    }

    /// Apply RFC 5755 §5 rule 7, the §4.3 criticality rules, and the
    /// §4.3/§6 extension-value rules.
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
    ///   criticality, or a malformed value. The value rules: an
    ///   `auditIdentity` of illegal length, a `noRevAvail` that is not
    ///   NULL, a duplicate extension, a `targetCert` used as a target,
    ///   a malformed `authorityInfoAccess`, and §6's refusal of
    ///   `noRevAvail` beside a revocation pointer.
    pub fn check_extensions(&self) -> Result<()> {
        let Some(exts) = self.inner.acinfo.extensions.as_ref() else {
            return Ok(());
        };

        // RFC 5280 §4.2 — not RFC 5755, which says nothing about it:
        // "a certificate MUST NOT include more than one instance of a
        // particular extension". Two instances let two implementations
        // read one certificate differently, which is the whole reason
        // the rule exists.
        for (i, e) in exts.iter().enumerate() {
            if exts[i + 1..].iter().any(|o| o.extn_id == e.extn_id) {
                return Err(Error::ProfileViolation(
                    ProfileViolation::DuplicateExtension,
                ));
            }
        }

        // §6: "An AC MUST NOT contain both a noRevAvail extension and a
        // 'pointer in AC'." The two schemes are alternatives — one says
        // no revocation information exists, the other says where to find
        // it — so an AC asserting both has not chosen, and a verifier
        // reading only the first it looks at would differ from one
        // reading the other.
        let has_no_rev_avail = exts.iter().any(|e| e.extn_id == ID_CE_NO_REV_AVAIL);

        // Every AIA value is decoded BEFORE the §6 pointer test below,
        // because that test has to read the extension to tell a
        // revocation pointer from a `caIssuers`-only AIA, and a value
        // it cannot decode would read as "no pointer".
        //
        // This check used to sit in the per-extension loop further
        // down — after the pointer test, not before it. The AC was
        // still refused, both being in this one function, but by the
        // syntax rule rather than §6's, so `NoRevAvailWithPointer` was
        // never the reported error and the ordering the safety
        // argument rested on was the reverse of the real one. Hoisted
        // so the mechanism matches the claim.
        //
        // The grammar is RFC 5280 §4.2.2.1. RFC 5755 §4.3.4 says only
        // that AIA "MAY be used" and makes `id-ad-caIssuers` support
        // OPTIONAL; it states no syntax rule.
        for e in exts.iter() {
            if e.extn_id == ID_PE_AUTHORITY_INFO_ACCESS {
                let aia = x509_cert::ext::pkix::AuthorityInfoAccessSyntax::from_der(
                    e.extn_value.as_bytes(),
                )
                .map_err(|_| {
                    Error::ProfileViolation(ProfileViolation::AuthorityInfoAccessMalformed)
                })?;
                // `AuthorityInfoAccessSyntax` is
                // `SEQUENCE SIZE (1..MAX) OF AccessDescription`, and
                // `der` does not enforce the lower bound: an empty
                // SEQUENCE decodes Ok. Same class as the empty-DN and
                // empty-GeneralNames cases this crate already rejects.
                if aia.0.is_empty() {
                    return Err(Error::ProfileViolation(
                        ProfileViolation::AuthorityInfoAccessMalformed,
                    ));
                }
            }
        }
        // A revocation pointer specifically — and this is an
        // interpretation that relaxes a literal MUST, not a reading of
        // what §6 says. §6 defines the scheme at EXTENSION
        // granularity: ACs may "'point' to sources of revocation
        // status information, using either an authorityInfoAccess
        // extension or a crlDistributionPoints extension within the
        // AC". Taken literally, `noRevAvail` beside any AIA violates
        // "MUST NOT contain both".
        //
        // Narrowed to the OCSP accessMethod because an AIA carrying
        // only `id-ad-caIssuers` points at the issuer's certificate
        // rather than at revocation status, so refusing it serves
        // nothing §6 is protecting. §4.3.4 supports reading the two
        // apart — it makes caIssuers support OPTIONAL — though its
        // stated reason is "since AC chains are not expected" rather
        // than the distinction drawn here.
        let has_pointer = exts.iter().any(|e| {
            e.extn_id == ID_CE_CRL_DISTRIBUTION_POINTS
                || (e.extn_id == ID_PE_AUTHORITY_INFO_ACCESS
                    && aia_names_ocsp(e.extn_value.as_bytes()))
        });
        if has_no_rev_avail && has_pointer {
            return Err(Error::ProfileViolation(
                ProfileViolation::NoRevAvailWithPointer,
            ));
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
                    // The VALUE's length, not the extension value's.
                    // `extn_value` is the DER of an OCTET STRING, so
                    // `as_bytes().len()` is two more than the octet
                    // count for short values — which put the window at
                    // 1..=18 real octets and let the one length §4.3.1
                    // forbids, zero, through as a two-byte `04 00`.
                    //
                    // §4.3.1: "the value of an audit identity MUST be
                    // longer than zero octets. The value of an audit
                    // identity MUST NOT be longer than 20 octets."
                    let value = octet_string_value(e.extn_value.as_bytes()).ok_or(
                        Error::ProfileViolation(ProfileViolation::AuditIdentityNotOctetString),
                    )?;
                    let len = value.len();
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
                    // Parsing it was not enough. §5 defines support for
                    // an extension as being able to parse the value AND
                    // honouring a rejection the value implies, and
                    // §4.3.2 says `targetCert` MUST NOT be used — so an
                    // AC carrying one has to be refused here, not only
                    // by `check_targeting`, which a caller may never
                    // reach.
                    //
                    // It also restores the reachability argument for
                    // `otherObjectTypes`: a `TargetCert` carries an
                    // `ObjectDigestInfo`, so leaving this to
                    // `check_targeting` left one route by which a
                    // profile-checked certificate could hold one.
                    for target in self.parse_targets()? {
                        if matches!(target, types::Target::TargetCert(_)) {
                            return Err(Error::ProfileViolation(ProfileViolation::TargetCertUsed));
                        }
                    }
                }
                // §4.3.6: criticality MUST be FALSE, and the syntax is
                // "NULL (i.e., '0500'H is the DER encoding)".
                ID_CE_NO_REV_AVAIL => {
                    if e.critical {
                        return Err(Error::ProfileViolation(
                            ProfileViolation::NoRevAvailCritical,
                        ));
                    }
                    // The value was never checked, so an AC carrying
                    // `noRevAvail` with a body of junk satisfied
                    // `no_revocation_available()` — a caller keyed on
                    // that accessor would skip revocation on an AC that
                    // never made the "never revoke" assertion.
                    if e.extn_value.as_bytes() != [0x05, 0x00] {
                        return Err(Error::ProfileViolation(ProfileViolation::NoRevAvailNotNull));
                    }
                }
                // Profiled by §4.3.3 and §4.3.5, and not acted on
                // beyond criticality: they assist a verifier in
                // finding the issuer's certificate or its revocation
                // data, which is the caller's job in this workspace.
                // Neither may be critical in a conforming AC, and if
                // one is, the rule below refuses it rather than this
                // arm waving it through.
                //
                // §4.3.4's authorityInfoAccess was once in this arm
                // and now has its own, because the §6 pointer test
                // made its value significant.
                ID_CE_AUTHORITY_KEY_IDENTIFIER | ID_CE_CRL_DISTRIBUTION_POINTS => {
                    if e.critical {
                        return Err(Error::UnsupportedCriticalExtension(e.extn_id));
                    }
                }
                ID_PE_AUTHORITY_INFO_ACCESS => {
                    if e.critical {
                        return Err(Error::UnsupportedCriticalExtension(e.extn_id));
                    }
                    // The value is checked above, before the §6
                    // pointer test that depends on it.
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
    /// Names compare by form rather than by bytes: `directoryName`
    /// under RFC 5280 §7.1, `dNSName` case-insensitively per RFC 4343,
    /// `rfc822Name` with a case-insensitive domain and an exact local
    /// part. A verifier that is the named target must not be told it is
    /// not because the AC spelled its name in a different string type.
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
                    if my_names.iter().any(|mine| general_names_match(n, mine)) {
                        matched = true;
                    }
                }
                types::Target::TargetGroup(g) => {
                    if my_groups.iter().any(|mine| general_names_match(g, mine)) {
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

/// A certificate's `subjectAltName` values, if it has the extension.
///
/// Needed because RFC 5755 §4.2.2 lets a holder's `entityName` match
/// either the subject or one of these, and an AC that names its holder
/// by anything other than a distinguished name has no other way to.
fn subject_alt_names(cert: &Certificate) -> Option<alloc::vec::Vec<GeneralName>> {
    const OID_SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");
    let exts = cert.tbs_certificate().extensions()?;
    // Counted, not found: two subjectAltName extensions would let two
    // implementations read one certificate differently, the same hazard
    // this crate refuses elsewhere. RFC 5280 §4.2 forbids the repeat, so
    // treat such a certificate as having no usable names rather than
    // picking one.
    let mut matching = exts.iter().filter(|e| e.extn_id == OID_SUBJECT_ALT_NAME);
    let ext = matching.next()?;
    if matching.next().is_some() {
        return None;
    }
    x509_cert::ext::pkix::SubjectAltName::from_der(ext.extn_value.as_bytes())
        .ok()
        .map(|san| san.0)
}

/// Whether an `authorityInfoAccess` value names `id-ad-ocsp`.
///
/// §6's "pointer in AC" scheme points at revocation status, and inside
/// an AIA that is the OCSP access method. An AIA holding only
/// `id-ad-caIssuers` points at the issuer's certificate instead, which
/// §4.3.4 treats as a separate and optional feature.
///
/// Only ever called on a value already decoded once:
/// [`AttributeCertificate::check_extensions`] rejects an undecodable
/// AIA in a pass that runs before the §6 pointer test, so by here a
/// `false` means "decodes, and names no OCSP access method" rather
/// than "could not be read".
///
/// That ordering is load-bearing, and two earlier versions of this
/// comment got it wrong — the first asserting a check that did not
/// exist, the second asserting an order that was reversed. If the
/// pointer test is ever moved out of `check_extensions`, the
/// validation pass has to move with it.
fn aia_names_ocsp(value: &[u8]) -> bool {
    const ID_AD_OCSP: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1");
    x509_cert::ext::pkix::AuthorityInfoAccessSyntax::from_der(value)
        .is_ok_and(|aia| aia.0.iter().any(|ad| ad.access_method == ID_AD_OCSP))
}

/// Compare two `GeneralName`s the way their own name forms require.
///
/// Byte equality is wrong here for the same reason it was wrong for the
/// issuer and holder names: a name can be re-encoded without becoming a
/// different name. The forms differ in how:
///
/// - `directoryName` compares under RFC 5280 §7.1 via
///   [`pkix_path::names_match`], so string type, letter case and
///   insignificant whitespace do not matter.
/// - `dNSName` is case-insensitive (RFC 4343, "domain name system case
///   insensitivity clarification"), ASCII-folded.
/// - `rfc822Name`'s domain half is likewise case-insensitive, while its
///   local part is not — RFC 5280 §4.2.1.6 says to compare the local
///   part exactly.
/// - Everything else falls back to byte equality, which is what the
///   remaining forms give us no basis to relax.
///
/// Getting this wrong fails closed and looks like a configuration
/// error: a verifier that *is* the named target is told it is not, for
/// the one deployment the AC was issued for.
fn general_names_match(a: &GeneralName, b: &GeneralName) -> bool {
    use GeneralName as G;
    match (a, b) {
        (G::DirectoryName(x), G::DirectoryName(y)) => pkix_path::names_match(x, y),
        (G::DnsName(x), G::DnsName(y)) => x.as_str().eq_ignore_ascii_case(y.as_str()),
        (G::Rfc822Name(x), G::Rfc822Name(y)) => {
            let (xs, ys) = (x.as_str(), y.as_str());
            match (xs.rsplit_once('@'), ys.rsplit_once('@')) {
                (Some((xl, xd)), Some((yl, yd))) => xl == yl && xd.eq_ignore_ascii_case(yd),
                // No '@' in one or both: nothing to split on, so compare
                // whole rather than guess which half is which.
                _ => xs == ys,
            }
        }
        _ => a == b,
    }
}

/// The contents of `input`, if `input` is exactly one DER `OCTET STRING`.
///
/// Borrowed rather than decoded into `der`'s owned `OctetString`,
/// because the accessor hands the value straight out and an allocation
/// per call to read 20 bytes would be silly. Reuses [`header`], so a
/// non-minimal or over-long length is refused here too.
///
/// `None` unless the whole of `input` is one `OCTET STRING`: trailing
/// bytes after it mean the extension value is not what it claims, and
/// accepting them would make the length check describe only the first
/// part of it.
fn octet_string_value(input: &[u8]) -> Option<&[u8]> {
    const TAG_OCTET_STRING: u8 = 0x04;
    if input.first() != Some(&TAG_OCTET_STRING) {
        return None;
    }
    let (value_len, header_len) = header(input)?;
    let end = header_len.checked_add(value_len)?;
    if end != input.len() {
        return None;
    }
    input.get(header_len..end)
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
        // `|` and `^` are the same operation here, because the shift
        // leaves the low eight bits zero and `b` touches only those. A
        // mutation sweep reports the `^` form as surviving; it is
        // equivalent, not untested.
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
///   public key cannot be used to validate a digital signature". So a
///   present `keyUsage` must assert `digitalSignature` or
///   `nonRepudiation` — per RFC 5280 §4.2.1.3 both denote verifying
///   signatures, differing in purpose rather than in capability. An
///   absent extension constrains nothing.
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

    // Counted, not found. `find` takes the first of several, so a
    // certificate carrying basicConstraints twice — cA=FALSE then
    // cA=TRUE — passed as an attribute authority, which is fail-open on
    // the one rule §4.5 exists to enforce. `pkix-path` rejects duplicate
    // extensions outright, so the composed path was covered; this
    // function is documented as usable standalone, and was not.
    for oid in [OID_BASIC_CONSTRAINTS, OID_KEY_USAGE] {
        if exts.iter().filter(|e| e.extn_id == oid).count() > 1 {
            return Err(Error::ProfileViolation(
                ProfileViolation::IssuerDuplicateExtension,
            ));
        }
    }

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
        // §4.5 forbids only a keyUsage that "explicitly indicate[s]
        // that the AC issuer's public key cannot be used to validate a
        // digital signature". Requiring `digitalSignature` specifically
        // refused an authority whose keyUsage asserts only
        // `nonRepudiation` (contentCommitment) — a bit that per RFC 5280
        // §4.2.1.3 also denotes verifying signatures, just for a
        // different purpose. Either bit means the key may validate one.
        if !ku.digital_signature() && !ku.non_repudiation() {
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
    /// §4.2.3: `issuerName`'s `directoryName` is an empty distinguished
    /// name, where the profile requires a non-empty one — "all AC
    /// issuers MUST have non-empty distinguished names".
    IssuerNameEmptyDn,
    /// §4.2.3: `issuerName` is not a `directoryName`, the only form that
    /// can be compared against a certificate's subject.
    IssuerNameNotDirectoryName,
    /// §4.2.3: `baseCertificateID` or `objectDigestInfo` appeared in the
    /// v2 form, where neither is permitted.
    IssuerExtraFields,
    /// §4.2.8: the AC's `issuerUniqueID` and the Attribute Authority's
    /// own unique identifier disagree — one is present without the
    /// other, or they hold different values. It "MUST NOT be used
    /// unless it is also used in the AC issuer's PKC, in which case it
    /// MUST be used".
    ///
    /// The authority's identifier is its certificate's
    /// `subjectUniqueID`, since the authority is that certificate's
    /// subject. Comparing against its `issuerUniqueID` would be asking
    /// about the authority's CA instead.
    ///
    /// Checked by [`AttributeCertificate::verify`] rather than
    /// [`AttributeCertificate::check_profile`], because it needs the
    /// authority's certificate and `check_profile` has none.
    IssuerUniqueIdMismatch,
    /// §4.2.2: the holder gives both `baseCertificateID` and
    /// `entityName`, so which identifies it is ambiguous.
    HolderAmbiguous,
    /// §4.2.2: the holder gives neither.
    HolderMissing,
    /// §4.2.2: the holder's `entityName` carries more than one name.
    /// Zero names is [`Self::HolderNameEmpty`].
    ///
    /// Stricter than the RFC, deliberately. §4.2.2 says "only one name
    /// SHOULD be present", not MUST — but several names leave which one
    /// identifies the holder undetermined, and deciding that for a
    /// caller is exactly what this crate refuses to do elsewhere. A
    /// verifier that picked one would differ from a verifier that picked
    /// another about the same certificate.
    HolderNameNotSingular,
    /// §4.1: the holder used `objectDigestInfo`, which this profile does
    /// not cover.
    HolderObjectDigestInfo,
    /// §4.2.5: the serial number's DER encoding has its sign bit set,
    /// where "AC issuers MUST force the serialNumber to be a positive
    /// integer".
    SerialNotPositive,
    /// §4.2.5: the serial number is zero, though the field "MUST be a
    /// positive integer".
    ///
    /// Distinct from [`Self::SerialNotPositive`], which is a sign-bit
    /// violation. Zero's sign bit is clear, so reporting it as
    /// negative would tell a caller the opposite of what happened.
    SerialZero,
    /// §4.2.5: the serial number is longer than 20 octets, where
    /// "conformant ACs MUST NOT contain serialNumber values longer than
    /// 20 octets".
    SerialTooLong,
    /// §4.2.2: the holder's `entityName` is present and carries no
    /// names at all, which `GeneralNames ::= SEQUENCE SIZE (1..MAX)`
    /// also forbids.
    HolderNameEmpty,
    /// §4.1: `attributes` is empty, though one is required.
    NoAttributes,
    /// §4.1: an attribute carries no values, though one is required.
    AttributeWithoutValues,
    /// §4.2.7: two attributes share an `AttributeType` OID, where "only
    /// one instance of each attribute can occur in a single AC, but each
    /// instance can be multi-valued".
    DuplicateAttributeType,
    /// RFC 5280 §4.2: the same extension appears more than once. Every
    /// other bare § in this enumeration is RFC 5755; this one is not,
    /// because RFC 5755 does not state the rule.
    DuplicateExtension,
    /// §4.3.1: `auditIdentity` is not marked critical, though it must be.
    AuditIdentityNotCritical,
    /// §4.3.1: `auditIdentity`'s value is empty or longer than 20
    /// octets.
    AuditIdentityLength,
    /// §4.3.1: `auditIdentity`'s extension value is not an
    /// `OCTET STRING`, which is the syntax the section gives it.
    AuditIdentityNotOctetString,
    /// §4.3.2: `targetInformation` is not marked critical, though it
    /// must be.
    TargetInformationNotCritical,
    /// §4.3.6: `noRevAvail` is marked critical, though it must not be.
    NoRevAvailCritical,
    /// §4.3.6: `noRevAvail`'s value is not `NULL` — the section gives
    /// the syntax as "NULL (i.e., `'0500'H` is the DER encoding)".
    NoRevAvailNotNull,
    /// §6: the AC carries both `noRevAvail` and a "pointer in AC"
    /// (`crlDistributionPoints` or `authorityInfoAccess`), where "an AC
    /// MUST NOT contain both".
    NoRevAvailWithPointer,
    /// §4.3.2: a target used `targetCert`, which MUST NOT be used.
    TargetCertUsed,
    /// §4.5: the Attribute Authority's certificate is a CA
    /// (`basicConstraints.cA` is TRUE). An AC issuer must not also be a
    /// PKC issuer.
    IssuerIsACa,
    /// §4.5: the Attribute Authority's `keyUsage` asserts neither
    /// `digitalSignature` nor `nonRepudiation`, so it excludes using
    /// that key to validate the signature it just made.
    IssuerCannotSign,
    /// §4.5: the Attribute Authority's `basicConstraints` or `keyUsage`
    /// extension will not decode.
    IssuerExtensionMalformed,
    /// RFC 5280 §4.2: the Attribute Authority's certificate carries
    /// `basicConstraints` or `keyUsage` more than once, so which copy
    /// §4.5 applies to is not determined.
    IssuerDuplicateExtension,
    /// RFC 5280 §4.2.2.1: the AC's `authorityInfoAccess` value is not
    /// a well-formed, non-empty `AuthorityInfoAccessSyntax`.
    ///
    /// The grammar is RFC 5280's. RFC 5755 §4.3.4 only says AIA "MAY
    /// be used" and makes `id-ad-caIssuers` support OPTIONAL; it
    /// states no syntax rule, so citing it here was wrong.
    ///
    /// Checked because §6's pointer test must decode it to tell a
    /// revocation pointer from a `caIssuers`-only AIA. A value that
    /// will not decode would otherwise read as "no pointer" and let an
    /// AC carry both `noRevAvail` and a pointer.
    AuthorityInfoAccessMalformed,
}

impl core::fmt::Display for ProfileViolation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::IssuerV1Form => "issuer uses v1Form, which RFC 5755 §4.2.3 forbids",
            Self::IssuerNameMissing => "issuerName is absent or empty (RFC 5755 §4.2.3)",
            Self::IssuerNameNotSingular => "issuerName carries more than one name",
            Self::IssuerNameEmptyDn => {
                "issuerName's directoryName is empty, though RFC 5755 §4.2.3 requires \
                 a non-empty distinguished name"
            }
            Self::IssuerNameNotDirectoryName => "issuerName is not a directoryName",
            Self::IssuerExtraFields => {
                "v2Form carries baseCertificateID or objectDigestInfo, which §4.2.3 forbids"
            }
            Self::IssuerUniqueIdMismatch => {
                "issuerUniqueID is present on only one of the AC and the authority's \
                 certificate, where RFC 5755 §4.2.8 requires both or neither"
            }
            Self::HolderAmbiguous => "holder gives both baseCertificateID and entityName",
            Self::HolderMissing => "holder gives neither baseCertificateID nor entityName",
            Self::HolderNameNotSingular => "holder carries more than one name",
            Self::HolderObjectDigestInfo => "holder uses objectDigestInfo, which is not profiled",
            Self::SerialZero => {
                "the serial number is zero, though RFC 5755 §4.2.5 requires a positive integer"
            }
            Self::SerialNotPositive => {
                "the serial number is negative, though RFC 5755 §4.2.5 requires a \
                 positive integer"
            }
            Self::SerialTooLong => {
                "the serial number is longer than the 20 octets RFC 5755 §4.2.5 permits"
            }
            Self::HolderNameEmpty => {
                "the holder's entityName is present but carries no names (RFC 5755 §4.2.2)"
            }
            Self::NoAttributes => "no attributes, though RFC 5755 §4.1 requires at least one",
            Self::AttributeWithoutValues => "an attribute carries no values",
            Self::DuplicateAttributeType => {
                "two attributes share one type OID, though RFC 5755 §4.2.7 requires \
                 each to be unique and multi-valued instead"
            }
            Self::DuplicateExtension => "the same extension appears more than once",
            Self::AuditIdentityNotCritical => {
                "auditIdentity is not critical, though RFC 5755 §4.3.1 requires it to be"
            }
            Self::AuditIdentityLength => {
                "auditIdentity's value must be between 1 and 20 octets (RFC 5755 §4.3.1)"
            }
            Self::AuditIdentityNotOctetString => {
                "auditIdentity's value is not an OCTET STRING (RFC 5755 §4.3.1)"
            }
            Self::TargetInformationNotCritical => {
                "targetInformation is not critical, though RFC 5755 §4.3.2 requires it to be"
            }
            Self::NoRevAvailCritical => {
                "noRevAvail is critical, though RFC 5755 §4.3.6 requires it not to be"
            }
            Self::NoRevAvailNotNull => {
                "noRevAvail's value is not NULL (RFC 5755 §4.3.6 gives it as '0500'H)"
            }
            Self::NoRevAvailWithPointer => {
                "the AC carries both noRevAvail and a revocation pointer, which \
                 RFC 5755 §6 forbids"
            }
            Self::TargetCertUsed => "a target used targetCert, which RFC 5755 §4.3.2 forbids",
            Self::IssuerIsACa => {
                "the attribute authority's certificate is a CA, which RFC 5755 §4.5 forbids"
            }
            Self::IssuerCannotSign => {
                "the attribute authority's keyUsage asserts neither digitalSignature nor \
                 nonRepudiation (RFC 5755 §4.5)"
            }
            Self::IssuerExtensionMalformed => {
                "the attribute authority's basicConstraints or keyUsage will not decode"
            }
            Self::AuthorityInfoAccessMalformed => {
                "the authorityInfoAccess extension value is malformed (RFC 5280 §4.2.2.1)"
            }
            Self::IssuerDuplicateExtension => {
                "the attribute authority's certificate repeats basicConstraints or keyUsage"
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
    /// The outer `signatureAlgorithm` does not match the `signature`
    /// field inside `acinfo`.
    ///
    /// `acinfo` is the signed region, so the inner field is covered by
    /// the signature and the outer one is not. A mismatch means someone
    /// rewrote the unprotected copy, and verifying under it would let
    /// them choose the algorithm the check runs with. RFC 5280 §4.1.1.2
    /// requires the two to be equal.
    SignatureAlgorithmMismatch,
    /// The attribute certificate carries no `noRevAvail`, and the
    /// verifier supports only RFC 5755 §6's "never revoke" scheme.
    ///
    /// §6: "if only the 'never revoke' scheme is supported, then all ACs
    /// that do not contain a noRevAvail extension, MUST be rejected."
    /// An AC without the extension is its issuer stating that revocation
    /// status checks are supported and some method is provided, so
    /// honouring it without checking anything accepts a credential its
    /// issuer expected to be checkable.
    RevocationUnsupported,
    /// The attribute certificate is targeted at verifiers this one is
    /// not among — RFC 5755 §4.3.2.
    ///
    /// [`AttributeCertificate::check_targeting`] reports this as
    /// [`Targeting::NotATarget`] rather than an error, because an audit
    /// tool may legitimately want to read an AC not addressed to it.
    /// This variant is for the composed check, where §4.3.2's "MUST
    /// reject the AC" applies.
    NotATarget,
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
            Self::SignatureAlgorithmMismatch => f.write_str(
                "outer signatureAlgorithm differs from the signature field inside acinfo",
            ),
            Self::RevocationUnsupported => f.write_str(
                "attribute certificate carries no noRevAvail and no revocation scheme \
                 is supported for it",
            ),
            Self::NotATarget => {
                f.write_str("attribute certificate is targeted at another verifier")
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    // Not in the prelude: this crate is `no_std`, and only the `std`
    // feature pulls in a prelude carrying `ToString`. The
    // default-feature test job is what notices.
    use alloc::string::ToString as _;

    /// Every [`ProfileViolation`] renders a reason that names its rule.
    ///
    /// Inside the crate deliberately. `ProfileViolation` is
    /// `#[non_exhaustive]`, so a `match` in an integration test needs a
    /// wildcard arm and would quietly stop covering new variants — which
    /// is what happened: the previous version of this test lived in
    /// `tests/validate.rs`, listed 11 of the 21 variants, and the rest
    /// were added after it without anyone noticing.
    ///
    /// Here the `match` has no wildcard, so adding a variant stops this
    /// crate's own tests compiling until it is listed. The drift is
    /// prevented rather than periodically repaired — and it caught a
    /// mistake in its own construction immediately, since the list was
    /// first generated by a pattern that excluded digits and so missed
    /// `IssuerV1Form`.
    #[test]
    fn every_profile_violation_renders_a_reason() {
        use ProfileViolation as V;

        let all = [
            V::IssuerV1Form,
            V::IssuerNameMissing,
            V::IssuerNameNotSingular,
            V::IssuerNameEmptyDn,
            V::IssuerNameNotDirectoryName,
            V::IssuerExtraFields,
            V::IssuerUniqueIdMismatch,
            V::HolderAmbiguous,
            V::HolderMissing,
            V::HolderNameNotSingular,
            V::HolderObjectDigestInfo,
            V::SerialNotPositive,
            V::SerialTooLong,
            V::HolderNameEmpty,
            V::NoAttributes,
            V::AttributeWithoutValues,
            V::DuplicateAttributeType,
            V::DuplicateExtension,
            V::AuditIdentityNotCritical,
            V::AuditIdentityLength,
            V::AuditIdentityNotOctetString,
            V::TargetInformationNotCritical,
            V::NoRevAvailCritical,
            V::NoRevAvailNotNull,
            V::NoRevAvailWithPointer,
            V::TargetCertUsed,
            V::IssuerIsACa,
            V::IssuerCannotSign,
            V::IssuerExtensionMalformed,
            V::IssuerDuplicateExtension,
            V::AuthorityInfoAccessMalformed,
            V::SerialZero,
        ];

        for v in all {
            // The exhaustive match is the guard. The name it yields is
            // only there to make a failure legible.
            let name = match v {
                V::IssuerV1Form => "IssuerV1Form",
                V::IssuerNameMissing => "IssuerNameMissing",
                V::IssuerNameNotSingular => "IssuerNameNotSingular",
                V::IssuerNameEmptyDn => "IssuerNameEmptyDn",
                V::IssuerNameNotDirectoryName => "IssuerNameNotDirectoryName",
                V::IssuerExtraFields => "IssuerExtraFields",
                V::IssuerUniqueIdMismatch => "IssuerUniqueIdMismatch",
                V::HolderAmbiguous => "HolderAmbiguous",
                V::HolderMissing => "HolderMissing",
                V::HolderNameNotSingular => "HolderNameNotSingular",
                V::HolderObjectDigestInfo => "HolderObjectDigestInfo",
                V::SerialNotPositive => "SerialNotPositive",
                V::SerialTooLong => "SerialTooLong",
                V::HolderNameEmpty => "HolderNameEmpty",
                V::NoAttributes => "NoAttributes",
                V::AttributeWithoutValues => "AttributeWithoutValues",
                V::DuplicateAttributeType => "DuplicateAttributeType",
                V::DuplicateExtension => "DuplicateExtension",
                V::AuditIdentityNotCritical => "AuditIdentityNotCritical",
                V::AuditIdentityLength => "AuditIdentityLength",
                V::AuditIdentityNotOctetString => "AuditIdentityNotOctetString",
                V::TargetInformationNotCritical => "TargetInformationNotCritical",
                V::NoRevAvailCritical => "NoRevAvailCritical",
                V::NoRevAvailNotNull => "NoRevAvailNotNull",
                V::NoRevAvailWithPointer => "NoRevAvailWithPointer",
                V::TargetCertUsed => "TargetCertUsed",
                V::IssuerIsACa => "IssuerIsACa",
                V::IssuerCannotSign => "IssuerCannotSign",
                V::IssuerExtensionMalformed => "IssuerExtensionMalformed",
                V::IssuerDuplicateExtension => "IssuerDuplicateExtension",
                V::AuthorityInfoAccessMalformed => "AuthorityInfoAccessMalformed",
                V::SerialZero => "SerialZero",
            };
            let rendered = Error::ProfileViolation(v).to_string();
            assert!(
                rendered.starts_with("RFC 5755 profile violation: "),
                "{name} rendered as {rendered:?}"
            );
            assert!(
                rendered.len() > 45,
                "{name} must say which rule broke, got {rendered:?}"
            );
        }
    }
    // -----------------------------------------------------------------
    // general_names_match
    // -----------------------------------------------------------------
    //
    // This decides whether an AC's holder `entityName`, or a target
    // name, is the same name as one the verifier presents. RFC 5755
    // §4.2.2 and §4.3.2 say "the same as", and sameness differs by name
    // form: a DN compares under RFC 4518 prep, a dNSName and the domain
    // half of an rfc822Name are case-insensitive, and nothing else gives
    // a basis to relax byte equality. Each arm is its own rule, and
    // deleting any of them silently falls through to byte equality --
    // which fails closed, so the AC stops matching the holder it was
    // issued for.

    fn dns(name: &str) -> GeneralName {
        GeneralName::DnsName(der::asn1::Ia5String::new(name).expect("ASCII"))
    }

    fn email(addr: &str) -> GeneralName {
        GeneralName::Rfc822Name(der::asn1::Ia5String::new(addr).expect("ASCII"))
    }

    fn uri(value: &str) -> GeneralName {
        GeneralName::UniformResourceIdentifier(der::asn1::Ia5String::new(value).expect("ASCII"))
    }

    fn dn(rdn: &str) -> GeneralName {
        use core::str::FromStr as _;
        GeneralName::DirectoryName(x509_cert::name::Name::from_str(rdn).expect("RFC 4514 DN"))
    }

    /// A `dNSName` compares without regard to case.
    ///
    /// Deleting the arm leaves byte equality, and a verifier presenting
    /// the same host in different case is told it is not the target.
    #[test]
    fn dns_names_compare_case_insensitively() {
        assert!(general_names_match(
            &dns("Holder.Example"),
            &dns("holder.example")
        ));
        assert!(!general_names_match(
            &dns("holder.example"),
            &dns("other.example")
        ));
    }

    /// A `directoryName` compares under the DN rules, not byte equality.
    ///
    /// RFC 4518 case-folds, so two DNs that differ only in the case of an
    /// attribute value are one name. Byte equality says otherwise.
    #[test]
    fn directory_names_compare_as_distinguished_names() {
        assert!(general_names_match(
            &dn("CN=Holder One"),
            &dn("cn=holder one")
        ));
        assert!(!general_names_match(
            &dn("CN=Holder One"),
            &dn("CN=Holder Two")
        ));
    }

    /// An `rfc822Name` is case-sensitive in its local part and
    /// case-insensitive in its domain.
    ///
    /// The local part belongs to the destination host and nothing lets a
    /// verifier fold it; the domain is DNS and does. Both halves are
    /// asserted, because one comparison decides them together: `&&`
    /// loosened to `||` matches any two addresses sharing either half,
    /// which is a different mailbox.
    #[test]
    fn mailbox_domains_fold_case_and_local_parts_do_not() {
        assert!(general_names_match(
            &email("Holder@Example.COM"),
            &email("Holder@example.com")
        ));
        assert!(
            !general_names_match(&email("holder@example.com"), &email("Holder@example.com")),
            "the local part is not case-folded"
        );
        assert!(
            !general_names_match(&email("holder@example.com"), &email("holder@other.com")),
            "a shared local part is not a shared mailbox"
        );
        assert!(
            !general_names_match(&email("holder@example.com"), &email("other@example.com")),
            "a shared domain is not a shared mailbox"
        );
        assert!(general_names_match(
            &email("holder@example.com"),
            &email("holder@example.com")
        ));
    }

    /// An `rfc822Name` with no `@` has no domain half to fold, so it
    /// compares whole.
    ///
    /// Splitting on a separator that is not there would mean guessing
    /// which half is the domain. These are malformed addresses, and the
    /// comparison neither accepts nor invents a reading of them.
    #[test]
    fn a_mailbox_without_an_at_sign_compares_whole() {
        assert!(general_names_match(&email("holder"), &email("holder")));
        assert!(!general_names_match(&email("holder"), &email("Holder")));
        assert!(!general_names_match(
            &email("holder"),
            &email("holder@example.com")
        ));
    }

    /// Every other name form falls back to byte equality.
    ///
    /// There is no relaxation to apply, but the fallback still has to
    /// answer `true` for a name equal to itself -- a URI target that
    /// stopped matching itself would make the AC unusable by the
    /// verifier it names.
    #[test]
    fn other_name_forms_compare_byte_for_byte() {
        assert!(general_names_match(
            &uri("https://holder.example/"),
            &uri("https://holder.example/")
        ));
        assert!(!general_names_match(
            &uri("https://holder.example/"),
            &uri("https://Holder.Example/")
        ));
        assert!(
            !general_names_match(&dns("holder.example"), &email("holder@example.com")),
            "two different forms are never the same name"
        );
    }
    // -----------------------------------------------------------------
    // header / acinfo_range
    // -----------------------------------------------------------------
    //
    // A hand-rolled DER length reader, used to take `acinfo` as a byte
    // range out of the original encoding rather than re-encoding it --
    // those are the bytes the Attribute Authority signed. It is
    // deliberately stricter than it needs to be: a length that `der`
    // would refuse must be refused here too, or the range handed to the
    // signature check covers bytes no AA ever signed.
    //
    // Only the length matters to these, so the tag byte below is an
    // arbitrary 0x30 and the value bytes are mostly absent. `header`
    // reports what the encoding claims; it is the callers that check the
    // claim against the buffer.

    /// A short-form length is the byte itself.
    #[test]
    fn a_short_form_length_is_the_length() {
        assert_eq!(header(&[0x30, 0x00]), Some((0, 2)));
        assert_eq!(header(&[0x30, 0x7F]), Some((0x7F, 2)));
    }

    /// 0x80 is not the length 128.
    ///
    /// It is the long form with no length octets, which DER does not
    /// define (BER's indefinite length). Read as a short form it claims
    /// 128 bytes; read as the long form it is a count of zero, which the
    /// count check refuses.
    #[test]
    fn an_indefinite_length_marker_is_refused() {
        assert_eq!(header(&[0x30, 0x80]), None);
        assert_eq!(header(&[0x30, 0x80, 0x01, 0x02]), None);
    }

    /// The long form carries one to four length octets.
    ///
    /// Four is the most this accepts; five is refused rather than
    /// truncated into a `usize`, because a length that large cannot
    /// describe a certificate anyone signed and silently narrowing it
    /// would produce a range into the middle of the value.
    #[test]
    fn the_long_form_accepts_up_to_four_length_octets() {
        assert_eq!(header(&[0x30, 0x81, 0x80]), Some((0x80, 3)));
        assert_eq!(header(&[0x30, 0x82, 0x01, 0x00]), Some((0x100, 4)));
        assert_eq!(
            header(&[0x30, 0x84, 0x01, 0x00, 0x00, 0x00]),
            Some((0x0100_0000, 6)),
            "four octets is the widest accepted, not the first rejected"
        );
        assert_eq!(
            header(&[0x30, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00]),
            None,
            "five is over-long"
        );
    }

    /// The long form must be minimal.
    ///
    /// A leading zero octet, or a value under 0x80 that the short form
    /// could have carried, is a non-canonical encoding. `der` refuses
    /// both, so accepting them here could only produce a byte range no
    /// Attribute Authority ever signed.
    #[test]
    fn a_non_minimal_long_form_length_is_refused() {
        assert_eq!(
            header(&[0x30, 0x82, 0x00, 0x80]),
            None,
            "a leading zero length octet"
        );
        assert_eq!(
            header(&[0x30, 0x81, 0x7F]),
            None,
            "0x7F fits the short form"
        );
        assert_eq!(
            header(&[0x30, 0x81, 0x80]),
            Some((0x80, 3)),
            "0x80 does not, so the long form is minimal for it"
        );
    }

    /// `acinfo_range` refuses an inner element that claims more bytes
    /// than the outer `SEQUENCE` holds.
    ///
    /// The range it returns is used to slice the signed bytes, so a
    /// claim the buffer cannot support has to be refused and not clamped
    /// -- clamping would hand the signature check a prefix of `acinfo`
    /// and call it the whole.
    #[test]
    fn acinfo_range_refuses_an_inner_length_past_the_outer_value() {
        // Outer SEQUENCE of 3 bytes holding an element claiming 5.
        assert_eq!(acinfo_range(&[0x30, 0x03, 0x30, 0x05, 0x00]), None);
    }

    /// An inner element exactly filling the outer value is in range.
    ///
    /// The comparison is `total > body.len()`, and the boundary is
    /// reachable: it is an outer `SEQUENCE` whose first element is also
    /// its last. Read as `>=` it refuses that, which is one byte of
    /// slack between "fits" and "does not".
    #[test]
    fn acinfo_range_accepts_an_inner_length_that_exactly_fills_the_outer() {
        // Outer SEQUENCE of 2 bytes holding a 2-byte element (tag, len 0).
        assert_eq!(acinfo_range(&[0x30, 0x02, 0x05, 0x00]), Some(2..4));
    }
}
