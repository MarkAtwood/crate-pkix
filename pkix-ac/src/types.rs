//! The RFC 5755 §4.1 ASN.1 structures.
//!
//! `x509-cert` 0.3 models public-key certificates, CRLs and certification
//! requests but not attribute certificates, so these are declared here.
//! They follow the shapes in RFC 5755 Appendix A verbatim, and the module
//! there is `DEFINITIONS IMPLICIT TAGS`, so every context-specific tag
//! below is `IMPLICIT` — unlike RFC 5280's, which are explicit. Getting
//! that backwards does not fail to compile; it fails to parse real
//! certificates, so it is stated here rather than left to be inferred.
//!
//! Profile rules — which fields RFC 5755 forbids even though the syntax
//! permits them — are deliberately not enforced at this layer. Parsing
//! accepts the syntax so that a certificate violating the profile can be
//! read and reported on, with a reason, rather than refused as
//! malformed. The checks belong above this module.

use alloc::vec::Vec;

use der::asn1::{BitString, GeneralizedTime, ObjectIdentifier, SetOfVec};
use der::{Any, Choice, Enumerated, Sequence};
use x509_cert::ext::pkix::name::{GeneralName, GeneralNames};
use x509_cert::ext::Extensions;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::AlgorithmIdentifierOwned;

/// `AttributeCertificate` — RFC 5755 §4.1.
///
/// The signature is over the DER encoding of [`Self::acinfo`]. Verifying
/// it needs those bytes exactly as they arrived, which is why
/// [`crate::AttributeCertificate`] keeps the original DER rather than
/// re-encoding this structure.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct AttributeCertificateInner {
    pub acinfo: AttributeCertificateInfo,
    pub signature_algorithm: AlgorithmIdentifierOwned,
    pub signature_value: BitString,
}

/// `AttributeCertificateInfo` — RFC 5755 §4.1.
///
/// `issuerUniqueID` and `extensions` are both `OPTIONAL` and neither is
/// context-tagged, which is unambiguous only because one is a `BIT
/// STRING` and the other a `SEQUENCE`.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct AttributeCertificateInfo {
    pub version: AttCertVersion,
    pub holder: Holder,
    pub issuer: AttCertIssuer,
    pub signature: AlgorithmIdentifierOwned,
    pub serial_number: SerialNumber,
    pub validity: AttCertValidityPeriod,
    pub attributes: Vec<Attribute>,
    #[asn1(optional = "true")]
    pub issuer_unique_id: Option<BitString>,
    #[asn1(optional = "true")]
    pub extensions: Option<Extensions>,
}

/// `AttCertVersion ::= INTEGER { v2(1) }` — RFC 5755 §4.1.
///
/// The profile requires v2, so there is exactly one legal value. Modelled
/// as an enumeration rather than an integer so that a wrong version is a
/// parse failure at the type level instead of a check someone can forget.
/// Note this is an ASN.1 `INTEGER`, not an `ENUMERATED`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
pub enum AttCertVersion {
    /// The only version this profile permits.
    V2 = 1,
}

/// `Holder` — RFC 5755 §4.1, identifying what the attributes are bound to.
///
/// All three fields are optional in the syntax. §4.2.2 requires exactly
/// one of `baseCertificateID` or `entityName`; that is a profile rule,
/// checked above this layer rather than during parsing.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct Holder {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub base_certificate_id: Option<IssuerSerial>,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub entity_name: Option<GeneralNames>,

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub object_digest_info: Option<ObjectDigestInfo>,
}

/// `AttCertIssuer` — RFC 5755 §4.1.
///
/// A `CHOICE` whose first arm, `v1Form`, the profile forbids (§4.2.3). It
/// is represented rather than dropped so that an AC carrying it parses
/// and can be refused with a reason, instead of failing as malformed.
/// Same for the profile rules on [`V2Form`]'s optional fields.
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
#[allow(missing_docs)]
// The variants differ a lot in size, and boxing the large one is the
// wrong trade here: V2Form is the only form the profile permits, so
// every conforming certificate would pay an allocation to save space on
// a form that exists only to be rejected.
#[allow(clippy::large_enum_variant)]
pub enum AttCertIssuer {
    /// `GeneralNames` — the v1 form. MUST NOT appear in this profile.
    V1Form(GeneralNames),

    /// `[0] V2Form` — the only form this profile permits.
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", constructed = "true")]
    V2Form(V2Form),
}

/// `V2Form` — RFC 5755 §4.1.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct V2Form {
    #[asn1(optional = "true")]
    pub issuer_name: Option<GeneralNames>,

    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub base_certificate_id: Option<IssuerSerial>,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub object_digest_info: Option<ObjectDigestInfo>,
}

/// `IssuerSerial` — RFC 5755 §4.1, a reference to a public-key
/// certificate by issuer and serial.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct IssuerSerial {
    pub issuer: GeneralNames,
    pub serial: SerialNumber,

    #[asn1(optional = "true")]
    pub issuer_uid: Option<BitString>,
}

/// `ObjectDigestInfo` — RFC 5755 §4.1, binding attributes to a digest of
/// an object rather than to a named holder.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct ObjectDigestInfo {
    pub digested_object_type: DigestedObjectType,

    #[asn1(optional = "true")]
    pub other_object_type_id: Option<ObjectIdentifier>,

    pub digest_algorithm: AlgorithmIdentifierOwned,
    pub object_digest: BitString,
}

/// `digestedObjectType` — RFC 5755 §4.1. A true ASN.1 `ENUMERATED`,
/// unlike [`AttCertVersion`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Enumerated)]
#[repr(u8)]
#[allow(missing_docs)]
pub enum DigestedObjectType {
    PublicKey = 0,
    PublicKeyCert = 1,
    /// MUST NOT be used in this profile (§4.1).
    OtherObjectTypes = 2,
}

/// `AttCertValidityPeriod` — RFC 5755 §4.1.
///
/// Both bounds are `GeneralizedTime`, with none of the UTCTime-before-2050
/// rule that applies to public-key certificates. §4.1 also requires the
/// seconds field to be present and the time to be in Z, which
/// `GeneralizedTime` already enforces.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct AttCertValidityPeriod {
    pub not_before_time: GeneralizedTime,
    pub not_after_time: GeneralizedTime,
}

/// `Attribute` — repeated in RFC 5755 §4.1 for convenience, and defined
/// in RFC 5280.
///
/// The values are a `SET OF ANY`: what they mean depends entirely on
/// `type`. This crate parses them and does not interpret them; see the
/// crate documentation for why.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct Attribute {
    pub r#type: ObjectIdentifier,
    pub values: SetOfVec<Any>,
}

/// `Targets ::= SEQUENCE OF Target` — RFC 5755 §4.3.2.
pub type Targets = Vec<Target>;

/// `Target` — RFC 5755 §4.3.2.
///
/// Group membership is deliberately not defined by the RFC: "any given
/// target 'knows' the names of the targetGroups to which it belongs or
/// can otherwise determine its membership". So a `targetGroup` cannot be
/// evaluated by this crate alone — the caller supplies its own group
/// names. See [`crate::AttributeCertificate::check_targeting`].
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
#[allow(missing_docs)]
#[allow(clippy::large_enum_variant)]
pub enum Target {
    /// A name the intended verifier answers to.
    ///
    /// `EXPLICIT`, despite this module being `DEFINITIONS IMPLICIT
    /// TAGS`. X.680 makes a tag on an untagged `CHOICE` explicit,
    /// because a `CHOICE` has no single tag of its own for an implicit
    /// tag to replace — and `GeneralName` is an untagged `CHOICE`. So
    /// `[0]` is constructed and wraps the `GeneralName`'s own tag.
    /// `constructed = "true"` must be stated alongside the explicit tag
    /// mode or the derive will not match the constructed bit — the same
    /// pairing `x509_cert`'s own `GeneralName::DirectoryName` uses.
    ///
    /// This is the opposite of [`Holder::entity_name`], where the inner
    /// type is a `SEQUENCE OF` and the implicit tag does replace its
    /// tag. Both live in this one module, which is why each field says
    /// which it is.
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", constructed = "true")]
    TargetName(GeneralName),

    /// A group the intended verifier belongs to. `EXPLICIT`, as
    /// [`Self::TargetName`].
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", constructed = "true")]
    TargetGroup(GeneralName),

    /// `targetCert` exists "only to allow future compatibility with
    /// [X.509-2000]" and §4.3.2 says it MUST NOT be used. Represented so
    /// that an AC carrying one parses and can be refused with a reason.
    ///
    /// `IMPLICIT` here, unlike the two arms above: `TargetCert` is a
    /// `SEQUENCE`, which has a tag of its own for `[2]` to replace.
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", constructed = "true")]
    TargetCert(TargetCert),
}

/// `TargetCert` — RFC 5755 §4.3.2. MUST NOT be used.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct TargetCert {
    pub target_certificate: IssuerSerial,

    #[asn1(optional = "true")]
    pub target_name: Option<GeneralName>,

    #[asn1(optional = "true")]
    pub cert_digest_info: Option<ObjectDigestInfo>,
}
