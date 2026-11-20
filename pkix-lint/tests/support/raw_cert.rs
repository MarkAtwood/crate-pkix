//! Test-only mutable mirror of `x509_cert::Certificate`.
//!
//! x509-cert 0.3 made the `Certificate` and `TbsCertificate` fields
//! private, so tests that build malformed or modified certificates decode
//! into these structs (same ASN.1 layout, public fields), edit them, and
//! re-encode. The signature is not recomputed: an edited certificate's
//! signature no longer verifies unless the test re-signs it.
#![allow(dead_code)]

use der::asn1::BitString;
use der::{Decode, Encode, Sequence};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::certificate::Version;
use x509_cert::ext::Extensions;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;
use x509_cert::Certificate;

/// Mirror of RFC 5280 `TBSCertificate` with public fields.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct RawTbs {
    #[asn1(context_specific = "0", default = "Default::default")]
    pub version: Version,
    pub serial_number: SerialNumber,
    pub signature: AlgorithmIdentifierOwned,
    pub issuer: Name,
    pub validity: Validity,
    pub subject: Name,
    pub subject_public_key_info: SubjectPublicKeyInfoOwned,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub issuer_unique_id: Option<BitString>,
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub subject_unique_id: Option<BitString>,
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    pub extensions: Option<Extensions>,
}

/// Mirror of RFC 5280 `Certificate` with public fields.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct RawCert {
    pub tbs_certificate: RawTbs,
    pub signature_algorithm: AlgorithmIdentifierOwned,
    pub signature: BitString,
}

impl RawCert {
    /// Decodes `cert`'s DER encoding into the mutable mirror.
    pub fn from_cert(cert: &Certificate) -> Self {
        Self::from_der(&cert.to_der().expect("encode certificate"))
            .expect("decode certificate mirror")
    }

    /// Re-encodes the mirror and parses it back as a `Certificate`.
    pub fn to_cert(&self) -> Certificate {
        Certificate::from_der(&self.to_der().expect("encode certificate mirror"))
            .expect("decode edited certificate")
    }
}

/// Returns a copy of `cert` with `edit` applied to its fields.
pub fn edit_cert(cert: &Certificate, edit: impl FnOnce(&mut RawCert)) -> Certificate {
    let mut raw = RawCert::from_cert(cert);
    edit(&mut raw);
    raw.to_cert()
}
