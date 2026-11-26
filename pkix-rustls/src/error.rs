//! Mapping [`pkix_chain::Error`] onto [`rustls::CertificateError`].
//!
//! rustls's vocabulary is narrower than this workspace's, so the
//! mapping is lossy by construction. It is arranged so that the loss is
//! only ever in *precision*, never in *presence*: anything that has a
//! rustls variant gets that variant, and anything that does not is
//! carried whole inside [`CertificateError::Other`], which rustls
//! documents as existing for custom verifiers to expose their own
//! errors. An application can downcast and recover the original.
//!
//! The alternative — collapsing unmapped cases to a generic failure —
//! would make "this chain has no trusted root", "this CRL would not
//! parse" and "this policy was violated" indistinguishable to the
//! caller, which is the same mistake as reporting every rejected SCT as
//! an empty list.

use std::sync::Arc;

use rustls::{CertificateError, OtherError};
use x509_cert::Certificate;

use pkix_chain::Error as ChainError;
use pkix_identity::IdentityError;
use pkix_path::Error as PathError;
use pkix_path_builder::Error as PathBuildError;
use pkix_revocation::Error as RevocationError;

/// Translate a verification failure into the error rustls reports.
///
/// `chain` and `now_unix` are the inputs the failure came from; they
/// are needed because [`PathError::ValidityPeriod`] does not say which
/// end of the window was missed while rustls distinguishes
/// [`CertificateError::Expired`] from
/// [`CertificateError::NotValidYet`]: the chain is re-examined to see
/// which end of the window was missed.
#[must_use]
pub fn map_error(error: ChainError, chain: &[Certificate], now_unix: u64) -> CertificateError {
    match error {
        ChainError::Path(e) => map_path_error(e, chain, now_unix),
        ChainError::Identity(e) => map_identity_error(e),
        ChainError::Revocation(e) => map_revocation_error(e),
        // Path *building* failing to reach an anchor is the same answer
        // to the caller as path *validation* finding no trusted path:
        // this chain does not lead anywhere trusted. These arrive here
        // rather than as `Path(NoTrustedPath)` whenever the builder is
        // the stage that gave up, which is the ordinary case for an
        // empty or wrong trust store — the second most common TLS
        // failure there is, so it must not land in `Other`.
        ChainError::PathBuild(PathBuildError::NoPathFound | PathBuildError::NoValidPath { .. }) => {
            CertificateError::UnknownIssuer
        }
        // Everything else — profile violations, OCSP delegation,
        // DANE, path building, the AIA budget errors — has no rustls
        // variant that would not be a lie. Carried intact instead.
        other => other_error(other),
    }
}

fn map_path_error(error: PathError, chain: &[Certificate], now_unix: u64) -> CertificateError {
    match error {
        PathError::SignatureInvalid { .. } | PathError::SignatureNotVerified { .. } => {
            CertificateError::BadSignature
        }
        PathError::MalformedCertificate { .. } | PathError::Der(_) => CertificateError::BadEncoding,
        e @ PathError::ValidityPeriod { .. } => validity_error(e, chain, now_unix),
        // No path to a trust anchor, by either route.
        PathError::ChainBroken { .. } | PathError::NoTrustedPath => CertificateError::UnknownIssuer,
        PathError::UnhandledCriticalExtension { .. } => {
            CertificateError::UnhandledCriticalExtension
        }
        // The certificate is not allowed to do what it is being used
        // for: not a CA where one is required, or missing the key usage
        // or EKU the role needs.
        PathError::NotCA { .. }
        | PathError::KeyUsageMissing { .. }
        | PathError::CrlSignMissing { .. }
        | PathError::MissingEku => CertificateError::InvalidPurpose,
        // A name constraint excluded the name, which is a name failure
        // from the caller's point of view even though it was decided at
        // a CA rather than at the leaf.
        PathError::NameConstraintViolation { .. } => CertificateError::NotValidForName,
        // `UnsupportedSignatureAlgorithmContext` would be the right
        // variant for AlgorithmNotAllowed, but it requires the
        // offending OID and the list of permitted algorithms, and the
        // error does not carry them. A variant filled with invented
        // values is worse than the real error, so it goes through
        // `Other` with its own message.
        other => other_error(ChainError::Path(other)),
    }
}

fn map_identity_error(error: IdentityError) -> CertificateError {
    match error {
        // The certificate presents names, and none of them is this one
        // — or it presents none at all.
        IdentityError::NoMatchingSan | IdentityError::MissingSan => {
            CertificateError::NotValidForName
        }
        // The certificate is at fault, not the name: a SAN extension
        // that will not parse, or two of them, which RFC 5280 §4.2
        // forbids.
        IdentityError::MalformedSan | IdentityError::DuplicateSan => CertificateError::BadEncoding,
        // The *requested* name was malformed, which says nothing about
        // the certificate and so must not be reported as a certificate
        // defect.
        other => other_error(ChainError::Identity(other)),
    }
}

fn map_revocation_error(error: RevocationError) -> CertificateError {
    match error {
        RevocationError::Revoked { .. } => CertificateError::Revoked,
        // rustls has one variant for "the revocation list is too old to
        // rely on" and it covers both CRL and OCSP staleness.
        RevocationError::CrlExpired | RevocationError::OcspExpired => {
            CertificateError::ExpiredRevocationList
        }
        // Checked, and the answer is not known. Distinct from revoked
        // and from not-checked, which is why rustls has a variant for
        // it.
        RevocationError::OcspStatusUnknown
        | RevocationError::OutOfScope(_)
        | RevocationError::AnchorCheckUnsupported
        | RevocationError::RevocationFetchFailed { .. } => {
            CertificateError::UnknownRevocationStatus
        }
        // A CRL or OCSP signature failure is not the certificate's
        // signature failing, so `BadSignature` would point at the wrong
        // thing. The rest — issuer mismatches, malformed responses,
        // delta-CRL inconsistencies — have no rustls variant either.
        other => other_error(ChainError::Revocation(other)),
    }
}

/// Decide between [`CertificateError::Expired`] and
/// [`CertificateError::NotValidYet`].
///
/// [`PathError::ValidityPeriod`] is one variant for both ends of the
/// window, so the chain is re-examined to see which it was. Expiry wins
/// when both are somehow present, because an expired certificate is the
/// actionable half: it was once good and needs renewing, whereas
/// not-yet-valid is almost always a wrong clock.
///
/// Every certificate is checked, not just the leaf — an expired
/// intermediate fails the path just as an expired leaf does, and
/// reporting the leaf's dates for an intermediate's problem would send
/// the reader to the wrong certificate. If neither end explains it, the
/// original error is carried through rather than guessed at.
fn validity_error(original: PathError, chain: &[Certificate], now_unix: u64) -> CertificateError {
    let mut not_yet_valid = false;
    for cert in chain {
        let validity = cert.tbs_certificate().validity();
        if now_unix > validity.not_after.to_unix_duration().as_secs() {
            return CertificateError::Expired;
        }
        if now_unix < validity.not_before.to_unix_duration().as_secs() {
            not_yet_valid = true;
        }
    }
    if not_yet_valid {
        return CertificateError::NotValidYet;
    }
    other_error(ChainError::Path(original))
}

/// Carry an error rustls has no variant for, without flattening it.
fn other_error(error: ChainError) -> CertificateError {
    CertificateError::Other(OtherError(Arc::new(error)))
}
