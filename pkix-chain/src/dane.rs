//! DANE composition with TLS server verification.
//!
//! [`verify_tls_server_dane`] is [`crate::verify_tls_server`] with the TLSA
//! records a domain publishes taken into account. It is a separate entry point
//! rather than a new parameter on the existing one because DANE does not
//! simply *add* a check: usages 2 and 3 change what validation happens at all.
//!
//! # What each usage does to validation
//!
//! | Usage | Effect |
//! |--|--|
//! | [`PkixTa`](pkix_dane::TlsaUsage::PkixTa) (0) | PKIX validation **and** a record must match a chain certificate |
//! | [`PkixEe`](pkix_dane::TlsaUsage::PkixEe) (1) | PKIX validation **and** a record must match the leaf |
//! | [`DaneTa`](pkix_dane::TlsaUsage::DaneTa) (2) | the chain validates to a **DANE-supplied** anchor, not the caller's |
//! | [`DaneEe`](pkix_dane::TlsaUsage::DaneEe) (3) | a record matches the leaf; **no chain validation at all** |
//!
//! Because usage 3 performs no path validation, there is no
//! [`ValidatedPath`] to return for it.
//! [`TlsAuthorization`] therefore reports *how* the connection was authorized
//! rather than pretending every route produces a path. A caller that wants to
//! log why a connection was accepted — or to apply its own policy to
//! DANE-authorized connections — needs that distinction, and synthesizing a
//! fake path with a meaningless `anchor_index` and `depth` would hide it.
//!
//! # Failure policy
//!
//! [`DaneFailurePolicy`] decides what happens when DANE could not give an
//! answer. One thing it deliberately cannot decide: a
//! [`Bogus`](pkix_dane::DnssecStatus::Bogus) DNSSEC status always fails. A
//! signed zone whose signatures do not verify is an attack signal, and a
//! policy knob that let it fall back to PKIX would let an attacker switch DANE
//! off for any domain by corrupting the DNS answer.

use pkix_dane::{DaneError, DnssecStatus, PresentedCert, TlsaRecord, TlsaResponse, TlsaUsage};
use pkix_identity::ServerName;
use pkix_path::{TrustAnchor, ValidatedPath};
use x509_cert::Certificate;

use crate::{Error, Result};
use pkix_aia::AiaFetcher;
use pkix_path::SignatureVerifier;
use pkix_profiles::Profile;
use pkix_revocation::RevocationChecker;

/// What to do when DANE could not produce an answer.
///
/// Decided for this workspace under `PKIX-j32w.4`. The default is
/// [`Opportunistic`](Self::Opportunistic).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DaneFailurePolicy {
    /// DANE applies when available; otherwise ordinary PKIX validation
    /// decides.
    ///
    /// A lookup that failed, a DNSSEC state that could not be determined, an
    /// unsigned zone, or a signed statement that the domain publishes no TLSA
    /// record all fall through to PKIX.
    ///
    /// An attacker who can block DNS can therefore suppress DANE — but they
    /// still need a certificate a public CA issued for the name, so this
    /// leaves the caller no worse off than before DANE existed. Failing
    /// instead would turn any DNS flakiness into a TLS failure, which breaks
    /// offline certificate audit and batch validation that never wanted a
    /// network call.
    #[default]
    Opportunistic,

    /// Only a DNSSEC-secure TLSA match is acceptable.
    ///
    /// A lookup failure, an undeterminable DNSSEC state, an unsigned zone and
    /// an authenticated denial all fail. For deployments that would rather
    /// lose a connection than lose DANE, and that can accept the brittleness
    /// — a DNS outage becomes a TLS outage.
    Strict,
}

/// DANE inputs for [`verify_tls_server_dane`].
///
/// # The certificate bytes must be the ones the peer sent
///
/// [`chain_der`](Self::chain_der) is index-aligned with the `chain` passed to
/// the verify function and must hold each certificate **exactly as received**.
/// TLSA matching compares against octets a domain operator hashed from their
/// certificate file, and `x509-cert` 0.3 normalizes a pre-2050
/// `GeneralizedTime` validity date to `UTCTime` when it re-encodes — so
/// re-deriving the bytes from the parsed `chain` would silently fail to match
/// a correctly-published record for such a certificate. A TLS client has the
/// wire bytes already; pass those.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct DaneConfig<'a> {
    /// The resolver's answer, or `None` when DANE was not attempted.
    ///
    /// `None` makes the call behave exactly like
    /// [`crate::verify_tls_server`] under
    /// [`Opportunistic`](DaneFailurePolicy::Opportunistic), and fail under
    /// [`Strict`](DaneFailurePolicy::Strict) — a strict caller that did not
    /// attempt resolution has not met its own policy.
    pub response: Option<&'a TlsaResponse>,

    /// What to do when DANE could not give an answer.
    pub policy: DaneFailurePolicy,

    /// The presented chain as received, index-aligned with `chain`.
    ///
    /// See the [type documentation](Self#the-certificate-bytes-must-be-the-ones-the-peer-sent).
    pub chain_der: &'a [&'a [u8]],
}

impl<'a> DaneConfig<'a> {
    /// DANE inputs with the default [`Opportunistic`](DaneFailurePolicy::Opportunistic) policy.
    #[must_use]
    pub const fn new(response: &'a TlsaResponse, chain_der: &'a [&'a [u8]]) -> Self {
        Self {
            response: Some(response),
            policy: DaneFailurePolicy::Opportunistic,
            chain_der,
        }
    }

    /// DANE inputs that attempt nothing, for a call site that wants pure PKIX
    /// in a DANE-enabled binary.
    ///
    /// This is the call-site override: it leaves the DANE code path present
    /// but inert, without the caller switching to a different function.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            response: None,
            policy: DaneFailurePolicy::Opportunistic,
            chain_der: &[],
        }
    }

    /// Sets the failure policy.
    #[must_use]
    pub const fn with_policy(mut self, policy: DaneFailurePolicy) -> Self {
        self.policy = policy;
        self
    }
}

/// How a TLS server certificate came to be accepted.
///
/// Returned by [`verify_tls_server_dane`]. The variants are not
/// interchangeable: [`DaneEndEntity`](Self::DaneEndEntity) carries no path
/// because none was validated, and a caller treating it as equivalent to
/// [`Pkix`](Self::Pkix) would be asserting a chain was checked when it was
/// not.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TlsAuthorization {
    /// RFC 5280 path validation alone. DANE did not apply — no records, an
    /// unsigned zone, or a lookup that failed under an opportunistic policy.
    Pkix(ValidatedPath),

    /// PKIX path validation, additionally constrained by a usage-0 or usage-1
    /// record.
    ///
    /// Both halves succeeded. The domain narrowed which certificate or CA is
    /// acceptable, and the caller's own trust store still had to accept the
    /// chain.
    PkixConstrained {
        /// The validated path.
        path: ValidatedPath,
        /// The record that constrained it.
        record: TlsaRecord,
        /// Which usage applied.
        usage: TlsaUsage,
    },

    /// The chain validated to a trust anchor the TLSA record supplied
    /// (usage 2).
    ///
    /// The caller's own trust store did not have to contain the anchor;
    /// DNSSEC vouched for it. Ordinary chain checks — signatures, validity
    /// periods, basic constraints, name constraints — still applied.
    DaneTrustAnchor {
        /// The path validated against the DANE-supplied anchor.
        path: ValidatedPath,
        /// The record that established the anchor.
        record: TlsaRecord,
    },

    /// A usage-3 record matched the leaf directly.
    ///
    /// **No chain was validated and none was required.** Per RFC 7671 §5.1 the
    /// certificate's validity dates and names are not consulted either: the
    /// TLSA record is the binding. A self-signed certificate is legitimate
    /// here.
    DaneEndEntity {
        /// The record that authorized the connection.
        record: TlsaRecord,
    },
}

impl TlsAuthorization {
    /// The validated path, or `None` for
    /// [`DaneEndEntity`](Self::DaneEndEntity) where no path was validated.
    #[must_use]
    pub const fn path(&self) -> Option<&ValidatedPath> {
        match self {
            Self::Pkix(path)
            | Self::PkixConstrained { path, .. }
            | Self::DaneTrustAnchor { path, .. } => Some(path),
            Self::DaneEndEntity { .. } => None,
        }
    }

    /// The TLSA record that authorized or constrained the connection, or
    /// `None` when DANE did not apply.
    #[must_use]
    pub const fn record(&self) -> Option<&TlsaRecord> {
        match self {
            Self::Pkix(_) => None,
            Self::PkixConstrained { record, .. }
            | Self::DaneTrustAnchor { record, .. }
            | Self::DaneEndEntity { record } => Some(record),
        }
    }

    /// Whether DANE took part in the decision.
    #[must_use]
    pub const fn used_dane(&self) -> bool {
        !matches!(self, Self::Pkix(_))
    }
}

/// What the DNSSEC status and record set permit.
#[derive(Debug, PartialEq, Eq)]
enum DaneApplicability {
    /// Usable records exist; evaluate them.
    Apply,
    /// DANE does not apply; ordinary PKIX decides.
    FallThrough,
    /// DANE could not be satisfied and the policy forbids falling through.
    Refuse(DaneError),
}

/// Decides whether DANE applies, given the response and the policy.
///
/// Split out from [`verify_tls_server_dane`] so the policy table is
/// inspectable and testable without a certificate chain or a trust store.
fn applicability(response: Option<&TlsaResponse>, policy: DaneFailurePolicy) -> DaneApplicability {
    let strict = policy == DaneFailurePolicy::Strict;

    let Some(response) = response else {
        // No attempt was made. Strict callers have not met their own policy.
        return if strict {
            DaneApplicability::Refuse(DaneError::ResolutionDisabled)
        } else {
            DaneApplicability::FallThrough
        };
    };

    let status = response.dnssec();

    // Bogus is not subject to policy. See the module documentation.
    if status == DnssecStatus::Bogus {
        return DaneApplicability::Refuse(DaneError::DnssecNotSecure { status });
    }

    if !status.is_secure() {
        return if strict {
            DaneApplicability::Refuse(DaneError::DnssecNotSecure { status })
        } else {
            DaneApplicability::FallThrough
        };
    }

    // Secure from here on.
    if !response.has_usable_record() {
        // Either an authenticated denial, or records whose parameters this
        // client cannot evaluate — RFC 7671 §17 treats the latter as
        // equivalent to publishing nothing.
        return if strict {
            DaneApplicability::Refuse(DaneError::NoUsableRecords {
                usage: TlsaUsage::DaneEe,
                records_for_usage: response.records().len(),
            })
        } else {
            DaneApplicability::FallThrough
        };
    }

    DaneApplicability::Apply
}

/// Verifies a TLS server certificate, taking DANE into account.
///
/// Composes [`crate::verify_tls_server`]'s PKIX validation with the TLSA
/// records in `dane`. See the [module documentation](self) for what each usage
/// does to validation, and [`TlsAuthorization`] for what a success reports.
///
/// # Order of evaluation
///
/// Usages are tried strongest-first: DANE-EE, then DANE-TA, then PKIX-EE, then
/// PKIX-TA. RFC 7671 §4.1 makes any matching record sufficient and does not
/// prescribe an order; strongest-first means a domain that publishes both a
/// DANE-EE and a PKIX-EE record gets the DANE-EE semantics it asked for rather
/// than having the connection depend on the client's trust store.
///
/// # Arguments
///
/// As [`crate::verify_tls_server`], plus `dane`. Pass
/// [`DaneConfig::disabled`] for pure PKIX at a call site in a DANE-enabled
/// binary.
///
/// # Errors
///
/// - [`Error::Dane`] when DANE was required and could not be satisfied:
///   a [`Bogus`](DnssecStatus::Bogus) DNSSEC status, which fails under every
///   policy; or, under [`Strict`](DaneFailurePolicy::Strict), an
///   undeterminable status, an unsigned zone, an authenticated denial, or no
///   usable records.
/// - [`Error::Dane`] carrying [`DaneError::NoMatch`] when usable records
///   existed and the certificate matched none. This is the genuine DANE
///   authentication failure.
/// - [`Error::Path`], [`Error::Revocation`], [`Error::Identity`] and the AIA
///   variants exactly as [`crate::verify_tls_server`] produces them, for the
///   routes that perform path validation.
///
/// # Panics
///
/// Does not panic. An empty `chain` is reported as
/// [`Error::Path`] by the underlying validation, as it is for
/// [`crate::verify_tls_server`].
#[allow(clippy::too_many_arguments)]
pub fn verify_tls_server_dane<V, P, R, A>(
    chain: &[Certificate],
    anchors: &[TrustAnchor],
    name: &ServerName<'_>,
    profile: &P,
    now_unix: u64,
    verifier: &V,
    revocation: &R,
    aia: &A,
    dane: &DaneConfig<'_>,
) -> Result<TlsAuthorization>
where
    V: SignatureVerifier,
    P: Profile,
    R: RevocationChecker,
    A: AiaFetcher,
{
    match applicability(dane.response, dane.policy) {
        DaneApplicability::Refuse(e) => return Err(Error::Dane(e)),
        DaneApplicability::FallThrough => {
            let path = crate::verify_tls_server(
                chain, anchors, name, profile, now_unix, verifier, revocation, aia,
            )?;
            return Ok(TlsAuthorization::Pkix(path));
        }
        DaneApplicability::Apply => {}
    }

    let response = dane
        .response
        .expect("applicability returns Apply only for Some(response)");

    // Pair each certificate with the octets it arrived as. A short or absent
    // chain_der is a caller error rather than a validation failure, so it is
    // reported as such rather than silently matching fewer certificates.
    if dane.chain_der.len() != chain.len() {
        return Err(Error::Dane(DaneError::ResolutionFailed(format!(
            "DaneConfig::chain_der has {} entries for a {}-certificate chain; \
             they must be index-aligned",
            dane.chain_der.len(),
            chain.len()
        ))));
    }
    let presented: Vec<PresentedCert<'_>> = dane
        .chain_der
        .iter()
        .zip(chain.iter())
        .map(|(der, parsed)| PresentedCert::new(der, parsed))
        .collect();
    let Some(leaf) = presented.first() else {
        return Err(Error::Dane(DaneError::ResolutionFailed(
            "empty certificate chain".into(),
        )));
    };

    // 1. DANE-EE (3): the record is the binding. No chain, no names, no dates.
    match pkix_dane::verify_dane_ee(leaf, response) {
        Ok(record) => {
            return Ok(TlsAuthorization::DaneEndEntity {
                record: record.clone(),
            })
        }
        Err(DaneError::NoRecordsForUsage { .. } | DaneError::NoUsableRecords { .. }) => {}
        Err(e) => return Err(Error::Dane(e)),
    }

    // 2. DANE-TA (2): validate the chain to the anchor the record supplies,
    //    instead of the caller's trust store. Merging the two would implement
    //    "DANE-TA or any CA", which is weaker than either.
    match pkix_dane::verify_dane_ta(&presented, response) {
        Ok(established) => {
            let record = established.record().clone();
            let anchor = established.into_anchor();
            let path = crate::verify_tls_server(
                chain,
                core::slice::from_ref(&anchor),
                name,
                profile,
                now_unix,
                verifier,
                revocation,
                aia,
            )?;
            return Ok(TlsAuthorization::DaneTrustAnchor { path, record });
        }
        Err(DaneError::NoRecordsForUsage { .. } | DaneError::NoUsableRecords { .. }) => {}
        Err(e) => return Err(Error::Dane(e)),
    }

    // 3. PKIX-EE (1) and PKIX-TA (0): the record narrows what PKIX would
    //    accept. Both halves must succeed, so path validation runs too.
    for (usage, matched) in [
        (TlsaUsage::PkixEe, pkix_dane::verify_pkix_ee(leaf, response)),
        (
            TlsaUsage::PkixTa,
            pkix_dane::verify_pkix_ta(&presented, response),
        ),
    ] {
        match matched {
            Ok(record) => {
                let record = record.clone();
                let path = crate::verify_tls_server(
                    chain, anchors, name, profile, now_unix, verifier, revocation, aia,
                )?;
                return Ok(TlsAuthorization::PkixConstrained {
                    path,
                    record,
                    usage,
                });
            }
            Err(DaneError::NoRecordsForUsage { .. } | DaneError::NoUsableRecords { .. }) => {}
            Err(e) => return Err(Error::Dane(e)),
        }
    }

    // Usable records existed — `applicability` established that — and none of
    // the four usages matched. The domain stated which certificate it uses and
    // this is not it.
    Err(Error::Dane(DaneError::NoMatch {
        usage: TlsaUsage::DaneEe,
        records_compared: response.records().len(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkix_dane::{TlsaMatchingType, TlsaSelector};

    fn record(usage: TlsaUsage) -> TlsaRecord {
        TlsaRecord::new(
            usage,
            TlsaSelector::Cert,
            TlsaMatchingType::Sha256,
            vec![0xab; 32],
        )
    }

    /// Bogus fails under both policies. This is the one row of the policy
    /// table that is not a policy choice: a configurable fallback there would
    /// let an attacker switch DANE off by corrupting the DNS answer.
    #[test]
    fn bogus_always_refuses() {
        let response = TlsaResponse::new(vec![record(TlsaUsage::DaneEe)], DnssecStatus::Bogus);
        for policy in [DaneFailurePolicy::Opportunistic, DaneFailurePolicy::Strict] {
            assert_eq!(
                applicability(Some(&response), policy),
                DaneApplicability::Refuse(DaneError::DnssecNotSecure {
                    status: DnssecStatus::Bogus
                }),
                "Bogus must refuse under {policy:?}"
            );
        }
    }

    /// Insecure and Indeterminate fall through opportunistically and refuse
    /// strictly.
    #[test]
    fn undeterminable_status_follows_policy() {
        for status in [DnssecStatus::Insecure, DnssecStatus::Indeterminate] {
            let response = TlsaResponse::new(vec![record(TlsaUsage::DaneEe)], status);
            assert_eq!(
                applicability(Some(&response), DaneFailurePolicy::Opportunistic),
                DaneApplicability::FallThrough,
                "{status:?} should fall through opportunistically"
            );
            assert_eq!(
                applicability(Some(&response), DaneFailurePolicy::Strict),
                DaneApplicability::Refuse(DaneError::DnssecNotSecure { status }),
                "{status:?} should refuse strictly"
            );
        }
    }

    /// An authenticated denial — a secure response with no records — is the
    /// domain signing that it publishes no TLSA record. Opportunistically that
    /// is a clean fall-through; strictly it is a failure, because the strict
    /// caller requires a DANE match and there is none to be had.
    #[test]
    fn authenticated_denial_follows_policy() {
        let response = TlsaResponse::new(Vec::new(), DnssecStatus::Secure);
        assert!(response.is_authenticated_denial());
        assert_eq!(
            applicability(Some(&response), DaneFailurePolicy::Opportunistic),
            DaneApplicability::FallThrough
        );
        assert!(matches!(
            applicability(Some(&response), DaneFailurePolicy::Strict),
            DaneApplicability::Refuse(_)
        ));
    }

    /// Records whose parameters cannot be evaluated are equivalent to
    /// publishing none (RFC 7671 §17), so they follow the same path as an
    /// authenticated denial rather than failing outright.
    #[test]
    fn wholly_unusable_records_follow_policy() {
        let unusable = TlsaRecord::new(
            TlsaUsage::DaneEe,
            TlsaSelector::Unassigned(9),
            TlsaMatchingType::Sha256,
            vec![0xab; 32],
        );
        assert!(!unusable.is_usable());
        let response = TlsaResponse::new(vec![unusable], DnssecStatus::Secure);

        assert_eq!(
            applicability(Some(&response), DaneFailurePolicy::Opportunistic),
            DaneApplicability::FallThrough
        );
        assert!(matches!(
            applicability(Some(&response), DaneFailurePolicy::Strict),
            DaneApplicability::Refuse(_)
        ));
    }

    /// No attempt at all: pure PKIX opportunistically, a failure strictly. A
    /// strict caller that never resolved has not met its own policy, and
    /// silently validating by PKIX alone would misreport that.
    #[test]
    fn no_response_follows_policy() {
        assert_eq!(
            applicability(None, DaneFailurePolicy::Opportunistic),
            DaneApplicability::FallThrough
        );
        assert_eq!(
            applicability(None, DaneFailurePolicy::Strict),
            DaneApplicability::Refuse(DaneError::ResolutionDisabled)
        );
    }

    #[test]
    fn secure_with_usable_records_applies() {
        let response = TlsaResponse::new(vec![record(TlsaUsage::DaneEe)], DnssecStatus::Secure);
        for policy in [DaneFailurePolicy::Opportunistic, DaneFailurePolicy::Strict] {
            assert_eq!(
                applicability(Some(&response), policy),
                DaneApplicability::Apply
            );
        }
    }

    #[test]
    fn the_disabled_config_attempts_nothing() {
        let config = DaneConfig::disabled();
        assert!(config.response.is_none());
        assert_eq!(config.policy, DaneFailurePolicy::Opportunistic);
        assert!(config.chain_der.is_empty());
    }

    #[test]
    fn the_default_policy_is_opportunistic() {
        assert_eq!(
            DaneFailurePolicy::default(),
            DaneFailurePolicy::Opportunistic
        );
    }

    #[test]
    fn authorization_accessors_report_the_route() {
        let rec = record(TlsaUsage::DaneEe);
        let ee = TlsAuthorization::DaneEndEntity {
            record: rec.clone(),
        };
        assert!(ee.path().is_none(), "usage 3 validates no path");
        assert_eq!(ee.record(), Some(&rec));
        assert!(ee.used_dane());
    }
}
