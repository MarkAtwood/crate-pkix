//! The hickory-backed reference resolver.

use std::sync::Arc;

use async_trait::async_trait;
use hickory_proto::dnssec::{Algorithm, Proof, PublicKeyBuf, TrustAnchors};
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::NetError;
use hickory_resolver::net::{DnsError, NoRecords};
use hickory_resolver::{Resolver, TokioResolver};
use pkix_dane::{
    DaneError, DnssecStatus, TlsaMatchingType, TlsaName, TlsaRecord, TlsaResponse, TlsaSelector,
    TlsaUsage,
};

use crate::{upstream_from_environment, AsyncTlsaResolver, ResolverError, UpstreamConfig};

/// A DNSSEC-validating TLSA resolver built on hickory.
///
/// Construct with [`new`](Self::new), supplying trust anchors. There is no
/// `Default`: a validating resolver with no anchor can determine nothing, so
/// there is no sensible default to offer.
///
/// # Example
///
/// ```no_run
/// use pkix_dane::{TlsaName, TlsaProtocol};
/// use pkix_dane_resolver::{AsyncTlsaResolver, HickoryTlsaResolver};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // IANA's anchors come from a separate, independently versioned crate.
/// let resolver = HickoryTlsaResolver::new(pkix_dnssec_anchor::CURRENT)?;
///
/// let name = TlsaName::new(443, &TlsaProtocol::Tcp, "example.com")?;
/// let response = resolver.resolve(&name).await?;
///
/// if response.dnssec().is_secure() {
///     // hand `response` to pkix-dane's matching functions
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct HickoryTlsaResolver {
    inner: Arc<TokioResolver>,
}

impl core::fmt::Debug for HickoryTlsaResolver {
    /// Deliberately opaque. `hickory`'s `Resolver` is not `Debug`, and its
    /// internals — connection pools, cache contents — are not a stable thing
    /// to print.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HickoryTlsaResolver { .. }")
    }
}

impl HickoryTlsaResolver {
    /// The underlying hickory resolver, for lookups other than TLSA.
    ///
    /// Crate-private: exposing hickory's types in this crate's public API
    /// would make a hickory major version a breaking change here.
    pub(crate) fn inner(&self) -> &TokioResolver {
        &self.inner
    }

    /// Builds a resolver that validates against `anchors`.
    ///
    /// Upstream servers come from [`upstream_from_environment`]: the
    /// `PKIX_DANE_RESOLVER` variable if set, otherwise the system
    /// configuration. Use [`with_upstream`](Self::with_upstream) to state
    /// them directly.
    ///
    /// `anchors` is anything iterable of [`pkix_dnssec_anchor::RootAnchor`]-shaped
    /// values; IANA's live in that crate's `CURRENT`. Anchors are inserted as
    /// root-zone keys, which is what a DANE validator needs.
    ///
    /// # Errors
    ///
    /// - [`ResolverError::NoTrustAnchor`] if `anchors` yields nothing usable.
    /// - [`ResolverError::AnchorWithoutPublicKey`] if an anchor carries only a
    ///   digest. IANA publishes some historical anchors that way; they cannot
    ///   seed a validator.
    /// - [`ResolverError::AnchorAlgorithmUnsupported`] for a DNSSEC algorithm
    ///   this build cannot verify with.
    /// - [`ResolverError::UpstreamUnavailable`] if `PKIX_DANE_RESOLVER` is set
    ///   but unparsable.
    /// - [`ResolverError::Construction`] if the DNS stack could not be built,
    ///   which on the system-configuration path includes being unable to read
    ///   that configuration.
    pub fn new<'a, I>(anchors: I) -> Result<Self, ResolverError>
    where
        I: IntoIterator<Item = &'a pkix_dnssec_anchor::RootAnchor>,
    {
        Self::with_upstream(anchors, upstream_from_environment()?)
    }

    /// Builds a resolver with explicitly chosen upstream servers.
    ///
    /// # Errors
    ///
    /// As [`new`](Self::new), except that no environment lookup occurs so
    /// [`ResolverError::UpstreamUnavailable`] cannot arise from a malformed
    /// override.
    pub fn with_upstream<'a, I>(anchors: I, upstream: UpstreamConfig) -> Result<Self, ResolverError>
    where
        I: IntoIterator<Item = &'a pkix_dnssec_anchor::RootAnchor>,
    {
        let trust_anchors = build_trust_anchors(anchors)?;

        let mut builder = match upstream {
            UpstreamConfig::Servers(servers) => {
                let name_servers = servers
                    .iter()
                    .map(|addr| NameServerConfig::udp_and_tcp(addr.ip()))
                    .collect();
                Resolver::builder_with_config(
                    ResolverConfig::from_name_servers(name_servers),
                    TokioRuntimeProvider::default(),
                )
            }
            UpstreamConfig::System => TokioResolver::builder_tokio()
                .map_err(|e| ResolverError::Construction(e.to_string()))?,
        };

        // Without this, hickory returns records without attempting
        // validation and every answer would come back Indeterminate.
        builder.options_mut().validate = true;

        let resolver = builder
            .with_trust_anchor(Arc::new(trust_anchors))
            .build()
            .map_err(|e| ResolverError::Construction(e.to_string()))?;
        Ok(Self {
            inner: Arc::new(resolver),
        })
    }
}

#[async_trait]
impl AsyncTlsaResolver for HickoryTlsaResolver {
    async fn resolve(&self, name: &TlsaName) -> Result<TlsaResponse, DaneError> {
        let lookup = match self.inner.lookup(name.as_str(), RecordType::TLSA).await {
            Ok(lookup) => lookup,
            Err(err) => return classify_lookup_error(&err),
        };

        let status = answer_status(lookup.answers());
        let records = lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::TLSA(tlsa) => Some(convert_record(tlsa)),
                _ => None,
            })
            .collect();

        // No records at all: the DNSSEC state belongs to the authenticated
        // denial, which hickory reports on the lookup rather than on a record.
        let status = status.unwrap_or(DnssecStatus::Secure);
        Ok(TlsaResponse::new(records, status))
    }
}

/// The DNSSEC status of an answer, taken from the records in it.
///
/// Each record carries its own proof. This takes the **weakest** across
/// the answer rather than the strongest: an attacker who can inject one
/// unvalidated record into an otherwise-secure RRset must not be able to
/// have the set treated as secure. That applies to the data — the TLSA
/// records, and any `CNAME` or `DNAME` the answer was reached through,
/// since an unauthenticated redirection must not yield authenticated
/// data.
///
/// `RRSIG` records are skipped, and that exclusion is the whole point of
/// this function existing. An `RRSIG` is not part of the RRset being
/// authenticated; it is a signature over it, and a zone may legitimately
/// publish signatures a validator cannot chain. A zone midway through an
/// algorithm rollover carries `RRSIG`s under a new algorithm before the
/// parent's DS set covers it, and those come back `Indeterminate` beside
/// data that validates `Secure` under the old algorithm. RFC 6840 §5.11
/// says a validator "MUST NOT insist that all algorithms signaled in the
/// DNSKEY RRset work".
///
/// Folding `RRSIG` proofs in broke exactly that rule. `debian.org`'s
/// `_25._tcp` TLSA answer is two TLSA records, both `Secure`, plus two
/// `RRSIG`s — one `Secure` under algorithm 8, one `Indeterminate` under
/// algorithm 13, which the parent publishes no DS for. That one
/// signature dragged the whole response to `Indeterminate`, and DANE
/// silently stopped applying to a correctly signed zone. The bug looked
/// like a validator bug in the dependency and was ours.
///
/// `None` when the answer holds no records to judge; the caller maps
/// that to the authenticated-denial case.
fn answer_status(answers: &[Record]) -> Option<DnssecStatus> {
    answers
        .iter()
        .filter(|record| record.record_type() != RecordType::RRSIG)
        .map(|record| proof_to_status(record.proof))
        .reduce(weaker)
}

/// Builds hickory's trust-anchor set from caller-supplied anchors.
fn build_trust_anchors<'a, I>(anchors: I) -> Result<TrustAnchors, ResolverError>
where
    I: IntoIterator<Item = &'a pkix_dnssec_anchor::RootAnchor>,
{
    let mut out = TrustAnchors::empty();
    let mut inserted = 0_usize;

    for anchor in anchors {
        if anchor.public_key.is_empty() {
            let label = if anchor.id.is_empty() {
                anchor.key_tag.to_string()
            } else {
                anchor.id.to_string()
            };
            return Err(ResolverError::AnchorWithoutPublicKey { anchor: label });
        }

        let algorithm = Algorithm::from_u8(anchor.algorithm);
        if matches!(algorithm, Algorithm::Unknown(_)) {
            return Err(ResolverError::AnchorAlgorithmUnsupported {
                algorithm: anchor.algorithm,
            });
        }

        out.insert(&PublicKeyBuf::new(anchor.public_key.to_vec(), algorithm));
        inserted += 1;
    }

    if inserted == 0 {
        return Err(ResolverError::NoTrustAnchor);
    }
    Ok(out)
}

/// Maps hickory's DNSSEC proof onto [`DnssecStatus`].
///
/// The two enumerations are the four RFC 4035 outcomes, so this is a
/// renaming rather than an interpretation.
pub(crate) const fn proof_to_status(proof: Proof) -> DnssecStatus {
    match proof {
        Proof::Secure => DnssecStatus::Secure,
        Proof::Insecure => DnssecStatus::Insecure,
        Proof::Bogus => DnssecStatus::Bogus,
        // Hickory distinguishes "not yet determined" from "cannot be
        // determined"; both mean the same thing to a caller deciding whether
        // DANE applies, and both must not authenticate.
        Proof::Indeterminate => DnssecStatus::Indeterminate,
    }
}

/// Returns the weaker of two statuses, ordered Secure > Insecure >
/// Indeterminate > Bogus by how much a caller may rely on it.
///
/// Bogus is weakest deliberately: it is the only status that forbids falling
/// back to PKIX, so a set containing one bogus record must be reported bogus
/// rather than merely unvalidated.
pub(crate) const fn weaker(a: DnssecStatus, b: DnssecStatus) -> DnssecStatus {
    const fn rank(status: DnssecStatus) -> u8 {
        match status {
            DnssecStatus::Bogus => 0,
            DnssecStatus::Indeterminate => 1,
            DnssecStatus::Insecure => 2,
            DnssecStatus::Secure => 3,
        }
    }
    if rank(a) <= rank(b) {
        a
    } else {
        b
    }
}

/// Converts hickory's TLSA rdata into this workspace's record type.
fn convert_record(tlsa: &hickory_proto::rr::rdata::TLSA) -> TlsaRecord {
    TlsaRecord::new(
        TlsaUsage::from_octet(u8::from(tlsa.cert_usage)),
        TlsaSelector::from_octet(u8::from(tlsa.selector)),
        TlsaMatchingType::from_octet(u8::from(tlsa.matching)),
        tlsa.cert_data.clone(),
    )
}

/// Decides whether a lookup error is a failure or a determinate answer.
///
/// `NoRecordsFound` is not a failure: it means DNS answered that the name has
/// no TLSA records. That is an authenticated denial when the zone is signed,
/// and the DNSSEC state hickory attached to the negative answer is what
/// distinguishes "the domain signed that it publishes no TLSA record" from
/// "something ate the answer".
fn classify_lookup_error(err: &NetError) -> Result<TlsaResponse, DaneError> {
    // DNS answered that the name holds no TLSA records. Whether that is an
    // authenticated denial — the zone has signed a statement that it
    // publishes no TLSA record — or an unsigned nothing that an attacker
    // could have produced by stripping records is carried by the negative
    // answer's own DNSSEC state, which `NoRecords` does surface.
    if let NetError::Dns(DnsError::NoRecordsFound(no_records)) = err {
        return Ok(TlsaResponse::new(
            Vec::new(),
            negative_answer_status(no_records),
        ));
    }
    Err(DaneError::ResolutionFailed(err.to_string()))
}

/// DNSSEC status of a negative answer — RFC 7672 §3.1.3.
///
/// A signed NODATA or NXDOMAIN is a statement the zone signed, so a client
/// knows DANE is deliberately absent rather than merely missing. That is
/// what [`TlsaResponse::is_authenticated_denial`] reports, and it is a
/// stronger fact than an unsigned nothing: nothing was stripped.
///
/// The denial is proven by the authority section — the NSEC or NSEC3
/// records and their signatures — and by the SOA. So the status is taken
/// from the proofs hickory attached to those records, and `Secure` is
/// returned only when every one of them is `Secure` and there is at least
/// one to inspect.
///
/// Erring in the other direction is the unsafe one. Reporting `Secure`
/// for a negative answer that was not validated would let a stripped
/// response pass as a deliberate absence, which is the attack DANE exists
/// to stop, so anything short of a complete `Secure` set degrades:
/// `Bogus` if any proof failed validation, `Insecure` if the zone is
/// provably unsigned, and `Indeterminate` when there is nothing to judge
/// — including the case where hickory attached no authority records at
/// all, which is what a resolver with no trust anchors produces.
fn negative_answer_status(no_records: &NoRecords) -> DnssecStatus {
    let mut proofs = Vec::new();
    if let Some(soa) = no_records.soa.as_deref() {
        proofs.push(soa.proof);
    }
    if let Some(authorities) = no_records.authorities.as_deref() {
        proofs.extend(authorities.iter().map(|r| r.proof));
    }

    if proofs.is_empty() {
        return DnssecStatus::Indeterminate;
    }
    // Order matters: a single failed proof outranks any number of good
    // ones, because the denial is only as good as its weakest link.
    if proofs.contains(&Proof::Bogus) {
        return DnssecStatus::Bogus;
    }
    if proofs.contains(&Proof::Insecure) {
        return DnssecStatus::Insecure;
    }
    if proofs.iter().all(|p| *p == Proof::Secure) {
        return DnssecStatus::Secure;
    }
    DnssecStatus::Indeterminate
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Query, ResponseCode};
    use hickory_proto::rr::rdata::SOA;
    use hickory_proto::rr::{Name, RData, Record};

    fn soa_record(proof: Proof) -> Record<SOA> {
        let soa = SOA::new(
            Name::from_ascii("ns.example.").expect("name"),
            Name::from_ascii("hostmaster.example.").expect("name"),
            1,
            7200,
            3600,
            604_800,
            3600,
        );
        let mut r = Record::from_rdata(Name::from_ascii("example.").expect("name"), 3600, soa);
        r.proof = proof;
        r
    }

    fn authority(proof: Proof) -> Record {
        let mut r = Record::from_rdata(
            Name::from_ascii("example.").expect("name"),
            3600,
            RData::NULL(hickory_proto::rr::rdata::NULL::new()),
        );
        r.proof = proof;
        r
    }

    fn no_records(soa: Option<Record<SOA>>, authorities: Vec<Record>) -> NoRecords {
        let mut nr = NoRecords::new(
            Query::query(
                Name::from_ascii("_25._tcp.mail.example.").expect("name"),
                RecordType::TLSA,
            ),
            ResponseCode::NoError,
        );
        nr.soa = soa.map(Box::new);
        if !authorities.is_empty() {
            nr.authorities = Some(authorities.into());
        }
        nr
    }

    fn tlsa_record(proof: Proof) -> Record {
        use hickory_proto::rr::rdata::tlsa::{CertUsage, Matching, Selector};
        let tlsa = hickory_proto::rr::rdata::TLSA::new(
            CertUsage::DaneEe,
            Selector::Spki,
            Matching::Sha256,
            vec![0u8; 32],
        );
        let mut r = Record::from_rdata(
            Name::from_ascii("_25._tcp.mail.example.").expect("name"),
            3600,
            RData::TLSA(tlsa),
        );
        r.proof = proof;
        r
    }

    /// A record whose type is `RRSIG`.
    ///
    /// Built through `RData::Unknown`, which reports its `code` as the
    /// record type, rather than by fabricating a signature: the only
    /// thing [`answer_status`] reads is `record_type()`, and a synthetic
    /// RRSIG body would suggest the signature mattered here when it does
    /// not.
    fn rrsig_record(proof: Proof) -> Record {
        let mut r = Record::from_rdata(
            Name::from_ascii("_25._tcp.mail.example.").expect("name"),
            3600,
            RData::Unknown {
                code: RecordType::RRSIG,
                rdata: hickory_proto::rr::rdata::NULL::new(),
            },
        );
        r.proof = proof;
        assert_eq!(
            r.record_type(),
            RecordType::RRSIG,
            "fixture must be an RRSIG"
        );
        r
    }

    /// An unchainable RRSIG must not drag down data that validated.
    ///
    /// This is the shape `debian.org` presents while midway through an
    /// algorithm rollover: TLSA records `Secure` under algorithm 8,
    /// alongside an `RRSIG` under algorithm 13 that the parent
    /// publishes no DS for, so it comes back `Indeterminate`.
    ///
    /// Oracle: RFC 6840 §5.11 — a validator "MUST NOT insist that all
    /// algorithms signaled in the DNSKEY RRset work", and the zone is
    /// entitled to publish an algorithm the DS set does not cover. The
    /// answer's status is the status of its data.
    #[test]
    fn an_unchainable_rrsig_does_not_weaken_validated_data() {
        let answers = vec![
            tlsa_record(Proof::Secure),
            tlsa_record(Proof::Secure),
            rrsig_record(Proof::Secure),
            rrsig_record(Proof::Indeterminate),
        ];
        assert_eq!(answer_status(&answers), Some(DnssecStatus::Secure));
    }

    /// But a weak *data* record still weakens the answer, which is the
    /// property the RRSIG exclusion must not have cost us. An attacker
    /// who injects one unvalidated record into an otherwise-secure
    /// RRset must not get the set treated as secure.
    #[test]
    fn a_weak_data_record_still_weakens_the_answer() {
        for (weak, expected) in [
            (Proof::Bogus, DnssecStatus::Bogus),
            (Proof::Insecure, DnssecStatus::Insecure),
            (Proof::Indeterminate, DnssecStatus::Indeterminate),
        ] {
            let answers = vec![
                tlsa_record(Proof::Secure),
                tlsa_record(weak),
                rrsig_record(Proof::Secure),
            ];
            assert_eq!(
                answer_status(&answers),
                Some(expected),
                "a {weak:?} TLSA record must still weaken the answer"
            );
        }
    }

    /// An answer of nothing but signatures has no data to judge.
    #[test]
    fn an_answer_of_only_signatures_has_no_status() {
        assert_eq!(answer_status(&[rrsig_record(Proof::Secure)]), None);
        assert_eq!(answer_status(&[]), None);
    }

    /// A validated negative answer is an authenticated denial.
    ///
    /// Oracle: RFC 7672 §3.1.3 — a signed NODATA is a statement the zone
    /// signed, so the client knows DANE is deliberately absent rather
    /// than stripped. This is what `is_authenticated_denial` reports,
    /// and it was unreachable before: every negative answer came back
    /// Indeterminate.
    #[test]
    fn a_validated_negative_answer_is_secure() {
        let nr = no_records(
            Some(soa_record(Proof::Secure)),
            vec![authority(Proof::Secure)],
        );
        assert_eq!(negative_answer_status(&nr), DnssecStatus::Secure);
    }

    /// The direction that must never be wrong: anything short of a
    /// complete Secure set must not report Secure, because that would
    /// let a stripped response pass as a deliberate absence — the attack
    /// DANE exists to stop.
    #[test]
    fn an_unvalidated_negative_answer_is_never_secure() {
        for (soa, auth, expected) in [
            // Nothing to judge: no authority section at all, which is
            // what a resolver with no trust anchors produces.
            (None, vec![], DnssecStatus::Indeterminate),
            // A failed proof outranks any number of good ones.
            (
                Some(soa_record(Proof::Secure)),
                vec![authority(Proof::Bogus)],
                DnssecStatus::Bogus,
            ),
            (
                Some(soa_record(Proof::Bogus)),
                vec![authority(Proof::Secure)],
                DnssecStatus::Bogus,
            ),
            // Provably unsigned zone.
            (
                Some(soa_record(Proof::Insecure)),
                vec![authority(Proof::Insecure)],
                DnssecStatus::Insecure,
            ),
            // Mixed Secure/Insecure is still not a validated denial.
            (
                Some(soa_record(Proof::Secure)),
                vec![authority(Proof::Insecure)],
                DnssecStatus::Insecure,
            ),
            // Indeterminate anywhere means the chain did not reach it.
            (
                Some(soa_record(Proof::Indeterminate)),
                vec![authority(Proof::Secure)],
                DnssecStatus::Indeterminate,
            ),
        ] {
            let nr = no_records(soa, auth);
            let got = negative_answer_status(&nr);
            assert_eq!(got, expected, "expected {expected:?}, got {got:?}");
            assert_ne!(
                got,
                DnssecStatus::Secure,
                "an unvalidated denial must never report Secure"
            );
        }
    }
}
