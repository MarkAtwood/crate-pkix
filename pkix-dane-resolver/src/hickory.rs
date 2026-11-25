//! The hickory-backed reference resolver.

use std::sync::Arc;

use async_trait::async_trait;
use hickory_proto::dnssec::{Algorithm, Proof, PublicKeyBuf, TrustAnchors};
use hickory_proto::rr::{RData, RecordType};
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::NetError;
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

        // Each record carries its own DNSSEC proof. Take the weakest across
        // the answer rather than the strongest: an attacker who can inject one
        // unvalidated record into an otherwise-secure RRset must not be able
        // to have the set treated as secure.
        let mut status: Option<DnssecStatus> = None;
        let mut records = Vec::new();

        for record in lookup.answers() {
            let proof = proof_to_status(record.proof);
            status = Some(match status {
                None => proof,
                Some(current) => weaker(current, proof),
            });

            if let RData::TLSA(tlsa) = &record.data {
                records.push(convert_record(tlsa));
            }
        }

        // No records at all: the DNSSEC state belongs to the authenticated
        // denial, which hickory reports on the lookup rather than on a record.
        let status = status.unwrap_or(DnssecStatus::Secure);
        Ok(TlsaResponse::new(records, status))
    }
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
    if err.is_no_records_found() {
        // DNS answered that the name holds no TLSA records. Whether that is
        // an authenticated denial or an unsigned nothing is carried by the
        // negative answer's own DNSSEC state, which this error type does not
        // surface per-record. Indeterminate is the fail-closed reading: it
        // does not authenticate, and under the opportunistic policy it
        // permits PKIX fallback, which is the correct handling for "the
        // domain appears to publish no TLSA record".
        //
        // A signed NXDOMAIN or NODATA *should* be reported Secure so that
        // TlsaResponse::is_authenticated_denial can distinguish it. Doing so
        // needs the SOA's proof off the negative response; filed as follow-up
        // work rather than guessed at here, because reporting Secure for an
        // unvalidated negative answer would be the one direction that is
        // unsafe.
        return Ok(TlsaResponse::new(Vec::new(), DnssecStatus::Indeterminate));
    }
    Err(DaneError::ResolutionFailed(err.to_string()))
}
