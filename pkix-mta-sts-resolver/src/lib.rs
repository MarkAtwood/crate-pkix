//! `_mta-sts` TXT record lookup — RFC 8461 §3.1.
//!
//! The DNS half of MTA-STS policy discovery. `pkix-mta-sts` holds §3.1's
//! parsing and record-selection rules; this crate performs the query and
//! applies them to what comes back.
//!
//! ```no_run
//! use pkix_mta_sts_resolver::MtaStsResolver;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let resolver = MtaStsResolver::from_system()?;
//! // Queries _mta-sts.example.com TXT
//! let record = resolver.lookup("example.com").await?;
//! println!("policy id: {}", record.id());
//! # Ok(())
//! # }
//! ```
//!
//! # DNSSEC is not required here, unlike DANE
//!
//! `pkix-dane-resolver` sets hickory's `validate` option and refuses an
//! unvalidated answer, because RFC 7672 §2.1.1 makes an indeterminate TLSA
//! lookup equivalent to an insecure one — DANE's whole trust basis is DNSSEC.
//!
//! MTA-STS's is not. RFC 8461 §1 "relies on certification authorities (CAs)
//! and does not require DNSSEC, at a cost of risking malicious downgrades".
//! The TXT record carries no authentication at all; it is a change token
//! pointing at a policy whose trust comes from the HTTPS certificate. So this
//! resolver does **not** require DNSSEC, and requiring it would refuse
//! policies from the overwhelming majority of conforming domains.
//!
//! A deployment that wants DNSSEC on the TXT lookup anyway can have it —
//! pass a resolver configured for validation to
//! [`MtaStsResolver::from_resolver`] — but it should know it is imposing a
//! requirement RFC 8461 does not, and that the protection it buys is small,
//! since an attacker who cannot touch DNS can still serve the policy.
//!
//! # What §3.1 requires, and what this applies
//!
//! - **The name is `_mta-sts.<policy-domain>`**, and §3.4 forbids falling
//!   back to a parent zone, so the domain is used unchanged.
//! - **A CNAME MUST be followed**, directly or through further CNAMEs; §8.2
//!   uses that for policy delegation. Hickory follows CNAMEs itself.
//! - **Records not beginning with the version tag are discarded**, so a
//!   domain may publish other TXT records at the same name.
//! - **If the surviving count is not one, there is no usable policy** —
//!   ambiguity is not resolved by picking one, since which policy is current
//!   is exactly what the id exists to settle.
//! - **Several character-strings in one record join without spaces.** A TXT
//!   record is length-prefixed strings of at most 255 bytes each, so a long
//!   record arrives split, and joining with a space would corrupt whichever
//!   field straddles the boundary.
//!
//! # A failed lookup does not mean "no policy"
//!
//! §3.1: "the absence of a usable TXT record is not by itself sufficient to
//! remove a sender's previously cached policy". So a lookup failure feeds
//! [`pkix_mta_sts::plan`] as an error and that function decides — it returns
//! `UseCached` when a live cached policy exists, not `NoPolicy`.
//!
//! [`LookupError::as_txt_error`] is the bridge, so a caller passes the
//! failure straight through rather than translating it and getting the rule
//! backwards.

#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

use std::net::SocketAddr;
use std::sync::Arc;

use hickory_proto::rr::{RData, RecordType};
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::{Resolver, TokioResolver};
use pkix_mta_sts::discovery::{StsTxtRecord, TxtError};
use pkix_mta_sts::txt_name;

/// Why a `_mta-sts` TXT lookup did not yield a usable record.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LookupErrorKind {
    /// The name does not exist, or holds no TXT records.
    ///
    /// The ordinary case for a domain that has not deployed MTA-STS.
    NoRecords,

    /// Records came back but none was usable, per §3.1.
    Record(TxtError),

    /// The query itself failed — SERVFAIL, a timeout, no reachable server.
    ///
    /// Distinct from [`NoRecords`](Self::NoRecords) because §3.3 asks
    /// senders to "alert administrators... when such attempts fail", and an
    /// operator needs to tell "this domain has no policy" from "our resolver
    /// is broken". The two are identical for delivery and different for
    /// diagnosis.
    Dns(String),
}

/// A `_mta-sts` TXT lookup that did not yield a usable record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupError {
    kind: LookupErrorKind,
    txt: TxtError,
}

impl LookupError {
    /// What went wrong, in detail.
    #[must_use]
    pub const fn kind(&self) -> &LookupErrorKind {
        &self.kind
    }

    /// The failure as [`pkix_mta_sts`] sees it, for [`pkix_mta_sts::plan`].
    ///
    /// §3.1 treats every unusable-record case alike, and a DNS failure
    /// likewise yields no usable record, so this maps to a [`TxtError`] that
    /// `plan` can take directly.
    ///
    /// Using this rather than translating by hand is what keeps the §3.1 rule
    /// intact: a lookup failure must not discard a live cached policy, and
    /// `plan` is where that is decided.
    #[must_use]
    pub const fn as_txt_error(&self) -> &TxtError {
        &self.txt
    }

    fn no_records() -> Self {
        Self {
            kind: LookupErrorKind::NoRecords,
            txt: TxtError::NoStsRecord,
        }
    }

    fn record(e: TxtError) -> Self {
        Self {
            kind: LookupErrorKind::Record(e.clone()),
            txt: e,
        }
    }

    fn dns(msg: String) -> Self {
        Self {
            kind: LookupErrorKind::Dns(msg),
            // A query that failed produced no usable record, which is what
            // §3.1 has a sender act on.
            txt: TxtError::NoStsRecord,
        }
    }
}

impl std::fmt::Display for LookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            LookupErrorKind::NoRecords => f.write_str("no _mta-sts TXT records"),
            LookupErrorKind::Record(e) => write!(f, "no usable _mta-sts TXT record: {e}"),
            LookupErrorKind::Dns(msg) => write!(f, "_mta-sts TXT lookup failed: {msg}"),
        }
    }
}

impl std::error::Error for LookupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            LookupErrorKind::Record(e) => Some(e),
            _ => None,
        }
    }
}

/// Why a resolver could not be built.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResolverError {
    /// The system resolver configuration could not be read or is unusable.
    Construction(String),
}

impl std::fmt::Display for ResolverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Construction(msg) => write!(f, "could not build a resolver: {msg}"),
        }
    }
}

impl std::error::Error for ResolverError {}

/// Looks up `_mta-sts` TXT records and applies §3.1.
#[derive(Clone, Debug)]
pub struct MtaStsResolver {
    inner: Arc<TokioResolver>,
}

impl MtaStsResolver {
    /// Use the system's configured resolvers.
    ///
    /// # Errors
    ///
    /// [`ResolverError::Construction`] if the system configuration cannot be
    /// read.
    pub fn from_system() -> Result<Self, ResolverError> {
        let resolver = TokioResolver::builder_tokio()
            .map_err(|e| ResolverError::Construction(e.to_string()))?
            .build()
            .map_err(|e| ResolverError::Construction(e.to_string()))?;
        Ok(Self {
            inner: Arc::new(resolver),
        })
    }

    /// Use explicit name servers, over UDP with TCP fallback.
    ///
    /// # Errors
    ///
    /// [`ResolverError::Construction`] if `servers` is empty, since a
    /// resolver with nowhere to ask would fail every lookup as a DNS error
    /// and look like every domain lacking a policy.
    pub fn from_name_servers(servers: &[SocketAddr]) -> Result<Self, ResolverError> {
        if servers.is_empty() {
            return Err(ResolverError::Construction(String::from(
                "no name servers given",
            )));
        }
        let name_servers = servers
            .iter()
            .map(|addr| NameServerConfig::udp_and_tcp(addr.ip()))
            .collect();
        let resolver = Resolver::builder_with_config(
            ResolverConfig::from_name_servers(name_servers),
            TokioRuntimeProvider::default(),
        )
        .build()
        .map_err(|e| ResolverError::Construction(e.to_string()))?;
        Ok(Self {
            inner: Arc::new(resolver),
        })
    }

    /// Use a resolver the caller configured.
    ///
    /// The escape hatch for anything this crate does not expose — a
    /// particular timeout, DNS-over-TLS, or DNSSEC validation, which MTA-STS
    /// does not require but a deployment may want anyway.
    #[must_use]
    pub const fn from_resolver(resolver: Arc<TokioResolver>) -> Self {
        Self { inner: resolver }
    }

    /// The underlying resolver, for a caller that needs other queries.
    ///
    /// A sender doing MTA-STS also needs MX records, and running two
    /// resolvers to serve one delivery would double the cache misses.
    #[must_use]
    pub fn inner(&self) -> &TokioResolver {
        &self.inner
    }

    /// Look up and select the `_mta-sts` TXT record for `policy_domain`.
    ///
    /// Queries `_mta-sts.<policy_domain>`, following CNAMEs as §3.1
    /// requires, then applies §3.1's selection: discard records that do not
    /// begin with the version tag, require exactly one to survive, and join
    /// each record's character-strings without spaces.
    ///
    /// # Errors
    ///
    /// [`LookupError`]. Pass [`LookupError::as_txt_error`] to
    /// [`pkix_mta_sts::plan`] rather than deciding from the failure directly
    /// — §3.1 is explicit that an absent record does not discard a cached
    /// policy, and `plan` is what applies that.
    pub async fn lookup(&self, policy_domain: &str) -> Result<StsTxtRecord, LookupError> {
        let name = txt_name(policy_domain);
        let lookup = match self.inner.lookup(&name, RecordType::TXT).await {
            Ok(l) => l,
            Err(e) if e.is_no_records_found() => return Err(LookupError::no_records()),
            Err(e) => return Err(LookupError::dns(e.to_string())),
        };

        // Each TXT record is a sequence of character-strings. §3.1 has them
        // joined without spaces, and the discard test applies to the joined
        // form, so filter on that rather than on the first string.
        //
        // Hickory has already followed any CNAME, which §3.1 requires and
        // §8.2 uses for policy delegation, so the answers are the TXT records
        // at the end of the chain.
        let records: Vec<Vec<&[u8]>> = lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::TXT(txt) => Some(txt.txt_data.iter().map(|b| b.as_ref()).collect()),
                // A CNAME in the answer section alongside the TXT records it
                // points at; not a record to select among.
                _ => None,
            })
            .collect();

        let candidates: Vec<&Vec<&[u8]>> = records
            .iter()
            .filter(|strings| StsTxtRecord::is_sts_txt_strings(strings))
            .collect();

        match candidates.as_slice() {
            [] if records.is_empty() => Err(LookupError::no_records()),
            [] => Err(LookupError::record(TxtError::NoStsRecord)),
            [one] => StsTxtRecord::from_txt_strings(one).map_err(LookupError::record),
            many => Err(LookupError::record(TxtError::MultipleStsRecords(
                many.len(),
            ))),
        }
    }
}

const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<MtaStsResolver>();
    assert_send_sync::<LookupError>();
};
