//! Async SMTP DANE discovery — the driver for [`pkix_dane::smtp_lookup`].
//!
//! The policy lives in `pkix-dane`'s sans-IO state machine. This module
//! performs the lookups that machine asks for, so the division is:
//! `pkix-dane` decides, this crate fetches.
//!
//! # The caller owns the loop
//!
//! [`SmtpDiscovery::next_target`] advances discovery until it has something to
//! say, and returns it. A sending MTA then attempts delivery and calls again
//! if that attempt failed:
//!
//! ```ignore
//! let mut discovery = SmtpDiscovery::new(resolver, "example.com", config);
//! loop {
//!     match discovery.next_target().await {
//!         SmtpDiscoveryStep::Target(target) => {
//!             if try_delivery(&target).await.is_ok() {
//!                 break;
//!             }
//!             // else: loop, and the next MX host in preference order is offered
//!         }
//!         SmtpDiscoveryStep::Delay(reason) => return Err(requeue(reason)),
//!         SmtpDiscoveryStep::Exhausted => return Err(no_server_accepted()),
//!     }
//! }
//! ```
//!
//! No callback, because a delivery attempt is itself async and borrows the
//! caller's connection state. Handing `pkix-dane`'s synchronous
//! [`resolve_with`](pkix_dane::smtp_lookup::resolve_with) an async closure is
//! not possible, and an async-callback variant would force the caller's
//! delivery code into a closure body for no gain.
//!
//! # Ordering is not this module's responsibility
//!
//! RFC 7672 §2.2.2 requires address lookups before TLSA lookups, and §2.2.1
//! requires strict MX preference order. Both are enforced by the state
//! machine, which only ever asks for one lookup at a time. A driver cannot
//! get them wrong by answering what it was asked, which is the reason the
//! split is worth the indirection.

use async_trait::async_trait;
use hickory_proto::rr::{RData, RecordType};

use pkix_dane::smtp_lookup::{
    DelayReason, DeliveryTarget, MxAnswer, MxRecord, MxResolution, MxStep, SmtpDaneConfig,
};
use pkix_dane::{DnssecStatus, TlsaName, TlsaProtocol};

use crate::hickory::{proof_to_status, weaker};
use crate::{AsyncTlsaResolver, HickoryTlsaResolver};

/// The lookups SMTP DANE discovery needs.
///
/// Implemented for [`HickoryTlsaResolver`]. A test double or an MTA's existing
/// resolver can implement it instead; every method returns an [`MxAnswer`]
/// rather than a `Result`, because "the lookup failed" is one of the answers
/// the state machine interprets — §2.2.1 makes a failed TLSA lookup mean the
/// server is unreachable, which is a verdict rather than an error.
#[async_trait]
pub trait AsyncSmtpDiscovery: Send + Sync {
    /// Look up the MX RRset for `domain`.
    ///
    /// Returns [`MxAnswer::MxCname`] when the name is an alias,
    /// [`MxAnswer::NoMx`] when it has no MX records, and
    /// [`MxAnswer::LookupFailed`] on transport failure or `SERVFAIL`.
    async fn lookup_mx(&self, domain: &str) -> MxAnswer;

    /// Look up A and/or AAAA records for `host`.
    ///
    /// The DNSSEC status must be that of the **first** query response, which
    /// is what RFC 7672 §2.2.2 keys the TLSA decision on.
    async fn lookup_addresses(&self, host: &str) -> MxAnswer;

    /// Look up TLSA records at `_25._tcp.<base_domain>`.
    async fn lookup_tlsa(&self, base_domain: &str) -> MxAnswer;
}

/// Blanket impls so a shared resolver need not be cloned or wrapped.
///
/// `SmtpDiscovery` takes its discovery source by value, which is convenient
/// for an owned resolver and inconvenient for one shared across deliveries.
/// These let `&resolver` and `Arc<resolver>` be passed directly, mirroring
/// the `Arc` impl on [`AsyncTlsaResolver`].
#[async_trait]
impl<D: AsyncSmtpDiscovery + ?Sized> AsyncSmtpDiscovery for &D {
    async fn lookup_mx(&self, domain: &str) -> MxAnswer {
        (**self).lookup_mx(domain).await
    }
    async fn lookup_addresses(&self, host: &str) -> MxAnswer {
        (**self).lookup_addresses(host).await
    }
    async fn lookup_tlsa(&self, base_domain: &str) -> MxAnswer {
        (**self).lookup_tlsa(base_domain).await
    }
}

#[async_trait]
impl<D: AsyncSmtpDiscovery + ?Sized> AsyncSmtpDiscovery for std::sync::Arc<D> {
    async fn lookup_mx(&self, domain: &str) -> MxAnswer {
        (**self).lookup_mx(domain).await
    }
    async fn lookup_addresses(&self, host: &str) -> MxAnswer {
        (**self).lookup_addresses(host).await
    }
    async fn lookup_tlsa(&self, base_domain: &str) -> MxAnswer {
        (**self).lookup_tlsa(base_domain).await
    }
}

/// What discovery concluded.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum SmtpDiscoveryStep {
    /// Attempt delivery to this server.
    ///
    /// Pass it to `pkix_chain::verify_smtp_server_dane` once the TLS handshake
    /// has produced a certificate chain.
    Target(DeliveryTarget),

    /// Delivery must be delayed and retried later.
    Delay(DelayReason),

    /// Every MX host was offered and the caller accepted none.
    Exhausted,
}

/// Async SMTP DANE discovery for one next-hop domain.
///
/// See the [module documentation](self) for the loop.
#[derive(Debug)]
pub struct SmtpDiscovery<D> {
    resolution: MxResolution,
    discovery: D,
    /// Set once a target has been handed out, so the next call advances past
    /// it rather than offering the same host forever.
    target_outstanding: bool,
}

impl<D: AsyncSmtpDiscovery> SmtpDiscovery<D> {
    /// Begin discovery for a next-hop domain subject to MX resolution.
    pub fn new(discovery: D, next_hop: &str, config: SmtpDaneConfig) -> Self {
        Self {
            resolution: MxResolution::new(next_hop, config),
            discovery,
            target_outstanding: false,
        }
    }

    /// Begin discovery for a host not subject to MX resolution — an
    /// administrator-configured relay (RFC 7672 §2.2.2).
    pub fn relay(discovery: D, host: &str, config: SmtpDaneConfig) -> Self {
        Self {
            resolution: MxResolution::relay(host, config),
            discovery,
            target_outstanding: false,
        }
    }

    /// Advance until discovery has something to report.
    ///
    /// Performs however many lookups the state machine asks for — typically
    /// an MX query, then address and TLSA queries per host — and returns at
    /// the first conclusion. Calling it again after a
    /// [`Target`](SmtpDiscoveryStep::Target) moves on to the next MX host in
    /// preference order, which is how a caller retries after a failed
    /// delivery attempt.
    pub async fn next_target(&mut self) -> SmtpDiscoveryStep {
        if self.target_outstanding {
            // The caller declined the host it was given. Tell the machine, so
            // it advances; the answer kind is immaterial in this state.
            self.resolution.absorb(MxAnswer::LookupFailed);
            self.target_outstanding = false;
        }

        loop {
            match self.resolution.next_step() {
                MxStep::Delay(reason) => return SmtpDiscoveryStep::Delay(reason),
                MxStep::Exhausted => return SmtpDiscoveryStep::Exhausted,
                MxStep::Deliver(target) => {
                    self.target_outstanding = true;
                    return SmtpDiscoveryStep::Target(target);
                }
                MxStep::LookupMx { domain } => {
                    let answer = self.discovery.lookup_mx(&domain).await;
                    self.resolution.absorb(answer);
                }
                MxStep::LookupAddresses { host } => {
                    let answer = self.discovery.lookup_addresses(&host).await;
                    self.resolution.absorb(answer);
                }
                MxStep::LookupTlsa { base_domain } => {
                    let answer = self.discovery.lookup_tlsa(&base_domain).await;
                    self.resolution.absorb(answer);
                }
                // MxStep is #[non_exhaustive]. A step this driver does not
                // understand must not be read as permission to deliver, so it
                // delays: the message is requeued rather than sent over a
                // connection whose discovery was not completed.
                _ => {
                    return SmtpDiscoveryStep::Delay(DelayReason::DnsFailure);
                }
            }
        }
    }

    /// The MX hosts, in the order they will be tried.
    ///
    /// Empty until the MX lookup has been absorbed.
    #[must_use]
    pub fn hosts(&self) -> &[alloc_string::String] {
        self.resolution.hosts()
    }
}

// `hosts()` returns `&[String]`; naming the type without pulling `alloc` into
// this std crate's imports.
use std::string as alloc_string;

#[async_trait]
impl AsyncSmtpDiscovery for HickoryTlsaResolver {
    async fn lookup_mx(&self, domain: &str) -> MxAnswer {
        let lookup = match self.inner().lookup(domain, RecordType::MX).await {
            Ok(lookup) => lookup,
            Err(err) if err.is_no_records_found() => {
                // RFC 7672 §2.2.2: a domain with no MX records is its own SMTP
                // server. The negative answer's own DNSSEC state is not
                // surfaced per-record by this error type, so Indeterminate is
                // the fail-closed reading — §2.1.1 folds it into "insecure",
                // which is the right handling for an unprovable absence.
                return MxAnswer::NoMx {
                    status: DnssecStatus::Indeterminate,
                };
            }
            Err(_) => return MxAnswer::LookupFailed,
        };

        let mut status: Option<DnssecStatus> = None;
        let mut records = Vec::new();
        let mut cname_target: Option<String> = None;

        for record in lookup.answers() {
            // Weakest proof across the answer, as elsewhere in this crate: one
            // injected unvalidated record must not let the set count as
            // secure.
            let proof = proof_to_status(record.proof);
            status = Some(match status {
                None => proof,
                Some(current) => weaker(current, proof),
            });

            match &record.data {
                RData::MX(mx) => records.push(MxRecord::new(
                    mx.preference,
                    mx.exchange.to_utf8().trim_end_matches('.'),
                )),
                // hickory follows CNAMEs itself and returns the chain. The
                // expansion is reported to the state machine rather than
                // swallowed, because RFC 7672 §3.2.2 makes the CNAME-expanded
                // next-hop domain a reference identifier in its own right.
                // That costs one extra MX query — the machine re-asks under
                // the expanded name — and buys a correct identity set.
                RData::CNAME(cname) if records.is_empty() => {
                    cname_target = Some(cname.0.to_utf8().trim_end_matches('.').to_string());
                }
                _ => {}
            }
        }

        let status = status.unwrap_or(DnssecStatus::Indeterminate);

        if records.is_empty() {
            if let Some(target) = cname_target {
                return MxAnswer::MxCname { status, target };
            }
            return MxAnswer::NoMx { status };
        }
        MxAnswer::Mx { status, records }
    }

    async fn lookup_addresses(&self, host: &str) -> MxAnswer {
        let lookup = match self.inner().lookup_ip(host).await {
            Ok(lookup) => lookup,
            Err(err) if err.is_no_records_found() => {
                // §2.2.2: "If no address records are found, the destination is
                // unreachable." A determinate answer, not a failure.
                return MxAnswer::Addresses {
                    status: DnssecStatus::Indeterminate,
                    found: false,
                };
            }
            Err(_) => return MxAnswer::LookupFailed,
        };

        let mut status: Option<DnssecStatus> = None;
        let mut found = false;
        for record in lookup.as_lookup().answers() {
            let proof = proof_to_status(record.proof);
            status = Some(match status {
                None => proof,
                Some(current) => weaker(current, proof),
            });
            if matches!(&record.data, RData::A(_) | RData::AAAA(_)) {
                found = true;
            }
        }

        MxAnswer::Addresses {
            status: status.unwrap_or(DnssecStatus::Indeterminate),
            found,
        }
    }

    async fn lookup_tlsa(&self, base_domain: &str) -> MxAnswer {
        // RFC 6698 §3: _25._tcp.<base domain> for SMTP on port 25.
        let name = match TlsaName::new(25, &TlsaProtocol::Tcp, base_domain) {
            Ok(name) => name,
            // A base domain this crate cannot form a TLSA name for cannot be
            // queried. Reported as a failed lookup, which §2.2.1 makes mean
            // "treat this server as unreachable" — the conservative reading,
            // since the alternative is delivering unauthenticated to a host
            // whose records were never checked.
            Err(_) => return MxAnswer::LookupFailed,
        };

        match self.resolve(&name).await {
            Ok(response) => MxAnswer::Tlsa {
                status: response.dnssec(),
                records: response.records().to_vec(),
            },
            Err(_) => MxAnswer::LookupFailed,
        }
    }
}
