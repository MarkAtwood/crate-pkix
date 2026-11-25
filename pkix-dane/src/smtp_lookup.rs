//! SMTP DANE discovery — RFC 7672 §2.1 and §2.2, as a sans-IO state machine.
//!
//! Finding out whether DANE applies to an SMTP delivery takes several DNS
//! lookups whose order and interpretation are constrained by the RFC. The
//! decisions are pure functions of DNS answers, so they live here, in
//! `no_std`, and the lookups themselves stay with whoever has a resolver —
//! the same split as [`pkix_chain::sans_io`].
//!
//! Driving it: call [`MxResolution::next_step`], perform the lookup it names,
//! hand the answer to [`MxResolution::absorb`], repeat. [`resolve_with`] does
//! that loop for a caller who has a synchronous lookup function.
//!
//! # The two requirements this exists to get right
//!
//! Both are MUSTs that a straightforward implementation violates.
//!
//! **MX preference order outranks channel security** (§2.2.1):
//!
//! > an MX hostname with a worse (numerically higher) MX preference that has
//! > TLSA records MUST NOT preempt an MX hostname with a better (numerically
//! > lower) preference that has no TLSA records. In other words, prevention
//! > of delivery loops by obeying MX preferences MUST take precedence over
//! > channel security considerations.
//!
//! Preferring the host that offers DANE is a conformance bug, and a tempting
//! one. Hosts are tried strictly in preference order here, and
//! [`a_secure_backup_mx_does_not_preempt_an_insecure_primary`] is the test
//! that says so.
//!
//! **Address lookups precede TLSA lookups** (§2.2.2):
//!
//! > the SMTP client MUST perform any A and/or AAAA queries for the
//! > destination before attempting to locate the associated TLSA records.
//!
//! Not an optimization. Load-balancing nameservers at some large providers
//! answer TLSA queries with SERVFAIL or NOTIMP rather than an "insecure"
//! negative reply, and a client that queried TLSA first would delay such mail
//! and eventually return it to the sender. The address answer also supplies
//! the DNSSEC status that decides whether a TLSA query is worth making at
//! all.
//!
//! [`a_secure_backup_mx_does_not_preempt_an_insecure_primary`]: https://docs.rs/pkix-dane
//! [`pkix_chain::sans_io`]: https://docs.rs/pkix-chain

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::record::{TlsaRecord, TlsaUsage};
use crate::smtp::SmtpIdentities;
use crate::{DnssecStatus, TlsaResponse};

/// Whether an RRset is usable as authenticated data, per RFC 7672 §2.1.1.
///
/// The RFC collapses two of [`DnssecStatus`]'s four values:
///
/// > DNS records that would be classified "indeterminate" in the sense of
/// > RFC 4035 are simply classified as "insecure".
///
/// and requires that "All 'insecure' RRsets MUST be handled identically". So
/// this profile sees three outcomes, not four, and the collapse happens at
/// the boundary rather than being left for each decision site to remember.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RrsetTrust {
    /// DNSSEC-validated. Usable to authenticate.
    Secure,
    /// Not validated, for any reason. Covers both `Insecure` and
    /// `Indeterminate`.
    Insecure,
    /// Validation failed. A signal of tampering, not merely of absence.
    Bogus,
}

impl From<DnssecStatus> for RrsetTrust {
    fn from(status: DnssecStatus) -> Self {
        match status {
            DnssecStatus::Secure => Self::Secure,
            // §2.1.1: indeterminate is a transient inability to locate the
            // records, and is classified as insecure.
            DnssecStatus::Insecure | DnssecStatus::Indeterminate => Self::Insecure,
            DnssecStatus::Bogus => Self::Bogus,
        }
    }
}

/// One MX record: a preference and a hostname.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MxRecord {
    /// Preference value. Numerically lower is preferred.
    pub preference: u16,
    /// The mail exchanger's hostname.
    pub host: String,
}

impl MxRecord {
    /// Convenience constructor.
    #[must_use]
    pub fn new(preference: u16, host: &str) -> Self {
        Self {
            preference,
            host: host.to_string(),
        }
    }
}

/// Policy for an SMTP DANE delivery attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SmtpDaneConfig {
    /// DANE TLS is mandatory for this destination (RFC 7672 §6).
    ///
    /// When set, an "insecure" MX RRset means delivery MUST be delayed rather
    /// than attempted in the clear, because the MX hostnames cannot be
    /// trusted and falling back would be exactly the downgrade the policy
    /// exists to prevent.
    pub mandatory: bool,

    /// Use TLSA records found via an **"insecure" MX RRset** (§2.2.1).
    ///
    /// The case this serves: a hosting provider has a signed zone and
    /// publishes TLSA records for its SMTP servers, while a hosted customer
    /// domain is unsigned. Electing DANE then protects the connection to the
    /// provider's server even though the MX redirection itself was not
    /// authenticated.
    ///
    /// The reference identity narrows accordingly — the MX hostname becomes
    /// the only identifier, via [`SmtpIdentities::insecure_mx`] — because an
    /// attacker who can rewrite an unsigned MX RRset chooses that hostname,
    /// so nothing about the intended destination has been proven.
    pub dane_despite_insecure_mx: bool,

    /// How many CNAMEs to follow while expanding the initial name (§2.2.1).
    ///
    /// MTAs "typically support recursion in CNAME expansion... up to the
    /// MTA's recursion limit". The RFC sets no number; this is that limit.
    pub max_cname_depth: u8,
}

impl Default for SmtpDaneConfig {
    /// Opportunistic, not mandatory; DANE not used via insecure MX; eight
    /// CNAMEs.
    ///
    /// `dane_despite_insecure_mx` defaults off because it changes what a
    /// successful authentication means — §2.2.1 forbids recording it as
    /// secure delivery to the intended next-hop domain — so it should be a
    /// deliberate choice rather than something acquired by taking defaults.
    fn default() -> Self {
        Self::new()
    }
}

impl SmtpDaneConfig {
    /// The default policy: opportunistic, DANE not used via an insecure MX
    /// RRset, eight CNAMEs.
    ///
    /// `#[non_exhaustive]` means a caller cannot use struct-update syntax, so
    /// the `with_*` methods below are how a field is changed — the same shape
    /// as [`pkix_chain::DaneConfig`] and `pkix_dnssec_anchor::RootAnchor`.
    ///
    /// [`pkix_chain::DaneConfig`]: https://docs.rs/pkix-chain
    #[must_use]
    pub const fn new() -> Self {
        Self {
            mandatory: false,
            dane_despite_insecure_mx: false,
            max_cname_depth: 8,
        }
    }

    /// Require DANE for this destination (RFC 7672 §6).
    ///
    /// An insecure MX RRset then delays delivery rather than falling back.
    #[must_use]
    pub const fn with_mandatory(mut self, mandatory: bool) -> Self {
        self.mandatory = mandatory;
        self
    }

    /// Use TLSA records reached via an insecure MX RRset — the
    /// hosting-provider case in §2.2.1.
    ///
    /// See [`SmtpDaneConfig::dane_despite_insecure_mx`] for what this changes
    /// about the reference identity, which is the part worth reading before
    /// enabling it.
    #[must_use]
    pub const fn with_dane_despite_insecure_mx(mut self, allow: bool) -> Self {
        self.dane_despite_insecure_mx = allow;
        self
    }

    /// Set the CNAME expansion limit.
    #[must_use]
    pub const fn with_max_cname_depth(mut self, depth: u8) -> Self {
        self.max_cname_depth = depth;
        self
    }
}

/// The lookup the driver must perform, or the conclusion reached.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MxStep {
    /// Issue an MX query for this domain.
    LookupMx {
        /// The domain to query. Not necessarily the original next-hop: CNAME
        /// expansion replaces it.
        domain: String,
    },

    /// Issue A and/or AAAA queries for this host.
    ///
    /// §2.2.2 requires this **before** the TLSA lookup for the same host.
    LookupAddresses {
        /// The hostname to resolve.
        host: String,
    },

    /// Issue a TLSA query for `_25._tcp.<base_domain>`.
    LookupTlsa {
        /// The TLSA base domain.
        base_domain: String,
    },

    /// Attempt delivery to this server, authenticating as described.
    Deliver(DeliveryTarget),

    /// Delivery must be delayed and retried later.
    Delay(DelayReason),

    /// Every MX host has been offered and none remain.
    ///
    /// Reached after the last [`Deliver`](Self::Deliver) is absorbed. A
    /// driver that delivered successfully stops before this; one that reaches
    /// it has exhausted the destination's servers.
    Exhausted,
}

/// Why delivery must be delayed rather than attempted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DelayReason {
    /// The MX RRset was "insecure" and DANE is mandatory for this
    /// destination (§2.2.1).
    ///
    /// > If the MX RRset (or any CNAME leading to it) is "insecure" and DANE
    /// > TLS for the given destination is mandatory, delivery MUST be
    /// > delayed.
    MandatoryDaneWithInsecureMx,

    /// A DNS lookup returned "bogus", or failed.
    ///
    /// Bogus is evidence of tampering rather than of absence, so it is not
    /// treated as "no records" — doing so would convert an attack into a
    /// silent downgrade. §2.1.2 requires such a destination be treated as
    /// unreachable, which for a sending MTA means delaying.
    DnsFailure,

    /// CNAME expansion exceeded [`SmtpDaneConfig::max_cname_depth`].
    CnameLoop,

    /// DANE is mandatory for this destination and no server offered usable
    /// "secure" TLSA records (RFC 7672 §6).
    ///
    /// > With mandatory DANE TLS, when no usable TLSA records are found,
    /// > message delivery is delayed. Thus, mail is only sent when an
    /// > authenticated TLS channel is established to the remote SMTP server.
    ///
    /// Distinct from [`MandatoryDaneWithInsecureMx`](Self::MandatoryDaneWithInsecureMx):
    /// there the MX hostnames themselves could not be trusted, whereas here
    /// they could and the servers simply publish nothing usable. The
    /// remedies differ — the first is the receiving domain's DNSSEC, the
    /// second its TLSA records — and §6 warns that an administrator running
    /// mandatory DANE has to watch for exactly these.
    MandatoryDaneWithoutUsableTlsa,
}

/// Where a delivery attempt should go, and how to authenticate it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryTarget {
    host: String,
    base_domain: String,
    next_hop: String,
    cname_expanded_next_hop: Option<String>,
    mx_was_secure: bool,
    came_from_mx: bool,
    tlsa: Vec<TlsaRecord>,
}

impl DeliveryTarget {
    /// The SMTP server to connect to.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Whether any record carries a usage this profile can authenticate with.
    ///
    /// DANE-EE(3) and DANE-TA(2) only. A domain publishing nothing but
    /// PKIX-TA(0) / PKIX-EE(1) has published records that cannot authenticate
    /// an SMTP connection — RFC 7672 §3.1.3 — so DANE does not apply even
    /// though the TLSA RRset is non-empty.
    ///
    /// Observed in the wild: `huque.com` publishes PKIX-EE(1) alongside
    /// DANE-EE(3) for its mail host, so a set mixing them is not hypothetical.
    fn has_authenticating_usage(&self) -> bool {
        self.tlsa
            .iter()
            .any(|r| matches!(r.usage(), TlsaUsage::DaneEe | TlsaUsage::DaneTa))
    }

    /// Whether DANE authentication applies, and with which records.
    ///
    /// `Some` means at least one usable "secure" TLSA record was found, and
    /// RFC 7672 §3.2 then applies in full:
    ///
    /// > When at least one usable "secure" TLSA record is found, the SMTP
    /// > client MUST use TLSA records to authenticate the SMTP server.
    /// > Messages MUST NOT be delivered via the SMTP server if authentication
    /// > fails.
    ///
    /// So this is not a hint. A caller that falls back to unauthenticated
    /// delivery after a DANE failure has violated a MUST NOT, and
    /// [`SmtpDaneConfig`] offers no setting that permits it.
    ///
    /// `None` means pre-DANE opportunistic TLS, or cleartext: no TLSA records
    /// were found, or only "insecure" ones, so there is nothing to
    /// authenticate against.
    #[must_use]
    pub fn dane_records(&self) -> Option<&[TlsaRecord]> {
        if self.has_authenticating_usage() {
            Some(&self.tlsa)
        } else {
            None
        }
    }

    /// The reference identifiers for a DANE-TA(2) name check, per §3.2.2.
    ///
    /// Returns `None` when [`dane_records`](Self::dane_records) does, since
    /// there is no DANE authentication to perform.
    ///
    /// The set is narrower when the MX RRset was "insecure": the MX hostname
    /// alone. See [`SmtpDaneConfig::dane_despite_insecure_mx`].
    #[must_use]
    pub fn identities(&self) -> Option<SmtpIdentities<'_>> {
        if !self.has_authenticating_usage() {
            return None;
        }
        if !self.came_from_mx {
            return Some(SmtpIdentities::non_mx(
                &self.base_domain,
                self.cname_expanded_next_hop
                    .as_deref()
                    .map(|_| self.next_hop.as_str()),
            ));
        }
        if self.mx_was_secure {
            Some(SmtpIdentities::secure_mx(
                &self.base_domain,
                &self.next_hop,
                self.cname_expanded_next_hop.as_deref(),
            ))
        } else {
            Some(SmtpIdentities::insecure_mx(&self.base_domain))
        }
    }

    /// The TLSA records as a [`TlsaResponse`], for the verify functions.
    ///
    /// The status is always [`DnssecStatus::Secure`]: records reach a
    /// `DeliveryTarget` only through a "secure" answer, because §2.2.1 makes
    /// insecure ones inapplicable and they are dropped during discovery
    /// rather than carried forward with a weaker label.
    ///
    /// Unlike [`dane_records`](Self::dane_records) this includes records whose
    /// usage this profile cannot authenticate with, so a caller can tell
    /// "the domain published only PKIX usages" from "the domain published
    /// nothing". `None` only when no usable record was found at all.
    #[must_use]
    pub fn tlsa_response(&self) -> Option<TlsaResponse> {
        if self.tlsa.is_empty() {
            None
        } else {
            Some(TlsaResponse::new(self.tlsa.clone(), DnssecStatus::Secure))
        }
    }

    /// Whether the MX RRset that produced this host was DNSSEC-validated.
    ///
    /// Exposed for logging, which §2.2.1 constrains:
    ///
    /// > Any successful authentication via an insecurely determined MX host
    /// > MUST NOT be misrepresented in the mail logs as secure delivery to
    /// > the intended next-hop domain.
    ///
    /// A log line that records the next-hop domain as the destination needs
    /// this to be true. §2.2.1 also asks that MX hostnames from insecure
    /// lookups be logged **unexpanded**, which is why
    /// [`next_hop`](Self::next_hop) stays available alongside the expansion.
    #[must_use]
    pub fn mx_was_secure(&self) -> bool {
        self.mx_was_secure
    }

    /// Whether this host came from an MX RRset, as opposed to being the
    /// destination domain itself or a configured relay.
    #[must_use]
    pub fn came_from_mx(&self) -> bool {
        self.came_from_mx
    }

    /// The original next-hop domain, before any CNAME expansion.
    #[must_use]
    pub fn next_hop(&self) -> &str {
        &self.next_hop
    }
}

/// A DNS answer, handed back to [`MxResolution::absorb`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MxAnswer {
    /// The MX RRset.
    Mx {
        /// DNSSEC status of the RRset, or of the weakest link in any CNAME
        /// chain leading to it.
        status: DnssecStatus,
        /// The records. Need not be sorted; this module sorts them.
        records: Vec<MxRecord>,
    },

    /// The queried name is a CNAME; the MX lookup must be repeated against
    /// the target (§2.2.1).
    MxCname {
        /// DNSSEC status of the CNAME record.
        status: DnssecStatus,
        /// The name to query instead.
        target: String,
    },

    /// No MX records exist for the domain.
    ///
    /// §2.2.2: "the domain's name is implicitly also its sole SMTP server
    /// name."
    NoMx {
        /// DNSSEC status of the negative answer.
        status: DnssecStatus,
    },

    /// Address records for the current host.
    Addresses {
        /// DNSSEC status of the **first** query response, which is what
        /// §2.2.2 keys the TLSA decision on.
        status: DnssecStatus,
        /// Whether any A or AAAA record was found. `false` means the host is
        /// unreachable.
        found: bool,
    },

    /// TLSA records for the current base domain.
    Tlsa {
        /// DNSSEC status of the TLSA RRset.
        status: DnssecStatus,
        /// The records. Unusable ones are filtered here.
        records: Vec<TlsaRecord>,
    },

    /// The lookup could not be completed: SERVFAIL, timeout, or similar.
    ///
    /// §2.2.1 is explicit for the TLSA case: "any errors during TLSA lookups
    /// MUST... cause the SMTP server in question to be treated as
    /// unreachable". Failing open would let an attacker who can drop TLSA
    /// responses downgrade every connection.
    LookupFailed,
}

/// Which lookup the machine is waiting on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Awaiting {
    Mx,
    Addresses,
    Tlsa,
    Nothing,
}

/// SMTP DANE discovery for one next-hop domain.
///
/// See the [module documentation](self) for the driving loop.
#[derive(Clone, Debug)]
pub struct MxResolution {
    config: SmtpDaneConfig,
    next_hop: String,
    /// The name to query MX for; replaced by CNAME expansion.
    mx_query_name: String,
    /// Set once the initial name turned out to be a CNAME.
    cname_expanded_next_hop: Option<String>,
    cname_depth: u8,
    /// Hosts in MX preference order, strictly. Never reordered by TLSA
    /// availability — see the module docs.
    hosts: Vec<String>,
    host_index: usize,
    /// Whether the MX RRset was secure. `None` until the MX answer arrives.
    mx_secure: Option<bool>,
    came_from_mx: bool,
    awaiting: Awaiting,
    /// Set when the current host's address lookup says a TLSA query is
    /// pointless (§2.2.2) or impossible.
    skip_tlsa_for_host: bool,
    /// TLSA records for the current host, once looked up.
    current_tlsa: Vec<TlsaRecord>,
    /// A terminal verdict, once reached.
    terminal: Option<DelayReason>,
    /// Whether some host was passed over because mandatory DANE found no
    /// usable TLSA records for it. Decides the delay reason on exhaustion.
    skipped_for_want_of_tlsa: bool,
    /// Whether any host was ever offered as a delivery target. A host passed
    /// over for want of usable records is only §6's delay when no host was
    /// deliverable at all; one that was offered and declined by the driver is
    /// the driver's business.
    offered_any: bool,
    done: bool,
}

impl MxResolution {
    /// Begin discovery for a next-hop domain subject to MX resolution.
    #[must_use]
    pub fn new(next_hop: &str, config: SmtpDaneConfig) -> Self {
        Self {
            config,
            next_hop: next_hop.to_string(),
            mx_query_name: next_hop.to_string(),
            cname_expanded_next_hop: None,
            cname_depth: 0,
            hosts: Vec::new(),
            host_index: 0,
            mx_secure: None,
            came_from_mx: true,
            awaiting: Awaiting::Mx,
            skip_tlsa_for_host: false,
            current_tlsa: Vec::new(),
            terminal: None,
            skipped_for_want_of_tlsa: false,
            offered_any: false,
            done: false,
        }
    }

    /// Begin discovery for a host **not** subject to MX resolution — an
    /// administrator-configured relay (§2.2.2).
    ///
    /// Skips the MX lookup entirely and treats `host` as the sole SMTP
    /// server. The reference identity follows §2.2.2's non-MX rule rather
    /// than its MX rule, which matters: there is no MX RRset whose security
    /// status could narrow the identifier set.
    #[must_use]
    pub fn relay(host: &str, config: SmtpDaneConfig) -> Self {
        let mut this = Self::new(host, config);
        this.hosts.push(host.to_string());
        this.came_from_mx = false;
        // No MX RRset was consulted, so its security is not in question.
        this.mx_secure = Some(true);
        this.awaiting = Awaiting::Addresses;
        this
    }

    /// What to do next.
    ///
    /// Pure: call it as often as convenient. State advances only in
    /// [`absorb`](Self::absorb).
    #[must_use]
    pub fn next_step(&self) -> MxStep {
        if let Some(reason) = self.terminal {
            return MxStep::Delay(reason);
        }
        // §6: mandatory DANE delays rather than reporting a dead end when the
        // reason every host was passed over is that none published usable
        // TLSA records. The distinction matters to the sending MTA: this is a
        // retryable condition at the receiving domain, not an exhausted list
        // of servers.
        if self.done && self.skipped_for_want_of_tlsa && !self.offered_any {
            return MxStep::Delay(DelayReason::MandatoryDaneWithoutUsableTlsa);
        }
        match self.awaiting {
            Awaiting::Mx => MxStep::LookupMx {
                domain: self.mx_query_name.clone(),
            },
            Awaiting::Addresses => match self.hosts.get(self.host_index) {
                Some(host) => MxStep::LookupAddresses { host: host.clone() },
                None => MxStep::Exhausted,
            },
            Awaiting::Tlsa => match self.hosts.get(self.host_index) {
                // The TLSA base domain for an MX host is the MX hostname
                // itself (§2.2.2 treats each as a non-MX destination).
                Some(host) => MxStep::LookupTlsa {
                    base_domain: host.clone(),
                },
                None => MxStep::Exhausted,
            },
            Awaiting::Nothing => match self.hosts.get(self.host_index) {
                Some(host) => MxStep::Deliver(DeliveryTarget {
                    host: host.clone(),
                    base_domain: host.clone(),
                    next_hop: self.next_hop.clone(),
                    cname_expanded_next_hop: self.cname_expanded_next_hop.clone(),
                    mx_was_secure: self.mx_secure.unwrap_or(false),
                    came_from_mx: self.came_from_mx,
                    tlsa: self.current_tlsa.clone(),
                }),
                None => MxStep::Exhausted,
            },
        }
    }

    /// Feed in the answer to the lookup [`next_step`](Self::next_step) asked
    /// for.
    ///
    /// An answer of the wrong kind for the current state is ignored rather
    /// than panicking: a driver that mixes up two outstanding queries should
    /// stall and be debugged, not abort a mail server.
    pub fn absorb(&mut self, answer: MxAnswer) {
        if self.terminal.is_some() || self.done {
            return;
        }
        match (self.awaiting, answer) {
            // ---- MX ----
            (Awaiting::Mx, MxAnswer::MxCname { status, target }) => {
                if RrsetTrust::from(status) == RrsetTrust::Bogus {
                    self.terminal = Some(DelayReason::DnsFailure);
                    return;
                }
                if self.cname_depth >= self.config.max_cname_depth {
                    self.terminal = Some(DelayReason::CnameLoop);
                    return;
                }
                self.cname_depth += 1;
                // §2.2.1: "If the MX RRset (or any CNAME leading to it) is
                // 'insecure'" — so an insecure CNAME taints the result even
                // if the eventual MX RRset is signed. Recorded by weakening,
                // never strengthening.
                if RrsetTrust::from(status) != RrsetTrust::Secure {
                    self.mx_secure = Some(false);
                }
                self.cname_expanded_next_hop = Some(target.clone());
                self.mx_query_name = target;
            }

            (Awaiting::Mx, MxAnswer::Mx { status, records }) => {
                let trust = RrsetTrust::from(status);
                if trust == RrsetTrust::Bogus {
                    self.terminal = Some(DelayReason::DnsFailure);
                    return;
                }
                let secure = trust == RrsetTrust::Secure && self.mx_secure != Some(false);
                self.mx_secure = Some(secure);

                if !secure && self.config.mandatory {
                    // §2.2.1: insecure MX plus mandatory DANE MUST delay.
                    self.terminal = Some(DelayReason::MandatoryDaneWithInsecureMx);
                    return;
                }

                self.hosts = sort_by_preference(records);
                self.host_index = 0;
                self.awaiting = Awaiting::Addresses;
            }

            (Awaiting::Mx, MxAnswer::NoMx { status }) => {
                let trust = RrsetTrust::from(status);
                if trust == RrsetTrust::Bogus {
                    self.terminal = Some(DelayReason::DnsFailure);
                    return;
                }
                // §2.2.2: a domain with no MX records is its own SMTP server,
                // and is then handled by the non-MX rules — including for the
                // reference identity, which is why came_from_mx is cleared.
                let secure = trust == RrsetTrust::Secure && self.mx_secure != Some(false);
                self.mx_secure = Some(secure);
                if !secure && self.config.mandatory {
                    self.terminal = Some(DelayReason::MandatoryDaneWithInsecureMx);
                    return;
                }
                self.hosts = Vec::from([self.mx_query_name.clone()]);
                self.host_index = 0;
                self.came_from_mx = false;
                self.awaiting = Awaiting::Addresses;
            }

            (Awaiting::Mx, MxAnswer::LookupFailed) => {
                self.terminal = Some(DelayReason::DnsFailure);
            }

            // ---- Addresses, which §2.2.2 requires before TLSA ----
            (Awaiting::Addresses, MxAnswer::Addresses { status, found }) => {
                if !found {
                    // §2.2.2: "If no address records are found, the
                    // destination is unreachable." Next host, in preference
                    // order.
                    self.advance_host();
                    return;
                }
                let trust = RrsetTrust::from(status);
                // §2.2.2: with an insecure first response, "the SMTP client
                // SHOULD NOT proceed to search for any associated TLSA
                // records" — such zones hold no secure TLSA records, and
                // querying them is what triggers the broken-nameserver
                // behaviour the ordering rule exists to avoid.
                //
                // Bogus is not merely insecure, but the outcome is the same
                // here: no TLSA lookup. The destination is still reachable,
                // so this is not a delay.
                self.skip_tlsa_for_host = trust != RrsetTrust::Secure;
                if self.skip_tlsa_for_host {
                    if self.config.mandatory {
                        // No TLSA query will be made, so no usable records can
                        // be found for this host. §6 again.
                        self.skipped_for_want_of_tlsa = true;
                        self.advance_host();
                    } else {
                        self.awaiting = Awaiting::Nothing;
                    }
                } else {
                    self.awaiting = Awaiting::Tlsa;
                }
            }

            (Awaiting::Addresses, MxAnswer::LookupFailed) => {
                // An address lookup failure makes this host unreachable, not
                // the destination: a backup MX may still answer.
                self.advance_host();
            }

            // ---- TLSA ----
            (Awaiting::Tlsa, MxAnswer::Tlsa { status, records }) => {
                let trust = RrsetTrust::from(status);
                if trust == RrsetTrust::Secure {
                    // Only usable records count. §2.2.1: "When, for a given
                    // MX hostname, no TLSA records are found or only
                    // 'insecure' TLSA records are found, DANE TLSA is not
                    // applicable."
                    let usable: Vec<TlsaRecord> =
                        records.into_iter().filter(TlsaRecord::is_usable).collect();

                    let may_use = self.mx_secure == Some(true)
                        || self.config.dane_despite_insecure_mx
                        || !self.came_from_mx;
                    self.current_tlsa = if may_use { usable } else { Vec::new() };
                } else {
                    // Insecure or bogus TLSA records authenticate nothing.
                    self.current_tlsa = Vec::new();
                }
                if self.config.mandatory && !self.current_has_authenticating_usage() {
                    // §6: nothing to authenticate with, so this server cannot
                    // be used. Try the next in preference order; only when
                    // none has usable records is delivery delayed.
                    self.skipped_for_want_of_tlsa = true;
                    self.advance_host();
                } else {
                    self.awaiting = Awaiting::Nothing;
                }
            }

            (Awaiting::Tlsa, MxAnswer::LookupFailed) => {
                // §2.2.1, and the only place in this profile where a failed
                // lookup makes a *reachable* server unusable: "any errors
                // during TLSA lookups MUST... cause the SMTP server in
                // question to be treated as unreachable."
                self.advance_host();
            }

            // ---- A delivery target was offered and the driver came back ----
            (Awaiting::Nothing, _) => {
                if self.host_index < self.hosts.len() {
                    self.offered_any = true;
                }
                self.advance_host();
            }

            // Mismatched answer: ignored. See the method docs.
            _ => {}
        }
    }

    /// Whether the current host's records include a usage we can authenticate
    /// with. See `DeliveryTarget::has_authenticating_usage`.
    fn current_has_authenticating_usage(&self) -> bool {
        self.current_tlsa
            .iter()
            .any(|r| matches!(r.usage(), TlsaUsage::DaneEe | TlsaUsage::DaneTa))
    }

    /// Move to the next MX host, in preference order.
    fn advance_host(&mut self) {
        self.host_index += 1;
        self.current_tlsa = Vec::new();
        self.skip_tlsa_for_host = false;
        self.awaiting = if self.host_index < self.hosts.len() {
            Awaiting::Addresses
        } else {
            self.done = true;
            Awaiting::Nothing
        };
    }

    /// The MX hosts, in the order they will be tried.
    #[must_use]
    pub fn hosts(&self) -> &[String] {
        &self.hosts
    }
}

/// Sort MX records into the order they must be tried.
///
/// Strictly by preference, numerically ascending. TLSA availability is not an
/// input, and that is the point: §2.2.1 makes reordering on it a MUST NOT.
///
/// Equal preferences keep their input order. RFC 5321 §5.1 asks that
/// equal-preference MX records be tried in random order to spread load, and
/// RFC 7672 §2.2.1 adds that "even with two equal-preference MX records, an
/// MTA is not obligated to choose the MX hostname that offers more security".
/// Randomizing is therefore the caller's to do — by shuffling before calling
/// — which keeps this function deterministic and the state machine testable.
fn sort_by_preference(mut records: Vec<MxRecord>) -> Vec<String> {
    records.sort_by_key(|r| r.preference);
    records.into_iter().map(|r| r.host).collect()
}

/// Drive a resolution to completion with a synchronous lookup function.
///
/// `lookup` is called with each [`MxStep`] that names a query and must return
/// the corresponding [`MxAnswer`]; returning [`MxAnswer::LookupFailed`] is
/// always acceptable. `on_target` is called for each [`DeliveryTarget`] in
/// preference order and returns `true` to stop — a driver returns `true` once
/// a message has been delivered.
///
/// # Errors
///
/// - `Err(Some(reason))` — discovery concluded that delivery must be delayed
///   and retried later. The destination's servers were not exhausted; the
///   reason says what went wrong.
/// - `Err(None)` — every host was offered in preference order and
///   `on_target` accepted none.
///
/// The two are distinct because a sending MTA treats them differently: a
/// delay is requeued and retried, whereas exhausting every host after trying
/// each one is a delivery failure to report.
pub fn resolve_with<L, T>(
    mut resolution: MxResolution,
    mut lookup: L,
    mut on_target: T,
) -> Result<(), Option<DelayReason>>
where
    L: FnMut(&MxStep) -> MxAnswer,
    T: FnMut(&DeliveryTarget) -> bool,
{
    loop {
        let step = resolution.next_step();
        match &step {
            MxStep::Delay(reason) => return Err(Some(*reason)),
            MxStep::Exhausted => return Err(None),
            MxStep::Deliver(target) => {
                if on_target(target) {
                    return Ok(());
                }
                resolution.absorb(MxAnswer::LookupFailed);
            }
            MxStep::LookupMx { .. }
            | MxStep::LookupAddresses { .. }
            | MxStep::LookupTlsa { .. } => {
                let answer = lookup(&step);
                resolution.absorb(answer);
            }
        }
    }
}
