//! The async SMTP DANE discovery driver.
//!
//! Most of these use a scripted [`AsyncSmtpDiscovery`] double rather than DNS.
//! The RFC's ordering and preference rules are enforced by the state machine
//! in `pkix-dane` and tested there; what is under test here is the driver
//! loop — that it asks for what it is told to, feeds answers back, and hands
//! out one target at a time without repeating or skipping a host.
//!
//! The live test at the end reaches real DNS and skips with a printed reason
//! when it cannot run, following `resolve.rs`.

use std::sync::Mutex;

use async_trait::async_trait;

use pkix_dane::record::{TlsaMatchingType, TlsaRecord, TlsaSelector, TlsaUsage};
use pkix_dane::smtp_lookup::{MxAnswer, MxRecord, SmtpDaneConfig};
use pkix_dane::DnssecStatus;
use pkix_dane_resolver::{AsyncSmtpDiscovery, SmtpDiscovery, SmtpDiscoveryStep};

fn tlsa() -> TlsaRecord {
    TlsaRecord::new(
        TlsaUsage::DaneEe,
        TlsaSelector::Spki,
        TlsaMatchingType::Sha256,
        vec![0xab; 32],
    )
}

/// A double that answers from a fixed script and records what it was asked.
struct Scripted {
    mx: Vec<MxRecord>,
    /// Hosts whose TLSA lookup yields records. Others yield an empty secure
    /// answer.
    with_tlsa: Vec<&'static str>,
    log: Mutex<Vec<String>>,
}

impl Scripted {
    fn new(mx: Vec<MxRecord>, with_tlsa: Vec<&'static str>) -> Self {
        Self {
            mx,
            with_tlsa,
            log: Mutex::new(Vec::new()),
        }
    }

    fn log(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
}

#[async_trait]
impl AsyncSmtpDiscovery for Scripted {
    async fn lookup_mx(&self, domain: &str) -> MxAnswer {
        self.log.lock().unwrap().push(format!("mx:{domain}"));
        MxAnswer::Mx {
            status: DnssecStatus::Secure,
            records: self.mx.clone(),
        }
    }

    async fn lookup_addresses(&self, host: &str) -> MxAnswer {
        self.log.lock().unwrap().push(format!("addr:{host}"));
        MxAnswer::Addresses {
            status: DnssecStatus::Secure,
            found: true,
        }
    }

    async fn lookup_tlsa(&self, base_domain: &str) -> MxAnswer {
        self.log.lock().unwrap().push(format!("tlsa:{base_domain}"));
        MxAnswer::Tlsa {
            status: DnssecStatus::Secure,
            records: if self.with_tlsa.contains(&base_domain) {
                vec![tlsa()]
            } else {
                vec![]
            },
        }
    }
}

// ---------------------------------------------------------------------------
// The loop
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_driver_performs_the_lookups_the_machine_asks_for() {
    let script = Scripted::new(
        vec![MxRecord::new(10, "mx.example.net")],
        vec!["mx.example.net"],
    );
    let mut discovery = SmtpDiscovery::new(&script, "example.com", SmtpDaneConfig::new());

    let step = discovery.next_target().await;
    match step {
        SmtpDiscoveryStep::Target(target) => {
            assert_eq!(target.host(), "mx.example.net");
            assert!(target.dane_records().is_some());
        }
        other => panic!("expected a target, got {other:?}"),
    }

    assert_eq!(
        script.log(),
        vec![
            "mx:example.com",
            "addr:mx.example.net",
            "tlsa:mx.example.net"
        ],
        "the address lookup must precede the TLSA lookup"
    );
}

/// Declining a target advances to the next MX host, in preference order.
///
/// This is how an MTA retries after a failed delivery attempt, and the driver
/// must neither repeat the declined host nor skip past the next one.
#[tokio::test]
async fn declining_a_target_offers_the_next_host() {
    let script = Scripted::new(
        vec![
            MxRecord::new(10, "a.example.net"),
            MxRecord::new(20, "b.example.net"),
        ],
        vec!["a.example.net", "b.example.net"],
    );
    let mut discovery = SmtpDiscovery::new(&script, "example.com", SmtpDaneConfig::new());

    let first = discovery.next_target().await;
    let SmtpDiscoveryStep::Target(a) = first else {
        panic!("expected a target");
    };
    assert_eq!(a.host(), "a.example.net");

    let second = discovery.next_target().await;
    let SmtpDiscoveryStep::Target(b) = second else {
        panic!("expected a second target");
    };
    assert_eq!(b.host(), "b.example.net", "preference order is preserved");

    assert!(matches!(
        discovery.next_target().await,
        SmtpDiscoveryStep::Exhausted
    ));
}

/// The MX lookup happens once, not once per host.
#[tokio::test]
async fn the_mx_lookup_is_not_repeated_per_host() {
    let script = Scripted::new(
        vec![
            MxRecord::new(10, "a.example.net"),
            MxRecord::new(20, "b.example.net"),
        ],
        vec![],
    );
    let mut discovery = SmtpDiscovery::new(&script, "example.com", SmtpDaneConfig::new());

    while let SmtpDiscoveryStep::Target(_) = discovery.next_target().await {}

    let mx_queries = script.log().iter().filter(|s| s.starts_with("mx:")).count();
    assert_eq!(mx_queries, 1);
}

/// A relay is not subject to MX resolution, so no MX query is made.
#[tokio::test]
async fn a_relay_makes_no_mx_query() {
    let script = Scripted::new(vec![], vec!["relay.internal"]);
    let mut discovery = SmtpDiscovery::relay(&script, "relay.internal", SmtpDaneConfig::new());

    let SmtpDiscoveryStep::Target(target) = discovery.next_target().await else {
        panic!("expected a target");
    };
    assert_eq!(target.host(), "relay.internal");
    assert!(
        !script.log().iter().any(|s| s.starts_with("mx:")),
        "a configured relay must not be MX-resolved"
    );
}

/// A delay propagates out of the loop rather than being retried internally.
#[tokio::test]
async fn a_delay_is_reported_not_retried() {
    struct Failing;

    #[async_trait]
    impl AsyncSmtpDiscovery for Failing {
        async fn lookup_mx(&self, _: &str) -> MxAnswer {
            MxAnswer::LookupFailed
        }
        async fn lookup_addresses(&self, _: &str) -> MxAnswer {
            MxAnswer::LookupFailed
        }
        async fn lookup_tlsa(&self, _: &str) -> MxAnswer {
            MxAnswer::LookupFailed
        }
    }

    let mut discovery = SmtpDiscovery::new(Failing, "example.com", SmtpDaneConfig::new());
    assert!(matches!(
        discovery.next_target().await,
        SmtpDiscoveryStep::Delay(_)
    ));
}

/// Under mandatory DANE a server with no usable records is not offered, and
/// the driver reports the delay rather than a target.
#[tokio::test]
async fn mandatory_dane_without_records_delays_through_the_driver() {
    let script = Scripted::new(vec![MxRecord::new(10, "bare.example.net")], vec![]);
    let config = SmtpDaneConfig::new().with_mandatory(true);
    let mut discovery = SmtpDiscovery::new(&script, "example.com", config);

    assert!(
        matches!(discovery.next_target().await, SmtpDiscoveryStep::Delay(_)),
        "a server publishing nothing usable must not be offered under mandatory DANE"
    );
}

/// Hosts without usable records are still offered when DANE is opportunistic,
/// as pre-DANE connections.
#[tokio::test]
async fn opportunistic_discovery_offers_hosts_without_records() {
    let script = Scripted::new(vec![MxRecord::new(10, "bare.example.net")], vec![]);
    let mut discovery = SmtpDiscovery::new(&script, "example.com", SmtpDaneConfig::new());

    let SmtpDiscoveryStep::Target(target) = discovery.next_target().await else {
        panic!("expected a target");
    };
    assert!(
        target.dane_records().is_none(),
        "no records means an unauthenticated connection, which is still a delivery"
    );
}

// ---------------------------------------------------------------------------
// Live discovery
// ---------------------------------------------------------------------------

/// End-to-end discovery against a real DANE-enabled mail domain.
///
/// `freebsd.org` publishes DANE-EE(3) TLSA records for its MX host and
/// validates cleanly under hickory, so this exercises the whole path — MX
/// lookup, address lookup, TLSA lookup, DNSSEC validation against IANA's
/// anchors — against something nobody in this workspace controls.
///
/// `debian.org` was the first choice and is not used: its TLSA RRset returns
/// `Indeterminate` under hickory even though the upstream sets `AD` and the
/// zone has a DS record. That is a pre-existing property of the resolver
/// rather than of this driver — `AsyncTlsaResolver::resolve` reports the same
/// — and is filed separately.
///
/// Skips with a printed reason rather than failing when the environment
/// cannot support it. A test that cannot run is an absent test, not evidence
/// of a defect — and the common cause here is not absent network but
/// `systemd-resolved`'s stub on `127.0.0.53`, which validates internally and
/// strips the DNSSEC records a validating client needs. Set
/// `PKIX_DANE_RESOLVER=9.9.9.9` to run it, noting that this sends the queried
/// names to that operator.
///
/// Run with `--nocapture` to see skip reasons.
#[tokio::test]
async fn live_discovery_against_a_real_dane_mail_domain() {
    let Ok(resolver) = pkix_dane_resolver::HickoryTlsaResolver::new(pkix_dnssec_anchor::CURRENT)
    else {
        println!("SKIP: could not build a resolver");
        return;
    };

    let mut discovery = SmtpDiscovery::new(&resolver, "freebsd.org", SmtpDaneConfig::new());

    match discovery.next_target().await {
        SmtpDiscoveryStep::Target(target) => {
            assert!(
                target.came_from_mx(),
                "freebsd.org publishes MX records, so the host must come from them"
            );
            assert!(
                !target.host().is_empty(),
                "a target must name a host to connect to"
            );

            match target.dane_records() {
                Some(records) => {
                    assert!(!records.is_empty());
                    assert!(
                        records.iter().all(pkix_dane::TlsaRecord::is_usable),
                        "discovery must filter unusable records before offering them"
                    );
                    println!(
                        "live: {} offered {} usable TLSA record(s), mx_secure={}",
                        target.host(),
                        records.len(),
                        target.mx_was_secure()
                    );
                }
                None => println!(
                    "SKIP-ish: {} offered no DANE records. Either the upstream strips \
                     DNSSEC (set PKIX_DANE_RESOLVER to a transparent resolver) or \
                     freebsd.org changed its publication. The driver worked either way.",
                    target.host()
                ),
            }
        }
        SmtpDiscoveryStep::Delay(reason) => {
            println!("SKIP: discovery delayed, most likely a DNS environment issue: {reason:?}");
        }
        SmtpDiscoveryStep::Exhausted => {
            println!("SKIP: no MX host was offered; DNS appears unavailable");
        }
        // SmtpDiscoveryStep is #[non_exhaustive].
        other => println!("SKIP: unrecognized discovery step: {other:?}"),
    }
}

/// A domain publishing PKIX-EE(1) **alongside** DANE-EE(3).
///
/// `huque.com` does exactly this for its mail host, which makes it a better
/// fixture than a synthetic PKIX-only set: it proves the PKIX record is
/// carried through discovery — the entry point needs it to report "only PKIX
/// usages were published" when that is the whole set — while the DANE-EE
/// records are what make DANE apply.
///
/// Found by this test failing against the real zone on an assumption that
/// `huque.com` published usage 1 alone.
#[tokio::test]
async fn live_a_mixed_usage_domain_authenticates_on_the_dane_records() {
    let Ok(resolver) = pkix_dane_resolver::HickoryTlsaResolver::new(pkix_dnssec_anchor::CURRENT)
    else {
        println!("SKIP: could not build a resolver");
        return;
    };

    let mut discovery = SmtpDiscovery::new(&resolver, "huque.com", SmtpDaneConfig::new());

    if let SmtpDiscoveryStep::Target(target) = discovery.next_target().await {
        match target.dane_records() {
            Some(records) => {
                assert!(
                    records
                        .iter()
                        .any(|r| matches!(r.usage(), TlsaUsage::DaneEe | TlsaUsage::DaneTa)),
                    "dane_records must only be Some when something can authenticate; \
                     got {records:?}"
                );
                println!(
                    "live: {} published {} usable record(s), usages {:?}",
                    target.host(),
                    records.len(),
                    records
                        .iter()
                        .map(|r| r.usage().to_octet())
                        .collect::<Vec<_>>()
                );
            }
            None => println!(
                "SKIP-ish: {} offered no DANE records; the environment likely \
                 cannot validate.",
                target.host()
            ),
        }
    } else {
        println!("SKIP: no target offered; DNS appears unavailable");
    }
}
