//! RFC 7672 §2.1 / §2.2 discovery: the MX lookup state machine.
//!
//! The headline tests are the two MUSTs a straightforward implementation
//! violates: that MX preference order outranks channel security, and that
//! address lookups precede TLSA lookups. Both have a plausible-looking wrong
//! behaviour that these assert against rather than merely exercising the
//! happy path.

#![cfg(feature = "smtp")]

use pkix_dane::record::{TlsaMatchingType, TlsaRecord, TlsaSelector, TlsaUsage};
use pkix_dane::smtp_lookup::{
    resolve_with, DelayReason, MxAnswer, MxRecord, MxResolution, MxStep, RrsetTrust, SmtpDaneConfig,
};
use pkix_dane::DnssecStatus;

/// A usable DANE-EE(3) / SPKI / SHA-256 record.
fn tlsa() -> TlsaRecord {
    TlsaRecord::new(
        TlsaUsage::DaneEe,
        TlsaSelector::Spki,
        TlsaMatchingType::Sha256,
        vec![0xab; 32],
    )
}

/// A DANE-TA(2) record, for the identity-set assertions.
fn tlsa_ta() -> TlsaRecord {
    TlsaRecord::new(
        TlsaUsage::DaneTa,
        TlsaSelector::Spki,
        TlsaMatchingType::Sha256,
        vec![0xcd; 32],
    )
}

/// Scripted driver: answers lookups from a closure and records every step.
struct Script {
    log: Vec<String>,
    targets: Vec<(String, bool)>,
}

impl Script {
    /// Run `resolution` to exhaustion, never accepting a target, answering
    /// each lookup via `answer`.
    fn run<F>(resolution: MxResolution, mut answer: F) -> (Self, Option<DelayReason>)
    where
        F: FnMut(&MxStep) -> MxAnswer,
    {
        let mut script = Script {
            log: Vec::new(),
            targets: Vec::new(),
        };
        let outcome = resolve_with(
            resolution,
            |step| {
                script.log.push(match step {
                    MxStep::LookupMx { domain } => format!("mx:{domain}"),
                    MxStep::LookupAddresses { host } => format!("addr:{host}"),
                    MxStep::LookupTlsa { base_domain } => format!("tlsa:{base_domain}"),
                    other => format!("unexpected:{other:?}"),
                });
                answer(step)
            },
            |target| {
                script
                    .targets
                    .push((target.host().to_string(), target.dane_records().is_some()));
                false
            },
        );
        let delay = match outcome {
            Err(Some(reason)) => Some(reason),
            _ => None,
        };
        (script, delay)
    }
}

// ---------------------------------------------------------------------------
// §2.1.1: indeterminate collapses into insecure
// ---------------------------------------------------------------------------

#[test]
fn indeterminate_is_treated_as_insecure() {
    assert_eq!(
        RrsetTrust::from(DnssecStatus::Indeterminate),
        RrsetTrust::Insecure
    );
    assert_eq!(
        RrsetTrust::from(DnssecStatus::Insecure),
        RrsetTrust::Insecure
    );
    assert_eq!(RrsetTrust::from(DnssecStatus::Secure), RrsetTrust::Secure);
    assert_eq!(RrsetTrust::from(DnssecStatus::Bogus), RrsetTrust::Bogus);
}

// ---------------------------------------------------------------------------
// §2.2.1: MX preference outranks channel security
// ---------------------------------------------------------------------------

/// The requirement most likely to be implemented backwards.
///
/// > an MX hostname with a worse (numerically higher) MX preference that has
/// > TLSA records MUST NOT preempt an MX hostname with a better (numerically
/// > lower) preference that has no TLSA records.
///
/// `primary` (preference 10) publishes no TLSA records; `backup`
/// (preference 20) does. The primary MUST still be offered first, without
/// DANE. An implementation that sorted on security would offer `backup`
/// first and pass every other test in this file.
#[test]
fn a_secure_backup_mx_does_not_preempt_an_insecure_primary() {
    let resolution = MxResolution::new("example.com", SmtpDaneConfig::default());
    let (script, delay) = Script::run(resolution, |step| match step {
        MxStep::LookupMx { .. } => MxAnswer::Mx {
            status: DnssecStatus::Secure,
            records: vec![
                // Deliberately given worst-first, so a missing sort shows up.
                MxRecord::new(20, "backup.example.net"),
                MxRecord::new(10, "primary.example.net"),
            ],
        },
        MxStep::LookupAddresses { .. } => MxAnswer::Addresses {
            status: DnssecStatus::Secure,
            found: true,
        },
        MxStep::LookupTlsa { base_domain } => {
            if base_domain == "backup.example.net" {
                MxAnswer::Tlsa {
                    status: DnssecStatus::Secure,
                    records: vec![tlsa()],
                }
            } else {
                // Primary publishes none.
                MxAnswer::Tlsa {
                    status: DnssecStatus::Insecure,
                    records: vec![],
                }
            }
        }
        _ => MxAnswer::LookupFailed,
    });

    assert_eq!(delay, None);
    assert_eq!(
        script.targets,
        vec![
            ("primary.example.net".to_string(), false),
            ("backup.example.net".to_string(), true),
        ],
        "the better-preference host must be offered first even though it \
         offers no DANE"
    );
}

#[test]
fn hosts_are_ordered_by_preference_regardless_of_input_order() {
    let resolution = MxResolution::new("example.com", SmtpDaneConfig::default());
    let (script, _) = Script::run(resolution, |step| match step {
        MxStep::LookupMx { .. } => MxAnswer::Mx {
            status: DnssecStatus::Secure,
            records: vec![
                MxRecord::new(30, "third.example.net"),
                MxRecord::new(10, "first.example.net"),
                MxRecord::new(20, "second.example.net"),
            ],
        },
        MxStep::LookupAddresses { .. } => MxAnswer::Addresses {
            status: DnssecStatus::Insecure,
            found: true,
        },
        _ => MxAnswer::LookupFailed,
    });

    let hosts: Vec<&str> = script.targets.iter().map(|(h, _)| h.as_str()).collect();
    assert_eq!(
        hosts,
        [
            "first.example.net",
            "second.example.net",
            "third.example.net"
        ]
    );
}

/// Equal preferences keep input order, which the module documents as the
/// caller's to randomize per RFC 5321 §5.1.
#[test]
fn equal_preferences_keep_their_input_order() {
    let resolution = MxResolution::new("example.com", SmtpDaneConfig::default());
    let (script, _) = Script::run(resolution, |step| match step {
        MxStep::LookupMx { .. } => MxAnswer::Mx {
            status: DnssecStatus::Secure,
            records: vec![
                MxRecord::new(10, "b.example.net"),
                MxRecord::new(10, "a.example.net"),
            ],
        },
        MxStep::LookupAddresses { .. } => MxAnswer::Addresses {
            status: DnssecStatus::Insecure,
            found: true,
        },
        _ => MxAnswer::LookupFailed,
    });
    let hosts: Vec<&str> = script.targets.iter().map(|(h, _)| h.as_str()).collect();
    assert_eq!(hosts, ["b.example.net", "a.example.net"]);
}

// ---------------------------------------------------------------------------
// §2.2.2: address lookups precede TLSA lookups
// ---------------------------------------------------------------------------

/// > the SMTP client MUST perform any A and/or AAAA queries for the
/// > destination before attempting to locate the associated TLSA records.
#[test]
fn the_address_lookup_precedes_the_tlsa_lookup_for_every_host() {
    let resolution = MxResolution::new("example.com", SmtpDaneConfig::default());
    let (script, _) = Script::run(resolution, |step| match step {
        MxStep::LookupMx { .. } => MxAnswer::Mx {
            status: DnssecStatus::Secure,
            records: vec![
                MxRecord::new(10, "a.example.net"),
                MxRecord::new(20, "b.example.net"),
            ],
        },
        MxStep::LookupAddresses { .. } => MxAnswer::Addresses {
            status: DnssecStatus::Secure,
            found: true,
        },
        MxStep::LookupTlsa { .. } => MxAnswer::Tlsa {
            status: DnssecStatus::Secure,
            records: vec![tlsa()],
        },
        _ => MxAnswer::LookupFailed,
    });

    assert_eq!(
        script.log,
        vec![
            "mx:example.com",
            "addr:a.example.net",
            "tlsa:a.example.net",
            "addr:b.example.net",
            "tlsa:b.example.net",
        ],
        "each host's address lookup must come before its TLSA lookup"
    );
}

/// §2.2.2: with an insecure first address response, no TLSA query is made at
/// all — not merely ignored if it fails.
///
/// This is the half that protects against the broken load-balancing
/// nameservers the ordering rule exists for: the query is never issued, so it
/// cannot SERVFAIL and strand the message.
#[test]
fn an_insecure_address_answer_suppresses_the_tlsa_query_entirely() {
    let resolution = MxResolution::new("example.com", SmtpDaneConfig::default());
    let (script, _) = Script::run(resolution, |step| match step {
        MxStep::LookupMx { .. } => MxAnswer::Mx {
            status: DnssecStatus::Secure,
            records: vec![MxRecord::new(10, "unsigned.example.net")],
        },
        MxStep::LookupAddresses { .. } => MxAnswer::Addresses {
            status: DnssecStatus::Insecure,
            found: true,
        },
        _ => MxAnswer::LookupFailed,
    });

    assert_eq!(
        script.log,
        vec!["mx:example.com", "addr:unsigned.example.net"]
    );
    assert!(
        !script.log.iter().any(|s| s.starts_with("tlsa:")),
        "no TLSA query may be issued after an insecure address answer"
    );
    // Still reachable: opportunistic delivery, not a delay.
    assert_eq!(
        script.targets,
        vec![("unsigned.example.net".to_string(), false)]
    );
}

#[test]
fn a_host_with_no_address_records_is_skipped() {
    let resolution = MxResolution::new("example.com", SmtpDaneConfig::default());
    let (script, _) = Script::run(resolution, |step| match step {
        MxStep::LookupMx { .. } => MxAnswer::Mx {
            status: DnssecStatus::Secure,
            records: vec![
                MxRecord::new(10, "gone.example.net"),
                MxRecord::new(20, "ok.example.net"),
            ],
        },
        MxStep::LookupAddresses { host } => MxAnswer::Addresses {
            status: DnssecStatus::Secure,
            found: host != "gone.example.net",
        },
        MxStep::LookupTlsa { .. } => MxAnswer::Tlsa {
            status: DnssecStatus::Secure,
            records: vec![tlsa()],
        },
        _ => MxAnswer::LookupFailed,
    });

    let hosts: Vec<&str> = script.targets.iter().map(|(h, _)| h.as_str()).collect();
    assert_eq!(
        hosts,
        ["ok.example.net"],
        "an unreachable host is not offered"
    );
}

// ---------------------------------------------------------------------------
// §2.2.1: a failed TLSA lookup makes the server unreachable
// ---------------------------------------------------------------------------

/// > any errors during TLSA lookups MUST... cause the SMTP server in question
/// > to be treated as unreachable.
///
/// Failing open here would let an attacker who can drop TLSA responses
/// downgrade every connection, which is the downgrade this rule closes.
#[test]
fn a_failed_tlsa_lookup_makes_that_server_unreachable() {
    let resolution = MxResolution::new("example.com", SmtpDaneConfig::default());
    let (script, _) = Script::run(resolution, |step| match step {
        MxStep::LookupMx { .. } => MxAnswer::Mx {
            status: DnssecStatus::Secure,
            records: vec![
                MxRecord::new(10, "broken.example.net"),
                MxRecord::new(20, "ok.example.net"),
            ],
        },
        MxStep::LookupAddresses { .. } => MxAnswer::Addresses {
            status: DnssecStatus::Secure,
            found: true,
        },
        MxStep::LookupTlsa { base_domain } => {
            if base_domain == "broken.example.net" {
                MxAnswer::LookupFailed
            } else {
                MxAnswer::Tlsa {
                    status: DnssecStatus::Secure,
                    records: vec![tlsa()],
                }
            }
        }
        _ => MxAnswer::LookupFailed,
    });

    let hosts: Vec<&str> = script.targets.iter().map(|(h, _)| h.as_str()).collect();
    assert_eq!(
        hosts,
        ["ok.example.net"],
        "a TLSA lookup error must not fall through to unauthenticated delivery"
    );
}

// ---------------------------------------------------------------------------
// §2.2.1: insecure MX, mandatory DANE, and the hosting-provider case
// ---------------------------------------------------------------------------

/// > If the MX RRset (or any CNAME leading to it) is "insecure" and DANE TLS
/// > for the given destination is mandatory, delivery MUST be delayed.
#[test]
fn mandatory_dane_with_an_insecure_mx_rrset_delays_delivery() {
    let config = SmtpDaneConfig::new().with_mandatory(true);
    let (script, delay) = Script::run(
        MxResolution::new("example.com", config),
        |step| match step {
            MxStep::LookupMx { .. } => MxAnswer::Mx {
                status: DnssecStatus::Insecure,
                records: vec![MxRecord::new(10, "mx.example.net")],
            },
            _ => MxAnswer::LookupFailed,
        },
    );

    assert_eq!(delay, Some(DelayReason::MandatoryDaneWithInsecureMx));
    assert!(
        script.targets.is_empty(),
        "no delivery may be attempted when DANE is mandatory and MX is insecure"
    );
}

#[test]
fn an_insecure_mx_rrset_is_opportunistic_when_dane_is_not_mandatory() {
    let (script, delay) = Script::run(
        MxResolution::new("example.com", SmtpDaneConfig::default()),
        |step| match step {
            MxStep::LookupMx { .. } => MxAnswer::Mx {
                status: DnssecStatus::Insecure,
                records: vec![MxRecord::new(10, "mx.example.net")],
            },
            MxStep::LookupAddresses { .. } => MxAnswer::Addresses {
                status: DnssecStatus::Secure,
                found: true,
            },
            MxStep::LookupTlsa { .. } => MxAnswer::Tlsa {
                status: DnssecStatus::Secure,
                records: vec![tlsa()],
            },
            _ => MxAnswer::LookupFailed,
        },
    );

    assert_eq!(delay, None);
    assert_eq!(
        script.targets,
        vec![("mx.example.net".to_string(), false)],
        "TLSA records reached via an insecure MX RRset are not used by default"
    );
}

/// The hosting-provider case: an unsigned customer zone, a signed provider
/// zone with TLSA records, and a client that elects DANE anyway.
#[test]
fn dane_despite_insecure_mx_uses_the_records_and_narrows_the_identity() {
    let config = SmtpDaneConfig::new().with_dane_despite_insecure_mx(true);
    let mut resolution = MxResolution::new("customer.example", config);

    // MX RRset is insecure (unsigned customer zone).
    resolution.absorb(MxAnswer::Mx {
        status: DnssecStatus::Insecure,
        records: vec![MxRecord::new(10, "mx.provider.example")],
    });
    resolution.absorb(MxAnswer::Addresses {
        status: DnssecStatus::Secure,
        found: true,
    });
    resolution.absorb(MxAnswer::Tlsa {
        status: DnssecStatus::Secure,
        records: vec![tlsa_ta()],
    });

    let MxStep::Deliver(target) = resolution.next_step() else {
        panic!(
            "expected a delivery target, got {:?}",
            resolution.next_step()
        );
    };

    assert!(
        target.dane_records().is_some(),
        "the provider's TLSA records are used"
    );
    assert!(
        !target.mx_was_secure(),
        "the MX RRset was not authenticated"
    );

    // §3.2.2: the MX hostname is the ONLY reference identifier here.
    let ids = target
        .identities()
        .expect("DANE applies, so identities exist");
    assert_eq!(ids.len(), 1);
    assert_eq!(ids.primary(), "mx.provider.example");
    assert!(
        !ids.iter().any(|i| i == "customer.example"),
        "the next-hop domain was never authenticated and must not be an identifier"
    );
}

// ---------------------------------------------------------------------------
// §2.2.1 / §2.2.2: CNAMEs and non-MX destinations
// ---------------------------------------------------------------------------

#[test]
fn a_cname_redirects_the_mx_query() {
    let (script, _) = Script::run(
        MxResolution::new("alias.example", SmtpDaneConfig::default()),
        |step| match step {
            MxStep::LookupMx { domain } if domain == "alias.example" => MxAnswer::MxCname {
                status: DnssecStatus::Secure,
                target: "real.example".to_string(),
            },
            MxStep::LookupMx { .. } => MxAnswer::Mx {
                status: DnssecStatus::Secure,
                records: vec![MxRecord::new(10, "mx.real.example")],
            },
            MxStep::LookupAddresses { .. } => MxAnswer::Addresses {
                status: DnssecStatus::Insecure,
                found: true,
            },
            _ => MxAnswer::LookupFailed,
        },
    );

    assert_eq!(
        script.log,
        vec![
            "mx:alias.example",
            "mx:real.example",
            "addr:mx.real.example"
        ]
    );
}

/// An insecure CNAME taints the result even when the eventual MX RRset is
/// signed: §2.2.1 says "the MX RRset (or any CNAME leading to it)".
#[test]
fn an_insecure_cname_taints_an_otherwise_secure_mx_rrset() {
    let config = SmtpDaneConfig::new().with_mandatory(true);
    let (_, delay) = Script::run(
        MxResolution::new("alias.example", config),
        |step| match step {
            MxStep::LookupMx { domain } if domain == "alias.example" => MxAnswer::MxCname {
                status: DnssecStatus::Insecure,
                target: "real.example".to_string(),
            },
            MxStep::LookupMx { .. } => MxAnswer::Mx {
                // Signed, but reached through an unsigned CNAME.
                status: DnssecStatus::Secure,
                records: vec![MxRecord::new(10, "mx.real.example")],
            },
            _ => MxAnswer::LookupFailed,
        },
    );

    assert_eq!(
        delay,
        Some(DelayReason::MandatoryDaneWithInsecureMx),
        "an insecure CNAME leading to the MX RRset must not be upgraded"
    );
}

#[test]
fn cname_expansion_stops_at_the_configured_depth() {
    let config = SmtpDaneConfig::new().with_max_cname_depth(2);
    let (_, delay) = Script::run(MxResolution::new("a.example", config), |step| match step {
        MxStep::LookupMx { .. } => MxAnswer::MxCname {
            status: DnssecStatus::Secure,
            target: "loop.example".to_string(),
        },
        _ => MxAnswer::LookupFailed,
    });
    assert_eq!(delay, Some(DelayReason::CnameLoop));
}

/// §2.2.2: "the domain's name is implicitly also its sole SMTP server name."
#[test]
fn a_domain_with_no_mx_records_is_its_own_server() {
    let mut resolution = MxResolution::new("solo.example", SmtpDaneConfig::default());
    resolution.absorb(MxAnswer::NoMx {
        status: DnssecStatus::Secure,
    });
    assert_eq!(
        resolution.next_step(),
        MxStep::LookupAddresses {
            host: "solo.example".to_string()
        }
    );
    resolution.absorb(MxAnswer::Addresses {
        status: DnssecStatus::Secure,
        found: true,
    });
    resolution.absorb(MxAnswer::Tlsa {
        status: DnssecStatus::Secure,
        records: vec![tlsa_ta()],
    });

    let MxStep::Deliver(target) = resolution.next_step() else {
        panic!("expected a delivery target");
    };
    assert_eq!(target.host(), "solo.example");
    assert!(!target.came_from_mx(), "no MX RRset was used");
    let ids = target.identities().expect("DANE applies");
    assert_eq!(ids.primary(), "solo.example");
}

/// A configured relay skips the MX lookup entirely (§2.2.2, first bullet).
#[test]
fn a_configured_relay_skips_the_mx_lookup() {
    let mut resolution = MxResolution::relay("relay.internal", SmtpDaneConfig::default());
    assert_eq!(
        resolution.next_step(),
        MxStep::LookupAddresses {
            host: "relay.internal".to_string()
        },
        "a relay is not subject to MX resolution"
    );
    resolution.absorb(MxAnswer::Addresses {
        status: DnssecStatus::Secure,
        found: true,
    });
    resolution.absorb(MxAnswer::Tlsa {
        status: DnssecStatus::Secure,
        records: vec![tlsa_ta()],
    });
    let MxStep::Deliver(target) = resolution.next_step() else {
        panic!("expected a delivery target");
    };
    assert!(!target.came_from_mx());
    assert!(target.dane_records().is_some());
}

// ---------------------------------------------------------------------------
// Bogus answers, and unusable records
// ---------------------------------------------------------------------------

/// Bogus is evidence of tampering, so it is not treated as "no records".
#[test]
fn a_bogus_mx_rrset_delays_rather_than_falling_back() {
    let (script, delay) = Script::run(
        MxResolution::new("example.com", SmtpDaneConfig::default()),
        |step| match step {
            MxStep::LookupMx { .. } => MxAnswer::Mx {
                status: DnssecStatus::Bogus,
                records: vec![MxRecord::new(10, "mx.example.net")],
            },
            _ => MxAnswer::LookupFailed,
        },
    );
    assert_eq!(delay, Some(DelayReason::DnsFailure));
    assert!(script.targets.is_empty());
}

#[test]
fn a_failed_mx_lookup_delays() {
    let (_, delay) = Script::run(
        MxResolution::new("example.com", SmtpDaneConfig::default()),
        |_| MxAnswer::LookupFailed,
    );
    assert_eq!(delay, Some(DelayReason::DnsFailure));
}

/// Unusable records are filtered, so a set containing only an unknown usage
/// yields no DANE rather than an empty-but-present record set.
#[test]
fn only_usable_tlsa_records_enable_dane() {
    let unusable = TlsaRecord::new(
        TlsaUsage::from_octet(9),
        TlsaSelector::Spki,
        TlsaMatchingType::Sha256,
        vec![0x11; 32],
    );
    let mut resolution = MxResolution::relay("relay.internal", SmtpDaneConfig::default());
    resolution.absorb(MxAnswer::Addresses {
        status: DnssecStatus::Secure,
        found: true,
    });
    resolution.absorb(MxAnswer::Tlsa {
        status: DnssecStatus::Secure,
        records: vec![unusable],
    });
    let MxStep::Deliver(target) = resolution.next_step() else {
        panic!("expected a delivery target");
    };
    assert!(
        target.dane_records().is_none(),
        "a set of only unusable records is not DANE"
    );
}

/// Insecure TLSA records authenticate nothing, even on a secure MX path.
#[test]
fn insecure_tlsa_records_do_not_enable_dane() {
    let mut resolution = MxResolution::relay("relay.internal", SmtpDaneConfig::default());
    resolution.absorb(MxAnswer::Addresses {
        status: DnssecStatus::Secure,
        found: true,
    });
    resolution.absorb(MxAnswer::Tlsa {
        status: DnssecStatus::Insecure,
        records: vec![tlsa()],
    });
    let MxStep::Deliver(target) = resolution.next_step() else {
        panic!("expected a delivery target");
    };
    assert!(target.dane_records().is_none());
    assert!(target.identities().is_none());
}

// ---------------------------------------------------------------------------
// The driver
// ---------------------------------------------------------------------------

#[test]
fn accepting_a_target_stops_the_loop() {
    let resolution = MxResolution::new("example.com", SmtpDaneConfig::default());
    let mut offered = 0_usize;
    let outcome = resolve_with(
        resolution,
        |step| match step {
            MxStep::LookupMx { .. } => MxAnswer::Mx {
                status: DnssecStatus::Secure,
                records: vec![
                    MxRecord::new(10, "a.example.net"),
                    MxRecord::new(20, "b.example.net"),
                ],
            },
            MxStep::LookupAddresses { .. } => MxAnswer::Addresses {
                status: DnssecStatus::Insecure,
                found: true,
            },
            _ => MxAnswer::LookupFailed,
        },
        |_target| {
            offered += 1;
            true
        },
    );
    assert_eq!(outcome, Ok(()));
    assert_eq!(
        offered, 1,
        "the second host must not be contacted after success"
    );
}

#[test]
fn exhausting_every_host_is_reported_distinctly_from_a_delay() {
    let resolution = MxResolution::new("example.com", SmtpDaneConfig::default());
    let outcome = resolve_with(
        resolution,
        |step| match step {
            MxStep::LookupMx { .. } => MxAnswer::Mx {
                status: DnssecStatus::Secure,
                records: vec![MxRecord::new(10, "a.example.net")],
            },
            MxStep::LookupAddresses { .. } => MxAnswer::Addresses {
                status: DnssecStatus::Insecure,
                found: true,
            },
            _ => MxAnswer::LookupFailed,
        },
        |_| false,
    );
    assert_eq!(outcome, Err(None), "no hosts left is not a delay reason");
}
