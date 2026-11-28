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

// ---------------------------------------------------------------------------
// §6: mandatory DANE delays when no usable TLSA records are found
// ---------------------------------------------------------------------------

/// > With mandatory DANE TLS, when no usable TLSA records are found, message
/// > delivery is delayed.
///
/// The MX RRset is secure here, so the hostnames are trustworthy — the server
/// simply publishes nothing usable. Offering it for unauthenticated delivery
/// would defeat the policy entirely.
#[test]
fn mandatory_dane_delays_when_a_server_publishes_no_usable_records() {
    let config = SmtpDaneConfig::new().with_mandatory(true);
    let (script, delay) = Script::run(
        MxResolution::new("example.com", config),
        |step| match step {
            MxStep::LookupMx { .. } => MxAnswer::Mx {
                status: DnssecStatus::Secure,
                records: vec![MxRecord::new(10, "bare.example.net")],
            },
            MxStep::LookupAddresses { .. } => MxAnswer::Addresses {
                status: DnssecStatus::Secure,
                found: true,
            },
            MxStep::LookupTlsa { .. } => MxAnswer::Tlsa {
                status: DnssecStatus::Secure,
                records: vec![],
            },
            _ => MxAnswer::LookupFailed,
        },
    );

    assert_eq!(delay, Some(DelayReason::MandatoryDaneWithoutUsableTlsa));
    assert!(
        script.targets.is_empty(),
        "no unauthenticated delivery may be offered under mandatory DANE"
    );
}

/// A host without usable records is passed over, not fatal: the next host in
/// preference order may still publish some.
#[test]
fn mandatory_dane_tries_the_next_host_before_delaying() {
    let config = SmtpDaneConfig::new().with_mandatory(true);
    let (script, delay) = Script::run(
        MxResolution::new("example.com", config),
        |step| match step {
            MxStep::LookupMx { .. } => MxAnswer::Mx {
                status: DnssecStatus::Secure,
                records: vec![
                    MxRecord::new(10, "bare.example.net"),
                    MxRecord::new(20, "dane.example.net"),
                ],
            },
            MxStep::LookupAddresses { .. } => MxAnswer::Addresses {
                status: DnssecStatus::Secure,
                found: true,
            },
            MxStep::LookupTlsa { base_domain } => MxAnswer::Tlsa {
                status: DnssecStatus::Secure,
                records: if base_domain == "dane.example.net" {
                    vec![tlsa()]
                } else {
                    vec![]
                },
            },
            _ => MxAnswer::LookupFailed,
        },
    );

    assert_eq!(delay, None, "a later host had usable records");
    assert_eq!(
        script.targets,
        vec![("dane.example.net".to_string(), true)],
        "the host without records is passed over, the one with them is offered"
    );
}

/// §2.2.2's suppressed TLSA query also counts as "no usable records found".
///
/// No TLSA query is issued at all when the address answer is insecure, so
/// under mandatory DANE the host cannot be used — and the absence of a query
/// must not be mistaken for an absence of policy.
#[test]
fn mandatory_dane_delays_when_the_tlsa_query_was_suppressed() {
    let config = SmtpDaneConfig::new().with_mandatory(true);
    let (script, delay) = Script::run(
        MxResolution::new("example.com", config),
        |step| match step {
            MxStep::LookupMx { .. } => MxAnswer::Mx {
                status: DnssecStatus::Secure,
                records: vec![MxRecord::new(10, "unsigned.example.net")],
            },
            MxStep::LookupAddresses { .. } => MxAnswer::Addresses {
                status: DnssecStatus::Insecure,
                found: true,
            },
            _ => MxAnswer::LookupFailed,
        },
    );

    assert!(!script.log.iter().any(|s| s.starts_with("tlsa:")));
    assert_eq!(delay, Some(DelayReason::MandatoryDaneWithoutUsableTlsa));
    assert!(script.targets.is_empty());
}

/// Insecure TLSA records are not usable records, so mandatory DANE delays.
#[test]
fn mandatory_dane_delays_on_insecure_tlsa_records() {
    let config = SmtpDaneConfig::new().with_mandatory(true);
    let (_, delay) = Script::run(
        MxResolution::new("example.com", config),
        |step| match step {
            MxStep::LookupMx { .. } => MxAnswer::Mx {
                status: DnssecStatus::Secure,
                records: vec![MxRecord::new(10, "mx.example.net")],
            },
            MxStep::LookupAddresses { .. } => MxAnswer::Addresses {
                status: DnssecStatus::Secure,
                found: true,
            },
            MxStep::LookupTlsa { .. } => MxAnswer::Tlsa {
                status: DnssecStatus::Insecure,
                records: vec![tlsa()],
            },
            _ => MxAnswer::LookupFailed,
        },
    );
    assert_eq!(delay, Some(DelayReason::MandatoryDaneWithoutUsableTlsa));
}

/// Exhausting hosts for *unreachability* under mandatory policy is still
/// plain exhaustion, not §6's delay.
///
/// The two have different remedies, so conflating them would mislead whoever
/// reads the log.
#[test]
fn unreachable_hosts_under_mandatory_dane_are_not_a_tlsa_delay() {
    let config = SmtpDaneConfig::new().with_mandatory(true);
    let (_, delay) = Script::run(
        MxResolution::new("example.com", config),
        |step| match step {
            MxStep::LookupMx { .. } => MxAnswer::Mx {
                status: DnssecStatus::Secure,
                records: vec![MxRecord::new(10, "gone.example.net")],
            },
            MxStep::LookupAddresses { .. } => MxAnswer::Addresses {
                status: DnssecStatus::Secure,
                found: false,
            },
            _ => MxAnswer::LookupFailed,
        },
    );
    assert_eq!(
        delay, None,
        "no host published anything; none was reachable either"
    );
}

// ---------------------------------------------------------------------------
// §3.1.3: a set of only PKIX usages is not DANE
// ---------------------------------------------------------------------------

/// A PKIX-EE(1) record is usable as a record and useless as SMTP
/// authentication.
///
/// `TlsaRecord::is_usable` is about whether the record parses and carries an
/// assigned usage, not about whether this profile can authenticate with it.
/// So a usage-1 record survives discovery's filter — deliberately, because
/// the entry point reports "the domain published only PKIX usages" distinctly
/// from "the domain published nothing", and needs to see them to do it.
///
/// What must not happen is `dane_records` claiming DANE applies.
#[test]
fn a_set_of_only_pkix_usages_does_not_count_as_dane() {
    let pkix_ee = TlsaRecord::new(
        TlsaUsage::PkixEe,
        TlsaSelector::Spki,
        TlsaMatchingType::Sha256,
        vec![0x22; 32],
    );
    assert!(pkix_ee.is_usable(), "usage 1 is an assigned usage");

    let mut resolution = MxResolution::relay("relay.internal", SmtpDaneConfig::new());
    resolution.absorb(MxAnswer::Addresses {
        status: DnssecStatus::Secure,
        found: true,
    });
    resolution.absorb(MxAnswer::Tlsa {
        status: DnssecStatus::Secure,
        records: vec![pkix_ee],
    });
    let MxStep::Deliver(target) = resolution.next_step() else {
        panic!("expected a delivery target");
    };

    assert!(
        target.dane_records().is_none(),
        "PKIX usages cannot authenticate an SMTP connection (§3.1.3)"
    );
    assert!(target.identities().is_none(), "no DANE means no name check");
    assert!(
        target.tlsa_response().is_some(),
        "the records are still carried, so the entry point can report that \
         only PKIX usages were published"
    );
}

/// A mixed set authenticates on its DANE records and carries the rest.
///
/// This is `huque.com`'s real publication: PKIX-EE(1) alongside DANE-EE(3).
#[test]
fn a_mixed_set_applies_dane_and_still_carries_the_pkix_record() {
    let pkix_ee = TlsaRecord::new(
        TlsaUsage::PkixEe,
        TlsaSelector::Spki,
        TlsaMatchingType::Sha256,
        vec![0x22; 32],
    );

    let mut resolution = MxResolution::relay("relay.internal", SmtpDaneConfig::new());
    resolution.absorb(MxAnswer::Addresses {
        status: DnssecStatus::Secure,
        found: true,
    });
    resolution.absorb(MxAnswer::Tlsa {
        status: DnssecStatus::Secure,
        records: vec![tlsa(), pkix_ee, tlsa()],
    });
    let MxStep::Deliver(target) = resolution.next_step() else {
        panic!("expected a delivery target");
    };

    let records = target
        .dane_records()
        .expect("DANE-EE records are present, so DANE applies");
    assert_eq!(records.len(), 3, "every usable record is carried");
    assert!(target.identities().is_some());
}

/// Under mandatory DANE, a PKIX-only set delays: nothing there can
/// authenticate, which is §6's condition.
#[test]
fn mandatory_dane_delays_on_a_pkix_only_set() {
    let pkix_ta = TlsaRecord::new(
        TlsaUsage::PkixTa,
        TlsaSelector::Spki,
        TlsaMatchingType::Sha256,
        vec![0x33; 32],
    );
    let config = SmtpDaneConfig::new().with_mandatory(true);
    let (script, delay) = Script::run(
        MxResolution::new("example.com", config),
        |step| match step {
            MxStep::LookupMx { .. } => MxAnswer::Mx {
                status: DnssecStatus::Secure,
                records: vec![MxRecord::new(10, "mx.example.net")],
            },
            MxStep::LookupAddresses { .. } => MxAnswer::Addresses {
                status: DnssecStatus::Secure,
                found: true,
            },
            MxStep::LookupTlsa { .. } => MxAnswer::Tlsa {
                status: DnssecStatus::Secure,
                records: vec![pkix_ta.clone()],
            },
            _ => MxAnswer::LookupFailed,
        },
    );

    assert_eq!(delay, Some(DelayReason::MandatoryDaneWithoutUsableTlsa));
    assert!(script.targets.is_empty());
}

// ---------------------------------------------------------------------------
// What a DeliveryTarget reports about itself
// ---------------------------------------------------------------------------

/// A secure MX resolution reports every part of its provenance.
///
/// `mx_was_secure`, `came_from_mx` and `next_hop` are how a caller
/// decides what to do with a message whose DANE check did not succeed:
/// RFC 7672 §2.2 makes delivery still possible, so the sender has to be
/// able to say *which* hop it reached, whether the MX RRset was
/// authenticated, and whether an MX RRset was used at all. That is a
/// tagging and routing decision, not a crash.
///
/// Every existing assertion on these is negative -- `!mx_was_secure()`,
/// `!came_from_mx()` -- taken from the insecure-MX and non-MX cases. So
/// each could answer `false` always, and `next_hop` could answer `""`,
/// and nothing would notice: a secure MX delivery would be reported as
/// an unauthenticated non-MX one to nowhere.
#[test]
fn a_secure_mx_target_reports_its_provenance() {
    let mut resolution = MxResolution::new("example.com", SmtpDaneConfig::new());
    resolution.absorb(MxAnswer::Mx {
        status: DnssecStatus::Secure,
        records: vec![MxRecord::new(10, "mail.example.com")],
    });
    resolution.absorb(MxAnswer::Addresses {
        status: DnssecStatus::Secure,
        found: true,
    });
    resolution.absorb(MxAnswer::Tlsa {
        status: DnssecStatus::Secure,
        records: vec![tlsa()],
    });

    let MxStep::Deliver(target) = resolution.next_step() else {
        panic!(
            "expected a delivery target, got {:?}",
            resolution.next_step()
        );
    };

    assert!(
        target.mx_was_secure(),
        "the MX RRset was authenticated, and saying otherwise narrows the \
         identity set for no reason"
    );
    assert!(
        target.came_from_mx(),
        "an MX RRset was used, so the MX hostname is an identifier"
    );
    assert_eq!(
        target.next_hop(),
        "example.com",
        "the original next-hop domain, which is what was asked for"
    );

    // §2.2.1 and §3.2.2 together: a secure MX gives both the base domain
    // and the MX hostname as reference identifiers. That set is what
    // `came_from_mx` selects, so asserting it here pins the accessor to a
    // consequence rather than to itself.
    let ids = target.identities().expect("DANE applies");
    assert!(
        ids.iter().any(|i| i == "example.com"),
        "the base domain is an identifier under a secure MX"
    );
    assert!(
        ids.iter().any(|i| i == "mail.example.com"),
        "and so is the MX hostname"
    );
    assert!(!ids.is_empty(), "a non-empty identity set is not empty");
}

// ---------------------------------------------------------------------------
// §2.2.2 NoMx: the same trust rules as an MX RRset, on their own copy
// ---------------------------------------------------------------------------

/// Mandatory DANE refuses an insecure `NoMx` answer.
///
/// §2.2.2 makes the domain its own SMTP server when it publishes no MX,
/// and the trust rules are the same as for an MX RRset: a sender
/// configured to require DANE cannot accept an unauthenticated answer,
/// because an attacker who can forge the absence of MX records can
/// choose the destination.
///
/// The `Mx` arm's copy of this logic is tested; the `NoMx` arm's is a
/// second copy and was not, which left five mutants of it alive --
/// including dropping the negation, which inverts the rule into refusing
/// only *secure* answers.
#[test]
fn mandatory_dane_refuses_an_insecure_no_mx_answer() {
    let mut resolution =
        MxResolution::new("solo.example", SmtpDaneConfig::new().with_mandatory(true));
    resolution.absorb(MxAnswer::NoMx {
        status: DnssecStatus::Insecure,
    });
    assert_eq!(
        resolution.next_step(),
        MxStep::Delay(DelayReason::MandatoryDaneWithInsecureMx),
        "an unauthenticated absence of MX records cannot satisfy mandatory DANE"
    );
}

/// And accepts a secure one.
///
/// The other side of the same comparison: without it, the rule could
/// refuse every `NoMx` answer and mandatory DANE would never deliver to
/// a domain that is its own server.
#[test]
fn mandatory_dane_accepts_a_secure_no_mx_answer() {
    let mut resolution =
        MxResolution::new("solo.example", SmtpDaneConfig::new().with_mandatory(true));
    resolution.absorb(MxAnswer::NoMx {
        status: DnssecStatus::Secure,
    });
    assert_eq!(
        resolution.next_step(),
        MxStep::LookupAddresses {
            host: "solo.example".to_string()
        },
        "a signed absence of MX records is authenticated, so delivery proceeds"
    );
}

/// An insecure CNAME before a secure `NoMx` leaves the result insecure.
///
/// The conjunct is `trust == Secure && self.mx_secure != Some(false)`:
/// once any step in the chain was unauthenticated, a later signed answer
/// does not repair it, because the attacker who controlled the earlier
/// step chose what the later one asks about. Dropping that conjunct makes
/// a secure `NoMx` after an insecure CNAME read as fully secure, which
/// mandatory DANE would then accept.
#[test]
fn an_insecure_cname_is_not_repaired_by_a_secure_no_mx() {
    let mut resolution =
        MxResolution::new("alias.example", SmtpDaneConfig::new().with_mandatory(true));
    resolution.absorb(MxAnswer::MxCname {
        status: DnssecStatus::Insecure,
        target: "real.example".to_string(),
    });
    resolution.absorb(MxAnswer::NoMx {
        status: DnssecStatus::Secure,
    });
    assert_eq!(
        resolution.next_step(),
        MxStep::Delay(DelayReason::MandatoryDaneWithInsecureMx),
        "the insecure CNAME is still the weakest link in the chain"
    );
}

/// An address-lookup failure moves to the next MX, not to a delay.
///
/// A host with no reachable address is unreachable; the destination is
/// not. §2.2.2's ordering exists so a backup MX gets its turn, and
/// deleting that arm leaves the resolution waiting for an answer it has
/// already had -- which is why the mutant times out rather than failing.
#[test]
fn an_address_lookup_failure_tries_the_next_mx() {
    let mut resolution = MxResolution::new("example.com", SmtpDaneConfig::new());
    resolution.absorb(MxAnswer::Mx {
        status: DnssecStatus::Secure,
        records: vec![
            MxRecord::new(10, "primary.example.com"),
            MxRecord::new(20, "backup.example.com"),
        ],
    });
    assert_eq!(
        resolution.next_step(),
        MxStep::LookupAddresses {
            host: "primary.example.com".to_string()
        }
    );

    resolution.absorb(MxAnswer::LookupFailed);
    assert_eq!(
        resolution.next_step(),
        MxStep::LookupAddresses {
            host: "backup.example.com".to_string()
        },
        "the backup MX still gets its turn"
    );
}

/// `hosts` reports the MX hosts in the order they will be tried.
///
/// Public, and nothing inside the crate reads it -- the resolution
/// drives itself from the same list. A caller logging or displaying the
/// delivery plan is what it exists for, and an empty answer makes a
/// two-host plan look like none.
#[test]
fn the_resolution_reports_its_host_order() {
    let mut resolution = MxResolution::new("example.com", SmtpDaneConfig::new());
    assert!(
        resolution.hosts().is_empty(),
        "no MX answer yet, so no hosts"
    );
    resolution.absorb(MxAnswer::Mx {
        status: DnssecStatus::Secure,
        records: vec![
            MxRecord::new(20, "backup.example.com"),
            MxRecord::new(10, "primary.example.com"),
        ],
    });
    assert_eq!(
        resolution.hosts(),
        ["primary.example.com", "backup.example.com"],
        "sorted by preference, not by the order they arrived"
    );
}

/// An answer arriving after a terminal verdict is ignored.
///
/// `absorb` returns early when the resolution already has a terminal
/// reason or is done. The guard is a disjunction, and narrowed to a
/// conjunction a late answer would be processed: a resolution that had
/// already decided to delay could be driven onward by an answer to a
/// question it is no longer asking.
#[test]
fn an_answer_after_a_terminal_verdict_changes_nothing() {
    let mut resolution = MxResolution::new("example.com", SmtpDaneConfig::new());
    resolution.absorb(MxAnswer::LookupFailed);
    assert_eq!(
        resolution.next_step(),
        MxStep::Delay(DelayReason::DnsFailure)
    );

    // A late, perfectly good MX answer.
    resolution.absorb(MxAnswer::Mx {
        status: DnssecStatus::Secure,
        records: vec![MxRecord::new(10, "mail.example.com")],
    });
    assert_eq!(
        resolution.next_step(),
        MxStep::Delay(DelayReason::DnsFailure),
        "the verdict stands; a late answer does not revive the resolution"
    );
    assert!(
        resolution.hosts().is_empty(),
        "and it did not reach the host list either"
    );
}
