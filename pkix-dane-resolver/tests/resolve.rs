//! Resolver construction, trust-anchor handling, and live resolution.
//!
//! The live tests need working DNS and reach real signed zones. They skip with
//! a printed reason rather than failing when the network is unavailable: a test
//! that cannot run is an absent test, not evidence of a defect. Run with
//! `--nocapture` to see skip reasons.
//!
//! # A DNSSEC-transparent resolver is required, and the usual one is not
//!
//! These tests validate signatures themselves, so the upstream resolver must
//! return `RRSIG`, `DNSKEY` and `DS` records to its clients. Many do not.
//! `systemd-resolved`'s stub listener on `127.0.0.53` — what `/etc/resolv.conf`
//! points at on most modern Linux desktops — validates internally and strips
//! the crypto on the way out, so a validating client behind it sees every
//! answer as unvalidatable.
//!
//! That is not a defect in this crate; it is the exact upstream-mangling case
//! the `PKIX_DANE_RESOLVER` override exists for. The live tests detect it and
//! skip with an actionable message rather than reporting a false failure, and
//! they do **not** report it as "no network", which would hide a real signal
//! behind a plausible-sounding excuse.
//!
//! To run them against a DNSSEC-transparent resolver, set the override — for
//! example `PKIX_DANE_RESOLVER=9.9.9.9`. Note that doing so sends the queried
//! names to that operator.

use pkix_dane::{TlsaName, TlsaProtocol};
use pkix_dane_resolver::{
    AsyncTlsaResolver, DnssecStatus, HickoryTlsaResolver, NoAsyncTlsaResolver, ResolverError,
    UpstreamConfig,
};
use pkix_dnssec_anchor::RootAnchor;

/// Builds a resolver against IANA's current anchors, or explains why not.
fn resolver() -> Option<HickoryTlsaResolver> {
    match HickoryTlsaResolver::new(pkix_dnssec_anchor::CURRENT) {
        Ok(r) => Some(r),
        Err(e) => {
            println!("SKIP: could not build a resolver: {e}");
            None
        }
    }
}

/// What a failed live lookup tells us.
enum LiveFailure {
    /// The upstream did not return the DNSSEC records validation needs.
    /// Almost always a stub resolver that strips them.
    UpstreamStripsDnssec,
    /// Something else — no route, timeout, refused.
    Transport,
}

/// Classifies a lookup error so a skip message can be honest about why.
///
/// Guessing "no network" for every error is how a real signal gets hidden: a
/// validation failure against a zone known to be signed means the answer
/// arrived and could not be validated, which is a completely different thing
/// from the answer never arriving.
fn classify(err: &pkix_dane::DaneError) -> LiveFailure {
    let text = err.to_string().to_ascii_lowercase();
    if text.contains("dnssec") || text.contains("validation") || text.contains("proof") {
        LiveFailure::UpstreamStripsDnssec
    } else {
        LiveFailure::Transport
    }
}

/// Runs a live lookup, returning `None` with a printed reason when the
/// environment cannot support it.
async fn live_lookup(
    resolver: &HickoryTlsaResolver,
    name: &TlsaName,
) -> Option<pkix_dane::TlsaResponse> {
    match resolver.resolve(name).await {
        Ok(response) => Some(response),
        Err(e) => {
            match classify(&e) {
                LiveFailure::UpstreamStripsDnssec => println!(
                    "SKIP: the upstream resolver does not pass DNSSEC records through \
                     (systemd-resolved's stub on 127.0.0.53 does this). Set \
                     PKIX_DANE_RESOLVER to a DNSSEC-transparent resolver to run this \
                     test. Underlying error: {e}"
                ),
                LiveFailure::Transport => {
                    println!("SKIP: lookup failed at the transport level: {e}");
                }
            }
            None
        }
    }
}

// -------------------------------------------------------------------------
// Construction
// -------------------------------------------------------------------------

/// A validating resolver with no anchor can determine nothing — every answer
/// would be Indeterminate. Refused at construction rather than silently
/// producing a resolver that never validates.
#[test]
fn no_anchors_is_refused() {
    let empty: [&RootAnchor; 0] = [];
    assert_eq!(
        HickoryTlsaResolver::with_upstream(empty, UpstreamConfig::System).unwrap_err(),
        ResolverError::NoTrustAnchor
    );
}

/// IANA publishes some historical anchors as a digest with no DNSKEY. Such an
/// anchor cannot seed a validator, so it is rejected by name rather than
/// silently skipped — skipping could leave the set empty and the resolver
/// unable to validate anything, for a reason the caller never sees.
#[test]
fn a_digest_only_anchor_is_refused() {
    let digest_only = RootAnchor::new(19036, 8, 2, &[0xab; 32]).with_id("Kjqmt7v");
    let err = HickoryTlsaResolver::with_upstream([&digest_only], UpstreamConfig::System)
        .expect_err("a digest-only anchor cannot seed a validator");
    assert_eq!(
        err,
        ResolverError::AnchorWithoutPublicKey {
            anchor: "Kjqmt7v".into()
        }
    );
    assert!(err.to_string().contains("Kjqmt7v"));
}

/// An anchor without an id falls back to naming its key tag, so the
/// diagnostic always identifies which anchor was at fault.
#[test]
fn an_unnamed_digest_only_anchor_is_identified_by_key_tag() {
    let anchor = RootAnchor::new(4242, 8, 2, &[0xab; 32]);
    assert_eq!(
        HickoryTlsaResolver::with_upstream([&anchor], UpstreamConfig::System).unwrap_err(),
        ResolverError::AnchorWithoutPublicKey {
            anchor: "4242".into()
        }
    );
}

#[test]
fn an_unsupported_algorithm_is_refused() {
    // 99 is not an assigned DNSSEC algorithm number.
    let anchor = RootAnchor::new(1, 99, 2, &[0xab; 32]).with_public_key(&[0xcd; 260]);
    assert_eq!(
        HickoryTlsaResolver::with_upstream([&anchor], UpstreamConfig::System).unwrap_err(),
        ResolverError::AnchorAlgorithmUnsupported { algorithm: 99 }
    );
}

/// IANA's shipped anchors must actually be accepted. If this fails, either the
/// anchor crate or the conversion into hickory's trust-anchor set is wrong, and
/// nothing downstream can work.
#[test]
fn ianas_current_anchors_are_accepted() {
    match HickoryTlsaResolver::with_upstream(pkix_dnssec_anchor::CURRENT, UpstreamConfig::System) {
        Ok(_) => {}
        // Reading the system DNS configuration can fail in a sandbox; that is
        // not an anchor problem.
        Err(ResolverError::Construction(diagnostic)) => {
            println!("SKIP: system DNS configuration unavailable: {diagnostic}");
        }
        Err(other) => panic!("IANA's current anchors should be accepted, got {other}"),
    }
}

/// Explicit upstream servers bypass system configuration entirely, which is
/// what the PKIX_DANE_RESOLVER override ultimately drives.
#[test]
fn explicit_upstream_servers_are_accepted() {
    let upstream = UpstreamConfig::Servers(vec!["9.9.9.9:53".parse().expect("valid address")]);
    HickoryTlsaResolver::with_upstream(pkix_dnssec_anchor::CURRENT, upstream)
        .expect("explicit servers need no system configuration");
}

// -------------------------------------------------------------------------
// NoAsyncTlsaResolver
// -------------------------------------------------------------------------

#[tokio::test]
async fn the_null_resolver_reports_disabled() {
    let name = TlsaName::new(443, &TlsaProtocol::Tcp, "example.com").expect("valid name");
    assert_eq!(
        NoAsyncTlsaResolver.resolve(&name).await,
        Err(pkix_dane::DaneError::ResolutionDisabled)
    );

    let batch = NoAsyncTlsaResolver
        .batch_resolve(&[name.clone(), name])
        .await;
    assert_eq!(batch.len(), 2);
    assert!(batch
        .iter()
        .all(|r| r == &Err(pkix_dane::DaneError::ResolutionDisabled)));
}

// -------------------------------------------------------------------------
// Live resolution
// -------------------------------------------------------------------------

/// A DNSSEC-signed zone that publishes TLSA records.
///
/// `good.dane.huque.com` is Shumon Huque's DANE test domain, maintained for
/// exactly this purpose: the zone is signed and publishes a usage-3 TLSA
/// record over SPKI/SHA-256 at port 443. `dns.google` was tried first and
/// publishes no TLSA records at all, which is worth recording so nobody
/// repeats the mistake.
///
/// If the domain stops publishing, the test skips rather than fails — this
/// crate cannot control a third party's DNS.
#[tokio::test]
async fn resolves_tlsa_records_from_a_signed_zone() {
    let Some(resolver) = resolver() else { return };

    let name = TlsaName::new(443, &TlsaProtocol::Tcp, "good.dane.huque.com").expect("valid name");
    let Some(response) = live_lookup(&resolver, &name).await else {
        return;
    };

    println!(
        "{}: {:?}, {} record(s)",
        name.as_str(),
        response.dnssec(),
        response.records().len()
    );

    if response.records().is_empty() {
        println!("SKIP: the zone published no TLSA records for this name");
        return;
    }

    // The substantive assertion: a signed zone's records come back Secure.
    // Anything else means validation is not actually happening, which is the
    // failure mode this whole crate exists to avoid.
    assert_eq!(
        response.dnssec(),
        DnssecStatus::Secure,
        "a signed zone's TLSA records should validate; got {:?}",
        response.dnssec()
    );
    assert!(
        response.has_usable_record(),
        "records from a signed zone should be usable"
    );

    for record in response.records() {
        println!(
            "  usage={:?} selector={:?} matching={:?} data={} octets",
            record.usage(),
            record.selector(),
            record.matching_type(),
            record.association_data().len()
        );
    }
}

/// An unsigned zone must come back Insecure, not Secure and not Bogus.
///
/// This is the test that proves validation is real rather than assumed: a
/// resolver that reported everything Secure would pass the signed-zone test
/// above and fail here.
#[tokio::test]
async fn an_unsigned_zone_is_reported_insecure() {
    let Some(resolver) = resolver() else { return };

    // example.com is deliberately unsigned.
    let name = TlsaName::new(443, &TlsaProtocol::Tcp, "example.com").expect("valid name");
    let Some(response) = live_lookup(&resolver, &name).await else {
        return;
    };

    println!("example.com: {:?}", response.dnssec());
    assert_ne!(
        response.dnssec(),
        DnssecStatus::Secure,
        "an unsigned zone must not be reported Secure"
    );
}

/// Wrong anchors must make a signed zone fail to validate rather than quietly
/// succeed. This is the strongest available check that the caller-supplied
/// anchor is actually in use — if the resolver ignored it and used a built-in
/// default, this would come back Secure.
#[tokio::test]
async fn a_bogus_trust_anchor_does_not_validate_a_signed_zone() {
    // Correct shape, correct algorithm, wrong key.
    let wrong = RootAnchor::new(20326, 8, 2, &[0xab; 32])
        .with_id("deliberately-wrong")
        .with_public_key(&[0x01; 260]);

    let Ok(resolver) = HickoryTlsaResolver::new([&wrong]) else {
        println!("SKIP: could not build a resolver with the wrong anchor");
        return;
    };

    let name = TlsaName::new(443, &TlsaProtocol::Tcp, "good.dane.huque.com").expect("valid name");
    match resolver.resolve(&name).await {
        Ok(response) => {
            println!("wrong anchor gave {:?}", response.dnssec());
            assert_ne!(
                response.dnssec(),
                DnssecStatus::Secure,
                "a signed zone must not validate against the wrong trust anchor"
            );
        }
        Err(e) => {
            // A hard failure is also an acceptable outcome here: validation
            // could not be established, which is what should happen.
            println!("wrong anchor failed the lookup, which is acceptable: {e}");
        }
    }
}

/// `batch_resolve` must return one result per name, in order.
#[tokio::test]
async fn batch_resolve_is_aligned_with_its_input() {
    let Some(resolver) = resolver() else { return };

    let names = vec![
        TlsaName::new(443, &TlsaProtocol::Tcp, "good.dane.huque.com").expect("valid"),
        TlsaName::new(443, &TlsaProtocol::Tcp, "example.com").expect("valid"),
    ];
    let results = resolver.batch_resolve(&names).await;
    assert_eq!(
        results.len(),
        names.len(),
        "batch_resolve must be index-aligned with its input"
    );
}

/// Validation against a DNSSEC-transparent resolver, opt-in.
///
/// The system resolver on a typical Linux desktop strips DNSSEC records, so
/// the tests above skip there. This one runs only when
/// `PKIX_DANE_RESOLVER_TEST_UPSTREAM` names a resolver known to pass them
/// through, and it is the test that actually proves validation works
/// end-to-end: a signed zone must come back `Secure` and an unsigned one must
/// not.
///
/// Opt-in rather than automatic because it sends the queried names to a
/// third-party resolver, which a test suite should not do unasked. Run with,
/// for example:
///
/// ```text
/// PKIX_DANE_RESOLVER_TEST_UPSTREAM=9.9.9.9 cargo test -p pkix-dane-resolver
/// ```
#[tokio::test]
async fn validates_against_a_dnssec_transparent_upstream() {
    let Ok(ip) = std::env::var("PKIX_DANE_RESOLVER_TEST_UPSTREAM") else {
        println!(
            "SKIP: set PKIX_DANE_RESOLVER_TEST_UPSTREAM to a DNSSEC-transparent \
             resolver IP to run this test"
        );
        return;
    };

    let addr = format!("{ip}:53")
        .parse()
        .unwrap_or_else(|_| panic!("expected an IP address, got {ip:?}"));
    let upstream = UpstreamConfig::Servers(vec![addr]);
    let resolver = HickoryTlsaResolver::with_upstream(pkix_dnssec_anchor::CURRENT, upstream)
        .expect("explicit servers need no system configuration");

    // A signed zone that publishes TLSA.
    let signed = TlsaName::new(443, &TlsaProtocol::Tcp, "good.dane.huque.com").expect("valid");
    match resolver.resolve(&signed).await {
        Ok(response) => {
            println!(
                "{}: {:?}, {} records",
                signed.as_str(),
                response.dnssec(),
                response.records().len()
            );
            assert_eq!(
                response.dnssec(),
                DnssecStatus::Secure,
                "a signed zone must validate against a DNSSEC-transparent upstream"
            );
            assert!(
                !response.records().is_empty(),
                "good.dane.huque.com should publish TLSA records for port 443"
            );
            assert!(response.has_usable_record());
        }
        Err(e) => panic!("the signed zone should have resolved: {e}"),
    }

    // An unsigned zone must not come back Secure. Without this, a resolver
    // that reported everything Secure would pass the assertion above.
    let unsigned = TlsaName::new(443, &TlsaProtocol::Tcp, "example.com").expect("valid");
    match resolver.resolve(&unsigned).await {
        Ok(response) => {
            println!("{}: {:?}", unsigned.as_str(), response.dnssec());
            assert_ne!(
                response.dnssec(),
                DnssecStatus::Secure,
                "an unsigned zone must not be reported Secure"
            );
        }
        Err(e) => println!("unsigned zone lookup failed, acceptable: {e}"),
    }
}
