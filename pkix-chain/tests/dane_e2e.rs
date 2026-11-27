//! End-to-end tests for `verify_tls_server_dane`.
//!
//! Uses the same PKITS §4.1.1 certificates as `e2e.rs`, which makes one
//! property available that is otherwise awkward to arrange: those
//! certificates carry no `dNSName` SAN, so every route through
//! `verify_tls_server_dane` that performs a name check **fails** on them,
//! while DANE-EE — which per RFC 7671 §5.1 consults neither names nor
//! validity dates — succeeds.
//!
//! That asymmetry is the test. A DANE-EE success here, alongside a pure-PKIX
//! failure on the identical inputs, demonstrates the name check was genuinely
//! bypassed rather than merely documented as bypassed.
//!
//! Records use matching type `Full` with selector `Cert`, so the association
//! data is the certificate DER itself and no digest is computed. The digest
//! arithmetic is tested in `pkix-dane` against `openssl dgst`; what is under
//! test here is the composition logic, and borrowing a digest oracle into this
//! crate would only add a way for the two to disagree.

#![cfg(feature = "dane")]

use pkix_chain::{
    verify_tls_server, verify_tls_server_dane, DaneConfig, DaneFailurePolicy, DefaultVerifier,
    Error, NoAiaFetcher, NoRevocation, TlsAuthorization,
};
use pkix_dane::{
    DaneError, DnssecStatus, TlsaMatchingType, TlsaRecord, TlsaResponse, TlsaSelector, TlsaUsage,
};
use pkix_identity::ServerName;
use pkix_path::TrustAnchor;
use pkix_profiles::BasicTlsProfile;
use x509_cert::Certificate;

const PKITS_NOW: u64 = 1_577_836_800;

const TRUST_ANCHOR_DER: &[u8] =
    include_bytes!("../../pkix-path/tests/pkits/certs/TrustAnchorRootCertificate.crt");
const GOOD_CA_DER: &[u8] = include_bytes!("../../pkix-path/tests/pkits/certs/GoodCACert.crt");
const VALID_EE_DER: &[u8] =
    include_bytes!("../../pkix-path/tests/pkits/certs/ValidCertificatePathTest1EE.crt");

fn load(der: &[u8]) -> Certificate {
    use x509_cert::der::Decode as _;
    Certificate::from_der(der).expect("parse cert")
}

/// The chain as a TLS peer would present it: leaf first, with the received
/// bytes alongside the parsed values.
struct Presented {
    chain: Vec<Certificate>,
    der: Vec<&'static [u8]>,
    anchors: Vec<TrustAnchor>,
}

fn presented() -> Presented {
    Presented {
        chain: vec![load(VALID_EE_DER), load(GOOD_CA_DER)],
        der: vec![VALID_EE_DER, GOOD_CA_DER],
        anchors: vec![TrustAnchor::from_cert(load(TRUST_ANCHOR_DER))],
    }
}

/// A `Full`/`Cert` record over `der`, so the association data is the
/// certificate itself.
fn full_record(usage: TlsaUsage, der: &[u8]) -> TlsaRecord {
    TlsaRecord::new(
        usage,
        TlsaSelector::Cert,
        TlsaMatchingType::Full,
        der.to_vec(),
    )
}

fn secure(records: Vec<TlsaRecord>) -> TlsaResponse {
    TlsaResponse::new(records, DnssecStatus::Secure)
}

/// Whether a failure came from the PKIX half rather than the DANE half.
///
/// The tests below care that PKIX got to decide, not which PKIX check fired
/// first. These certificates carry no `dNSName` SAN, so `BasicTlsProfile`
/// rejects them at path validation (`Path(MissingSan)`) before the identity
/// binding would — asserting the specific variant would make the test a
/// statement about check ordering inside pkix-path, which is not what is
/// under test here and which pkix-path is free to change.
fn rejected_by_pkix(result: &Result<TlsAuthorization, Error>) -> bool {
    matches!(result, Err(Error::Path(_) | Error::Identity(_)))
}

fn run(
    p: &Presented,
    response: Option<&TlsaResponse>,
    policy: DaneFailurePolicy,
) -> Result<TlsAuthorization, Error> {
    let dane = match response {
        Some(response) => DaneConfig::new(response, &p.der).with_policy(policy),
        None => DaneConfig::disabled().with_policy(policy),
    };
    verify_tls_server_dane(
        &p.chain,
        &p.anchors,
        &ServerName::dns_name("anything.example").expect("valid dns name"),
        &BasicTlsProfile,
        PKITS_NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
        &dane,
    )
}

/// The baseline that makes the DANE-EE test meaningful: these certificates do
/// not satisfy a name check, so pure PKIX rejects them.
#[test]
fn pure_pkix_rejects_these_certificates_on_identity() {
    let p = presented();
    let result = verify_tls_server(
        &p.chain,
        &p.anchors,
        &ServerName::dns_name("anything.example").expect("valid dns name"),
        &BasicTlsProfile,
        PKITS_NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    );
    assert!(
        matches!(result, Err(Error::Path(_) | Error::Identity(_))),
        "PKITS certs carry no dNSName SAN, so PKIX should reject them; got {result:?}"
    );
}

/// DANE-EE authorizes the leaf with no chain validation, no name check and no
/// validity check — on the very certificates pure PKIX just rejected.
#[test]
fn dane_ee_authorizes_without_a_name_check() {
    let p = presented();
    let response = secure(vec![full_record(TlsaUsage::DaneEe, VALID_EE_DER)]);

    let authorization = run(&p, Some(&response), DaneFailurePolicy::Opportunistic)
        .expect("a DANE-EE match should authorize");

    assert!(
        matches!(authorization, TlsAuthorization::DaneEndEntity { .. }),
        "expected DaneEndEntity, got {authorization:?}"
    );
    assert!(
        authorization.path().is_none(),
        "usage 3 validates no path, so there is none to report"
    );
    assert!(authorization.used_dane());
    assert_eq!(
        authorization.record().map(TlsaRecord::usage),
        Some(TlsaUsage::DaneEe)
    );
}

/// A usage-3 record naming a different certificate does not authorize. Without
/// this, a matcher that ignored its input would pass the test above.
#[test]
fn dane_ee_rejects_a_record_naming_another_certificate() {
    let p = presented();
    // The record names the CA, not the leaf.
    let response = secure(vec![full_record(TlsaUsage::DaneEe, GOOD_CA_DER)]);

    let result = run(&p, Some(&response), DaneFailurePolicy::Opportunistic);
    assert!(
        matches!(result, Err(Error::Dane(DaneError::NoMatch { .. }))),
        "expected a DANE no-match, got {result:?}"
    );
}

/// A usage-1 record matches the leaf, but PKIX validation still has to pass —
/// and here it does not, because the name check fails. The error must come
/// from the PKIX half, proving usage 1 did not waive it.
#[test]
fn pkix_ee_still_requires_pkix_validation() {
    let p = presented();
    let response = secure(vec![full_record(TlsaUsage::PkixEe, VALID_EE_DER)]);

    let result = run(&p, Some(&response), DaneFailurePolicy::Opportunistic);
    assert!(
        rejected_by_pkix(&result),
        "usage 1 must not waive PKIX validation; got {result:?}"
    );
}

/// With both a DANE-EE and a PKIX-EE record present, the DANE-EE semantics
/// win. Strongest-first ordering means a domain that published usage 3 gets
/// usage 3 behaviour rather than having the outcome depend on the client's
/// trust store.
#[test]
fn dane_ee_is_preferred_over_pkix_ee() {
    let p = presented();
    let response = secure(vec![
        full_record(TlsaUsage::PkixEe, VALID_EE_DER),
        full_record(TlsaUsage::DaneEe, VALID_EE_DER),
    ]);

    let authorization = run(&p, Some(&response), DaneFailurePolicy::Opportunistic)
        .expect("the usage-3 record should authorize");
    assert!(
        matches!(authorization, TlsAuthorization::DaneEndEntity { .. }),
        "usage 3 should win over usage 1; got {authorization:?}"
    );
}

/// Bogus fails under the opportunistic policy, which is the whole point of its
/// not being configurable: an attacker who can corrupt the DNS answer must not
/// be able to downgrade the connection to PKIX.
#[test]
fn a_bogus_dnssec_status_fails_even_opportunistically() {
    let p = presented();
    let response = TlsaResponse::new(
        vec![full_record(TlsaUsage::DaneEe, VALID_EE_DER)],
        DnssecStatus::Bogus,
    );

    for policy in [DaneFailurePolicy::Opportunistic, DaneFailurePolicy::Strict] {
        let result = run(&p, Some(&response), policy);
        assert!(
            matches!(
                result,
                Err(Error::Dane(DaneError::DnssecNotSecure {
                    status: DnssecStatus::Bogus
                }))
            ),
            "Bogus must fail under {policy:?}; got {result:?}"
        );
    }
}

/// An unsigned zone falls through to PKIX opportunistically. The identity
/// error proves the fall-through happened — a DANE error would mean it did
/// not.
#[test]
fn an_unsigned_zone_falls_through_to_pkix_opportunistically() {
    let p = presented();
    let response = TlsaResponse::new(
        vec![full_record(TlsaUsage::DaneEe, VALID_EE_DER)],
        DnssecStatus::Insecure,
    );

    let result = run(&p, Some(&response), DaneFailurePolicy::Opportunistic);
    assert!(
        rejected_by_pkix(&result),
        "an insecure status should fall through to PKIX, which then rejects \
         these certificates; a DANE error would mean it did not fall through. \
         Got {result:?}"
    );
}

/// The same input under a strict policy fails with a DANE error rather than
/// reaching PKIX at all.
#[test]
fn an_unsigned_zone_fails_strictly() {
    let p = presented();
    let response = TlsaResponse::new(
        vec![full_record(TlsaUsage::DaneEe, VALID_EE_DER)],
        DnssecStatus::Insecure,
    );

    let result = run(&p, Some(&response), DaneFailurePolicy::Strict);
    assert!(
        matches!(
            result,
            Err(Error::Dane(DaneError::DnssecNotSecure {
                status: DnssecStatus::Insecure
            }))
        ),
        "a strict policy should refuse an unsigned zone; got {result:?}"
    );
}

/// No DANE attempt at all behaves exactly like pure PKIX under the
/// opportunistic policy. This is the call-site override.
#[test]
fn the_disabled_config_is_pure_pkix() {
    let p = presented();
    let dane = DaneConfig::disabled();
    let with_dane_disabled = verify_tls_server_dane(
        &p.chain,
        &p.anchors,
        &ServerName::dns_name("anything.example").expect("valid dns name"),
        &BasicTlsProfile,
        PKITS_NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
        &dane,
    );
    let pure = verify_tls_server(
        &p.chain,
        &p.anchors,
        &ServerName::dns_name("anything.example").expect("valid dns name"),
        &BasicTlsProfile,
        PKITS_NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    );

    // Same outcome either way: PKIX decided, and decided the same thing.
    assert!(rejected_by_pkix(&with_dane_disabled));
    assert!(
        matches!(pure, Err(Error::Path(_) | Error::Identity(_))),
        "got {pure:?}"
    );
    assert_eq!(
        format!("{:?}", with_dane_disabled.map(|_| ())),
        format!("{:?}", pure.map(|_| ())),
        "a disabled DaneConfig must produce exactly what pure PKIX produces"
    );
}

/// A strict caller that never attempted resolution has not met its own policy,
/// so it fails rather than silently validating by PKIX alone.
#[test]
fn a_strict_caller_that_did_not_resolve_fails() {
    let p = presented();
    let result = run(&p, None, DaneFailurePolicy::Strict);
    assert!(
        matches!(result, Err(Error::Dane(DaneError::ResolutionDisabled))),
        "expected ResolutionDisabled, got {result:?}"
    );
}

/// An authenticated denial falls through opportunistically: the domain signed
/// that it publishes no TLSA record, so PKIX decides.
#[test]
fn an_authenticated_denial_falls_through_opportunistically() {
    let p = presented();
    let response = secure(Vec::new());
    assert!(response.is_authenticated_denial());

    let result = run(&p, Some(&response), DaneFailurePolicy::Opportunistic);
    assert!(
        rejected_by_pkix(&result),
        "an authenticated denial should fall through to PKIX; got {result:?}"
    );
}

/// A record set this client cannot evaluate is equivalent to publishing none
/// (RFC 7671 §17), so it falls through rather than failing the connection.
#[test]
fn unevaluable_records_fall_through_opportunistically() {
    let p = presented();
    let unusable = TlsaRecord::new(
        TlsaUsage::DaneEe,
        TlsaSelector::Unassigned(9),
        TlsaMatchingType::Full,
        VALID_EE_DER.to_vec(),
    );
    assert!(!unusable.is_usable());

    let result = run(
        &p,
        Some(&secure(vec![unusable])),
        DaneFailurePolicy::Opportunistic,
    );
    assert!(
        rejected_by_pkix(&result),
        "unevaluable records should fall through; got {result:?}"
    );
}

/// A misaligned `chain_der` is a caller error and is reported as one, rather
/// than silently matching against fewer certificates than the chain holds.
#[test]
fn a_misaligned_chain_der_is_rejected() {
    let p = presented();
    let response = secure(vec![full_record(TlsaUsage::DaneEe, VALID_EE_DER)]);
    // One entry for a two-certificate chain.
    let dane = DaneConfig::new(&response, &[VALID_EE_DER]);
    let result = verify_tls_server_dane(
        &p.chain,
        &p.anchors,
        &ServerName::dns_name("anything.example").expect("valid dns name"),
        &BasicTlsProfile,
        PKITS_NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
        &dane,
    );
    assert!(
        matches!(result, Err(Error::Dane(DaneError::ResolutionFailed(_)))),
        "a misaligned chain_der should be reported, got {result:?}"
    );
}

/// The `Pkix` variant's accessors, which nothing above reaches.
///
/// Every chain in this file fails PKIX deliberately -- that is what makes the
/// DANE-EE cases meaningful -- so the only authorization any test here
/// obtains is `DaneEndEntity`, whose `path()` is `None` and whose
/// `used_dane()` is `true`. Both accessors could have been those constants
/// and every assertion in the file would still have held, while a caller
/// asking "did DANE decide this?" or "which path validated?" got the wrong
/// answer for the common case.
///
/// So this one uses the crate's own chain fixtures, which do satisfy a name
/// check, with DANE switched off at the call site.
#[test]
fn a_pkix_only_authorization_reports_its_path_and_no_dane() {
    const FLAT_ROOT_DER: &[u8] = include_bytes!("fixtures/root.der");
    const FLAT_LEAF_DER: &[u8] = include_bytes!("fixtures/leaf-san-www-example.der");

    let chain = [load(FLAT_LEAF_DER)];
    let anchors = [TrustAnchor::from_cert(load(FLAT_ROOT_DER))];
    let dane = DaneConfig::disabled().with_policy(DaneFailurePolicy::Opportunistic);

    let authorization = verify_tls_server_dane(
        &chain,
        &anchors,
        &ServerName::dns_name("www.example.com").expect("valid dns name"),
        &BasicTlsProfile,
        PKITS_NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
        &dane,
    )
    .expect("the chain validates and no DANE applied");

    assert!(
        matches!(authorization, TlsAuthorization::Pkix(_)),
        "expected Pkix, got {authorization:?}"
    );
    assert!(
        authorization.path().is_some(),
        "PKIX validated a path, so there is one to report"
    );
    assert!(
        !authorization.used_dane(),
        "DANE was disabled; it took no part in this decision"
    );
    assert!(
        authorization.record().is_none(),
        "no TLSA record applied, so there is none to report"
    );
}
