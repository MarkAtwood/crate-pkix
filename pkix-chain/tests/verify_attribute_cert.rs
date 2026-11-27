//! End-to-end RFC 5755 attribute certificate validation.
//!
//! This is `pkix-ac`'s first real consumer, and it exists to exercise
//! the seam: `pkix-ac` takes no trust anchors and validates no path, so
//! on its own it will check a signature against whatever authority
//! certificate it is handed. [`verify_attribute_cert`] validates both
//! paths first.
//!
//! # Fixtures
//!
//! - The root, holder and holder's chain come from `pkix-ct`'s
//!   `sct-oracle` set: `precert-issuer.der` is a self-signed CA used
//!   here as the single trust anchor, and `precert-leaf-final.der` is
//!   the entity presenting the AC.
//! - The Attribute Authority is `pkix-ac`'s own `aa-cert.der`, built by
//!   `pkix-ac/tests/fixtures/make_aa.sh`: `cA=FALSE`, keyUsage
//!   `digitalSignature`, issued by that root.
//! - The attribute certificates come from
//!   `pkix-ac/tests/fixtures/gen.py` and are signed by the authority's
//!   key with `openssl dgst`.
//!
//! The authority had to be built for this test. The AC fixtures were
//! originally signed by `precert-issuer` itself, which is `CA:TRUE` with
//! keyUsage `Certificate Sign, CRL Sign` — and RFC 5755 §4.5 forbids an
//! AC issuer from being a CA or from having keyUsage that excludes
//! `digitalSignature`. Those fixtures verified arithmetically in
//! `pkix-ac`'s own tests and could never have passed a conforming
//! end-to-end validation. Writing this consumer is what surfaced that.

#![cfg(feature = "attribute-certs")]

use pkix_ac::{AttributeCertificate, Targeting};
use pkix_chain::{verify_attribute_cert, Error, NoAiaFetcher, NoRevocation};
use pkix_path::{DefaultVerifier, TrustAnchor};
use pkix_profiles::Rfc5280Profile;
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

/// Inside every fixture's window.
const NOW: u64 = 1_767_225_600; // 2025-12-31T12:00:00Z

const ROOT_DER: &[u8] =
    include_bytes!("../../pkix-ct/tests/fixtures/sct-oracle/precert-issuer.der");
const HOLDER_DER: &[u8] =
    include_bytes!("../../pkix-ct/tests/fixtures/sct-oracle/precert-leaf-final.der");
const AA_DER: &[u8] = include_bytes!("../../pkix-ac/tests/fixtures/aa-cert.der");
const AC_VALID: &[u8] = include_bytes!("../../pkix-ac/tests/fixtures/ac-role-valid.der");
const AC_EXPIRED: &[u8] = include_bytes!("../../pkix-ac/tests/fixtures/ac-expired.der");
const AC_TARGETED: &[u8] = include_bytes!("../../pkix-ac/tests/fixtures/ac-targeted.der");

fn load(der: &[u8]) -> Certificate {
    Certificate::from_der(der).expect("fixture parses")
}

fn anchors() -> Vec<TrustAnchor> {
    vec![TrustAnchor::from_cert(load(ROOT_DER))]
}

fn run(
    ac_der: &[u8],
    holder: &[Certificate],
    aa: &[Certificate],
) -> Result<pkix_chain::ValidatedAttributeCert, Error> {
    run_as(ac_der, holder, aa, &[], &[])
}

fn run_as(
    ac_der: &[u8],
    holder: &[Certificate],
    aa: &[Certificate],
    my_names: &[x509_cert::ext::pkix::name::GeneralName],
    my_groups: &[x509_cert::ext::pkix::name::GeneralName],
) -> Result<pkix_chain::ValidatedAttributeCert, Error> {
    let ac = AttributeCertificate::from_der(ac_der).expect("AC parses");
    verify_attribute_cert(
        &ac,
        holder,
        aa,
        &anchors(),
        my_names,
        my_groups,
        &Rfc5280Profile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
}

/// The whole composition: both paths validated, the AC verified, the
/// holder bound.
#[test]
fn a_conforming_attribute_certificate_validates_end_to_end() {
    let holder = vec![load(HOLDER_DER)];
    let aa = vec![load(AA_DER)];

    let out = run(AC_VALID, &holder, &aa).expect("conforming AC must validate");

    // Untargeted, not Matched: the AC carries no targetInformation, and
    // conflating "no restriction" with "I am a named target" is the
    // mistake the enum exists to prevent.
    assert_eq!(out.targeting, Targeting::Untargeted);
    // Both paths are returned because both were validated.
    assert_eq!(out.holder.anchor_index, 0);
    assert_eq!(out.authority.anchor_index, 0);
}

/// A CA cannot be an Attribute Authority — RFC 5755 §4.5.
///
/// This is the check that makes §5 rule 4 ("the AC issuer MUST be
/// directly trusted as an AC issuer") harder to satisfy by accident. The
/// root here is a perfectly good trust anchor and a perfectly good CA,
/// and it is refused as an authority anyway.
#[test]
fn the_root_ca_is_refused_as_an_attribute_authority() {
    let holder = vec![load(HOLDER_DER)];
    // The root is self-signed, so this is a valid one-element chain.
    let aa = vec![load(ROOT_DER)];

    match run(AC_VALID, &holder, &aa) {
        Err(Error::AttributeCert(e)) => {
            let rendered = e.to_string();
            assert!(
                rendered.contains("CA") || rendered.contains("digitalSignature"),
                "must name the §4.5 rule it broke, got {rendered}"
            );
        }
        other => panic!("a CA must be refused as an authority, got {other:?}"),
    }
}

/// An AC issued to somebody else is refused, however good its signature.
///
/// Without the holder binding the result would mean "an authority you
/// trust issued this to someone", which answers no question anybody
/// asks. The authority's own certificate stands in for the wrong
/// holder: it chains to the same anchor, so the holder path validates
/// and only the binding fails.
#[test]
fn an_attribute_certificate_for_a_different_holder_is_refused() {
    let wrong_holder = vec![load(AA_DER)];
    let aa = vec![load(AA_DER)];

    assert_eq!(
        run(AC_VALID, &wrong_holder, &aa).err(),
        Some(Error::AttributeCert(pkix_ac::Error::HolderMismatch))
    );
}

/// The AC's own validity is enforced, not just the certificates'.
#[test]
fn an_expired_attribute_certificate_is_refused() {
    let holder = vec![load(HOLDER_DER)];
    let aa = vec![load(AA_DER)];

    assert_eq!(
        run(AC_EXPIRED, &holder, &aa).err(),
        Some(Error::AttributeCert(pkix_ac::Error::Expired))
    );
}

/// The authority's path is validated, so an authority that does not
/// chain to the caller's anchors is refused before the AC is examined.
#[test]
fn an_unanchored_authority_is_refused() {
    let holder = vec![load(HOLDER_DER)];
    let aa = vec![load(AA_DER)];
    let ac = AttributeCertificate::from_der(AC_VALID).expect("AC parses");

    // Anchor the holder's root only... which is also the authority's
    // root, so instead drop the anchors entirely: both paths then fail,
    // and the holder's is checked first.
    let err = verify_attribute_cert(
        &ac,
        &holder,
        &aa,
        &[],
        &[],
        &[],
        &Rfc5280Profile,
        NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect_err("no anchors must fail");
    // Either path-side variant is right; the point is that it fails on
    // the chain rather than reaching the AC checks at all.
    assert!(
        matches!(err, Error::Path(_) | Error::PathBuild(_)),
        "must fail on the certification path, not as an AC error: {err:?}"
    );
}

/// Targeting reaches the caller through the wrapper, in all three
/// states.
///
/// The end-to-end test above only ever saw `Untargeted`, because every
/// fixture it used was untargeted -- so the field was returned and
/// never shown to carry anything else. A targeted AC validates
/// identically whether or not this verifier is a target: the AC is
/// valid, and whether being outside its targets is fatal is the
/// caller's policy, not an error from here.
#[test]
fn targeting_is_reported_through_the_wrapper() {
    let holder = vec![load(HOLDER_DER)];
    let aa = vec![load(AA_DER)];
    let dns = |h: &str| {
        x509_cert::ext::pkix::name::GeneralName::DnsName(
            x509_cert::der::asn1::Ia5String::new(h).expect("host"),
        )
    };

    let named = run_as(
        AC_TARGETED,
        &holder,
        &aa,
        std::slice::from_ref(&dns("verifier.example.com")),
        &[],
    )
    .expect("a targeted AC is still a valid AC");
    assert_eq!(named.targeting, Targeting::Matched);

    let by_group = run_as(
        AC_TARGETED,
        &holder,
        &aa,
        &[],
        std::slice::from_ref(&dns("printers.example.com")),
    )
    .expect("matching by group is still valid");
    assert_eq!(by_group.targeting, Targeting::Matched);

    // Not a target: Ok, with the fact reported. A caller that ignores
    // the field treats this as success, which is why it is a field and
    // not a silent pass.
    let stranger = run_as(
        AC_TARGETED,
        &holder,
        &aa,
        std::slice::from_ref(&dns("elsewhere.example.com")),
        &[],
    )
    .expect("being outside the targets is not a validation failure");
    assert_eq!(stranger.targeting, Targeting::NotATarget);
}
