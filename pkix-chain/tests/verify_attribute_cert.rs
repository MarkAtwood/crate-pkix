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
use pkix_chain::{verify_attribute_cert, AcRevocation, Error, NoAiaFetcher, NoRevocation};
use pkix_path::{DefaultVerifier, TrustAnchor};
use pkix_profiles::Rfc5280Profile;
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

/// Inside every fixture's window.
const NOW: u64 = 1_767_225_600; // 2026-01-01T00:00:00Z

const ROOT_DER: &[u8] =
    include_bytes!("../../pkix-ct/tests/fixtures/sct-oracle/precert-issuer.der");
const HOLDER_DER: &[u8] =
    include_bytes!("../../pkix-ct/tests/fixtures/sct-oracle/precert-leaf-final.der");
const AA_DER: &[u8] = include_bytes!("../../pkix-ac/tests/fixtures/aa-cert.der");
const AC_VALID: &[u8] = include_bytes!("../../pkix-ac/tests/fixtures/ac-role-valid.der");
const AC_EXPIRED: &[u8] = include_bytes!("../../pkix-ac/tests/fixtures/ac-expired.der");
const AC_TARGETED: &[u8] = include_bytes!("../../pkix-ac/tests/fixtures/ac-targeted.der");

fn dns(host: &str) -> x509_cert::ext::pkix::name::GeneralName {
    x509_cert::ext::pkix::name::GeneralName::DnsName(
        x509_cert::der::asn1::Ia5String::new(host).expect("host"),
    )
}

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
        // The fixtures carry no noRevAvail, so §6's never-revoke-only
        // reading would refuse them all. These tests are about the other
        // rules; §6 has a test of its own.
        AcRevocation::CallerChecks,
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
        AcRevocation::CallerChecks,
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

/// An AC targeted at somebody else is refused — RFC 5755 §4.3.2.
///
/// "An (honest) AC verifier who is not amongst the named
/// servers/services MUST reject the AC."
///
/// This function returned `Ok(.. NotATarget)` and left the decision to
/// the caller, reasoning that being outside an AC's targets is policy
/// rather than invalidity. That was fail-open on a MUST: the obvious use
/// is `let v = verify_attribute_cert(..)?` followed by granting the
/// attribute, which honours an AC scoped to another service.
#[test]
fn an_attribute_certificate_targeted_elsewhere_is_refused() {
    let holder = vec![load(HOLDER_DER)];
    let aa = vec![load(AA_DER)];

    assert_eq!(
        run_as(
            AC_TARGETED,
            &holder,
            &aa,
            std::slice::from_ref(&dns("elsewhere.example.com")),
            &[],
        )
        .err(),
        Some(Error::AttributeCert(pkix_ac::Error::NotATarget)),
        "§4.3.2 requires rejection, not a field the caller may ignore"
    );

    // A verifier that supplies no names at all is not among the targets
    // either, so a targeted AC must not pass by default.
    assert_eq!(
        run(AC_TARGETED, &holder, &aa).err(),
        Some(Error::AttributeCert(pkix_ac::Error::NotATarget)),
        "supplying no names must not be a way past targeting"
    );
}

/// And a verifier that IS a target validates, by name or by group.
///
/// `targeting` then reports which of the two permitted states applied.
/// It can never hold `NotATarget`, since that is now an error.
#[test]
fn a_named_target_validates_by_name_or_group() {
    let holder = vec![load(HOLDER_DER)];
    let aa = vec![load(AA_DER)];

    let named = run_as(
        AC_TARGETED,
        &holder,
        &aa,
        std::slice::from_ref(&dns("verifier.example.com")),
        &[],
    )
    .expect("this verifier is named by the AC");
    assert_eq!(named.targeting, Targeting::Matched);

    let by_group = run_as(
        AC_TARGETED,
        &holder,
        &aa,
        &[],
        std::slice::from_ref(&dns("printers.example.com")),
    )
    .expect("matching by group counts");
    assert_eq!(by_group.targeting, Targeting::Matched);

    // Case differs from the AC's spelling. DNS names are
    // case-insensitive (RFC 4343), so this is the same target — and
    // being told otherwise would fail closed for the one deployment the
    // AC was issued for.
    let shouting = run_as(
        AC_TARGETED,
        &holder,
        &aa,
        std::slice::from_ref(&dns("VERIFIER.EXAMPLE.COM")),
        &[],
    )
    .expect("dNSName comparison is case-insensitive");
    assert_eq!(shouting.targeting, Targeting::Matched);

    // An untargeted AC still validates for anyone.
    let untargeted = run(AC_VALID, &holder, &aa).expect("untargeted");
    assert_eq!(untargeted.targeting, Targeting::Untargeted);
}

const ICA_DER: &[u8] = include_bytes!("../../pkix-ac/tests/fixtures/ica-cert.der");
const AA_DEEP_DER: &[u8] = include_bytes!("../../pkix-ac/tests/fixtures/aa-deep-cert.der");
const HOLDER_DEEP_DER: &[u8] = include_bytes!("../../pkix-ac/tests/fixtures/holder-deep-cert.der");
const AC_DEEP: &[u8] = include_bytes!("../../pkix-ac/tests/fixtures/ac-deep.der");

/// The composition walks a real chain on both sides.
///
/// Every other test here uses one-element chains, so the wrapper had
/// never seen an intermediate even though every deployment has one.
/// These fixtures are a two-level PKI from
/// `pkix-ac/tests/fixtures/make_aa.sh`: the `pkix-ct` root as the single
/// trust anchor, an intermediate CA under it with `pathlen:0`, and both
/// the attribute authority and the holder issued from that
/// intermediate.
#[test]
fn both_chains_may_have_intermediates() {
    let holder = vec![load(HOLDER_DEEP_DER), load(ICA_DER)];
    let aa = vec![load(AA_DEEP_DER), load(ICA_DER)];

    let out = run(AC_DEEP, &holder, &aa).expect("depth is ordinary, not exceptional");
    assert_eq!(out.targeting, Targeting::Untargeted);
    // Both paths reached the same anchor, two certificates deep.
    assert_eq!(out.holder.anchor_index, 0);
    assert_eq!(out.authority.anchor_index, 0);
}

/// An incomplete chain fails on the path, not as an attribute-certificate
/// problem.
///
/// Which error arrives matters: a caller who forgot an intermediate
/// needs to be told their chain is short, not sent looking at the AC.
/// The holder's chain is validated first, so its failure is the one
/// reported when both are short.
#[test]
fn a_missing_intermediate_is_a_path_failure_on_either_side() {
    let holder = vec![load(HOLDER_DEEP_DER), load(ICA_DER)];
    let aa = vec![load(AA_DEEP_DER), load(ICA_DER)];

    for (name, h, a) in [
        ("holder", vec![load(HOLDER_DEEP_DER)], aa.clone()),
        ("authority", holder.clone(), vec![load(AA_DEEP_DER)]),
    ] {
        let err = run(AC_DEEP, &h, &a).expect_err("a short chain cannot validate");
        assert!(
            matches!(err, Error::Path(_) | Error::PathBuild(_)),
            "the {name} chain's gap must surface as a path error, got {err:?}"
        );
    }
}

/// A reversed authority chain is caught by §4.5, not by luck.
///
/// `aa_chain[0]` is the authority, leaf-first like every other chain in
/// this workspace. Hand it leaf-last and position 0 holds the
/// intermediate — which is a CA, and RFC 5755 §4.5 forbids an AC issuer
/// from being one.
///
/// So the rule that exists to stop a PKI CA being reused as an attribute
/// authority also catches an ordinary ordering mistake, and names it.
/// Worth pinning because it is the second time §4.5 has paid for itself
/// on something other than the attack it was written for.
#[test]
fn a_reversed_authority_chain_is_refused_as_a_ca() {
    let holder = vec![load(HOLDER_DEEP_DER), load(ICA_DER)];
    let reversed = vec![load(ICA_DER), load(AA_DEEP_DER)];

    assert_eq!(
        run(AC_DEEP, &holder, &reversed).err(),
        Some(Error::AttributeCert(pkix_ac::Error::ProfileViolation(
            pkix_ac::ProfileViolation::IssuerIsACa
        )))
    );
}

/// Passing the two chains the wrong way round is refused by name.
///
/// Both chains validate against the anchors, so path validation cannot
/// catch this — it is the issuer-name check that does, because the AC
/// does not name the holder as its authority. A plausible mistake with
/// a real consequence, since the alternative to catching it is verifying
/// an AC against a key its issuer never held.
#[test]
fn swapping_the_holder_and_authority_chains_is_refused() {
    let holder = vec![load(HOLDER_DEEP_DER), load(ICA_DER)];
    let aa = vec![load(AA_DEEP_DER), load(ICA_DER)];

    assert_eq!(
        run(AC_DEEP, &aa, &holder).err(),
        Some(Error::AttributeCert(pkix_ac::Error::IssuerMismatch))
    );
}

/// RFC 5755 §6: a verifier that checks no AC revocation status MUST
/// reject an AC without `noRevAvail`.
///
/// §6: "for AC users, the 'never revoke' scheme MUST be supported ...
/// If only the 'never revoke' scheme is supported, then all ACs that do
/// not contain a noRevAvail extension, MUST be rejected." This function
/// checks none, so [`AcRevocation::NeverRevokeOnly`] is what it
/// actually supports — and an AC without the extension is its issuer
/// "implicitly stating that revocation status checks are supported, and
/// some revocation method MUST be provided".
///
/// Accepting those regardless was fail-open on a MUST, the same mistake
/// as returning `Ok` for an AC targeted elsewhere. `CallerChecks` is the
/// opt-out, and it is a parameter rather than a default so the decision
/// is named at every call site — nothing here can verify the caller
/// really does check.
#[test]
fn an_ac_without_no_rev_avail_is_refused_unless_the_caller_checks() {
    let holder = vec![load(HOLDER_DER)];
    let aa = vec![load(AA_DER)];
    let ac = AttributeCertificate::from_der(AC_VALID).expect("AC parses");

    let run_with = |policy| {
        verify_attribute_cert(
            &ac,
            &holder,
            &aa,
            &anchors(),
            &[],
            &[],
            policy,
            &Rfc5280Profile,
            NOW,
            &DefaultVerifier,
            &NoRevocation,
            &NoAiaFetcher,
        )
    };

    assert_eq!(
        run_with(AcRevocation::NeverRevokeOnly).err(),
        Some(Error::AttributeCert(pkix_ac::Error::RevocationUnsupported)),
        "this AC carries no noRevAvail, and §6 requires rejecting it"
    );

    run_with(AcRevocation::CallerChecks)
        .expect("a caller who establishes revocation status itself may proceed");
}
