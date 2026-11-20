//! Review: assorted §6.1 findings. Fixtures: `tests/fixtures/review/misc/`
//! (see `gen.sh`; `prepend_ext.py` is a stdlib-only DER helper it calls).
//! Every well-formed chain here is accepted by `openssl verify`; the
//! duplicate-extension chain is rejected by it.

#![cfg(all(feature = "p256", feature = "rsa"))]

mod support {
    pub mod raw_cert;
}

use der::Decode as _;
use pkix_path::{DefaultVerifier, TrustAnchor, ValidationPolicy};
use x509_cert::Certificate;

const NOW: u64 = 1_798_761_600; // 2027-01-01T00:00:00Z
const P: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.2.1");

fn load(name: &str) -> Certificate {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/review/misc")
        .join(format!("{name}.der"));
    Certificate::from_der(&std::fs::read(&p).unwrap()).unwrap()
}

fn validate(
    chain: &[&str],
    root: &str,
    policy: &ValidationPolicy,
) -> pkix_path::Result<pkix_path::ValidatedPath> {
    let chain: Vec<_> = chain.iter().map(|n| load(n)).collect();
    pkix_path::validate_path(
        &chain,
        &[TrustAnchor::from_cert(load(root))],
        policy,
        &DefaultVerifier,
    )
}

// ---------------------------------------------------------------------------
// RSA moduli up to 8192 bits verify.
// ---------------------------------------------------------------------------

/// An RSA-8192 root signing a leaf is a valid path (`openssl verify` OK).
/// The `rsa` crate's default `RsaPublicKey::MAX_SIZE` is 4096 bits, so the
/// verifier must opt into the larger limit.
#[test]
fn rsa_8192_issuer_key_verifies() {
    validate(
        &["rsa8192-leaf"],
        "rsa8192-root",
        &ValidationPolicy::new(NOW),
    )
    .expect("RSA-8192 issuer + sha256WithRSAEncryption is valid");
}

// ---------------------------------------------------------------------------
// §6.1.4(b)(1): expected_policy_set update is order dependent.
// ---------------------------------------------------------------------------

/// CA asserts P and maps {P→P, P→Q}; leaf asserts P. RFC 5280 §6.1.4(b)(1)
/// sets the P node's expected_policy_set to {P, Q}, so the leaf's P matches
/// and the path validates under initial-explicit-policy (`openssl verify
/// -explicit_policy -policy P` → OK). A per-mapping "remove ID-P, add
/// subject policy" update would let the later P→Q entry delete the P that
/// P→P just added.
#[test]
fn identity_mapping_listed_first_is_not_lost() {
    let mut policy = ValidationPolicy::new(NOW);
    policy.initial_explicit_policy = true;
    policy.initial_policy_set = vec![P];
    validate(&["map-leaf-first", "map-ca-first"], "map-root", &policy)
        .expect("expected_policy_set must be {P, Q} regardless of mapping order");
}

/// Control: the same mappings in the other order.
#[test]
fn identity_mapping_listed_last_control() {
    let mut policy = ValidationPolicy::new(NOW);
    policy.initial_explicit_policy = true;
    policy.initial_policy_set = vec![P];
    validate(&["map-leaf-last", "map-ca-last"], "map-root", &policy).expect("control");
}

// ---------------------------------------------------------------------------
// RFC 5280 §4.2: duplicate extensions are not rejected.
// ---------------------------------------------------------------------------

/// The intermediate carries two critical basicConstraints: cA=TRUE then
/// cA=FALSE. "A certificate MUST NOT include more than one instance of a
/// particular extension" (§4.2). OpenSSL rejects the chain (invalid CA
/// certificate); a validator that reads only the first instance would accept
/// it as a CA, a parser differential an attacker can aim at mixed-validator
/// deployments.
#[test]
fn duplicate_basic_constraints_rejected() {
    let r = validate(
        &["dupbc-leaf", "dupbc-ca"],
        "dupbc-root",
        &ValidationPolicy::new(NOW),
    );
    assert!(
        matches!(r, Err(pkix_path::Error::MalformedCertificate { index: 1 })),
        "duplicate basicConstraints must be MalformedCertificate at index 1: {:?}",
        r.map(|v| v.depth)
    );
}

// ---------------------------------------------------------------------------
// min_rsa_key_bits counts id-RSASSA-PSS subject keys as RSA.
// ---------------------------------------------------------------------------

/// A leaf whose SubjectPublicKeyInfo is a 1024-bit id-RSASSA-PSS key
/// (RFC 4055 §1.2) must fail a 2048-bit floor like an rsaEncryption key.
#[test]
fn min_rsa_key_bits_rejects_small_rsassa_pss_key() {
    let mut policy = ValidationPolicy::new(NOW);
    policy.min_rsa_key_bits = Some(2048);
    let r = validate(&["pss1024-leaf"], "pss-root", &policy);
    assert!(
        matches!(r, Err(pkix_path::Error::KeyTooSmall { index: 0 })),
        "{:?}",
        r.map(|v| v.depth)
    );
}

/// Control: a 2048-bit id-RSASSA-PSS key meets the same floor.
#[test]
fn min_rsa_key_bits_accepts_2048_bit_rsassa_pss_key() {
    let mut policy = ValidationPolicy::new(NOW);
    policy.min_rsa_key_bits = Some(2048);
    validate(&["pss2048-leaf"], "pss-root", &policy).expect("2048-bit PSS key");
}

// ---------------------------------------------------------------------------
// check_inputs: O(n^2) duplicate scan runs before the path-length check.
// ---------------------------------------------------------------------------

/// A 20 000-entry "chain" (distinct serials, identical names) must be
/// rejected cheaply with PathTooLong, before the O(n^2) duplicate scan in
/// `check_inputs` (~2*10^8 `names_match` calls for this input). Chain length is attacker-controlled when the
/// chain comes off the wire (e.g. a TLS Certificate message).
#[test]
fn overlong_chain_rejected_in_linear_time() {
    let base = load("rsa8192-leaf");
    let chain: Vec<Certificate> = (0..20_000u32)
        .map(|i| {
            support::raw_cert::edit_cert(&base, |raw| {
                raw.tbs_certificate.serial_number =
                    x509_cert::serial_number::SerialNumber::new(&(i + 1).to_be_bytes()).unwrap();
            })
        })
        .collect();
    let anchors = vec![TrustAnchor::from_cert(load("rsa8192-root"))];
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(pkix_path::validate_path(
            &chain,
            &anchors,
            &ValidationPolicy::new(NOW),
            &DefaultVerifier,
        ));
    });
    match rx.recv_timeout(std::time::Duration::from_secs(10)) {
        Ok(r) => assert!(matches!(r, Err(pkix_path::Error::PathTooLong)), "{r:?}"),
        Err(_) => panic!("validate_path spent >10s on a 20 000-cert chain before the length check"),
    }
}
