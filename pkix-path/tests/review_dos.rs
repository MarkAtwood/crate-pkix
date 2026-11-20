//! Review regression tests: unbounded work on attacker-controlled DER in
//! `pkix-path`. Fixtures: `tests/fixtures/review/dos/` (see gen.py there).
//!
//! This is a wall-clock test. The budget is generous: with the
//! `MAX_AVAS_PER_RDN` cap the case finishes in milliseconds even in a
//! debug build; before the fix it took ~6.5 s.

#![cfg(feature = "p256")]

use std::time::{Duration, Instant};

use der::Decode as _;
use pkix_path::{DefaultVerifier, TrustAnchor, ValidationPolicy};
use x509_cert::Certificate;

const NOW: u64 = 1_735_689_600;

fn load(dir: &str, name: &str) -> Certificate {
    let path = format!(
        "{}/tests/fixtures/review/{dir}/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let der = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    Certificate::from_der(&der).unwrap_or_else(|e| panic!("bad DER {path}: {e}"))
}

fn root() -> TrustAnchor {
    TrustAnchor::try_from(load("nc", "root.der")).expect("anchor")
}

/// Two ~50 KB certs, each with issuer == subject == one RDN of 1000
/// BMPString CN AVAs (distinct serials). Nothing here is signed by a
/// trusted key and no anchor name matches; a validator should reject with
/// `NoTrustedPath` almost immediately.
///
/// `check_inputs` runs `names_match` over every chain pair,
/// `validate_path` runs it again per cert for the self-issued count, and
/// `names_match` is O(AVAs^2) per RDN. All of this precedes any signature
/// verification, so an unauthenticated peer controls it. `names_match` now
/// refuses RDNs above `pkix_path::MAX_AVAS_PER_RDN` and no longer allocates
/// per comparison.
#[test]
fn review_dos_wide_rdn_names_match_is_quadratic_pre_signature() {
    let chain: Vec<Certificate> = (0..2)
        .map(|k| load("dos", &format!("dn_wide_rdn_{k}.der")))
        .collect();
    let start = Instant::now();
    let res = pkix_path::validate_path(
        &chain,
        &[root()],
        &ValidationPolicy::new(NOW),
        &DefaultVerifier,
    );
    let elapsed = start.elapsed();
    assert!(res.is_err());
    assert!(
        elapsed < Duration::from_secs(2),
        "unauthenticated 2-cert chain took {elapsed:?} to reject ({res:?})"
    );
}

fn wide_name(n: usize) -> x509_cert::name::Name {
    use core::str::FromStr as _;
    let s: Vec<String> = (0..n).map(|i| format!("CN=v{i:04}")).collect();
    x509_cert::name::Name::from_str(&s.join("+")).expect("name")
}

/// The cap is inclusive: an RDN of exactly `MAX_AVAS_PER_RDN` AVAs still
/// compares normally, one more never matches (not even itself).
#[test]
fn review_dos_names_match_ava_cap_boundary() {
    let at_cap = wide_name(pkix_path::MAX_AVAS_PER_RDN);
    assert!(pkix_path::names_match(&at_cap, &at_cap.clone()));
    let over = wide_name(pkix_path::MAX_AVAS_PER_RDN + 1);
    assert!(!pkix_path::names_match(&over, &over.clone()));
    // Ordinary multi-valued RDNs are unaffected and order-independent.
    use core::str::FromStr as _;
    let a = x509_cert::name::Name::from_str("CN=Alice+OU=Eng,O=Example").unwrap();
    let b = x509_cert::name::Name::from_str("OU=eng+CN=alice,O=example").unwrap();
    assert!(pkix_path::names_match(&a, &b));
}
