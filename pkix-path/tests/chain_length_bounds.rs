//! The two length bounds in `validate_path`, told apart.
//!
//! RFC 5280 §4.2.1.9 counts only non-self-issued intermediates against
//! `pathLenConstraint`, so a chain may legitimately be longer than
//! `max_path_len` suggests: a CA re-certifying itself under a new key adds
//! a certificate that costs nothing against the limit. `validate_path`
//! applies a cheap bound on `chain.len()` first -- `2 * max_path_len + 3`
//! -- and the §4.2.1.9 count after.
//!
//! Both report `Error::PathTooLong`, so a chain refused by the second says
//! nothing about the first, and every chain in the suite is refused by the
//! second or well inside both. Separating them needs a chain whose length
//! sits at the cheap bound while its non-self-issued count stays inside
//! §4.2.1.9's, which means self-issued padding -- and nothing had any.
//!
//! Fixture rationale: `tests/fixtures/chain-length/gen.py`.

use pkix_path::{validate_path, DefaultVerifier, Error, TrustAnchor, ValidationPolicy};
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

const NOW: u64 = 1_600_000_000; // 2020-09-13, inside the fixtures' window
const DIR: &str = "tests/fixtures/chain-length";

fn load(name: &str) -> Certificate {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(DIR)
        .join(name);
    let der = std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
    Certificate::from_der(&der).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

/// `chain` is leaf-first. `max_path_len` is the policy cap; every CA in the
/// fixtures is unconstrained by its own basicConstraints, so this is the
/// only limit in play.
fn run(chain: &[&str], max_path_len: u8) -> pkix_path::Result<pkix_path::ValidatedPath> {
    let certs: Vec<Certificate> = chain.iter().map(|n| load(n)).collect();
    let anchors = [TrustAnchor::from_cert(load("root.der"))];
    let mut policy = ValidationPolicy::new(NOW);
    policy.max_path_len = max_path_len;
    validate_path(&certs, &anchors, &policy, &DefaultVerifier)
}

/// Five certificates at `max_path_len = 1`: exactly the cheap bound, and
/// one non-self-issued intermediate.
///
/// This is the case that distinguishes the bound from an off-by-one in it,
/// and the arithmetic producing it from two plausible misreadings --
/// `2 * n + 3` read as `2 * n * 3` or as `2 + n + 3` both move the bound
/// to six, which this chain would also satisfy, so it is paired with the
/// six-certificate case below.
///
/// It also pins the §4.2.1.9 count: one non-self-issued intermediate
/// against a limit of one must pass, and `>` read as `>=` refuses it.
#[test]
fn a_chain_exactly_at_the_cheap_bound_validates() {
    run(&["leaf5.der", "si3.der", "si2.der", "si1.der", "ca.der"], 1)
        .expect("five certificates is 2 * 1 + 3, and only `ca` is non-self-issued");
}

/// Six certificates at the same `max_path_len` is one past the bound.
///
/// The §4.2.1.9 count is still one, so this refusal can only come from the
/// cheap bound -- which is what makes it a statement about the arithmetic.
#[test]
fn a_chain_one_past_the_cheap_bound_is_refused() {
    let r = run(
        &[
            "leaf6.der",
            "si4.der",
            "si3.der",
            "si2.der",
            "si1.der",
            "ca.der",
        ],
        1,
    );
    assert!(
        matches!(r, Err(Error::PathTooLong)),
        "six certificates exceeds 2 * 1 + 3, got: {r:?}"
    );
}

/// The §4.2.1.9 count on its own, with length to spare.
///
/// At `max_path_len = 0` the five-certificate chain is past the cheap bound
/// too, so this uses the three-certificate form: one non-self-issued
/// intermediate against a limit of zero.
#[test]
fn one_non_self_issued_intermediate_exceeds_a_limit_of_zero() {
    let r = run(&["leaf5.der", "si3.der", "si2.der", "si1.der", "ca.der"], 0);
    assert!(
        matches!(r, Err(Error::PathTooLong)),
        "`ca` is a non-self-issued intermediate and the limit is zero, got: {r:?}"
    );
}
