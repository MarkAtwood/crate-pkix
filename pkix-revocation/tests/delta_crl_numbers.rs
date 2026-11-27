//! RFC 5280 §5.2.4: a delta CRL names the base it updates, and the pair has
//! to agree.
//!
//! `CrlChecker::with_delta` refuses a delta that expects a base newer than
//! the one supplied -- `delta_base_num > base_num`. The existing
//! `delta-crl-*` fixtures are a matching pair, base `cRLNumber` 1 against
//! delta `BaseCRLNumber` 1, which satisfies the comparison without telling
//! it apart from any other: every mutant in the three functions that read
//! these numbers survived. `uint_to_u64` could return a constant,
//! `crl_number` could return `None` and skip the comparison entirely, and a
//! delta expecting a newer base would have been applied to an older one.
//!
//! Fixture rationale: `tests/fixtures/delta-crl-numbers/gen.py`.

#![cfg(feature = "crl")]

use pkix_path::DefaultVerifier;
use pkix_revocation::{CrlChecker, Error};

const NOW: u64 = 1_780_272_000;
const DIR: &str = "tests/fixtures/delta-crl-numbers";

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(DIR)
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn pair(base: &str, delta: &str) -> Result<CrlChecker<DefaultVerifier>, Error> {
    CrlChecker::with_delta(fixture(base), fixture(delta), NOW, DefaultVerifier)
}

/// A delta expecting an older base than the one supplied is fine: the base
/// is at least as current as the delta assumes.
///
/// The numbers are 3 against 5 rather than 1 against 1, so a comparison
/// against a constant does not pass by coincidence.
#[test]
fn a_delta_expecting_an_older_base_is_accepted() {
    pair("base-5.der", "delta-base-3.der")
        .expect("BaseCRLNumber 3 against cRLNumber 5 is a usable pair");
}

/// A delta expecting a newer base than the one supplied is refused.
///
/// This is the direction that matters. Applying a delta to a base older
/// than it was built against means the revocations between the two CRL
/// numbers appear in neither: the base predates them and the delta assumes
/// they are already there.
#[test]
fn a_delta_expecting_a_newer_base_is_refused() {
    let r = pair("base-5.der", "delta-base-9.der");
    assert!(
        matches!(r, Err(Error::CrlNumberMismatch)),
        "BaseCRLNumber 9 against cRLNumber 5 must be refused, got: {r:?}"
    );
}

/// A `cRLNumber` that fills a `u64` exactly is still read.
///
/// `uint_to_u64` refuses an INTEGER longer than eight bytes, and DER strips
/// leading zeros, so 2^56 is the smallest value whose encoding reaches eight
/// -- the last one that fits. Every number in the other fixtures is one byte
/// long, so the boundary went untested in both directions.
#[test]
fn an_eight_byte_crl_number_still_fits() {
    pair("base-2pow56.der", "delta-base-1.der")
        .expect("2^56 encodes in eight bytes, which is what a u64 holds");
}

/// And one that does not fit is a parse error, not a skipped comparison.
///
/// The rustdoc on `crl_number` is explicit: a `cRLNumber` above 2^64 is
/// implausible in any deployed PKI "but must not silently disable the
/// staleness check". Returning `None` there would read as "this CRL has no
/// number", which is the signal for the extension being absent, and the
/// comparison would be skipped.
#[test]
fn a_crl_number_too_large_for_a_u64_is_a_parse_error() {
    let r = pair("base-2pow64.der", "delta-base-1.der");
    assert!(
        matches!(r, Err(Error::CrlParseError(_))),
        "2^64 does not fit a u64 and must not pass as an absent number, got: {r:?}"
    );
}
