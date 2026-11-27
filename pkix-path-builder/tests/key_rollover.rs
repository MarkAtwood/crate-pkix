//! Key rollover: a self-issued CA directly under a same-name trust anchor.
//!
//! `pkix-path` covers this for `validate_path` in
//! `tests/review_self_issued_rollover.rs` (GitHub issue #11). This file
//! covers the *builder* half, which is a separate question: `validate_path`
//! is handed a chain, while the builder has to construct one, and the
//! correct chain here is not the shortest one.
//!
//! Fixtures are pkix-path's, not copies — a second copy would drift, and
//! the point is that both halves agree about the same bytes.
//!
//! Why this needed its own file: the builder's support for this topology
//! arrived with candidate iteration (PKIX-lwr9.4.1) and had no test of its
//! own. `pkix-difftest/baseline-limbo-analysis.md` still described the
//! builder as unable to do it, because the limbo corpus is out of tree and
//! the baseline was never re-run — so the only statement anywhere about
//! this behaviour was a stale one saying it did not work. PKIX-xj81.3.

use der::Decode as _;
use pkix_path::{DefaultVerifier, TrustAnchor, ValidationPolicy};
use pkix_path_builder::{build_first_valid_path, CertPool, Error};
use x509_cert::Certificate;

const NOW: u64 = 1_798_761_600; // 2027-01-01T00:00:00Z

fn load(name: &str) -> Certificate {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../pkix-path/tests/fixtures/review/self-issued-rollover")
        .join(format!("{name}.der"));
    Certificate::from_der(&std::fs::read(&p).expect("fixture present")).expect("fixture parses")
}

fn pool_with_ica() -> CertPool {
    let mut pool = CertPool::new();
    pool.add(load("ica"));
    pool
}

fn anchors(names: &[&str]) -> Vec<TrustAnchor> {
    names
        .iter()
        .map(|n| TrustAnchor::from_cert(load(n)))
        .collect()
}

/// The builder constructs the rollover chain under a same-name anchor.
///
/// The leaf is signed with the new key while the anchor holds the old one,
/// so the only chain that can verify is `[leaf, ica]`. What this pins is
/// that the builder finds it at all: the rollover CA shares the anchor's
/// subject name, and a builder that treated "same name as an anchor" as
/// "stop here" would never reach it.
///
/// What it does NOT pin, despite an earlier name of mine claiming
/// otherwise ("…not just the shortest one"): candidate *iteration*.
/// `build_path_candidates` does yield a one-certificate candidate, but
/// `build_first_valid_path` constructs its iterator with a verifier, which
/// filters signature-inconsistent chains before `validate_path` ever sees
/// them — so the short candidate is never offered and there is nothing to
/// iterate past. Mutating the loop to give up after its first failure
/// leaves this test green, which is how the false claim was caught.
#[test]
fn the_rollover_chain_is_built_under_a_same_name_anchor() {
    let leaf = load("leaf");
    let pool = pool_with_ica();
    let anchors = anchors(&["root"]);
    let policy = ValidationPolicy::new(NOW);

    let path = build_first_valid_path(&leaf, &pool, &anchors, &policy, &DefaultVerifier)
        .expect("the rollover chain validates");
    assert_eq!(path.len(), 2, "[leaf, ica] — not [leaf] under the anchor");

    // And it agrees with the half pkix-path already tests.
    pkix_path::validate_path(&path, &anchors, &policy, &DefaultVerifier)
        .expect("the built path validates as a path");
}

/// Positive control: the rollover CA is what makes the chain work.
///
/// Without this, the test above would pass just as well if the builder were
/// somehow validating the leaf directly under the anchor — the assertion on
/// length says the result has two certificates, not that the second one is
/// load-bearing.
#[test]
fn without_the_rollover_ca_there_is_no_path() {
    let leaf = load("leaf");
    let empty = CertPool::new();
    let policy = ValidationPolicy::new(NOW);

    let err = build_first_valid_path(
        &leaf,
        &empty,
        &anchors(&["root"]),
        &policy,
        &DefaultVerifier,
    )
    .expect_err("the leaf is signed with the new key, which the anchor is not");
    // Exactly this, not an alternation: with no rollover CA the builder
    // still offers the one-certificate candidate — leaf directly under the
    // anchor — and it fails on the signature, because the leaf was signed
    // with the new key. `NoPathFound` would mean the builder found nothing
    // to try, which is a different and weaker statement.
    assert!(
        matches!(
            err,
            Error::NoValidPath {
                tried: 1,
                last_error: pkix_path::Error::SignatureInvalid { .. },
                ..
            }
        ),
        "expected one tried candidate failing on the signature, got {err:?}"
    );
}

/// A same-name anchor with an unrelated key yields no path.
///
/// The security half: "same subject as the anchor" must not be mistaken for
/// "issued by the anchor". Without the signature check, the forged root
/// would look exactly as good as the real one.
///
/// Two independent layers enforce this, and this test is satisfied by
/// either: the candidate iterator's `signed_by` filter, and
/// `validate_path` itself. Mutating out either one alone leaves this
/// green. That is defence in depth rather than a weak assertion, but it
/// does mean this test does not localise a regression to one of them.
#[test]
fn a_forged_same_name_anchor_yields_no_path() {
    let leaf = load("leaf");
    let pool = pool_with_ica();
    let policy = ValidationPolicy::new(NOW);

    let err = build_first_valid_path(
        &leaf,
        &pool,
        &anchors(&["forged-root"]),
        &policy,
        &DefaultVerifier,
    )
    .expect_err("an unrelated key must not anchor this chain");

    assert!(
        matches!(err, Error::NoValidPath { .. }),
        "expected NoValidPath, got {err:?}"
    );
}

/// A forged anchor listed first does not mask the real one.
///
/// Key-rollover trust stores legitimately hold several same-name anchors,
/// so the builder cannot stop at the first subject-name match.
#[test]
fn a_forged_anchor_listed_first_does_not_mask_the_real_one() {
    let leaf = load("leaf");
    let pool = pool_with_ica();
    let policy = ValidationPolicy::new(NOW);

    let path = build_first_valid_path(
        &leaf,
        &pool,
        &anchors(&["forged-root", "root"]),
        &policy,
        &DefaultVerifier,
    )
    .expect("the second anchor signs the rollover CA");
    assert_eq!(path.len(), 2);
}
