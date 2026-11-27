//! The search's own bookkeeping: duplicate suppression, candidate
//! ranking, the depth bound, and what `NoValidPath` carries.
//!
//! These decide how much work the builder does and in what order, not
//! whether a chain is accepted -- `validate_path` decides that. They are
//! still worth pinning: a pool is attacker-influenced in the general
//! case (a server sends the intermediates), so duplicate suppression and
//! the depth bound are what stand between a hostile bundle and an
//! exponential search, and the ranking is what makes the common case
//! terminate on its first candidate.
//!
//! Fixtures: PKITS, through `pkix-path`'s tree.

use pkix_path::{DefaultVerifier, TrustAnchor, ValidationPolicy};
use pkix_path_builder::{
    build_first_valid_path, build_path_candidates, build_path_candidates_with_config, CertPool,
    Error, PathBuilderConfig,
};
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

/// 2020-01-26, inside the PKITS validity window.
const PKITS_NOW: u64 = 1_580_000_000;

fn pkits_cert(name: &str) -> Certificate {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../pkix-path/tests/pkits/certs")
        .join(format!("{name}.crt"));
    let der = std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
    Certificate::from_der(&der).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

fn anchor() -> TrustAnchor {
    TrustAnchor::from(&pkits_cert("TrustAnchorRootCertificate"))
}

/// The same certificate twice in a pool yields no extra candidates.
///
/// A pool is whatever the peer sent, so an identical intermediate
/// repeated N times must not multiply the search. `mark_duplicates`
/// groups the pool by signature bytes and marks every entry that an
/// identical earlier entry already covers; `rank_candidates` then skips
/// the marked ones.
///
/// Two of its steps had no test. Advancing the run boundary on *equal*
/// signatures rather than differing ones, or requiring the earlier
/// duplicate to be marked before marking this one, both leave every copy
/// unmarked -- and then a pool holding the same intermediate ten times
/// explores ten identical subtrees.
#[test]
fn duplicate_pool_entries_do_not_multiply_the_search() {
    let ee = pkits_cert("ValidCertificatePathTest1EE");
    let intermediate = pkits_cert("GoodCACert");
    let anchors = [anchor()];

    let mut once = CertPool::new();
    once.add(intermediate.clone());
    let baseline = build_path_candidates(&ee, &once, &anchors)
        .filter_map(Result::ok)
        .count();
    assert!(baseline >= 1, "the single-copy pool yields a path");

    let mut many = CertPool::new();
    for _ in 0..6 {
        many.add(intermediate.clone());
    }
    assert_eq!(many.len(), 6, "six identical certificates");
    let with_duplicates = build_path_candidates(&ee, &many, &anchors)
        .filter_map(Result::ok)
        .count();

    assert_eq!(
        with_duplicates, baseline,
        "six copies of one intermediate must explore what one copy does"
    );
}

/// A candidate that reaches an anchor is ranked ahead of one that does
/// not.
///
/// `rank_candidates` sorts on `(tier, !reaches_anchor)`, so among
/// equally-keyed candidates the ones whose issuer is an anchor come
/// first. Dropping the negation reverses that: the candidate that
/// terminates the chain is tried last, and the search walks the rest of
/// the pool before finding what was in front of it.
///
/// Observable as which chain is yielded first. `GoodCACert` is issued by
/// the anchor; `GoodsubCACert` is issued by `GoodCACert` and reaches the
/// anchor only through it, so a pool holding both has one anchor-issued
/// candidate and one that is not.
#[test]
fn an_anchor_issued_candidate_is_tried_first() {
    let ee = pkits_cert("ValidCertificatePathTest1EE");
    let anchors = [anchor()];

    let mut pool = CertPool::new();
    // Order in the pool deliberately puts the anchor-issued candidate
    // second, so first-yielded reflects the ranking and not the input
    // order.
    pool.add(pkits_cert("GoodsubCACert"));
    pool.add(pkits_cert("GoodCACert"));

    let first = build_path_candidates(&ee, &pool, &anchors)
        .filter_map(Result::ok)
        .next()
        .expect("a candidate path exists");
    assert_eq!(
        first.len(),
        2,
        "the shortest route is leaf + anchor-issued CA; got {} certificates",
        first.len()
    );
    assert_eq!(
        first[1],
        pkits_cert("GoodCACert"),
        "the anchor-issued candidate is the one tried first"
    );
}

/// The depth bound admits a chain at the limit and refuses one past it.
///
/// `max_depth` counts intermediates, and the frame stack runs to
/// `max_depth + 1` so the deepest frame can still perform its anchor
/// check. The comparison that decides when to stop descending is
/// `frames.len() > max_depth`; read as `>=`, a chain needing exactly
/// `max_depth` intermediates is refused, and the bound then means one
/// less than it says.
#[test]
fn the_depth_bound_is_inclusive_at_the_limit() {
    let ee = pkits_cert("ValidCertificatePathTest1EE");
    let anchors = [anchor()];
    let mut pool = CertPool::new();
    pool.add(pkits_cert("GoodCACert"));

    // `PathBuilderConfig` is #[non_exhaustive], so it is built and then
    // adjusted rather than struct-literal'd.
    let mut at_limit = PathBuilderConfig::new();
    at_limit.max_depth = 1;
    let found = build_path_candidates_with_config(&ee, &pool, &anchors, &at_limit)
        .filter_map(Result::ok)
        .count();
    assert!(
        found >= 1,
        "one intermediate is within max_depth = 1, so the chain must be found"
    );

    let mut below_limit = PathBuilderConfig::new();
    below_limit.max_depth = 0;
    let none = build_path_candidates_with_config(&ee, &pool, &anchors, &below_limit)
        .filter_map(Result::ok)
        .count();
    assert_eq!(
        none, 0,
        "max_depth = 0 admits no intermediate, so there is no chain to find"
    );
}

/// `NoValidPath` exposes the validation error that explains it.
///
/// The variant exists to say *why* the candidates it tried were refused;
/// its `Display` interpolates the inner error, and `source` must hand it
/// out so a chained report reaches it too. Answering `None` leaves a
/// caller walking the chain with nothing underneath "none validated".
#[test]
fn no_valid_path_exposes_its_last_validation_error() {
    use std::error::Error as _;

    let ee = pkits_cert("InvalidCASignatureTest2EE");
    let mut pool = CertPool::new();
    pool.add(pkits_cert("BadSignedCACert"));
    let anchors = [anchor()];
    let policy = ValidationPolicy::new(PKITS_NOW);

    let err = build_first_valid_path(&ee, &pool, &anchors, &policy, &DefaultVerifier)
        .expect_err("PKITS 4.1.2: the CA's own signature does not verify");
    let Error::NoValidPath { last_error, .. } = &err else {
        panic!("expected NoValidPath, got {err:?}");
    };
    assert!(
        matches!(last_error, pkix_path::Error::SignatureInvalid { .. }),
        "the reason is a bad signature; got {last_error:?}"
    );
    let source = err.source().expect("NoValidPath carries a cause");
    assert_eq!(
        format!("{source}"),
        format!("{last_error}"),
        "and source hands out that same error"
    );
}

/// `NoValidPath.tried` counts the candidates that were validated and
/// refused.
///
/// The count matters because it separates two situations a caller acts
/// on differently: the search found nothing to try, and the search tried
/// things that all failed. `tried: 0` with a validation error cannot
/// happen through the counting path -- that combination is reported by a
/// separate fallback, which validates one topological candidate so a
/// caller learns *why* rather than only that nothing was found.
///
/// So this needs a chain whose signatures verify -- otherwise the
/// iterator prunes it and the fallback answers instead -- and which
/// `validate_path` then refuses for some other reason. PKITS 4.2.1 is
/// that: `BadnotBeforeDateCACert` is properly signed by the anchor and
/// its validity period has not begun.
///
/// With the increment read as `*=` the count stays 0 and the two
/// situations become indistinguishable; read as `-=` it underflows.
#[test]
fn no_valid_path_counts_the_candidates_it_refused() {
    let ee = pkits_cert("InvalidCAnotBeforeDateTest1EE");
    let mut pool = CertPool::new();
    pool.add(pkits_cert("BadnotBeforeDateCACert"));
    let anchors = [anchor()];
    let policy = ValidationPolicy::new(PKITS_NOW);

    // Premise: the signatures verify, so the verifier-aware search
    // yields this chain rather than pruning it.
    let yielded = build_path_candidates(&ee, &pool, &anchors)
        .filter_map(Result::ok)
        .count();
    assert_eq!(yielded, 1, "exactly one topological candidate");

    let err = build_first_valid_path(&ee, &pool, &anchors, &policy, &DefaultVerifier)
        .expect_err("PKITS 4.2.1: the CA's validity period has not begun");
    let Error::NoValidPath {
        tried, last_error, ..
    } = &err
    else {
        panic!("expected NoValidPath, got {err:?}");
    };
    assert_eq!(
        *tried, 1,
        "one candidate was validated and refused, so the count is one"
    );
    assert!(
        matches!(last_error, pkix_path::Error::ValidityPeriod { .. }),
        "refused for its validity period, not its signature; got {last_error:?}"
    );
}

/// With two certificates for one CA, the anchor-issued one is tried
/// first.
///
/// `rank_candidates` sorts on `(tier, !reaches_anchor)` so that, in a
/// signature-checked search, a candidate whose own issuer is an anchor
/// comes before one that reaches the anchor through further
/// certificates. The rustdoc's reason is that the common case should
/// terminate on its first candidate.
///
/// Nothing tested it: `reaches_anchor` is only computed for
/// signature-checked searches, so a no-verifier search leaves it false
/// for every candidate and the negation decides nothing. And no fixture
/// gave a leaf two candidate issuers to sort -- a single-element sort is
/// the same in any order.
///
/// A cross-certified CA is the ordinary shape that produces two:
/// `ca-x-by-root` and `ca-x-by-other` name the same CA and carry the same
/// key, so both verify the leaf and both routes validate. They differ in
/// length, which is how the ordering shows. Dropping the negation
/// returns the three-certificate route through the second authority
/// when a two-certificate route to the anchor was available.
#[test]
fn the_anchor_issued_certificate_of_a_cross_certified_ca_wins() {
    fn cross(name: &str) -> Certificate {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/cross-certified")
            .join(format!("{name}.der"));
        let der = std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
        Certificate::from_der(&der).unwrap_or_else(|e| panic!("parse {name}: {e}"))
    }

    let leaf = cross("leaf");
    let anchors = [TrustAnchor::from(&cross("root"))];
    // 2030-01-01, inside the fixtures' window.
    let policy = ValidationPolicy::new(1_893_456_000);

    let mut pool = CertPool::new();
    // The longer route first in the pool, so what comes back reflects the
    // ranking rather than the input order.
    pool.add(cross("ca-x-by-other"));
    pool.add(cross("other-ca"));
    pool.add(cross("ca-x-by-root"));

    let path = build_first_valid_path(&leaf, &pool, &anchors, &policy, &DefaultVerifier)
        .expect("both routes validate, so one of them is returned");
    assert_eq!(
        path.len(),
        2,
        "the anchor-issued certificate gives [leaf, CA X]; got {} certificates",
        path.len()
    );
    assert_eq!(
        path[1],
        cross("ca-x-by-root"),
        "and it is the one the anchor issued"
    );

    // Both routes really do validate, so the assertion above is about
    // the order and not about one of them being refused.
    let long = vec![leaf.clone(), cross("ca-x-by-other"), cross("other-ca")];
    pkix_path::validate_path(&long, &anchors, &policy, &DefaultVerifier)
        .expect("the route through the second authority is valid too");
}
