//! Integration tests for `pkix_difftest::corpus::pkits` (PKIX-7nsf.4).
//!
//! Independent oracle: PKITS itself.
//! - `vectors.json` is a fixed manifest committed under
//!   `pkix-path/tests/pkits/`. The schema has 8 fields; every entry has all
//!   8 (verified during PKIX-7nsf.4 explore). 249 entries total.
//! - Every cert filename in any `CertPath` is expected to resolve to a file
//!   under `pkix-path/tests/pkits/certs/`. Verified by the explore.
//! - These tests assert structural properties of the corpus loader (every
//!   entry resolves; the count matches the manifest; ground-truth verdicts
//!   are emitted) without using `pkix-path` itself as the oracle.

use std::path::PathBuf;

use pkix_difftest::corpus::pkits::PkitsCorpus;
use pkix_difftest::corpus::Corpus;
use pkix_difftest::Verdict;

fn pkits_root() -> PathBuf {
    // PKITS lives under pkix-path's tests dir at the workspace root.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("pkix-path/tests/pkits")
}

#[test]
fn pkits_loads_all_249_vectors() {
    let corpus = PkitsCorpus::load(pkits_root()).expect("load PKITS manifest");
    assert_eq!(
        corpus.len(),
        249,
        "PKITS vectors.json shipped with this project has 249 entries; got {}",
        corpus.len()
    );
}

#[test]
fn pkits_iterator_yields_a_chain_for_every_vector() {
    let corpus = PkitsCorpus::load(pkits_root()).expect("load");
    let mut ok = 0usize;
    let mut errs: Vec<String> = Vec::new();
    for item in corpus.iter() {
        match item {
            Ok(it) => {
                assert!(
                    it.chain.certs_der.len() >= 2,
                    "{}: chain too short ({})",
                    it.name,
                    it.chain.certs_der.len()
                );
                ok += 1;
            }
            Err(e) => errs.push(e.to_string()),
        }
    }
    assert!(
        errs.is_empty(),
        "every PKITS vector must resolve cleanly; got {} errors. First: {:?}",
        errs.len(),
        errs.first()
    );
    assert_eq!(ok, 249);
}

#[test]
fn pkits_ground_truth_round_trip_for_first_two_known_entries() {
    let corpus = PkitsCorpus::load(pkits_root()).expect("load");
    let first_two: Vec<_> = corpus.iter().take(2).collect();
    let names: Vec<_> = first_two
        .iter()
        .map(|r| r.as_ref().expect("ok").name.clone())
        .collect();
    // PKITS 4.1.1 is "Valid Signatures Test1" (ShouldValidate: true).
    // PKITS 4.1.2 is "Invalid CA Signature Test2" (ShouldValidate: false).
    // Both names are stable across PKITS releases.
    assert_eq!(names[0], "4.1.1 Valid Signatures Test1");
    assert_eq!(names[1], "4.1.2 Invalid CA Signature Test2");

    let v1 = first_two[0].as_ref().unwrap().expected.clone().unwrap();
    let v2 = first_two[1].as_ref().unwrap().expected.clone().unwrap();
    assert_eq!(v1, Verdict::Pass);
    assert!(matches!(v2, Verdict::Fail { .. }));
}

#[test]
fn pkits_load_errors_on_missing_directory() {
    let err = PkitsCorpus::load("/nonexistent/path/for/pkits").unwrap_err();
    assert!(
        err.to_string().contains("PKITS corpus") || err.kind() == std::io::ErrorKind::NotFound,
        "expected useful error message; got: {err}"
    );
}
