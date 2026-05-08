//! Integration tests for `pkix_difftest::corpus::pem_tree` (PKIX-7nsf.4).
//!
//! Independent oracles: every assertion here is about *structural properties*
//! of the loader (file discovery, ordering normalisation, non-cert filtering)
//! rather than about path validation verdicts. The fixture chains are
//! borrowed from PKIX-7nsf.1 and were validated against PKITS ground truth
//! and OpenSSL there.

use std::fs;
use std::path::PathBuf;

use pkix_difftest::corpus::pem_tree::PemTreeCorpus;
use pkix_difftest::corpus::Corpus;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

#[test]
fn pem_tree_finds_chain_pem_in_subdirectory() {
    // Build a temp tree like:
    //   <tmp>/case-a/chain.pem  ← good fixture (copied)
    //   <tmp>/case-b/chain.pem  ← bad fixture (copied)
    //   <tmp>/extra/notes.txt   ← ignored
    let tmp = tempfile::TempDir::new().unwrap();
    let case_a = tmp.path().join("case-a");
    let case_b = tmp.path().join("case-b");
    let extra = tmp.path().join("extra");
    fs::create_dir(&case_a).unwrap();
    fs::create_dir(&case_b).unwrap();
    fs::create_dir(&extra).unwrap();
    fs::copy(
        fixtures_dir().join("good-chain.pem"),
        case_a.join("chain.pem"),
    )
    .unwrap();
    fs::copy(
        fixtures_dir().join("bad-chain.pem"),
        case_b.join("chain.pem"),
    )
    .unwrap();
    fs::write(extra.join("notes.txt"), "ignore me").unwrap();

    let corpus = PemTreeCorpus::load(tmp.path()).expect("load tree");
    assert_eq!(
        corpus.len(),
        2,
        "expected exactly 2 chain.pem files, got {}",
        corpus.len()
    );

    let mut names: Vec<String> = corpus.iter().map(|r| r.unwrap().name).collect();
    names.sort();
    // Names are root-relative paths.
    assert_eq!(
        names,
        vec![
            "case-a/chain.pem".to_string(),
            "case-b/chain.pem".to_string()
        ]
    );
}

#[test]
fn pem_tree_filters_non_cert_blocks_silently() {
    // chain.pem with a private key block mixed in. The PEM-tree loader
    // should drop the key and load the certs. (This is the policy that
    // distinguishes corpus-walking from the strict CLI single-chain loader.)
    let tmp = tempfile::TempDir::new().unwrap();
    let case = tmp.path().join("with-key");
    fs::create_dir(&case).unwrap();

    let mut bytes = fs::read(fixtures_dir().join("good-chain.pem")).unwrap();
    bytes.extend_from_slice(
        b"\n-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n",
    );
    fs::write(case.join("chain.pem"), bytes).unwrap();

    let corpus = PemTreeCorpus::load(tmp.path()).unwrap();
    let mut iter = corpus.iter();
    let item = iter
        .next()
        .expect("one item")
        .expect("loads despite key block");
    assert_eq!(
        item.chain.certs_der.len(),
        3,
        "the 3 certs from good-chain are preserved"
    );
    assert!(item.expected.is_none(), "PEM-tree provides no ground truth");
}

#[test]
fn pem_tree_load_errors_on_missing_root() {
    let err = PemTreeCorpus::load("/nonexistent/pem/tree").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn pem_tree_returns_empty_when_no_chain_files_present() {
    let tmp = tempfile::TempDir::new().unwrap();
    fs::write(tmp.path().join("readme.txt"), "no chains here").unwrap();
    let corpus = PemTreeCorpus::load(tmp.path()).expect("load");
    assert_eq!(corpus.len(), 0);
    assert!(corpus.iter().next().is_none());
}

#[test]
fn pem_tree_iteration_order_is_deterministic() {
    // The walker sorts paths so reports are diff-friendly. Confirm that two
    // independent walks of the same tree produce identically-ordered name
    // lists.
    let tmp = tempfile::TempDir::new().unwrap();
    for sub in ["c", "a", "b"] {
        let dir = tmp.path().join(sub);
        fs::create_dir(&dir).unwrap();
        fs::copy(fixtures_dir().join("good-chain.pem"), dir.join("chain.pem")).unwrap();
    }
    let names_a: Vec<String> = PemTreeCorpus::load(tmp.path())
        .unwrap()
        .iter()
        .map(|r| r.unwrap().name)
        .collect();
    let names_b: Vec<String> = PemTreeCorpus::load(tmp.path())
        .unwrap()
        .iter()
        .map(|r| r.unwrap().name)
        .collect();
    assert_eq!(names_a, names_b);
    // Sort policy is path-sorted (a, b, c) not insertion-sorted (c, a, b).
    assert_eq!(
        names_a,
        vec![
            "a/chain.pem".to_string(),
            "b/chain.pem".to_string(),
            "c/chain.pem".to_string()
        ]
    );
}
