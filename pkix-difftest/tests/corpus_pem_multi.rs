//! Integration tests for `pkix_difftest::corpus::pem_multi` (PKIX-7nsf.4).
//!
//! Independent oracles: structural assertions (file count, ordering
//! normalisation) only. Verdict correctness for the embedded chain is
//! covered by PKIX-7nsf.1's smoke tests.

use std::fs;
use std::path::PathBuf;

use pkix_difftest::corpus::pem_multi::PemMultiCorpus;
use pkix_difftest::corpus::Corpus;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

#[test]
fn pem_multi_loads_chain_from_pem_files() {
    // Split the 3-cert good-chain.pem into three individual PEM files in a
    // tempdir, then ask PemMultiCorpus to reassemble them.
    let bytes = fs::read(fixtures_dir().join("good-chain.pem")).unwrap();
    let pem_text = std::str::from_utf8(&bytes).unwrap();
    let blocks: Vec<&str> = pem_text
        .split("-----END CERTIFICATE-----")
        .filter(|s| s.contains("-----BEGIN"))
        .collect();
    assert_eq!(blocks.len(), 3, "fixture should split into 3 blocks");

    let tmp = tempfile::TempDir::new().unwrap();
    let mut paths = Vec::new();
    for (i, block) in blocks.iter().enumerate() {
        let path = tmp.path().join(format!("cert-{i}.pem"));
        fs::write(&path, format!("{block}-----END CERTIFICATE-----\n")).unwrap();
        paths.push(path);
    }

    let corpus = PemMultiCorpus::new(paths, "test-multi");
    let item = corpus
        .iter()
        .next()
        .expect("one chain")
        .expect("chain loads cleanly");
    assert_eq!(item.name, "test-multi");
    assert_eq!(item.chain.certs_der.len(), 3);
    assert!(item.chain.root_in_chain);
    assert!(item.expected.is_none(), "pem-multi has no ground truth");
}

#[test]
fn pem_multi_loads_chain_from_der_files() {
    // The pem-multi loader auto-detects DER vs PEM. Use the raw .crt files
    // shipped with PKITS (which are DER) and confirm they get assembled.
    let pkits_certs = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("pkix-path/tests/pkits/certs");

    let paths = vec![
        pkits_certs.join("ValidCertificatePathTest1EE.crt"),
        pkits_certs.join("GoodCACert.crt"),
        pkits_certs.join("TrustAnchorRootCertificate.crt"),
    ];

    let corpus = PemMultiCorpus::new(paths, "der-mixed");
    let item = corpus
        .iter()
        .next()
        .expect("one chain")
        .expect("chain loads cleanly");
    assert_eq!(item.chain.certs_der.len(), 3);
}

#[test]
fn pem_multi_iterator_is_exhausted_after_one_call() {
    let tmp = tempfile::TempDir::new().unwrap();
    let p = tmp.path().join("cert.pem");
    fs::copy(fixtures_dir().join("good-chain.pem"), &p).unwrap();
    let corpus = PemMultiCorpus::new(vec![p], "single");
    let mut iter = corpus.iter();
    assert!(iter.next().is_some(), "first call yields the chain");
    assert!(
        iter.next().is_none(),
        "iterator is exhausted after one call"
    );
}

#[test]
fn pem_multi_errors_on_empty_path_list() {
    let corpus = PemMultiCorpus::new(vec![], "empty");
    let result = corpus.iter().next().expect("yields an io::Result");
    assert!(
        result.is_err(),
        "empty path list must surface as an error, not an empty stream"
    );
}
