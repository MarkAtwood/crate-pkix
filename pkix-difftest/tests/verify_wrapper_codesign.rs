//! Wrapper-level differential test for code-signing chains (PKIX-fmtv.24).
//!
//! Supersedes PKIX-fmtv.18.5 (closed: OpenSSL `verify -purpose codesign`
//! does not exist). The oracle here is a composed pyca/cryptography
//! sidecar (`pyca_codesign_oracle.py`) that decomposes the wrapper's job
//! into two independent checks that don't touch workspace code:
//!
//! 1. Chain walk via pyca's `Certificate.verify_directly_issued_by`
//!    primitive (issuer DN match + signature verification on each pair),
//!    plus validity-period overlap on every cert.
//! 2. Standalone EKU check: the leaf's `ExtendedKeyUsage` extension
//!    must contain `id-kp-codeSigning` (1.3.6.1.5.5.7.3.3). Hand-rolled
//!    extension lookup + OID comparison — not pyca's PolicyBuilder.
//!
//! Combined oracle verdict: `chain_ok AND eku_ok`. Compared to the
//! workspace's `pkix_chain::verify_code_signer(...).is_ok()`.
//!
//! See `pyca_codesign_oracle.py` rustdoc for the rationale on why the
//! oracle is composed rather than reused from the PolicyBuilder-based
//! `pyca_verify_oracle.py` (PolicyBuilder is TLS-bound; it has no
//! code-signing surface).
//!
//! ## Running
//!
//! ```sh
//! pkix-difftest/python/setup-venv.sh         # idempotent, once per checkout
//! cargo test -p pkix-difftest --test verify_wrapper_codesign -- --nocapture
//! ```
//!
//! When the venv is missing the test reports the absence and skips.

#![forbid(unsafe_code)]

use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use pkix_chain::{
    verify_code_signer, DefaultVerifier, Error, NoAiaFetcher, NoRevocation, TrustAnchor,
};
use pkix_profiles::BasicCodeSigningProfile;
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

const NOW: u64 = 1_780_272_000;

// ---------------------------------------------------------------------------
// Outcome vocabulary
// ---------------------------------------------------------------------------

/// What our Rust verifier said.
#[derive(Clone, Debug, PartialEq, Eq)]
enum RustOutcome {
    Ok,
    Path,
    Other(String),
}

impl RustOutcome {
    fn from_result<T>(r: Result<T, Error>) -> Self {
        match r {
            Ok(_) => RustOutcome::Ok,
            Err(Error::Path(_)) => RustOutcome::Path,
            Err(other) => RustOutcome::Other(format!("{other:?}")),
        }
    }

    fn is_pass(&self) -> bool {
        matches!(self, RustOutcome::Ok)
    }
}

/// What the pyca-composed oracle said.
#[derive(Clone, Debug, PartialEq, Eq)]
enum PycaOutcome {
    Pass,
    Fail(String),
}

impl PycaOutcome {
    fn is_pass(&self) -> bool {
        matches!(self, PycaOutcome::Pass)
    }
}

/// Per-case agreement classifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AgreementKind {
    Agree,
    LooserThanPyca,
    StricterThanPyca,
}

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

struct Case<'a> {
    name: &'a str,
    leaf: &'a str,
    root: &'a str,
    /// Override for `validation_time_unix`. `None` means use [`NOW`].
    validation_time: Option<u64>,
    expected_rust: RustOutcome,
}

#[rustfmt::skip]
fn cases() -> Vec<Case<'static>> {
    use RustOutcome::*;
    vec![
        // Positive: code-signing leaf + valid root + current time.
        // Mirrors `verify_code_signer_ok` in pkix-chain/tests/verify_code_signer.rs.
        Case {
            name: "positive_codesign_leaf",
            leaf: "leaf-codesigning.der",
            root: "root.der",
            validation_time: None,
            expected_rust: Ok,
        },
        // Negative: serverAuth leaf under BasicCodeSigningProfile. EKU
        // mismatch — both oracles must reject.
        // Mirrors `verify_code_signer_wrong_eku_returns_path_error`.
        Case {
            name: "negative_wrong_eku_serverauth",
            leaf: "leaf-san-www-example.der",
            root: "root.der",
            validation_time: None,
            expected_rust: Path,
        },
        // Negative: code-signing leaf evaluated before notBefore (1970).
        // Validity-period check fires; both oracles must reject.
        // Mirrors `verify_code_signer_expired_chain_returns_path_error`.
        Case {
            name: "negative_validity_period_before_notbefore",
            leaf: "leaf-codesigning.der",
            root: "root.der",
            validation_time: Some(0),
            expected_rust: Path,
        },
    ]
}

// ---------------------------------------------------------------------------
// Test driver
// ---------------------------------------------------------------------------

#[test]
fn verify_wrapper_codesign_diff() {
    let Some(python) = locate_python() else {
        eprintln!(
            "verify_wrapper_codesign_diff: skipping — no Python sidecar venv at \
             pkix-difftest/python/.venv/bin/python. Run \
             pkix-difftest/python/setup-venv.sh and re-test."
        );
        return;
    };
    let sidecar = sidecar_script_path();
    if !sidecar.exists() {
        eprintln!(
            "verify_wrapper_codesign_diff: skipping — sidecar script missing: {}",
            sidecar.display()
        );
        return;
    }

    let mut rows: Vec<Row> = Vec::new();
    for case in cases() {
        let leaf = load_fixture(case.leaf);
        let root = load_fixture(case.root);
        let anchors = [TrustAnchor::from_cert(root.clone())];
        let chain = [leaf.clone()];
        let vtime = case.validation_time.unwrap_or(NOW);

        // Rust verdict
        let rust = RustOutcome::from_result(verify_code_signer(
            &chain,
            &anchors,
            &BasicCodeSigningProfile,
            vtime,
            &DefaultVerifier,
            &NoRevocation,
            &NoAiaFetcher,
        ));
        assert_eq!(
            rust, case.expected_rust,
            "Rust outcome diverged from expectation for {} (leaf {}, root {}, time {vtime})",
            case.name, case.leaf, case.root,
        );

        // pyca verdict
        let leaf_pem = der_to_pem(leaf.to_der_bytes());
        let root_pem = der_to_pem(root.to_der_bytes());
        let spec = build_spec(&leaf_pem, &root_pem, vtime);
        let pyca = run_sidecar(&python, &sidecar, &spec)
            .expect("pyca codesign sidecar must produce a verdict for every case");
        let kind = classify(rust.is_pass(), pyca.is_pass());

        rows.push(Row {
            case: case.name.to_string(),
            leaf: case.leaf.to_string(),
            root: case.root.to_string(),
            rust: format!("{rust:?}"),
            pyca: pyca_label(&pyca),
            kind,
        });
    }

    eprintln!();
    eprintln!("=== verify_code_signer diff vs pyca composed oracle ===");
    emit_matrix(&rows);
    let summary = summarize(&rows);
    eprintln!();
    eprintln!(
        "codesign: {n} cases — {agree} agree, {looser} Rust-looser, {stricter} Rust-stricter",
        n = rows.len(),
        agree = summary.agree,
        looser = summary.looser,
        stricter = summary.stricter,
    );

    // Hard invariant: no disagreement. Both oracles independently check
    // the same chain + EKU surface that `verify_code_signer` enforces;
    // any disagreement is a bug somewhere (most likely the workspace, but
    // could be the oracle composition, the fixtures, or a pyca-version
    // edge case).
    assert_eq!(
        summary.looser, 0,
        "no Rust-looser cases are tolerated — pyca-composed oracle refused \
         while verify_code_signer passed; this is a potential bug, investigate"
    );
    assert_eq!(
        summary.stricter, 0,
        "no Rust-stricter cases are tolerated — pyca-composed oracle accepted \
         while verify_code_signer refused; investigate"
    );
}

// ---------------------------------------------------------------------------
// Sidecar plumbing
// ---------------------------------------------------------------------------

fn build_spec(leaf_pem: &str, root_pem: &str, validation_time_unix: u64) -> String {
    let spec = serde_json::json!({
        "leaf": leaf_pem,
        "intermediates": [],
        "roots": [root_pem],
        "validation_time_unix": validation_time_unix,
    });
    serde_json::to_string(&spec).expect("JSON encode")
}

fn run_sidecar(python: &Path, script: &Path, spec_json: &str) -> io::Result<PycaOutcome> {
    let mut child = Command::new(python)
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(spec_json.as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "sidecar exited {}: {}",
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ));
    }
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("sidecar stdout not JSON: {e}"),
        )
    })?;
    match v.get("verdict").and_then(|x| x.as_str()) {
        Some("pass") => Ok(PycaOutcome::Pass),
        Some("fail") => Ok(PycaOutcome::Fail(
            v.get("reason")
                .and_then(|x| x.as_str())
                .unwrap_or("(no reason)")
                .to_string(),
        )),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("sidecar unknown verdict {other:?}"),
        )),
    }
}

fn locate_python() -> Option<PathBuf> {
    if let Ok(env_path) = std::env::var("PYCA_DIFFTEST_PYTHON") {
        let p = PathBuf::from(env_path);
        if p.exists() {
            return Some(p);
        }
    }
    let cwd = std::env::current_dir().ok()?;
    for ancestor in cwd.ancestors() {
        let candidate = ancestor.join("pkix-difftest/python/.venv/bin/python");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn sidecar_script_path() -> PathBuf {
    let cwd = std::env::current_dir().expect("cwd");
    for ancestor in cwd.ancestors() {
        let candidate = ancestor.join("pkix-difftest/python/pyca_codesign_oracle.py");
        if candidate.exists() {
            return candidate;
        }
    }
    PathBuf::from("pkix-difftest/python/pyca_codesign_oracle.py")
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../pkix-chain/tests/fixtures")
}

fn load_fixture(name: &str) -> Certificate {
    let path = fixtures_dir().join(name);
    let der = std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
    Certificate::from_der(&der).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

trait CertExt {
    fn to_der_bytes(&self) -> Vec<u8>;
}
impl CertExt for Certificate {
    fn to_der_bytes(&self) -> Vec<u8> {
        use der::Encode as _;
        let mut out = Vec::new();
        self.encode_to_vec(&mut out).expect("re-encode DER");
        out
    }
}

fn der_to_pem(der: Vec<u8>) -> String {
    pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &der)
        .expect("PEM encode")
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

struct Row {
    case: String,
    leaf: String,
    root: String,
    rust: String,
    pyca: String,
    kind: AgreementKind,
}

struct Summary {
    agree: usize,
    looser: usize,
    stricter: usize,
}

fn classify(rust_pass: bool, pyca_pass: bool) -> AgreementKind {
    match (rust_pass, pyca_pass) {
        (true, true) | (false, false) => AgreementKind::Agree,
        (true, false) => AgreementKind::LooserThanPyca,
        (false, true) => AgreementKind::StricterThanPyca,
    }
}

fn pyca_label(p: &PycaOutcome) -> String {
    match p {
        PycaOutcome::Pass => "pass".to_string(),
        PycaOutcome::Fail(_) => "fail".to_string(),
    }
}

fn emit_matrix(rows: &[Row]) {
    eprintln!(
        "{:42}  {:34}  {:20}  {:6}  {:6}  agreement",
        "case", "leaf", "root", "rust", "pyca"
    );
    eprintln!("{}", "-".repeat(140));
    for r in rows {
        eprintln!(
            "{:42}  {:34}  {:20}  {:6}  {:6}  {:?}",
            r.case, r.leaf, r.root, r.rust, r.pyca, r.kind
        );
    }
}

fn summarize(rows: &[Row]) -> Summary {
    let mut s = Summary {
        agree: 0,
        looser: 0,
        stricter: 0,
    };
    for r in rows {
        match r.kind {
            AgreementKind::Agree => s.agree += 1,
            AgreementKind::LooserThanPyca => s.looser += 1,
            AgreementKind::StricterThanPyca => s.stricter += 1,
        }
    }
    s
}
