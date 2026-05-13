//! Wrapper-level differential test (PKIX-fmtv.18.7).
//!
//! Compares `pkix_chain::verify_ocsp_responder` against `openssl verify
//! -purpose ocsphelper`.
//!
//! ## Scope is intrinsically narrow
//!
//! OpenSSL's `-purpose ocsphelper` is **chain-only**: it does NOT
//! enforce `id-kp-OCSPSigning` EKU on the leaf (verified against
//! OpenSSL 3.0.13: `host-exact-foo.pem` with serverAuth-only EKU
//! validates fine under `-purpose ocsphelper`). It also has no notion
//! of:
//!
//! - **RFC 6960 §4.2.2.2 delegation DN match** — the wrapper's
//!   `Error::OcspDelegation` check compares `chain[0].issuer` against
//!   the supplied `issuer` cert's subject. OpenSSL has no equivalent
//!   CLI flag.
//!
//! - **RFC 6960 §4.2.2.2.1 nocheck bypass** — the wrapper installs a
//!   revocation-checker shim that skips OCSP-checking the responder
//!   itself when it carries `id-pkix-ocsp-nocheck`. OpenSSL's `verify`
//!   CLI doesn't run OCSP at all in the absence of `-CRLfile` /
//!   custom flags.
//!
//! As a result this diff is structurally limited to chain validity
//! questions (notBefore / notAfter, signature validity, anchor binding)
//! plus the very-weak EKU absence-check (OpenSSL accepts more than the
//! wrapper does, so divergences here are Rust-stricter and expected).
//!
//! ## Pending design clarification
//!
//! PKIX-fmtv.13.3 has a pending design clarification for the OCSP
//! responder wrapper's `issuer` argument shape; the diff harness here
//! stays out of that decision by exercising only the positive-chain
//! case and the chain-invalid-time case.
//!
//! ## Running
//!
//! ```sh
//! cargo test -p pkix-difftest --test verify_wrapper_openssl_ocsp -- --nocapture
//! ```

#![forbid(unsafe_code)]

use std::path::PathBuf;

use pkix_chain::{verify_ocsp_responder, Error, NoRevocation, TrustAnchor};
use pkix_difftest::oracles;
use pkix_difftest::{Chain, Verdict};
use pkix_profiles::BasicOcspResponderProfile;
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

const NOW: u64 = 1_780_272_000;
const BEFORE: u64 = 0;

#[derive(Clone, Debug, PartialEq, Eq)]
enum RustOutcome {
    Ok,
    Path,
    OcspDelegation,
    Other(String),
}

impl RustOutcome {
    fn from_result<T>(r: Result<T, Error>) -> Self {
        match r {
            Ok(_) => RustOutcome::Ok,
            Err(Error::Path(_)) => RustOutcome::Path,
            Err(Error::OcspDelegation { .. }) => RustOutcome::OcspDelegation,
            Err(other) => RustOutcome::Other(format!("{other:?}")),
        }
    }

    fn is_pass(&self) -> bool {
        matches!(self, RustOutcome::Ok)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AgreementKind {
    Agree,
    LooserThanOpenssl,
    StricterThanOpenssl,
}

struct OcspCase<'a> {
    name: &'a str,
    fixture: &'a str,
    issuer_fixture: &'a str,
    time: u64,
    expected_rust: RustOutcome,
}

#[rustfmt::skip]
fn ocsp_cases() -> Vec<OcspCase<'static>> {
    use RustOutcome::*;
    vec![
        // Happy path: OCSPSigning EKU leaf, valid issuer, in-window time.
        OcspCase { name: "happy_path",                fixture: "leaf-ocsp-responder.der",          issuer_fixture: "root.der",              time: NOW,    expected_rust: Ok },
        // Nocheck-bearing responder leaf, same shape.
        OcspCase { name: "happy_path_with_nocheck",   fixture: "leaf-ocsp-responder-nocheck.der",  issuer_fixture: "root.der",              time: NOW,    expected_rust: Ok },
        // Chain-time invalid: BEFORE notBefore. Both sides reject.
        OcspCase { name: "before_not_before",         fixture: "leaf-ocsp-responder.der",          issuer_fixture: "root.der",              time: BEFORE, expected_rust: Path },
    ]
}

#[test]
fn verify_ocsp_responder_diff_against_openssl_ocsphelper() {
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root.clone())];

    let mut rows: Vec<Row> = Vec::new();
    for case in ocsp_cases() {
        let leaf = load_fixture(case.fixture);
        let issuer = load_fixture(case.issuer_fixture);
        let chain = [leaf.clone()];

        let rust = RustOutcome::from_result(verify_ocsp_responder(
            &chain,
            &anchors,
            &issuer,
            &BasicOcspResponderProfile,
            case.time,
            &NoRevocation,
        ));
        assert_eq!(
            rust, case.expected_rust,
            "Rust outcome diverged from expected for {} (fixture {}, time {})",
            case.name, case.fixture, case.time,
        );

        let diff_chain = Chain {
            certs_der: vec![cert_der(&leaf), cert_der(&root)],
            crls: Vec::new(),
            root_in_chain: true,
            label: case.name.to_string(),
            validation_time_unix: Some(case.time),
        };
        let args = oracles::openssl::VerifyArgs {
            purpose: Some("ocsphelper"),
            ..oracles::openssl::VerifyArgs::default()
        };
        let openssl =
            expect_openssl_available(oracles::openssl::verify_with_args(&diff_chain, &args));
        let kind = classify(rust.is_pass(), openssl.is_pass());

        rows.push(Row {
            case: case.name.to_string(),
            fixture: case.fixture.to_string(),
            time: case.time,
            rust: format!("{rust:?}"),
            openssl: openssl_label(&openssl),
            kind,
        });
    }

    eprintln!();
    eprintln!("=== verify_ocsp_responder diff vs `openssl verify -purpose ocsphelper` ===");
    emit_matrix(&rows);
    let summary = summarize(&rows);
    eprintln!();
    eprintln!(
        "ocsp_responder: {n} cases — {agree} agree, {looser} Rust-looser, {stricter} Rust-stricter",
        n = rows.len(),
        agree = summary.agree,
        looser = summary.looser,
        stricter = summary.stricter,
    );
    eprintln!(
        "Note: OpenSSL's -purpose ocsphelper is chain-only — see baseline-verify-openssl.md."
    );

    assert_eq!(
        summary.looser, 0,
        "no Rust-looser cases tolerated — OpenSSL refused while wrapper \
         passed; investigate"
    );
}

fn cert_der(c: &Certificate) -> Vec<u8> {
    use der::Encode as _;
    let mut out = Vec::new();
    c.encode_to_vec(&mut out).expect("re-encode DER");
    out
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../pkix-chain/tests/fixtures")
}

fn load_fixture(name: &str) -> Certificate {
    let path = fixtures_dir().join(name);
    let der = std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
    Certificate::from_der(&der).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

fn expect_openssl_available(result: std::io::Result<Verdict>) -> Verdict {
    match result {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            panic!(
                "openssl binary not on $PATH; install OpenSSL ≥ 1.1 or set \
                 PKIX_DIFFTEST_OPENSSL_BIN. Original: {e}"
            );
        }
        Err(e) => panic!("openssl oracle harness error: {e}"),
    }
}

struct Row {
    case: String,
    fixture: String,
    time: u64,
    rust: String,
    openssl: String,
    kind: AgreementKind,
}

struct Summary {
    agree: usize,
    looser: usize,
    stricter: usize,
}

fn classify(rust_pass: bool, openssl_pass: bool) -> AgreementKind {
    match (rust_pass, openssl_pass) {
        (true, true) | (false, false) => AgreementKind::Agree,
        (true, false) => AgreementKind::LooserThanOpenssl,
        (false, true) => AgreementKind::StricterThanOpenssl,
    }
}

fn openssl_label(v: &Verdict) -> String {
    match v {
        Verdict::Pass => "pass".to_string(),
        Verdict::Fail { .. } => "fail".to_string(),
    }
}

fn emit_matrix(rows: &[Row]) {
    eprintln!(
        "{:34}  {:40}  {:12}  {:18}  {:7}  agreement",
        "case", "fixture", "time", "rust", "openssl"
    );
    eprintln!("{}", "-".repeat(130));
    for r in rows {
        eprintln!(
            "{:34}  {:40}  {:12}  {:18}  {:7}  {:?}",
            r.case, r.fixture, r.time, r.rust, r.openssl, r.kind
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
            AgreementKind::LooserThanOpenssl => s.looser += 1,
            AgreementKind::StricterThanOpenssl => s.stricter += 1,
        }
    }
    s
}
