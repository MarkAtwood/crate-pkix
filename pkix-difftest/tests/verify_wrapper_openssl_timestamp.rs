//! Wrapper-level differential test (PKIX-fmtv.18.6).
//!
//! Compares `pkix_chain::verify_time_stamper` against `openssl verify
//! -purpose timestampsign` over the timestamping fixtures in
//! `pkix-chain/tests/fixtures/`.
//!
//! ## Surfaced divergence: RFC 3161 §2.3 KeyUsage shape
//!
//! OpenSSL's `-purpose timestampsign` strictly enforces RFC 3161
//! §2.3: the TSA cert's KeyUsage MUST contain ONLY `digitalSignature`
//! and/or `nonRepudiation`. `keyEncipherment`, `keyAgreement`, etc.
//! trigger "unsuitable certificate purpose" rejection.
//!
//! pkix-chain's `leaf-timestamping.der` fixture (authored by pyca's
//! gen.py for the smoke surface) carries
//! `digitalSignature + keyEncipherment` in KU. Under
//! `verify_time_stamper`, the wrapper does NOT check KU shape — only
//! EKU presence / criticality / sole-EKU — so the fixture validates.
//! OpenSSL rejects.
//!
//! The diff therefore records `happy_path` as **Rust-looser**: this
//! is a real semantic gap, tracked separately (see baseline-
//! verify-openssl.md for the follow-up bead). The
//! `summary.looser == 0` assertion is intentionally lifted here.
//!
//! The remaining cases (`eku_not_critical`, `eku_not_sole`,
//! `before_not_before`) exercise the failure modes where both sides
//! reject; they agree.
//!
//! ## Running
//!
//! ```sh
//! cargo test -p pkix-difftest --test verify_wrapper_openssl_timestamp -- --nocapture
//! ```

#![forbid(unsafe_code)]

use std::path::PathBuf;

use pkix_chain::{verify_time_stamper, Error, NoRevocation, TrustAnchor};
use pkix_difftest::oracles;
use pkix_difftest::{Chain, Verdict};
use pkix_profiles::BasicTimeStampingProfile;
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

const NOW: u64 = 1_780_272_000;
const BEFORE: u64 = 0;

#[derive(Clone, Debug, PartialEq, Eq)]
enum RustOutcome {
    Ok,
    Path,
    ProfileViolation,
    Other(String),
}

impl RustOutcome {
    fn from_result<T>(r: Result<T, Error>) -> Self {
        match r {
            Ok(_) => RustOutcome::Ok,
            Err(Error::Path(_)) => RustOutcome::Path,
            Err(Error::ProfileViolation { .. }) => RustOutcome::ProfileViolation,
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

struct TsCase<'a> {
    name: &'a str,
    fixture: &'a str,
    time: u64,
    expected_rust: RustOutcome,
    /// `true` when an intentional Rust-looser / Rust-stricter divergence
    /// is expected for documented reasons. The test skips its hard
    /// `looser == 0` assertion when at least one row is flagged.
    known_divergence: bool,
}

#[rustfmt::skip]
fn ts_cases() -> Vec<TsCase<'static>> {
    use RustOutcome::*;
    vec![
        // KU=digitalSignature+keyEncipherment violates RFC 3161 §2.3.
        // OpenSSL rejects; verify_time_stamper accepts. Tracked as a
        // workspace follow-up (see baseline-verify-openssl.md).
        TsCase { name: "happy_path_rfc3161_ku_violation", fixture: "leaf-timestamping.der",              time: NOW,    expected_rust: Ok,   known_divergence: true },

        // EKU not critical — wrapper rejects with ProfileViolation (RFC 3161 §2.3
        // mandates criticality); OpenSSL also rejects (different reason).
        TsCase { name: "eku_not_critical",                fixture: "leaf-timestamping-not-critical.der", time: NOW,    expected_rust: ProfileViolation, known_divergence: false },

        // EKU not sole — wrapper rejects with ProfileViolation (RFC 3161 §2.3
        // mandates sole); OpenSSL also rejects.
        TsCase { name: "eku_not_sole",                    fixture: "leaf-timestamping-not-sole.der",     time: NOW,    expected_rust: ProfileViolation, known_divergence: false },

        // Before notBefore — both sides reject on chain validity.
        TsCase { name: "before_not_before",               fixture: "leaf-timestamping.der",              time: BEFORE, expected_rust: Path, known_divergence: false },
    ]
}

#[test]
fn verify_time_stamper_diff_against_openssl_timestampsign() {
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root.clone())];

    let mut rows: Vec<Row> = Vec::new();
    let mut any_known_divergence = false;
    for case in ts_cases() {
        let leaf = load_fixture(case.fixture);
        let chain = [leaf.clone()];

        let rust = RustOutcome::from_result(verify_time_stamper(
            &chain,
            &anchors,
            &BasicTimeStampingProfile,
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
            purpose: Some("timestampsign"),
            ..oracles::openssl::VerifyArgs::default()
        };
        let openssl =
            expect_openssl_available(oracles::openssl::verify_with_args(&diff_chain, &args));
        let kind = classify(rust.is_pass(), openssl.is_pass());

        if case.known_divergence && kind != AgreementKind::Agree {
            any_known_divergence = true;
        }

        rows.push(Row {
            case: case.name.to_string(),
            fixture: case.fixture.to_string(),
            time: case.time,
            rust: format!("{rust:?}"),
            openssl: openssl_label(&openssl),
            kind,
            known_divergence: case.known_divergence,
        });
    }

    eprintln!();
    eprintln!("=== verify_time_stamper diff vs `openssl verify -purpose timestampsign` ===");
    emit_matrix(&rows);
    let summary = summarize(&rows);
    eprintln!();
    eprintln!(
        "timestamp: {n} cases — {agree} agree, {looser} Rust-looser, {stricter} Rust-stricter \
         ({kd} known divergence{s})",
        n = rows.len(),
        agree = summary.agree,
        looser = summary.looser,
        stricter = summary.stricter,
        kd = if any_known_divergence { 1 } else { 0 },
        s = if any_known_divergence { "" } else { "s" },
    );

    // The Rust-looser assertion is lifted for this purpose because the
    // happy-path case has a documented intentional divergence (fixture
    // violates RFC 3161 §2.3 KU shape, wrapper does not check it). The
    // test still pins case-by-case Rust outcomes against expected, and
    // surfaces the divergence visibly in the matrix.
    //
    // What we DO assert: every non-`known_divergence` case must agree.
    // Catches regressions where the wrapper starts behaving differently
    // on cases where we expect agreement.
    let unexpected = rows
        .iter()
        .filter(|r| !r.known_divergence && r.kind != AgreementKind::Agree)
        .count();
    assert_eq!(
        unexpected, 0,
        "timestamp: unexpected disagreement on a row not flagged as \
         known_divergence; investigate"
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
    known_divergence: bool,
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
        "{:38}  {:42}  {:12}  {:18}  {:7}  {:18}  known_divergence",
        "case", "fixture", "time", "rust", "openssl", "agreement"
    );
    eprintln!("{}", "-".repeat(160));
    for r in rows {
        eprintln!(
            "{:38}  {:42}  {:12}  {:18}  {:7}  {:18}  {}",
            r.case,
            r.fixture,
            r.time,
            r.rust,
            r.openssl,
            format!("{:?}", r.kind),
            r.known_divergence
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
