//! Wrapper-level differential test (PKIX-fmtv.18.4).
//!
//! Compares `pkix_chain::verify_smime_signer` and
//! `pkix_chain::verify_smime_recipient` against `openssl verify` over the
//! curated RFC 5280 §4.2.1.6 / RFC 8398 mailbox corpus from
//! `pkix-chain/tests/fixtures/` (authored under PKIX-fmtv.23).
//!
//! - `verify_smime_signer` ↔ `openssl verify -purpose smimesign -verify_email X`
//! - `verify_smime_recipient` ↔ `openssl verify -purpose smimeencrypt -verify_email X`
//!
//! Both wrappers share byte-identical bodies (per `mailbox_corpus.rs`),
//! so the diff test exercises both purposes on every fixture and pins
//! that they remain aligned with OpenSSL on both invocations.
//!
//! ## Running
//!
//! ```sh
//! cargo test -p pkix-difftest --test verify_wrapper_openssl_smime -- --nocapture
//! ```

#![forbid(unsafe_code)]

use std::path::PathBuf;

use pkix_chain::{
    verify_smime_recipient, verify_smime_signer, Error, IdentityError, MailboxName, NoRevocation,
    TrustAnchor,
};
use pkix_difftest::oracles;
use pkix_difftest::{Chain, Verdict};
use pkix_profiles::Rfc5280Profile;
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

const NOW: u64 = 1_780_272_000;

// ---------------------------------------------------------------------------
// Outcome vocabulary
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum RustOutcome {
    Ok,
    NoMatchingSan,
    MissingSan,
    Path,
    Other(String),
}

impl RustOutcome {
    fn from_result<T>(r: Result<T, Error>) -> Self {
        match r {
            Ok(_) => RustOutcome::Ok,
            Err(Error::Identity(IdentityError::NoMatchingSan)) => RustOutcome::NoMatchingSan,
            Err(Error::Identity(IdentityError::MissingSan)) => RustOutcome::MissingSan,
            Err(Error::Path(_)) => RustOutcome::Path,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Signer,
    Recipient,
}

impl Role {
    fn openssl_purpose(self) -> &'static str {
        match self {
            Role::Signer => "smimesign",
            Role::Recipient => "smimeencrypt",
        }
    }
}

// ---------------------------------------------------------------------------
// Corpus — mirrors mailbox_corpus.rs cases that exercise verify_* (the
// two parse-only rows #21/#22 are out of scope for this diff).
// ---------------------------------------------------------------------------

struct SmimeCase<'a> {
    name: &'a str,
    fixture: &'a str,
    target: &'a str,
    expected_rust: RustOutcome,
}

#[rustfmt::skip]
fn smime_cases() -> Vec<SmimeCase<'static>> {
    use RustOutcome::*;
    vec![
        SmimeCase { name: "rfc822_exact_match",                       fixture: "mailbox-rfc822-user-example.der",  target: "user@example.com",      expected_rust: Ok },
        SmimeCase { name: "rfc822_local_part_mismatch",               fixture: "mailbox-rfc822-user-example.der",  target: "other@example.com",     expected_rust: NoMatchingSan },
        SmimeCase { name: "domain_case_insensitive_san_to_target",    fixture: "mailbox-rfc822-user-EXAMPLE.der",  target: "user@example.com",      expected_rust: Ok },
        SmimeCase { name: "domain_case_insensitive_target_to_san",    fixture: "mailbox-rfc822-user-example.der",  target: "user@EXAMPLE.com",      expected_rust: Ok },
        SmimeCase { name: "local_part_case_sensitive_strict",         fixture: "mailbox-rfc822-User-example.der",  target: "user@example.com",      expected_rust: NoMatchingSan },
        SmimeCase { name: "local_part_case_sensitive_strict_inv",     fixture: "mailbox-rfc822-user-example.der",  target: "User@example.com",      expected_rust: NoMatchingSan },
        SmimeCase { name: "smtputf8_only_i18n_match",                 fixture: "mailbox-smtputf8-only.der",        target: "用户@example.com",      expected_rust: Ok },
        SmimeCase { name: "smtputf8_only_ascii_target_rejected",      fixture: "mailbox-smtputf8-only.der",        target: "user@example.com",      expected_rust: NoMatchingSan },
        SmimeCase { name: "mixed_san_ascii_target_matches_rfc822",    fixture: "mailbox-mixed.der",                target: "user@example.com",      expected_rust: Ok },
        SmimeCase { name: "mixed_san_i18n_target_matches_smtputf8",   fixture: "mailbox-mixed.der",                target: "用户@example.com",      expected_rust: Ok },
        SmimeCase { name: "mixed_san_unrelated_target_rejected",      fixture: "mailbox-mixed.der",                target: "stranger@example.com",  expected_rust: NoMatchingSan },
        SmimeCase { name: "multi_rfc822_first_match",                 fixture: "mailbox-multi-rfc822.der",         target: "alpha@example.com",     expected_rust: Ok },
        SmimeCase { name: "multi_rfc822_middle_match",                fixture: "mailbox-multi-rfc822.der",         target: "beta@example.com",      expected_rust: Ok },
        SmimeCase { name: "multi_rfc822_last_match",                  fixture: "mailbox-multi-rfc822.der",         target: "gamma@example.com",     expected_rust: Ok },
        SmimeCase { name: "multi_rfc822_no_match",                    fixture: "mailbox-multi-rfc822.der",         target: "delta@example.com",     expected_rust: NoMatchingSan },
        SmimeCase { name: "dns_only_san_rejects_mailbox_under_rfc5280", fixture: "mailbox-dns-only.der",           target: "user@example.com",      expected_rust: NoMatchingSan },
        SmimeCase { name: "missing_san_extension",                    fixture: "leaf-no-san.der",                  target: "user@example.com",      expected_rust: MissingSan },
        SmimeCase { name: "rfc822_san_without_at_sign_is_not_a_match", fixture: "mailbox-rfc822-malformed-no-at.der", target: "user@example.com",   expected_rust: NoMatchingSan },
        SmimeCase { name: "smtputf8_malformed_utf8_is_not_a_match",   fixture: "mailbox-smtputf8-bad-utf8.der",    target: "用户@example.com",      expected_rust: NoMatchingSan },
    ]
}

// ---------------------------------------------------------------------------
// Test driver
// ---------------------------------------------------------------------------

#[test]
fn verify_smime_signer_diff_against_openssl_smimesign() {
    run_diff(Role::Signer);
}

#[test]
fn verify_smime_recipient_diff_against_openssl_smimeencrypt() {
    run_diff(Role::Recipient);
}

fn run_diff(role: Role) {
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root.clone())];

    let mut rows: Vec<Row> = Vec::new();
    for case in smime_cases() {
        let leaf = load_fixture(case.fixture);
        let chain = [leaf.clone()];
        let mailbox = MailboxName::parse(case.target).expect("parse target mailbox in corpus row");

        // Rust verdict
        let rust = match role {
            Role::Signer => RustOutcome::from_result(verify_smime_signer(
                &chain,
                &anchors,
                &mailbox,
                &Rfc5280Profile,
                NOW,
                &NoRevocation,
            )),
            Role::Recipient => RustOutcome::from_result(verify_smime_recipient(
                &chain,
                &anchors,
                &mailbox,
                &Rfc5280Profile,
                NOW,
                &NoRevocation,
            )),
        };
        assert_eq!(
            rust, case.expected_rust,
            "Rust outcome diverged from mailbox_corpus expectation for \
             {} (role {:?}, fixture {}, target {:?})",
            case.name, role, case.fixture, case.target,
        );

        // OpenSSL verdict
        let diff_chain = Chain {
            certs_der: vec![cert_der(&leaf), cert_der(&root)],
            crls: Vec::new(),
            root_in_chain: true,
            label: case.name.to_string(),
            validation_time_unix: Some(NOW),
        };
        let args = oracles::openssl::VerifyArgs {
            purpose: Some(role.openssl_purpose()),
            verify_email: Some(case.target),
            ..oracles::openssl::VerifyArgs::default()
        };
        let openssl =
            expect_openssl_available(oracles::openssl::verify_with_args(&diff_chain, &args));
        let kind = classify(rust.is_pass(), openssl.is_pass());

        rows.push(Row {
            case: case.name.to_string(),
            fixture: case.fixture.to_string(),
            target: case.target.to_string(),
            rust: format!("{rust:?}"),
            openssl: openssl_label(&openssl),
            kind,
        });
    }

    eprintln!();
    eprintln!(
        "=== verify_smime_{} diff vs `openssl verify -purpose {}` ===",
        match role {
            Role::Signer => "signer",
            Role::Recipient => "recipient",
        },
        role.openssl_purpose()
    );
    emit_matrix(&rows);
    let summary = summarize(&rows);
    eprintln!();
    eprintln!(
        "{role:?}: {n} cases — {agree} agree, {looser} Rust-looser, {stricter} Rust-stricter",
        n = rows.len(),
        agree = summary.agree,
        looser = summary.looser,
        stricter = summary.stricter,
    );

    assert_eq!(
        summary.looser, 0,
        "{role:?}: no Rust-looser cases tolerated — OpenSSL refused while \
         the wrapper passed; investigate"
    );
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

struct Row {
    case: String,
    fixture: String,
    target: String,
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
        "{:46}  {:42}  {:24}  {:18}  {:7}  agreement",
        "case", "fixture", "target", "rust", "openssl"
    );
    eprintln!("{}", "-".repeat(170));
    for r in rows {
        eprintln!(
            "{:46}  {:42}  {:24}  {:18}  {:7}  {:?}",
            r.case, r.fixture, r.target, r.rust, r.openssl, r.kind
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
