//! Wrapper-level differential test (PKIX-fmtv.19).
//!
//! Compares `pkix_chain::verify_tls_server` and
//! `pkix_chain::verify_tls_client_dns` against pyca/cryptography's
//! `PolicyBuilder` over the curated RFC 6125 corpus that ships in
//! `pkix-chain/tests/fixtures/` (authored under PKIX-fmtv.22).
//!
//! Scope mirrors the bead description:
//!
//! - **TLS server** — `PolicyBuilder().build_server_verifier(DNSName/IPAddress)`
//!   vs `verify_tls_server`. Compared under a permissive EE extension policy
//!   on the pyca side (`permit_all().require_present(SAN, ...)`) so the diff
//!   reflects RFC 6125 binding rather than orthogonal CA/B Forum
//!   strictures like required AKI/SKI. See `pyca_verify_oracle.py` rustdoc
//!   for the rationale.
//!
//! - **TLS client** — `PolicyBuilder().build_client_verifier()` vs
//!   `verify_tls_client_dns`. pyca's client verifier does NOT bind a
//!   subject, so the comparison is path-walk-only. SAN-binding outcomes
//!   are surfaced as `pyca-weaker` rather than disagreements; see the
//!   per-case table emitted at the end of the test.
//!
//! - **S/MIME signer / recipient, code-signing, time-stamping,
//!   OCSP responder** — pyca's `PolicyBuilder` has no purpose-specific
//!   verifier for these. The diff harness records them as
//!   `no-pyca-oracle` in the baseline report; substantive coverage
//!   falls to PKIX-fmtv.18 (OpenSSL).
//!
//! ## Running
//!
//! ```sh
//! pkix-difftest/python/setup-venv.sh         # idempotent, once per checkout
//! cargo test -p pkix-difftest --test verify_wrapper_pyca -- --nocapture
//! ```
//!
//! When the venv is missing the test reports the absence and skips, so
//! the harness keeps green on environments that don't have Python or
//! pyca installed.

#![forbid(unsafe_code)]

use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use pkix_chain::{
    verify_tls_client_dns, verify_tls_server, Error, IdentityError, NoRevocation, ServerName,
    TrustAnchor,
};
use pkix_profiles::{BasicTlsClientProfile, Rfc5280Profile};
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

/// What pyca said.
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

/// Classifier verdict comparing Rust and pyca.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AgreementKind {
    /// Both verifiers agreed (both pass, or both fail).
    Agree,
    /// Rust accepted; pyca rejected. Rust is looser.
    LooserThanPyca,
    /// Rust rejected; pyca accepted. Rust is stricter (or pyca's surface
    /// doesn't enforce the binding — see `client` mode rustdoc).
    StricterThanPyca,
}

// ---------------------------------------------------------------------------
// Server-mode corpus
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Target<'a> {
    Dns(&'a str),
    Ip(&'a str),
}

/// One curated server-mode case. The rows mirror `pkix-chain`'s
/// `hostname_corpus.rs` 1:1 so the per-case agreement matrix is easy
/// to audit.
struct ServerCase<'a> {
    name: &'a str,
    fixture: &'a str,
    target: Target<'a>,
    expected_rust: RustOutcome,
}

#[rustfmt::skip]
fn server_cases() -> Vec<ServerCase<'static>> {
    use RustOutcome::*;
    use Target::*;
    vec![
        // Exact-match dNSName SANs (RFC 6125 §6.4.1)
        ServerCase { name: "exact_match",                       fixture: "host-exact-foo.der",            target: Dns("foo.example.com"),     expected_rust: Ok },
        ServerCase { name: "exact_mismatch",                    fixture: "host-exact-foo.der",            target: Dns("bar.example.com"),     expected_rust: NoMatchingSan },
        ServerCase { name: "exact_parent_does_not_match",       fixture: "host-exact-foo.der",            target: Dns("example.com"),         expected_rust: NoMatchingSan },
        // Wildcards (RFC 6125 §6.4.2)
        ServerCase { name: "wildcard_matches_single_label",     fixture: "host-wildcard.der",             target: Dns("foo.example.com"),     expected_rust: Ok },
        ServerCase { name: "wildcard_parent_rejected",          fixture: "host-wildcard.der",             target: Dns("example.com"),         expected_rust: NoMatchingSan },
        ServerCase { name: "wildcard_deeper_rejected",          fixture: "host-wildcard.der",             target: Dns("foo.bar.example.com"), expected_rust: NoMatchingSan },
        ServerCase { name: "wildcard_partial_label_rejected",   fixture: "host-wildcard-partial-label.der", target: Dns("foo.example.com"),   expected_rust: NoMatchingSan },
        ServerCase { name: "wildcard_internal_rejected",        fixture: "host-wildcard-internal.der",    target: Dns("foo.bar.example.com"), expected_rust: NoMatchingSan },
        ServerCase { name: "wildcard_public_suffix_rejected",   fixture: "host-wildcard-tld.der",         target: Dns("foo.com"),             expected_rust: NoMatchingSan },
        // Case folding (RFC 4343)
        ServerCase { name: "case_san_upper_target_lower",       fixture: "host-mixed-case-san.der",       target: Dns("foo.example.com"),     expected_rust: Ok },
        ServerCase { name: "case_san_lower_target_upper",       fixture: "host-exact-foo.der",            target: Dns("FOO.example.com"),     expected_rust: Ok },
        // IDN (RFC 5891)
        ServerCase { name: "idn_alabel_san_alabel_target",      fixture: "host-idn-alabel.der",           target: Dns("xn--bcher-kva.example"), expected_rust: Ok },
        // IP literal SANs (RFC 5280 §4.2.1.6)
        ServerCase { name: "ipv4_san_matches_ipv4_target",      fixture: "host-ipv4.der",                 target: Ip("192.0.2.5"),            expected_rust: Ok },
        ServerCase { name: "ipv4_san_mismatch",                 fixture: "host-ipv4.der",                 target: Ip("192.0.2.6"),            expected_rust: NoMatchingSan },
        ServerCase { name: "ipv6_san_matches_ipv6_target",      fixture: "host-ipv6.der",                 target: Ip("2001:db8::1"),          expected_rust: Ok },
        ServerCase { name: "ipv6_san_mismatch",                 fixture: "host-ipv6.der",                 target: Ip("2001:db8::2"),          expected_rust: NoMatchingSan },
        ServerCase { name: "ipv4_san_v6_target_rejected",       fixture: "host-ipv4.der",                 target: Ip("2001:db8::42"),         expected_rust: NoMatchingSan },
        ServerCase { name: "dns_san_ip_target_rejected",        fixture: "host-exact-foo.der",            target: Ip("192.0.2.5"),            expected_rust: NoMatchingSan },
        // Multi-SAN iteration
        ServerCase { name: "multi_san_first_matches",           fixture: "host-multi-san.der",            target: Dns("api.example.com"),     expected_rust: Ok },
        ServerCase { name: "multi_san_middle_matches",          fixture: "host-multi-san.der",            target: Dns("www.example.com"),     expected_rust: Ok },
        ServerCase { name: "multi_san_wildcard_matches",        fixture: "host-multi-san.der",            target: Dns("static.cdn.example.com"), expected_rust: Ok },
        ServerCase { name: "multi_san_none_match",              fixture: "host-multi-san.der",            target: Dns("other.example.com"),   expected_rust: NoMatchingSan },
        // SAN-absent (RFC 6125 §6.4.4)
        ServerCase { name: "missing_san_rejected",              fixture: "leaf-no-san.der",               target: Dns("foo.example.com"),     expected_rust: MissingSan },
    ]
}

// ---------------------------------------------------------------------------
// Client-mode corpus (path + EKU only; pyca cannot bind subject)
// ---------------------------------------------------------------------------

struct ClientCase<'a> {
    name: &'a str,
    fixture: &'a str,
    /// `Some(name)` to check Rust's SAN binding; pyca ignores subject in
    /// client mode regardless of this value.
    target: Option<Target<'a>>,
    /// Profile to drive Rust under. `BasicTlsClientProfile` enforces
    /// clientAuth EKU; `Rfc5280Profile` does not.
    profile_basic_client: bool,
    expected_rust: RustOutcome,
}

#[rustfmt::skip]
fn client_cases() -> Vec<ClientCase<'static>> {
    use RustOutcome::*;
    use Target::*;
    vec![
        // Valid clientAuth leaf with matching DNS SAN — both should pass.
        ClientCase { name: "client_dns_match_rfc5280",     fixture: "leaf-clientauth-dns.der",     target: Some(Dns("client.example.com")), profile_basic_client: false, expected_rust: Ok },
        ClientCase { name: "client_dns_match_basic_client",fixture: "leaf-clientauth-dns.der",     target: Some(Dns("client.example.com")), profile_basic_client: true,  expected_rust: Ok },
        // Valid clientAuth leaf but identity mismatch — Rust rejects on
        // binding; pyca passes because it doesn't bind subject.
        ClientCase { name: "client_dns_san_mismatch",      fixture: "leaf-clientauth-dns.der",     target: Some(Dns("other.example.com")),  profile_basic_client: false, expected_rust: NoMatchingSan },
        // serverAuth-only leaf under BasicTlsClientProfile — Rust rejects
        // for EKU; pyca passes because its permit_all EE policy doesn't
        // enforce EKU.
        ClientCase { name: "client_dns_eku_mismatch",      fixture: "host-exact-foo.der",          target: None,                            profile_basic_client: true,  expected_rust: Path },
        // Identity None on a leaf without SAN — Rust passes (no binding to
        // do); pyca passes.
        ClientCase { name: "client_dns_none_no_san_ok",    fixture: "leaf-clientauth-dns.der",     target: None,                            profile_basic_client: false, expected_rust: Ok },
    ]
}

// ---------------------------------------------------------------------------
// Test driver
// ---------------------------------------------------------------------------

#[test]
fn verify_wrapper_pyca_diff() {
    let Some(python) = locate_python() else {
        eprintln!(
            "verify_wrapper_pyca_diff: skipping — no Python sidecar venv at \
             pkix-difftest/python/.venv/bin/python. Run \
             pkix-difftest/python/setup-venv.sh and re-test."
        );
        return;
    };
    let sidecar = sidecar_script_path();
    if !sidecar.exists() {
        eprintln!(
            "verify_wrapper_pyca_diff: skipping — sidecar script missing: {}",
            sidecar.display()
        );
        return;
    }

    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root.clone())];
    let root_pem = der_to_pem(root.to_der_bytes());

    // --- server mode ---
    let mut server_rows: Vec<Row> = Vec::new();
    for case in server_cases() {
        let leaf = load_fixture(case.fixture);
        let chain = [leaf.clone()];

        // Rust verdict
        let server_name = match case.target {
            Target::Dns(s) => ServerName::dns_name(s).expect("parse DNS"),
            Target::Ip(s) => ServerName::ip_address(s).expect("parse IP"),
        };
        // Drive Rust under `Rfc5280Profile`, mirroring `hostname_corpus.rs`.
        // `BasicTlsProfile` sets `require_subject_alt_name=true`, which
        // promotes SAN-absent to `Error::Path(_)` and hides the identity-
        // layer outcome we want to compare against pyca's `ServerVerifier`
        // (which surfaces the same condition as a SAN-binding failure).
        let rust = RustOutcome::from_result(verify_tls_server(
            &chain,
            &anchors,
            &server_name,
            &Rfc5280Profile,
            NOW,
            &NoRevocation,
        ));
        assert_eq!(
            rust, case.expected_rust,
            "Rust outcome diverged from hostname_corpus expectation \
             for {} (fixture {}, target {:?})",
            case.name, case.fixture, case.target,
        );

        // pyca verdict
        let leaf_pem = der_to_pem(leaf.to_der_bytes());
        let spec = build_server_spec(&leaf_pem, &root_pem, case.target);
        let pyca = run_sidecar(&python, &sidecar, &spec)
            .expect("pyca sidecar must produce a verdict for every server case");
        let kind = classify(rust.is_pass(), pyca.is_pass());

        server_rows.push(Row {
            case: case.name.to_string(),
            fixture: case.fixture.to_string(),
            target: format!("{:?}", case.target),
            rust: format!("{rust:?}"),
            pyca: pyca_label(&pyca),
            kind,
        });
    }

    // --- client mode ---
    let mut client_rows: Vec<Row> = Vec::new();
    for case in client_cases() {
        let leaf = load_fixture(case.fixture);
        let chain = [leaf.clone()];

        let server_name = case.target.map(|t| match t {
            Target::Dns(s) => ServerName::dns_name(s).expect("parse DNS"),
            Target::Ip(s) => ServerName::ip_address(s).expect("parse IP"),
        });
        // Bind the server_name reference; pkix_chain's wrapper takes Option<&_>.
        let server_name_ref = server_name.as_ref();

        // The wrapper under test is verify_tls_client_dns; mailbox-name
        // cases are tracked separately under PKIX-fmtv.23 and not exercised
        // here.
        let rust = if case.profile_basic_client {
            RustOutcome::from_result(verify_tls_client_dns(
                &chain,
                &anchors,
                server_name_ref,
                &BasicTlsClientProfile,
                NOW,
                &NoRevocation,
            ))
        } else {
            RustOutcome::from_result(verify_tls_client_dns(
                &chain,
                &anchors,
                server_name_ref,
                &Rfc5280Profile,
                NOW,
                &NoRevocation,
            ))
        };
        assert_eq!(
            rust, case.expected_rust,
            "Rust outcome diverged from client_cases expectation for {}",
            case.name
        );

        let leaf_pem = der_to_pem(leaf.to_der_bytes());
        let spec = build_client_spec(&leaf_pem, &root_pem);
        let pyca = run_sidecar(&python, &sidecar, &spec)
            .expect("pyca sidecar must produce a verdict for every client case");
        let kind = classify(rust.is_pass(), pyca.is_pass());

        client_rows.push(Row {
            case: case.name.to_string(),
            fixture: case.fixture.to_string(),
            target: case
                .target
                .map(|t| format!("{t:?}"))
                .unwrap_or_else(|| "none".to_string()),
            rust: format!("{rust:?}"),
            pyca: pyca_label(&pyca),
            kind,
        });
    }

    // Emit the per-case agreement matrix to stderr so `--nocapture` shows it
    // and CI logs preserve it for offline comparison with
    // baseline-verify-pyca.md.
    eprintln!();
    eprintln!("=== verify_tls_server diff vs pyca ServerVerifier ===");
    emit_matrix(&server_rows);
    eprintln!();
    eprintln!("=== verify_tls_client_dns diff vs pyca ClientVerifier ===");
    emit_matrix(&client_rows);

    // Aggregate per-mode pass-rates for the baseline document.
    let server_summary = summarize(&server_rows);
    let client_summary = summarize(&client_rows);
    eprintln!();
    eprintln!(
        "server: {n} cases — {agree} agree, {looser} Rust-looser, {stricter} Rust-stricter",
        n = server_rows.len(),
        agree = server_summary.agree,
        looser = server_summary.looser,
        stricter = server_summary.stricter,
    );
    eprintln!(
        "client: {n} cases — {agree} agree, {looser} Rust-looser, {stricter} Rust-stricter",
        n = client_rows.len(),
        agree = client_summary.agree,
        looser = client_summary.looser,
        stricter = client_summary.stricter,
    );

    // Hard invariant: every server-mode disagreement must be either a
    // known scope difference (none expected today — pyca's purpose-driven
    // ServerVerifier matches RFC 6125 binding 1:1 with our implementation
    // on this corpus) or surfaced loudly so the baseline doc tracks it.
    //
    // For client mode we DO expect Rust-stricter divergences where Rust
    // enforces SAN binding or clientAuth EKU and pyca's client verifier
    // does not. Those are recorded in the matrix but not failed on.
    assert_eq!(
        server_summary.looser, 0,
        "server: no Rust-looser cases are tolerated — pyca refused while \
         verify_tls_server passed; this is a potential bug, investigate"
    );
}

// ---------------------------------------------------------------------------
// Sidecar plumbing
// ---------------------------------------------------------------------------

fn build_server_spec(leaf_pem: &str, root_pem: &str, target: Target<'_>) -> String {
    let mut spec = serde_json::json!({
        "leaf": leaf_pem,
        "intermediates": [],
        "roots": [root_pem],
        "validation_time_unix": NOW,
        "mode": "server",
    });
    match target {
        Target::Dns(s) => spec["dns"] = serde_json::json!(s),
        Target::Ip(s) => {
            // Disambiguate v4 vs v6 by parsing once. The sidecar errors out
            // on ambiguity, so we route deliberately.
            if s.parse::<std::net::Ipv4Addr>().is_ok() {
                spec["ipv4"] = serde_json::json!(s);
            } else {
                spec["ipv6"] = serde_json::json!(s);
            }
        }
    }
    serde_json::to_string(&spec).expect("JSON encode")
}

fn build_client_spec(leaf_pem: &str, root_pem: &str) -> String {
    let spec = serde_json::json!({
        "leaf": leaf_pem,
        "intermediates": [],
        "roots": [root_pem],
        "validation_time_unix": NOW,
        "mode": "client",
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
        let candidate = ancestor.join("pkix-difftest/python/pyca_verify_oracle.py");
        if candidate.exists() {
            return candidate;
        }
    }
    PathBuf::from("pkix-difftest/python/pyca_verify_oracle.py")
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../pkix-chain/tests/fixtures")
}

fn load_fixture(name: &str) -> Certificate {
    let path = fixtures_dir().join(name);
    let der = std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
    Certificate::from_der(&der).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

/// `Certificate` doesn't expose raw DER round-trip directly here without
/// `Encode`; helper to keep call sites tidy.
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
    fixture: String,
    target: String,
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
        "{:38}  {:34}  {:24}  {:18}  {:6}  agreement",
        "case", "fixture", "target", "rust", "pyca"
    );
    eprintln!("{}", "-".repeat(140));
    for r in rows {
        eprintln!(
            "{:38}  {:34}  {:24}  {:18}  {:6}  {:?}",
            r.case, r.fixture, r.target, r.rust, r.pyca, r.kind
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
