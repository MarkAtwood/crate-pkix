//! Integration tests for `pkix_difftest::corpus::limbo` (PKIX-g9vc.2).
//!
//! Independent oracles for these tests:
//!
//! * The x509-limbo `limbo.json` manifest itself (when present at the
//!   conventional path `$HOME/GIT/x509-limbo/limbo.json`) — this gives
//!   the corpus-loader the real upstream input and asserts a
//!   range-bounded survivor count.
//! * Hand-built `limbo.json` byte strings serialised from inline structs
//!   for filter / time-threading / chain-ordering assertions. The PEM
//!   payloads come from the on-disk fixture `tests/fixtures/good-chain.pem`
//!   so the loader sees real-shape wire data; the chain need not
//!   cryptographically validate (the loader does no validation).
//!
//! Per the project test discipline: no test uses `LimboCorpus` as its own
//! oracle. Filter behaviour is asserted against independently-built input.

use std::path::{Path, PathBuf};

use pkix_difftest::corpus::limbo::LimboCorpus;
use pkix_difftest::corpus::Corpus;
use pkix_difftest::Verdict;

// ---------------------------------------------------------------------------
// PEM source — pulled out of the shared good-chain.pem fixture so each test
// works with three known-distinct CERTIFICATE blocks.
// ---------------------------------------------------------------------------

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/good-chain.pem")
}

/// Split a concatenated-PEM blob into individual `CERTIFICATE` PEM strings.
///
/// Each returned string is a complete `-----BEGIN CERTIFICATE-----\n...\n
/// -----END CERTIFICATE-----` block including a trailing newline, suitable
/// for use as a `peer_certificate` / `untrusted_intermediates[*]` /
/// `trusted_certs[*]` value in a synthetic `limbo.json`.
fn split_cert_pems(bundle: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = bundle;
    while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
        rest = &rest[start..];
        let Some(end_rel) = rest.find("-----END CERTIFICATE-----") else {
            break;
        };
        let end = end_rel + "-----END CERTIFICATE-----".len();
        let mut block = rest[..end].to_string();
        block.push('\n');
        out.push(block);
        rest = &rest[end..];
    }
    out
}

fn cert_pems() -> Vec<String> {
    let bundle =
        std::fs::read_to_string(fixture_path()).expect("read tests/fixtures/good-chain.pem");
    let pems = split_cert_pems(&bundle);
    assert!(
        pems.len() >= 2,
        "good-chain.pem fixture should ship at least 2 cert blocks; got {}",
        pems.len()
    );
    pems
}

// ---------------------------------------------------------------------------
// Synthetic `limbo.json` builder
// ---------------------------------------------------------------------------

/// Build a `limbo.json` byte string from a list of (almost-)complete
/// per-testcase JSON object strings. We assemble at the string layer
/// rather than via `serde_json::to_string(&Testcase)` because the
/// `Testcase` type is private to the loader module — the public surface
/// here is JSON. This keeps the test independent from any serde changes
/// the loader's internal types might undergo.
fn manifest_json(testcases: &[&str]) -> String {
    let mut out = String::from("{\"testcases\":[");
    for (i, tc) in testcases.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(tc);
    }
    out.push_str("]}");
    out
}

/// Embed a PEM string as a JSON-string literal (escape `"`, `\\`, and
/// newlines, which are the only special characters PEM produces).
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Inputs needed to spell one testcase. Only the loader-consumed fields are
/// surfaced; everything else gets schema-required-but-empty defaults.
struct TestcaseBuilder<'a> {
    id: &'a str,
    validation_kind: &'a str, // "SERVER" or "CLIENT"
    expected_result: &'a str, // "SUCCESS" or "FAILURE"
    peer_pem: &'a str,
    intermediates_pem: Vec<&'a str>,
    trusted_pem: Vec<&'a str>,
    features: Vec<&'a str>, // kebab-case feature names
    max_chain_depth: Option<u32>,
    /// `Some(Some(rfc3339))` → real time string. `Some(None)` → `null`.
    /// `None` → field omitted entirely (also defaults to null by schema).
    validation_time: Option<Option<&'a str>>,
}

impl TestcaseBuilder<'_> {
    fn to_json(&self) -> String {
        let intermediates_json: Vec<String> = self
            .intermediates_pem
            .iter()
            .map(|p| json_string(p))
            .collect();
        let trusted_json: Vec<String> = self.trusted_pem.iter().map(|p| json_string(p)).collect();
        let features_json: Vec<String> = self.features.iter().map(|f| format!("\"{f}\"")).collect();
        let validation_time_json = match self.validation_time {
            Some(Some(s)) => format!(",\"validation_time\":{}", json_string(s)),
            Some(None) => ",\"validation_time\":null".to_string(),
            None => String::new(),
        };
        let max_chain_depth_json = match self.max_chain_depth {
            Some(n) => format!(",\"max_chain_depth\":{n}"),
            None => String::new(),
        };
        format!(
            concat!(
                "{{",
                "\"id\":{id},",
                "\"description\":\"synthetic\",",
                "\"validation_kind\":\"{vk}\",",
                "\"trusted_certs\":[{tc}],",
                "\"untrusted_intermediates\":[{ui}],",
                "\"peer_certificate\":{pc},",
                "\"signature_algorithms\":[],",
                "\"key_usage\":[],",
                "\"extended_key_usage\":[],",
                "\"expected_result\":\"{er}\",",
                "\"expected_peer_names\":[],",
                "\"features\":[{ft}]",
                "{vt}",
                "{mcd}",
                "}}"
            ),
            id = json_string(self.id),
            vk = self.validation_kind,
            tc = trusted_json.join(","),
            ui = intermediates_json.join(","),
            pc = json_string(self.peer_pem),
            er = self.expected_result,
            ft = features_json.join(","),
            vt = validation_time_json,
            mcd = max_chain_depth_json,
        )
    }
}

fn minimal_server_case<'a>(id: &'a str, pems: &'a [String]) -> TestcaseBuilder<'a> {
    TestcaseBuilder {
        id,
        validation_kind: "SERVER",
        expected_result: "SUCCESS",
        peer_pem: &pems[0],
        intermediates_pem: if pems.len() >= 3 {
            vec![&pems[1]]
        } else {
            vec![]
        },
        trusted_pem: vec![&pems[pems.len() - 1]],
        features: vec![],
        max_chain_depth: None,
        validation_time: None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn limbo_load_errors_on_missing_manifest() {
    let err = LimboCorpus::load(Path::new("/nonexistent/path/for/limbo.json")).unwrap_err();
    assert!(
        err.to_string().contains("limbo corpus") || err.kind() == std::io::ErrorKind::NotFound,
        "expected a useful error message; got: {err}"
    );
}

#[test]
fn limbo_loads_and_filters_real_manifest() {
    // Resolve via `HOME` env var (no `dirs` dep added).
    let Some(home) = std::env::var_os("HOME") else {
        eprintln!("SKIP limbo_loads_and_filters_real_manifest: HOME not set");
        return;
    };
    let manifest = PathBuf::from(home).join("GIT/x509-limbo/limbo.json");
    if !manifest.exists() {
        eprintln!(
            "SKIP limbo_loads_and_filters_real_manifest: {} does not exist",
            manifest.display()
        );
        return;
    }
    let corpus = LimboCorpus::load(&manifest).expect("load real limbo.json");
    let count = corpus.iter().count();
    // Current limbo (commit on disk) survives 9726 cases. Range-bound so
    // minor upstream tweaks don't invalidate the test.
    assert!(
        (9700..=9740).contains(&count),
        "expected retained count in 9700..=9740 after default filter; got {count}",
    );
}

#[test]
fn limbo_filter_excludes_client_cases() {
    let pems = cert_pems();
    let mut server = minimal_server_case("ns::server", &pems);
    server.id = "ns::server";
    let mut client = minimal_server_case("ns::client", &pems);
    client.id = "ns::client";
    client.validation_kind = "CLIENT";

    let json = manifest_json(&[&server.to_json(), &client.to_json()]);
    let corpus = LimboCorpus::load_from_bytes(json.as_bytes()).expect("load");

    let names: Vec<String> = corpus.iter().map(|r| r.expect("ok").name).collect();
    assert_eq!(names, vec!["ns::server".to_string()]);
}

#[test]
fn limbo_filter_excludes_featured_cases() {
    let pems = cert_pems();

    let plain = minimal_server_case("ns::plain", &pems);
    let mut has_crl = minimal_server_case("ns::has-crl", &pems);
    has_crl.features = vec!["has-crl"];
    let mut name_constraint = minimal_server_case("ns::name-constraint", &pems);
    name_constraint.features = vec!["name-constraint-dn"];

    let json = manifest_json(&[
        &plain.to_json(),
        &has_crl.to_json(),
        &name_constraint.to_json(),
    ]);
    let corpus = LimboCorpus::load_from_bytes(json.as_bytes()).expect("load");

    let names: Vec<String> = corpus.iter().map(|r| r.expect("ok").name).collect();
    assert_eq!(names, vec!["ns::plain".to_string()]);
}

#[test]
fn limbo_filter_excludes_max_chain_depth_outlier() {
    let pems = cert_pems();
    let mut outlier = minimal_server_case("ns::mcd-outlier", &pems);
    outlier.max_chain_depth = Some(255); // and features stays empty

    let json = manifest_json(&[&outlier.to_json()]);
    let corpus = LimboCorpus::load_from_bytes(json.as_bytes()).expect("load");

    assert_eq!(corpus.iter().count(), 0);
}

#[test]
fn limbo_validation_time_threaded_into_chain() {
    let pems = cert_pems();
    let mut tc = minimal_server_case("ns::timed", &pems);
    tc.validation_time = Some(Some("2024-06-15T12:00:00+00:00"));

    let json = manifest_json(&[&tc.to_json()]);
    let corpus = LimboCorpus::load_from_bytes(json.as_bytes()).expect("load");

    let item = corpus
        .iter()
        .next()
        .expect("at least one item")
        .expect("item ok");
    // 2024-06-15T12:00:00Z == 1718452800
    assert_eq!(item.chain.validation_time_unix, Some(1_718_452_800));
}

#[test]
fn limbo_validation_time_default_when_null() {
    let pems = cert_pems();
    let mut tc = minimal_server_case("ns::null-time", &pems);
    tc.validation_time = Some(None);

    let json = manifest_json(&[&tc.to_json()]);
    let corpus = LimboCorpus::load_from_bytes(json.as_bytes()).expect("load");

    let item = corpus.iter().next().expect("one item").expect("ok");
    // Documented default: 2023-11-14T22:13:20Z.
    assert_eq!(item.chain.validation_time_unix, Some(1_700_000_000));
}

#[test]
fn limbo_chain_ordering_is_leaf_first() {
    let pems = cert_pems();
    assert!(pems.len() >= 3, "need a peer + intermediate + anchor");

    // Decode each PEM block to DER ourselves (independent oracle): the
    // first cert in `chain.certs_der` must equal DER(peer_pem), and the
    // last must equal DER(trusted_pem). We use `pem-rfc7468` here directly
    // — same crate the loader uses internally, but invoked separately so
    // we can compare bytes without depending on the loader's parsing.
    let peer_der = pem_rfc7468::decode_vec(pems[0].as_bytes())
        .expect("decode peer")
        .1;
    let intermediate_der = pem_rfc7468::decode_vec(pems[1].as_bytes())
        .expect("decode intermediate")
        .1;
    let trusted_der = pem_rfc7468::decode_vec(pems[2].as_bytes())
        .expect("decode trusted")
        .1;

    let tc = TestcaseBuilder {
        id: "ns::ordering",
        validation_kind: "SERVER",
        expected_result: "SUCCESS",
        peer_pem: &pems[0],
        intermediates_pem: vec![&pems[1]],
        trusted_pem: vec![&pems[2]],
        features: vec![],
        max_chain_depth: None,
        validation_time: None,
    };
    let json = manifest_json(&[&tc.to_json()]);
    let corpus = LimboCorpus::load_from_bytes(json.as_bytes()).expect("load");

    let item = corpus.iter().next().expect("one item").expect("ok");
    assert_eq!(item.chain.certs_der.len(), 3);
    assert_eq!(
        item.chain.certs_der.first().map(Vec::as_slice),
        Some(peer_der.as_slice()),
        "first cert in chain must equal the testcase's peer_certificate"
    );
    assert_eq!(
        item.chain.certs_der.get(1).map(Vec::as_slice),
        Some(intermediate_der.as_slice()),
        "middle cert must equal the testcase's untrusted_intermediates[0]"
    );
    assert_eq!(
        item.chain.certs_der.last().map(Vec::as_slice),
        Some(trusted_der.as_slice()),
        "last cert in chain must equal the testcase's trusted_certs[0]"
    );
    assert!(item.chain.root_in_chain);
    assert_eq!(item.expected, Some(Verdict::Pass));
}
