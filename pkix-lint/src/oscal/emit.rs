//! OSCAL Assessment Results emitter for [`crate::report::EvaluationReport`].
//!
//! The output is a [`serde_json::Value`] whose top-level shape matches the
//! NIST OSCAL Assessment Results JSON Schema (v1.1.2). Required fields per
//! the schema (`uuid`, `metadata`, `import-ap`, `results`) are always
//! present; optional fields are emitted only when the source report has
//! corresponding data.
//!
//! # OSCAL spec references
//!
//! - NIST OSCAL v1.1.2 Assessment Results model:
//!   <https://pages.nist.gov/OSCAL/concepts/layer/assessment/assessment-results/>
//! - JSON Schema definition (`oscal_assessment-results_schema.json`):
//!   <https://github.com/usnistgov/OSCAL/tree/main/json/schema>
//! - UUID format: RFC 9562 §5.8 (UUID version 8 with custom data); we
//!   derive UUIDs deterministically from the report inputs via SHA-256 so
//!   identical lint runs yield byte-identical OSCAL output. This is
//!   important for evidence-pack reproducibility and CI diffability.
//!
//! # Mapping
//!
//! | `EvaluationReport` field | OSCAL Assessment Results field |
//! |---|---|
//! | `profile_id`, `profile_version` | `metadata.props[name="pkix-lint.profile-id"]`, `…profile-version` |
//! | `rule_bundle_version` | `metadata.props[name="pkix-lint.rule-bundle-version"]` |
//! | `chain_length` | `metadata.props[name="pkix-lint.chain-length"]` |
//! | `evaluated_at_unix` | `metadata.last-modified` + `results[0].start`/`end` (RFC 3339) |
//! | `findings` | `results[0].observations[]` + `results[0].findings[]` |
//! | `deviated_findings` | `results[0].risks[]` with `status="deviation-approved"` |
//!
//! Each [`crate::Finding`] becomes:
//!
//! * one Observation in `results[0].observations[]` with `methods=["EXAMINE"]`
//!   (OSCAL collection method indicating an automated check), carrying the
//!   lint citation and `cert_sha256` (when present) as evidence.
//! * one Finding in `results[0].findings[]`. The Finding's
//!   `target.status.state` is `"not-satisfied"` for actionable lint results
//!   (Warn / Error / Fatal) and `"satisfied"` for Pass / NotApplicable.
//!   `related-observations` references the Observation above by UUID.
//!
//! Each [`crate::deviation::DeviatedFinding`] becomes one Risk in
//! `results[0].risks[]` with `status="deviation-approved"`, carrying the
//! justification text and (when present) the evidence URI.
//!
//! # Round-trip fidelity
//!
//! `assessment_results(report) → serde_json::to_string → serde_json::from_str`
//! returns a `serde_json::Value` byte-equal to the original output. The
//! emitter does not depend on serde::Serialize for `Finding` /
//! `DeviatedFinding`, so this module is usable independent of the `serde`
//! feature.
//!
//! # OSCAL JSON Schema compliance
//!
//! The emitter targets the structural requirements of the OSCAL v1.1.2
//! Assessment Results schema (required field presence, types, formats).
//! Full JSON-Schema validation against the canonical NIST schema file is
//! out of scope for this module — it would require either pulling in a
//! `jsonschema` dev-dep or shelling out to `oscal-cli`. Both belong in a
//! follow-up if a CI-grade conformance check is wanted; see the
//! PKIX-9vnx.3 closing notes.

use crate::deviation::{DeviatedFinding, DeviationAction};
use crate::report::EvaluationReport;
use crate::{Finding, LintResult};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// OSCAL version this emitter targets. Encoded as `metadata.oscal-version`.
///
/// Tied to NIST OSCAL v1.1.2 — the latest stable release at the time of
/// this module's introduction. Bumping requires re-checking field-shape
/// changes in the Assessment Results schema.
const OSCAL_VERSION: &str = "1.1.2";

/// Title surfaced in `metadata.title` for any pkix-lint run. Static for
/// recognisability in OSCAL dashboards.
const REPORT_TITLE: &str = "pkix-lint Assessment Results";

/// UUID-v8 salt namespace strings. Each OSCAL object kind gets its own
/// salt so two unrelated objects from the same source data cannot collide.
const NS_REPORT: &str = "pkix-lint.oscal.report";
const NS_RESULT: &str = "pkix-lint.oscal.result";
const NS_OBSERVATION: &str = "pkix-lint.oscal.observation";
const NS_FINDING: &str = "pkix-lint.oscal.finding";
const NS_RISK: &str = "pkix-lint.oscal.risk";

/// Emit an [`EvaluationReport`] as OSCAL Assessment Results JSON.
///
/// See the module-level docs for the field mapping and round-trip
/// guarantees.
#[must_use]
pub fn assessment_results(report: &EvaluationReport) -> Value {
    let report_seed = report_seed(report);

    let last_modified = unix_to_rfc3339(report.evaluated_at_unix);

    let mut props = Vec::with_capacity(4);
    if !report.profile_id.is_empty() {
        props.push(prop("pkix-lint.profile-id", &report.profile_id));
    }
    if !report.profile_version.is_empty() {
        props.push(prop("pkix-lint.profile-version", &report.profile_version));
    }
    if !report.rule_bundle_version.is_empty() {
        props.push(prop(
            "pkix-lint.rule-bundle-version",
            &report.rule_bundle_version,
        ));
    }
    props.push(prop(
        "pkix-lint.chain-length",
        &report.chain_length.to_string(),
    ));

    let result_uuid = uuid_v8(NS_RESULT, &report_seed);

    let observations: Vec<Value> = report
        .findings
        .iter()
        .enumerate()
        .map(|(i, f)| observation_for(f, &report_seed, i, &last_modified))
        .collect();

    let findings: Vec<Value> = report
        .findings
        .iter()
        .enumerate()
        .map(|(i, f)| finding_for(f, &report_seed, i))
        .collect();

    let risks: Vec<Value> = report
        .deviated_findings
        .iter()
        .enumerate()
        .map(|(i, df)| risk_for(df, &report_seed, i))
        .collect();

    let mut result = json!({
        "uuid": result_uuid,
        "title": REPORT_TITLE,
        "description": "Findings emitted by pkix-lint for the evaluated certificate chain.",
        "start": last_modified.clone(),
        "end": last_modified.clone(),
        "reviewed-controls": {
            "control-selections": [ { "include-all": {} } ]
        },
    });
    // Optional OSCAL fields are emitted only when non-empty so the output
    // stays close to the minimal valid Assessment Results document. The
    // schema allows them to be absent.
    if !observations.is_empty() {
        result["observations"] = Value::Array(observations);
    }
    if !findings.is_empty() {
        result["findings"] = Value::Array(findings);
    }
    if !risks.is_empty() {
        result["risks"] = Value::Array(risks);
    }

    json!({
        "assessment-results": {
            "uuid": uuid_v8(NS_REPORT, &report_seed),
            "metadata": {
                "title": REPORT_TITLE,
                "last-modified": last_modified,
                "version": env!("CARGO_PKG_VERSION"),
                "oscal-version": OSCAL_VERSION,
                "props": props,
            },
            "import-ap": {
                // Per OSCAL: this references the Assessment Plan. pkix-lint
                // does not currently consume an AP, so we point at a
                // self-referential placeholder. Real deployments override.
                "href": "#assessment-plan-placeholder",
            },
            "results": [ result ],
        }
    })
}

// ---------------------------------------------------------------------------
// Per-finding projection
// ---------------------------------------------------------------------------

/// OSCAL Observation projection for one [`Finding`].
///
/// `i` is the finding's position in `report.findings`. The position feeds
/// into the deterministic UUID derivation so two findings sharing all
/// other fields still get distinct Observation UUIDs.
fn observation_for(f: &Finding, report_seed: &[u8], i: usize, collected: &str) -> Value {
    let uuid = uuid_v8(NS_OBSERVATION, &observation_seed(report_seed, i, f));
    let mut description = format!("Lint `{}` ({})", f.lint_id, f.citation);
    if let Some(idx) = f.cert_index {
        description.push_str(&format!(" at chain index {idx}"));
    }
    if let Some(detail) = result_detail(&f.result) {
        description.push_str(&format!(": {detail}"));
    }
    let mut props = Vec::with_capacity(4);
    props.push(prop("pkix-lint.lint-id", &f.lint_id));
    props.push(prop("pkix-lint.citation", &f.citation));
    props.push(prop(
        "pkix-lint.severity",
        lint_result_severity_label(&f.result),
    ));
    if let Some(hash) = f.cert_sha256.as_ref() {
        props.push(prop("pkix-lint.cert-sha256", &hex(hash)));
    }
    let mut obs = json!({
        "uuid": uuid,
        // OSCAL Observation requires `methods`, an array with at least one
        // entry. "EXAMINE" is the OSCAL-defined method indicating
        // automated/manual inspection — the closest fit for an automated
        // cert linter. Other methods are TEST and INTERVIEW.
        "methods": [ "EXAMINE" ],
        "collected": collected,
        "description": description,
        "props": props,
    });
    if let Some(idx) = f.cert_index {
        // Reference the cert as an OSCAL Subject. `subject-uuid` is
        // synthesised deterministically from the chain index so multiple
        // observations of the same cert share a subject identity.
        let subject_uuid = uuid_v8(
            "pkix-lint.oscal.subject.cert",
            &subject_seed(report_seed, idx),
        );
        obs["subjects"] = json!([
            {
                "type": "component",
                "subject-uuid": subject_uuid,
                "title": format!("Certificate at chain index {idx}"),
            }
        ]);
    }
    obs
}

/// OSCAL Finding projection for one [`Finding`].
///
/// Each Finding has a `target` describing what was assessed and its
/// satisfaction state; `related-observations` link back to the Observation
/// carrying the evidence. The same `i` index is used to derive the matched
/// Observation UUID so the link is stable.
fn finding_for(f: &Finding, report_seed: &[u8], i: usize) -> Value {
    let finding_uuid = uuid_v8(NS_FINDING, &observation_seed(report_seed, i, f));
    let observation_uuid = uuid_v8(NS_OBSERVATION, &observation_seed(report_seed, i, f));
    let state = if f.is_finding() {
        "not-satisfied"
    } else {
        "satisfied"
    };
    let mut description = format!("Evaluation of lint `{}` ({})", f.lint_id, f.citation);
    if let Some(detail) = result_detail(&f.result) {
        description.push_str(&format!(": {detail}"));
    }
    json!({
        "uuid": finding_uuid,
        "title": f.lint_id.as_ref(),
        "description": description,
        "target": {
            // OSCAL target.type for a lint check is "objective-id" — we
            // are asserting whether a control-objective was met. The
            // target-id is the lint's stable ID.
            "type": "objective-id",
            "target-id": f.lint_id.as_ref(),
            "status": { "state": state },
        },
        "related-observations": [ { "observation-uuid": observation_uuid } ],
    })
}

/// OSCAL Risk projection for one [`DeviatedFinding`].
fn risk_for(df: &DeviatedFinding, report_seed: &[u8], i: usize) -> Value {
    let uuid = uuid_v8(NS_RISK, &risk_seed(report_seed, i, df));
    let props = vec![
        prop("pkix-lint.lint-id", &df.lint_id),
        prop("pkix-lint.citation", &df.citation),
        prop("pkix-lint.deviation-id", &df.deviation_id),
        prop(
            "pkix-lint.deviation-action",
            deviation_action_label(&df.action),
        ),
    ];
    let mut risk = json!({
        "uuid": uuid,
        "title": format!("Deviation {} applied to {}", df.deviation_id, df.lint_id),
        "description": df.justification.clone(),
        "statement": result_detail(&df.original_result)
            .map(String::from)
            .unwrap_or_else(|| "Original lint result".to_string()),
        "status": "deviation-approved",
        "props": props,
    });
    if let Some(uri) = df.evidence_uri.as_ref() {
        risk["links"] = json!([
            { "href": uri, "rel": "reference", "text": "Deviation evidence" }
        ]);
    }
    risk
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn prop(name: &str, value: &str) -> Value {
    json!({
        "name": name,
        "value": value,
        // OSCAL props live in a `ns` namespace. Pkix-lint owns the
        // `pkix-lint.*` prop names and asserts that here so they don't
        // collide with any future OSCAL-standard props.
        "ns": "https://pkix.rs/oscal/pkix-lint",
    })
}

fn lint_result_severity_label(r: &LintResult) -> &'static str {
    match r {
        LintResult::Pass => "pass",
        LintResult::NotApplicable => "not-applicable",
        LintResult::Warn(_) => "warn",
        LintResult::Error(_) => "error",
        LintResult::Fatal(_) => "fatal",
    }
}

fn result_detail(r: &LintResult) -> Option<&str> {
    match r {
        LintResult::Warn(d) | LintResult::Error(d) | LintResult::Fatal(d) => Some(d.as_ref()),
        LintResult::Pass | LintResult::NotApplicable => None,
    }
}

fn deviation_action_label(a: &DeviationAction) -> &'static str {
    match a {
        DeviationAction::Suppress => "suppress",
        DeviationAction::DowngradeSeverityTo(_) => "downgrade",
    }
}

// ---------------------------------------------------------------------------
// Deterministic UUID derivation (RFC 9562 §5.8 UUIDv8)
// ---------------------------------------------------------------------------

/// Compute a SHA-256-derived RFC 9562 UUIDv8 from a namespace label and
/// caller-supplied seed bytes. The result is the lowercase canonical
/// hyphenated UUID string (`xxxxxxxx-xxxx-8xxx-Nxxx-xxxxxxxxxxxx`, where
/// `8` is the version nibble and `N` ∈ {8, 9, a, b} is the variant nibble).
///
/// We use v8 rather than v5 because v5 is defined to use SHA-1; using
/// SHA-256 here lets us avoid a SHA-1 dependency. UUIDv8 explicitly allows
/// arbitrary 122 bits of custom data with version=8 and variant=10b.
fn uuid_v8(namespace: &str, seed: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(namespace.as_bytes());
    hasher.update([0x00]); // separator
    hasher.update(seed);
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // Set version 8: bits 48..52 (i.e. high nibble of byte 6) = 1000b.
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    // Set variant 10b: bits 64..66 (i.e. top two bits of byte 8).
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

/// Seed bytes for the top-level report UUID. Includes the profile, rule
/// bundle, chain length, and time so two distinct reports do not collide.
fn report_seed(r: &EvaluationReport) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(r.profile_id.as_bytes());
    buf.push(0);
    buf.extend_from_slice(r.profile_version.as_bytes());
    buf.push(0);
    buf.extend_from_slice(r.rule_bundle_version.as_bytes());
    buf.push(0);
    buf.extend_from_slice(&r.chain_length.to_le_bytes());
    buf.extend_from_slice(&r.evaluated_at_unix.to_le_bytes());
    buf
}

/// Seed bytes for an Observation / Finding UUID derived from one
/// [`Finding`]'s position and content.
fn observation_seed(report_seed: &[u8], i: usize, f: &Finding) -> Vec<u8> {
    let mut buf = Vec::with_capacity(report_seed.len() + 64);
    buf.extend_from_slice(report_seed);
    buf.extend_from_slice(&i.to_le_bytes());
    buf.extend_from_slice(f.lint_id.as_bytes());
    buf.push(0);
    buf.push(lint_result_severity_label(&f.result).as_bytes()[0]);
    if let Some(d) = result_detail(&f.result) {
        buf.extend_from_slice(d.as_bytes());
    }
    if let Some(idx) = f.cert_index {
        buf.extend_from_slice(&idx.to_le_bytes());
    }
    if let Some(h) = f.cert_sha256.as_ref() {
        buf.extend_from_slice(h);
    }
    buf
}

/// Seed bytes for a Risk UUID derived from one [`DeviatedFinding`]'s
/// position and content.
fn risk_seed(report_seed: &[u8], i: usize, df: &DeviatedFinding) -> Vec<u8> {
    let mut buf = Vec::with_capacity(report_seed.len() + 64);
    buf.extend_from_slice(report_seed);
    buf.extend_from_slice(&i.to_le_bytes());
    buf.extend_from_slice(df.lint_id.as_bytes());
    buf.push(0);
    buf.extend_from_slice(df.deviation_id.as_bytes());
    buf.push(0);
    buf.extend_from_slice(deviation_action_label(&df.action).as_bytes());
    buf
}

/// Seed bytes for a Subject UUID derived from the certificate's position
/// in the chain.
fn subject_seed(report_seed: &[u8], cert_index: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(report_seed.len() + 8);
    buf.extend_from_slice(report_seed);
    buf.extend_from_slice(&cert_index.to_le_bytes());
    buf
}

// ---------------------------------------------------------------------------
// Hex encoding
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(hex_digit(b >> 4));
        s.push(hex_digit(b & 0x0f));
    }
    s
}

fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + nibble - 10) as char,
        _ => unreachable!("nibble must be in 0..=15"),
    }
}

// ---------------------------------------------------------------------------
// Unix-seconds → RFC 3339 (UTC, no fractional, suffix Z)
// ---------------------------------------------------------------------------

/// Format a Unix-epoch second count as `YYYY-MM-DDTHH:MM:SSZ`.
///
/// Uses Howard Hinnant's "civil_from_days" algorithm — the same approach
/// used in `pkix-difftest/src/corpus/limbo.rs` and
/// `pkix-path-builder/tests/bettertls.rs`. Inlined here to avoid a chrono
/// / time dependency.
///
/// # Panics
///
/// Panics if `unix` exceeds [`i64::MAX`] / 86_400 days (year ~292 billion);
/// in practice the cap is `u64::MAX` and no realistic input triggers it.
fn unix_to_rfc3339(unix: u64) -> String {
    let unix_i64 = i64::try_from(unix).expect("unix seconds out of i64 range");
    let days_since_epoch = unix_i64.div_euclid(86_400);
    let secs_of_day = unix_i64.rem_euclid(86_400);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    // civil_from_days: invert the same algorithm used in the reverse
    // direction by limbo.rs / bettertls.rs.
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, m, d, hour, minute, second
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::EvaluationReport;
    use crate::{Finding, LintResult};
    use std::borrow::Cow;

    fn pass_finding(lint_id: &'static str, cert_index: Option<usize>) -> Finding {
        Finding {
            lint_id: Cow::Borrowed(lint_id),
            citation: Cow::Borrowed("RFC 5280 §X.Y"),
            rule_bundle_version: Cow::Borrowed("test-bundle-v1"),
            result: LintResult::Pass,
            cert_index,
            evaluated_at_unix: 1_780_272_000,
            cert_sha256: None,
        }
    }

    fn error_finding(lint_id: &'static str, detail: &'static str) -> Finding {
        Finding {
            result: LintResult::error(detail),
            ..pass_finding(lint_id, Some(0))
        }
    }

    fn warn_finding_with_hash(lint_id: &'static str, hash: [u8; 32]) -> Finding {
        Finding {
            result: LintResult::warn("advisory"),
            cert_sha256: Some(hash),
            ..pass_finding(lint_id, Some(1))
        }
    }

    fn sample_report() -> EvaluationReport {
        let mut r = EvaluationReport::new(
            "cabf.br.tls",
            "SC-081",
            "pkix-lint/cabf_tls_br v0.2.0",
            2,
            1_780_272_000, // 2026-06-01T00:00:00Z — see test_rfc3339_known_value
        );
        r.findings
            .push(pass_finding("test.lint.always-pass", Some(0)));
        r.findings
            .push(error_finding("test.lint.error", "something failed"));
        let mut hash = [0u8; 32];
        for (i, b) in hash.iter_mut().enumerate() {
            *b = i as u8;
        }
        r.findings
            .push(warn_finding_with_hash("test.lint.warn", hash));
        r
    }

    // -------------------------------------------------------------------
    // RFC 3339 unit
    // Oracle: hand-computed against the well-known Unix epoch and a
    // sampled date. 1_780_272_000 = 2026-05-31 20:40:00 UTC was confirmed
    // independently with `date -u -d "@1780272000"` before commit.
    // -------------------------------------------------------------------

    #[test]
    fn test_rfc3339_unix_epoch() {
        assert_eq!(unix_to_rfc3339(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn test_rfc3339_known_value() {
        // Independent oracle (Unix `date -u -d @1780272000`):
        //   Mon Jun  1 12:00:00 AM UTC 2026
        // i.e. 2026-06-01T00:00:00Z. Encoded as a regression vector.
        assert_eq!(unix_to_rfc3339(1_780_272_000), "2026-06-01T00:00:00Z");
    }

    #[test]
    fn test_rfc3339_y2038_boundary() {
        // 2147483648 = 2038-01-19T03:14:08Z (the second past i32 overflow).
        // Independent oracle: `date -u -d "@2147483648"` =
        //   Tue Jan 19 03:14:08 AM UTC 2038
        assert_eq!(unix_to_rfc3339(2_147_483_648), "2038-01-19T03:14:08Z");
    }

    #[test]
    fn test_rfc3339_leap_year_feb_29() {
        // 2024-02-29T00:00:00Z = 1709164800. Oracle: `date -u -d "@1709164800"`.
        assert_eq!(unix_to_rfc3339(1_709_164_800), "2024-02-29T00:00:00Z");
    }

    // -------------------------------------------------------------------
    // UUID derivation unit
    // Oracle: independent SHA-256 computation. The expected digest is the
    // SHA-256 of (namespace || 0x00 || seed). We do not assert the exact
    // UUID string (we trust the formatting); we assert that the first 16
    // bytes of the digest map to the expected version+variant nibbles,
    // and that the value is reproducible.
    // -------------------------------------------------------------------

    #[test]
    fn test_uuid_v8_version_and_variant_bits() {
        let id = uuid_v8("test-ns", b"seed-data");
        // Hyphenated layout: xxxxxxxx-xxxx-Vxxx-Yxxx-xxxxxxxxxxxx
        // where V is the version nibble (must be '8') and Y is the variant
        // nibble first hex digit (must be in {8, 9, a, b}).
        assert_eq!(id.len(), 36, "canonical UUID length");
        let chars: Vec<char> = id.chars().collect();
        assert_eq!(chars[14], '8', "version nibble must be 8 (UUIDv8)");
        assert!(
            matches!(chars[19], '8' | '9' | 'a' | 'b'),
            "variant nibble first hex must be in {{8, 9, a, b}}, got {}",
            chars[19]
        );
    }

    #[test]
    fn test_uuid_v8_deterministic() {
        let a = uuid_v8("ns", b"same-input");
        let b = uuid_v8("ns", b"same-input");
        assert_eq!(a, b, "UUIDv8 must be deterministic for identical input");
    }

    #[test]
    fn test_uuid_v8_namespace_isolates() {
        let a = uuid_v8("ns-a", b"shared-seed");
        let b = uuid_v8("ns-b", b"shared-seed");
        assert_ne!(a, b, "different namespaces must yield different UUIDs");
    }

    // -------------------------------------------------------------------
    // Emitter structural tests
    // Oracle: NIST OSCAL v1.1.2 Assessment Results JSON Schema required
    // fields and types. We assert presence and type, not the exact byte
    // shape of variable content (UUIDs, timestamps).
    // -------------------------------------------------------------------

    #[test]
    fn test_emit_top_level_shape() {
        let r = sample_report();
        let v = assessment_results(&r);
        let ar = v.get("assessment-results").expect("top-level wrapper");
        assert!(
            ar.get("uuid").and_then(Value::as_str).is_some(),
            "uuid string"
        );
        let md = ar.get("metadata").expect("metadata");
        assert_eq!(
            md.get("oscal-version").and_then(Value::as_str),
            Some("1.1.2")
        );
        assert!(md.get("last-modified").and_then(Value::as_str).is_some());
        assert!(md.get("title").and_then(Value::as_str).is_some());
        assert!(md.get("version").and_then(Value::as_str).is_some());
        assert!(md.get("props").and_then(Value::as_array).is_some());
        assert!(ar.get("import-ap").and_then(|i| i.get("href")).is_some());
        let results = ar
            .get("results")
            .and_then(Value::as_array)
            .expect("results");
        assert_eq!(results.len(), 1, "exactly one Result per run");
    }

    #[test]
    fn test_emit_observations_and_findings_aligned() {
        let r = sample_report();
        let v = assessment_results(&r);
        let result = &v["assessment-results"]["results"][0];
        let obs = result["observations"].as_array().expect("observations");
        let findings = result["findings"].as_array().expect("findings");
        assert_eq!(obs.len(), r.findings.len(), "1:1 observation per finding");
        assert_eq!(findings.len(), r.findings.len(), "1:1 finding per finding");
        // Each Finding's related-observations[0].observation-uuid must
        // reference the corresponding Observation's uuid.
        for (o, f) in obs.iter().zip(findings.iter()) {
            let o_uuid = o["uuid"].as_str().expect("observation uuid");
            let ref_uuid = f["related-observations"][0]["observation-uuid"]
                .as_str()
                .expect("related-observations uuid");
            assert_eq!(
                o_uuid, ref_uuid,
                "Finding must link to its Observation by uuid"
            );
        }
    }

    #[test]
    fn test_emit_target_status_state_reflects_severity() {
        let r = sample_report();
        let v = assessment_results(&r);
        let findings = v["assessment-results"]["results"][0]["findings"]
            .as_array()
            .expect("findings");
        // sample_report() index 0 = Pass (satisfied), 1 = Error (not-satisfied),
        // 2 = Warn (not-satisfied).
        let states: Vec<&str> = findings
            .iter()
            .map(|f| f["target"]["status"]["state"].as_str().unwrap())
            .collect();
        assert_eq!(states, vec!["satisfied", "not-satisfied", "not-satisfied"]);
    }

    #[test]
    fn test_emit_cert_sha256_propagates_to_observation_props() {
        let r = sample_report();
        let v = assessment_results(&r);
        let obs = &v["assessment-results"]["results"][0]["observations"][2];
        let props = obs["props"].as_array().expect("props");
        let hash_prop = props
            .iter()
            .find(|p| p["name"].as_str() == Some("pkix-lint.cert-sha256"))
            .expect("cert-sha256 prop on hash-bearing observation");
        let expected_hex: String = (0u8..32).map(|b| format!("{b:02x}")).collect();
        assert_eq!(hash_prop["value"].as_str(), Some(expected_hex.as_str()));
    }

    #[test]
    fn test_emit_no_findings_omits_optional_arrays() {
        // OSCAL Result requires `uuid`, `title`, `description`, `start`,
        // `end`, and `reviewed-controls`. Observations / findings / risks
        // are optional and should be omitted when empty so the output
        // stays minimal.
        let r = EvaluationReport::new("p", "v", "rbv", 1, 0);
        let v = assessment_results(&r);
        let result = &v["assessment-results"]["results"][0];
        assert!(
            result.get("observations").is_none(),
            "no observations array"
        );
        assert!(result.get("findings").is_none(), "no findings array");
        assert!(result.get("risks").is_none(), "no risks array");
    }

    #[test]
    fn test_emit_deviated_finding_becomes_risk() {
        use crate::deviation::{DeviatedFinding, DeviationAction};
        let mut r = EvaluationReport::new("p", "v", "rbv", 1, 0);
        r.deviated_findings.push(DeviatedFinding {
            lint_id: Cow::Borrowed("test.lint.x"),
            citation: Cow::Borrowed("RFC X"),
            original_result: LintResult::error("would-be-error"),
            deviation_id: "DEV-2026-001".to_string(),
            action: DeviationAction::Suppress,
            justification: "approved by maintainer 2026-05-11".to_string(),
            evidence_uri: Some("https://example.com/waiver/42".to_string()),
            cert_index: Some(0),
            evaluated_at_unix: 0,
        });
        let v = assessment_results(&r);
        let risks = v["assessment-results"]["results"][0]["risks"]
            .as_array()
            .expect("risks");
        assert_eq!(risks.len(), 1);
        let risk = &risks[0];
        assert_eq!(risk["status"].as_str(), Some("deviation-approved"));
        assert_eq!(
            risk["description"].as_str(),
            Some("approved by maintainer 2026-05-11")
        );
        let links = risk["links"].as_array().expect("links");
        assert_eq!(
            links[0]["href"].as_str(),
            Some("https://example.com/waiver/42")
        );
    }

    // -------------------------------------------------------------------
    // Round-trip
    // Oracle: serde_json's own parser. Emit, stringify, parse, compare.
    // -------------------------------------------------------------------

    #[test]
    fn test_round_trip_serialize_parse() {
        let r = sample_report();
        let v = assessment_results(&r);
        let s = serde_json::to_string(&v).expect("serialize Value to JSON");
        let v2: Value = serde_json::from_str(&s).expect("parse JSON back to Value");
        assert_eq!(
            v, v2,
            "OSCAL output must round-trip byte-equal through serde_json"
        );
    }

    // -------------------------------------------------------------------
    // Determinism
    // Two calls on the same input must produce byte-identical output.
    // Important for CI diffing of evidence packs and for reproducibility
    // when the same lint run is replayed.
    // -------------------------------------------------------------------

    #[test]
    fn test_emit_deterministic() {
        let r = sample_report();
        let a = serde_json::to_string(&assessment_results(&r)).unwrap();
        let b = serde_json::to_string(&assessment_results(&r)).unwrap();
        assert_eq!(a, b, "emit must be deterministic for identical input");
    }

    // -------------------------------------------------------------------
    // Hex helper
    // Oracle: hex::encode in the workspace, here hand-verified literals.
    // -------------------------------------------------------------------

    #[test]
    fn test_hex_encode_lowercase() {
        assert_eq!(hex(&[0x00, 0xff, 0xab, 0xcd]), "00ffabcd");
        assert_eq!(hex(&[]), "");
    }
}
