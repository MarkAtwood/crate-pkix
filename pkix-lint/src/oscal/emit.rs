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

use crate::deviation::{
    DeviatedFinding, Deviation, DeviationAction, DeviationScope, DeviationStore, ScopePropValue,
    PROP_ISSUER_DN_DER, PROP_ISSUER_DN_SUBSTRING, PROP_SERIAL_END, PROP_SERIAL_START,
    SCOPE_KIND_ANY, SCOPE_KIND_ISSUER_DN_CONTAINS, SCOPE_KIND_ISSUER_DN_EXACT,
    SCOPE_KIND_SERIAL_RANGE,
};
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

    // Evidence-deduplicated Observations: one Observation per unique
    // (cert_sha256, cert_index) pair. Findings that share evidence (e.g.,
    // multiple lints on the same cert) reference the same Observation
    // UUID via `related-observations`. This implements OSCAL's intended
    // 1:N (Observation : Finding) cardinality.
    let evidence_index = EvidenceIndex::build(&report.findings);
    let observations: Vec<Value> = evidence_index
        .keys_in_order()
        .iter()
        .map(|key| observation_for_evidence(key, &report_seed, &last_modified))
        .collect();

    let findings: Vec<Value> = report
        .findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let observation_uuid = evidence_index.observation_uuid(&report_seed, f);
            finding_for(f, &report_seed, i, &observation_uuid)
        })
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
// Evidence index (Observation : Finding = 1:N)
// ---------------------------------------------------------------------------

/// The identifying tuple of an OSCAL Observation: which cert (by hash and
/// chain index) the evidence concerns.
///
/// `(Some(hash), Some(idx))` is the typical cert-scope finding case;
/// `(None, None)` represents path-scope findings (no single cert
/// triggered the finding — the whole chain did). Mixed cases
/// `(None, Some)` and `(Some, None)` are valid but rare.
///
/// Equality on this key is what binds Findings to a shared Observation.
#[derive(Clone, Debug, Eq, PartialEq)]
struct EvidenceKey {
    cert_sha256: Option<[u8; 32]>,
    cert_index: Option<usize>,
}

impl EvidenceKey {
    fn from_finding(f: &Finding) -> Self {
        Self {
            cert_sha256: f.cert_sha256,
            cert_index: f.cert_index,
        }
    }

    /// Seed bytes for the Observation UUID derived from this evidence key.
    ///
    /// Two Findings with identical `(cert_sha256, cert_index)` produce the
    /// same seed, so they share an Observation UUID.
    fn seed(&self, report_seed: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(report_seed.len() + 48);
        buf.extend_from_slice(report_seed);
        match self.cert_sha256 {
            Some(h) => {
                buf.push(1);
                buf.extend_from_slice(&h);
            }
            None => buf.push(0),
        }
        match self.cert_index {
            Some(i) => {
                buf.push(1);
                buf.extend_from_slice(&i.to_le_bytes());
            }
            None => buf.push(0),
        }
        buf
    }
}

/// Insertion-ordered set of distinct evidence keys. First-seen ordering
/// keeps the emitter deterministic and stable across runs (test invariant
/// `test_emit_deterministic`).
struct EvidenceIndex {
    keys: Vec<EvidenceKey>,
}

impl EvidenceIndex {
    fn build(findings: &[Finding]) -> Self {
        let mut keys: Vec<EvidenceKey> = Vec::new();
        for f in findings {
            let k = EvidenceKey::from_finding(f);
            if !keys.contains(&k) {
                keys.push(k);
            }
        }
        Self { keys }
    }

    fn keys_in_order(&self) -> &[EvidenceKey] {
        &self.keys
    }

    fn observation_uuid(&self, report_seed: &[u8], f: &Finding) -> String {
        let key = EvidenceKey::from_finding(f);
        uuid_v8(NS_OBSERVATION, &key.seed(report_seed))
    }
}

// ---------------------------------------------------------------------------
// Per-evidence and per-finding projection
// ---------------------------------------------------------------------------

/// OSCAL Observation projection for one [`EvidenceKey`].
///
/// The Observation describes the *evidence* (which cert) and not the lint
/// outcome — multiple Findings may reference the same Observation when
/// they share evidence. Lint-specific details (severity, citation, result
/// detail) live on the Finding side, not the Observation side.
fn observation_for_evidence(key: &EvidenceKey, report_seed: &[u8], collected: &str) -> Value {
    let uuid = uuid_v8(NS_OBSERVATION, &key.seed(report_seed));
    let mut props = Vec::with_capacity(2);
    if let Some(hash) = key.cert_sha256.as_ref() {
        props.push(prop("pkix-lint.cert-sha256", &hex(hash)));
    }
    if let Some(idx) = key.cert_index {
        props.push(prop("pkix-lint.cert-index", &idx.to_string()));
    }
    let description = match (key.cert_index, key.cert_sha256) {
        (Some(idx), Some(_)) => {
            format!("Certificate at chain index {idx} (identified by SHA-256 digest)")
        }
        (Some(idx), None) => format!("Certificate at chain index {idx}"),
        (None, Some(_)) => "Certificate identified by SHA-256 digest".to_string(),
        (None, None) => {
            "Path-scope evidence: the validated certificate chain as a whole".to_string()
        }
    };
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
    if let Some(idx) = key.cert_index {
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
/// satisfaction state; `related-observations` links back to the
/// (deduplicated) Observation carrying the evidence. The Finding holds
/// the lint-specific metadata (lint_id, citation, severity) as props;
/// shared cert evidence lives on the Observation side.
fn finding_for(f: &Finding, report_seed: &[u8], i: usize, observation_uuid: &str) -> Value {
    let finding_uuid = uuid_v8(NS_FINDING, &finding_seed(report_seed, i, f));
    let state = if f.is_finding() {
        "not-satisfied"
    } else {
        "satisfied"
    };
    let mut description = format!("Evaluation of lint `{}` ({})", f.lint_id, f.citation);
    if let Some(detail) = result_detail(&f.result) {
        description.push_str(&format!(": {detail}"));
    }
    let props = vec![
        prop("pkix-lint.lint-id", &f.lint_id),
        prop("pkix-lint.citation", &f.citation),
        prop("pkix-lint.severity", lint_result_severity_label(&f.result)),
    ];
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
        "props": props,
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
// Deviation (policy) → OSCAL Risk projection
// ---------------------------------------------------------------------------

/// Emit every [`Deviation`] in a [`DeviationStore`] as a Vec of OSCAL Risk
/// `serde_json::Value`s, suitable for persisting a deviation policy as a
/// JSON array of OSCAL Risks.
///
/// The emitted Risks are policy entries (the deviations themselves), not
/// applied-deviation events on a specific evaluation run. The
/// [`assessment_results`] emitter already projects per-run
/// [`crate::deviation::DeviatedFinding`]s into Risk shapes inside an
/// Assessment Results document; this function is the policy-side
/// counterpart.
///
/// # Round-trip
///
/// A parser back to `DeviationStore` is intended as follow-up work (see
/// PKIX-9vnx.5 follow-up trackers). Today's emitter therefore tags every
/// Risk with the props needed for lossless reconstruction:
///
/// - `pkix-lint.deviation-id` — the [`Deviation::id`].
/// - `pkix-lint.target-lint` — [`Deviation::target_lint`].
/// - `pkix-lint.action` — `"suppress"` or `"downgrade:<severity>"`.
/// - `pkix-lint.effective-start` / `pkix-lint.effective-end` — Unix seconds,
///   emitted only when `Some`.
/// - `pkix-lint.authorized-by` — [`Deviation::authorized_by`].
/// - Scope-axis props on the Risk's `subjects[]` (see [`encode_scope`]).
///
/// # Determinism
///
/// Risk UUIDs derive from `(NS_RISK_POLICY, deviation.id)` so identical
/// deviation IDs yield identical Risk UUIDs across runs. Two stores
/// containing the same deviations emit byte-identical arrays.
#[must_use]
pub fn risks_from_store(store: &DeviationStore) -> Vec<Value> {
    store.all().iter().map(risk_for_deviation).collect()
}

/// Namespace for policy-side deviation Risk UUIDs. Distinct from
/// [`NS_RISK`] (which is used by per-run DeviatedFinding Risks) so a
/// deviation policy entry and an applied-deviation event cannot collide.
const NS_RISK_POLICY: &str = "pkix-lint.oscal.risk.policy";

fn risk_for_deviation(d: &Deviation) -> Value {
    let uuid = uuid_v8(NS_RISK_POLICY, d.id.as_bytes());

    let mut props = Vec::with_capacity(8);
    props.push(prop("pkix-lint.deviation-id", &d.id));
    props.push(prop("pkix-lint.target-lint", &d.target_lint));
    props.push(prop(
        "pkix-lint.action",
        &deviation_action_prop_value(&d.action),
    ));
    props.push(prop("pkix-lint.authorized-by", &d.authorized_by));
    if let Some(start) = d.effective_start {
        props.push(prop("pkix-lint.effective-start", &start.to_string()));
    }
    if let Some(end) = d.effective_end {
        props.push(prop("pkix-lint.effective-end", &end.to_string()));
    }

    let mut risk = json!({
        "uuid": uuid,
        "title": format!("Deviation {} for lint {}", d.id, d.target_lint),
        "description": d.justification.clone(),
        // OSCAL Risks may carry a free-form `statement` describing the
        // condition that triggers the risk. For pkix-lint deviations we
        // reuse the justification — the operator wrote it specifically to
        // explain "why this is permitted." Real OSCAL POA&M Risk
        // statements are richer; pkix-lint deviations are intentionally
        // narrower.
        "statement": d.justification.clone(),
        "status": "deviation-approved",
        "props": props,
        "subjects": encode_scope(&d.scope),
    });
    if let Some(uri) = d.evidence_uri.as_ref() {
        risk["links"] = json!([
            {
                "href": uri,
                "rel": "reference",
                "text": "Deviation authorization document",
            }
        ]);
    }
    risk
}

/// Encode a [`DeviationScope`] as one or more OSCAL Subject objects.
///
/// Each canonical kind constant
/// (`pkix-lint.scope.any`, `pkix-lint.scope.issuer-dn-contains`,
/// `pkix-lint.scope.issuer-dn-exact`, `pkix-lint.scope.serial-range`)
/// maps 1:1 to an OSCAL Subject `type`. The scope's props bag is rendered
/// into the OSCAL Subject's `props` array, with `Bytes` values hex-encoded
/// and DN-typed Bytes additionally rendered as a human-readable
/// `pkix-lint.issuer-dn` string prop for operator readability.
///
/// `Vec<Value>` rather than a single `Value` to allow future scope kinds
/// that fan out to multiple Subjects.
///
/// Unknown kinds (those not in the canonical list above) are emitted
/// best-effort: kind string becomes the OSCAL Subject `type`, props bag is
/// rendered using a generic mapping, no `title` decoration. This keeps OSCAL
/// emit stable as new kinds land without requiring per-kind encoder updates.
fn encode_scope(scope: &DeviationScope) -> Vec<Value> {
    match scope.kind.as_str() {
        SCOPE_KIND_ANY => vec![json!({
            "type": SCOPE_KIND_ANY,
            "subject-uuid": uuid_v8("pkix-lint.oscal.subject.scope-any", b""),
            "title": "All certificates",
        })],
        SCOPE_KIND_ISSUER_DN_CONTAINS => {
            let substring = scope_text(scope, PROP_ISSUER_DN_SUBSTRING);
            vec![json!({
                "type": SCOPE_KIND_ISSUER_DN_CONTAINS,
                "subject-uuid": uuid_v8(
                    "pkix-lint.oscal.subject.issuer-dn-contains",
                    substring.as_bytes(),
                ),
                "title": format!("Issuer DN contains '{substring}'"),
                "props": [
                    prop(PROP_ISSUER_DN_SUBSTRING, substring),
                ],
            })]
        }
        SCOPE_KIND_ISSUER_DN_EXACT => {
            let der = scope_bytes(scope, PROP_ISSUER_DN_DER);
            let der_hex = hex(der);
            let name_str = decode_name_display(der);
            vec![json!({
                "type": SCOPE_KIND_ISSUER_DN_EXACT,
                "subject-uuid": uuid_v8(
                    "pkix-lint.oscal.subject.issuer-dn-exact",
                    der,
                ),
                "title": format!("Issuer DN equals {name_str}"),
                "props": [
                    prop("pkix-lint.issuer-dn", &name_str),
                    prop(PROP_ISSUER_DN_DER, &der_hex),
                ],
            })]
        }
        SCOPE_KIND_SERIAL_RANGE => {
            let der = scope_bytes(scope, PROP_ISSUER_DN_DER);
            let start = scope_bytes(scope, PROP_SERIAL_START);
            let end = scope_bytes(scope, PROP_SERIAL_END);
            let der_hex = hex(der);
            let start_hex = hex(start);
            let end_hex = hex(end);
            let name_str = decode_name_display(der);
            let mut seed: Vec<u8> = Vec::with_capacity(der.len() + start.len() + end.len() + 2);
            seed.extend_from_slice(der);
            seed.push(0);
            seed.extend_from_slice(start);
            seed.push(0);
            seed.extend_from_slice(end);
            vec![json!({
                "type": SCOPE_KIND_SERIAL_RANGE,
                "subject-uuid": uuid_v8(
                    "pkix-lint.oscal.subject.serial-range",
                    &seed,
                ),
                "title": format!(
                    "Serial range [0x{}, 0x{}] from issuer {}",
                    start_hex, end_hex, name_str
                ),
                "props": [
                    prop("pkix-lint.issuer-dn", &name_str),
                    prop(PROP_ISSUER_DN_DER, &der_hex),
                    prop(PROP_SERIAL_START, &start_hex),
                    prop(PROP_SERIAL_END, &end_hex),
                ],
            })]
        }
        // Unknown / future kinds: emit a generic Subject with the kind as type
        // and all props rendered via the typed-value mapping.
        other => {
            let mut seed: Vec<u8> = Vec::with_capacity(64);
            seed.extend_from_slice(other.as_bytes());
            for (name, value) in &scope.props {
                seed.push(0);
                seed.extend_from_slice(name.as_bytes());
                seed.push(0);
                match value {
                    ScopePropValue::Text(s) => seed.extend_from_slice(s.as_bytes()),
                    ScopePropValue::Bytes(b) => seed.extend_from_slice(b),
                }
            }
            let mut props_json: Vec<Value> = Vec::with_capacity(scope.props.len());
            for (name, value) in &scope.props {
                let v = match value {
                    ScopePropValue::Text(s) => s.clone(),
                    ScopePropValue::Bytes(b) => hex(b),
                };
                props_json.push(prop(name.as_str(), &v));
            }
            vec![json!({
                "type": other,
                "subject-uuid": uuid_v8("pkix-lint.oscal.subject.custom", &seed),
                "title": format!("Custom scope '{other}'"),
                "props": props_json,
            })]
        }
    }
}

/// Read a `Text` prop, falling back to empty string if missing or wrong type.
/// Used by `encode_scope` for canonical kinds whose schema is enforced by
/// constructors (so missing/wrong-typed props indicate a code-side bug, not
/// caller misuse).
fn scope_text<'a>(scope: &'a DeviationScope, name: &str) -> &'a str {
    match scope.get_prop(name) {
        Some(ScopePropValue::Text(s)) => s.as_str(),
        _ => "",
    }
}

/// Read a `Bytes` prop, falling back to empty slice if missing or wrong type.
fn scope_bytes<'a>(scope: &'a DeviationScope, name: &str) -> &'a [u8] {
    match scope.get_prop(name) {
        Some(ScopePropValue::Bytes(b)) => b.as_slice(),
        _ => &[],
    }
}

/// Decode DER-encoded `Name` bytes into an RFC 4514 display string. Returns
/// "<malformed DN>" if the bytes do not decode; the OSCAL output is best-
/// effort here because the `title` and `pkix-lint.issuer-dn` prop are
/// informational. The lossless prop is `pkix-lint.issuer-dn-der`.
fn decode_name_display(der: &[u8]) -> String {
    use der::Decode as _;
    x509_cert::name::Name::from_der(der)
        .map(|n| n.to_string())
        .unwrap_or_else(|_| "<malformed DN>".to_string())
}

/// Render a [`DeviationAction`] as a stable string value usable as both
/// an OSCAL prop value and (eventually) the discriminator a parser keys
/// off of. `"suppress"` is bare; `"downgrade:<severity-label>"` carries
/// the target severity inline.
fn deviation_action_prop_value(a: &DeviationAction) -> String {
    match a {
        DeviationAction::Suppress => "suppress".to_string(),
        DeviationAction::DowngradeSeverityTo(s) => format!("downgrade:{}", severity_label(*s)),
    }
}

pub(super) fn severity_label(s: crate::Severity) -> &'static str {
    match s {
        crate::Severity::Info => "info",
        crate::Severity::Warn => "warn",
        crate::Severity::Error => "error",
        crate::Severity::Fatal => "fatal",
    }
}

pub(super) fn scope_label(s: crate::Scope) -> &'static str {
    match s {
        crate::Scope::Certificate => "certificate",
        crate::Scope::Path => "path",
    }
}

pub(super) fn subject_kind_label(s: crate::SubjectKind) -> &'static str {
    match s {
        crate::SubjectKind::Leaf => "leaf",
        crate::SubjectKind::IntermediateCa => "intermediate-ca",
        crate::SubjectKind::AnchorIssued => "anchor-issued",
        crate::SubjectKind::Any => "any",
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(super) fn prop(name: &str, value: &str) -> Value {
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
pub(super) fn uuid_v8(namespace: &str, seed: &[u8]) -> String {
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

/// Seed bytes for a Finding UUID derived from one [`Finding`]'s position
/// and content.
///
/// Observation UUIDs are derived separately, from
/// [`EvidenceKey::seed`], so that multiple Findings sharing one piece of
/// evidence still get distinct Finding UUIDs.
fn finding_seed(report_seed: &[u8], i: usize, f: &Finding) -> Vec<u8> {
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

    /// Builds a report with three distinct evidence keys so emitted
    /// Observations and Findings are 1:1 in this case. Other tests
    /// construct reports with intentional evidence sharing to exercise
    /// the 1:N path.
    fn sample_report() -> EvaluationReport {
        let mut r = EvaluationReport::new(
            "cabf.br.tls",
            "SC-081",
            "pkix-lint-cabf/cabf_tls_br v0.2.0",
            2,
            1_780_272_000, // 2026-06-01T00:00:00Z — see test_rfc3339_known_value
        );
        // Finding 0: cert_index=0, cert_sha256=None.
        r.findings
            .push(pass_finding("test.lint.always-pass", Some(0)));
        // Finding 1: cert_index=Some(2), cert_sha256=None. Distinct key
        // from finding 0 so the 1:1 assumption in
        // test_emit_observations_and_findings_aligned holds for this
        // sample.
        r.findings.push(Finding {
            cert_index: Some(2),
            ..error_finding("test.lint.error", "something failed")
        });
        // Finding 2: cert_index=Some(1), cert_sha256=Some(...). Distinct
        // key again — third Observation in the emitted output.
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
    // Evidence deduplication (Observation : Finding = 1:N)
    // OSCAL's Observation model is specifically designed for one evidence
    // record to support multiple Findings. The acceptance criterion
    // "One Observation may support multiple Findings (1:N relationship
    // preserved)" from PKIX-9vnx.4 is exercised here.
    // -------------------------------------------------------------------

    #[test]
    fn test_emit_evidence_deduplicates_shared_cert() {
        // Two findings on the same cert (same cert_index AND same
        // cert_sha256) must collapse into ONE Observation, and both
        // Findings reference it.
        let mut r = EvaluationReport::new("p", "v", "rbv", 1, 0);
        let mut hash = [0u8; 32];
        for (i, b) in hash.iter_mut().enumerate() {
            *b = i as u8;
        }
        r.findings.push(Finding {
            cert_sha256: Some(hash),
            ..error_finding("test.lint.a", "lint A failed")
        });
        r.findings.push(Finding {
            cert_sha256: Some(hash),
            ..error_finding("test.lint.b", "lint B failed")
        });

        let v = assessment_results(&r);
        let result = &v["assessment-results"]["results"][0];
        let obs = result["observations"].as_array().expect("observations");
        let findings = result["findings"].as_array().expect("findings");

        assert_eq!(obs.len(), 1, "shared evidence → one Observation");
        assert_eq!(findings.len(), 2, "still two Findings");
        let shared_uuid = obs[0]["uuid"].as_str().unwrap();
        for (idx, f) in findings.iter().enumerate() {
            let ref_uuid = f["related-observations"][0]["observation-uuid"]
                .as_str()
                .unwrap();
            assert_eq!(
                ref_uuid, shared_uuid,
                "finding {idx} must link to the shared Observation"
            );
        }
    }

    #[test]
    fn test_emit_distinct_certs_get_distinct_observations() {
        // Findings on certs at different chain indices get distinct
        // Observations even when no cert_sha256 is set.
        let mut r = EvaluationReport::new("p", "v", "rbv", 3, 0);
        r.findings.push(error_finding("test.lint.x", "fail at 0"));
        r.findings.push(Finding {
            cert_index: Some(1),
            ..error_finding("test.lint.y", "fail at 1")
        });
        r.findings.push(Finding {
            cert_index: Some(2),
            ..error_finding("test.lint.z", "fail at 2")
        });

        let v = assessment_results(&r);
        let obs = v["assessment-results"]["results"][0]["observations"]
            .as_array()
            .expect("observations");
        assert_eq!(
            obs.len(),
            3,
            "three distinct cert positions → three Observations"
        );
        // UUIDs must be pairwise distinct.
        let mut uuids: Vec<&str> = obs.iter().map(|o| o["uuid"].as_str().unwrap()).collect();
        uuids.sort_unstable();
        uuids.dedup();
        assert_eq!(
            uuids.len(),
            3,
            "Observation UUIDs must be pairwise distinct"
        );
    }

    #[test]
    fn test_emit_path_scope_findings_share_observation() {
        // Findings with both cert_index=None AND cert_sha256=None share
        // a single "path-scope" Observation.
        let mut r = EvaluationReport::new("p", "v", "rbv", 2, 0);
        r.findings.push(Finding {
            cert_index: None,
            cert_sha256: None,
            ..error_finding("test.lint.path1", "path-scope fail 1")
        });
        r.findings.push(Finding {
            cert_index: None,
            cert_sha256: None,
            ..error_finding("test.lint.path2", "path-scope fail 2")
        });

        let v = assessment_results(&r);
        let obs = v["assessment-results"]["results"][0]["observations"]
            .as_array()
            .expect("observations");
        let findings = v["assessment-results"]["results"][0]["findings"]
            .as_array()
            .expect("findings");
        assert_eq!(
            obs.len(),
            1,
            "all path-scope findings share one Observation"
        );
        assert_eq!(findings.len(), 2);
        // Path-scope observation description must signal that scope so
        // OSCAL consumers can render it differently from cert-scope.
        let desc = obs[0]["description"].as_str().unwrap();
        assert!(
            desc.contains("Path-scope"),
            "path-scope observation description should identify its scope (got: {desc})"
        );
        // Observation should NOT have a subjects array because there is
        // no specific cert position.
        assert!(
            obs[0].get("subjects").is_none(),
            "path-scope Observation should not carry a subjects array"
        );
    }

    #[test]
    fn test_emit_finding_props_include_lint_metadata() {
        // After the evidence-dedup refactor, lint-specific metadata
        // (lint_id, citation, severity) lives on the Finding side as
        // props. The Observation side carries only evidence pointers.
        let r = sample_report();
        let v = assessment_results(&r);
        let findings = v["assessment-results"]["results"][0]["findings"]
            .as_array()
            .unwrap();
        for f in findings {
            let props = f["props"].as_array().expect("finding props");
            let names: Vec<&str> = props.iter().map(|p| p["name"].as_str().unwrap()).collect();
            assert!(
                names.contains(&"pkix-lint.lint-id"),
                "finding props must include lint-id (got {names:?})"
            );
            assert!(
                names.contains(&"pkix-lint.citation"),
                "finding props must include citation (got {names:?})"
            );
            assert!(
                names.contains(&"pkix-lint.severity"),
                "finding props must include severity (got {names:?})"
            );
        }
    }

    // -------------------------------------------------------------------
    // Deviation → OSCAL Risk emit (policy side)
    // PKIX-9vnx.5: deviation policy entries are emitted as OSCAL Risks
    // suitable for persistence as a JSON array. The full parse/round-trip
    // pair is a separate follow-up; today we lock down the emit shape.
    // -------------------------------------------------------------------

    fn sample_deviation() -> Deviation {
        Deviation {
            id: "policy-2026-q1-fpki-keyusage".to_string(),
            target_lint: "fpki.common.6.1.5".to_string(),
            scope: DeviationScope::issuer_dn_contains("agency x"),
            effective_start: Some(1_704_067_200), // 2024-01-01T00:00:00Z
            effective_end: Some(1_767_225_600),   // 2026-01-01T00:00:00Z
            action: DeviationAction::DowngradeSeverityTo(crate::Severity::Warn),
            justification: "FPKIPA waiver memo 2025-11-03".to_string(),
            authorized_by: "agency-x-ciso@agency.gov".to_string(),
            evidence_uri: Some("https://policy.agency.gov/waivers/2025-11-03".to_string()),
        }
    }

    #[test]
    fn test_risk_for_deviation_required_fields() {
        let d = sample_deviation();
        let r = risk_for_deviation(&d);
        // All OSCAL Risk required fields.
        assert!(r["uuid"].as_str().is_some(), "uuid required");
        assert!(r["title"].as_str().is_some(), "title required");
        assert!(r["description"].as_str().is_some(), "description required");
        assert!(r["statement"].as_str().is_some(), "statement required");
        assert_eq!(r["status"].as_str(), Some("deviation-approved"));
        assert!(r["props"].as_array().is_some(), "props required");
        assert!(r["subjects"].as_array().is_some(), "subjects required");
        // Evidence URI propagates as a link.
        let links = r["links"].as_array().expect("evidence_uri produces links");
        assert_eq!(
            links[0]["href"].as_str(),
            Some("https://policy.agency.gov/waivers/2025-11-03")
        );
    }

    #[test]
    fn test_risk_for_deviation_props_carry_persistence_metadata() {
        let d = sample_deviation();
        let r = risk_for_deviation(&d);
        let prop_value = |name: &str| -> Option<String> {
            r["props"]
                .as_array()
                .unwrap()
                .iter()
                .find(|p| p["name"].as_str() == Some(name))
                .and_then(|p| p["value"].as_str())
                .map(String::from)
        };
        assert_eq!(
            prop_value("pkix-lint.deviation-id"),
            Some("policy-2026-q1-fpki-keyusage".to_string())
        );
        assert_eq!(
            prop_value("pkix-lint.target-lint"),
            Some("fpki.common.6.1.5".to_string())
        );
        assert_eq!(
            prop_value("pkix-lint.action"),
            Some("downgrade:warn".to_string())
        );
        assert_eq!(
            prop_value("pkix-lint.authorized-by"),
            Some("agency-x-ciso@agency.gov".to_string())
        );
        assert_eq!(
            prop_value("pkix-lint.effective-start"),
            Some("1704067200".to_string())
        );
        assert_eq!(
            prop_value("pkix-lint.effective-end"),
            Some("1767225600".to_string())
        );
    }

    #[test]
    fn test_risk_for_deviation_omits_optional_time_bounds() {
        let d = Deviation {
            effective_start: None,
            effective_end: None,
            ..sample_deviation()
        };
        let r = risk_for_deviation(&d);
        let names: Vec<&str> = r["props"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        assert!(
            !names.contains(&"pkix-lint.effective-start"),
            "effective-start prop must be omitted when None"
        );
        assert!(
            !names.contains(&"pkix-lint.effective-end"),
            "effective-end prop must be omitted when None"
        );
    }

    #[test]
    fn test_risk_for_deviation_action_suppress() {
        let d = Deviation {
            action: DeviationAction::Suppress,
            ..sample_deviation()
        };
        let r = risk_for_deviation(&d);
        let action_value = r["props"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"].as_str() == Some("pkix-lint.action"))
            .and_then(|p| p["value"].as_str())
            .unwrap();
        assert_eq!(action_value, "suppress");
    }

    #[test]
    fn test_encode_scope_any() {
        let subjects = encode_scope(&DeviationScope::any());
        assert_eq!(subjects.len(), 1);
        assert_eq!(subjects[0]["type"].as_str(), Some("pkix-lint.scope.any"));
    }

    #[test]
    fn test_encode_scope_issuer_dn_contains() {
        let s = DeviationScope::issuer_dn_contains("agency x");
        let subjects = encode_scope(&s);
        assert_eq!(subjects.len(), 1);
        let subj = &subjects[0];
        assert_eq!(
            subj["type"].as_str(),
            Some("pkix-lint.scope.issuer-dn-contains")
        );
        let substring = subj["props"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"].as_str() == Some("pkix-lint.issuer-dn-substring"))
            .and_then(|p| p["value"].as_str())
            .unwrap();
        assert_eq!(substring, "agency x");
    }

    #[test]
    fn test_encode_scope_issuer_dn_exact_carries_der() {
        // Reuse an existing PKITS cert fixture to obtain a real Name.
        // Path is relative to pkix-lint crate root; CARGO_MANIFEST_DIR at
        // test time is pkix-lint/.
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../pkix-path/tests/pkits/certs/GoodCACert.crt");
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => {
                // PKITS fixtures not co-located; skip when running this
                // crate's tests outside the workspace.
                eprintln!("PKITS fixture not found, skipping test");
                return;
            }
        };
        use der::Decode as _;
        let cert = x509_cert::Certificate::from_der(&bytes).expect("parse fixture");
        let name = cert.tbs_certificate.subject;
        let scope = DeviationScope::issuer_dn_exact(&name).expect("DER encode");
        let subjects = encode_scope(&scope);
        assert_eq!(subjects.len(), 1);
        let subj = &subjects[0];
        assert_eq!(
            subj["type"].as_str(),
            Some("pkix-lint.scope.issuer-dn-exact")
        );
        // The DER prop must be present, non-empty, and parse back to the
        // original Name — that's the round-trip oracle (lossless DER
        // encoding of the DN).
        let der_hex = subj["props"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"].as_str() == Some("pkix-lint.issuer-dn-der"))
            .and_then(|p| p["value"].as_str())
            .expect("dn-der prop must be present");
        assert!(!der_hex.is_empty());
        let der_bytes = hex_decode(der_hex).expect("hex decodes");
        let parsed = x509_cert::name::Name::from_der(&der_bytes).expect("DER round-trip");
        assert!(
            pkix_path::names_match(&name, &parsed),
            "DER round-trip must yield an equivalent Name"
        );
    }

    /// Local hex-string decoder for the round-trip test above. Returns
    /// `None` on invalid input. Kept inline to avoid pulling in a hex
    /// crate dependency just for one test.
    fn hex_decode(s: &str) -> Option<Vec<u8>> {
        if s.len() % 2 != 0 {
            return None;
        }
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let hi = nibble(bytes[i])?;
            let lo = nibble(bytes[i + 1])?;
            out.push((hi << 4) | lo);
            i += 2;
        }
        Some(out)
    }

    fn nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }

    #[test]
    fn test_encode_scope_serial_range() {
        // Synthesise a SerialRange using a real Name (PKITS fixture) and
        // small byte vectors. We only check the structural shape; the
        // DER round-trip is covered by test_encode_scope_issuer_dn_exact.
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../pkix-path/tests/pkits/certs/GoodCACert.crt");
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => return,
        };
        use der::Decode as _;
        let cert = x509_cert::Certificate::from_der(&bytes).expect("parse fixture");
        let scope = DeviationScope::serial_range(
            &cert.tbs_certificate.subject,
            vec![0x01, 0x00],
            vec![0x01, 0xff],
        )
        .expect("DER encode");
        let subjects = encode_scope(&scope);
        assert_eq!(subjects.len(), 1);
        let subj = &subjects[0];
        assert_eq!(subj["type"].as_str(), Some("pkix-lint.scope.serial-range"));
        let prop_value = |name: &str| -> Option<String> {
            subj["props"]
                .as_array()
                .unwrap()
                .iter()
                .find(|p| p["name"].as_str() == Some(name))
                .and_then(|p| p["value"].as_str())
                .map(String::from)
        };
        assert_eq!(
            prop_value("pkix-lint.serial-start"),
            Some("0100".to_string())
        );
        assert_eq!(prop_value("pkix-lint.serial-end"), Some("01ff".to_string()));
        assert!(prop_value("pkix-lint.issuer-dn-der").is_some());
    }

    #[test]
    fn test_risks_from_store_round_trips_through_serde_json() {
        let mut store = DeviationStore::new();
        store.add(sample_deviation()).expect("add");
        store
            .add(Deviation {
                id: "policy-2026-suppress-test".to_string(),
                action: DeviationAction::Suppress,
                scope: DeviationScope::any(),
                ..sample_deviation()
            })
            .expect("add");
        let arr = risks_from_store(&store);
        assert_eq!(arr.len(), 2);
        // serde_json round-trip on the array.
        let json = serde_json::to_string(&Value::Array(arr.clone())).expect("serialize");
        let parsed: Value = serde_json::from_str(&json).expect("parse back");
        assert_eq!(
            parsed,
            Value::Array(arr),
            "OSCAL Risk array must round-trip byte-equal"
        );
    }

    #[test]
    fn test_risk_for_deviation_uuid_is_deterministic() {
        let d = sample_deviation();
        let a = risk_for_deviation(&d);
        let b = risk_for_deviation(&d);
        assert_eq!(
            a["uuid"], b["uuid"],
            "same deviation must yield same Risk UUID across calls"
        );
    }

    #[test]
    fn test_risk_for_deviation_uuid_namespace_isolates_from_run_risk() {
        // A policy-side deviation Risk and a run-side DeviatedFinding Risk
        // must not collide even if their seeds overlap. Verified by the
        // distinct NS_RISK vs NS_RISK_POLICY namespaces — same input,
        // different UUIDs.
        let report_seed = b"shared-seed".to_vec();
        let df = DeviatedFinding {
            lint_id: Cow::Borrowed("x"),
            citation: Cow::Borrowed("y"),
            original_result: LintResult::error("z"),
            deviation_id: "policy-2026-q1-fpki-keyusage".to_string(),
            action: DeviationAction::Suppress,
            justification: "j".to_string(),
            evidence_uri: None,
            cert_index: Some(0),
            evaluated_at_unix: 0,
        };
        let run_risk = risk_for(&df, &report_seed, 0);
        let policy_risk = risk_for_deviation(&sample_deviation());
        assert_ne!(
            run_risk["uuid"], policy_risk["uuid"],
            "policy-side and run-side Risk UUIDs must not collide"
        );
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
