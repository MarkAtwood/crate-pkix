//! Evidence pack: `EvaluationReport` bundles all findings from a lint run.
//!
//! An [`EvaluationReport`] is the exportable unit for the "evidence pack" workflow:
//! one operator exports it, attaches it to a CA help-desk ticket, and the CA sees
//! exactly which cert, which rule, which version, and which time produced each finding.
//! This eliminates the "send me the cert details" round-trip.
//!
//! # JSON export
//!
//! Enable the `serde` feature to get `serde::Serialize`/`Deserialize` on all types
//! in this module. The JSON schema is stable — field names are part of the public API.
//!
//! ```toml
//! pkix-lint = { version = "0.2", features = ["serde"] }
//! ```
//!
//! # OSCAL compatibility
//!
//! The `EvaluationReport` fields map to OSCAL Assessment Results as follows:
//! - `evaluated_at_unix` → `assessment-results.metadata.last-modified`
//! - `profile_id` / `profile_version` → `assessment-results.import-ap.href` (profile reference)
//! - `rule_bundle_version` → `assessment-results.metadata.prop[name=rule-bundle-version]`
//! - `findings` → `assessment-results.results.findings` (non-deviated)
//! - `deviated_findings` → `assessment-results.results.risks[status=deviation-approved]`
//!
//! The OSCAL Assessment Results emitter ships in-crate under the `oscal`
//! cargo feature ([`crate::oscal::emit::assessment_results`]). See that
//! module's docs for the full field-mapping table and round-trip
//! guarantees.

use std::borrow::Cow;

use crate::deviation::DeviatedFinding;
use crate::Finding;

#[cfg(feature = "serde")]
use crate::de_cow_static;

/// The complete output of a lint evaluation run.
///
/// Bundles all findings (both clean and deviated) with the metadata needed to
/// reconstruct who ran what, when, and against which cert chain. This is the
/// "evidence pack" that operators attach to CA help-desk tickets.
///
/// # Stable JSON schema
///
/// All field names in this struct are part of the public API and will not be
/// renamed without a semver-major bump. Consumers may safely parse them
/// across minor version updates.
///
/// # Serde
///
/// All string fields use `Cow<'static, str>` and deserialize as `Cow::Owned`
/// without leaking allocations. The earlier `'de: 'static` bound (required
/// when `LintResult` detail fields were `&'static str`) was removed in
/// pkix-lint 0.3.0. Deserialization works from any source — `serde_json::from_str`,
/// `serde_json::from_slice`, or any other.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EvaluationReport {
    /// The profile ID used for this evaluation (from [`crate::Profile::id`]).
    ///
    /// Example: `"cabf.br.tls"`. Empty string if no profile was specified.
    #[cfg_attr(feature = "serde", serde(deserialize_with = "de_cow_static"))]
    pub profile_id: Cow<'static, str>,

    /// The profile version string (from [`crate::Profile::version`]).
    ///
    /// Example: `"SC-081"`. Empty string if no profile was specified.
    #[cfg_attr(feature = "serde", serde(deserialize_with = "de_cow_static"))]
    pub profile_version: Cow<'static, str>,

    /// The rule bundle version string (from [`crate::LintRunner::bundle_version`]).
    ///
    /// Example: `"pkix-lint-cabf/cabf_tls_br v0.2.0, sourced from TLS BR SC-081"`.
    /// Empty string if the runner was constructed without a bundle version.
    #[cfg_attr(feature = "serde", serde(deserialize_with = "de_cow_static"))]
    pub rule_bundle_version: Cow<'static, str>,

    /// The number of certificates in the evaluated chain.
    pub chain_length: usize,

    /// Unix epoch seconds at which the evaluation was performed.
    ///
    /// For audit-mode (time-of-issuance), this is the cert's `notBefore`.
    /// For operational-mode (current time), this is the wall-clock time.
    ///
    /// Note: individual findings also carry `evaluated_at_unix`, which may
    /// differ from this field when different certs in the chain were evaluated
    /// at different times (e.g., in a mixed audit+operational run). Prefer
    /// per-finding `evaluated_at_unix` for precise attribution.
    pub evaluated_at_unix: u64,

    /// Findings that were not affected by any deviation.
    ///
    /// These are the normal compliance findings. Yellow/red in the operator UI.
    pub findings: Vec<Finding>,

    /// Findings that had a deviation applied.
    ///
    /// Always included for auditability — never hidden. The operator UI should
    /// display these as `DEVIATION APPLIED by <id>` with the justification and
    /// `evidence_uri` (when present) shown inline.
    pub deviated_findings: Vec<DeviatedFinding>,
}

/// Extract the [`crate::Severity`] from a [`crate::LintResult`], if any.
///
/// `Pass` and `NotApplicable` carry no severity and return `None`.
const fn severity_of(r: &crate::LintResult) -> Option<crate::Severity> {
    match r {
        crate::LintResult::Warn(_) => Some(crate::Severity::Warn),
        crate::LintResult::Error(_) => Some(crate::Severity::Error),
        crate::LintResult::Fatal(_) => Some(crate::Severity::Fatal),
        _ => None,
    }
}

impl EvaluationReport {
    /// Create an empty report with the given metadata.
    ///
    /// All string parameters accept anything that converts to `Cow<'static, str>`,
    /// so you can pass string literals (borrowed) or owned `String` values:
    ///
    /// ```rust,no_run
    /// use pkix_lint::report::EvaluationReport;
    ///
    /// // Static string literal — zero allocation
    /// let now: u64 = unimplemented!("current Unix epoch seconds");
    /// let _report = EvaluationReport::new("cabf.br.tls", "SC-081", "v0.2.0", 2, now);
    ///
    /// // Runtime-constructed string — uses Cow::Owned
    /// let version = "1.2.3";
    /// let _report2 = EvaluationReport::new(
    ///     format!("bundle-{}", version),
    ///     "SC-081",
    ///     "v0.2.0",
    ///     2,
    ///     0u64,
    /// );
    /// ```
    #[must_use]
    pub fn new(
        profile_id: impl Into<Cow<'static, str>>,
        profile_version: impl Into<Cow<'static, str>>,
        rule_bundle_version: impl Into<Cow<'static, str>>,
        chain_length: usize,
        evaluated_at_unix: u64,
    ) -> Self {
        Self {
            profile_id: profile_id.into(),
            profile_version: profile_version.into(),
            rule_bundle_version: rule_bundle_version.into(),
            chain_length,
            evaluated_at_unix,
            findings: Vec::new(),
            deviated_findings: Vec::new(),
        }
    }

    /// Return `true` if there are any actionable findings (Warn, Error, or Fatal).
    ///
    /// Deviated findings do not count toward this result regardless of their
    /// original severity — the deviation has already been applied.
    #[must_use]
    pub fn has_findings(&self) -> bool {
        self.findings.iter().any(Finding::is_finding)
    }

    /// Return all findings at or above the given severity.
    ///
    /// Useful for rendering: show only Error+ findings in a summary panel,
    /// or Warn+ in a detail view.
    #[must_use]
    pub fn findings_at_or_above(&self, min_severity: crate::Severity) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| severity_of(&f.result).is_some_and(|s| s >= min_severity))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LintResult, Severity};

    fn empty_report() -> EvaluationReport {
        EvaluationReport::new("cabf.br.tls", "SC-081", "v0.2.0", 2, 1_780_272_000)
    }

    fn pass_finding() -> Finding {
        Finding {
            lint_id: std::borrow::Cow::Borrowed("test.lint"),
            citation: std::borrow::Cow::Borrowed("test"),
            rule_bundle_version: std::borrow::Cow::Borrowed("v0.2.0"),
            result: LintResult::Pass,
            cert_index: Some(0),
            evaluated_at_unix: 1_780_272_000,
            cert_sha256: None,
        }
    }

    fn error_finding() -> Finding {
        Finding {
            result: LintResult::error("something wrong"),
            ..pass_finding()
        }
    }

    fn warn_finding() -> Finding {
        Finding {
            result: LintResult::warn("advisory"),
            ..pass_finding()
        }
    }

    // -----------------------------------------------------------------------
    // EvaluationReport basic tests
    // Oracle: the field semantics in EvaluationReport doc comments.
    // -----------------------------------------------------------------------

    #[test]
    fn empty_report_has_no_findings() {
        let r = empty_report();
        assert!(!r.has_findings());
        assert!(r.findings.is_empty());
        assert!(r.deviated_findings.is_empty());
    }

    #[test]
    fn report_with_only_pass_has_no_findings() {
        let mut r = empty_report();
        r.findings.push(pass_finding());
        assert!(!r.has_findings(), "Pass result must not count as a finding");
    }

    #[test]
    fn report_with_error_has_findings() {
        let mut r = empty_report();
        r.findings.push(error_finding());
        assert!(r.has_findings());
    }

    #[test]
    fn findings_at_or_above_error_excludes_warn() {
        let mut r = empty_report();
        r.findings.push(error_finding());
        r.findings.push(warn_finding());
        let at_error = r.findings_at_or_above(Severity::Error);
        assert_eq!(at_error.len(), 1, "only Error findings at Error threshold");
        assert!(matches!(at_error[0].result, LintResult::Error(_)));
    }

    #[test]
    fn findings_at_or_above_warn_includes_error() {
        let mut r = empty_report();
        r.findings.push(error_finding());
        r.findings.push(warn_finding());
        let at_warn = r.findings_at_or_above(Severity::Warn);
        assert_eq!(at_warn.len(), 2, "both Error and Warn at Warn threshold");
    }

    #[test]
    fn report_metadata_fields_preserved() {
        let r = EvaluationReport::new("cabf.br.tls", "SC-081", "bundle-v1", 3, 999_000);
        assert_eq!(r.profile_id, "cabf.br.tls");
        assert_eq!(r.profile_version, "SC-081");
        assert_eq!(r.rule_bundle_version, "bundle-v1");
        assert_eq!(r.chain_length, 3);
        assert_eq!(r.evaluated_at_unix, 999_000);
    }

    // -----------------------------------------------------------------------
    // JSON serialization test (requires serde feature)
    // Oracle: serde_json round-trip — the deserialized report must equal the original.
    //
    // NOTE: this test is compiled and run only when the `serde` feature is
    // enabled. To exercise it explicitly:
    //   cargo test -p pkix-lint --features serde
    // or:
    //   cargo test -p pkix-lint --all-features
    // -----------------------------------------------------------------------

    #[test]
    #[cfg(feature = "serde")]
    fn json_round_trip() {
        let mut r = empty_report();
        r.findings.push(error_finding());
        r.findings.push(warn_finding());

        // Serialize using serde_json (dev-dependency).
        let json = serde_json::to_string_pretty(&r).expect("serialization must succeed");
        // Verify it's valid JSON and contains expected fields.
        assert!(
            json.contains("\"profile_id\""),
            "JSON must contain profile_id"
        );
        assert!(
            json.contains("\"cabf.br.tls\""),
            "JSON must contain profile id value"
        );
        assert!(json.contains("\"lint_id\""), "JSON must contain lint_id");
        assert!(
            json.contains("\"rule_bundle_version\""),
            "JSON must contain rule_bundle_version"
        );
        assert!(
            json.contains("\"evaluated_at_unix\""),
            "JSON must contain evaluated_at_unix"
        );

        // Round-trip: deserialize back into EvaluationReport and verify key fields.
        // No 'de: 'static bound is required after the PKIX-ua6q migration —
        // both serde_json::from_str and serde_json::from_slice work.
        let r2: EvaluationReport =
            serde_json::from_str(&json).expect("deserialization must succeed");
        assert_eq!(r2.profile_id, r.profile_id);
        assert_eq!(r2.profile_version, r.profile_version);
        assert_eq!(r2.rule_bundle_version, r.rule_bundle_version);
        assert_eq!(r2.findings.len(), r.findings.len());

        // Also verify the Cow<'static, str> detail in LintResult round-trips
        // correctly. The deserialized detail must equal the source detail.
        match (&r.findings[0].result, &r2.findings[0].result) {
            (LintResult::Error(a), LintResult::Error(b)) => assert_eq!(a, b),
            (a, b) => panic!("unexpected result variants: {a:?} vs {b:?}"),
        }
    }

    /// LintResult round-trips dynamic (Cow::Owned) detail through serde without
    /// leaking the allocation. Regression coverage for the PKIX-ua6q migration.
    #[test]
    #[cfg(feature = "serde")]
    fn lint_result_dynamic_detail_round_trip() {
        // Build a finding whose detail is a runtime-formatted owned string.
        let actual = 400u64;
        let detail_text = format!("validity {actual} days exceeds 398-day cap");
        let f = Finding {
            lint_id: std::borrow::Cow::Borrowed("test.lint"),
            citation: std::borrow::Cow::Borrowed("test"),
            rule_bundle_version: std::borrow::Cow::Borrowed("v0.3.0"),
            result: LintResult::error(detail_text.clone()),
            cert_index: Some(0),
            evaluated_at_unix: 0,
            cert_sha256: None,
        };
        let json = serde_json::to_string(&f).expect("serialize");
        // Use from_slice to confirm no 'de: 'static bound remains.
        let f2: Finding = serde_json::from_slice(json.as_bytes()).expect("from_slice must succeed");
        match &f2.result {
            LintResult::Error(d) => assert_eq!(d.as_ref(), detail_text.as_str()),
            other => panic!("expected Error variant, got {other:?}"),
        }
    }
}
