//! Deviation (waiver) mechanism for `pkix-lint`.
//!
//! A [`Deviation`] is an operator-authored, scoped, time-bounded exception to a
//! specific lint finding. Deviations are the only mechanism for suppressing or
//! downgrading lint findings — there are no CLI flags or global overrides.
//!
//! # Design rationale
//!
//! The deviation mechanism is designed to:
//! - Make suppression **explicit and attributable**: every deviation has an ID,
//!   a justification, and an authorized_by field that appear in reports.
//! - Force **scoping**: deviations match specific certs (by issuer DN, serial, etc.),
//!   not all certs globally.
//! - Enforce **expiry**: deviations with an `effective_end` re-activate findings
//!   after they expire, forcing renewal and re-justification.
//! - **Not launder violations**: a suppressed finding is recorded as a
//!   [`DeviatedFinding`] in the output, not silently removed. Auditors can see it.
//!
//! # No vendor deviation packs
//!
//! `pkix-lint` never ships deviation packs. CAs, vendors, or policy authorities
//! who want to ship deviations for their customers must distribute them separately,
//! and operators must explicitly load them into their own [`DeviationStore`]. This
//! prevents the tool from becoming an instrument for CA-side laundering.
//!
//! # Usage
//!
//! ```rust,ignore
//! use pkix_lint::deviation::{Deviation, DeviationAction, DeviationScope, DeviationStore};
//! use pkix_lint::Severity;
//!
//! let mut store = DeviationStore::new();
//! store.add(Deviation {
//!     id: "agency-x-fpki-keyusage-2026-q1".to_string(),
//!     target_lint: "fpki.common.6.1.5",
//!     scope: DeviationScope::IssuerDnContains("Agency X Issuing CA".to_string()),
//!     effective_start: None,
//!     effective_end: Some(1_767_225_600), // 2026-01-01
//!     action: DeviationAction::DowngradeSeverityTo(Severity::Info),
//!     justification: "FPKIPA waiver memo 2025-11-03".to_string(),
//!     authorized_by: "agency-x-ciso@agency.gov".to_string(),
//! });
//!
//! // Use a DeviationRunner (wraps LintRunner) to apply deviations automatically.
//! ```

use crate::Severity;
use x509_cert::Certificate;

/// A scoped, time-bounded exception to a specific lint finding.
///
/// See the module-level documentation for the design rationale and usage.
#[derive(Clone, Debug)]
pub struct Deviation {
    /// Unique identifier for this deviation within the operator's store.
    ///
    /// Appears verbatim in finding output as "DEVIATION APPLIED by <id>".
    /// Must be unique within the [`DeviationStore`] that contains it.
    pub id: String,

    /// The stable lint ID this deviation applies to.
    ///
    /// Must exactly match the value returned by [`crate::Lint::id`] for the
    /// target lint. Deviations are lint-ID scoped — they do not apply to all
    /// findings of a given severity or category.
    pub target_lint: &'static str,

    /// Which certificates this deviation applies to.
    ///
    /// Only certs that match the scope will have the deviation applied.
    /// Use [`DeviationScope::Any`] only for internal CAs or test environments
    /// where the profile itself is being applied informally.
    pub scope: DeviationScope,

    /// Unix epoch (seconds) after which this deviation becomes active.
    ///
    /// `None` means the deviation is active immediately (from the Unix epoch).
    pub effective_start: Option<u64>,

    /// Unix epoch (seconds) after which this deviation expires.
    ///
    /// `None` means the deviation never expires. This is strongly discouraged
    /// for production deviations — omitting an end date removes the automatic
    /// re-review trigger. Use `None` only for structural deviations that are
    /// permanent by design (e.g., an internal CA that will never follow FPKI policy).
    pub effective_end: Option<u64>,

    /// What to do with a matching finding.
    pub action: DeviationAction,

    /// Human-readable justification for this deviation.
    ///
    /// Examples: "FPKIPA waiver memo 2025-11-03", "Internal CA not subject to FPKI",
    /// "CA confirmed CP §6.1.5 interpreted as optional for HW tokens per guidance doc".
    /// Appears in finding output and audit reports. Must be non-empty.
    pub justification: String,

    /// Who authorized this deviation.
    ///
    /// Typically a name, email, or key reference of the person with authority to
    /// approve the deviation. Examples: "agency-x-ciso@agency.gov",
    /// "CN=PKI Officer, OU=CISO, O=Agency X".
    /// Appears in finding output and audit reports. Must be non-empty.
    pub authorized_by: String,

    /// Optional URI pointing to the backing waiver or authorization document.
    ///
    /// When present, this URI is included in [`DeviatedFinding`] output so that
    /// operators can navigate directly to the authorization document when
    /// reviewing or escalating a deviated finding.
    ///
    /// # Examples
    ///
    /// - `Some("file:///var/lib/agency-x-pki/waivers/2025-11-03.pdf")` — local file
    /// - `Some("https://pkipolicy.agency.gov/waivers/2025-11-03")` — web document
    /// - `Some("https://github.com/agency-x/pki-exceptions/issues/47")` — issue tracker
    ///
    /// `None` is acceptable but discouraged for production deviations in gov/mil
    /// contexts where the IG may ask for the authorizing document.
    pub evidence_uri: Option<String>,
}

impl Deviation {
    /// Returns `true` if this deviation is active at `now_unix`.
    ///
    /// A deviation is active when:
    /// - `effective_start` is `None` or `<= now_unix`
    /// - `effective_end` is `None` or `> now_unix`
    ///
    /// The `>` comparison on `effective_end` means a deviation expires at
    /// the second it reaches its end timestamp, not one second after.
    #[must_use]
    pub fn is_active_at(&self, now_unix: u64) -> bool {
        let after_start = self
            .effective_start
            .map_or(true, |start| now_unix >= start);
        let before_end = self
            .effective_end
            .map_or(true, |end| now_unix < end);
        after_start && before_end
    }

    /// Returns `true` if this deviation applies to `cert` at `now_unix`.
    ///
    /// Both the time-active check and the scope check must pass.
    #[must_use]
    pub fn applies_to(&self, cert: &Certificate, now_unix: u64) -> bool {
        if !self.is_active_at(now_unix) {
            return false;
        }
        self.scope.matches(cert)
    }
}

/// Specifies which certificates a [`Deviation`] applies to.
///
/// Scopes are evaluated against the certificate at chain index 0 (the leaf)
/// for cert-scope lints. For path-scope lints, the scope is evaluated against
/// the leaf certificate.
///
/// # v0.2 scope
///
/// The v0.2 scope supports `IssuerDnContains` (substring match on the issuer
/// DN string representation) and `Any`. Future versions will add:
/// - `IssuerDnExact` (RFC 4518-normalized DN match)
/// - `SerialRange { issuer, start, end }`
/// - `SubjectDnContains`
/// - `PolicyOid(ObjectIdentifier)` (certs asserting a specific CP OID)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviationScope {
    /// The deviation applies to all certificates. Use with care; see note on
    /// `Any` in the module-level documentation.
    Any,

    /// The deviation applies to certs whose issuer DN string representation
    /// contains the given substring (case-insensitive).
    ///
    /// Example: `IssuerDnContains("Agency X Issuing CA".to_string())` matches
    /// any cert whose issuer DN contains "Agency X Issuing CA".
    ///
    /// This is a substring match, not an RFC 4518-normalized DN match. It is
    /// intended for practical human-readable scoping, not cryptographic identity.
    /// Do not rely on it to distinguish issuers whose DNs differ only by whitespace
    /// or case; use `IssuerDnExact` (planned) for that.
    IssuerDnContains(String),
}

impl DeviationScope {
    /// Returns `true` if `cert` is within this scope.
    #[must_use]
    pub fn matches(&self, cert: &Certificate) -> bool {
        match self {
            DeviationScope::Any => true,
            DeviationScope::IssuerDnContains(substring) => {
                let issuer_str = cert.tbs_certificate.issuer.to_string();
                issuer_str
                    .to_lowercase()
                    .contains(&substring.to_lowercase())
            }
        }
    }
}

/// What a [`Deviation`] does to a matching finding.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviationAction {
    /// Change the finding's severity to the specified level.
    ///
    /// The finding is still recorded in the output — it is not removed.
    /// The deviation ID appears in the [`DeviatedFinding`] so auditors can see it.
    DowngradeSeverityTo(Severity),

    /// Mark the finding as suppressed (effectively `NotApplicable` for reporting).
    ///
    /// The finding is still recorded as a [`DeviatedFinding`] with
    /// `action: DeviationAction::Suppress` so auditors can see that the deviation
    /// was applied. It does not appear as a normal finding.
    ///
    /// Use only when `DowngradeSeverityTo(Severity::Info)` is not sufficient
    /// (e.g., the finding would be incorrectly categorized as Info in reports).
    Suppress,
}

/// A finding with a deviation applied.
///
/// The underlying lint ID, original result, and deviation metadata are all
/// preserved for audit purposes. A `DeviatedFinding` is never silently hidden.
///
/// # Operator UI guidance
///
/// Display deviated findings as "DEVIATION APPLIED" rather than green/pass.
/// Show `deviation_id`, `justification`, and `evidence_uri` (when present) so
/// operators can navigate to the backing waiver document without a second lookup.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviatedFinding {
    /// The stable lint ID of the lint that produced this finding.
    pub lint_id: &'static str,
    /// The citation for the lint that produced this finding.
    pub citation: &'static str,
    /// The original lint result before the deviation was applied.
    pub original_result: crate::LintResult,
    /// The deviation ID that was applied.
    pub deviation_id: String,
    /// The action taken by the deviation.
    pub action: DeviationAction,
    /// Human-readable justification from the deviation.
    pub justification: String,
    /// URI pointing to the backing waiver document, if one was provided.
    ///
    /// `None` if the deviation did not include an `evidence_uri`.
    pub evidence_uri: Option<String>,
    /// For certificate-scope findings, the zero-based chain index.
    pub cert_index: Option<usize>,
}

impl DeviatedFinding {
    /// Returns the effective severity after the deviation was applied.
    ///
    /// - `DowngradeSeverityTo(s)` returns `s`.
    /// - `Suppress` returns `None` (the finding is suppressed from normal output).
    #[must_use]
    pub fn effective_severity(&self) -> Option<Severity> {
        match &self.action {
            DeviationAction::DowngradeSeverityTo(s) => Some(*s),
            DeviationAction::Suppress => None,
        }
    }
}

/// An in-memory collection of [`Deviation`]s.
///
/// The store is append-only in v0.2. Future versions may add update/delete
/// and persistence (file-backed JSON/OSCAL format).
#[derive(Clone, Debug, Default)]
pub struct DeviationStore {
    deviations: Vec<Deviation>,
}

impl DeviationStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a deviation to the store.
    ///
    /// # Panics
    ///
    /// Panics if `deviation.justification` or `deviation.authorized_by` is empty,
    /// or if a deviation with the same `id` already exists in the store.
    /// These are programming errors; the store does not accept incomplete or
    /// duplicate deviations.
    pub fn add(&mut self, deviation: Deviation) {
        assert!(
            !deviation.justification.is_empty(),
            "deviation justification must not be empty"
        );
        assert!(
            !deviation.authorized_by.is_empty(),
            "deviation authorized_by must not be empty"
        );
        assert!(
            !self.deviations.iter().any(|d| d.id == deviation.id),
            "deviation id '{}' already exists in the store",
            deviation.id
        );
        self.deviations.push(deviation);
    }

    /// Return all deviations in the store.
    pub fn all(&self) -> &[Deviation] {
        &self.deviations
    }

    /// Return all deviations that are active at `now_unix`.
    pub fn active_at(&self, now_unix: u64) -> impl Iterator<Item = &Deviation> {
        self.deviations
            .iter()
            .filter(move |d| d.is_active_at(now_unix))
    }

    /// Return all deviations targeting `lint_id` that are active at `now_unix`.
    pub fn active_for_lint(
        &self,
        lint_id: &'static str,
        now_unix: u64,
    ) -> impl Iterator<Item = &Deviation> {
        self.deviations
            .iter()
            .filter(move |d| d.target_lint == lint_id && d.is_active_at(now_unix))
    }

    /// Return all deviations that have expired as of `now_unix`.
    ///
    /// Used by corpus-reporting tools to surface deviations that need renewal.
    pub fn expired_at(&self, now_unix: u64) -> impl Iterator<Item = &Deviation> {
        self.deviations.iter().filter(move |d| {
            d.effective_end
                .map_or(false, |end| now_unix >= end)
        })
    }

    /// Check whether a specific finding should be deviated.
    ///
    /// Returns the first active deviation that matches `cert` and `lint_id` at
    /// `now_unix`, or `None` if no deviation applies.
    ///
    /// In the case of multiple matching deviations, the first one added to the
    /// store wins. Deviations should be scoped to avoid unintentional overlap.
    #[must_use]
    pub fn find_deviation(
        &self,
        lint_id: &'static str,
        cert: &Certificate,
        now_unix: u64,
    ) -> Option<&Deviation> {
        self.deviations
            .iter()
            .find(|d| d.target_lint == lint_id && d.applies_to(cert, now_unix))
    }
}

// ---------------------------------------------------------------------------
// DeviationRunner
// ---------------------------------------------------------------------------

/// The output of a [`DeviationRunner`] evaluation: findings with deviations applied.
///
/// Findings where a deviation was applied are moved from `findings` to `deviated`.
/// Callers can use `findings` for normal compliance reporting and `deviated`
/// for audit/transparency reporting.
#[derive(Clone, Debug, Default)]
pub struct DeviationRunResult {
    /// Findings that were not affected by any deviation.
    ///
    /// Same semantics as [`crate::Finding`] — this is what you report to the operator.
    pub findings: Vec<crate::Finding>,

    /// Findings that had a deviation applied.
    ///
    /// These are always included in output (never silently hidden) so that
    /// auditors can see what was deviated and why. If `action` is
    /// [`DeviationAction::Suppress`], `effective_severity()` returns `None`;
    /// the caller can display these with a "DEVIATION APPLIED" tag rather than
    /// as normal findings.
    pub deviated: Vec<DeviatedFinding>,
}

/// A lint runner that applies [`DeviationStore`] logic to findings.
///
/// `DeviationRunner` wraps a [`crate::LintRunner`] and a [`DeviationStore`].
/// After each lint evaluation, it checks whether a deviation applies to the
/// finding. If one does, the finding is moved to [`DeviationRunResult::deviated`];
/// otherwise it stays in [`DeviationRunResult::findings`].
///
/// # Transparency guarantee
///
/// `DeviationRunner` **never silently drops findings**. Every finding — including
/// deviated ones — appears in [`DeviationRunResult`]. Operators see what was
/// deviated; auditors can enumerate deviations via [`DeviationStore::all`].
///
/// # Usage
///
/// ```rust,ignore
/// use pkix_lint::deviation::{DeviationRunner, DeviationStore, Deviation, DeviationAction, DeviationScope};
/// use pkix_lint::{LintRunner, Severity};
///
/// let store = DeviationStore::new(); // populate with operator deviations
/// let runner = LintRunner::new(vec![/* your lints */]);
/// let dev_runner = DeviationRunner::new(runner, store);
///
/// let result = dev_runner.run_cert(&cert, SubjectKind::Leaf, 0, now_unix);
/// // result.findings — normal findings
/// // result.deviated — deviated findings (always included for auditability)
/// ```
pub struct DeviationRunner {
    runner: crate::LintRunner,
    store: DeviationStore,
}

impl DeviationRunner {
    /// Create a new deviation runner from a lint runner and a deviation store.
    #[must_use]
    pub fn new(runner: crate::LintRunner, store: DeviationStore) -> Self {
        Self { runner, store }
    }

    /// Return a reference to the inner [`crate::LintRunner`].
    pub fn lint_runner(&self) -> &crate::LintRunner {
        &self.runner
    }

    /// Return a reference to the [`DeviationStore`].
    pub fn deviation_store(&self) -> &DeviationStore {
        &self.store
    }

    /// Evaluate certificate-scope lints and apply deviations.
    ///
    /// Same semantics as [`crate::LintRunner::run_cert`], but findings are
    /// partitioned into `findings` (no deviation) and `deviated` (deviation applied).
    #[must_use]
    pub fn run_cert(
        &self,
        cert: &Certificate,
        kind: crate::SubjectKind,
        cert_index: usize,
        now_unix: u64,
    ) -> DeviationRunResult {
        let raw = self.runner.run_cert(cert, kind, cert_index, now_unix);
        self.apply_deviations(raw, cert, now_unix)
    }

    /// Evaluate certificate-scope lints on every cert in `chain` and apply deviations.
    #[must_use]
    pub fn run_chain(
        &self,
        chain: &[Certificate],
        kinds: &[crate::SubjectKind],
        now_unix: u64,
    ) -> DeviationRunResult {
        let mut result = DeviationRunResult::default();
        for (i, cert) in chain.iter().enumerate() {
            let kind = kinds
                .get(i)
                .copied()
                .unwrap_or(crate::SubjectKind::IntermediateCa);
            let raw = self.runner.run_cert(cert, kind, i, now_unix);
            let partial = self.apply_deviations(raw, cert, now_unix);
            result.findings.extend(partial.findings);
            result.deviated.extend(partial.deviated);
        }
        result
    }

    /// Evaluate path-scope lints and apply deviations.
    ///
    /// For path-scope lints, scope matching uses the leaf certificate (`chain[0]`).
    #[must_use]
    pub fn run_path(
        &self,
        chain: &[Certificate],
        path: &crate::ValidatedPath,
        now_unix: u64,
    ) -> DeviationRunResult {
        let raw = self.runner.run_path(chain, path, now_unix);
        // Use the leaf cert for scope matching on path-level deviations.
        // If the chain is empty (shouldn't happen after validate_path), fall
        // back to no scope matching (treat as Any).
        match chain.first() {
            Some(leaf) => self.apply_deviations(raw, leaf, now_unix),
            None => DeviationRunResult {
                findings: raw,
                deviated: vec![],
            },
        }
    }

    /// Internal: partition a `Vec<Finding>` by whether a deviation applies.
    fn apply_deviations(
        &self,
        raw: Vec<crate::Finding>,
        cert: &Certificate,
        now_unix: u64,
    ) -> DeviationRunResult {
        let mut result = DeviationRunResult::default();
        for finding in raw {
            match self
                .store
                .find_deviation(finding.lint_id, cert, now_unix)
            {
                None => {
                    result.findings.push(finding);
                }
                Some(dev) => {
                    result.deviated.push(DeviatedFinding {
                        lint_id: finding.lint_id,
                        citation: finding.citation,
                        original_result: finding.result,
                        deviation_id: dev.id.clone(),
                        action: dev.action.clone(),
                        justification: dev.justification.clone(),
                        evidence_uri: dev.evidence_uri.clone(),
                        cert_index: finding.cert_index,
                    });
                }
            }
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LintResult;

    fn make_deviation(id: &str, lint_id: &'static str) -> Deviation {
        Deviation {
            id: id.to_string(),
            target_lint: lint_id,
            scope: DeviationScope::Any,
            effective_start: None,
            effective_end: None,
            action: DeviationAction::DowngradeSeverityTo(Severity::Info),
            justification: "test justification".to_string(),
            authorized_by: "test-author@example.com".to_string(),
            evidence_uri: None,
        }
    }

    fn load_cert() -> Certificate {
        use der::Decode as _;
        Certificate::from_der(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/webpki-self-signed-365d.der"
        ))
        .expect("fixture is valid DER")
    }

    // -----------------------------------------------------------------------
    // is_active_at tests
    // Oracle: the time-range semantics in Deviation::is_active_at doc comment.
    // -----------------------------------------------------------------------

    #[test]
    fn deviation_active_at_no_bounds() {
        let d = make_deviation("d1", "test.lint");
        // No bounds: always active.
        assert!(d.is_active_at(0));
        assert!(d.is_active_at(u64::MAX));
    }

    #[test]
    fn deviation_active_after_start() {
        let d = Deviation {
            effective_start: Some(100),
            effective_end: None,
            ..make_deviation("d2", "test.lint")
        };
        assert!(!d.is_active_at(99), "before start must not be active");
        assert!(d.is_active_at(100), "at start must be active");
        assert!(d.is_active_at(200), "after start must be active");
    }

    #[test]
    fn deviation_expires_at_end() {
        let d = Deviation {
            effective_start: None,
            effective_end: Some(200),
            ..make_deviation("d3", "test.lint")
        };
        assert!(d.is_active_at(199), "before end must be active");
        assert!(!d.is_active_at(200), "at end must NOT be active (exclusive)");
        assert!(!d.is_active_at(201), "after end must not be active");
    }

    #[test]
    fn deviation_active_within_range() {
        let d = Deviation {
            effective_start: Some(100),
            effective_end: Some(200),
            ..make_deviation("d4", "test.lint")
        };
        assert!(!d.is_active_at(99));
        assert!(d.is_active_at(100));
        assert!(d.is_active_at(150));
        assert!(d.is_active_at(199));
        assert!(!d.is_active_at(200));
    }

    // -----------------------------------------------------------------------
    // DeviationScope::matches tests
    // Oracle: the scope-matching rules in the DeviationScope doc comment.
    // -----------------------------------------------------------------------

    #[test]
    fn scope_any_matches_any_cert() {
        let cert = load_cert();
        assert!(DeviationScope::Any.matches(&cert));
    }

    #[test]
    fn scope_issuer_dn_contains_case_insensitive() {
        let cert = load_cert();
        // The webpki-self-signed-365d cert has a CN we can match.
        // Get the issuer string to find what's in it.
        let issuer = cert.tbs_certificate.issuer.to_string();
        // Take the first word of the issuer for a partial match.
        let word = issuer.split_whitespace().next().unwrap_or("cert");
        let scope_lower = DeviationScope::IssuerDnContains(word.to_lowercase());
        let scope_upper = DeviationScope::IssuerDnContains(word.to_uppercase());
        assert!(scope_lower.matches(&cert), "lowercase match must succeed");
        assert!(scope_upper.matches(&cert), "uppercase match must succeed (case-insensitive)");
    }

    #[test]
    fn scope_issuer_dn_contains_no_match() {
        let cert = load_cert();
        let scope = DeviationScope::IssuerDnContains("XYZ_NONEXISTENT_ISSUER_9999".to_string());
        assert!(!scope.matches(&cert));
    }

    // -----------------------------------------------------------------------
    // DeviationStore tests
    // Oracle: the store contract in DeviationStore doc comments.
    // -----------------------------------------------------------------------

    #[test]
    fn store_add_and_retrieve() {
        let mut store = DeviationStore::new();
        store.add(make_deviation("d1", "test.lint.a"));
        store.add(make_deviation("d2", "test.lint.b"));
        assert_eq!(store.all().len(), 2);
    }

    #[test]
    #[should_panic(expected = "justification must not be empty")]
    fn store_rejects_empty_justification() {
        let mut store = DeviationStore::new();
        store.add(Deviation {
            justification: "".to_string(),
            ..make_deviation("d1", "test.lint")
        });
    }

    #[test]
    #[should_panic(expected = "authorized_by must not be empty")]
    fn store_rejects_empty_authorized_by() {
        let mut store = DeviationStore::new();
        store.add(Deviation {
            authorized_by: "".to_string(),
            ..make_deviation("d1", "test.lint")
        });
    }

    #[test]
    #[should_panic(expected = "already exists")]
    fn store_rejects_duplicate_id() {
        let mut store = DeviationStore::new();
        store.add(make_deviation("d1", "test.lint.a"));
        store.add(make_deviation("d1", "test.lint.b")); // same id → panic
    }

    #[test]
    fn store_find_deviation_matches() {
        let cert = load_cert();
        let now: u64 = 1_000_000;
        let mut store = DeviationStore::new();
        store.add(Deviation {
            effective_start: None,
            effective_end: None,
            ..make_deviation("d1", "test.lint.a")
        });
        let found = store.find_deviation("test.lint.a", &cert, now);
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, "d1");
    }

    #[test]
    fn store_find_deviation_no_match_wrong_lint() {
        let cert = load_cert();
        let now: u64 = 1_000_000;
        let mut store = DeviationStore::new();
        store.add(make_deviation("d1", "test.lint.a"));
        assert!(store.find_deviation("test.lint.b", &cert, now).is_none());
    }

    #[test]
    fn store_find_deviation_expired_not_matched() {
        let cert = load_cert();
        let now: u64 = 1_000;
        let mut store = DeviationStore::new();
        store.add(Deviation {
            effective_end: Some(500), // expired at 500
            ..make_deviation("d1", "test.lint.a")
        });
        // At now=1000, the deviation has expired.
        assert!(store.find_deviation("test.lint.a", &cert, now).is_none());
    }

    #[test]
    fn store_expired_at_reports_expired_deviations() {
        let mut store = DeviationStore::new();
        store.add(Deviation {
            effective_end: Some(500),
            ..make_deviation("d1", "test.lint.a")
        });
        store.add(Deviation {
            effective_end: None, // never expires
            ..make_deviation("d2", "test.lint.b")
        });
        let expired: Vec<_> = store.expired_at(1000).collect();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].id, "d1");
    }

    #[test]
    fn deviated_finding_effective_severity() {
        let f = DeviatedFinding {
            lint_id: "test.lint",
            citation: "test citation",
            original_result: LintResult::Error("original"),
            deviation_id: "d1".to_string(),
            action: DeviationAction::DowngradeSeverityTo(Severity::Info),
            justification: "test justification".to_string(),
            evidence_uri: None,
            cert_index: None,
        };
        assert_eq!(f.effective_severity(), Some(Severity::Info));

        let f2 = DeviatedFinding {
            action: DeviationAction::Suppress,
            ..f
        };
        assert_eq!(f2.effective_severity(), None);
    }

    // -----------------------------------------------------------------------
    // DeviationRunner tests
    // Oracle: DeviationRunner contract from doc comments.
    // -----------------------------------------------------------------------

    /// A lint that always returns Error — used to test deviation application.
    struct AlwaysError;
    impl crate::Lint for AlwaysError {
        fn id(&self) -> &'static str { "test.always_error" }
        fn citation(&self) -> &'static str { "test" }
        fn severity(&self) -> crate::Severity { crate::Severity::Error }
        fn scope(&self) -> crate::Scope { crate::Scope::Certificate }
        fn applies_to(&self) -> crate::SubjectKind { crate::SubjectKind::Any }
        fn check_cert(&self, _cert: &Certificate, _kind: crate::SubjectKind, _now: u64) -> crate::LintResult {
            crate::LintResult::Error("always errors")
        }
    }

    /// A lint that always passes — used to verify non-deviated findings stay in findings.
    struct AlwaysPass;
    impl crate::Lint for AlwaysPass {
        fn id(&self) -> &'static str { "test.always_pass" }
        fn citation(&self) -> &'static str { "test" }
        fn severity(&self) -> crate::Severity { crate::Severity::Info }
        fn scope(&self) -> crate::Scope { crate::Scope::Certificate }
        fn applies_to(&self) -> crate::SubjectKind { crate::SubjectKind::Any }
        fn check_cert(&self, _cert: &Certificate, _kind: crate::SubjectKind, _now: u64) -> crate::LintResult {
            crate::LintResult::Pass
        }
    }

    #[test]
    fn deviation_runner_moves_deviated_finding_to_deviated() {
        let cert = load_cert();
        let now: u64 = 1_000_000;

        let mut store = DeviationStore::new();
        store.add(Deviation {
            target_lint: "test.always_error",
            ..make_deviation("d1", "test.always_error")
        });

        let runner = crate::LintRunner::new(vec![Box::new(AlwaysError)]);
        let dev_runner = DeviationRunner::new(runner, store);
        let result = dev_runner.run_cert(&cert, crate::SubjectKind::Leaf, 0, now);

        // The error finding must be deviated, not in normal findings.
        assert!(result.findings.is_empty(), "deviated finding must not be in findings");
        assert_eq!(result.deviated.len(), 1, "deviated finding must be in deviated");
        assert_eq!(result.deviated[0].lint_id, "test.always_error");
        assert_eq!(result.deviated[0].deviation_id, "d1");
        // Original result is preserved.
        assert!(matches!(result.deviated[0].original_result, crate::LintResult::Error(_)));
    }

    #[test]
    fn deviation_runner_non_deviated_finding_stays_in_findings() {
        let cert = load_cert();
        let now: u64 = 1_000_000;

        // Deviation targets a different lint than what we're running.
        let mut store = DeviationStore::new();
        store.add(make_deviation("d1", "test.different_lint"));

        let runner = crate::LintRunner::new(vec![Box::new(AlwaysPass)]);
        let dev_runner = DeviationRunner::new(runner, store);
        let result = dev_runner.run_cert(&cert, crate::SubjectKind::Leaf, 0, now);

        // Pass finding not matched by deviation: stays in findings.
        assert_eq!(result.findings.len(), 1);
        assert!(result.deviated.is_empty());
    }

    #[test]
    fn deviation_runner_expired_deviation_does_not_apply() {
        let cert = load_cert();
        let now: u64 = 2_000_000;

        let mut store = DeviationStore::new();
        store.add(Deviation {
            effective_end: Some(1_000_000), // expired before now
            ..make_deviation("d1", "test.always_error")
        });

        let runner = crate::LintRunner::new(vec![Box::new(AlwaysError)]);
        let dev_runner = DeviationRunner::new(runner, store);
        let result = dev_runner.run_cert(&cert, crate::SubjectKind::Leaf, 0, now);

        // Expired deviation: error finding stays in findings (not deviated).
        assert_eq!(result.findings.len(), 1);
        assert!(result.deviated.is_empty());
    }

    #[test]
    fn deviation_runner_suppress_action_sets_effective_severity_none() {
        let cert = load_cert();
        let now: u64 = 1_000_000;

        let mut store = DeviationStore::new();
        store.add(Deviation {
            action: DeviationAction::Suppress,
            ..make_deviation("d1", "test.always_error")
        });

        let runner = crate::LintRunner::new(vec![Box::new(AlwaysError)]);
        let dev_runner = DeviationRunner::new(runner, store);
        let result = dev_runner.run_cert(&cert, crate::SubjectKind::Leaf, 0, now);

        assert!(result.findings.is_empty());
        assert_eq!(result.deviated.len(), 1);
        // Suppressed findings have no effective severity.
        assert_eq!(result.deviated[0].effective_severity(), None);
    }

    /// evidence_uri flows from Deviation through to DeviatedFinding.
    ///
    /// Oracle: DeviatedFinding.evidence_uri must equal Deviation.evidence_uri.
    /// This is the field operators use to navigate to the waiver document.
    #[test]
    fn evidence_uri_flows_to_deviated_finding() {
        let cert = load_cert();
        let now: u64 = 1_000_000;
        let uri = "https://pkipolicy.agency.gov/waivers/2025-11-03";

        let mut store = DeviationStore::new();
        store.add(Deviation {
            evidence_uri: Some(uri.to_string()),
            ..make_deviation("d1", "test.always_error")
        });

        let runner = crate::LintRunner::new(vec![Box::new(AlwaysError)]);
        let dev_runner = DeviationRunner::new(runner, store);
        let result = dev_runner.run_cert(&cert, crate::SubjectKind::Leaf, 0, now);

        assert_eq!(result.deviated.len(), 1);
        assert_eq!(
            result.deviated[0].evidence_uri.as_deref(),
            Some(uri),
            "evidence_uri must flow from Deviation to DeviatedFinding"
        );
        // justification also flows through.
        assert_eq!(
            result.deviated[0].justification,
            "test justification"
        );
    }

    /// When evidence_uri is None, DeviatedFinding.evidence_uri is None.
    #[test]
    fn evidence_uri_none_when_deviation_has_no_uri() {
        let cert = load_cert();
        let now: u64 = 1_000_000;

        let mut store = DeviationStore::new();
        store.add(make_deviation("d1", "test.always_error")); // evidence_uri: None

        let runner = crate::LintRunner::new(vec![Box::new(AlwaysError)]);
        let dev_runner = DeviationRunner::new(runner, store);
        let result = dev_runner.run_cert(&cert, crate::SubjectKind::Leaf, 0, now);

        assert_eq!(result.deviated.len(), 1);
        assert_eq!(result.deviated[0].evidence_uri, None);
    }
}
