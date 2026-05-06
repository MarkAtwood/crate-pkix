#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! Lint engine for X.509 certificate chains — structured soft-fail and advisory results.
//!
//! # What this crate provides
//!
//! `pkix-path` returns `Result<ValidatedPath, Error>` — hard pass or fail.
//! That model cannot express "this certificate is RFC 5280 valid but violates
//! CA/B Forum BR §7.1.4.2" without aborting the chain entirely.
//!
//! `pkix-lint` adds an advisory layer:
//!
//! - [`Lint`] — the unit of evaluation. Each lint has a stable ID, a normative
//!   citation, a severity, a scope (certificate vs. full chain path), and a
//!   subject-kind filter (leaf, intermediate CA, etc.).
//! - [`LintResult`] — `Pass | NotApplicable | Warn | Error | Fatal`. `Warn`
//!   and `Error` carry a `&'static str` detail message. `Fatal` within
//!   `pkix-lint` means "stop evaluating further lints" — it is **not** a TLS
//!   hard-fail. See the advisory-only contract below.
//! - [`Finding`] — a lint ID paired with a [`LintResult`], optionally referencing
//!   the chain index of the offending certificate.
//! - [`LintRunner`] — evaluates a slice of `dyn Lint` objects against a certificate
//!   or validated path and returns `Vec<Finding>`.
//! - [`LintProfile`] — extends [`pkix_path::Profile`] with a `lints()` method so
//!   that a profile can bundle its own lint set.
//!
//! # Finding ID stability
//!
//! Finding IDs (returned by [`Lint::id`]) are part of the public API.
//! They MUST NOT change between crate versions without a semver-major bump.
//! Format convention: `<regime>.<section>.<noun>`, e.g.:
//! - `"cabf.br.tls.validity.max"`
//! - `"cabf.smime.san.type"`
//! - `"rfc5280.basic_constraints.ca_flag"`
//!
//! # Advisory-only contract
//!
//! **`pkix-lint` findings never cause a certificate to be rejected.** All runner
//! methods return `Vec<Finding>` — they never return `Result::Err` and they never
//! cause a TLS stack to abort a connection. Findings are advisory signals.
//!
//! Whether to act on a finding (reject a TLS connection, block a cert, alert an
//! operator) is the caller's decision, configured per finding-ID at the integration
//! layer (e.g., `pkix-chain` or a TLS stack binding). This design is intentional:
//!
//! - `pkix-lint` does not know whether you are in audit, monitoring, or enforcement
//!   context. The caller does.
//! - Spec ambiguity (CA/B Forum CPs, FPKI CPs, etc.) means some findings require
//!   human judgment before enforcement. Hard-fail by default would cause outages.
//! - The deviation/waiver mechanism (PKIX-jge) operates at this layer, not in
//!   `pkix-lint` core.
//!
//! The only in-engine effect of [`LintResult::Fatal`] is stopping further lint
//! evaluation for the current item — it does not escape as an error.
//!
//! # Design rationale
//!
//! Inspired by zlint and certlint but with several deliberate differences:
//!
//! - **Trait-based, not enum-based**: external crates can implement [`Lint`] and
//!   pass `Box<dyn Lint>` to [`LintRunner`] without modifying this crate.
//! - **Static detail messages**: `LintResult::Warn` and `LintResult::Error` carry
//!   `&'static str` detail. This keeps the engine allocation-free in the common path.
//!   Dynamic messages are planned for v0.3 via `Cow<'static, str>`.
//! - **Temporality-aware**: [`LintRunner::run_cert`] takes `now_unix: u64` so lints
//!   can enforce rules that have effective dates (e.g., SC-081 validity caps).
//! - **Scope-separated**: certificate lints and path lints run in separate passes so
//!   path lints can see the full validated output.
//!
//! # Example
//!
//! ```rust,ignore
//! use pkix_lint::{Lint, LintResult, LintRunner, Scope, Severity, SubjectKind};
//! use x509_cert::Certificate;
//!
//! struct MyLint;
//! impl Lint for MyLint {
//!     fn id(&self) -> &'static str { "example.my_lint" }
//!     fn citation(&self) -> &'static str { "Example Corp Policy §1.2" }
//!     fn severity(&self) -> Severity { Severity::Warn }
//!     fn scope(&self) -> Scope { Scope::Certificate }
//!     fn applies_to(&self) -> SubjectKind { SubjectKind::Leaf }
//!     fn check_cert(&self, cert: &Certificate, _now: u64) -> LintResult {
//!         if cert.tbs_certificate.subject.to_string().is_empty() {
//!             LintResult::Warn("empty Subject DN")
//!         } else {
//!             LintResult::Pass
//!         }
//!     }
//! }
//!
//! let runner = LintRunner::new(vec![Box::new(MyLint)]);
//! let findings = runner.run_cert(&cert, SubjectKind::Leaf, now_unix);
//! for f in &findings {
//!     println!("{}: {:?}", f.lint_id, f.result);
//! }
//! ```

use x509_cert::Certificate;

// Re-export so callers only need to depend on pkix-lint, not pkix-path.
pub use pkix_path::{Profile, ValidatedPath, ValidationPolicy};

pub mod cabf_tls_br;
pub mod deviation;
pub mod report;

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

/// How seriously to treat a lint finding.
///
/// Severity is a property of the lint definition, not the result. A lint that
/// checks a MUST requirement from a normative spec should be [`Severity::Error`].
/// A lint that checks a SHOULD or advisory requirement should be [`Severity::Warn`].
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Severity {
    /// Advisory / best-practice — does not constitute a violation.
    Info,
    /// Violation of a SHOULD or RECOMMENDED requirement.
    Warn,
    /// Violation of a MUST or REQUIRED requirement.
    Error,
    /// Violation so severe that further evaluation is meaningless.
    ///
    /// For example: malformed DER structure that prevents parsing subsequent fields.
    Fatal,
}

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

/// Whether a lint evaluates a single certificate or the complete validated path.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Scope {
    /// The lint evaluates one certificate in isolation.
    Certificate,
    /// The lint evaluates the full [`ValidatedPath`] and all certificates together.
    Path,
}

// ---------------------------------------------------------------------------
// SubjectKind
// ---------------------------------------------------------------------------

/// Which certificate positions in the chain a lint applies to.
///
/// Used both as a filter in [`Lint::applies_to`] (which certs the lint checks)
/// and as the label in [`LintRunner`] when calling the lint (what cert we're at).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SubjectKind {
    /// End-entity (leaf) certificate — the subject of the chain.
    Leaf,
    /// Intermediate CA certificate — has BasicConstraints cA=TRUE, not a trust anchor.
    IntermediateCa,
    /// Any certificate issued directly by a trust anchor (the top intermediate).
    AnchorIssued,
    /// All certificate positions (lint applies universally).
    Any,
}

impl SubjectKind {
    /// Returns `true` if a lint declared for `filter` should run against `self`.
    ///
    /// Rules:
    /// - `Any` filter matches everything.
    /// - An exact match always returns `true`.
    /// - `AnchorIssued` is a sub-category of `IntermediateCa`; a filter of
    ///   `IntermediateCa` also matches `AnchorIssued` certificates.
    #[must_use]
    pub fn matches(self, filter: SubjectKind) -> bool {
        match filter {
            SubjectKind::Any => true,
            SubjectKind::IntermediateCa => {
                self == SubjectKind::IntermediateCa || self == SubjectKind::AnchorIssued
            }
            other => self == other,
        }
    }
}

// ---------------------------------------------------------------------------
// LintResult
// ---------------------------------------------------------------------------

/// The outcome of evaluating a single lint against a certificate or path.
///
/// # Stability
///
/// The variant names and associated `&'static str` detail fields are stable.
/// Dynamic `String` detail is planned for v0.3 via `Cow<'static, str>`.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LintResult {
    /// The lint check passed — no finding.
    Pass,
    /// The lint does not apply to this certificate or context.
    ///
    /// For example, a lint that checks SAN for leaves would return `NotApplicable`
    /// when called against an intermediate CA certificate.
    ///
    /// `NotApplicable` is not an error; the runner records it for audit completeness
    /// but it does not affect compliance status.
    NotApplicable,
    /// Advisory finding — the cert deviates from a SHOULD or best practice.
    ///
    /// The `&'static str` field is a human-readable explanation of the finding.
    Warn(&'static str),
    /// Error finding — the cert violates a MUST or REQUIRED requirement.
    ///
    /// The `&'static str` field is a human-readable explanation of the finding.
    Error(&'static str),
    /// Fatal finding — further evaluation of this cert/path is not meaningful.
    ///
    /// The `&'static str` field is a human-readable explanation of the finding.
    /// The runner stops evaluating remaining lints for the current item when
    /// it encounters a `Fatal`.
    ///
    /// # `Fatal` is report-only
    ///
    /// **`Fatal` does NOT cause the TLS stack to reject the certificate.**
    /// `pkix-lint` is an advisory layer only. All findings — including `Fatal` —
    /// are reported in the `Vec<Finding>` returned by [`LintRunner`]. Whether to
    /// act on a finding (e.g., reject a TLS connection, abort a certificate
    /// issuance, or log a compliance event) is the caller's decision, made at the
    /// integration boundary (e.g., `pkix-chain` or a TLS stack binding).
    ///
    /// The only effect of `Fatal` within `pkix-lint` itself is to stop evaluating
    /// further lints for the current certificate or path — it does not propagate
    /// as a `Result::Err` or cause any panic.
    Fatal(&'static str),
}

impl LintResult {
    /// Returns `true` if this result represents a clean pass (no finding).
    #[must_use]
    pub fn is_pass(&self) -> bool {
        matches!(self, LintResult::Pass)
    }

    /// Returns `true` if this result represents a finding (Warn, Error, or Fatal).
    #[must_use]
    pub fn is_finding(&self) -> bool {
        matches!(
            self,
            LintResult::Warn(_) | LintResult::Error(_) | LintResult::Fatal(_)
        )
    }

    /// Returns `true` if the runner should stop evaluating further lints for this item.
    #[must_use]
    pub fn is_fatal(&self) -> bool {
        matches!(self, LintResult::Fatal(_))
    }

    /// Returns the detail message for `Warn`, `Error`, or `Fatal`; `None` for `Pass`/`NotApplicable`.
    #[must_use]
    pub fn detail(&self) -> Option<&'static str> {
        match self {
            LintResult::Warn(d) | LintResult::Error(d) | LintResult::Fatal(d) => Some(d),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Display implementations
// ---------------------------------------------------------------------------

impl core::fmt::Display for Severity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Severity::Info => f.write_str("info"),
            Severity::Warn => f.write_str("warn"),
            Severity::Error => f.write_str("error"),
            Severity::Fatal => f.write_str("fatal"),
        }
    }
}

impl core::fmt::Display for LintResult {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LintResult::Pass => f.write_str("Pass"),
            LintResult::NotApplicable => f.write_str("NotApplicable"),
            LintResult::Warn(msg) => write!(f, "Warn: {msg}"),
            LintResult::Error(msg) => write!(f, "Error: {msg}"),
            LintResult::Fatal(msg) => write!(f, "Fatal: {msg}"),
        }
    }
}

impl core::fmt::Display for Finding {
    /// Format: `"lint_id [severity]: message"` for findings, `"lint_id [pass]"` for non-findings.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let severity_label = match &self.result {
            LintResult::Warn(_) => "warn",
            LintResult::Error(_) => "error",
            LintResult::Fatal(_) => "fatal",
            LintResult::Pass => "pass",
            LintResult::NotApplicable => "n/a",
        };
        match self.result.detail() {
            Some(msg) => write!(f, "{} [{}]: {}", self.lint_id, severity_label, msg),
            None => write!(f, "{} [{}]", self.lint_id, severity_label),
        }
    }
}

// ---------------------------------------------------------------------------
// Lint trait
// ---------------------------------------------------------------------------

/// A single, independently evaluable lint check.
///
/// # Implementing `Lint`
///
/// Each lint must have a stable, globally unique ID (see crate-level doc for the
/// naming convention). Both `check_cert` and `check_path` are provided so the
/// same trait covers both certificate-scoped and path-scoped lints. Implement
/// whichever method is appropriate for your lint and let the other return
/// [`LintResult::NotApplicable`] (the default).
///
/// # Object safety
///
/// The trait is object-safe: `Box<dyn Lint>` and `&dyn Lint` both work.
pub trait Lint: Send + Sync {
    /// Globally unique, stable identifier for this lint.
    ///
    /// Format: `<regime>.<section>.<noun>` e.g. `"cabf.br.tls.validity.max"`.
    /// This string is part of the public API — never change it once published.
    fn id(&self) -> &'static str;

    /// Human-readable citation: spec name, version, and section.
    ///
    /// Example: `"CA/B Forum TLS BR §6.3.2 (SC-081)"`.
    /// Not parsed by the engine; used in reports and error messages.
    fn citation(&self) -> &'static str;

    /// The declared severity of a positive finding from this lint.
    ///
    /// Note: [`LintResult::Warn`] and [`LintResult::Error`] can be returned
    /// regardless of the declared `severity()`. The declared severity is metadata
    /// used by report renderers and compliance dashboards.
    fn severity(&self) -> Severity;

    /// Whether this lint operates on individual certificates or the full path.
    fn scope(&self) -> Scope;

    /// Which certificate positions this lint applies to.
    ///
    /// The runner uses this to skip `check_cert` for positions that don't match,
    /// returning [`LintResult::NotApplicable`] automatically.
    fn applies_to(&self) -> SubjectKind;

    /// Evaluate the lint against a single certificate.
    ///
    /// `kind` is the role of this certificate in the chain (leaf, intermediate CA, etc.).
    /// `now_unix` is seconds since the Unix epoch at evaluation time.
    ///
    /// Default: returns [`LintResult::NotApplicable`].
    /// Lints with `scope() == Scope::Certificate` MUST override this method.
    #[allow(unused_variables)]
    fn check_cert(&self, cert: &Certificate, kind: SubjectKind, now_unix: u64) -> LintResult {
        LintResult::NotApplicable
    }

    /// Evaluate the lint against the full validated path.
    ///
    /// `chain` is the full certificate chain (leaf-first). `path` is the
    /// [`ValidatedPath`] returned by `pkix_path::validate_path`.
    /// `now_unix` is seconds since the Unix epoch at evaluation time.
    ///
    /// Default: returns [`LintResult::NotApplicable`].
    /// Lints with `scope() == Scope::Path` MUST override this method.
    #[allow(unused_variables)]
    fn check_path(
        &self,
        chain: &[Certificate],
        path: &ValidatedPath,
        now_unix: u64,
    ) -> LintResult {
        LintResult::NotApplicable
    }
}

// ---------------------------------------------------------------------------
// Finding
// ---------------------------------------------------------------------------

/// A recorded lint outcome, associating a lint ID with its result.
///
/// # Evidence pack support
///
/// `Finding` carries the metadata needed to construct an evidence pack
/// (a bundle of cert + path + findings + citations exportable as structured JSON
/// or OSCAL Assessment Results). The `citation` field records the normative
/// citation from [`Lint::citation`]; `evaluated_at_unix` records when the lint
/// was run; `rule_bundle_version` records which version of the lint bundle was active.
///
/// # Planned fields (v0.3)
///
/// - `cert_sha256: [u8; 32]` — SHA-256 of the DER cert that triggered this finding.
///   Deferred to avoid adding a SHA-256 dependency to the engine core.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    /// The stable ID of the lint that produced this finding (from [`Lint::id`]).
    pub lint_id: &'static str,
    /// The normative citation for this lint (from [`Lint::citation`]).
    ///
    /// Included here so consumers of `Vec<Finding>` do not need to re-look up
    /// the lint to get the citation for report generation and evidence packs.
    pub citation: &'static str,
    /// Version string of the rule bundle that produced this finding.
    ///
    /// Set by [`LintRunner::with_bundle_version`]. Defaults to `""` when the runner
    /// was constructed with [`LintRunner::new`] without a version.
    ///
    /// Example: `"pkix-lint/cabf_tls_br v0.2.0, sourced from TLS BR SC-081"`.
    ///
    /// This field enables the "yellow today, green tomorrow because we updated the
    /// rule bundle from v1.3 to v1.4" explanation that prevents operators from
    /// treating a finding change as a tool defect.
    pub rule_bundle_version: &'static str,
    /// The outcome of the lint evaluation.
    pub result: LintResult,
    /// For certificate-scope lints, the zero-based chain index of the evaluated cert.
    /// `None` for path-scope lints.
    pub cert_index: Option<usize>,
    /// Unix epoch seconds at which the lint was evaluated.
    ///
    /// For audit-mode evaluations (pass issuance time), this records the issuance time.
    /// For operational-mode evaluations (pass current time), this records the current time.
    /// Together with `cert_index` and the chain, this is sufficient to reconstruct
    /// the evaluation context in an evidence pack.
    pub evaluated_at_unix: u64,
}

impl Finding {
    /// Returns `true` if this finding is actionable (Warn, Error, or Fatal).
    #[must_use]
    pub fn is_finding(&self) -> bool {
        self.result.is_finding()
    }
}

// ---------------------------------------------------------------------------
// LintRunner
// ---------------------------------------------------------------------------

/// Evaluates a collection of [`Lint`]s against certificates or a validated path.
///
/// The runner is stateless beyond the lint set — construct once, call many times.
///
/// # Findings are advisory only
///
/// `LintRunner` methods return `Vec<Finding>` — they never return `Result::Err`
/// and they never cause a certificate to be rejected by a TLS stack. Findings
/// are an advisory layer. Whether to act on a finding (reject a connection,
/// block a cert, page an operator) is the caller's responsibility, configured
/// per finding-ID at the integration boundary.
///
/// This separation is intentional and must not be violated:
/// - `pkix-lint` does not know whether you are in an audit context, a
///   monitoring context, or an enforcement context. The caller does.
/// - Hard-fail behavior per finding-ID is configured in the integration layer
///   (e.g., `pkix-chain` or a TLS stack binding), not here.
/// - `pkix-lint` will never introduce a code path that returns `Err` or
///   panics based on lint findings.
///
/// # Evaluation order
///
/// Lints are evaluated in the order they were supplied to [`LintRunner::new`].
/// If a lint returns [`LintResult::Fatal`], the runner stops evaluating further
/// lints for the current item (cert or path) and records the fatal finding.
/// See [`LintResult::Fatal`] for the definition of "fatal within lint evaluation."
///
/// # Thread safety
///
/// `LintRunner` is `Send + Sync` as long as all supplied lints are `Send + Sync`
/// (enforced by the `Lint: Send + Sync` bound).
pub struct LintRunner {
    lints: Vec<Box<dyn Lint>>,
    /// Version string stamped into every [`Finding`] produced by this runner.
    ///
    /// Set via [`LintRunner::with_bundle_version`]. Defaults to `""`.
    bundle_version: &'static str,
}

impl core::fmt::Debug for LintRunner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LintRunner")
            .field("lint_count", &self.lints.len())
            .field("bundle_version", &self.bundle_version)
            .finish()
    }
}

impl LintRunner {
    /// Create a new runner from a set of lints, with no bundle version string.
    ///
    /// Lints are evaluated in the order supplied. Duplicates (same `id()`) are
    /// allowed but will produce duplicate findings — callers should deduplicate.
    ///
    /// To set a bundle version (recommended for production use), use
    /// [`LintRunner::with_bundle_version`].
    #[must_use]
    pub fn new(lints: Vec<Box<dyn Lint>>) -> Self {
        Self {
            lints,
            bundle_version: "",
        }
    }

    /// Create a new runner with an explicit bundle version string.
    ///
    /// The `version` string is stamped into every [`Finding`] produced by this runner
    /// as [`Finding::rule_bundle_version`]. Use this in production to record which
    /// version of the rule bundle was active when findings were generated.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let runner = LintRunner::with_bundle_version(
    ///     lints,
    ///     "pkix-lint/cabf_tls_br v0.2.0, sourced from TLS BR SC-081",
    /// );
    /// ```
    #[must_use]
    pub fn with_bundle_version(lints: Vec<Box<dyn Lint>>, version: &'static str) -> Self {
        Self {
            lints,
            bundle_version: version,
        }
    }

    /// Return a reference to the registered lints.
    pub fn lints(&self) -> &[Box<dyn Lint>] {
        &self.lints
    }

    /// Return the bundle version string set on this runner.
    pub fn bundle_version(&self) -> &'static str {
        self.bundle_version
    }

    /// Evaluate all certificate-scope lints against `cert`.
    ///
    /// `kind` is the position of this certificate in the chain (leaf, intermediate, etc.).
    /// `now_unix` is the evaluation time (seconds since Unix epoch).
    ///
    /// # Evaluation modes
    ///
    /// Pass the **issuance time** (`cert.tbs_certificate.validity.not_before`) for
    /// audit-mode evaluation: "was this cert compliant when it was issued?"
    ///
    /// Pass the **current time** for operational-mode evaluation: "is this cert
    /// compliant under current rules?"
    ///
    /// Use [`LintRunner::run_cert_at_issuance`] as a convenience wrapper for audit mode.
    ///
    /// Both modes are valid and different — lints with effective dates (e.g., SC-081
    /// validity caps) produce different results depending on which mode is used.
    ///
    /// Only lints with `scope() == Scope::Certificate` whose `applies_to()` matches
    /// `kind` are invoked. Lints that do not apply return `NotApplicable` findings
    /// (recorded for audit completeness).
    ///
    /// Evaluation stops early if any lint returns `Fatal`.
    #[must_use]
    pub fn run_cert(
        &self,
        cert: &Certificate,
        kind: SubjectKind,
        cert_index: usize,
        now_unix: u64,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        for lint in &self.lints {
            if lint.scope() != Scope::Certificate {
                continue;
            }
            let result = if kind.matches(lint.applies_to()) {
                lint.check_cert(cert, kind, now_unix)
            } else {
                LintResult::NotApplicable
            };
            let is_fatal = result.is_fatal();
            findings.push(Finding {
                lint_id: lint.id(),
                citation: lint.citation(),
                rule_bundle_version: self.bundle_version,
                result,
                cert_index: Some(cert_index),
                evaluated_at_unix: now_unix,
            });
            if is_fatal {
                break;
            }
        }
        findings
    }

    /// Evaluate certificate-scope lints as of the certificate's issuance time.
    ///
    /// Convenience wrapper for **audit mode**: extracts `notBefore` from the cert
    /// and passes it as `now_unix` to `run_cert`. This answers: "was this cert
    /// compliant when it was issued?"
    ///
    /// For operational mode ("is it compliant under current rules?"), call `run_cert`
    /// directly with the current time.
    ///
    /// See `run_cert` for full documentation on evaluation modes.
    #[must_use]
    pub fn run_cert_at_issuance(
        &self,
        cert: &Certificate,
        kind: SubjectKind,
        cert_index: usize,
    ) -> Vec<Finding> {
        let issuance_unix = cert
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            .as_secs();
        self.run_cert(cert, kind, cert_index, issuance_unix)
    }

    /// Evaluate all certificate-scope lints against every certificate in `chain`.
    ///
    /// `kinds` maps chain index to [`SubjectKind`]. If `kinds` is shorter than
    /// `chain`, remaining certs are treated as [`SubjectKind::IntermediateCa`].
    ///
    /// Returns a flat `Vec<Finding>` with cert_index set for each.
    ///
    /// # Determining the `AnchorIssued` position
    ///
    /// The `AnchorIssued` certificate is the one directly signed by the trust anchor —
    /// typically the last certificate in the chain before the anchor itself (i.e., the
    /// highest-index intermediate). Callers are responsible for identifying this
    /// position and passing [`SubjectKind::AnchorIssued`] in `kinds`. The runner has
    /// no access to trust anchor information and cannot determine this automatically.
    ///
    /// # Fatal behavior across certificates
    ///
    /// Note: [`LintResult::Fatal`] stops lint evaluation for the *current certificate
    /// only*. Subsequent certificates in the chain continue to be evaluated.
    #[must_use]
    pub fn run_chain(
        &self,
        chain: &[Certificate],
        kinds: &[SubjectKind],
        now_unix: u64,
    ) -> Vec<Finding> {
        let mut all = Vec::new();
        for (i, cert) in chain.iter().enumerate() {
            let kind = kinds.get(i).copied().unwrap_or(SubjectKind::IntermediateCa);
            all.extend(self.run_cert(cert, kind, i, now_unix));
        }
        all
    }

    /// Evaluate all path-scope lints against the full validated path.
    ///
    /// `chain` must be the same slice passed to `pkix_path::validate_path`.
    /// `path` is the [`ValidatedPath`] returned by that call.
    ///
    /// Evaluation stops early if any lint returns `Fatal`.
    #[must_use]
    pub fn run_path(
        &self,
        chain: &[Certificate],
        path: &ValidatedPath,
        now_unix: u64,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        for lint in &self.lints {
            if lint.scope() != Scope::Path {
                continue;
            }
            let result = lint.check_path(chain, path, now_unix);
            let is_fatal = result.is_fatal();
            findings.push(Finding {
                lint_id: lint.id(),
                citation: lint.citation(),
                rule_bundle_version: self.bundle_version,
                result,
                cert_index: None,
                evaluated_at_unix: now_unix,
            });
            if is_fatal {
                break;
            }
        }
        findings
    }
}

// ---------------------------------------------------------------------------
// LintProfile trait
// ---------------------------------------------------------------------------

/// A [`Profile`] that also bundles a set of lints.
///
/// This is the integration point between profile policy and the lint engine.
/// Implement `LintProfile` on a type that already implements [`Profile`] to
/// associate a set of lints with the profile.
///
/// # Why not on `Profile` directly?
///
/// Adding `lints()` to [`pkix_path::Profile`] would create a mandatory dep on
/// `pkix-lint` from `pkix-path`. That would violate `pkix-path`'s `no_std`
/// boundary and force the lint engine into every profile consumer.
/// `LintProfile` is a separate trait in `pkix-lint` that callers opt into.
pub trait LintProfile: Profile {
    /// Return the lints that this profile enforces.
    ///
    /// The returned slice owns `Box<dyn Lint>` values. The runner uses them
    /// directly — no cloning needed.
    fn lints(&self) -> &[Box<dyn Lint>];

    /// Convenience: produce a [`LintRunner`] from this profile's lints.
    ///
    /// Implementors should document whether this method caches the runner or
    /// allocates fresh on each call. Callers that invoke this repeatedly should
    /// cache the returned [`LintRunner`] themselves.
    #[must_use]
    fn lint_runner(&self) -> LintRunner;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // SubjectKind::matches tests
    //
    // Oracle: the filter/subject matching rules in the SubjectKind doc comment.
    // -----------------------------------------------------------------------

    #[test]
    fn subject_kind_any_matches_all() {
        for &kind in &[
            SubjectKind::Leaf,
            SubjectKind::IntermediateCa,
            SubjectKind::AnchorIssued,
            SubjectKind::Any,
        ] {
            assert!(
                kind.matches(SubjectKind::Any),
                "{kind:?} must match filter Any"
            );
        }
    }

    #[test]
    fn subject_kind_exact_matches_self() {
        assert!(SubjectKind::Leaf.matches(SubjectKind::Leaf));
        assert!(SubjectKind::IntermediateCa.matches(SubjectKind::IntermediateCa));
        assert!(SubjectKind::AnchorIssued.matches(SubjectKind::AnchorIssued));
    }

    #[test]
    fn subject_kind_intermediate_filter_includes_anchor_issued() {
        // AnchorIssued is a sub-kind of IntermediateCa — an anchor-issued cert
        // is still a CA cert and should be checked by IntermediateCa lints.
        assert!(SubjectKind::AnchorIssued.matches(SubjectKind::IntermediateCa));
    }

    #[test]
    fn subject_kind_leaf_does_not_match_intermediate() {
        assert!(!SubjectKind::Leaf.matches(SubjectKind::IntermediateCa));
        assert!(!SubjectKind::Leaf.matches(SubjectKind::AnchorIssued));
    }

    #[test]
    fn subject_kind_intermediate_does_not_match_leaf() {
        assert!(!SubjectKind::IntermediateCa.matches(SubjectKind::Leaf));
    }

    // -----------------------------------------------------------------------
    // LintResult helper method tests
    //
    // Oracle: the LintResult variant semantics in the doc comments.
    // -----------------------------------------------------------------------

    #[test]
    fn lint_result_pass_is_pass() {
        assert!(LintResult::Pass.is_pass());
        assert!(!LintResult::Pass.is_finding());
        assert!(!LintResult::Pass.is_fatal());
        assert_eq!(LintResult::Pass.detail(), None);
    }

    #[test]
    fn lint_result_not_applicable_is_not_pass_not_finding() {
        assert!(!LintResult::NotApplicable.is_pass());
        assert!(!LintResult::NotApplicable.is_finding());
        assert_eq!(LintResult::NotApplicable.detail(), None);
    }

    #[test]
    fn lint_result_warn_is_finding() {
        let r = LintResult::Warn("test warning");
        assert!(!r.is_pass());
        assert!(r.is_finding());
        assert!(!r.is_fatal());
        assert_eq!(r.detail(), Some("test warning"));
    }

    #[test]
    fn lint_result_error_is_finding() {
        let r = LintResult::Error("test error");
        assert!(!r.is_pass());
        assert!(r.is_finding());
        assert!(!r.is_fatal());
        assert_eq!(r.detail(), Some("test error"));
    }

    #[test]
    fn lint_result_fatal_is_fatal_and_finding() {
        let r = LintResult::Fatal("fatal error");
        assert!(!r.is_pass());
        assert!(r.is_finding());
        assert!(r.is_fatal());
        assert_eq!(r.detail(), Some("fatal error"));
    }

    // -----------------------------------------------------------------------
    // LintRunner tests using a trivial in-test Lint implementation
    //
    // Oracle: the runner contract defined in LintRunner doc comments.
    // The test lints are independent oracles — they do not call other lints or
    // validate against the code under test.
    // -----------------------------------------------------------------------

    /// A lint that always passes, used to verify the runner records Pass findings.
    struct AlwaysPass;
    impl Lint for AlwaysPass {
        fn id(&self) -> &'static str {
            "test.always_pass"
        }
        fn citation(&self) -> &'static str {
            "test"
        }
        fn severity(&self) -> Severity {
            Severity::Info
        }
        fn scope(&self) -> Scope {
            Scope::Certificate
        }
        fn applies_to(&self) -> SubjectKind {
            SubjectKind::Any
        }
        fn check_cert(&self, _cert: &Certificate, _kind: SubjectKind, _now: u64) -> LintResult {
            LintResult::Pass
        }
    }

    /// A lint that always warns, used to verify runner records Warn findings.
    struct AlwaysWarn;
    impl Lint for AlwaysWarn {
        fn id(&self) -> &'static str {
            "test.always_warn"
        }
        fn citation(&self) -> &'static str {
            "test"
        }
        fn severity(&self) -> Severity {
            Severity::Warn
        }
        fn scope(&self) -> Scope {
            Scope::Certificate
        }
        fn applies_to(&self) -> SubjectKind {
            SubjectKind::Any
        }
        fn check_cert(&self, _cert: &Certificate, _kind: SubjectKind, _now: u64) -> LintResult {
            LintResult::Warn("always warns")
        }
    }

    /// A lint that always returns Fatal, used to test early-exit behavior.
    struct AlwaysFatal;
    impl Lint for AlwaysFatal {
        fn id(&self) -> &'static str {
            "test.always_fatal"
        }
        fn citation(&self) -> &'static str {
            "test"
        }
        fn severity(&self) -> Severity {
            Severity::Fatal
        }
        fn scope(&self) -> Scope {
            Scope::Certificate
        }
        fn applies_to(&self) -> SubjectKind {
            SubjectKind::Any
        }
        fn check_cert(&self, _cert: &Certificate, _kind: SubjectKind, _now: u64) -> LintResult {
            LintResult::Fatal("always fatal")
        }
    }

    /// A lint scoped to leaves only, used to verify kind filtering.
    struct LeafOnlyLint;
    impl Lint for LeafOnlyLint {
        fn id(&self) -> &'static str {
            "test.leaf_only"
        }
        fn citation(&self) -> &'static str {
            "test"
        }
        fn severity(&self) -> Severity {
            Severity::Warn
        }
        fn scope(&self) -> Scope {
            Scope::Certificate
        }
        fn applies_to(&self) -> SubjectKind {
            SubjectKind::Leaf
        }
        fn check_cert(&self, _cert: &Certificate, _kind: SubjectKind, _now: u64) -> LintResult {
            LintResult::Warn("leaf lint fires")
        }
    }

    /// A path-scope lint, used to verify run_path.
    struct PathDepthLint;
    impl Lint for PathDepthLint {
        fn id(&self) -> &'static str {
            "test.path_depth"
        }
        fn citation(&self) -> &'static str {
            "test"
        }
        fn severity(&self) -> Severity {
            Severity::Warn
        }
        fn scope(&self) -> Scope {
            Scope::Path
        }
        fn applies_to(&self) -> SubjectKind {
            SubjectKind::Any
        }
        fn check_path(
            &self,
            _chain: &[Certificate],
            path: &ValidatedPath,
            _now: u64,
        ) -> LintResult {
            if path.depth > 5 {
                LintResult::Warn("chain depth exceeds 5")
            } else {
                LintResult::Pass
            }
        }
    }

    // We need a minimal Certificate to call run_cert. Load from a real fixture.
    fn load_fixture_cert() -> Certificate {
        use der::Decode as _;
        Certificate::from_der(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/webpki-self-signed-365d.der"
        ))
        .expect("fixture is valid DER")
    }

    #[test]
    fn runner_records_pass_finding() {
        let cert = load_fixture_cert();
        let runner = LintRunner::new(vec![Box::new(AlwaysPass)]);
        let findings = runner.run_cert(&cert, SubjectKind::Leaf, 0, 0);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].lint_id, "test.always_pass");
        assert_eq!(findings[0].result, LintResult::Pass);
        assert_eq!(findings[0].cert_index, Some(0));
    }

    #[test]
    fn runner_records_warn_finding() {
        let cert = load_fixture_cert();
        let runner = LintRunner::new(vec![Box::new(AlwaysWarn)]);
        let findings = runner.run_cert(&cert, SubjectKind::Leaf, 0, 0);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].lint_id, "test.always_warn");
        assert!(matches!(findings[0].result, LintResult::Warn(_)));
        assert!(findings[0].is_finding());
    }

    #[test]
    fn runner_stops_after_fatal() {
        // Fatal lint followed by another lint — the second must NOT be evaluated.
        let cert = load_fixture_cert();
        let runner = LintRunner::new(vec![
            Box::new(AlwaysFatal),
            Box::new(AlwaysWarn), // must not appear in findings
        ]);
        let findings = runner.run_cert(&cert, SubjectKind::Leaf, 0, 0);
        // Only one finding: the fatal. The warn is never reached.
        assert_eq!(findings.len(), 1, "runner must stop after Fatal");
        assert_eq!(findings[0].lint_id, "test.always_fatal");
        assert!(findings[0].result.is_fatal());
    }

    #[test]
    fn runner_skips_non_applicable_scope_kind() {
        // LeafOnlyLint declares applies_to = Leaf.
        // Running it against IntermediateCa must return NotApplicable, not Warn.
        let cert = load_fixture_cert();
        let runner = LintRunner::new(vec![Box::new(LeafOnlyLint)]);
        let findings = runner.run_cert(&cert, SubjectKind::IntermediateCa, 1, 0);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].result, LintResult::NotApplicable);
    }

    #[test]
    fn runner_applies_leaf_lint_to_leaf() {
        let cert = load_fixture_cert();
        let runner = LintRunner::new(vec![Box::new(LeafOnlyLint)]);
        let findings = runner.run_cert(&cert, SubjectKind::Leaf, 0, 0);
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0].result, LintResult::Warn(_)));
    }

    fn validated_path_for_self_signed() -> (Vec<Certificate>, ValidatedPath) {
        use pkix_path::{EcdsaP256Verifier, TrustAnchor, ValidationPolicy};
        let cert = load_fixture_cert();
        let anchor = TrustAnchor::from_cert(cert.clone());
        // 2026-01-01 = pre-SC-081, so 365-day cert passes the 398-day cap.
        let policy = ValidationPolicy::new(1_767_225_600);
        let path = pkix_path::validate_path(std::slice::from_ref(&cert), &[anchor], &policy, &EcdsaP256Verifier)
            .expect("fixture cert must validate");
        (vec![cert], path)
    }

    #[test]
    fn runner_skips_cert_lints_in_run_path() {
        // AlwaysWarn is a Certificate-scope lint; run_path must not invoke it.
        let (chain, path) = validated_path_for_self_signed();
        let runner = LintRunner::new(vec![Box::new(AlwaysWarn)]);
        let findings = runner.run_path(&chain, &path, 0);
        assert!(
            findings.is_empty(),
            "run_path must not invoke Certificate-scope lints"
        );
    }

    #[test]
    fn runner_invokes_path_lint_in_run_path() {
        let (chain, path) = validated_path_for_self_signed();
        let runner = LintRunner::new(vec![Box::new(PathDepthLint)]);
        let findings = runner.run_path(&chain, &path, 0);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].lint_id, "test.path_depth");
        // Self-signed chain: depth=0, not > 5 → Pass.
        assert_eq!(findings[0].result, LintResult::Pass);
        assert_eq!(findings[0].cert_index, None, "path findings have no cert_index");
    }

    #[test]
    fn runner_run_chain_sets_cert_index() {
        let cert = load_fixture_cert();
        let chain = vec![cert.clone(), cert.clone(), cert];
        let kinds = vec![
            SubjectKind::Leaf,
            SubjectKind::IntermediateCa,
            SubjectKind::AnchorIssued,
        ];
        let runner = LintRunner::new(vec![Box::new(AlwaysPass)]);
        let findings = runner.run_chain(&chain, &kinds, 0);
        // One Pass finding per cert.
        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].cert_index, Some(0));
        assert_eq!(findings[1].cert_index, Some(1));
        assert_eq!(findings[2].cert_index, Some(2));
    }

    #[test]
    fn finding_is_finding_reflects_result() {
        let f_pass = Finding {
            lint_id: "x",
            citation: "test",
            rule_bundle_version: "",
            result: LintResult::Pass,
            cert_index: None,
            evaluated_at_unix: 0,
        };
        let f_warn = Finding {
            lint_id: "x",
            citation: "test",
            rule_bundle_version: "",
            result: LintResult::Warn("w"),
            cert_index: None,
            evaluated_at_unix: 0,
        };
        assert!(!f_pass.is_finding());
        assert!(f_warn.is_finding());
    }

    #[test]
    fn finding_citation_is_threaded_from_lint() {
        let cert = load_fixture_cert();
        let runner = LintRunner::new(vec![Box::new(AlwaysPass)]);
        let findings = runner.run_cert(&cert, SubjectKind::Leaf, 0, 12345);
        assert_eq!(findings.len(), 1);
        // Citation must come from the lint's citation() method.
        assert_eq!(findings[0].citation, "test", "citation must be threaded from Lint::citation()");
        assert_eq!(findings[0].evaluated_at_unix, 12345, "evaluated_at_unix must be the passed now_unix");
    }

    #[test]
    fn run_cert_at_issuance_uses_not_before() {
        let cert = load_fixture_cert();
        // Get the expected issuance time from the cert's notBefore.
        let expected_unix = cert
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            .as_secs();
        let runner = LintRunner::new(vec![Box::new(AlwaysPass)]);
        let findings = runner.run_cert_at_issuance(&cert, SubjectKind::Leaf, 0);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].evaluated_at_unix, expected_unix,
            "run_cert_at_issuance must use cert notBefore as evaluated_at_unix"
        );
    }

    #[test]
    fn bundle_version_stamped_into_findings() {
        let cert = load_fixture_cert();
        let runner = LintRunner::with_bundle_version(
            vec![Box::new(AlwaysPass)],
            "pkix-lint/cabf_tls_br v0.2.0",
        );
        let findings = runner.run_cert(&cert, SubjectKind::Leaf, 0, 0);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].rule_bundle_version,
            "pkix-lint/cabf_tls_br v0.2.0",
            "rule_bundle_version must be stamped from runner into Finding"
        );
    }

    #[test]
    fn bundle_version_empty_by_default() {
        let cert = load_fixture_cert();
        let runner = LintRunner::new(vec![Box::new(AlwaysPass)]);
        let findings = runner.run_cert(&cert, SubjectKind::Leaf, 0, 0);
        assert_eq!(findings[0].rule_bundle_version, "");
    }
}
