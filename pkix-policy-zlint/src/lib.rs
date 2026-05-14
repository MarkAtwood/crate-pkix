#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! Thin [`pkix_lint::Lint`] adapter over [`pkix_zlint_bridge::ZlintBridge`].
//!
//! `pkix-policy-zlint` exposes each of zlint's per-check verdicts as a
//! workspace [`pkix_lint::Lint`] implementation, so callers can mix zlint
//! findings into a [`pkix_lint::LintRunner`] alongside the workspace's
//! own RFC-conformance and `-cabf` reference lints, without any awareness
//! that the verdicts come from a subprocess.
//!
//! Per AGENTS.md non-negotiable #5 (three-mode policy-class model), this
//! is the **principled path for predicate-comprehensive CA/B Forum
//! coverage**. zlint stays the source of truth for the checks it covers;
//! the workspace contributes the framework, not the policy. The hand-
//! authored [`pkix-lint-cabf`] reference set covers a small curated
//! subset of marquee BR predicates; this crate covers the whole catalog
//! (~400 lints at the time of writing).
//!
//! # Usage
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use pkix_lint::LintRunner;
//! use pkix_zlint_bridge::{BridgeConfig, ZlintBridge};
//! use pkix_policy_zlint::all_lints;
//!
//! # fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! // Construct one bridge per process. The bridge owns the per-cert
//! // verdict cache that amortises subprocess cost across all ~400
//! // wrapped lints.
//! let bridge = Arc::new(ZlintBridge::new(BridgeConfig::default())?);
//!
//! // Enumerate zlint's catalog once and wrap each check as a Lint.
//! let lints = all_lints(bridge)?;
//!
//! // Hand to the workspace LintRunner like any other Lint set.
//! let runner = LintRunner::new(lints);
//! # let _ = runner;
//! # Ok(())
//! # }
//! ```
//!
//! # Lint identity is leaked at adapter-construction time
//!
//! [`pkix_lint::Lint::id`] and [`pkix_lint::Lint::citation`] return
//! `&'static str`. zlint's catalog is enumerated at runtime, so the
//! metadata strings (`check_id`, `citation`, `description`) are
//! `String`s owned by [`pkix_zlint_bridge::ZlintLintInfo`]. To satisfy
//! the `&'static str` contract, [`all_lints`] leaks each `ZlintLintInfo`
//! once at construction time via `Box::leak`, and the resulting
//! [`ZlintLint`] holds a `&'static ZlintLintInfo`.
//!
//! The leak is **bounded and intentional**: ~400 leaks of small
//! `ZlintLintInfo` records (~150 bytes each, dominated by the catalog's
//! description string) at startup, never growing. This trades a small
//! one-time program-lifetime allocation for `&'static str`-shaped
//! metadata methods on the workspace [`pkix_lint::Lint`] trait. The
//! alternative — broadening the trait to `Cow<'static, str>` or
//! `Box<str>` — was rejected because it would ripple through every
//! hand-authored `Lint` impl in `pkix-lint`, `pkix-lint-cabf`, and
//! external crates for the sake of a single adapter.
//!
//! # Mapping zlint verdicts to [`pkix_lint::LintResult`]
//!
//! | [`pkix_zlint_bridge::Verdict`] | [`pkix_lint::LintResult`] |
//! |--------------------------------|---------------------------|
//! | `NotApplicable`                | `NotApplicable`           |
//! | `Pass`                         | `Pass`                    |
//! | `Notice`                       | `Warn(detail)`            |
//! | `Warn`                         | `Warn(detail)`            |
//! | `Error`                        | `Error(detail)`           |
//! | `Fatal`                        | `Fatal(detail)`           |
//!
//! `Notice` collapses into `Warn` at the LintResult level because
//! `LintResult` does not have a separate notice variant — the workspace
//! `Severity::Notice` is metadata on the lint, not on the per-cert
//! result. Reports that need to differentiate `Notice` from `Warn`
//! consult [`pkix_lint::Lint::severity`] (which forwards from
//! `ZlintLintInfo::severity`).
//!
//! Per-cert bridge errors (malformed DER, zlint runtime panic for that
//! cert) surface as `LintResult::Error` with the underlying error's
//! `Display` text as detail.
//!
//! # Limitations
//!
//! - **One [`ZlintBridge`] per program.** The bridge owns the
//!   per-certificate verdict cache; if you construct multiple bridges
//!   you pay the subprocess cost multiple times. Wrap the bridge in
//!   `Arc` and share it across all `ZlintLint` instances (which is what
//!   [`all_lints`] does).
//! - **`SubjectKind::Any` for every wrapped lint.** zlint's catalog
//!   metadata does not surface a stable "applies-to" classification
//!   (leaf vs. intermediate vs. anchor); zlint itself internally
//!   determines applicability and returns the per-cert `Verdict::NotApplicable`
//!   when the rule does not fire. The adapter therefore reports
//!   `SubjectKind::Any` and lets zlint's own logic do the filtering.
//! - **`Scope::Certificate` only.** zlint operates on a single
//!   certificate at a time; the adapter mirrors that. Path-scope lints
//!   (chain-wide rules like algorithm consistency across intermediates)
//!   live in `pkix-lint` and `pkix-lint-cabf`, not here.
//! - **Per-check `parameters()` empty.** zlint exposes no
//!   externally-configurable parameters per check; the adapter does not
//!   invent a parameter surface that zlint does not have.
//! - **`title()` and `description()` use the leaked `ZlintLintInfo`'s
//!   fields verbatim.** They are not localised, paraphrased, or
//!   reformatted — what zlint says is what callers see.
//!
//! [`pkix-lint-cabf`]: https://docs.rs/pkix-lint-cabf

use std::sync::Arc;

use der::Encode as _;
use pkix_lint::{Lint, LintResult, Scope, Severity, SubjectKind};
use pkix_zlint_bridge::{BridgeError, Verdict, ZlintBridge, ZlintLintInfo};
use x509_cert::Certificate;

/// One workspace [`Lint`] wrapping one zlint check.
///
/// Constructed by [`all_lints`]; not constructed directly by callers.
/// Holding `&'static ZlintLintInfo` lets [`Lint::id`] and
/// [`Lint::citation`] return the underlying `String` slices with the
/// required `&'static str` lifetime — see the crate-level rustdoc for
/// the leak-at-construction rationale.
///
/// `Clone` is required by the [`pkix_lint::LintClone`] supertrait that
/// gates `Box<dyn Lint>` cloning (PKIX-hy2e.6). Cloning a `ZlintLint`
/// duplicates the `&'static ZlintLintInfo` reference and clones the
/// shared `Arc<ZlintBridge>` — no per-cert subprocess work is
/// duplicated.
#[derive(Clone)]
pub struct ZlintLint {
    info: &'static ZlintLintInfo,
    bridge: Arc<ZlintBridge>,
}

impl ZlintLint {
    /// Construct a single `ZlintLint` for a specific zlint check.
    ///
    /// Most callers want [`all_lints`] instead, which enumerates the
    /// full catalog. This entry point is exposed for tests and for
    /// callers who want to restrict to a small hand-picked subset of
    /// zlint checks (e.g. a deployment that already runs its own
    /// `LintRunner` and wants to add three specific zlint checks).
    ///
    /// The caller is responsible for ensuring `info` outlives the
    /// `ZlintLint`. The simplest way to do that is to leak the
    /// `ZlintLintInfo` via `Box::leak` once at startup; that is what
    /// [`all_lints`] does internally.
    #[must_use]
    pub fn new(info: &'static ZlintLintInfo, bridge: Arc<ZlintBridge>) -> Self {
        Self { info, bridge }
    }
}

impl Lint for ZlintLint {
    fn id(&self) -> &'static str {
        self.info.check_id.as_str()
    }

    fn citation(&self) -> &'static str {
        self.info.citation.as_str()
    }

    fn severity(&self) -> Severity {
        self.info.severity
    }

    fn scope(&self) -> Scope {
        Scope::Certificate
    }

    fn applies_to(&self) -> SubjectKind {
        SubjectKind::Any
    }

    fn title(&self) -> &str {
        // The catalog `description` is closer to a human-readable title
        // than `check_id` (which is a slug). If the description is
        // empty (defensive — should not happen on a well-formed catalog),
        // fall back to the id.
        if self.info.description.is_empty() {
            &self.info.check_id
        } else {
            &self.info.description
        }
    }

    fn description(&self) -> Option<&str> {
        if self.info.description.is_empty() {
            None
        } else {
            Some(&self.info.description)
        }
    }

    fn spec_section_id(&self) -> Option<&str> {
        // zlint's `citation` is free-form text (e.g. "BRs: 7.1.2.7.7"
        // or "RFC 5280: 4.2.1.9"), not a workspace-shape `source-section`
        // slug. We expose the raw citation via Lint::citation and leave
        // spec_section_id unset rather than guessing at a slug shape.
        None
    }

    fn check_cert(&self, cert: &Certificate, _kind: SubjectKind, _now_unix: u64) -> LintResult {
        // Encode to DER on each call. The bridge's per-cert SHA-256
        // cache means the actual subprocess spawn happens at most once
        // per certificate per program lifetime, regardless of how many
        // ZlintLint impls fire `check_cert` for the same cert.
        let der = match cert.to_der() {
            Ok(der) => der,
            Err(e) => {
                return LintResult::error(format!(
                    "pkix-policy-zlint: re-encode cert to DER failed: {e}"
                ));
            }
        };

        let verdicts = match self.bridge.run_on_cert(&der) {
            Ok(v) => v,
            Err(e) => {
                return LintResult::error(format!(
                    "pkix-policy-zlint: zlint bridge run_on_cert failed: {e}"
                ));
            }
        };

        match verdicts.get(self.info.check_id.as_str()) {
            Some(Verdict::NotApplicable) | None => LintResult::NotApplicable,
            Some(Verdict::Pass) => LintResult::Pass,
            Some(Verdict::Notice) => LintResult::warn("zlint notice (see check description)"),
            Some(Verdict::Warn) => LintResult::warn("zlint warn (see check description)"),
            Some(Verdict::Error) => LintResult::error("zlint error (see check description)"),
            Some(Verdict::Fatal) => LintResult::fatal("zlint fatal (see check description)"),
            // `Verdict` is `#[non_exhaustive]`; future bridge versions may
            // add levels we do not yet recognise. Surface them as Error
            // so callers see the unfamiliar verdict rather than silently
            // dropping it.
            Some(_other) => LintResult::error("zlint emitted an unrecognised verdict level"),
        }
    }
}

/// Enumerate zlint's catalog via `bridge` and wrap every check as a
/// workspace [`Lint`].
///
/// Returns one `Box<dyn Lint>` per check zlint reports from
/// `zlint -list-lints-json`. At the time of writing, zlint ships ~400
/// checks; the exact count varies by zlint version.
///
/// # Leak at construction
///
/// Each [`ZlintLintInfo`] returned by the bridge is leaked via
/// `Box::leak` so the resulting `ZlintLint` can return `&'static str`
/// slices for its `id()` and `citation()` methods. See the crate-level
/// rustdoc for the rationale and the bounded-leak design.
///
/// # Errors
///
/// Surfaces any [`BridgeError`] from
/// [`ZlintBridge::enumerate_lints`] — typically a missing or
/// unparseable zlint binary, or an output-shape mismatch caused by an
/// incompatible zlint version. Per-cert errors land later, on
/// [`Lint::check_cert`] calls (they do not fail enumeration).
pub fn all_lints(bridge: Arc<ZlintBridge>) -> Result<Vec<Box<dyn Lint>>, BridgeError> {
    let infos = bridge.enumerate_lints()?;

    let lints: Vec<Box<dyn Lint>> = infos
        .into_iter()
        .map(|info| -> Box<dyn Lint> {
            // Leak the ZlintLintInfo so its String fields can be
            // returned as &'static str slices. Bounded leak: ~400
            // small structs, one-time at adapter construction. See
            // crate-level rustdoc for the rationale.
            let leaked: &'static ZlintLintInfo = Box::leak(Box::new(info));
            Box::new(ZlintLint::new(leaked, bridge.clone()))
        })
        .collect();

    Ok(lints)
}
