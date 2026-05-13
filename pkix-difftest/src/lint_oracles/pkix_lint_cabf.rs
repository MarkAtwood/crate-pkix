//! In-process oracle backed by `pkix-lint-cabf`'s reference CA/B Forum TLS
//! BR lint bundle.
//!
//! See the parent module ([`super`]) for the trait surface and the broader
//! PKIX-hbzo.1 context.
//!
//! # Result mapping
//!
//! pkix-lint's [`LintResult`] enum maps into [`NormalizedFinding`] as
//! follows:
//!
//! | `LintResult`          | `NormalizedFinding` | Notes |
//! |-----------------------|---------------------|-------|
//! | `Pass`                | *(dropped)*         | Not a finding. |
//! | `NotApplicable`       | *(dropped)*         | Not a finding. |
//! | `Warn(_)`             | `Severity::Warn`    | |
//! | `Error(_)`            | `Severity::Error`   | |
//! | `Fatal(_)`            | `Severity::Fatal`   | |
//!
//! `LintResult` is `#[non_exhaustive]` (notably it has no `Notice` variant
//! today). Future Notice/Info/etc. additions land in the `_` arm of
//! `result_to_severity` and drop silently until this adapter is updated;
//! the bead-tracking discipline for that update is the same as for zlint
//! Verdict additions on the sibling adapter.
//!
//! # Subject kind handling
//!
//! Every cert is linted as `SubjectKind::Leaf`. The PKIX-hbzo.1 corpus
//! (the dependent .1.3 child) is end-entity-shaped CA/B Forum TLS BR test
//! vectors — none of the BR lints in scope today need a CA-kind
//! discriminator. If the corpus grows to include intermediates, this
//! adapter will need a per-cert kind input and the caller (reconciliation
//! layer) will need to thread chain position through.

use der::Decode as _;
use pkix_lint::{LintProfile as _, LintResult, LintRunner, SubjectKind};
use pkix_profiles_cabf::WebPkiProfile;
use x509_cert::Certificate;

use super::{LintOracle, LintOracleResult, NormalizedFinding, OracleSource};

/// In-process lint oracle backed by `pkix_profiles_cabf::WebPkiProfile`'s
/// `pkix_lint::LintProfile` impl (which bundles the six CA/B Forum TLS BR
/// lint types defined in `pkix_lint_cabf::cabf_tls_br`).
///
/// Constructs one `LintRunner` per oracle instance (six lints today) and
/// reuses it across calls. The runner is `Sync` thanks to pkix-lint's
/// `Box<dyn Lint>` being `Send + Sync` by the trait's bounds.
///
/// # Evaluation mode
///
/// Lints are run in **audit mode** via [`LintRunner::run_cert_at_issuance`]
/// — the `now_unix` time pinned to each cert's `notBefore`. This anchors
/// the SC-081 phased validity cap (`cabf.br.tls.validity.max`) to the
/// issuance moment per CA/B Forum TLS BR §6.3.2: the cap that applied at
/// issuance governs the cert for its lifetime, not the cap that applies
/// at relying-party time. The differential layer compares oracles on
/// historical artefacts (zlint testdata, possibly old CT corpus), so
/// audit mode is the right semantics regardless of wall clock.
pub struct PkixLintCabfOracle {
    runner: LintRunner,
}

impl PkixLintCabfOracle {
    /// Construct an oracle with a freshly-allocated lint runner.
    #[must_use]
    pub fn new() -> Self {
        Self {
            runner: WebPkiProfile.lint_runner(),
        }
    }
}

impl Default for PkixLintCabfOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl LintOracle for PkixLintCabfOracle {
    fn source(&self) -> OracleSource {
        OracleSource::PkixLintCabf
    }

    fn lint_cert(&self, cert_der: &[u8]) -> LintOracleResult {
        let cert = match Certificate::from_der(cert_der) {
            Ok(c) => c,
            Err(e) => {
                return LintOracleResult::oracle_error(format!(
                    "pkix-lint-cabf: DER parse failed: {e}"
                ));
            }
        };

        let findings = self
            .runner
            .run_cert_at_issuance(&cert, SubjectKind::Leaf, 0);

        let mut normalized: Vec<NormalizedFinding> = findings
            .into_iter()
            .filter_map(|f| {
                let severity = result_to_severity(&f.result)?;
                Some(NormalizedFinding {
                    id: f.lint_id.into_owned(),
                    severity,
                    source: OracleSource::PkixLintCabf,
                })
            })
            .collect();
        normalized.sort_by(|a, b| a.id.cmp(&b.id));

        LintOracleResult {
            findings: normalized,
            oracle_error: None,
        }
    }
}

/// Translate one [`LintResult`] into the [`pkix_lint::Severity`] it
/// normalises to.
///
/// Returns `None` for `Pass` and `NotApplicable` (explicit) and for any
/// unknown future variant ([`LintResult`] is `#[non_exhaustive]`). See the
/// module docs for the full mapping table. The collapse of the
/// "intentionally not-a-finding" arm with the "future variant" arm is
/// the same shape as `verdict_to_severity` in the zlint adapter: both
/// produce no finding, and the catch-all arm carries the documentation
/// for future variants.
fn result_to_severity(result: &LintResult) -> Option<pkix_lint::Severity> {
    Some(match result {
        LintResult::Warn(_) => pkix_lint::Severity::Warn,
        LintResult::Error(_) => pkix_lint::Severity::Error,
        LintResult::Fatal(_) => pkix_lint::Severity::Fatal,
        // `LintResult::Pass`, `LintResult::NotApplicable`, and any future
        // non_exhaustive variants. See function docs.
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    /// Parse the leaf certificate from the in-tree `good-chain.pem` fixture.
    ///
    /// `good-chain.pem` is the PKITS "Good CA Test1" three-cert chain
    /// (leaf / intermediate / trust anchor). We only need the leaf for the
    /// TLS BR lints (every BR lint in the bundle either applies to leaves
    /// or applies to "Any" with leaf-kind handling).
    ///
    /// Routes through the public `crate::Chain` loader so we get the same
    /// leaf-first canonicalisation the path-validation oracle layer uses.
    fn good_leaf_der() -> Vec<u8> {
        let pem_bytes = include_bytes!("../../tests/fixtures/good-chain.pem");
        let chain = crate::Chain::from_pem_bytes(pem_bytes, "good-chain.pem".to_string())
            .expect("good-chain.pem parses cleanly");
        chain.certs_der[0].clone()
    }

    #[test]
    fn result_to_severity_actionable() {
        assert_eq!(
            result_to_severity(&LintResult::Warn(Cow::Borrowed("x"))),
            Some(pkix_lint::Severity::Warn)
        );
        assert_eq!(
            result_to_severity(&LintResult::Error(Cow::Borrowed("x"))),
            Some(pkix_lint::Severity::Error)
        );
        assert_eq!(
            result_to_severity(&LintResult::Fatal(Cow::Borrowed("x"))),
            Some(pkix_lint::Severity::Fatal)
        );
    }

    #[test]
    fn result_to_severity_drops_pass_and_na() {
        assert_eq!(result_to_severity(&LintResult::Pass), None);
        assert_eq!(result_to_severity(&LintResult::NotApplicable), None);
    }

    #[test]
    fn oracle_source_is_pkix_lint_cabf() {
        let oracle = PkixLintCabfOracle::new();
        assert_eq!(oracle.source(), OracleSource::PkixLintCabf);
    }

    #[test]
    fn lint_cert_on_malformed_der_returns_oracle_error() {
        let oracle = PkixLintCabfOracle::new();
        // 8 bytes of garbage that will not decode as a Certificate.
        let result = oracle.lint_cert(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        assert!(result.findings.is_empty(), "no findings on parse failure");
        assert!(
            result
                .oracle_error
                .as_deref()
                .is_some_and(|e| e.contains("DER parse")),
            "expected DER parse error, got {:?}",
            result.oracle_error,
        );
    }

    #[test]
    fn lint_cert_on_good_leaf_yields_expected_findings() {
        // The PKITS Good CA Test1 leaf is an RFC 5280-shaped 2010-vintage
        // cert. Against the CA/B Forum TLS BR lint bundle it should fire
        // multiple BR violations: it predates SC-081's validity caps but
        // also predates SAN-required and EKU-server-auth enforcement, so
        // those lints fire because the cert lacks those fields. Rather
        // than pinning a specific lint set (which would couple this test
        // to pkix-lint-cabf's exact bundle), assert structural properties:
        //
        // 1. Adapter returned no oracle_error (parse succeeded).
        // 2. Findings are sorted by id.
        // 3. Each finding has source = PkixLintCabf.
        // 4. Each finding's severity is one of Warn/Error/Fatal (the
        //    actionable levels we keep).
        //
        // If the bundle is later trimmed to zero findings on this cert
        // (e.g., a more lenient default), tighten this assertion at that
        // time. For now we just check at least one BR lint fires, which
        // confirms the pipeline reached the runner.
        let der = good_leaf_der();
        let oracle = PkixLintCabfOracle::new();
        let result = oracle.lint_cert(&der);
        assert!(
            result.oracle_error.is_none(),
            "good leaf should parse cleanly, got {:?}",
            result.oracle_error
        );
        assert!(
            !result.findings.is_empty(),
            "PKITS Good CA Test1 leaf should trip at least one CA/B Forum TLS BR lint"
        );

        // Sorted by id.
        for window in result.findings.windows(2) {
            assert!(
                window[0].id <= window[1].id,
                "findings must be sorted by id, got {} then {}",
                window[0].id,
                window[1].id,
            );
        }

        // All from this adapter, all actionable severity.
        for finding in &result.findings {
            assert_eq!(finding.source, OracleSource::PkixLintCabf);
            assert!(
                matches!(
                    finding.severity,
                    pkix_lint::Severity::Warn
                        | pkix_lint::Severity::Error
                        | pkix_lint::Severity::Fatal
                ),
                "unexpected severity: {:?}",
                finding.severity
            );
            // Lint IDs from pkix-lint-cabf start with the `cabf.br.tls.` prefix.
            assert!(
                finding.id.starts_with("cabf.br.tls."),
                "lint id missing cabf.br.tls. prefix: {}",
                finding.id
            );
        }
    }
}
