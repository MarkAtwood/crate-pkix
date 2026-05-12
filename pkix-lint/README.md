# pkix-lint

Advisory lint engine for X.509 certificate chains — CA/B Forum and RFC rules
with structured soft-fail results, deviations, and exportable evidence packs.

## What this crate provides

`pkix-path::validate_path` returns `Result<ValidatedPath, Error>` — hard pass
or fail. That binary model cannot express "this certificate is RFC 5280 valid
but violates CA/B Forum TLS BR §7.1.4.2" without aborting validation entirely.

`pkix-lint` adds an advisory layer on top:

- **`Lint` trait** — the unit of evaluation. Each lint has a stable ID, a
  normative citation, a severity (`Warn`, `Error`, `Fatal`), a scope
  (`Certificate` or `Path`), and a subject-kind filter (`Leaf`,
  `IntermediateCa`, `AnchorIssued`, or `Any`).
- **`LintResult`** — `Pass | NotApplicable | Warn | Error | Fatal`. `Warn`,
  `Error`, and `Fatal` carry a `Cow<'static, str>` detail message —
  zero-allocation for static literals (via `Cow::Borrowed`) and
  runtime-formatted strings for dynamic values (via `Cow::Owned`). `Fatal`
  stops further lint evaluation for that item; it does not propagate as a
  hard failure.
- **`Finding`** — a lint ID paired with a result and the chain index of the
  offending certificate.
- **`LintRunner`** — evaluates a set of `dyn Lint` objects against a
  certificate or validated path, returning `Vec<Finding>`.
- **`LintProfile` trait** — extends `pkix_path::Profile` with a `lints()`
  method so a profile struct bundles its own lint set.
- **`deviation` module** — a waiver/exception mechanism that records approved
  deviations from lint rules for audit purposes.
- **`EvaluationReport`** — an exportable evidence pack suitable for OSCAL
  Assessment Results and compliance audits.

## Advisory-only contract

`pkix-lint` findings **never** cause a certificate to be rejected. All runner
methods return `Vec<Finding>` — never `Result::Err`. Whether to act on a
finding is the caller's decision, configured per finding ID at the integration
layer. This is intentional:

- Spec ambiguity (CA/B Forum CPs, FPKI CPs) means some findings require human
  judgment before enforcement.
- `pkix-lint` does not know whether you are in audit, monitoring, or hard-fail
  enforcement context. The caller does.

## Built-in lints (`pkix-lint::rfc5280`)

`pkix-lint` ships the framework and standards-body (RFC) conformance lints.
CA/B Forum lint bundles live in the sibling [`pkix-lint-cabf`] crate marked
"reference / not authoritative"; project policy (see workspace `AGENTS.md`)
is that vendor and industry-forum policy interpretations stay out of the
main crate.

| ID | Rule | Scope |
|----|------|-------|
| `rfc5280.cert.serial_number.max_octets` | Certificate `serialNumber` length cap (RFC 5280 §4.1.2.2) | Any |

CA/B Forum TLS BR lints (`cabf.br.tls.*`) — SC-081 phased validity caps,
SHA-1 prohibition, RSA min-key-size, SAN/EKU presence, `BasicConstraints`
cA-flag — are in [`pkix-lint-cabf::cabf_tls_br`].

[`pkix-lint-cabf`]: https://docs.rs/pkix-lint-cabf
[`pkix-lint-cabf::cabf_tls_br`]: https://docs.rs/pkix-lint-cabf/latest/pkix_lint_cabf/cabf_tls_br/

## Usage

### Run CA/B Forum TLS BR lints against a chain (via `pkix-lint-cabf`)

```rust,no_run
use pkix_lint::{LintProfile, SubjectKind};
use pkix_lint_cabf::cabf_tls_br::CabfTlsBrProfile;

let profile = CabfTlsBrProfile;
let runner = profile.lint_runner();

let kinds = vec![SubjectKind::Leaf, SubjectKind::AnchorIssued];
let findings = runner.run_chain(&chain, &kinds, now_unix);

for f in findings.iter().filter(|f| f.is_finding()) {
    eprintln!("[{}] {}: {:?}", f.cert_index, f.lint_id, f.result);
}
```

### Implement a custom lint

```rust,no_run
use pkix_lint::{Lint, LintResult, LintRunner, Scope, Severity, SubjectKind};
use x509_cert::Certificate;

struct NoEmptySubjectLint;

impl Lint for NoEmptySubjectLint {
    fn id(&self) -> &'static str { "corp.policy.subject.non_empty" }
    fn citation(&self) -> &'static str { "Corp PKI Policy §2.3.1" }
    fn severity(&self) -> Severity { Severity::Error }
    fn scope(&self) -> Scope { Scope::Certificate }
    fn applies_to(&self) -> SubjectKind { SubjectKind::Leaf }

    fn check_cert(&self, cert: &Certificate, _kind: SubjectKind, _now_unix: u64) -> LintResult {
        if cert.tbs_certificate.subject.to_string().is_empty() {
            LintResult::error("Subject DN must not be empty")
        } else {
            LintResult::Pass
        }
    }
}

let runner = LintRunner::new(vec![Box::new(NoEmptySubjectLint)]);
```

### Record a deviation (waiver)

```rust,no_run
use pkix_lint::deviation::{Deviation, DeviationScope, DeviationStore};

let mut store = DeviationStore::new();
store.add(Deviation {
    id: "waiver-2026-003".to_string(),
    target_lint: "cabf.br.tls.validity.max".to_string(),
    scope: DeviationScope::issuer_dn_contains("agency x issuing ca"),
    reason: "Agency X issued certs before SC-081 effective date".to_string(),
    justification: "PKIPPA waiver memo 2026-03-01".to_string(),
    authorized_by: "pki-policy@agency.gov".to_string(),
    evidence_uri: Some("https://pkipolicy.agency.gov/waivers/2026-003".to_string()),
})?;
```

### Export an evidence pack

```rust,no_run
use pkix_lint::report::EvaluationReport;

let mut report = EvaluationReport::new("cabf.br.tls", "SC-081", "v0.2.0", chain.len() as u32, now_unix);
report.record_findings(&findings);
let json = serde_json::to_string_pretty(&report)?; // requires `serde` feature
```

## Finding ID stability

Finding IDs returned by `Lint::id()` are part of the public API and must not
change between crate versions without a semver-major bump. Format convention:
`<regime>.<section>.<noun>`, e.g. `"cabf.br.tls.validity.max"`.

## Features

| Feature | Enables |
|---------|---------|
| `serde` | `Serialize`/`Deserialize` on `Finding`, `EvaluationReport`, `Deviation`, and related types |

## Standards

- CA/B Forum Baseline Requirements for TLS Server Certificates (SC-081)
- CA/B Forum S/MIME Baseline Requirements
- [RFC 5280] — Internet X.509 PKI Certificate and CRL Profile

## License

Apache-2.0 OR MIT
