# OSCAL Output Format Coverage

`pkix-lint` ships emit/parse support for a subset of [NIST OSCAL] JSON
models — Catalog, Profile, Assessment Results, and the embedded
Finding / Observation / Risk sub-models. This document records which
OSCAL models the shipped code in `pkix-lint/src/oscal/*` touches,
which Rust types serialize to or parse from each, and which models
are out of scope.

[NIST OSCAL]: https://pages.nist.gov/OSCAL/

## Status: OSCAL is one supported output format

As of 2026-05-11, OSCAL has been **demoted from "source of truth" to
"one supported output format among possibly many."** The shipped code
in `pkix-lint/src/oscal/*` remains current and supported — but the
workspace no longer prescribes a single serialization format for lint
catalogs, profile composition, deviations, or assessment findings.
Choosing a replacement policy/config data format is an open design
question deliberately left undecided at the workspace level (per
AGENTS.md non-negotiable #5 and memory `pkix-oscal-demoted-2026-05-11`).

What this means for this document:

- The model coverage tables below describe what the shipped OSCAL
  emit/parse code in `pkix-lint/src/oscal/*` produces and consumes.
  They remain accurate as a reference for that code.
- Phrases such as "OSCAL Catalog is the container for ..." refer to
  OSCAL's own internal canonicalization for those models within OSCAL.
  They are not workspace prescriptions that OSCAL is the canonical
  workspace format.
- An earlier section titled "Constraints inherited from non-negotiables"
  has been removed. The workspace ships OSCAL emit/parse because the
  code is useful, not because OSCAL is prescribed. The remaining
  invariant properties of the shipped surface are listed under "What
  stays constant about the OSCAL emit/parse surface" below.

The full demotion history lives in epic `PKIX-ncab`.

## Pinned OSCAL version

OSCAL **v1.2.2**, schemas vendored under `specs/oscal-v1.2.2/`. JSON
schemas are the authoritative source; XML and YAML renderings are
synchronized to the same metaschema but are not exposed by the
workspace.

Files relevant to this document:

| Schema file | OSCAL model |
|---|---|
| `oscal_catalog_schema.json` | Catalog |
| `oscal_profile_schema.json` | Profile |
| `oscal_assessment-results_schema.json` | Assessment Results |
| `oscal_assessment-plan_schema.json` | Assessment Plan (passthrough only — see below) |
| `oscal_component_schema.json` | Component Definition (OUT OF SCOPE) |
| `oscal_ssp_schema.json` | System Security Plan (OUT OF SCOPE) |
| `oscal_poam_schema.json` | POA&M (deferred — see below) |
| `oscal_mapping_schema.json` | Control Mapping (OUT OF SCOPE) |

A version bump (e.g. OSCAL v1.3.x) is a coordinated workspace change:
update the vendored schemas, re-run the cross-validation in CI, bump
`pkix-lint`'s OSCAL version property, and CHANGELOG it.

## Models we DO emit/parse

### Catalog

OSCAL Catalog is OSCAL's container for collections of controls. In the
PKIX workspace, a "lint catalog" serialized as an OSCAL Catalog has
one Control per lint rule.

| Rust type | OSCAL element | Notes |
|---|---|---|
| `pkix_lint::Lint` (trait) | `catalog.controls[*]` | Each `Lint` impl supplies a Control's metadata (id, title, parts, parameters). The Rust trait is the executable side; the Control is the OSCAL-shape metadata view. Shipped in PKIX-9vnx.6 + .6.1. |
| `Lint::id()` | `control.id` | Stable identifier — part of pkix-lint's public API contract. |
| `Lint::title()` | `control.title` | Human-readable name. |
| `Lint::description()` | `control.parts[name=statement].prose` | Long-form description. |
| `Lint::spec_section_id()` | `control.props[name=spec-section-id]` (or stable `Control.id` shaping) | Standards-body section identifier (RFC, ITU-T X.509, CA/B Forum BR, NIST SP, etc.). Renamed from `rfc_section_id` in pkix-lint 0.6.0; deprecated alias remains for one minor version. |
| `Lint::spec_url()` | `control.links[rel=reference]` | Permanent URL to the section. Renamed from `rfc_url` in pkix-lint 0.6.0; deprecated alias remains for one minor version. |
| `Lint::severity()` | `control.props[name=severity]` | Custom OSCAL prop in workspace namespace. |
| `Lint::scope()`, `Lint::applies_to()` | `control.props[*]` | Workspace-defined props for cert-vs-path scope and subject-kind filter. |
| `Lint::parameters()` | `control.params[*]` | Tunable knobs as OSCAL Parameter shape. Shipped in PKIX-9vnx.6.4. |

Workspace-authored Catalogs (initial):

- `pkix-lint` ships an **RFC-baseline** Catalog (RFC 5280 conformance
  rules). Framework-not-policy stance (PKIX-amgn) keeps vendor / forum
  policy out of `pkix-lint`.
- `pkix-lint-cabf` ships the CA/B Forum reference Catalog. Marked
  "reference / not authoritative."

### Profile

OSCAL Profile is OSCAL's container for catalog composition.
"Bundle `cabf.br.tls`" can be serialized as an OSCAL Profile that
imports one or more Catalogs and selects the controls relevant to
TLS BR.

| Rust type | OSCAL element | Notes |
|---|---|---|
| `pkix_lint::LintProfile` (trait) | `profile` | A `LintProfile` impl serializes to an OSCAL Profile. Shipped in PKIX-9vnx.7. |
| `pkix_path::Profile::id()` | `profile.metadata.title` / custom prop | The existing Profile ID maps to Profile metadata. |
| Bundle membership | `profile.imports[*].include-controls` | Select-by-id and select-by-match semantics. |
| Bundle composition (A ∪ B − {X}) | `profile.imports[*]` chaining + `exclude-controls` | OSCAL's `import → modify → merge` machinery. |
| Parameter overrides | `profile.modify.set-parameters[*]` | Validity-cap dates, key-size minimums, etc. |

### Assessment Results

OSCAL Assessment Results is the document shape produced for a lint run.

| Rust type | OSCAL element | Notes |
|---|---|---|
| `pkix_lint::EvaluationReport` | `assessment-results` (root) | One AR document per lint run. Shipped in PKIX-9vnx.3. |
| `EvaluationReport.evaluated_at_unix` | `assessment-results.metadata.last-modified` | RFC 3339 timestamp on serialization. |
| `EvaluationReport.profile_id` / `profile_version` | `assessment-results.import-ap.href` (or custom prop) | Profile reference. AR requires an `import-ap`, so a minimal AP stub is emitted — see "Assessment Plan" below. |
| `EvaluationReport.rule_bundle_version` | `assessment-results.metadata.props[name=rule-bundle-version]` | Custom prop in PKIX workspace namespace. |
| `EvaluationReport.findings` | `assessment-results.results[*].findings[*]` | Non-deviated findings. |
| `EvaluationReport.deviated_findings` | `assessment-results.results[*].risks[status=deviation-approved]` | Per Risk model (below). |
| `EvaluationReport.observations` | `assessment-results.results[*].observations[*]` | Raw evidence — see Observation. |

### Finding

OSCAL Finding sits inside Assessment Results. Each Finding references one
or more Observations (raw evidence) and optionally one or more Risks
(when the finding involves accepted risk / deviation).

| Rust type | OSCAL element | Notes |
|---|---|---|
| `pkix_lint::Finding` | `result.findings[*]` | Shipped in PKIX-9vnx.4. |
| `Finding.lint_id` | `finding.target.target-id` (control-id reference) | Points at the OSCAL Control. |
| `Finding.result` (Pass / Warn / Error / Fatal) | `finding.target.status.state` + custom severity prop | OSCAL's built-in `status` is satisfied/other-than-satisfied/not-applicable; severity is workspace-defined. |
| `Finding.cert_index` (chain position) | `finding.related-observations[*]` → Observation with cert-evidence link | Indirection via Observation, not a direct field. |
| `Finding.cert_sha256` | Observation `links[]` or `props[name=cert-sha256]` | Evidence pointer — see Observation. |

### Observation

OSCAL Observation carries the raw evidence underlying a Finding. For
PKIX lints, an Observation is "we evaluated lint X against cert Y at
time T and got result Z."

| Rust type | OSCAL element | Notes |
|---|---|---|
| `pkix_lint::Observation` | `result.observations[*]` | Shipped in PKIX-9vnx.4. |
| Cert identity | `observation.subjects[*]` (subject-reference type=`component` + custom prop, or evidence link) | Tracks which cert was examined. |
| Cert SHA-256 | `observation.props[name=cert-sha256]` or `observation.links[rel=evidence]` | Cryptographic evidence pointer. |
| Evaluation timestamp | `observation.collected` | RFC 3339 timestamp. |
| Lint engine identity | `observation.origins[*].actors[*]` | "Performed by pkix-lint vX.Y.Z." |

### Risk (and Risk store — deviation persistence)

OSCAL Risk represents acknowledged / accepted / mitigated risks. A
PKIX deviation (waiver) is an OSCAL Risk with `status=deviation-approved`.

| Rust type | OSCAL element | Notes |
|---|---|---|
| `pkix_lint::Deviation` | `result.risks[*]` (status=deviation-approved) | Shipped in PKIX-9vnx.5. |
| `Deviation.id` | `risk.uuid` (or stable `risk.id` via prop) | Stable identifier. |
| `Deviation.target_lint` | `risk.related-observations[*]` → Observation referencing the lint Control | Indirection via Observation. |
| `Deviation.scope` (DeviationScope kind+props bag) | `risk.props[*]` + `risk.subjects[*]` | Scope axes ride OSCAL Subject props on Risk. `DeviationScope` was refactored from a closed enum to an open-ended kind+props bag in pkix-lint 0.4.0 (PKIX-9vnx.11). |
| `Deviation.effective_start` / `effective_end` | `risk.props[name=effective-start]` / `effective-end` | Custom workspace props. |
| `Deviation.action` (Suppress / DowngradeSeverityTo) | `risk.remediations[*]` or `risk.props[name=action]` | Shipped in PKIX-9vnx.5. |
| `Deviation.justification` | `risk.statement` | Free-text rationale. |
| `Deviation.authorized_by` | `risk.props[name=authorized-by]` | Human attribution (git commit history is the audit trail, not in-band signatures). |
| `Deviation.evidence_uri` | `risk.links[rel=reference]` | Pointer to backing memo / waiver document. |
| `pkix_lint::DeviationStore` | Collection of Risks | Risk-list document; round-trip parser shipped in PKIX-9vnx.10. |
| `pkix_lint::DeviatedFinding` | `finding.related-risks[*]` | Finding ↔ Risk link inside the same AR document. |

## Models we minimally touch (passthrough)

### Assessment Plan

OSCAL Assessment Results requires an `import-ap` field referencing an
Assessment Plan. The PKIX workspace does not author full APs — APs
describe planned assessment activities, which is an organizational /
human concern, not a lint-engine concern.

Approach (decided in PKIX-9vnx.3):

- **Default:** emit a minimal stub AP referenced inline by URI fragment
  ("synthesized by pkix-lint vX.Y.Z, no formal AP authored").
- **Caller-supplied:** allow the caller to pass an `import-ap` href
  pointing at an externally-authored AP. The lint engine does not
  generate AP content beyond the stub.

We do not implement AP authoring tools, AP validation beyond
"href is a syntactically valid URI," or AP-driven scheduling.

## Models we DO NOT emit/parse (out of scope)

### Component Definition (out of scope)

OSCAL Component Definition describes "this component implements these
controls." `pkix-lint` is a validator, not a system inventory tool. It
does not describe components or their control implementations. Out of
scope unless / until a downstream consumer asks for it with a concrete
use case.

### System Security Plan (out of scope)

OSCAL SSP describes "this system is configured this way and inherits
these controls from these components." Far beyond what a path-validation
lint engine produces. Out of scope.

### Control Mapping (out of scope)

OSCAL Mapping (`oscal_mapping_schema.json`) maps controls between
catalogs (e.g., NIST 800-53 ↔ ISO 27001). The PKIX workspace authors
PKIX-domain Catalogs and does not currently need to map them against
other frameworks. Out of scope unless a downstream consumer needs it.

### Rego rule mappings (out of scope)

OSCAL has a Rego profile for executable policy. The PKIX workspace's
executable side is Rust traits (`Lint::check_cert` / `Lint::check_path`),
not Rego. We do not emit Rego.

## Models we may revisit (deferred)

### POA&M (Plan of Action and Milestones)

OSCAL POA&M tracks remediation plans for findings. Closely related to
Risk and could plausibly be how the workspace expresses
"deviation expires on date X, after which the underlying finding
re-activates." Deferred — for now we treat deviation expiry as a
property on the Risk itself. Revisit if a downstream consumer needs
explicit POA&M emission.

## What stays constant about the OSCAL emit/parse surface

These are properties of the shipped code, not workspace prescriptions:

1. **No 1:1 Rust mirror of OSCAL types.** No `pkix-oscal` crate, no
   `roscal_lib` dependency, no schema-generated binding. Internal Rust
   types stay lean and tailored to lint work; thin serializer/parser
   modules in `pkix-lint/src/oscal/*` bridge between them and OSCAL JSON.
   The mapping tables above describe what each Rust type *serializes to
   or parses from* in OSCAL JSON, not what its Rust shape mirrors.
2. **`pkix-path::ValidationPolicy` is not in scope of the OSCAL surface.**
   It is the validator's runtime config, not a compliance assertion.
   The OSCAL emit/parse surface lives in `pkix-lint`, not `pkix-path`.
3. **Framework, not policy.** `pkix-lint` ships only the framework plus
   RFC-baseline lints. CA/B Forum content lives in `pkix-lint-cabf`
   (per PKIX-amgn). The OSCAL emit/parse code in `pkix-lint` is
   consumed by both crates.

## Cross-references

- **Demotion stance:** AGENTS.md non-negotiable #5; memory
  `pkix-oscal-demoted-2026-05-11`; demotion cleanup epic `PKIX-ncab`.
- **Historical alignment epic:** `PKIX-9vnx` (renamed to "OSCAL
  emit/parse (historical alignment epic — superseded by PKIX-ncab)").
  Closed audit `PKIX-9vnx.1` produced an earlier version of this
  document.
- **Shipped emit/parse work:** `PKIX-9vnx.3` (Assessment Results),
  `.4` (Finding / Observation), `.5` (Risk / Deviation), `.6` and
  `.6.1` (Lint-as-Control mapping), `.7` (Profile composition),
  `.10` (Risk parser for DeviationStore round-trip), `.11`
  (DeviationScope kind+props refactor). All closed.
- **Earlier stance bead:** `PKIX-ztmr` (Architecture 2 interpreter
  decision; superseded by the 2026-05-11 demotion but retained as
  decision-history).
