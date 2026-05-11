# OSCAL Model Coverage Audit

Audit of which [NIST OSCAL] models the PKIX workspace touches, which Rust
types map to each, and which models are out of scope.

[NIST OSCAL]: https://pages.nist.gov/OSCAL/

## Scope

- **Stance:** PKIX-ztmr — OSCAL is the source of truth for lint catalogs,
  profile composition, deviations, and assessment findings (at the
  serialization + policy-vocabulary level).
- **Architecture:** Interpreter, not binding. `pkix-lint` consumes OSCAL
  Catalog/Profile JSON as configuration and emits OSCAL Assessment
  Results JSON as canonical output. Internal Rust types stay lean and
  tailored to lint work; thin serializer/parser modules bridge between
  them and OSCAL JSON. **No 1:1 Rust mirror of OSCAL types** — no
  `pkix-oscal` crate, no `roscal_lib` dependency, no schema-generated
  binding. Decided 2026-05-11; see PKIX-ztmr notes.
- **Alignment epic:** PKIX-9vnx.
- **Audit issue:** PKIX-9vnx.1.

The mapping tables below describe **what each Rust type serializes to or
parses from in OSCAL JSON**, not what its Rust shape mimics. Round-trip
correctness is at the JSON layer.

## Pinned OSCAL version

OSCAL **v1.2.2**, schemas vendored under `specs/oscal-v1.2.2/`. JSON
schemas are the authoritative source; XML and YAML renderings are
synchronized to the same metaschema but are not part of the workspace's
public surface.

Files relevant to this audit:

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

## Models we DO use (in-scope)

### Catalog

OSCAL Catalog is the canonical container for lint rule definitions.
A "lint catalog" in the PKIX workspace is an OSCAL Catalog whose
`controls` are individual lint rules.

| Rust type | OSCAL element | Notes |
|---|---|---|
| `pkix_lint::Lint` (trait) | `catalog.controls[*]` | Each `Lint` impl supplies a Control's metadata (id, title, parts, parameters). The Rust trait is the *executable* side; the Control is the canonical *metadata*. Implemented in PKIX-9vnx.6. |
| `Lint::id()` | `control.id` | Stable identifier — already part of pkix-lint's public API contract. |
| `Lint::title()` (planned) | `control.title` | Human-readable name. |
| `Lint::description()` (planned) | `control.parts[name=statement].prose` | Normative description. |
| `Lint::severity()` | `control.props[name=severity]` | Custom OSCAL prop (namespace TBD in PKIX-9vnx.6). |
| `Lint::scope()`, `Lint::subject_kind()` | `control.props[*]` | Workspace-defined props for cert-vs-path scope and subject-kind filter. |

Workspace-authored Catalogs (initial):

- `pkix-lint` ships an **RFC-baseline** Catalog (RFC 5280 conformance
  rules). Framework-not-policy stance (PKIX-amgn) keeps vendor / forum
  policy out of `pkix-lint`.
- `pkix-lint-cabf` (planned, PKIX-amgn.3) ships the CA/B Forum reference
  Catalog. Marked "reference / not authoritative."

### Profile

OSCAL Profile is the canonical container for *lint bundle composition*.
"Bundle `cabf.br.tls`" becomes "Profile that imports one or more
Catalogs and selects the controls relevant to TLS BR."

| Rust type | OSCAL element | Notes |
|---|---|---|
| `pkix_lint::LintProfile` (trait) | `profile` | Each `LintProfile` impl produces an OSCAL Profile when serialized. Implemented in PKIX-9vnx.7. |
| `pkix_path::Profile::id()` | `profile.metadata.title` / custom prop | Existing `Profile` ID maps to Profile metadata. |
| Bundle membership | `profile.imports[*].include-controls` | Select-by-id and select-by-match semantics. |
| Bundle composition (A ∪ B − {X}) | `profile.imports[*]` chaining + `exclude-controls` | OSCAL's `import → modify → merge` machinery, not Rust composition functions (per PKIX-ztmr non-negotiable). |
| Parameter overrides | `profile.modify.set-parameters[*]` | Validity-cap dates, key-size minimums, etc. |

### Assessment Results

OSCAL Assessment Results is the output document of a lint run.

| Rust type | OSCAL element | Notes |
|---|---|---|
| `pkix_lint::EvaluationReport` | `assessment-results` (root) | One AR document per lint run. Realign in PKIX-9vnx.3. |
| `EvaluationReport.evaluated_at_unix` | `assessment-results.metadata.last-modified` | RFC 3339 timestamp on serialization. |
| `EvaluationReport.profile_id` / `profile_version` | `assessment-results.import-ap.href` (or custom prop) | Profile reference. The exact placement (`import-ap` vs. `metadata.props`) is decided in .3; AR requires an `import-ap` so we will emit a minimal AP stub — see "Assessment Plan" below. |
| `EvaluationReport.rule_bundle_version` | `assessment-results.metadata.props[name=rule-bundle-version]` | Custom prop in PKIX workspace namespace. |
| `EvaluationReport.findings` | `assessment-results.results[*].findings[*]` | Non-deviated findings. |
| `EvaluationReport.deviated_findings` | `assessment-results.results[*].risks[status=deviation-approved]` | Per Risk model (below). |
| `EvaluationReport.observations` (planned) | `assessment-results.results[*].observations[*]` | Raw evidence — see Observation. |

### Finding

OSCAL Finding sits inside Assessment Results. Each Finding references one
or more Observations (raw evidence) and optionally one or more Risks
(when the finding involves accepted risk / deviation).

| Rust type | OSCAL element | Notes |
|---|---|---|
| `pkix_lint::Finding` | `result.findings[*]` | Realign in PKIX-9vnx.4. |
| `Finding.lint_id` | `finding.target.target-id` (control-id reference) | Points at the OSCAL Control. |
| `Finding.result` (Pass / Warn / Error / Fatal) | `finding.target.status.state` + custom severity prop | OSCAL's built-in `status` is satisfied/other-than-satisfied/not-applicable; severity is workspace-defined. |
| `Finding.cert_index` (chain position) | `finding.related-observations[*]` → Observation with cert-evidence link | Indirection via Observation, not a direct field. |
| `Finding.cert_sha256` (planned, PKIX-a86q) | Observation `links[]` or `props[name=cert-sha256]` | Evidence pointer — see Observation. |

### Observation

OSCAL Observation carries the raw evidence underlying a Finding. For
PKIX lints, an Observation is "we evaluated lint X against cert Y at
time T and got result Z."

| Rust type | OSCAL element | Notes |
|---|---|---|
| (planned) `pkix_lint::Observation` | `result.observations[*]` | New type or merged into Finding; decided in PKIX-9vnx.4. |
| Cert identity | `observation.subjects[*]` (subject-reference type=`component` + custom prop, or evidence link) | Tracks which cert was examined. |
| Cert SHA-256 (PKIX-a86q) | `observation.props[name=cert-sha256]` or `observation.links[rel=evidence]` | Cryptographic evidence pointer. |
| Evaluation timestamp | `observation.collected` | RFC 3339 timestamp. |
| Lint engine identity | `observation.origins[*].actors[*]` | "Performed by pkix-lint vX.Y.Z." |

### Risk (and Risk store — deviation persistence)

OSCAL Risk represents acknowledged / accepted / mitigated risks. A
PKIX deviation (waiver) is an OSCAL Risk with `status=deviation-approved`.

| Rust type | OSCAL element | Notes |
|---|---|---|
| `pkix_lint::Deviation` | `result.risks[*]` (status=deviation-approved) | Realign in PKIX-9vnx.5. |
| `Deviation.id` | `risk.uuid` (or stable `risk.id` via prop) | Stable identifier. |
| `Deviation.target_lint` | `risk.related-observations[*]` → Observation referencing the lint Control | Indirection via Observation. |
| `Deviation.scope` (DeviationScope enum) | `risk.props[*]` + `risk.subjects[*]` | OSCAL Subject props on Risk — per PKIX-ztmr non-negotiable, **scope axes are OSCAL Subject props, not new Rust enum variants**. The existing `DeviationScope` enum variants reshape under .5; see PKIX-8mzp WONTFIX. |
| `Deviation.effective_start` / `effective_end` | `risk.props[name=effective-start]` / `effective-end` | Custom workspace props. |
| `Deviation.action` (Suppress / DowngradeSeverityTo) | `risk.remediations[*]` or `risk.props[name=action]` | Decided in .5. |
| `Deviation.justification` | `risk.statement` | Free-text rationale. |
| `Deviation.authorized_by` | `risk.props[name=authorized-by]` | Human attribution (per `deviation.rs` design — git commit history is the audit trail, not in-band signatures). |
| `Deviation.evidence_uri` | `risk.links[rel=reference]` | Pointer to backing memo / waiver document. |
| `pkix_lint::DeviationStore` | Collection of Risks | Persistence layout TBD. Currently planned as Assessment Plan body fragment OR a sidecar Risk-list document. Decided in PKIX-9vnx.5 and PKIX-dbhe. |
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

## Models we DO NOT use (out of scope)

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
executable side is Rust traits (`Lint::evaluate`), not Rego. We do
not emit Rego.

## Models we may revisit (deferred)

### POA&M (Plan of Action and Milestones)

OSCAL POA&M tracks remediation plans for findings. Closely related to
Risk and could plausibly be how the workspace expresses
"deviation expires on date X, after which the underlying finding
re-activates." Deferred — for v1 we treat deviation expiry as a
property on the Risk itself. Revisit if a downstream consumer needs
explicit POA&M emission.

## Constraints inherited from non-negotiables

Per the project AGENTS.md and PKIX-ztmr stance:

1. **No bespoke serialization formats** for Catalog / Profile / Assessment
   Results / Finding / Observation / Risk. The serialization is OSCAL JSON.
2. **No new deviation-scope Rust enum variants** as the primary scope axis.
   Scope is OSCAL Subject props on Risk. Existing `DeviationScope` is a
   convenience wrapper that reshapes under PKIX-9vnx.5.
3. **No bespoke Profile composition functions.** Composition uses OSCAL
   Profile semantics (import / select / exclude / modify chaining).
4. **`pkix-path::ValidationPolicy` is out of scope.** It is the
   validator's runtime config, not a compliance assertion. The OSCAL
   alignment does not touch `pkix-path`.
5. **Framework, not policy.** The main `pkix-lint` crate ships only the
   framework plus RFC-baseline Catalogs. CA/B Forum content lives in
   `pkix-lint-cabf` (per PKIX-amgn). The OSCAL alignment applies to
   both crates uniformly.

## Cross-references

- **Stance:** PKIX-ztmr (this document records the model touch surface
  that stance implies).
- **Epic:** PKIX-9vnx (this is the .1 deliverable).
- **Downstream:**
  - PKIX-9vnx.2 — binding choice (existing OSCAL Rust crate vs.
    hand-rolled subset vs. schema-generated). Scope of binding follows
    from this audit.
  - PKIX-9vnx.3..7 — per-model realignment.
  - PKIX-amgn.3 — `pkix-lint-cabf` authors content AS an OSCAL Catalog
    from day one.
  - PKIX-amgn.5 — `pkix-lint` refactor ships OSCAL-shaped types in its
    refactor, not bespoke-then-realign.
- **Reshapes under this alignment:** PKIX-8mzp (DeviationScope variants),
  PKIX-dbhe (DeviationStore persistence), PKIX-nlxl (`pkix-lint-oscal`
  adapter — now subsumed because OSCAL *is* the source of truth, not an
  external adapter target).
