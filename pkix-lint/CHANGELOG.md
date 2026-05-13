# Changelog

All notable changes to `pkix-lint` are documented here. The crate
follows [Keep a Changelog](https://keepachangelog.com/) headings and
[Semantic Versioning](https://semver.org/).

## [Unreleased]

_Nothing yet._

## [1.0.0] — TBD

First stable release.

### Added

- `Send + Sync` compile-time assertion on `Finding` (PKIX-2l0v.2).
- Top-level `# Limitations` rustdoc section documenting the crate as
  a framework, not a comprehensive rule set, and clarifying that OSCAL
  is one supported output format rather than canonical (PKIX-wlsr.6).

### Changed

- `WebPkiProfile::LintProfile` impl moved from `pkix-lint-cabf`'s
  `CabfTlsBrProfile` to `pkix-profiles-cabf::WebPkiProfile` to fix the
  cycle in the workspace's one-way `pkix-profiles* → pkix-lint*` dep
  flow (PKIX-9vnx.9.2.2). `pkix-lint` itself was not refactored;
  consumer-side impact is documented in `pkix-lint-cabf`'s CHANGELOG.

## [0.9.0] — 2026-05-13

### Added

- Three new RFC-conformance `Lint` impls closing out the 8-of-8
  acceptance criterion for PKIX-9vnx.9.2.1's candidate list
  (PKIX-9vnx.9.2.1.1):
  - `rfc5280::Rfc5280SanRequiredWhenSubjectEmptyLint` — RFC 5280
    §4.2.1.6: certificates whose Subject is the zero-length
    `RDNSequence` MUST include a `subjectAltName` extension marked
    critical. No-op (`Pass`) for certs with a non-empty Subject.
  - `rfc5280::Rfc5280SignatureAlgorithmMatchLint` — RFC 5280 §4.1.1.2:
    the outer `Certificate.signatureAlgorithm` MUST equal the inner
    `tbsCertificate.signature`. Compares both fields structurally via
    x509-cert's `AlgorithmIdentifier` `PartialEq` impl, catching both
    OID mismatches and parameter-encoding inconsistencies (e.g. NULL
    parameters on one side, absent parameters on the other for
    RSA-PKCS1 per RFC 4055 §2.1).
  - `rfc8398::Rfc8398SmimeMailboxEquivalenceLint` — RFC 8398 §3: when
    both `rfc822Name` and `id-on-SmtpUTF8Mailbox` `OtherName` SAN
    entries are present, every entry of one kind must match some
    entry of the other under byte-equal local-parts and IDN A-label
    ↔ U-label equivalent domains. Domain conversion uses the
    workspace `idna` crate.
- `idna` (workspace pin, `default-features = false`,
  `features = ["alloc", "compiled_data"]`) added as a direct
  dependency (already transitive via `pkix-identity`).

## [0.8.0] — 2026-05-12

### Added

- `Severity::Notice` variant slotted between `Info` and `Warn`
  (PKIX-jy95.2.1). The resulting ordering
  `Info < Notice < Warn < Error < Fatal` aligns with both the zlint
  catalog ranking (`pass(3) < notice(4) < warn(5) < error(6) <
  fatal(7)`) and syslog RFC 5424 §6.2.1 severity ranking.
  `Severity` is `#[non_exhaustive]`, so the addition is non-breaking
  for callers that already include a wildcard arm on external
  matches.
- `severity_ordering_is_info_notice_warn_error_fatal` unit test pins
  the ordering contract so a future variant insertion cannot
  silently reorder existing variants.

### Changed

- In-tree exhaustive matches in `oscal::emit::severity_label` and
  `oscal::parse::parse_action` gain a `Notice` arm (`"notice"` label,
  symmetric with the existing `info` / `warn` / `error` / `fatal`
  labels).

## [0.7.0] — 2026-05-12

### Added

- Five new RFC-conformance shape-check `Lint` impls covering the
  shape-check requirements for `BasicTlsProfile` and `BasicSmimeProfile`
  in `pkix-profiles` (PKIX-9vnx.9.2.1):
  - `rfc5280::Rfc5280BasicConstraintsCaLeafLint` — RFC 5280 §4.2.1.9:
    end-entity certs MUST NOT assert `BasicConstraints.cA=TRUE`.
  - `rfc5280::Rfc5280EkuServerAuthLint` — RFC 5280 §4.2.1.12: TLS
    server end-entity certs MUST assert `id-kp-serverAuth` in
    `ExtendedKeyUsage`.
  - `rfc6125::Rfc6125TlsServerSanLint` — RFC 6125 §6.4.1: TLS server
    certs MUST carry a `subjectAltName` containing at least one
    `dNSName` or `iPAddress` entry.
  - `rfc8398::Rfc8398SmimeSanLint` — RFC 8398 §3 + RFC 5280 §4.2.1.6:
    S/MIME certs MUST carry a `subjectAltName` containing at least
    one `rfc822Name` or `otherName` of type `id-on-SmtpUTF8Mailbox`.
  - `rfc8551::Rfc8551EkuEmailProtectionLint` — RFC 5280 §4.2.1.12 +
    RFC 8551 §3.3: S/MIME certs MUST assert `id-kp-emailProtection`
    in `ExtendedKeyUsage`.
- Three new public modules `rfc6125`, `rfc8398`, `rfc8551`. Module
  structure mirrors the workspace convention of one module per
  standards-body source.

## [0.6.0] — 2026-05-12

### Added

- `Lint::spec_section_id() -> Option<&str>` and `Lint::spec_url() ->
  Option<&str>` as the new canonical default methods (PKIX-ncab.11).
  The slot was never RFC-specific — it accepts CA/B Forum BR, ITU-T
  X.509, NIST SP, and other standards-body section identifiers.

### Deprecated

- `Lint::rfc_section_id()` and `Lint::rfc_url()` remain as
  `#[deprecated(since = "0.6.0")]` default methods that return `None`.
  Override and call `spec_section_id` / `spec_url`. The deprecated
  aliases will be removed in a future minor release (no earlier than
  `pkix-lint 0.7.0`).

### Changed

- Doc comments on `title`, `description`, `spec_section_id`,
  `spec_url`, `parameters`, and `set_parameter` softened to reflect
  that OSCAL emit is one consumer of this metadata rather than its
  sole purpose, per the post-OSCAL-demotion framing
  (AGENTS.md non-negotiable #5).

## [0.5.0] — 2026-05-11

### Removed (breaking)

- `cabf_tls_br` module moved out to the sibling `pkix-lint-cabf`
  reference crate per the workspace framework-not-policy stance
  (AGENTS.md non-negotiable #5, PKIX-amgn.5). Types moved:
  `ValidityMaxLint`, `Sha1ProhibitedLint`, `RsaMinKeySizeLint`,
  `SanRequiredLint`, `EkuServerAuthLint`, `BcCaFlagLint`,
  `CabfTlsBrProfile`; free function `all_lints() -> Vec<Box<dyn
  Lint>>`; integration tests `tests/cabf_tls_br_tests.rs`.
- `pkix-profiles-cabf` runtime dependency dropped from this crate;
  the dep moves to `pkix-lint-cabf`.

  Migration:

  ```rust
  // before (pkix-lint 0.4.0):
  use pkix_lint::cabf_tls_br::CabfTlsBrProfile;

  // after (pkix-lint 0.5.0 + pkix-lint-cabf 0.2.0):
  use pkix_lint_cabf::cabf_tls_br::CabfTlsBrProfile;
  ```

### Changed (internal)

- OSCAL catalog/profile tests previously used `cabf_tls_br::ValidityMaxLint`
  and `cabf_tls_br::all_lints()` as fixtures. They now use a
  self-contained `PolicyShapedLint` test fixture and an in-crate
  `multi_lint_fixture()` so `pkix-lint`'s tests stay independent of
  CA/B Forum policy content. Cross-crate round-trip coverage against
  the real CA/B Forum lint set continues in `pkix-lint-cabf`'s
  integration tests.

## [0.4.0] — 2026-05-11

### Added — OSCAL alignment

- `oscal` cargo feature exposing `oscal::emit::assessment_results`,
  `oscal::emit::risks_from_store`, and
  `oscal::parse::deviation_store_from_risks` (PKIX-9vnx.3 / .4 / .5 /
  .10, Architecture 2 per PKIX-ztmr).
  - `assessment_results(&EvaluationReport) -> serde_json::Value`
    projects an evaluation run into a NIST OSCAL v1.1.2 Assessment
    Results document with evidence-deduplicated Observations keyed by
    `(cert_sha256, cert_index)` (matching OSCAL's intended 1:N
    Observation:Finding cardinality), per-lint Findings, and
    `DeviatedFinding`s as Risks with `status="deviation-approved"`.
  - `risks_from_store(&DeviationStore) -> Vec<serde_json::Value>`
    projects a deviation policy as a JSON array of OSCAL Risk
    objects with lossless reconstruction props (id, target_lint,
    action, authorized_by, effective_start/end, evidence_uri, and
    scope as OSCAL Subjects with type-specific props).
  - `deviation_store_from_risks(&serde_json::Value) ->
    Result<DeviationStore, ParseError>` is the inverse of
    `risks_from_store`; `(emit . parse)` over any non-empty store
    yields an `Eq`-equal store. The parser is intentionally narrow
    — it accepts the exact shape emitted by `risks_from_store`,
    not arbitrary OSCAL Risk documents.
- `oscal::catalog::catalog_from_lints(lints, catalog_id,
  catalog_version) -> serde_json::Value` (PKIX-9vnx.6.2). Projects a
  slice of `Box<dyn Lint>` onto an OSCAL Catalog v1.1.2 JSON Value.
  Each `Lint` impl maps to one OSCAL Control; UUIDs are derived
  deterministically (RFC 9562 §5.8 v8 using SHA-256) for byte-
  identical output.
- `oscal::parse::lint_ids_from_catalog(value) -> Result<Vec<String>,
  ParseError>` (PKIX-9vnx.6.3). Walks an OSCAL Catalog JSON Value
  and returns the ordered list of Control ids.
- `LintRunner::filter_to_ids(self, ids) -> Result<LintRunner,
  ParseError>` (feature-gated behind `oscal`). Returns a new
  `LintRunner` containing only the lints whose `id()` appears in
  `ids`, in the order `ids` requests them. Unknown ids error.
- `OSCAL Profile composition` via `oscal::profile::resolve_profile`
  for resolve + apply-overrides workflows.

### Added — Lint trait OSCAL-Control metadata

- Four new default-provided `Lint` trait methods (PKIX-9vnx.6.1):
  `title()`, `description()`, `rfc_section_id()`, `rfc_url()`.
  Title defaults to `id()`; the other three default to `None`.
  Renamed to `spec_*` in `0.6.0`; see that entry.

### Added — Lint parameter mechanism

- `LintParameter { id, label, default_value }` and `ParameterError`
  enum (PKIX-9vnx.6.4). Descriptor-only — maps onto an OSCAL Catalog
  `Parameter`. Lints store typed state directly; `set_parameter`
  parses the string-rendered override into that state.
- New default-provided trait methods `Lint::parameters(&self) ->
  &[LintParameter]` and `Lint::set_parameter(&mut self, id, value)
  -> Result<(), ParameterError>`.
- New module `rfc5280` with the first RFC-conformance lint:
  `Rfc5280MaxSerialLengthLint` (RFC 5280 §4.1.2.2: certificate
  serialNumber must not exceed 20 octets). Parametric on `max-octets`
  (default 20).

### Changed (breaking) — DeviationScope refactor

- `DeviationScope` enum replaced with a struct (PKIX-9vnx.11):

  ```rust
  pub struct DeviationScope {
      pub kind: String,
      pub props: Vec<(String, ScopePropValue)>,
  }

  #[non_exhaustive]
  pub enum ScopePropValue {
      Text(String),
      Bytes(Vec<u8>),
  }
  ```

  The shape mirrors OSCAL Subject (kind discriminator + typed props
  bag). Future scope axes are expressible via new `kind` strings +
  props without growing the public Rust enum surface.

  Migration uses the new constructors:

  ```rust
  // Before (0.3.x):
  let s = DeviationScope::Any;
  let s = DeviationScope::IssuerDnContains("agency x".to_string());

  // After (0.4.x):
  let s = DeviationScope::any();
  let s = DeviationScope::issuer_dn_contains("agency x");
  let s = DeviationScope::issuer_dn_exact(&cert.tbs_certificate.subject)?;
  let s = DeviationScope::serial_range(&cert.tbs_certificate.subject, start, end)?;
  ```

  Public constants exported for kind discriminators
  (`SCOPE_KIND_ANY`, `SCOPE_KIND_ISSUER_DN_CONTAINS`, etc.) and prop
  names (`PROP_ISSUER_DN_SUBSTRING`, `PROP_ISSUER_DN_DER`, etc.).

  Round-trip preservation: OSCAL JSON wire form unchanged. Stores
  that round-trip through OSCAL JSON before and after this release
  produce bit-identical output. Fail-closed semantics:
  `DeviationScope::matches` returns `false` for unknown kinds,
  missing props, wrong-typed props, or malformed DER.

## [0.3.0] — 2026-05-08

### Changed (breaking)

- `LintResult::Warn(&'static str)` → `LintResult::Warn(Cow<'static,
  str>)`. Same for `Error` and `Fatal` (PKIX-ua6q). Static string
  literals stay zero-allocation (via `Cow::Borrowed`); runtime-
  formatted strings (e.g. `format!(...)`) work without leaking memory
  (via `Cow::Owned`). Pattern matches stay unchanged —
  `LintResult::Warn(_)` still works.
- `LintResult::detail` returns `Option<&str>` (borrowed from `self`)
  rather than `Option<&'static str>`.
- `Finding`, `DeviatedFinding`, and `EvaluationReport` lose their
  `'de: 'static` serde deserialization bound. Deserialization no
  longer leaks heap allocations from `LintResult` detail strings,
  fixing the long-running-service memory growth documented in the
  prior crate's `de_static_str` rustdoc. `serde_json::from_slice`
  now works directly.
- Internal `de_static_str` serde helper removed.
- `Finding` gains a `cert_sha256: Option<[u8; 32]>` public field
  (PKIX-a86q). Construction sites that build a `Finding` via struct
  literal must add the field; `LintRunner::run_cert` populates it
  automatically.

### Added

- `LintResult::warn`, `LintResult::error`, and `LintResult::fatal`
  constructor helpers taking `impl Into<Cow<'static, str>>` for
  ergonomic construction from both static literals and runtime
  strings.
- `Finding.cert_sha256` — SHA-256 of the DER-encoded certificate
  that triggered the finding (PKIX-a86q). Pins findings to a
  specific cert by content hash so evidence packs are replayable.
  `Some(hash)` for cert-scope findings; `None` for path-scope
  findings. JSON serialisation uses a lowercase 64-char hex string.
- Direct `sha2` dependency (already transitive via `x509-cert`,
  so the binary footprint cost is zero).

## [0.2.0] — 2026-05-06

First crates.io release. Lint engine for X.509 certificates with
structured soft-fail and advisory results: `Lint`, `LintResult`,
`LintRunner`, `LintProfile`, `Finding`, `Scope`, `Severity`,
`SubjectKind`. `EvaluationReport`, `DeviationStore`,
`DeviationRunner`, and `Deviation` for advisory waiver tracking.
CABF TLS Baseline Requirements lints (validity, signature algorithm,
RSA, SAN, EKU, BC) shipped in the `cabf_tls_br` module (later moved
to `pkix-lint-cabf` in `0.5.0`).

### Notable

- `serial_lex_ge` / `serial_lex_le` consolidated into `serial_cmp`
  returning `core::cmp::Ordering`. Internal change; not on the
  public API surface.

## Pre-history

Initial scaffold landed under `15a7e0c9` (`feat: add pkix-lint
crate with Lint/LintResult/LintRunner/LintProfile traits`); the
CABF TLS BR reference lints landed in `468d0021` (`feat: CABF TLS
BR reference lints in pkix-lint (validity, alg, RSA, SAN, EKU,
BC)`); the advisory deviation mechanism landed in `973f2044` (`feat:
deviation (waiver) mechanism in pkix-lint`). These stabilized
through the `0.2.x` cycle.
