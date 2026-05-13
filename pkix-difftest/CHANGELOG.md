# Changelog

All notable changes to `pkix-difftest` are documented here. The crate is
dev tooling (`publish = false`) and is not on crates.io; this file
exists to track version-bearing changes for downstream consumers of the
in-tree harness (CI scripts, contributor workflows, baseline-diff
infrastructure). The format follows
[Keep a Changelog](https://keepachangelog.com/) headings and the spirit
of [Semantic Versioning](https://semver.org/) even though the crate is
not published.

## [Unreleased]

### Added

- Code-signing differential test (`tests/verify_wrapper_codesign.rs`)
  driven by a composed pyca/cryptography oracle
  (`python/pyca_codesign_oracle.py`). Resolves the PKIX-fmtv.18.5
  oracle-coverage gap that closed earlier: OpenSSL's `verify` tool has
  no `-purpose codesign` verb and pyca's `PolicyBuilder` is TLS-bound,
  so neither workspace-standard oracle covered `verify_code_signer`.
  The new oracle decomposes the wrapper's job into two independent
  checks neither of which uses workspace code: (1) chain walk via
  pyca's `Certificate.verify_directly_issued_by` primitive plus
  validity-period overlap, (2) standalone OID-match EKU check
  asserting `id-kp-codeSigning` on the leaf. 3 / 3 cases in agreement
  on the seed corpus; hard invariant of zero disagreement in either
  direction. `baseline-verify-openssl.md` updated to record the
  resolution. (PKIX-fmtv.24.)

- `lint_oracles` module behind the new `lint-oracles` cargo feature
  (off by default). Houses the lint-domain differential infrastructure
  for `PKIX-hbzo.1`:
  - `LintOracle` trait (`Send + Sync`) abstracting over per-cert lint
    oracles.
  - `OracleSource` enum (`PkixLintCabf` / `Zlint` / `Pkilint`). Not
    `#[non_exhaustive]`: adding a new oracle is an architectural event
    that should break match sites.
  - `NormalizedFinding` struct carrying `(id, severity, source)` — the
    cross-oracle vocabulary used by the reconciliation layer
    (`PKIX-hbzo.1.3`, pending).
  - `LintOracleResult` with explicit `oracle_error` channel for per-cert
    oracle failures (malformed DER, missing zlint binary). Per-cert
    failures surface here rather than as `Result::Err` so a single
    missing tool does not crash the differential run.
- `lint_oracles::zlint::ZlintOracle` — subprocess oracle backed by
  `pkix-zlint-bridge`'s `ZlintBridge::run_on_cert`. Maps zlint's
  `Verdict` enum to `pkix_lint::Severity` per the PKIX-jy95.2 severity
  table (`NotApplicable` / `Pass` drop; `Notice` / `Warn` / `Error` /
  `Fatal` map like-named).
- `lint_oracles::pkix_lint_cabf::PkixLintCabfOracle` — in-process oracle
  backed by `pkix_lint_cabf::cabf_tls_br::CabfTlsBrProfile`. Runs lints
  in audit mode (`run_cert_at_issuance`) so the SC-081 validity cap is
  anchored to the cert's `notBefore` per TLS BR §6.3.2.
- New optional workspace deps under the `lint-oracles` feature:
  `pkix-zlint-bridge`, `pkix-lint`, `pkix-lint-cabf`. Default-features
  build is unchanged (zero new transitive deps when the feature is off).
- 13 unit tests covering the verdict-mapping helpers, oracle-result
  constructors, and end-to-end shape on the in-tree `good-chain.pem`
  fixture (for the in-process pkix-lint-cabf oracle).
- 4 integration tests in `tests/lint_oracles.rs` (3 zlint-gated): real
  zlint subprocess against PKITS Good CA Test1 leaf + intermediate,
  malformed-input handling, and trait-object dispatch through
  `Box<dyn LintOracle>`. The zlint tests auto-skip when the binary is
  not on `PATH`.

### Notes

- Empirical: zlint dev-unknown returns only `NA` / `NE` / `pass` on the
  PKITS Good CA Test1 leaf and intermediate (generic RFC 5280 test
  certs that do not claim to be CA/B Forum TLS Server certificates).
  The integration test asserts the empty-findings shape rather than
  fabricating expected lint IDs. A cert that actually trips zlint
  findings will come from the CA/B Forum corpus selection in the
  follow-on `PKIX-hbzo.1.3` work.
- The `Pkilint` `OracleSource` variant is declared without an in-tree
  producer; the pkilint adapter is filed as `PKIX-hbzo.1.2` and blocked
  on `PKIX-jy95.8` (`pkix-pkilint-bridge` not yet shipped).
