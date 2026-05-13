# Changelog

All notable changes to `pkix-zlint-bridge` are documented here. The
crate follows [Keep a Changelog](https://keepachangelog.com/) headings
and [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Scaffold release: public type surface for the zlint subprocess
  bridge. `Verdict`, `ZlintLintInfo`, `BridgeError`, `PerCertError`,
  `BridgeConfig`, `ZlintBridge` (constructor only; no subprocess
  invocation yet). All result/error types are
  `Clone + Debug + PartialEq + Eq + Send + Sync + non_exhaustive`,
  with `serde::Serialize` / `serde::Deserialize` derives gated on the
  `serde` cargo feature. `Verdict` is `Hash + Ord`. Send/Sync
  compile-time assertions follow the `PKIX-2l0v.2` const-block
  pattern. (PKIX-jy95.7.1.)
- Crate-level rustdoc explains the framework-not-policy positioning
  and cites the four design decisions inherited from the parent epic:
  per-check granularity (`.1`), severity mapping (`.2`), multi-file
  batch shape (`.3`), and bridge-vs-per-cert error discrimination
  (`.4`).
- `BridgeConfig::default()` returns `{ zlint_path: "zlint", timeout:
  60s }`. `ZlintBridge::new` accepts any config and is currently
  infallible (scaffold); the fallible signature is in place so
  binary-existence and version-pinning checks can land additively.
- `ZlintBridge::enumerate_lints()` spawns
  `<zlint_path> -list-lints-json` and returns
  `Vec<ZlintLintInfo>` from the line-delimited JSON output.
  Severity is derived from the check name prefix (`e_*` →
  `Severity::Error`, `w_*` → `Warn`, `n_*` → `Notice`); any other
  prefix surfaces as `BridgeError::OutputParseError` so a silent
  upstream catalog-shape change cannot mis-label findings. Optional
  fields (`description`, `citation`, `source`) default to the empty
  string when missing — zlint's catalog has several entries (CRL
  checks, community-source checks) that omit `citation`, and being
  strict here would refuse to enumerate the real catalog. Subprocess
  plumbing drains stdout/stderr on dedicated reader threads to avoid
  the classic pipe-buffer deadlock. Best-effort timeout enforcement
  via `try_wait` + sleep poll using
  [`BridgeConfig::timeout`]. (PKIX-jy95.7.2.)
- `ZlintBridge::run_on_cert(cert_der)` lints a single DER-encoded
  certificate and returns `HashMap<String, Verdict>` keyed by zlint
  check id. Results are cached on the bridge by `SHA-256(cert_der)`,
  so the `~400-Lint` adapter pattern from PKIX-jy95.1 pays only one
  subprocess cost per certificate. Cache lives in
  `Mutex<HashMap<[u8; 32], HashMap<String, Verdict>>>`; lookups
  return a clone to keep callers off the lock. Temporary input file
  is `pkix-zlint-bridge-<sha256-hex>.der` under `std::env::temp_dir()`,
  cleaned up on drop. Verdict mapping: `NA`/`NE` → `NotApplicable`;
  `pass`/`notice`/`warn`/`error`/`fatal` → like-named `Verdict`
  variants. (PKIX-jy95.7.3.)
- New unified `Error` enum (`Bridge(BridgeError)` /
  `Cert(PerCertError)`) for the single-certificate `run_on_cert`
  path. The bead's nominal `Result<_, PerCertError>` shape was
  incomplete — it could not represent bridge-level failures (binary
  missing, timeout, output parse error) that have nothing to do with
  the cert itself. `From` impls for both inner types, `Display`
  delegates with a discriminating prefix, `std::error::Error::source`
  returns the inner. The batch path keeps the asymmetric
  `Result<Vec<Result<_, PerCertError>>, BridgeError>` shape per
  PKIX-jy95.4. (PKIX-jy95.7.3.)
- New workspace dep: `sha2` (only needed for the verdict-cache key;
  same pin used by `pkix-revocation` and `pkix-ct`).
- `ZlintBridge::run_on_certs(certs_der)` lints a slice of
  certificates and returns one `Result<VerdictMap, PerCertError>`
  per input, in input order. Bridge-level failures (binary missing,
  subprocess crash, timeout) fail the whole call as the outer
  `BridgeError`; per-cert errors live inside the `Vec` so a single
  malformed cert does not poison the batch. Implementation walks
  zlint's multi-file invocation pattern with recursive batching:
  zlint aborts on the first malformed cert and emits partial output
  covering only the successful prefix, so the bridge records the
  malformed index and re-invokes zlint on the remainder. Typical
  batches (all valid) execute one subprocess call; batches with N
  malformed certs execute at most N + 1 calls. Cache integration:
  cached certs skip the subprocess entirely; the batch invocation
  only includes cache misses. New type aliases `VerdictMap`,
  `CertResult`, `BatchResults` factor out the batch-return shape.
  (PKIX-jy95.7.4.)
- Per-invocation temporary directory under `std::env::temp_dir()`
  named `pkix-zlint-bridge-<pid>-<atomic-counter>-<nanos>`. Each
  subprocess call gets its own scratch dir cleaned up on `Drop`
  via `remove_dir_all`. Replaces the earlier stable-per-cert-hash
  path scheme that raced on concurrent calls linting the same
  certificate (one call's cleanup deleted another in-flight call's
  input). (PKIX-jy95.7.4.)
