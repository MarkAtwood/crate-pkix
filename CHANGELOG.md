# Changelog

All notable changes to the workspace crates are documented here. The workspace
follows [Keep a Changelog](https://keepachangelog.com/) headings and
[Semantic Versioning](https://semver.org/) for each crate independently.

## [unreleased]

### Policy: drop v0.x milestone gating (2026-05-11)

Dropped v0.x milestone gating across the workspace. The project drives to
full RFC 5280 and adjacent-RFC coverage; no features are gated by a version
milestone. Per-crate `# Limitations` rustdoc sections continue to describe
current shipped behavior and shrink as features land — not by editorial
fiat, but when the underlying code changes. Sweep tracked as PKIX-agp7.

### Coordinated 0.3 follow-up wave (May 2026)

The `pkix-path 0.3.0` release on git is the centerpiece of a coordinated
follow-up to the May-2026 0.3 wave already published on crates.io. Five
crates ship together to keep the dep graph consistent across crates.io
once published:

| Crate | Old (crates.io) | New (this release) | Type |
|---|---|---|---|
| `pkix-path` | 0.2.1 | **0.3.0** | BREAKING (`ValidatedPath` loses `Copy` / `Hash`; new owned-data fields) |
| `pkix-revocation` | 0.3.0 | **0.3.2** | additive (CDP/IDP variant + RevocationFetchFailed variant + dep on pkix-path 0.3) |
| `pkix-chain` | 0.3.0 | **0.4.0** | TRANSITIVELY BREAKING (re-exports `pkix-path::ValidatedPath`) |
| `pkix-chain-simple` | 0.3.0 | **0.4.0** | TRANSITIVELY BREAKING (same rationale) |
| `pkix-path-builder` | 0.2.1 | **0.3.0** | BREAKING (dep major bump + skip-not-fail behavior change) |

Why a follow-up release: `pkix-revocation 0.3.0` was published on
crates.io on 2026-05-08 with a frozen `pkix-path = "^0.2.1"` dep. With
`pkix-path 0.3.0` on git, the published `pkix-revocation 0.3.0` cannot
depend on it (Cargo pre-1.0 SemVer treats 0.2.x and 0.3.x as
incompatible). The 0.3.1 / 0.4.0 / 0.3.0 bumps below restore a clean
dep graph on crates.io once the wave is published.

Publish order (dependency-graph-respecting):
1. `pkix-path 0.3.0`
2. `pkix-revocation 0.3.2`
3. `pkix-path-builder 0.3.0`
4. `pkix-chain 0.4.0`
5. `pkix-chain-simple 0.4.0`

`pkix-profiles`, `pkix-lint`, `pkix-difftest` are NOT bumped in this
wave — they have low download counts on crates.io, no urgent consumer
need, and can ride a future 0.3.x wave when they actually change.
Consumers who pull these crates from crates.io will continue to get
their existing 0.2.x versions (which depend on `pkix-path 0.2.x` from
crates.io); a fresh project that wants `pkix-path 0.3.0` features
should consume `pkix-path` directly rather than transitively via these
secondary crates until they ship updates.

### `pkix-lint 0.3.0`

BREAKING. Two coordinated changes ship in 0.3.0:

1. `LintResult` detail field migrated to `Cow<'static, str>` (PKIX-ua6q).
2. `Finding.cert_sha256: Option<[u8; 32]>` added for evidence-pack
   provenance (PKIX-a86q).

The first sub-change is the LintResult migration: `LintResult::Warn`,
`LintResult::Error`, and `LintResult::Fatal` now carry `Cow<'static, str>`
instead of `&'static str`. Static string literals stay zero-allocation
(via `Cow::Borrowed`); runtime-formatted strings (e.g. `format!(...)`)
work without leaking memory (via `Cow::Owned`).

#### Changed (breaking)

- `LintResult::Warn(&'static str)` → `LintResult::Warn(Cow<'static, str>)`.
  Same for `Error` and `Fatal`.
- `LintResult::detail` returns `Option<&str>` (borrowed from `self`) rather
  than `Option<&'static str>`. The borrow's lifetime is tied to `self`.
- `Finding`, `DeviatedFinding`, and `EvaluationReport` lose their
  `'de: 'static` serde deserialization bound. Deserialization no longer
  leaks heap allocations from `LintResult` detail strings, fixing the
  long-running-service memory growth documented in the prior crate's
  `de_static_str` rustdoc. `serde_json::from_slice` (which could not be
  used before because of `'de: 'static`) now works.
- The internal `de_static_str` serde helper is removed (no longer needed).

#### Added

- `LintResult::warn`, `LintResult::error`, and `LintResult::fatal`
  constructor helpers taking `impl Into<Cow<'static, str>>`. Use these for
  ergonomic construction from both static literals and runtime strings:

  ```rust
  use pkix_lint::LintResult;
  let r1 = LintResult::warn("static text");           // Cow::Borrowed
  let bits = 1024u32;
  let r2 = LintResult::error(format!("RSA modulus {bits} bits < 2048"));
  ```

- One new lint detail in `cabf_tls_br::Sc081ValidityMaxLint` demonstrates
  `Cow::Owned` usage: the cap-violation error now reports the actual cert
  duration in days and the cap in effect at issuance, instead of a static
  "exceeds cap" message. Audit trails see the offending value.

- `Finding.cert_sha256: Option<[u8; 32]>` (PKIX-a86q). SHA-256 of the
  DER-encoded certificate that triggered the finding, pinning the
  finding to a specific cert by content hash so evidence packs are
  replayable. `Some(hash)` for cert-scope findings (populated by
  `LintRunner::run_cert`), `None` for path-scope findings (no single
  triggering cert). JSON serialisation uses a lowercase 64-char hex
  string; binary serde formats emit the same hex-string form for
  consistency. Adds a direct `sha2` dependency (already transitive via
  `x509-cert`, so the binary footprint cost is zero).

#### Migration

Pattern-matches stay unchanged — `LintResult::Warn(_)` still works.

Construction sites change:

```rust
// Before (0.2.x):
LintResult::Error("static text")

// After (0.3.0):
LintResult::error("static text")
// or equivalently:
LintResult::Error(std::borrow::Cow::Borrowed("static text"))
```

The constructor-helper form (`LintResult::error("...")`) is recommended.
It is zero-cost for static strings and also accepts `String` /
`format!(...)` output:

```rust
LintResult::error(format!("duration {days} > {cap_days}"))
```

Code that used `Box::leak` on JSON input to satisfy the prior
`'de: 'static` bound can drop the leak — `serde_json::from_str` and
`from_slice` both work directly on any owned String / slice now.

Construction sites that build a `Finding` via struct literal must add
`cert_sha256: None` (or the appropriate `Some([u8; 32])`) to the field
list — adding a public field to a non-`#[non_exhaustive]` struct is a
breaking change for external code that constructs via struct literal.
`LintRunner::run_cert` populates the field automatically; callers using
the runner do not need to construct `Finding` manually.

### `pkix-revocation 0.3.2`

#### Added

- `Error::RevocationFetchFailed { description: String }` variant.
  Returned by network-fetching adapters (`pkix-revocation-http`'s
  `HttpCrlFetcher` / `HttpOcspFetcher`, future LDAP / out-of-band
  adapters) when every URL extracted from the certificate failed
  either at the transport layer (network, TLS, HTTP error) or at the
  response layer (DER parse, signature, validity). Distinct from
  `Revoked`, `OcspStatusUnknown`, and `OutOfScope`. Hard-fail callers
  MUST reject the chain on this variant; soft-fail callers MAY treat
  it permissively.

  `Error` is `#[non_exhaustive]`, so adding the variant is
  non-breaking. Callers that exhaustively match on `Error` should add
  an arm (or use `_`) to be forward-compatible. Tracked as PKIX-a1yc.5
  in the project beads.

### `pkix-revocation 0.3.1`

#### Added

- `OutOfScopeReason::CrlIdpDistributionPointMismatch` variant. Returned
  by `CrlChecker::check_revocation` and `check_revocation_against_anchor`
  when the CRL's `IssuingDistributionPoint.distributionPoint` does not
  match (or is incompatible with) any of the certificate's
  `cRLDistributionPoints` extension entries (RFC 5280 §6.3.3(b)(1)).
  `OutOfScopeReason` is `#[non_exhaustive]`, so adding the variant is
  non-breaking.

  See the existing 0.3.0 entry below for the surrounding `Error::OutOfScope`
  contract that this variant participates in.

#### Changed (non-breaking)

- `CrlChecker` now performs RFC 5280 §6.3.3(b)(1) distribution-point
  name matching as part of the existing IDP scope check. Both
  `DistributionPointName::FullName` and
  `DistributionPointName::NameRelativeToCRLIssuer` forms are supported
  with cross-form resolution. PKITS §4.14.3, §4.14.8, §4.14.9
  (previously `#[ignore]`'d) now pass.

  See `pkix-revocation/src/crl.rs` rustdoc for the algorithm and
  documented limitations (per-DP `cRLIssuer` field not honored when
  resolving the cert's CDP base DN; reasons-subset check on
  `onlySomeReasons` not yet implemented).

  Tracked as PKIX-zg9y in the project beads.

#### Migration

- Dep bump: `pkix-revocation = "0.3.1"` and `pkix-path = "0.3"`.
  Callers that match on `Error::OutOfScope(_)` should add an arm for
  `OutOfScopeReason::CrlIdpDistributionPointMismatch` (or use a
  catch-all `_` arm) to be ready for future variants.

### `pkix-chain 0.4.0` — TRANSITIVELY BREAKING

#### Migration

- Bump `pkix-chain = "0.3"` to `pkix-chain = "0.4"` in your
  `Cargo.toml`.
- The re-exported `pkix_path::ValidatedPath` no longer derives `Copy`
  or `Hash`. If you relied on bit-copy semantics, add `.clone()` calls
  or pass `&ValidatedPath` instead. See `pkix-path 0.3.0` migration
  for full details.
- Transitively picks up `pkix-revocation 0.3.1`'s
  `CrlIdpDistributionPointMismatch` variant on `Error::OutOfScope`.

#### No surface changes

`pkix-chain`'s own public API (the `verify_chain` function family) is
unchanged. The break is purely the `ValidatedPath` re-export shape
change and the `Error` re-export's new variant.

### `pkix-chain-simple 0.4.0` — TRANSITIVELY BREAKING

Same migration and rationale as `pkix-chain 0.4.0` above.

### `pkix-path-builder 0.3.0` — BREAKING

#### Migration

- Bump `pkix-path-builder = "0.2"` to `pkix-path-builder = "0.3"` in
  your `Cargo.toml`.
- Behavior change: `build_path`, `build_path_with_config`, and the
  `PathCandidates` iterator now silently **skip** candidate
  intermediates whose `BasicConstraints` extension is present but
  cannot be DER-decoded, rather than aborting the search with
  `Error::MalformedIntermediate`. See the previous unreleased section
  for the full skip-not-fail rationale.
- Dep major bump on `pkix-path` (0.2 → 0.3); the `pkix-path-builder`
  public API is otherwise unchanged.

  Tracked as PKIX-qgw1 in the project beads.

### `pkix-path 0.3.0` — BREAKING

#### Added — RFC 5280 §6.1.2(a) policy qualifier processing

- `ValidatedPath::valid_policy_tree: Option<Vec<PolicyTreeNode>>` — the
  final §6.1.5 valid_policy_tree, or `None` if reduced to NULL during
  validation. Each node carries the policy qualifiers attached to it at
  creation time, sourced per RFC 5280:
  - §6.1.3(d)(1)(i)/(ii): from the cert's per-policy `policy_qualifiers`.
  - §6.1.3(d)(2) (anyPolicy expansion): from the cert's anyPolicy entry.
  - §6.1.4(b)(1) (PolicyMappings synthesis): from the cert's anyPolicy
    entry per RFC §6.1.4(b)(1)(ii).
  - §6.1.5(g)(iii)(3) (initial-policy-set materialization): inherited
    from the leaf anyPolicy node about to be deleted.

- `pub struct PolicyTreeNode` — public mirror of the internal
  `PolicyNode`. `#[non_exhaustive]`. Fields: `depth`, `valid_policy`,
  `expected_policy_set`, `qualifiers`. Qualifiers are exposed as the
  upstream `x509_cert::ext::pkix::certpolicy::PolicyQualifierInfo` raw
  (a `(qualifier_id_oid, raw_any_value)` pair); decoding the `Any`
  content to `CpsUri`/`UserNotice` is left to the caller because
  x509-cert 0.2.5 has a typo on `UserNotice.notice_ref` (declared
  `Option<GeneralizedTime>` instead of `Option<NoticeReference>`) and
  upstream-side decoding would silently mishandle real-world
  UserNotice qualifiers.

- `ValidatedPath::policy_qualifiers()` — convenience iterator yielding
  `(&policy_oid, &PolicyQualifierInfo)` pairs across every tree node.
  Returns an empty iterator when the tree is `None`.

  Path validation does NOT gate on qualifier validity — RFC 5280 §6.1.2(a)
  explicitly says qualifier processing is application-specific. The new
  fields are pure read-side outputs.

  Tracked as PKIX-an8h in the project beads. Decoding the `Any` content
  side of `PolicyQualifierInfo` is deferred until x509-cert ships a fix
  for `UserNotice.notice_ref`.

#### Changed (breaking)

- **`ValidatedPath` no longer derives `Copy`.** Four new heap-backed fields
  surface the §6.1.5 leaf-intrinsic outputs (`leaf_subject`, `leaf_issuer`,
  `leaf_serial`, `leaf_spki`); none of the field types
  (`x509_cert::name::Name`, `x509_cert::serial_number::SerialNumber`,
  `spki::SubjectPublicKeyInfoOwned`) implement `Copy` upstream, so the
  derive must be removed.

  **Migration**: callers that relied on bit-copy semantics (passing
  `ValidatedPath` by value to multiple consumers without `.clone()`) need
  to either insert an explicit `.clone()` or pass `&ValidatedPath` instead.
  No in-tree workspace consumer relied on this; downstream impact is
  expected to be minimal.

- **`ValidatedPath` no longer derives `Hash`.** None of the new field
  types implement `Hash` upstream. Existing usage of `ValidatedPath` as
  a `HashMap`/`HashSet` key — none observed in this workspace — is no
  longer possible. Callers needing hashable identity for a validated path
  can hash any of the new fields (`leaf_serial`, `leaf_spki`'s DER
  encoding) directly.

#### Added

- `ValidatedPath::leaf_subject: x509_cert::name::Name` — RFC 5280 §6.1.5
  output: subject DN of the validated leaf certificate (`chain[0]`).
- `ValidatedPath::leaf_issuer: x509_cert::name::Name` — issuer DN of the
  validated leaf certificate.
- `ValidatedPath::leaf_serial: x509_cert::serial_number::SerialNumber` —
  serial number of the validated leaf certificate.
- `ValidatedPath::leaf_spki: spki::SubjectPublicKeyInfoOwned` —
  `SubjectPublicKeyInfo` of the validated leaf certificate (carries
  algorithm OID, parameters, and public-key bits).

  These four fields let downstream code read the validated leaf's
  identity without re-parsing `chain[0]`. Common uses include revocation
  lookups (need `{ issuer, serial }`), application-layer signature
  verification using the validated leaf as a trust delegate (needs SPKI),
  and audit logging (needs subject DN).

  Tracked as PKIX-qzmr in the project beads.

### `pkix-revocation` — CDP/IDP `distributionPoint` matching (RFC 5280 §6.3.3(b)(1))

#### Added

- `OutOfScopeReason::CrlIdpDistributionPointMismatch` variant. Returned by
  `CrlChecker::check_revocation` and `check_revocation_against_anchor` when
  the CRL's `IssuingDistributionPoint.distributionPoint` does not match (or
  is incompatible with) any of the certificate's `cRLDistributionPoints`
  extension entries. `Error` and `OutOfScopeReason` are both
  `#[non_exhaustive]`, so adding this variant is **non-breaking** for
  callers using `match` arms.

#### Changed (non-breaking)

- `CrlChecker` now performs RFC 5280 §6.3.3(b)(1) distribution-point name
  matching as part of the existing IssuingDistributionPoint scope check.
  Both `DistributionPointName::FullName` and
  `DistributionPointName::NameRelativeToCRLIssuer` forms are supported,
  with `NameRelativeToCRLIssuer` resolved by appending the relative RDN to
  the appropriate base DN (the certificate's issuer for the cert's CDP,
  the CRL signer's subject for the CRL's IDP). Cross-form matching works:
  a cert whose CDP uses `NameRelativeToCRLIssuer` matches a CRL whose IDP
  uses `FullName` when both resolve to the same DN.

  `GeneralName::DirectoryName` entries compare via `pkix_path::names_match`
  (proper RFC 4518 DN equivalence including the new BMPString support).
  Other `GeneralName` variants (URI, dNSName, rfc822Name, IP address, OID,
  etc.) compare via byte-exact DER encoding equality.

  PKITS §4.14.3, §4.14.8, and §4.14.9 — the three `#[ignore]`d tests for
  CDP/IDP name matching — now pass with assertions tightened to expect
  `Err(OutOfScope(CrlIdpDistributionPointMismatch))` specifically. PKITS
  §4.14.4 (cross-form match: cert `NameRelativeToCRLIssuer`, CRL
  `FullName`) continues to pass.

  Limitations:
  - The per-`DistributionPoint` `cRLIssuer` field is not honored when
    resolving the cert's CDP base DN; the certificate's own issuer is
    always used. This is correct for the common case (RFC 5280 §4.2.1.13
    requires conforming CAs to omit `cRLIssuer` when the cert issuer also
    issues the CRL) and is sufficient for all PKITS §4.14 fixtures.
  - The reasons-subset check (`onlySomeReasons` on IDP must cover the
    reasons the cert's CDP asks to be checked) is not implemented. PKITS
    §4.14 fixtures do not exercise it. Tracked as future work; a separate
    `OutOfScopeReason` variant will be added at that time.

  Tracked as PKIX-zg9y in the project beads.

### `pkix-path` — `BMPString` AVA values are now compared after UCS-2-BE → UTF-8 transcoding

#### Changed (non-breaking)

- `names_match` (and the underlying `ava_values_match`) now decodes
  `BMPString`-tagged `AttributeTypeAndValue` content from UCS-2 big-endian
  to UTF-8 before applying the existing ASCII case-fold and
  insignificant-whitespace normalization. As a result, two AVAs that
  encode the same Unicode code points using different DER string types
  (`BMPString` vs `UTF8String`/`PrintableString`/`IA5String`/`VisibleString`)
  now compare equal where they previously fell through to raw DER byte
  comparison and compared unequal.

  Behaviour change for adversarial / malformed input: a `BMPString` with
  odd-length content bytes or 16-bit units in the UTF-16 surrogate range
  (U+D800..=U+DFFF) is now rejected by `any_to_str_bytes` (returns
  `None`); the dispatcher in `ava_values_match` then returns `false` for
  any comparison involving the malformed value (fail-closed). Previously
  malformed `BMPString` values fell through to raw DER byte comparison,
  so two byte-identical malformed values would have compared equal.
  Real-world certificates with malformed `BMPString` content do not
  exist in the PKITS corpus or any other in-tree fixture; the change is
  cosmetic for non-adversarial input.

  `UniversalString` AVAs continue to be parser-rejected upstream by
  `der` 0.7 (tag 0x1C is absent from `der::Tag::try_from`) and never
  reach this comparator. `TeletexString` continues to fall through to
  raw DER byte comparison (deferred pending a clear interoperability
  target — see PKIX-l63j.3).

  No new dependencies. `no_std` preserved. `pkix-path` stays at 0.2.x.

  Tracked as PKIX-l63j.1 (subset of the PKIX-l63j RFC 4518 epic) in the
  project beads. NFKC and full RFC 4518 prep for non-ASCII Unicode is
  tracked separately as PKIX-l63j.2.

### `pkix-path-builder` — skip-not-fail on malformed `BasicConstraints`

#### Changed (non-breaking)

- `build_path`, `build_path_with_config`, and the `PathCandidates` iterator
  now silently **skip** candidate intermediates whose `BasicConstraints`
  extension is present but cannot be DER-decoded, rather than aborting the
  search with `Error::MalformedIntermediate`. This matches the existing
  treatment of candidates with `cA = FALSE` or no `BasicConstraints` at all.

  Rationale: real-world certificate pools (notably CMS
  `SignedData.certificates` bags) routinely include unsolicited or corrupt
  certs the verifier did not request — for other recipients in a
  multi-recipient encrypted message, intermediates from unrelated CAs that
  rode along, or expired/corrupt artefacts from someone's pipeline. One bad
  cert in the bag must not poison verification of an otherwise-valid chain.

  When skipping all malformed candidates would leave no path to a trust
  anchor, `build_path` returns `Error::NoPathFound` (as it would for any
  other no-path scenario). The `Error::MalformedIntermediate` variant is
  retained because `Error` is `#[non_exhaustive]` and may be repurposed by
  a future diagnostic mode.

  Tracked as PKIX-qgw1 in the project beads.

### `pkix-ct` — SCT parser, delivery adapters, and CT log list

#### Added

- `SignedCertificateTimestamp` and `SctList` now carry parsed values
  rather than placeholder fields. `SignedCertificateTimestamp` exposes
  `version`, `log_id` (32 bytes), `timestamp_ms` (u64 BE), `extensions`
  (Vec<u8>), `hash_alg`, `sig_alg`, and `signature` (raw bytes).
- `SignedCertificateTimestamp::from_bytes` parses a single SCT.
- `SctList::from_extension_value` parses the value of a cert's SCT-list
  extension (OID 1.3.6.1.4.1.11129.2.4.2). It peels the inner DER
  OCTET STRING that RFC 6962 §3.3 wraps the `SignedCertificateTimestampList`
  in. The outer extension OCTET STRING is assumed to be already stripped
  by the extension framework (e.g. via `x509_cert::ext::Extension::extn_value.as_bytes()`).
- `SctList::from_serialized_list` parses bare `SerializedSCTList` bytes
  for callers handling TLS-handshake-extension or OCSP-extension delivery
  (the OCSP and TLS forms are not double-wrapped).
- `sct_list_from_tls_extension` parses the payload of TLS handshake
  extension 18 (`signed_certificate_timestamp`). Thin alias over
  `SctList::from_serialized_list` since the TLS-wire form is not
  OCTET-STRING-wrapped.
- `sct_list_from_ocsp_response` parses an OCSP `BasicOcspResponse` DER
  and extracts the first `SignedCertificateTimestampList` extension found
  (single-response extensions first, then top-level response extensions).
  Gated behind a new `ocsp` crate feature; pulls in `x509-ocsp`.
- `CtLog` and `CtLogList` types (behind a new `log-list` feature) hold
  the trust anchor set for SCT verification. `CtLogList::insert`
  enforces `log_id == SHA-256(key_der)` per RFC 6962 §3.2. Includes
  `new` / `insert` / `get` / `len` / `is_empty` / `iter` accessors.
- `CtLogList::from_google_log_list_json` (behind a new `log-list-json`
  feature, which implies `log-list`) parses the Chrome / Google
  `log_list.json` schema v3 published at
  <https://www.gstatic.com/ct/log_list/v3/log_list.json>. Unknown JSON
  fields are ignored; `state.usable.timestamp` and `state.retired.timestamp`
  are extracted as `usable_from_ms` and `retired_at_ms`.
- New `Error` variants `UnsupportedVersion(u8)` and `TruncatedOrTrailing`
  (`Error` is `#[non_exhaustive]`; adding variants is non-breaking).

#### Changed

- The crate is now `no_std` + `alloc` by default (default features is
  the empty set). A new `std` feature gates the `std::error::Error` impl
  on `Error` and propagates `std` to `der`, `x509-cert`, `signature`,
  and optionally `x509-ocsp` / `sha2`. Consumers wanting std-only
  behaviour add `features = ["std"]`. No consumer code is currently
  broken: the previous default included `std::error::Error`; the new
  default does not, so a consumer that relied on `Error: std::error::Error`
  will need to enable the feature. pkix-ct is at `0.0.0` and not
  published, so the impact is contained to in-tree consumers.

- `verify_scts` removed from the crate root. Replaced by methods on
  [`SctVerifier`]: `verify_sct_for_cert` (RFC 6962 `x509_entry`),
  `verify_sct_for_precert` (`precert_entry`), and `verify_embedded_scts`
  (count-returning loop helper for cert-embedded SCT-list extensions).
  BREAKING for any in-tree caller of `pkix_ct::verify_scts`; none
  exist, and pkix-ct remains at 0.0.0 (unpublished). The non-`log-list`
  stub `CtLogList` was retired together with the old standalone
  helper. Tracked as PKIX-baac.7.

- Error variants `NoTrustedSct` and `PrecertEntryNotImplemented` removed
  from `Error`: both were only emitted by the prior `verify_scts` stub
  / pre-cert stub paths that no longer exist. New variant
  `LeafMissingSctList` added for the `verify_sct_for_precert` case
  where the leaf has no SCT-list extension. `Error` remains
  `#[non_exhaustive]`.

- The `Limitations` rustdoc section is updated to describe what's
  implemented (parsing + delivery adapters + log list + signature
  verification for both `x509_entry` and `precert_entry`) vs what is
  not (Merkle inclusion proofs, tracked as PKIX-baac.5).

  Tracked as PKIX-baac.1 (parser), PKIX-baac.6 (delivery adapters),
  PKIX-baac.2 (log list), PKIX-baac.3 (`x509_entry` verifier),
  PKIX-baac.4 (`precert_entry` verifier), and PKIX-baac.7
  (`verify_embedded_scts`).

## [0.3.0 / 0.2.1] — 2026-05-07

This release groups three concurrent crate versions:

- `pkix-revocation 0.3.0`, `pkix-chain 0.3.0`, `pkix-chain-simple 0.3.0` — semver-breaking.
- `pkix-path 0.2.1`, `pkix-path-builder 0.2.1`, `pkix-profiles 0.2.1` — additive.
- `pkix-lint 0.2.0` — first publish.

### `pkix-revocation 0.3.0` — BREAKING

#### Changed (breaking)

- **`Error::OutOfScope(OutOfScopeReason)` variant added** and is now returned at
  six previously-`Ok(())` sites in `CrlChecker::check_revocation` and
  `CrlChecker::check_revocation_against_anchor` corresponding to the three
  `IssuingDistributionPoint` scope-flag mismatches in RFC 5280 §5.2.5
  (`onlyContainsAttributeCerts`, `onlyContainsUserCerts`, `onlyContainsCACerts`).

  The pre-0.3.0 API documented `Ok(())` as having "dual semantics" — it could
  mean either "verified not-revoked" OR "no determination made (out of scope)".
  Hard-fail callers had no programmatic way to distinguish.

  Under 0.3.0, `Ok(())` is unambiguous "verified not-revoked"; "not covered"
  surfaces as `Err(Error::OutOfScope(reason))` for CRL or
  `Err(Error::OcspStatusUnknown)` for OCSP.

  **Migration**: callers that used `match` on `pkix_revocation::Error` MUST
  add a match arm for `Error::OutOfScope(_)` (the enum is `#[non_exhaustive]`,
  so this is a warning rather than a compile error, but the behavior change
  is silent without the new arm). Hard-fail revocation policies should treat
  `Error::OutOfScope` as a failure. Soft-fail callers can match on the
  specific `OutOfScopeReason` (`CrlOnlyAttributeCerts`, `CrlOnlyUserCerts`,
  `CrlOnlyCaCerts`) and decide which scopes to tolerate.

  Tracked as PKIX-qwzx.11 in the project beads.

#### Added

- `pub enum OutOfScopeReason` with variants `CrlOnlyAttributeCerts`,
  `CrlOnlyUserCerts`, `CrlOnlyCaCerts`. Derives `Clone`, `Copy`, `Debug`,
  `PartialEq`, `Eq`, `Hash`. Has a `Display` impl. `#[non_exhaustive]`.
- `Error::OutOfScope(OutOfScopeReason)` variant. `Display` formats as
  `"revocation source out of scope: {reason}"`.

#### Documentation

- `RevocationChecker::check_revocation` trait doc rewritten to remove the
  "dual semantics" warning and to document the new `OutOfScope` /
  `OcspStatusUnknown` distinction between CRL and OCSP "not covered" paths.

### `pkix-chain 0.3.0` — transitively breaking

Re-exports `pkix-revocation::Error` via `Error::Revocation(_)`. The
`OutOfScope` variant change above propagates: cases that previously surfaced
as `Ok(())` from `verify_chain` / `verify_chain_default` now surface as
`Err(Error::Revocation(Error::OutOfScope(_)))`. No `pkix-chain` API
surface changes beyond the dependency bump.

### `pkix-chain-simple 0.3.0` — transitively breaking

Same rationale as `pkix-chain 0.3.0`.

### `pkix-path 0.2.1`

#### Added

- `pub fn cert_is_ca(cert: &Certificate) -> Result<bool, DerError>` — RFC 5280
  §4.2.1.9 `BasicConstraints` decode helper. Returns `Ok(true)` if the cert
  has `cA = TRUE`, `Ok(false)` if absent or `cA = FALSE`, `Err(DerError)` if
  the extension is present but malformed (fail-closed). Shared by
  `pkix-path-builder` and `pkix-revocation::crl` to avoid duplicate
  RFC 5280 §4.2.1.9 decoders.

### `pkix-path-builder 0.2.1`

#### Added

- `PathBuilderConfig` and `build_path_with_config` (originally landed in
  earlier 0.2 work; full surface stable in 0.2.1).

#### Changed (non-breaking)

- `cert_is_ca` is now a thin wrapper over `pkix_path::cert_is_ca` with
  `.map_err(|_| Error::MalformedIntermediate)`. Behavior unchanged.
- `Error::DepthExceeded` doc and `Display` no longer hardcode "(10)";
  reference `PathBuilderConfig::max_depth` and `DEFAULT_MAX_DEPTH`.

### `pkix-profiles 0.2.1`

Documentation and lint adjustments. No public API changes.

### `pkix-lint 0.2.0` — first publish

First crates.io release. Lint engine for X.509 certificates with structured
soft-fail and advisory results. CABF TLS Baseline Requirements lints,
deviation tracking, OSCAL-style reports.

#### Notable

- `serial_lex_ge` / `serial_lex_le` consolidated into `serial_cmp` returning
  `core::cmp::Ordering`. Internal change; not on the public API surface.

### New workspace member: `pkix-truststore`

Tier 1 trust anchor loading. Bytes-in (PEM or DER), `Vec<TrustAnchor>`-out.
File-reading convenience wrappers and a `from_der_iter` entry point that
adapter crates (system stores, HSMs, cloud KMS) feed.

Binding project stance recorded in `AGENTS.md`: no compiled-in CA bundle,
no baked-in trust source. Platform / HSM / cloud trust stores are
out-of-tree adapter crates (`pkix-truststore-system` (PKIX-8h87),
`pkix-truststore-pkcs11` (PKIX-p8vz), etc.) that fetch DER bytes from a
source-specific API and feed them into `pkix_truststore::from_der_iter(...)`.

Initial version `0.0.0` per the workspace stub-crate convention; bumped
to `0.1.0` on first publish.

### Stub crates

The following crates remain at `0.0.0` placeholder versions and are NOT
published in this release:

- `pkix-revocation-http` (online CRL/OCSP fetching — not yet implemented)
- `pkix-ct` (Certificate Transparency SCT verification — not yet implemented)
- `pkix-composite` (composite classical+PQC signatures — not yet implemented)
- `pkix-ac` (RFC 5755 attribute certificates — not yet implemented)
- `pkix-truststore` (PEM/DER trust anchor loading — implemented, unpublished
  pending first crates.io release decision)

The 0.1.1 versions of these stubs on crates.io are placeholder releases that
predate the 0.0.0 reset; consumers should not depend on them.

## [0.2.0] — 2026-05-06

Initial 0.2 release. Workspace structure stabilized; PKITS happy-path subset
green; `pkix-path` `chain_walk` implements RFC 5280 §6.1 across signature
verification, validity period, name constraints (with `nameConstraints`
intersection/union and `nc_constrained_types` tracking), policy tree
(including `PolicyMappings` and `InhibitAnyPolicy`), and the §6.1.5 wrap-up.

## [0.1.x] — 2026-05-05 and earlier

Pre-release iteration. See git log for details.
