# Changelog

All notable changes to the workspace crates are documented here. The workspace
follows [Keep a Changelog](https://keepachangelog.com/) headings and
[Semantic Versioning](https://semver.org/) for each crate independently.

## [unreleased]

### Send + Sync compile-time assertions on result types (2026-05-13)

AGENTS.md non-negotiable #6 requires load-bearing result and error types
to be `Send + Sync` so callers can move values across threads and store
them in shared caches. The rule was previously aspirational — every type
satisfied it via auto-derive (no `Rc<T>`, `RefCell<T>`, or raw
pointers anywhere), but a future field adding `Rc<T>` to an `Error`
variant would silently regress without any compile-time check.

This change adds a `const _: fn() = || { _assert_send_sync::<T>() }`
block to each crate that defines such a type, promoting the
auto-derived `Send + Sync` from happenstance to a compile-time
invariant. Asserted types:

- `pkix-path`: `ValidatedPath`, `Error`, `TrustAnchor`, `ValidationPolicy`
- `pkix-chain`: `Error`
- `pkix-revocation`: `Error`
- `pkix-truststore`: `Error` (the `TrustAnchor` re-export is covered by
  the `pkix-path` assertion)
- `pkix-lint`: `Finding`

No new dependencies (no `static_assertions` crate); the
`const _: fn() = || { ... }` pattern uses only stable Rust.

No behavior change. No version bumps; the assertions are private
`const _` items that do not affect any crate's public API.

Tracked as [PKIX-2l0v.2].

[PKIX-2l0v.2]: https://github.com/MarkAtwood/crate-pkix  "Send+Sync compile-time audit"

### `pkix-lint` 0.9.0: three deferred RFC-conformance lints (2026-05-13)

`pkix-lint` ships the three remaining lints from the PKIX-9vnx.9.2.1
candidate list ([PKIX-9vnx.9.2.1.1]), closing out the 8-of-8 acceptance
criterion for the parent [PKIX-9vnx.9.2.1] batch.

Three new public `Lint` impls:

- `rfc5280::Rfc5280SanRequiredWhenSubjectEmptyLint` — RFC 5280 §4.2.1.6:
  certificates whose Subject is the zero-length `RDNSequence` MUST
  include a `subjectAltName` extension marked as critical. Lint is a
  no-op (`Pass`) for certs with a non-empty Subject; on empty-Subject
  certs it fires `Error` if SAN is absent or not critical.
- `rfc5280::Rfc5280SignatureAlgorithmMatchLint` — RFC 5280 §4.1.1.2:
  the outer `Certificate.signatureAlgorithm` MUST equal the inner
  `tbsCertificate.signature`. Compares both fields structurally using
  x509-cert's `AlgorithmIdentifier` `PartialEq` impl, which catches
  both OID mismatches and parameter-encoding inconsistencies (e.g.
  NULL parameters on one side, absent parameters on the other for
  RSA-PKCS1 — RFC 4055 §2.1 mandates NULL; real-world encoder bugs
  produce mismatches).
- `rfc8398::Rfc8398SmimeMailboxEquivalenceLint` — RFC 8398 §3: when
  both `rfc822Name` and `id-on-SmtpUTF8Mailbox` `OtherName` SAN
  entries are present, every entry of one kind must match some entry
  of the other under byte-equal local-parts and IDN A-label ↔ U-label
  equivalent domains. Domain conversion uses the workspace `idna`
  crate. The pure equivalence helper (`mailbox_equivalent`) is
  unit-tested exhaustively against a hand-written oracle table cross-
  checked with `python3 -c 'import idna; print(idna.encode(...))'`
  for IDN reference encodings.

Tests follow the existing module pattern: at least one positive case
against an existing `pkix-path/tests/fixtures/policy-checks/` fixture,
plus a metadata test pinning `id`, `citation`, `severity`, `scope`,
`applies_to`, `spec_section_id`, and `spec_url`. Negative cases for
all three lints require fixture generation outside the well-behaved
OpenSSL / pyca production path (empty-subject leaf, mismatched
outer/inner sigalg, disagreeing rfc822Name/SmtpUTF8Mailbox pair); per
the bead, those fixtures are explicitly out of scope here and the
positive-only test coverage is the shippable bar.

19 new tests in total (3 lint positive-path cases per RFC module + 3
metadata tests + 9 `mailbox_equivalent` helper tests = 19, contributing
to the lint test count rising from 222 to 241).

One new dependency: `idna` (workspace pin, `default-features = false`,
`features = ["alloc", "compiled_data"]`) added to `pkix-lint`. The
workspace already depended on it transitively via `pkix-identity`.

`pkix-lint` minor-bumped to 0.9.0 (additive: new public types and a
new dependency). No breaking changes; existing 0.8 callers compile
unchanged.

[PKIX-9vnx.9.2.1]: https://github.com/MarkAtwood/crate-pkix  "RFC-conformance shape-check lints batch"
[PKIX-9vnx.9.2.1.1]: https://github.com/MarkAtwood/crate-pkix  "Three deferred RFC-conformance lints"

### `pkix-lint` 0.8.0: `Severity::Notice` variant (2026-05-12)

`pkix-lint::Severity` gains a `Notice` variant slotted between `Info`
and `Warn`. The resulting ordering
`Info < Notice < Warn < Error < Fatal` aligns with both the zlint
catalog ranking (`pass(3) < notice(4) < warn(5) < error(6) <
fatal(7)`) and syslog RFC 5424 §6.2.1 severity ranking
(Informational > Notice > Warning).

The variant is added in support of the planned `pkix-zlint-bridge`
adapter (filed as [PKIX-jy95.7]): zlint catalog `notice`-level checks
need a workspace severity that is distinct from both `Info`
(advisory / best-practice) and `Warn` (SHOULD/RECOMMENDED violation).
Lint-metadata severity comes from the zlint catalog ranking, NOT from
the per-cert verdict level — see the
[PKIX-jy95.2 decision][PKIX-jy95.2].

Additive change. `Severity` is `#[non_exhaustive]`, so adding a
variant is non-breaking for callers that already include a wildcard
arm on external matches. In-tree exhaustive matches in
`pkix-lint::oscal::emit::severity_label` and
`pkix-lint::oscal::parse::parse_action` gain a `Notice` arm
(`"notice"` label, symmetric with the existing
`info`/`warn`/`error`/`fatal` labels).

A new `severity_ordering_is_info_notice_warn_error_fatal` unit test
pins the documented ordering contract so a future variant insertion
cannot silently reorder existing variants.

Out of scope (deferred to [PKIX-jy95.7]): mapping zlint per-cert
verdict levels (`notice`, `warn`, `error`, `fatal`) into
`LintResult` — those continue to map to
`LintResult::error(detail)` regardless of the lint's declared
severity, per the [PKIX-jy95.2 decision][PKIX-jy95.2].

[PKIX-jy95.7]: https://github.com/MarkAtwood/crate-pkix  "Create pkix-zlint-bridge crate"
[PKIX-jy95.2]: https://github.com/MarkAtwood/crate-pkix  "Severity-mapping decision for zlint verdicts"

### `pkix-lint`: RFC-conformance shape-check lints (2026-05-12)

`pkix-lint` gains five new RFC-conformance `Lint` impls covering the
shape-check requirements for `BasicTlsProfile` and `BasicSmimeProfile`
in `pkix-profiles`. These replace what would otherwise be near-empty
`LintProfile::lints()` methods on those profiles, making
`check_basic_tls_shape` / `check_basic_smime_shape` (filed under
[PKIX-9vnx.9.2]) substantive shape-checks once their convenience aliases
land.

Five new lints across four RFC source modules:

- `rfc5280::Rfc5280BasicConstraintsCaLeafLint` — RFC 5280 §4.2.1.9:
  end-entity certs MUST NOT assert `BasicConstraints.cA=TRUE`. Complement
  of `pkix_lint_cabf::cabf_tls_br::BcCaFlagLint` (which requires cA=TRUE
  on intermediates).
- `rfc5280::Rfc5280EkuServerAuthLint` — RFC 5280 §4.2.1.12: TLS server
  end-entity certs MUST assert `id-kp-serverAuth` in `ExtendedKeyUsage`.
  RFC-conformance variant of
  `pkix_lint_cabf::cabf_tls_br::EkuServerAuthLint`.
- `rfc6125::Rfc6125TlsServerSanLint` — RFC 6125 §6.4.1: TLS server certs
  MUST carry a `subjectAltName` containing at least one `dNSName` or
  `iPAddress` entry. Tightens the CABF "SAN required" lint with the
  RFC 6125 type requirement.
- `rfc8398::Rfc8398SmimeSanLint` — RFC 8398 §3 + RFC 5280 §4.2.1.6:
  S/MIME certs MUST carry a `subjectAltName` containing at least one
  `rfc822Name` or `otherName` of type `id-on-SmtpUTF8Mailbox`.
- `rfc8551::Rfc8551EkuEmailProtectionLint` — RFC 5280 §4.2.1.12 + RFC
  8551 §3.3: S/MIME certs MUST assert `id-kp-emailProtection` in
  `ExtendedKeyUsage`.

Two new public modules expose these lints alongside the existing
`rfc5280` module: `rfc6125`, `rfc8398`, `rfc8551`. Module structure
mirrors the workspace convention of one module per standards-body source
(established by `rfc5280`).

Tests use independent oracles: `openssl x509 -text` readings of the
existing fixtures under `pkix-path/tests/fixtures/policy-checks/`. Each
new lint has at least one positive test plus one negative per failure
mode, plus a metadata test pinning `id`, `citation`, `severity`,
`scope`, `applies_to`, `spec_section_id`, and `spec_url`. 13 new tests
total (in addition to the existing 91 lib tests; 104 total).

`pkix-lint` minor-bumped to 0.7.0 (additive: new public modules and
lint impls). No breaking changes; existing 0.6 callers compile
unchanged.

Three further RFC-conformance lints from the original
[PKIX-9vnx.9.2.1] candidate list are deferred to follow-on beads:

- RFC 5280 §4.2.1.6 SAN-when-subject-empty (needs RDN-emptiness logic).
- RFC 5280 §4.1 signatureAlgorithm match between outer `Certificate`
  and `tbsCertificate.signature` (needs `AlgorithmIdentifier` equality).
- RFC 8398 §3 rfc822Name / SmtpUTF8Mailbox pair-equivalence (needs
  cross-SAN-entry semantic comparison).

[PKIX-9vnx.9.2]: https://github.com/MarkAtwood/crate-pkix
[PKIX-9vnx.9.2.1]: https://github.com/MarkAtwood/crate-pkix

### `pkix-chain` + `pkix-profiles`: use-case verify wrappers (2026-05-12)

Five of seven canonical use-case wrappers from PKIX-fmtv.7's
five-axis resolution ship in `pkix-chain`, with matching RFC-baseline
profiles in `pkix-profiles`. Implementation beads:
[PKIX-fmtv.11.2] (TLS server), [PKIX-fmtv.12.2] (S/MIME signer +
recipient), [PKIX-fmtv.13.1] (code signer), [PKIX-fmtv.13.2] (time
stamper).

`pkix-chain` additions:

- `verify_tls_server` — composes `verify_chain` with RFC 6125 SAN
  hostname binding. Caller pre-parses with `ServerName::dns_name` /
  `ServerName::ip_address`.
- `verify_smime_signer` and `verify_smime_recipient` — compose
  `verify_chain` with RFC 5280 §4.2.1.6 / RFC 8398 mailbox binding.
  Caller pre-parses with `MailboxName::parse`. Distinct names
  communicate intent at the call site; the KeyUsage distinction
  (digitalSignature vs keyEncipherment) is encoded in the
  caller-supplied `Profile`.
- `verify_code_signer` — thin composition of `verify_chain` under a
  profile requiring `id-kp-codeSigning`. No identity binding.
- `verify_time_stamper` — composes `verify_chain` with a
  post-validation check enforcing the RFC 3161 §2.3 critical-and-sole
  `id-kp-timeStamping` EKU rule.
- `Error::Identity(IdentityError)` — additive non-exhaustive variant
  for identity-binding failures.
- `Error::ProfileViolation { reason: &'static str }` — additive
  non-exhaustive variant for wrapper-side spec invariants that
  `ValidationPolicy` cannot express (used by `verify_time_stamper`
  for the RFC 3161 §2.3 rule; reusable by future wrappers).
- Re-exports `ServerName`, `MailboxName`, `IdentityError`, and
  `Profile` so callers don't need direct deps on the underlying
  crates.

`pkix-profiles` additions:

- `BasicCodeSigningProfile` + `basic_code_signing_policy` — RFC 5280
  EKU baseline (id-kp-codeSigning only, no SAN requirement).
- `BasicTimeStampingProfile` + `basic_time_stamping_policy` — RFC 3161
  §2.3 EKU baseline (id-kp-timeStamping). The critical-and-sole rule
  is enforced at the wrapper layer rather than in the profile.

Two wrappers from the seven-set are deferred pending human design
clarification: `verify_tls_client` ([PKIX-fmtv.11.2.1]) and
`verify_ocsp_responder` ([PKIX-fmtv.13.3]). Both filed as
`human`-labeled beads with concrete option enumerations.

**Update 2026-05-12:** [PKIX-fmtv.11.2.1] resolved; the client half
ships as **two** wrappers — `verify_tls_client_dns(Option<&ServerName>)`
and `verify_tls_client_mailbox(Option<&MailboxName>)` — preserving
type discipline at the call site. Both accept `None` to skip identity
binding (path-only mode). `verify_ocsp_responder` remains deferred.

[PKIX-fmtv.11.2]: https://github.com/MarkAtwood/crate-pkix
[PKIX-fmtv.12.2]: https://github.com/MarkAtwood/crate-pkix
[PKIX-fmtv.13.1]: https://github.com/MarkAtwood/crate-pkix
[PKIX-fmtv.13.2]: https://github.com/MarkAtwood/crate-pkix
[PKIX-fmtv.11.2.1]: https://github.com/MarkAtwood/crate-pkix
[PKIX-fmtv.13.3]: https://github.com/MarkAtwood/crate-pkix

### `pkix-lint 0.6.0`: `Lint::rfc_section_id` / `rfc_url` renamed to `spec_section_id` / `spec_url` (2026-05-12)

Additive rename of two `Lint` trait default methods to reflect that the
slot was never RFC-specific — it accepts CA/B Forum BR, ITU-T X.509,
NIST SP, and other standards-body section identifiers. Filed under
[PKIX-ncab.11] as part of the post-OSCAL-demotion framing cleanup
([PKIX-ncab]).

- `Lint::spec_section_id() -> Option<&str>` is the new canonical name.
- `Lint::spec_url() -> Option<&str>` is the new canonical name.
- `Lint::rfc_section_id()` and `Lint::rfc_url()` remain as
  `#[deprecated(since = "0.6.0")]` default methods that return `None`.
  Override and call the new names; the deprecated aliases are
  independent default impls, so calling them on a lint that overrides
  only the new name returns `None`.
- Doc comments on `title`, `description`, `spec_section_id`, `spec_url`,
  `parameters`, and `set_parameter` were softened to reflect that
  OSCAL emit is one consumer of this metadata rather than its sole
  purpose (post-OSCAL-demotion framing, [`AGENTS.md`][AGENTS]
  non-negotiable #5).
- In-tree consumers updated: `pkix-lint/src/rfc5280.rs` (RFC 5280
  serial-length lint), `pkix-lint/src/oscal/catalog.rs` (Catalog
  emitter and test fixture), `pkix-lint/src/oscal/profile.rs` (test
  fixture), `pkix-lint-cabf/src/cabf_tls_br.rs` (six lint impls), and
  `pkix-lint-cabf/tests/cabf_tls_br_tests.rs` (metadata test
  assertions).
- The deprecated aliases will be removed in a future minor release
  (no earlier than `pkix-lint 0.7.0`).

[PKIX-ncab]: https://github.com/MarkAtwood/crate-pkix  "OSCAL demotion cleanup"
[PKIX-ncab.11]: https://github.com/MarkAtwood/crate-pkix  "Apply .6 decision to Lint trait OSCAL-Control metadata methods"

### pkix-identity — RFC 6125 §6.4 + RFC 5280/8398 identity binding (2026-05-11)

PKIX-fmtv.11.1 and PKIX-fmtv.12.1 fill in the pkix-identity scaffold
with the RFC 6125 §6.4 hostname-binding and RFC 5280 §4.2.1.6 + RFC
8398 mailbox-binding implementations:

- `ServerName::dns_name` — LDH + length validation, ASCII lower-casing,
  IDN U-label → A-label conversion via the `idna` crate.
- `ServerName::ip_address` — IPv4 dotted-quad and IPv6 (with or
  without brackets) → canonical 4- or 16-byte form.
- `verify_dns_name` — walks the leaf's Subject Alternative Name
  extension, matches `GeneralName::DnsName` and `GeneralName::IpAddress`
  entries with case-insensitive exact comparison plus single
  leftmost-label wildcards. CN fallback is intentionally not performed
  (RFC 6125 §6.4.4 deprecates it).
- `MailboxName::parse` — RFC 5322 dot-atom local-part validation,
  non-ASCII local-parts pass through verbatim (RFC 6532), domain
  normalized to lower-case A-label form via the `idna` crate.
- `verify_mailbox` — walks `Rfc822Name` SAN entries for ASCII targets
  and `OtherName(id-on-SmtpUTF8Mailbox)` SAN entries (OID
  1.3.6.1.5.5.7.8.9, RFC 8398 §3) for internationalized targets.
  Decodes the inner `UTF8String` of each `OtherName.value`. Local-part
  match is byte-equal; domain match is ASCII case-insensitive against
  the A-label form so U-label SAN and A-label target (and vice versa)
  interoperate.
- New error variant `IdentityError::MalformedSan` for SAN extensions
  that fail to parse.

Workspace gained an `idna` dependency entry (1.x, no_std + `alloc` +
`compiled_data`); only pkix-identity consumes it. `pkix-identity`'s own
deps gained `idna` and `der` (the `0.1.0` scaffold had only
`x509-cert`).

The `pkix-chain` `verify_tls_server` / `verify_tls_client` /
`verify_smime_signer` / `verify_smime_recipient` wrappers are split
out as PKIX-fmtv.11.2 and PKIX-fmtv.12.2, still blocked on the
PKIX-fmtv.7 wrapper-set decision.

### pkix-identity 0.1.0 — initial scaffold (2026-05-11)

New workspace crate (PKIX-fmtv.21) for cert-side identity matching:
RFC 6125 hostname binding, RFC 5280 §4.2.1.6 + RFC 8398 mailbox
binding, IP literal matching. Pure function over (cert,
identity-string); no chain context, no trust anchors. `no_std`. The
`0.1.0` release ships the public API surface (`ServerName`,
`MailboxName`, `IdentityError`, `verify_dns_name`, `verify_mailbox`)
with stub bodies that return `IdentityError::NotYetImplemented`.
Bodies fill in via PKIX-fmtv.11 (`verify_dns_name` + IDN
normalization) and PKIX-fmtv.12 (`verify_mailbox` + SmtpUTF8Mailbox
handling). The split-out crate is precedented by
`rustls-pki-types::ServerName` + `webpki::SubjectNameRef`; identity
matching is a stateless data transform that does not fit the
`Profile` trait. See [`pkix-identity/README.md`][pi-readme] for
in-scope / out-of-scope discipline. [PKIX-fmtv.21]

[pi-readme]: pkix-identity/README.md

### Workspace: framework / policy split (2026-05-11)

The workspace stance encoded in [`AGENTS.md`][AGENTS] non-negotiable #6
(PKIX-amgn) splits standards-body mechanisms from industry-forum policy
content across crate boundaries. Core crates ship the framework + RFC
baselines; CA/B Forum content lives in sibling `-cabf` reference crates
marked "not authoritative."

Crate boundary changes that landed across the PKIX-amgn umbrella:

```
pkix-profiles  →  pkix-profiles-cabf  (WebPkiProfile, SmimeProfile,
                                       CodeSigningProfile, sc081_validity_cap,
                                       CABF_*_ALLOWED_ALGS)             [PKIX-amgn.4]
pkix-lint      →  pkix-lint-cabf      (cabf_tls_br module: ValidityMaxLint,
                                       Sha1ProhibitedLint, RsaMinKeySizeLint,
                                       SanRequiredLint, EkuServerAuthLint,
                                       BcCaFlagLint, CabfTlsBrProfile,
                                       all_lints)                       [PKIX-amgn.5]
```

The `-cabf` crates carry a "reference, not authoritative" rustdoc header
and are explicitly not maintained as canonical CA/B Forum encodings. They
are intended as a starting point: fork and adapt to your deployment's
current interpretation of the BR text.

Migration for downstream consumers:

```toml
# Cargo.toml — add a dep on the relevant -cabf crate
pkix-profiles      = "0.3"
pkix-profiles-cabf = "0.2"  # CA/B Forum Profile types
pkix-lint          = "0.5"
pkix-lint-cabf     = "0.2"  # CA/B Forum lint bundles
```

```rust
// Profile types
- use pkix_profiles::{WebPkiProfile, SmimeProfile, CodeSigningProfile};
+ use pkix_profiles_cabf::{WebPkiProfile, SmimeProfile, CodeSigningProfile};

// SC-081 helper
- use pkix_profiles::sc081_validity_cap;
+ use pkix_profiles_cabf::sc081_validity_cap;

// CA/B Forum lint bundle
- use pkix_lint::cabf_tls_br::CabfTlsBrProfile;
+ use pkix_lint_cabf::cabf_tls_br::CabfTlsBrProfile;
```

Retained in `pkix-profiles` 0.3.0:

- `Profile` trait + `ValidationPolicy` re-exports.
- `BasicTlsProfile` — RFC 5280 + RFC 6125 + universally-required
  `id-kp-serverAuth` EKU.
- `BasicSmimeProfile` — RFC 8551 §3 baseline (`id-kp-emailProtection`
  EKU + `rfc822Name` SAN).
- Deprecated re-exports of the CA/B Forum types from
  `pkix-profiles-cabf` (drop in 0.4.0).

Retained in `pkix-lint` 0.5.0:

- Framework: `Lint`, `LintRunner`, `LintProfile`, `Finding`,
  `EvaluationReport`, `Deviation`, `DeviationStore`, `DeviationRunner`.
- OSCAL Catalog + Profile machinery (`oscal::catalog::catalog_from_lints`,
  `oscal::parse::lint_ids_from_catalog`, `oscal::profile::resolve_profile`,
  `oscal::emit::assessment_results`).
- RFC-conformance lint bundle (`rfc5280::Rfc5280MaxSerialLengthLint`).

See [PKIX-amgn] for the full rationale and the framework/policy stance
encoded in [`AGENTS.md`][AGENTS] non-negotiable #6.

[AGENTS]: ./AGENTS.md
[PKIX-amgn]: ./AGENTS.md

### `pkix-lint 0.5.0` + `pkix-lint-cabf 0.2.0`: CA/B Forum bundle migration (2026-05-11)

**BREAKING.** PKIX-amgn.5 — refactor `pkix-lint` to ship only the framework
plus standards-body (RFC) conformance lints; the CA/B Forum TLS BR lint
bundle (`cabf_tls_br`) moves to the sibling `pkix-lint-cabf` reference
crate per the workspace framework-not-policy stance (`AGENTS.md`
non-negotiable #6, PKIX-amgn).

Moved out of `pkix-lint` 0.4.0 → into `pkix-lint-cabf` 0.2.0:

- `cabf_tls_br` module
  - Types: `ValidityMaxLint`, `Sha1ProhibitedLint`, `RsaMinKeySizeLint`,
    `SanRequiredLint`, `EkuServerAuthLint`, `BcCaFlagLint`,
    `CabfTlsBrProfile`.
  - Free function: `all_lints() -> Vec<Box<dyn Lint>>`.
- Integration tests (`tests/cabf_tls_br_tests.rs`).

Stays in `pkix-lint` 0.5.0:

- Framework: `Lint`, `LintRunner`, `LintProfile`, `LintResult`, `Finding`,
  `Scope`, `Severity`, `SubjectKind`, `LintParameter`, `ParameterError`.
- `report::EvaluationReport`, `deviation::DeviationStore`,
  `deviation::DeviationRunner`, `deviation::Deviation`.
- OSCAL Catalog + Profile machinery (`oscal::catalog::catalog_from_lints`,
  `oscal::parse::lint_ids_from_catalog`, `oscal::profile::resolve_profile`,
  `oscal::emit::*`).
- RFC-conformance lints (`rfc5280::Rfc5280MaxSerialLengthLint`).

Migration:

```rust
// before (pkix-lint 0.4.0):
use pkix_lint::cabf_tls_br::CabfTlsBrProfile;

// after (pkix-lint 0.5.0 + pkix-lint-cabf 0.2.0):
use pkix_lint_cabf::cabf_tls_br::CabfTlsBrProfile;
```

Downstream consumers must add `pkix-lint-cabf` to their `Cargo.toml` to
continue using the CA/B Forum TLS BR lint bundle. `pkix-lint` no longer
depends on `pkix-profiles-cabf`; that dep moves to `pkix-lint-cabf`.

OSCAL catalog/profile tests inside `pkix-lint` previously used
`cabf_tls_br::ValidityMaxLint` and `cabf_tls_br::all_lints()` as
fixtures. Those tests now use a self-contained `PolicyShapedLint` test
fixture (rfc_section_id set, rfc_url left None — same metadata shape)
and an in-crate `multi_lint_fixture()` so `pkix-lint`'s tests stay
independent of CA/B Forum policy content. Cross-crate round-trip
coverage against the real CA/B Forum lint set continues in
`pkix-lint-cabf`'s integration tests.

`pkix-lint-cabf` 0.2.0 carries the same "reference / not authoritative"
crate-level rustdoc disclaimer as the existing 0.1.0 stub. Future bundles
(`cabf_smime_br`, `cabf_cs_br`) and zlint-derived OSCAL Catalogs will
land via PKIX-amgn.8 and friends.

### `pkix-path-builder 0.3.1`: `build_first_valid_path<V>` helper (2026-05-11)

**Additive.** PKIX-lwr9.4.2 — closes the consumer ergonomics gap surfaced
by PKIX-lwr9.4 / BetterTLS tc60: [`build_path`] is single-shot and has no
[`SignatureVerifier`] dependency, so it cannot know which of its DFS
candidates will be rejected downstream by [`pkix_path::validate_path`]
(e.g., cross-signed pools containing an intermediate signed under an
algorithm the verifier does not dispatch).

New functions in `pkix_path_builder`:

```rust
pub fn build_first_valid_path<V>(
    target: &Certificate,
    pool: &CertPool,
    anchors: &[pkix_path::TrustAnchor],
    policy: &pkix_path::ValidationPolicy,
    verifier: &V,
) -> Result<Vec<Certificate>>
where
    V: pkix_path::SignatureVerifier;

pub fn build_first_valid_path_with_config<V>(
    target: &Certificate,
    pool: &CertPool,
    anchors: &[pkix_path::TrustAnchor],
    policy: &pkix_path::ValidationPolicy,
    verifier: &V,
    config: &PathBuilderConfig,
) -> Result<Vec<Certificate>>
where
    V: pkix_path::SignatureVerifier;
```

Semantics: iterate [`build_path_candidates`] until the first candidate
chain passes [`pkix_path::validate_path`]. Return that chain. If every
candidate is rejected, surface the new `Error::NoValidPath { tried,
last_error }` variant. Zero-yield exhaustion still surfaces as
`Error::NoPathFound` (matches `build_path`'s contract).

New error variant on the `#[non_exhaustive]` `Error` enum:

```rust
NoValidPath {
    tried: usize,
    last_error: String,
},
```

The inner `pkix_path::Error` is rendered to `String` rather than carried
verbatim so the builder's `Error` enum retains its `Hash` derive
(`pkix_path::Error` is not `Hash`). Consumers needing programmatic match
on inner errors should drop to `build_path_candidates` and call
`validate_path` per candidate themselves.

Rustdoc updates: `build_path`, `PathCandidates`, and the new helpers
cross-reference each other under a three-way "Choosing between ..."
heading. Existing signatures unchanged.

Three new integration tests in `tests/build_first_valid_path.rs`:

- Positive: BetterTLS tc60 fixture (cross-signed depth-6 pool, one
  intermediate uses ecdsa-with-SHA1 which `DefaultVerifier` does not
  dispatch). `build_path` returns a chain that `validate_path` rejects
  with `SignatureInvalid { index: 3 }`; `build_first_valid_path` iterates
  past that candidate and returns a SHA-256-only chain that validates.
- `NoValidPath`: PKITS §4.1.1 chain paired with an `AlwaysRejectVerifier`
  that rejects every signature. Confirms `tried >= 1` and `last_error`
  populated.
- `NoPathFound` passthrough: empty pool. Confirms zero-yield exhaustion
  surfaces as `NoPathFound`, not `NoValidPath { tried: 0 }`.

New dev-dependencies (workspace-pinned): `spki`, `signature`. Required to
spell out the `SignatureVerifier` trait's argument types in the
`AlwaysRejectVerifier` impl in the new test.

### `pkix-lint 0.4.0`: OSCAL Catalog round-trip + id-pair runner (2026-05-11)

**Additive.** PKIX-9vnx.6.3 — closes the OSCAL Catalog round-trip loop.

New function in `pkix_lint::oscal::parse`:

```rust
pub fn lint_ids_from_catalog(value: &Value) -> Result<Vec<String>, ParseError>
```

Walks an OSCAL Catalog JSON Value and returns the ordered list of
Control ids. Parser is intentionally narrow — it accepts the shape
emitted by `catalog_from_lints`, not arbitrary OSCAL Catalogs nested
inside `groups[]` or keyed off `class`.

New method on `LintRunner` (feature-gated behind `oscal`):

```rust
pub fn filter_to_ids(self, ids: &[String])
    -> Result<LintRunner, oscal::parse::ParseError>
```

Returns a new `LintRunner` containing only the lints whose `id()`
appears in `ids`, in the order `ids` requests them. Unknown ids
(`UnknownLintId`) error. Duplicates in `ids` are silently deduplicated
(OSCAL Catalogs forbid duplicate Control ids). `bundle_version` is
preserved.

`ParseError` grew six Catalog-side variants (`CatalogNotObject`,
`CatalogMissingWrapper`, `ControlsNotArray`, `ControlNotObject`,
`ControlMissingId`, `ControlIdNotString`, `ControlIdEmpty`) plus
`UnknownLintId` for the filter step. `non_exhaustive` made these
additions non-breaking.

Ten new tests in `oscal::catalog::tests`: id extraction order, full
emit → serialise → parse → filter → run round-trip on the six CABF
lints with a fixture chain asserting identical Findings (independent
oracle: the pkix-lint engine itself is shared substrate, the test
verifies the lint-set survives round-trip), unknown-id error path,
id-order preservation, subset drop, bundle-version preservation, and
four malformed-input rejection paths (non-object root, missing
wrapper, non-array controls, control missing id).

Test counts: oscal 211 (was 201), all-features 217 (was 207).

### `pkix-lint 0.4.0`: OSCAL Catalog JSON emitter for registered lints (2026-05-11)

**Additive.** PKIX-9vnx.6.2 — new module
`pkix_lint::oscal::catalog::catalog_from_lints` projects a slice of
`Box<dyn Lint>` onto an OSCAL Catalog v1.1.2 JSON Value.

```rust
pub fn catalog_from_lints(
    lints: &[Box<dyn crate::Lint>],
    catalog_id: &str,
    catalog_version: &str,
) -> serde_json::Value
```

Each `Lint` impl maps to one OSCAL Control: `id` from `Lint::id`,
`title` from `Lint::title`, citation / severity / scope / applies-to /
section-id / lint-id / control-uuid as `pkix-lint.*` props,
`Lint::rfc_url` as a `rel="reference"` link,
`Lint::description` (when `Some`) as a `parts[statement]` prose block,
and `Lint::parameters` as OSCAL `params[]` with the parameter id
namespaced as `<lint_id>.<param_id>` to avoid collisions across lints.

UUIDs are derived deterministically from `(catalog_id, catalog_version,
lint_id, param_id)` via the existing `uuid_v8` helper (SHA-256-seeded
RFC 9562 §5.8 UUIDv8); `metadata.last-modified` is pinned to
`1970-01-01T00:00:00Z` for byte-deterministic output. Callers needing
a wall-clock timestamp post-edit the returned Value.

Parameters land in this bead rather than waiting for PKIX-9vnx.6.5 —
the Catalog Control is the natural place to *declare* parameters with
defaults; `.6.5` covers the Profile-side `modify` directive that
*overrides* them at composition time, which is a distinct concern.

`emit::prop`, `emit::uuid_v8`, `emit::severity_label`, and two new
helpers (`scope_label`, `subject_kind_label`) became `pub(super)` so
the catalog submodule can share them without duplication.

Eight new tests under `oscal::catalog::tests` cover structural
required-field presence, the rfc5280 → Control mapping, the CABF
no-rfc-url omission case, byte determinism, UUID derivation
independent-oracle recomputation, version-change UUID invalidation,
empty input, and parameter id namespacing. Test counts:
`pkix-lint --features oscal` 201 (was 193), `--all-features` 207 (was 199).

### `pkix-lint 0.4.0`: `LintParameter` + first RFC-conformance lint (2026-05-11)

**Additive.** PKIX-9vnx.6.4 — Lint parameter mechanism and the first
RFC-conformance lint demonstrate it end-to-end.

New public types in `pkix-lint`:

```rust
pub struct LintParameter {
    pub id: Cow<'static, str>,
    pub label: Cow<'static, str>,
    pub default_value: Cow<'static, str>,
}

pub enum ParameterError {
    UnknownParameter(String),
    InvalidValue { id: String, reason: String },
}
```

New default-provided trait methods on `Lint`:

```rust
fn parameters(&self) -> &[LintParameter] { &[] }
fn set_parameter(&mut self, id: &str, value: &str)
    -> Result<(), ParameterError> { ... default rejects all ids ... }
```

`LintParameter` is descriptor-only — it maps onto an OSCAL Catalog
`Parameter` (id, label, default value) and does not hold the lint's
current value. Lints store typed state directly (`usize`, `Duration`,
etc.); `set_parameter` parses the string-rendered override into that
state. `&mut self` is required because parameter updates change
behaviour; callers configure parameters before installing the lint
into a `LintRunner` (the runner exposes no mutation).

New module `pkix_lint::rfc5280` with the first RFC-conformance lint:

* **`Rfc5280MaxSerialLengthLint`** — RFC 5280 §4.1.2.2: certificate
  serialNumber must not exceed 20 octets. Parametric on `max-octets`
  (default 20). First built-in lint in `pkix-lint` proper; all other
  shipped lints are still CA/B Forum-shaped in `cabf_tls_br` (they
  migrate to `pkix-lint-cabf` via PKIX-amgn.5).

Nine new tests cover the lint's behaviour, parameter machinery,
boundary conditions, and metadata, with `openssl x509 -serial` as the
independent oracle for fixture serial-length values. Test counts:
pkix-lint default 130 (was 121), `--features oscal` 193 (was 184),
`--all-features` 199 (was 190).

### `pkix-lint 0.4.0`: `Lint` trait grows OSCAL-Control metadata methods (2026-05-11)

**Additive.** Four new default-provided methods on the `Lint` trait
(PKIX-9vnx.6.1 — first step toward emitting each `Lint` impl as an OSCAL
Catalog `Control`):

```rust
fn title(&self) -> &str { self.id() }
fn description(&self) -> Option<&str> { None }
fn rfc_section_id(&self) -> Option<&str> { None }
fn rfc_url(&self) -> Option<&str> { None }
```

`title` defaults to `id()`; the other three default to `None`. All
existing `Lint` impls keep compiling unchanged. The six CABF TLS BR
lints in `cabf_tls_br.rs` override `title` and `rfc_section_id` with
human-readable titles and OSCAL Control-id-shaped strings
(`cabf-tls-br-<section>`). `rfc_url` stays `None` for CABF lints
because the CA/B Forum publishes BR documents as versioned PDFs without
stable per-section anchors.

`rfc_section_id` accepts any standards-body section identifier in
`<source>-<section>` shape — IETF RFC (`rfc5280-4.2.1.9`), CA/B Forum
(`cabf-tls-br-6.3.2`), ITU-T X.509, NIST SP, etc. The method name is
kept as-spec'd by PKIX-9vnx.6's design discussion; the rustdoc
documents the generic semantics.

Seven new tests in `tests/cabf_tls_br_tests.rs` pin the metadata for
each CABF lint plus the default behavior of an override-less `Lint`
impl.

### `pkix-lint 0.4.0`: `DeviationScope` refactor to open-ended kind + props bag (2026-05-11)

**BREAKING.** Replaces `pub enum DeviationScope { Any, IssuerDnContains(String),
IssuerDnExact(Name), SerialRange { ... } }` with a struct:

```rust
pub struct DeviationScope {
    pub kind: String,                            // e.g. "pkix-lint.scope.issuer-dn-exact"
    pub props: Vec<(String, ScopePropValue)>,
}

#[non_exhaustive]
pub enum ScopePropValue {
    Text(String),
    Bytes(Vec<u8>),
}
```

The shape mirrors OSCAL Subject (kind discriminator + typed props bag) per
the workspace OSCAL alignment stance (PKIX-9vnx / PKIX-ztmr). Future scope
axes (PKIX-8mzp's planned `SubjectDnContains`, `PolicyOid`, etc.) are now
expressible via new `kind` strings + props without growing the public Rust
enum surface.

**Migration** — replace direct enum-variant construction with the new
constructors:

```rust
// Before (pkix-lint 0.3.x):
let s = DeviationScope::Any;
let s = DeviationScope::IssuerDnContains("agency x".to_string());
let s = DeviationScope::IssuerDnExact(cert.tbs_certificate.subject.clone());
let s = DeviationScope::SerialRange {
    issuer: cert.tbs_certificate.subject.clone(),
    start: vec![0x01], end: vec![0x02],
};

// After (pkix-lint 0.4.x):
let s = DeviationScope::any();
let s = DeviationScope::issuer_dn_contains("agency x");
let s = DeviationScope::issuer_dn_exact(&cert.tbs_certificate.subject)?;
let s = DeviationScope::serial_range(&cert.tbs_certificate.subject, vec![0x01], vec![0x02])?;
```

Public constants are exported for the four canonical kind discriminators
and the four canonical prop names: `SCOPE_KIND_ANY`,
`SCOPE_KIND_ISSUER_DN_CONTAINS`, `SCOPE_KIND_ISSUER_DN_EXACT`,
`SCOPE_KIND_SERIAL_RANGE`; `PROP_ISSUER_DN_SUBSTRING`,
`PROP_ISSUER_DN_DER`, `PROP_SERIAL_START`, `PROP_SERIAL_END`.

**Round-trip preservation.** The OSCAL emit and parse layers are unchanged
at the JSON-wire level — the same subject `type` discriminators and prop
names. Stores that round-trip through OSCAL JSON before and after this
release produce bit-identical output.

**Fail-closed semantics.** `DeviationScope::matches` returns `false` for
unknown kinds, for missing props, for wrong-typed props (e.g. `Text` where
`Bytes` is expected), and for malformed DER under the
`pkix-lint.issuer-dn-der` prop. Code-built scopes go through constructors
and cannot hit these paths; only hand-built scopes (or hand-edited OSCAL
JSON that bypasses the parser) can. The OSCAL parser rejects malformed
input before constructing a `DeviationScope`.

Tracked as PKIX-9vnx.11.

### `pkix-path`: integration tests gated on algorithm features (2026-05-11)

Test-only. `cargo test -p pkix-path --no-default-features` previously
failed to compile the integration test crates because they
unconditionally import `DefaultVerifier`, which is itself gated on
`any(feature = "p256", feature = "p384", feature = "rsa")`. Each of the
nine integration test files now carries the matching `#![cfg(...)]`
attribute, so `--no-default-features` compiles cleanly (yielding an
empty test suite per the integration test crate, which is the
intended behaviour when no algorithm backend is enabled). No runtime
behaviour change. Tracked as PKIX-yg2r.

### `pkix-profiles 0.3.0` + `pkix-profiles-cabf 0.2.0`: framework-not-policy split (2026-05-11)

**BREAKING for `pkix-profiles 0.3.0`. Substantive content release for `pkix-profiles-cabf 0.2.0`.**

CA/Browser Forum-specific profile content moved from `pkix-profiles` to
the sibling `pkix-profiles-cabf` crate per the framework-not-policy
workspace stance (PKIX-amgn):

- `WebPkiProfile`, `SmimeProfile`, `CodeSigningProfile` and their
  `web_pki_policy`/`smime_policy`/`code_signing_policy` aliases.
- `sc081_validity_cap()` (CA/B Forum SC-081 phased validity).
- `CABF_TLS_BR_ALLOWED_ALGS`, `CABF_SMIME_BR_ALLOWED_ALGS`,
  `CABF_CS_BR_ALLOWED_ALGS` (the latter three are now `pub` in
  `pkix-profiles-cabf`; in `pkix-profiles 0.2.x` they were
  crate-private).

`pkix-profiles 0.3.0` keeps RFC-baseline content:

- `Rfc5280Profile` / `rfc5280_policy` (unchanged from 0.2.x).
- New `BasicTlsProfile` / `basic_tls_policy` — RFC 5280 + RFC 6125 +
  `id-kp-serverAuth` EKU. No CA/B Forum overlay.
- New `BasicSmimeProfile` / `basic_smime_policy` — RFC 8551 §3 baseline:
  `id-kp-emailProtection` EKU + `rfc822Name` SAN. No CA/B Forum overlay.

`pkix-profiles 0.3.x` carries deprecated `pub use` re-exports of the
moved symbols (`WebPkiProfile`, `SmimeProfile`, `CodeSigningProfile`,
`web_pki_policy`, `smime_policy`, `code_signing_policy`,
`sc081_validity_cap`) so existing `use pkix_profiles::WebPkiProfile;`
imports continue to compile with a deprecation warning. The re-exports
drop in `pkix-profiles 0.4.0`. Migration:

```rust
// Before (pkix-profiles 0.2.x):
use pkix_profiles::{WebPkiProfile, web_pki_policy, sc081_validity_cap};

// After (pkix-profiles-cabf 0.2.x):
use pkix_profiles_cabf::{WebPkiProfile, web_pki_policy, sc081_validity_cap};
```

`pkix-lint`'s `cabf_tls_br` module migrated to the new crate as part of
this change; the `pkix-profiles` dependency was replaced with
`pkix-profiles-cabf` in `pkix-lint`'s `Cargo.toml`. (`cabf_tls_br` itself
is slated to move to `pkix-lint-cabf` via PKIX-amgn.5.)

`pkix-profiles-cabf 0.1.0` was a namespace-reservation stub with no
public types; `0.2.0` is the first substantive content release. Tracked
as PKIX-amgn.4.

### `pkix-path`: `ValidationPolicy::require_crl_sign_on_cas` opt-in flag (2026-05-11)

Additive. New `ValidationPolicy::require_crl_sign_on_cas: bool` (default
`false`). When `true`, an intermediate CA certificate whose `KeyUsage`
extension is present but does not include `cRLSign` is rejected with the
new `Error::CrlSignMissing { index }` variant. Default behaviour is
unchanged (the RFC 5280 §6.1 literal reading does not require this check).
Restores PKITS §4.7.4 / §4.7.5 conformance for callers who opt in.
`Error` is `#[non_exhaustive]`, so the new variant is additive. See
`INTEROP.md` §7 for the divergence rationale. Tracked as PKIX-0x9z.

### `pkix-revocation`: path-level CRL signer discovery (RFC 5280 §6.3.3(f)) (2026-05-11)

Additive. New public API for locating a CRL's signer in a caller-supplied
bundle without inverting the workspace's one-way dep direction
(`pkix-chain` → `pkix-revocation` → `pkix-path`):

- New free helper `pkix_revocation::discover_crl_signer(bundle, &crl) ->
  Option<&Certificate>`. AKI/SKI walk (RFC 5280 §4.2.1.1 / §4.2.1.2) with
  issuer-DN fallback. No signature verification — discovery only.
- New constructor `CrlChecker::new_with_signer_discovery(crl_der, bundle,
  cert_to_check, now, verifier)`. Runs discovery, gates the result on
  `cRLSign` in `KeyUsage` per §6.3.3(f), and performs a structural
  anchor-reachability walk (the discovered signer must reach a self-signed
  cert by repeated AKI/SKI or issuer-DN steps within the bundle).
- New `Error` variants: `CrlSignerNotFound`, `CrlSignerNotTrusted`. `Error`
  is `#[non_exhaustive]`, so this is additive.
- PKITS §4.5 integration tests (`pkix-revocation/tests/pkits_4_5.rs`)
  rewritten to use the new constructor in place of the prior manual
  AKI/SKI workaround.

The structural anchor-reachability check is intentionally lenient: it
does NOT verify signatures along the signer's chain. Full RFC 5280 §6.1
validation of the signer's path remains the responsibility of higher-layer
composers such as `pkix-chain`. Tradeoff stance tracked as PKIX-yi7k.1.
Tracked as PKIX-cqwt.

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

- `oscal` cargo feature exposing `pkix_lint::oscal::emit::assessment_results`,
  `pkix_lint::oscal::emit::risks_from_store`, and
  `pkix_lint::oscal::parse::deviation_store_from_risks`
  (PKIX-9vnx.3 + .4 + .5 + .10, Architecture 2 per PKIX-ztmr).
  - `assessment_results(&EvaluationReport) -> serde_json::Value` projects
    an evaluation run into a NIST OSCAL v1.1.2 Assessment Results
    `serde_json::Value` document — top-level `assessment-results` with
    `metadata`, `import-ap`, and one `results[]` entry containing
    evidence-deduplicated Observations and per-lint Findings.
    Observations are keyed by `(cert_sha256, cert_index)` so multiple
    Findings sharing one piece of evidence (e.g., multiple lints on the
    same cert) reference one Observation via `related-observations`,
    matching OSCAL's intended 1:N Observation:Finding cardinality.
    Path-scope findings (both keys `None`) share a single
    "path-scope" Observation. Each Finding's `target.status.state` is
    `satisfied` for Pass/NotApplicable and `not-satisfied` for
    Warn/Error/Fatal; lint-specific metadata (`lint-id`, `citation`,
    `severity`) lives on the Finding side as props. Per-run
    `DeviatedFinding`s become Risks with `status="deviation-approved"`.
  - `risks_from_store(&DeviationStore) -> Vec<serde_json::Value>`
    projects a deviation policy as a JSON array of OSCAL Risk objects.
    Each `Deviation` becomes one Risk carrying the full set of props
    needed for lossless reconstruction (id, target_lint, action,
    authorized_by, effective_start/end, evidence_uri), plus the scope
    encoded as OSCAL Subjects with type-specific props. `IssuerDnExact`
    and `SerialRange` scopes carry both a human-readable DN string and
    the DER bytes hex-encoded for lossless reconstruction.
  - `deviation_store_from_risks(&serde_json::Value) -> Result<DeviationStore, ParseError>`
    is the inverse of `risks_from_store`: it reconstructs a
    `DeviationStore` from a JSON array of OSCAL Risk objects in the
    shape this crate emits. `(emit . parse)` over any non-empty store
    yields an `Eq`-equal store, closing the round-trip loop for
    deviation-policy persistence. The parser is intentionally narrow —
    it accepts the exact shape emitted by `risks_from_store`, not
    arbitrary OSCAL Risk documents authored by other tools — which
    keeps the error surface tight and the round-trip contract
    guaranteed by construction. The DN-DER prop
    (`pkix-lint.issuer-dn-der`) is the canonical oracle for `Name`
    reconstruction; the companion RFC-4514 string prop is
    informational and ignored by the parser. `Deviation` and
    `DeviationStore` now derive `PartialEq, Eq` to support the
    round-trip assertion (additive change; pattern-matching unchanged).
  - UUIDs are deterministically derived (RFC 9562 §5.8 v8 using SHA-256)
    so identical inputs yield byte-identical OSCAL output. The feature
    gates a new optional `serde_json` dependency; default builds are
    unchanged. Internal `EvaluationReport` / `Finding` / `Deviation` /
    `DeviationStore` shapes are NOT reshaped to mirror OSCAL
    field-for-field — the emitter projects, per the Architecture 2
    stance.

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
  PKIX-baac.4 (`precert_entry` verifier), PKIX-baac.5
  (Merkle inclusion + STH signature verification, see below), and
  PKIX-baac.7 (`verify_embedded_scts`).

- `SctVerifier::verify_inclusion` verifies an RFC 6962 §2.1.1 / RFC
  9162 §2.1.3.2 Merkle audit path against a trusted root hash. Helper
  `merkle_leaf_hash` computes the §2.1 leaf hash. New types
  `MerkleAuditPath` and `SignedTreeHead`. Tracked as PKIX-baac.5.

- `SctVerifier::verify_sth` verifies the signature on a Signed Tree
  Head (RFC 6962 §3.5) against the log's public key. Tampered
  timestamps, tree sizes, or root hashes all surface as
  `Error::InvalidSignature`.

- Error variants added: `MerkleProofInvalid` (verification failed —
  reconstructed root mismatch or out-of-range index) and
  `MerkleProofMalformed` (proof shape inconsistent — empty tree,
  audit path longer than tree height permits).

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
