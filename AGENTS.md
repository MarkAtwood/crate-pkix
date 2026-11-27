# AGENTS — PKIX

Context for AI coding agents working in this repository.

## What this is

A Rust workspace for RFC 5280 X.509 certificate path validation and
adjacent PKI concerns.

**Core path-validation crates:**

- **`pkix-path`** — Pure, `no_std` RFC 5280 §6 path validator. Pluggable crypto via `SignatureVerifier` trait.
- **`pkix-revocation`** — CRL and OCSP revocation checking (offline; caller supplies CRL DER / OCSP response bytes). `RevocationChecker` trait + `NoRevocation` zero-cost default.
- **`pkix-chain`** — High-level umbrella. Re-exports `pkix-path`, `pkix-revocation`, and `pkix-aia`; provides the `Verifier<'a, V, R, A>` struct (`verify_one` / `verify_batch`) as the primary entry point for callers validating many chains against the same trust state, the free function `verify_chain()` as a thin wrapper for single-call use, plus use-case wrappers (`verify_tls_server`, `verify_tls_client_dns`, `verify_tls_client_mailbox`, `verify_smime_signer`/`_recipient`, `verify_code_signer`, `verify_time_stamper`, `verify_ocsp_responder`) that compose chain validation with `pkix-identity` SAN binding and profile-supplied EKU rules. The `A: AiaFetcher = NoAiaFetcher` 3rd generic is the third trust-domain callback alongside `SignatureVerifier` (signatures) and `RevocationChecker` (revocation); when the caller-supplied chain is incomplete and a real `AiaFetcher` is wired, `verify_one` follows `id-ad-caIssuers` URIs to reassemble the chain via `pkix-path-builder` (PKIX-zkjb.7). The use-case wrappers take an `aia: &A` argument like `verify_chain`; pass `NoAiaFetcher` to disable fetching. AIA reassembly is bounded by `AiaConfig` (per-cert URI cap, total fetch cap, deadline; set via `Verifier::with_aia_config`).
- **`pkix-path-builder`** — RFC 4158 path building from unordered cert bundles. Output feeds `pkix-path`.
- **`pkix-truststore`** — Tier-1 trust anchor loading from PEM / DER bytes or files. See the `pkix-truststore` section below.

**Adjacent / specialized crates:**

- **`pkix-revocation-http`** — Online HTTP fetching of CRLs and OCSP responses (std-only add-on to `pkix-revocation`).
- **`pkix-profiles`** — RFC-baseline profile policy pre-configurations (RFC 5280 / 6125 / 8551). Per PKIX-amgn this crate is reverting to RFC-baseline only; CA/B Forum content moves to `pkix-profiles-cabf`.
- **`pkix-lint`** — Advisory lint engine. RFC-conformance lint Catalogs ship here; CA/B Forum bundles move to `pkix-lint-cabf`.
- **`pkix-chain-simple`** — Opinionated validator with extension whitelist for high-assurance contexts.
- **`pkix-ac`** — RFC 5755 attribute certificate validation. Composed by
  `pkix_chain::verify_attribute_cert` behind the `attribute-certs` feature.
- **`pkix-ct`** — RFC 6962 / RFC 9162 Certificate Transparency / SCT verification (skeleton; tracked as PKIX-baac).
- **`pkix-composite`** — Composite (PQC + classical) signature verification (skeleton).
- **`pkix-identity`** — Cert-side identity matching (RFC 6125 hostname, RFC 5280 §4.2.1.6 + RFC 8398 mailbox, IP literal). Pure function over (cert, identity-string); no chain context, no trust anchors. Scaffold-only at 0.1.0; bodies land via PKIX-fmtv.11 / .12.
- **`pkix-dane`** — DANE (RFC 6698 + 7218 + 7671) TLSA record parsing and per-usage match logic (PKIX-TA / PKIX-EE / DANE-TA / DANE-EE). No DNS: the `TlsaResolver` trait is the seam, and callers supply a `TlsaResponse` pairing records with the `DnssecStatus` they arrived under, so the DNSSEC check cannot be skipped. Matching hashes the certificate **as the peer presented it**, never a re-encoding — `x509-cert` 0.3 normalizes pre-2050 `GeneralizedTime` to `UTCTime`, so `to_der()` output would not match a correctly-published TLSA record (see `tests/byte_exactness.rs`). Shipped at 0.2.0 with all four usages (PKIX-j32w.1); `pkix-chain` integration is PKIX-j32w.3.
- **`pkix-dane-resolver`** — DNSSEC-validating resolver that fetches TLSA records. Std-only. Default upstream uses system resolv.conf.
- **`pkix-zlint-bridge`** — Shared subprocess + NDJSON-parsing infrastructure for running zlint on certificates. Consumed by `pkix-policy-zlint` (runtime adapter) and `pkix-difftest`'s zlint oracle. Shipped at 0.0.0 with full public surface (`Verdict`, `ZlintLintInfo`, `BridgeError`, `PerCertError`, `BridgeConfig`, `ZlintBridge`) and the `enumerate_lints` / `run_on_cert` / `run_on_certs` entry points (PKIX-jy95.7.1 / .7.2 / .7.3 / .7.4 all closed).
- **`pkix-pkilint-bridge`** — Shared subprocess + output-parsing infrastructure for running pkilint on certificates. Same shape as `pkix-zlint-bridge` for pkilint. Not yet shipped; planned per PKIX-jy95.8.
- **`pkix-policy-zlint`** — Thin `pkix_lint::Lint` adapter wrapping each zlint catalog check (~400) via `pkix-zlint-bridge`. The principled path for predicate-comprehensive CA/B Forum coverage (PKIX-jy95.10). zlint stays the source of truth for the checks it covers; the workspace contributes the framework. Shipped at 0.0.0; post-1.0 0.x cadence.

**Reference / not authoritative crates** (snapshot-style implementations of industry-forum requirements; fork and adapt to your deployment's current interpretation):

- **`pkix-profiles-cabf`** — CA/Browser Forum profile types (TLS BR, S/MIME BR, Code Signing BR), hand-authored as a small curated reference set. Explicit **unprincipled exception** to non-negotiable #5's no-transcription rule. For comprehensive CA/B Forum coverage, use `pkix-policy-zlint` (sibling adapter crate).
- **`pkix-lint-cabf`** — CA/Browser Forum lint bundles, hand-authored as a small curated reference set. Same **unprincipled exception** status as `pkix-profiles-cabf`. For comprehensive coverage, use `pkix-policy-zlint`.

**Trust store adapter crates** (see the `pkix-truststore` section below):

- **`pkix-truststore-system`** — OS-native trust stores (macOS, Windows, iOS, Android). Currently a stub; substantive content lands via PKIX-8h87.
- **`pkix-truststore-pkcs11`** — PKCS#11 / HSM / smart card adapters. Currently a stub; substantive content lands via PKIX-p8vz.

**Dev tooling (not published):**

- **`pkix-difftest`** — Differential test harness across `pkix-path` / OpenSSL / pyca-cryptography. PKITS, pyca, and x509-limbo corpora.

## Project phase and decision framing

This workspace is **prelaunch**. The driving goal is "RFC 5280 X.509 for Rust, done right from the start." That phase shapes how design decisions are made.

**Apply these frames:**

- **Design for the eventual complete shape.** Ask "what does this API look like when finished?" not "what's the minimum we can ship?" Architectural completeness is the target; iterative accretion is not.
- **Maintainer judgment without consumer pressure.** Decisions are made on architectural and design merit. There are no users yet — that is the default condition for this phase, not a signal about whether a feature belongs. The point of the prelaunch window is that the maintainer can apply judgment without organic-growth pressure.
- **Breaking changes are free.** Pre-1.0, semver explicitly permits breaking changes across 0.x releases. They are the *mechanism* for getting the design right. Treating "non-breaking later" as a tiebreaker is wrong in this phase.
- **YAGNI applies to features, not to architecture.** "Should we ship a TLS profile?" is a feature question; YAGNI may apply. "Should the trust-domain seam have three callbacks or two?" is an architectural-completeness question; YAGNI does not apply. A trait that completes a structural pattern (e.g., `SignatureVerifier` + `RevocationChecker` + `AiaFetcher` as the complete trust-domain seam) is design closure, not surface bloat.

**Reject these frames when they appear in decision support:**

- "No concrete consumer is asking" — true for almost every decision in this phase; not informative.
- "Wait for consumer demand to drive the API" — produces an organic-growth shape, the opposite of "done right from the start."
- "We can add it later non-breakingly" — applicable post-1.0; pre-1.0 it is avoidance of design closure.
- "Speculative engineering" / "path of least regret = minimum surface" — speculation cost is real for features, not for architectural completeness.

**When this phase ends:** post-1.0, with users, the post-launch frames (preserve the API, gate on concrete consumer asks, etc.) become appropriate. Until then, decisions are made on design grounds.

**Rationale for this framing:** captured 2026-05-12 after a sweep found that several closed decisions had used post-launch-flavored reasoning ("no consumer demand," "non-breaking later") as supporting arguments. The substantive architectural reasons usually stood on their own; the wrong-frame reasoning had been weakening them. This section establishes the correct frame for future decisions. See memory `pkix-prelaunch-framing-2026-05-12` and the closed decision sweep recorded under that key.

## Non-negotiable constraints

1. `pkix-path` is `no_std`. Do not add network, async, or std-only deps to it. Ever.
2. `pkix-path` does not import `pkix-revocation`. The dependency flows one way: chain → revocation → path.
3. `SignatureVerifier` is the only place algorithm-specific code lives in `pkix-path`.
4. The trait surface must be stable across MSRV (rust-version = "1.88"). Raised from 1.73 to 1.87 in Nov 2026 because x509-cert 0.3, der 0.8 and the RustCrypto 0.14 / rsa 0.10 stack require 1.87; raised again to 1.88 for hickory-resolver 0.26, which `pkix-dane-resolver` is built on. The 1.88 bump was taken workspace-wide in preference to a per-crate `rust-version` override on `pkix-dane-resolver`, so the workspace keeps one MSRV. The cost is accepted knowingly: every crate inherits it, `pkix-path` included, although that crate is `no_std` and targets embedded platforms that will never compile a DNS resolver. Decided 2026-11-24.
5. **Framework, not policy. Three policy classes with different ownership.** The workspace ships mechanisms (`Profile` trait, `Lint` trait, `ValidationPolicy`, `DeviationStore`, etc.) and standards-body baselines. It does NOT ship Rust transcriptions of industry-forum or vendor policy that the maintainer would have to track in lockstep with the upstream source — that path puts the maintainer on the hook for someone else's living rule set.

   1. **Standards-body specs** (IETF RFCs, ITU-T X.509, ISO standards governing cert structure) — authored as fast Rust validator/lint code in the workspace's core crates (`pkix-path`, `pkix-revocation`, `pkix-identity`, `pkix-profiles`, `pkix-lint` RFC-conformance Catalog). These are stable, slow-changing standards the workspace commits to; not "someone else's policy."

   2. **Industry-forum / vendor policies** (CA/B Forum BR, Mozilla / Apple / Microsoft root programs, ETSI, DoD, root-program ingestion rules, FedRAMP, individual CA CPSs) — NOT transcribed as Rust in the workspace. Consumed via sibling **policy-adapter crates** that defer to the upstream maintainer's tool: `pkix-policy-zlint`, `pkix-policy-pkilint`, etc. Each adapter normalizes upstream findings into the workspace's `Finding`/`Lint` shape.

   3. **Site-local policy** — entirely consumer-defined. Deployers write their own `Lint` / `Profile` impls or load policy data in whatever format suits them. Workspace does not prescribe shape.

   **No prescribed wire format.** Each policy-adapter crate consumes the upstream tool's natural format (zlint NDJSON, pkilint Python API, OSCAL JSON, etc.). Site-local policy uses the deployer's choice. The OSCAL emit/parse shipped in `pkix-lint/src/oscal/*` is one optional adapter, not a workspace canonical format.

   **Unprincipled exception:** `pkix-lint-cabf` and `pkix-profiles-cabf` exist as hand-authored Rust transcriptions of CA/B Forum BR content. They *do* contain Rust transcriptions of vendor policy and *do* violate the no-transcription rule. They are bounded, explicitly labeled "reference, not authoritative," and exist because (a) CA/B Forum BR is the most-asked-about industry-forum spec, and (b) a curated reference is useful for downstream consumers comparing their interpretation against the workspace's.

   **Spec-taxonomy principle for `-cabf` crates** (decided 2026-05-13 per PKIX-mzsk / PKIX-jbvb):

   - **Subscriber-cert taxonomy is in scope.** `-cabf` crates ship idiomatic Rust `Profile` types for each subscriber-certificate profile/tier explicitly named in the underlying CA/B Forum BR. Variant subdivisions within a subscriber profile (e.g., EV vs. non-EV TLS, EV vs. non-EV code signing, Mailbox-/Organization-/Sponsor-/Individual-validated S/MIME) are included.
   - **CA-cert / Root-cert profiles are out of scope.** Those are path-validator concerns handled by RFC 5280 §6.1 in `pkix-path`, not by per-tier `Profile` shells in `-cabf`.
   - **Per-predicate Lint enforcement is out of scope.** `pkix-lint-cabf` ships a small curated marquee subset of BR predicates as `Lint` impls; comprehensive predicate coverage is `pkix-policy-zlint`'s job. The intent is operational: a caller writing `verify_smime_signer(..., &SmimeSponsorValidated, ...)` gets correct tier-aware enforcement without ever invoking zlint.
   - **Maintenance threshold acknowledges AI-grinding.** "Small curated reference set" formerly meant "what one human can author and review by hand." With AI grinding the transcription, the practical threshold is "what AI can grind faithfully from each BR refresh under human review." That widens the subscriber-cert taxonomy in scope but does not relax the CA-cert / per-predicate / horizontal-expansion bars.

   This exception is **not a template** — no equivalent `-mozilla`, `-fedramp`, `-dod`, `-etsi` crates are admitted without explicit human re-decision. Distinguishing the two coverage axes: the `-cabf` crates own **taxonomy coverage** (one `Profile` per BR-named subscriber-cert tier), and `pkix-policy-zlint` owns **predicate coverage** (matching zlint's per-section rule scope per BR family).

   Stance / epic: PKIX-amgn (framework / policy split), PKIX-mzsk (this amendment). Previous wire-format question (PKIX-apmt) resolved 2026-05-12 by the three-mode model: the question dissolves rather than gets answered, because each mode has different format ownership.

6. **Prevalidation, batch validation, and caching must remain possible.** No API in the workspace shall foreclose on these patterns. Specifically:

   - **Callbacks not closed structs.** Per-cert callbacks (`SignatureVerifier`, `RevocationChecker`, `AiaFetcher`, `Lint`) admit caller-side caching by design — any caller can implement a caching wrapper. Do not collapse callbacks into closed structs that hide the seam.

   - **Cache-friendly result types.** Public result/error types (`ValidatedPath`, `Error`, `Finding`, `TrustAnchor`, `ValidationPolicy`, etc.) MUST derive `Clone + Debug + PartialEq + Eq` and MUST be `Send + Sync`. They SHOULD support `serde::Serialize + Deserialize` behind a `serde` feature flag for cross-process / persistent caches. Do not embed non-cloneable, non-serializable handles (raw OS handles, `&'a` borrows, `Rc<T>`) into these types.

   - **Batch APIs where setup cost is non-trivial.** Policy-adapter crates with subprocess overhead (`pkix-policy-zlint`, `pkix-policy-pkilint`, future similar) MUST expose batch APIs that amortize subprocess setup across many certs. Subprocess fork+exec is ~10ms; the upstream linter typically runs in microseconds. Per-cert subprocess invocation is not just an optimization issue — it changes asymptotic cost by 1000×.

   - **Prevalidation is a supported pattern.** Producing a verdict ahead of point-of-use, storing it, and replaying later is part of the design. `ValidatedPath` represents the verdict; persisting and replaying it is a caller responsibility, but the workspace must not bake in assumptions that prevent it.

   The workspace does not have to BUILD caches. It has to ADMIT them. Caches and batch wrappers are caller-side or sibling-crate concerns.

7. **Current-regime only; historical and version-pinned postures go out-of-process.**

   Workspace `Profile` and `Lint` types snapshot the current rules from
   the latest BR text. They evaluate "is this cert conforming under
   today's rules?" — including rules the spec itself writes as
   time-keyed (SC-081 phased validity cap, future similar). The
   time-keying is part of the current rule's definition, not historical
   replay.

   The workspace does NOT ship validators that evaluate against:
   - rules in force at a past time, with predicates that have since
     been changed or removed (historical-regime replay), or
   - a caller-pinned spec version (version-frozen replay).

   For either posture, use `pkix-policy-zlint` with a version-pinned
   lint set. zlint owns the historian role for vendor policy.

   `ValidationPolicy::new(now_unix)` selects the moment at which
   validity-period checks are evaluated, NOT the moment whose rules are
   in force. This is documented on the API (see PKIX-kgnk for the
   rustdoc clarification).

   This cuts on a different axis from non-negotiable #5: #5 governs
   *who owns* the policy specification (standards-body / industry-forum /
   site-local); this rule governs *when* the policy is evaluated
   (current regime in-process / historical or version-pinned out-of-
   process). A rule the spec itself writes as time-keyed stays in-
   process because the time-keying is part of the current rule's
   definition — it's transcribing what the spec literally says, not
   maintaining a delta history.

   Stance: PKIX-e3nl (this codification), PKIX-kgnk (the `now_unix`
   rustdoc half), PKIX-jy95 (`pkix-policy-zlint`, where historical-
   regime replay lives).

## What already exists (and why we are not using it)

| Crate | Why not |
|---|---|
| `x509-cert` | Cert creation/encoding only; no chain validation |
| `x509-verify` | Single-signature primitive; no chain walking, no policy |
| `rustls-webpki` | WebPKI/TLS-server-auth shaped; pulls in ring (C/C++); wrong shape |
| `pki-rs` | Personal project, unmaintained since 2023 |
| `pkix` (Fortanix) | Encoding helpers only; unrelated to path validation |

The RustCrypto upstream gap is tracked at RustCrypto/formats#838 (open since 2023, no PR).

## Key design facts

- RFC 5280 §6.1 state machine lives in `pkix-path::validate_path`.
- Path building (RFC 4158 — cross-signed certs, multiple candidate issuers) lives in `pkix-path-builder`. `pkix-path` itself is positional: `chain[i+1]` must be the issuer of `chain[i]`.
- DN comparison must follow RFC 4518 string prep — do not use byte-equality for names.
- `BasicConstraints` cA=TRUE is mandatory on every intermediate; keyCertSign in KeyUsage must be checked.

## Trust anchor loading: `pkix-truststore`

`pkix-truststore` is a small Tier 1 crate that turns PEM/DER bytes (or files)
into `Vec<TrustAnchor>`. It also exposes `from_der_iter(...)` as the
canonical adapter entry point for non-file sources.

**Project stance (binding): no baked-in trust data, no baked-in trust source.**
No compiled-in Mozilla CA bundle (rejects the `webpki-roots` model). No
built-in knowledge of any platform trust store. Trust data is deployment
configuration, not library content. Platform / HSM / cloud KMS sources are
separate adapter crates (`pkix-truststore-system`, `pkix-truststore-pkcs11`,
…) — sibling workspace members, not in `pkix-truststore` itself — that fetch
DER bytes from a source-specific API and feed them into
`pkix_truststore::from_der_iter(...)`.

Do not add a `webpki-roots`-style trust-data dependency to any crate in this
workspace without explicit human approval. Do not add platform-specific FFI
or `[target.<platform>.dependencies]` to `pkix-truststore` itself; that
belongs in an adapter crate.

## Status

Crypto coverage, RFC compliance, and feature surfaces land incrementally.
Per-crate `# Limitations` rustdoc sections describe what each crate's
shipped code currently does and does not do. The scope being worked
towards is full RFC 5280 and adjacent-RFC coverage; no work is gated by
a version milestone.

PKITS (NIST) test corpus is the Tier-1 integration-test bar; the
x509-limbo corpus is Tier-2. See `pkix-difftest/baseline-pkits-analysis.md`
and `pkix-difftest/baseline-limbo-analysis.md` for current state.

## Test discipline

- No test may use the code under test as its own oracle.
- External oracles for differential testing: OpenSSL (`openssl verify`), pyca/cryptography.
- Test vector / expected-result sources: NIST PKITS (binary fixtures committed), x509-limbo (curated JSON manifest, fetched into `~/GIT/x509-limbo` on demand), per-RFC test vectors.
- Tests are fully offline.

### Run the gates the way CI runs them

`quality-gates.yml` sets `RUSTFLAGS: -D warnings` for the lint and test
jobs. A local `cargo clippy` or `cargo test` without it passes on code CI
rejects -- an unused constant, an `Arc` around a non-`Sync` type -- and the
failure arrives after the push instead of before it:

    RUSTFLAGS="-D warnings" cargo fmt --all -- --check
    RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets --all-features
    RUSTFLAGS="-D warnings" cargo test --workspace --all-features

The feature-powerset job deliberately clears `RUSTFLAGS`, and the
bare-metal job sets its own; everything else inherits the deny.

### A field the builder will not set can still be written

`cryptography` refuses to emit a certificate with a duplicate extension, a
pre-2050 `GeneralizedTime`, or an `encipherOnly` without `keyAgreement`, and it
gives no way to choose an OCSP response's `producedAt` -- OpenSSL fills that in
with the clock at signing time. None of that makes the shape untestable. Build
the object, rebuild the signed part at the DER level with the field replaced,
and re-sign with the key the generator already holds.
`pkix-path/tests/fixtures/dup-ext/gen.py` established the pattern;
`gentime/gen.py` and `pkix-revocation/tests/fixtures/ocsp-produced-at/gen.py`
follow it.

So the question is never whether the builder can be coaxed into setting the
field. It is whether the field sits inside something this generator can
re-sign. Asking the first question produced a WONTFIX for the `producedAt`
boundary that was simply wrong.

Two things the splice needs. Sign *after* editing, because a validator checks
the signature before anything else and an unsigned splice is refused for the
wrong reason. And have the generator verify its own output -- that it parses,
that it carries the value asked for, and that the new signature checks under
the key that is supposed to have made it -- since a fixture whose signature
broke tests the error path it was built to avoid.

### "Subsumed" usually means the fixture is the wrong shape

A guard whose verdict a later check reaches anyway looks untestable: mutate it,
and the certificate is still refused, with the same error. The conclusion to
resist is that the guard is redundant. The honest question is whether some
*other* input reaches the guard on a path where the later check does not fire.

`check_san_name_form`'s unevaluable-name-form guard spent a day recorded as
subsumed on exactly that reasoning. Every fixture put the unevaluable form in a
**permitted** subtree, where the refusal is overdetermined -- a name the
matchers cannot decide matches no subtree, and a constrained type matching
nothing is a violation, so the generic check refuses it whether or not the
guard ran. Move the same form into an **excluded** subtree and it inverts: the
generic check asks whether the name *matches*, one it cannot decide matches
none, no violation is raised, and the certificate passes. The guard was the
only thing refusing it, and the fail-open direction widens a CA's trust scope
past what the CA published.

So for any guard that looks subsumed, ask what the subsuming check is asking.
If it asks "does this match something required", a name that matches nothing
fails it for you. If it asks "does this match something forbidden", a name that
matches nothing passes. Those are opposite, and one of them needs the guard.

### A test can be thorough about a rule and blind to where it applies

`required_leaf_policy_oids` and `required_leaf_subject_dn_attrs` are checked
only on the leaf, `if i == 0`. Both guards survived mutation to `i != 0`, which
applies each requirement to every certificate *but* the leaf, because the only
chain testing them is PKITS `AllCertificatesSamePoliciesTest10` -- and the name
is the reason. Every certificate in it asserts the same policies, so no verdict
in that suite can distinguish "check the leaf" from "check everything but the
leaf", however many policy combinations it tries.

When a rule names a position in a chain -- the leaf, the anchor, an
intermediate -- the fixture has to differ at that position. A chain whose
certificates are alike in the property under test cannot see the index at all.

## Commit messages: no tool attribution

Never add `Assisted-by`, `Co-Authored-By`, `Generated with`, or any other
trailer naming a model or tool. Not optional, not configurable, not "nobody
is penalized either way". No commit in this repository has ever carried one
and none ever will.

The commit message records what the patch does and why. Who or what typed it
is not part of that, and a trailer claiming assistance establishes nothing a
reviewer can use.

## Crate docs: no heading that repeats the crate name

**Do not open a crate's rustdoc with `//! # <crate-name>`.** rustdoc already
renders the crate name as the page title, so the heading shows it twice, and
it pushes the one sentence that says what the crate is for below a line
carrying no information.

Start with that sentence instead:

```rust
//! DNSSEC-validating resolution of DANE TLSA records.
```

The workspace was split three ways on this — some crates never had one, some
had it removed in a prose pass, some still carried it — which is the actual
cost of leaving a convention unwritten. All of them now start with the
sentence.

This applies to rustdoc only. A `README.md` keeps its `# <crate-name>`
heading: nothing else supplies a title when it renders on crates.io or in a
file viewer.

## Changelogs: don't

**Do not write `CHANGELOG.md` entries as part of ordinary work.** The git
history is the record. A commit message that explains its patch, with the
reasoning a maintainer needs in two years, is the one place that belongs.

This was never an instruction — agents generated it unprompted, every commit,
and then restated the same prose in the commit message. The result is a
2700-line root changelog that says what `git log` already says, in the same
voice, maintained twice.

Concretely:

- A code change touches `CHANGELOG.md` **only** if a human asked it to.
- Put the root cause, the invariant, the design choice and the inherited
  constraint in the commit message. Do not also put them in a changelog.
- Do not create a `CHANGELOG.md` for a new crate.
- If you catch yourself writing a release narrative for a version that has not
  been released, stop. Write it when it ships, if at all.

The narrow case where a changelog earns its place: **a hand-written note about
breaking changes, at release time**, for the consumers of a published crate.
Most crates here are published on crates.io, so that case is real — what was
deleted was not that. It was maintainer-voice prose restating the commit it
came from, written per-commit and read by nobody.

Same rule, stated as a smell: if the commit message and the changelog entry
would say the same thing, the changelog entry is the one to drop.

## Clean up build exhaust

Cargo keys build artifacts by configuration hash and never collects the old
ones. Anything that sweeps configurations piles them up:
`cargo hack --feature-powerset`, the per-feature doc job, and `cargo mutants`,
which copies the whole tree per job and builds each copy.

Measured 2026-11-27: `target/debug` reached 278G — roughly 23 full builds,
with 2572 configuration directories under `target/debug/build/pkix-chain`
alone and a 135 MB test binary in each. The disk filled and a mutation sweep
died with ENOSPC.

So:

- Run `scripts/prune-build-exhaust.sh` after a powerset run or a mutation
  sweep. Not before — the point is to not leave the exhaust behind.
- Check free space before starting a sweep, and keep the job count modest.
  `-j 10` is what exhausted the disk; each job is a tree copy plus its own
  build.
- `cargo mutants` removes its own tree copies on a clean exit and leaves them
  behind when killed. The prune script collects those, and refuses to while a
  sweep is running.

`[profile.dev] debug = "line-tables-only"` in the workspace manifest cuts
each test binary by 2.6x and keeps file and line in backtraces. It does not
address accumulation, which was the larger half.

## Name the features when running a mutation sweep

`cargo mutants` builds its mutant list from the syntax tree, before `cfg` is
resolved. Code behind a feature the sweep did not enable is still mutated,
the mutation changes nothing in the build, the tests pass, and the mutant is
reported MISSED. The report cannot tell that from a real coverage gap.

A default-feature sweep of pkix-chain reported survivors in
`combine_smtp_transport_security`, `SmtpTransportSecurity::permits_delivery`
and `verify_attribute_cert`. All three sit behind `mta-sts` or
`attribute-certs`, both off by default, and all three have tests that pass
under their own features. Every one was spurious.

So pass the features the crate's own tests need -- `--all-features` unless
some combination does not build -- and read the baseline's `Test` phase
duration in `outcomes.json`. A second or two means almost nothing ran.

The inverse trap is real too: a crate whose test targets declare
`required-features` runs none of them when the sweep omits the feature, so
genuine gaps get hidden rather than invented.

### Test code gets mutated too

`#[cfg(test)]` modules are mutated like anything else, and a mutated test
helper cannot be caught by the tests it serves, so it is always reported
MISSED. Adding an in-crate test module therefore adds permanent survivors:
pkix-revocation went from 276 mutants to 288 that way, one of which is a
helper asserting that error messages are distinct.

`-E` excludes them by name, matched against what `--list` shows:

    cargo mutants -p <crate> --all-features -E 'tests::|_tests::'

Check what the regex actually removed rather than assuming -- module names
vary, and a regex that matches nothing is silent.

### Sweeps are I/O bound, and one mutant class leaves a process behind

Two things learned the hard way on 2026-11-27.

A sweep's limit is disk, not cores. Each job is a tree copy that builds
independently, so six jobs under `--all-features` drove this machine to 64-80%
I/O wait with 2.9 GB of swap in use, and the rate fell from 556 mutants in
24 minutes to one mutant every four. `vmstat 1` tells you which: a high `wa`
column and a long `b` queue mean adding jobs makes it slower. Keep the count at
4 or below, and do not run heavy `cargo test --workspace` builds beside one.

What is on the disk is mostly linker output, and the multiplier is the crate's
integration test count. `pkix-path` has thirty files in `tests/`, so every
mutant relinks thirty binaries before a single assertion runs, and the whole
crate's 541 mutants do not finish in an afternoon. Scope the run when the
question is scoped: `-f "**/verifiers.rs"` cuts 541 to 68, and `--` passes
arguments through to `cargo test`, so `-- --lib` or a named `--test` restricts
what gets built per mutant. Narrowing the tests narrows the sweep's authority
too -- a mutant only the excluded tests would catch now reads as missed -- so
say which subset ran when recording the result.

A mutation that turns a bounded loop into an unbounded one leaves a runaway
process behind when verified by hand. `reaches_self_signed`'s step counter is
one: with `+= 1` mutated to `*= 1` the walk never terminates, and the test
binary kept a core busy for an hour and 42 minutes after the verification
finished -- the test's own deadline is on the thread waiting for the answer,
not on the thread computing it. After hand-verifying any mutation to a loop
bound, check:

    ps -eo pid,etime,pcpu,comm --sort=-pcpu | head

Kill what it finds by PID. `pkill -f pkix_path-` matches the shell that invoked
the verification too, because that pattern appears in its own command line, so
it kills the harness and leaves the source file holding a mutation. If a
verification run ends early, grep the file for the mutation text before trusting
it.

### A non-terminating mutant can only be caught by a timeout

Some mutations do not produce a wrong answer, they produce a program that never
answers: an `Iterator::next` replaced by `Some(0)`, or a position counter whose
`+= 1` becomes `*= 1`. Any caller that consumes such an iterator to exhaustion
runs forever, and the only way a test suite can report that is by not
finishing. cargo-mutants calls it a timeout and does not count it as missed.
That is the correct verdict and there is nothing to chase: a bounded test of
the same iterator will fail in seconds when run on its own, but a sweep still
sees the hang, because production code -- `names_match`, in `pkix-path`'s case
-- consumes the whole stream and is right to.

Two things are worth doing about such a mutant. Check whether the operator can
be written out of the code: `NormalizedIter`'s space run used
`while self.inner.peek() == Some(&b' ')`, whose reversed comparison consumes
nothing and never ends, and `Peekable::next_if_eq` says the same thing with no
comparison to reverse, so the mutant stopped existing. And add the bounded
direct test anyway, because an iterator whose output nothing asserts is an
untested iterator whatever the sweep says.

## Escalation rule

If you hit 3 failed attempts at the same error without progress, stop and surface to the human.
Do not retry in a loop.

## Agent Workflow

Work is organized as **epics → issues → subagents**:

1. **Decompose** — create a beads epic; break it into issues small enough for one
   subagent each. Use `bd epic` and `bd create`.
2. **Parallelize** — use `TeamCreate` to run one subagent per ready issue concurrently.
   Check `bd ready` for issues with no outstanding blockers.
3. **Subagent contract**:
   - Claim the issue before touching code: `bd update <id> --claim`
   - Work only the scope described in that issue — nothing more
   - Close on completion: `bd close <id>`
   - Return a brief summary: what changed, any new blockers discovered
4. **Orchestrator** — top-level agent owns epics, spawns teams, collects results,
   files follow-up issues for incomplete work.

**Rule: one subagent = one bead. Never assign two issues to one subagent.**

## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` for full workflow context.

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work atomically
bd close <id>         # Complete work
```

**We do not use dolt.** Beads runs its flat-file backend here: issues are JSON
under `.beads/issues/`, committed with the repo like any other file, so
`git push` is the whole of "sync the issue database". There is no separate sync
step and no `bd dolt` command in any workflow.

Expect to be told otherwise. `bd` still ships `bd dolt` subcommands whose own
help text says "Beads uses a dolt sql-server for all database operations",
which is stale, and older checklists in this and sibling repositories listed
`bd dolt push` as mandatory. Both are wrong. Ignore them rather than running a
command against a backend this project does not have.

**Beads is the only task and planning tool.** Do NOT use:
- TodoWrite / markdown TODO lists
- Scratchpad or audit files (`audit-*.md`, `plan-scratch.md`, or any similar throwaway planning file)
- MEMORY.md or any other markdown file as a knowledge store

The only permitted markdown planning artifact is a crate's `PLAN.md`, which is a permanent
design document checked into the repo — not a scratchpad. Use `bd remember` for persistent
knowledge and `bd create` for all task tracking.
