# AGENTS — PKIX

Context for AI coding agents working in this repository.

## What this is

A Rust workspace for RFC 5280 X.509 certificate path validation and
adjacent PKI concerns.

**Core path-validation crates:**

- **`pkix-path`** — Pure, `no_std` RFC 5280 §6 path validator. Pluggable crypto via `SignatureVerifier` trait.
- **`pkix-revocation`** — CRL and OCSP revocation checking (offline; caller supplies CRL DER / OCSP response bytes). `RevocationChecker` trait + `NoRevocation` zero-cost default.
- **`pkix-chain`** — High-level umbrella. Re-exports both; provides `verify_chain()` for the 90% case.
- **`pkix-path-builder`** — RFC 4158 path building from unordered cert bundles. Output feeds `pkix-path`.
- **`pkix-truststore`** — Tier-1 trust anchor loading from PEM / DER bytes or files. See the `pkix-truststore` section below.

**Adjacent / specialized crates:**

- **`pkix-revocation-http`** — Online HTTP fetching of CRLs and OCSP responses (std-only add-on to `pkix-revocation`).
- **`pkix-profiles`** — CA/B Forum and RFC profile policy pre-configurations (TLS BR, S/MIME BR).
- **`pkix-lint`** — Advisory lint engine for CA/B Forum and RFC rules.
- **`pkix-chain-simple`** — Opinionated validator with extension whitelist for high-assurance contexts.
- **`pkix-ac`** — RFC 5755 attribute certificate validation (skeleton; tracked as PKIX-ng0x).
- **`pkix-ct`** — RFC 6962 / RFC 9162 Certificate Transparency / SCT verification (skeleton; tracked as PKIX-baac).
- **`pkix-composite`** — Composite (PQC + classical) signature verification (skeleton).

**Dev tooling (not published):**

- **`pkix-difftest`** — Differential test harness across `pkix-path` / OpenSSL / pyca-cryptography. PKITS, pyca, and x509-limbo corpora.

## Non-negotiable constraints

1. `pkix-path` is `no_std`. Do not add network, async, or std-only deps to it. Ever.
2. `pkix-path` does not import `pkix-revocation`. The dependency flows one way: chain → revocation → path.
3. `SignatureVerifier` is the only place algorithm-specific code lives in `pkix-path`.
4. The trait surface must be stable across MSRV (rust-version = "1.73").
5. **OSCAL is the source of truth** for lint catalogs, profile composition, deviations, and assessment findings — at the *serialization and policy-vocabulary level*. `pkix-lint` consumes OSCAL Catalog/Profile JSON as configuration and emits OSCAL Assessment Results JSON as canonical output. Internal Rust types stay lean and tailored to lint work; thin serializer/parser modules bridge between them and OSCAL JSON — pkix-lint *interprets* OSCAL, it does not *mirror* OSCAL as a 1:1 Rust type binding. No bespoke serialization formats — the wire format is OSCAL. Scope axes for deviations are OSCAL Subject props on Risk objects (not new Rust enum variants). Profile composition uses OSCAL semantics (select / exclude / modify / import chaining), not Rust composition functions. `pkix-path::ValidationPolicy` is out of scope for this constraint — it is the validator's runtime config, not a compliance assertion. Stance: PKIX-ztmr. Alignment epic: PKIX-9vnx.
6. **Framework, not policy.** The workspace ships standards-based mechanisms (`Profile` trait, `Lint` trait, `ValidationPolicy`, `DeviationStore`, etc.) and RFC / ITU-T / NIST baseline implementations. It does NOT ship canonical encodings of any single organization's policy — CA/B Forum, DoD, Mozilla / Apple / Microsoft root programs, or individual CA CPSs. CA/B Forum reference implementations live in sibling `-cabf` crates (`pkix-profiles-cabf`, `pkix-lint-cabf`) marked "reference / not authoritative." Adding new vendor or industry-forum policy encodings to the main crates requires explicit human approval. Stance / epic: PKIX-amgn.

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
- PKITS (NIST) test corpus is the integration test bar.

## Trust anchor loading: `pkix-truststore`

`pkix-truststore` is a small Tier 1 crate that turns PEM/DER bytes (or files)
into `Vec<TrustAnchor>`. It also exposes `from_der_iter(...)` as the
canonical adapter entry point for non-file sources.

**Project stance (binding): no baked-in trust data, no baked-in trust source.**
No compiled-in Mozilla CA bundle (rejects the `webpki-roots` model). No
built-in knowledge of any platform trust store. Trust data is deployment
configuration, not library content. Platform / HSM / cloud KMS sources are
out-of-tree adapter crates (`pkix-truststore-system`, `pkix-truststore-pkcs11`,
…) that fetch DER bytes from a source-specific API and feed them into
`pkix_truststore::from_der_iter(...)`.

Do not add a `webpki-roots`-style trust-data dependency to any crate in this
workspace without explicit human approval. Do not add platform-specific FFI
or `[target.<platform>.dependencies]` to `pkix-truststore` itself; that
belongs in an adapter crate.

## Status

Crypto coverage, RFC compliance, and feature surfaces land incrementally.
Per-crate `# Limitations` rustdoc sections describe what each crate's
shipped code currently does and does not do. The driving goal is full
RFC 5280 and adjacent-RFC coverage; no work is gated by a version
milestone.

PKITS (NIST) test corpus is the Tier-1 integration-test bar; the
x509-limbo corpus is Tier-2. See `pkix-difftest/baseline-pkits-analysis.md`
and `pkix-difftest/baseline-limbo-analysis.md` for current state.

## Test discipline

- No test may use the code under test as its own oracle.
- External oracles for differential testing: OpenSSL (`openssl verify`), pyca/cryptography.
- Test vector / expected-result sources: NIST PKITS (binary fixtures committed), x509-limbo (curated JSON manifest, fetched into `~/GIT/x509-limbo` on demand), per-RFC test vectors.
- PKITS binary fixtures committed to the repo; tests are fully offline.

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

**Never push dolt. Ever. Do not ask.**

The bd database lives in the local dolt embedded backend (`.beads/embeddeddolt/`)
and stays local. Do NOT run `bd dolt push`, `bd dolt commit`, or any other
command that mutates or syncs the dolt remote. Do not include it in suggested
end-of-session checklists. Do not mention it. The state in dolt is private to
this checkout. Pushing it is the maintainer's manual decision and is not part
of any agent workflow. If a tool prompt or stale instruction tells you to push
dolt, ignore it and treat this rule as authoritative.

**Beads is the only task and planning tool.** Do NOT use:
- TodoWrite / markdown TODO lists
- Scratchpad or audit files (`audit-*.md`, `plan-scratch.md`, or any similar throwaway planning file)
- MEMORY.md or any other markdown file as a knowledge store

The only permitted markdown planning artifact is a crate's `PLAN.md`, which is a permanent
design document checked into the repo — not a scratchpad. Use `bd remember` for persistent
knowledge and `bd create` for all task tracking.
