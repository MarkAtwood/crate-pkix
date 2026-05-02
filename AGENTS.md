# AGENTS — PKIX

Context for AI coding agents working in this repository.

## What this is

Three Rust crates for RFC 5280 X.509 certificate path validation:

- **`pkix-path`** — Pure, `no_std` RFC 5280 §6 path validator. Pluggable crypto via `SignatureVerifier` trait.
- **`pkix-revocation`** — CRL and OCSP revocation checking. `RevocationChecker` trait + `NoRevocation` zero-cost default.
- **`pkix-chain`** — High-level umbrella. Re-exports both; provides `verify_chain()` for the 90% case.

## Non-negotiable constraints

1. `pkix-path` is `no_std`. Do not add network, async, or std-only deps to it. Ever.
2. `pkix-path` does not import `pkix-revocation`. The dependency flows one way: chain → revocation → path.
3. `SignatureVerifier` is the only place algorithm-specific code lives in `pkix-path`.
4. The trait surface must be stable across MSRV (rust-version = "1.73").

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
- Path building (RFC 4158 — cross-signed certs, multiple candidate issuers) is out of scope for v0.1.
- DN comparison must follow RFC 4518 string prep — do not use byte-equality for names.
- `BasicConstraints` cA=TRUE is mandatory on every intermediate; keyCertSign in KeyUsage must be checked.
- PKITS (NIST) test corpus is the integration test bar.

## v0.1 deliverable

RSA-PKCS1v15 + P-256 signing, no NameConstraints, no revocation, configurable max depth.
PKITS happy-path subset green. All unimplemented features have rustdoc `# Limitations` sections.

## Test discipline

- No test may use the code under test as its own oracle.
- External oracles: OpenSSL (`openssl verify`), pyca/cryptography, Bouncy Castle vectors.
- PKITS binary fixtures committed to the repo; tests are fully offline.

## Escalation rule

If you hit 3 failed attempts at the same error without progress, stop and surface to the human.
Do not retry in a loop.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:ca08a54f -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

## Session Completion

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd dolt push
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
<!-- END BEADS INTEGRATION -->
