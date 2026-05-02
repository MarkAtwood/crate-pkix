# PKIX — Certificate Path Validation

Three Rust crates implementing RFC 5280 X.509 certificate chain validation.

## Crate Map

| Crate | Purpose | `no_std` |
|---|---|---|
| `pkix-path` | Path building + RFC 5280 §6 validation, pluggable crypto | yes |
| `pkix-revocation` | CRL + OCSP revocation checking | yes (core), no (fetch) |
| `pkix-chain` | Umbrella: re-exports both, high-level `verify_chain()` | no |

## Architecture Decisions

**`SignatureVerifier` trait** is the pluggable crypto seam in `pkix-path`.
All algorithm-specific code is behind this trait. Default feature `rustcrypto`
wires in RustCrypto backends (RSA-PKCS1v15, RSA-PSS, P-256, P-384, Ed25519).
FIPS path: implement `SignatureVerifier` against `wolfcrypt-rustcrypto`.

**`pkix-path` stays `no_std` forever.** Revocation is in `pkix-revocation`,
never in `pkix-path`. This constraint protects embedded users (Caliptra, DPE).

**`RevocationChecker` trait** is the seam between path validation and revocation.
`NoRevocation` is the zero-cost default for offline/embedded use.

## Planned Algorithm Support

| Algorithm | v0.1 | v0.2 |
|---|---|---|
| RSA-PKCS1v15 (SHA-256/384/512) | yes | yes |
| RSA-PSS | no | yes |
| P-256 ECDSA | yes | yes |
| P-384 ECDSA | no | yes |
| Ed25519 | no | yes |
| ML-DSA-44/65/87 | no | hook |

## v0.1 Scope Limits (document in rustdoc `# Limitations`)

- No NameConstraints (RFC 5280 §4.2.1.10)
- No PolicyConstraints / policy validation (§4.2.1.9, §6.1.5)
- No revocation (use `pkix-revocation::NoRevocation`)
- Fixed-depth only (configurable max, no path builder with cross-sign handling)

## Test Requirements

- PKITS (NIST SP 800-89 test suite) is the integration test baseline
- Never derive test vectors from the code under test
- External oracles only: OpenSSL, pyca/cryptography, Bouncy Castle test vectors
- All test vectors committed as hex literals or binary fixtures; tests must be fully offline

## Build Commands

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all
RUSTDOCFLAGS="--cfg docsrs -D warnings" cargo +nightly doc --no-deps --all-features --workspace
cargo +1.73 check --workspace  # MSRV check
```

## Beads Issue Tracker

Run `bd prime` for workflow commands. All tasks tracked in beads, not markdown TODOs.


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
