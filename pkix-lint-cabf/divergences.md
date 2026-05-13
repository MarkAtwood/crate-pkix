# `pkix-lint-cabf` — divergences from current CA/B Forum BR

This crate is a hand-authored snapshot of a small curated subset of CA/B
Forum Baseline Requirements predicates, exposed as `pkix-lint::Lint`
impls per AGENTS.md non-negotiable #5's "unprincipled exception"
clause. It is **reference, not authoritative.** The BR text is the
only canonical source.

This file records:

1. Which CA/B Forum specs and which version of each this crate was last
   refreshed against.
2. Known divergences between this crate's shipped lints and the
   upstream BR text — both intentional and unintentional.
3. The policy under which this crate is refreshed.

For **comprehensive** CA/B Forum predicate coverage, see the sibling
crate `pkix-policy-zlint`, which wraps zlint's ~400 BR-conformance
checks via subprocess at runtime (PKIX-jy95.10).

## Last refresh

| Spec | Version | Refresh date |
|---|---|---|
| CA/B Forum TLS BR | 2.2.6 | 2026-05-13 |

The S/MIME and CS BR documents are also audited at the workspace
level (see `pkix-profiles-cabf/divergences.md`), but this crate
currently ships lints only for TLS BR. S/MIME / CS lint coverage is
intentionally deferred to `pkix-policy-zlint`.

## Lint coverage

| Lint | Citation | Severity | Applies to |
|---|---|---|---|
| `cabf.br.tls.validity.max` | TLS BR §6.3.2 (SC-081) | Error | Leaf |
| `cabf.br.tls.alg.sha1_prohibited` | TLS BR §7.1.3 | Error | Any |
| `cabf.br.tls.rsa.min_key_size` | TLS BR §6.1.5 | Error | Any |
| `cabf.br.tls.san.required` | TLS BR §7.1.2.7.12 | Error | Leaf |
| `cabf.br.tls.eku.server_auth` | TLS BR §7.1.2.7.10 | Error | Leaf |
| `cabf.br.tls.bc.ca_flag` | TLS BR §7.1.2.10.4 | Error | `IntermediateCa` |

## Intentional divergences

### Not predicate-comprehensive

This crate ships six marquee lints. Full TLS BR predicate coverage
(roughly one Lint per BR sub-section, matching zlint's CA/B Forum
ruleset) is intentionally out of scope here. Use `pkix-policy-zlint`
when you need that breadth.

### `BcCaFlagLint` cites the umbrella `BasicConstraints` section

The lint's `applies_to = IntermediateCa` scope covers every kind of
TLS BR Sub CA certificate (Cross-Cert §7.1.2.2, Tech-Constrained
Non-TLS §7.1.2.3, Tech-Constrained TLS §7.1.2.5, TLS §7.1.2.6). All
four of those Sub CA profiles cross-reference §7.1.2.10.4 (CA
Certificate Basic Constraints) for the `cA=TRUE` rule, so this lint
cites the umbrella section directly rather than pinning a single Sub
CA flavor. Earlier versions cited §7.1.2.5 (Tech-Constrained TLS)
specifically, which was structurally too narrow.

### No S/MIME BR or CS BR lint module

`pkix-profiles-cabf` ships `SmimeProfile` and `CodeSigningProfile`
profile types, but this crate currently has no corresponding lint
modules. Per-predicate enforcement for those BR families is the job
of `pkix-policy-zlint`.

### `cabf_tls_br` lints are not gated by a `LintProfile::version`

`CabfTlsBrProfile` delegates `version()` to
`pkix_profiles_cabf::WebPkiProfile::version()`, which returns
`"2.2.6"` after the most recent refresh. Lint behavior does not
branch on the version string — the six checks above evaluate the
same predicates regardless of which BR version a caller is targeting.
Callers needing per-version behavioral differences should layer their
own profile.

## Out of scope by design

- `pkix-lint-mozilla`, `pkix-lint-fedramp`, `pkix-lint-dod`,
  `pkix-lint-etsi` — barred by the AGENTS.md non-negotiable #5
  "not a template" clause. Other industry-forum / vendor policies
  must come in via policy-adapter crates that defer to upstream tools,
  not via workspace-internal transcription.
- Per-cert lints requiring cross-cert correlation (e.g. CA name
  consistency across a chain) — out of scope for the per-cert `Lint`
  shape.

## Refresh policy

Same wholesale-audit policy as `pkix-profiles-cabf`: refreshed when
the workspace maintainer pulls in updated BR sources under `specs/`,
not per-ballot. Between refreshes, citations may drift behind the
upstream specs.

If you depend on bit-exact CA/B Forum conformance, **fork and review**.
The crate-level rustdoc says so explicitly.

PRs that point out a divergence (citation, behavior, or coverage gap)
are welcome. File the divergence here first, then either propose the
fix in the same PR or split it into a follow-up.

## Cross-references

- AGENTS.md non-negotiable #5 — three-mode policy-class architecture
  and the unprincipled-exception clause that admits this crate.
- AGENTS.md spec-taxonomy principle (PKIX-mzsk).
- `pkix-policy-zlint` — principled predicate-comprehensive CA/B Forum
  coverage (PKIX-jy95.10).
- `pkix-profiles-cabf/divergences.md` — sibling divergence record for
  the profile side of the unprincipled exception.
