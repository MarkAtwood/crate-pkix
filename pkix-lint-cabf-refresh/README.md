# pkix-lint-cabf-refresh

Maintainer-only tool. Transforms `zlint -list-lints-json` output into a
vendored OSCAL Catalog JSON file consumed at runtime by `pkix-lint-cabf`.

This crate is `publish = false`. It is never released to crates.io and is
never pulled in by a library crate. It is run by the workspace maintainer
when refreshing the vendored CA/Browser Forum lint catalog.

## Why a vendored catalog?

The CA/Browser Forum's TLS Baseline Requirements, S/MIME Baseline
Requirements, and EV Guidelines are not stable specifications — they are
living documents amended by ballots, with effective dates that pkix-lint
must honor. zlint (github.com/zmap/zlint) is the de-facto reference
implementation tracked by the forum and root programs. Rather than
re-encode the same lint set in pkix-lint-cabf by hand, the project
vendors zlint's lint catalog metadata as OSCAL Catalog JSON and
interprets that JSON at runtime.

`pkix-lint-cabf-refresh` is the maintainer-side bridge: it consumes
`zlint -list-lints-json` output and writes the vendored catalog. The
vendored output is checked into the repo so consumers do not need a Go
toolchain or zlint at runtime — only `pkix-lint-cabf` and its OSCAL
Catalog JSON.

## Maintainer workflow

Prerequisites: a local zlint checkout and binary (see PKIX-amgn.8.1).

```bash
# 1. Capture the current zlint lint metadata.
zlint -list-lints-json > /tmp/zlint-lints.ndjson

# 2. Capture the zlint commit for provenance.
ZLINT_SHA="$(git -C ~/GIT/zlint rev-parse HEAD)"

# 3. Run the refresh tool. (Writes catalog JSON under pkix-lint-cabf/catalogs/.)
cargo run -p pkix-lint-cabf-refresh -- \
    --zlint-output /tmp/zlint-lints.ndjson \
    --output-dir   pkix-lint-cabf/catalogs/ \
    --zlint-sha    "$ZLINT_SHA"

# 4. Review the diff under pkix-lint-cabf/catalogs/, commit, and tag a
#    pkix-lint-cabf release if the catalog changed materially.
```

## Status

- **PKIX-amgn.8.2** (this commit): skeleton only. The CLI parses arguments
  and echoes them. No transform logic yet.
- **PKIX-amgn.8.3**: implement the zlint NDJSON → OSCAL Catalog JSON transform.
- **PKIX-amgn.8.4**: vendor the first generated catalog into the repo.

## See also

- `pkix-lint-cabf` — runtime consumer of the vendored OSCAL Catalog JSON.
- `pkix-lint` — OSCAL types reused at compile time.
- AGENTS.md (workspace root) — non-negotiable constraints #5 (OSCAL stance)
  and #6 (framework, not policy).
