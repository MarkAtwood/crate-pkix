#!/usr/bin/env bash
# Prune accumulated Cargo build artifacts.
#
# WHY THIS EXISTS
#
# Cargo keys build artifacts by configuration hash and never collects the old
# ones. This workspace produces a lot of configurations -- `cargo hack
# --feature-powerset --depth 2` over 34 crates, a per-feature doc job, a
# default-features job, and `cargo mutants`, which copies the tree per job and
# builds each copy. Test binaries are the per-unit cost and they are large.
#
# Measured 2026-11-27: target/debug had grown to 278G, with 2572 configuration
# hash directories under target/debug/build/pkix-chain alone and one test
# binary of 135 MB in each. One clean full build is 12G, so that was roughly 23
# builds' worth. The disk hit 100% and a mutation sweep died with ENOSPC.
#
# Run this after a powerset run or a mutation sweep, not before: the point is
# to not leave the exhaust behind.
set -euo pipefail
cd "$(dirname "$0")/.."

KEEP_HOURS="${KEEP_HOURS:-6}"
DRY_RUN="${DRY_RUN:-0}"

say() { printf '%s\n' "$*"; }
size() { du -sh "$1" 2>/dev/null | cut -f1; }

before=$(df -h . | tail -1 | awk '{print $4}')
say "free before: $before"

# 1. Configuration hash directories older than KEEP_HOURS. Keeps a recent
#    build warm so the next `cargo test` is not a cold rebuild.
if [ -d target/debug/build ]; then
  say "target/debug/build: $(size target/debug/build) across $(find target/debug/build -mindepth 2 -maxdepth 2 -type d | wc -l) configuration dirs"
  if [ "$DRY_RUN" = 1 ]; then
    find target/debug/build -mindepth 2 -maxdepth 2 -type d -mmin "+$((KEEP_HOURS * 60))" -print | head -20
    say "(dry run; $(find target/debug/build -mindepth 2 -maxdepth 2 -type d -mmin "+$((KEEP_HOURS * 60))" | wc -l) dirs would go)"
  else
    find target/debug/build -mindepth 2 -maxdepth 2 -type d -mmin "+$((KEEP_HOURS * 60))" -exec rm -rf {} + 2>/dev/null || true
  fi
fi

# 2. Incremental state. Always safe to drop; it only costs a slower next build,
#    and it was 51G of the 278G.
if [ -d target/debug/incremental ]; then
  say "target/debug/incremental: $(size target/debug/incremental)"
  [ "$DRY_RUN" = 1 ] || rm -rf target/debug/incremental
fi

# 3. Tree copies abandoned by an interrupted `cargo mutants`. It removes its
#    own on a clean exit; a killed run leaves them.
#
#    Guarded two ways, because a RUNNING sweep's copies look exactly like
#    abandoned ones and deleting them kills it. The first version of this
#    script did precisely that -- the dry run listed four directories that
#    belonged to a sweep in progress.
if pgrep -x cargo-mutants >/dev/null 2>&1; then
  say "a sweep is running: leaving its tree copies alone"
else
  for d in "${TMPDIR:-/tmp}"/cargo-mutants-*.tmp /data/tmp/cargo-mutants-*.tmp; do
    [ -d "$d" ] || continue
    # Age filter as well as the process check: a sweep started seconds ago may
    # not have its process visible under that exact name yet.
    if [ -z "$(find "$d" -maxdepth 0 -mmin "+$((KEEP_HOURS * 60))")" ]; then
      say "recent mutants copy, leaving alone: $d ($(size "$d"))"
      continue
    fi
    say "abandoned mutants copy: $d ($(size "$d"))"
    [ "$DRY_RUN" = 1 ] || rm -rf "$d"
  done
fi

say "free after:  $(df -h . | tail -1 | awk '{print $4}')"
