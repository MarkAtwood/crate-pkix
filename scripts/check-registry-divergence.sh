#!/usr/bin/env bash
#
# Fails if any crate in the workspace carries a version number that is
# already published to crates.io with different *consumer-visible*
# content.
#
# WHAT THIS GATE CATCHES
#
#   Editing a published crate's manifest, sources or build script without
#   bumping its version. The repo then says "this is pkix-foo 1.2.3"
#   while crates.io serves different bytes under that same name and
#   version, and the two can never be reconciled: crates.io versions are
#   immutable, so the only remedies are a yank or a new version.
#   pkix-dane 0.2.0 shipped this way and had to be yanked.
#
#   Those three are the hard failures because they are what a dependent
#   compiles. If they match, every consumer of that version gets what
#   this repo says they get.
#
# WHAT IT ONLY REPORTS
#
#   Divergence in tests, fixtures, examples and READMEs, which no
#   dependent ever compiles. These drift routinely and legitimately: a
#   test-only fix lands without a release, and older tarballs still carry
#   the CHANGELOG.md files this workspace has since dropped. Worth
#   knowing before cutting a release, not worth blocking a commit.
#
# WHAT IT DOES NOT CATCH
#
#   A repo version that is simply ahead of the registry. That is the
#   normal state of unreleased work and is always allowed. The invariant
#   is only that a version number, once published, stops being editable:
#   change a published crate and the version must move in the same
#   commit.
#
#   It also says nothing about whether a release is a correct semver
#   step. Deciding patch vs minor stays a human call.
#
# The manifest comparison uses Cargo.toml.orig from the tarball, which
# cargo stores verbatim, rather than the published Cargo.toml, which
# cargo rewrites during packaging (workspace inheritance resolved,
# dependency tables normalised).
#
set -euo pipefail

cd "$(dirname "$0")/.."

command -v jq >/dev/null || { echo "error: jq is required" >&2; exit 2; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

failed=()
noted=()
checked=0
unreleased=0

# Untracked build detritus on the repo side, never in a tarball.
ignore=(-x target -x __pycache__ -x '*.pyc')

# `publish` is null for a publishable crate and [] for publish = false.
while IFS=$'\t' read -r name version dir; do
    url="https://static.crates.io/crates/${name}/${name}-${version}.crate"
    code=$(curl -sSL -o "$work/${name}.crate" -w '%{http_code}' "$url" || echo 000)

    case "$code" in
        200) : ;;
        403|404)
            # Not published at this version: unreleased work, which is fine.
            unreleased=$((unreleased + 1))
            continue
            ;;
        *)
            echo "error: fetching ${name} ${version} from crates.io failed (HTTP ${code})" >&2
            echo "       this gate cannot pass without reaching the registry" >&2
            exit 2
            ;;
    esac

    checked=$((checked + 1))
    mkdir -p "$work/$name"
    tar xzf "$work/${name}.crate" -C "$work/$name"
    pub="$work/$name/${name}-${version}"

    # --- what a dependent compiles: hard failure ---------------------
    hard=""
    m=$(diff "$pub/Cargo.toml.orig" "$dir/Cargo.toml" 2>&1 || true)
    [ -n "$m" ] && hard+="--- Cargo.toml (published Cargo.toml.orig -> repo) ---"$'\n'"$m"$'\n'
    s=$(diff -r "${ignore[@]}" "$pub/src" "$dir/src" 2>&1 || true)
    [ -n "$s" ] && hard+="--- src/ (published -> repo) ---"$'\n'"$s"$'\n'
    if [ -f "$pub/build.rs" ] || [ -f "$dir/build.rs" ]; then
        b=$(diff "$pub/build.rs" "$dir/build.rs" 2>&1 || true)
        [ -n "$b" ] && hard+="--- build.rs (published -> repo) ---"$'\n'"$b"$'\n'
    fi

    # --- everything else published: report only ----------------------
    rest=$(
        diff -rq "${ignore[@]}" \
            -x Cargo.toml -x Cargo.toml.orig -x Cargo.lock \
            -x .cargo_vcs_info.json -x src -x build.rs \
            "$pub" "$dir" 2>&1 || true
    )

    if [ -n "$hard" ]; then
        failed+=("$name $version")
        echo "=============================================================="
        echo "FAIL: ${name} ${version} is published with different code"
        echo "=============================================================="
        printf '%s' "$hard" | head -60
        echo
    elif [ -n "$rest" ]; then
        noted+=("$name $version")
        echo "note: ${name} ${version} matches as compiled, but differs elsewhere:"
        printf '%s\n' "$rest" | sed 's/^/      /' | head -10
    fi
done < <(
    cargo metadata --no-deps --format-version 1 |
        jq -r '.packages[]
               | select(.publish == null)
               | [.name, .version, (.manifest_path | rtrimstr("/Cargo.toml"))]
               | @tsv'
)

echo
echo "checked ${checked} published crate version(s); ${unreleased} carry unreleased versions"
[ ${#noted[@]} -gt 0 ] && echo "${#noted[@]} differ only in files no dependent compiles (see notes above)"

if [ ${#failed[@]} -gt 0 ]; then
    cat >&2 <<EOF

${#failed[@]} crate(s) are published under the same version with different code:
$(printf '  %s\n' "${failed[@]}")

Bump the version of each crate listed above. The registry copy cannot be
changed, so the repo has to stop claiming to be it. Publishing the new
version is a separate decision; the bump alone restores the invariant.
EOF
    exit 1
fi

echo "no crate claims a published version whose code it does not match"
