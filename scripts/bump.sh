#!/bin/sh
# Bump keel's version. Cargo.toml is the single source of truth — the binary
# (`keel version`), the release workflow's gate, and the Homebrew formula all
# derive from it.
#
#   scripts/bump.sh <new-version>      e.g. scripts/bump.sh 0.1.1
#
# Then: update CHANGELOG.md, open a PR, and merging it to develop triggers the
# release (see docs/RELEASING.md). SemVer: patch = fixes, minor = features,
# major = breaking policy/CLI changes.
set -eu

V="${1:?usage: bump.sh <new-version, e.g. 0.1.1>}"
case "$V" in
  [0-9]*.[0-9]*.[0-9]*) : ;;
  *) echo "bump.sh: '$V' is not a SemVer x.y.z version" >&2; exit 2 ;;
esac

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
toml="$root/Cargo.toml"

old=$(grep -E '^version = ' "$toml" | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
# replace only the first `version = "..."` (the [package] one; not rust-version)
awk -v v="$V" '
  /^version = / && !done { sub(/"[^"]+"/, "\"" v "\""); done=1 }
  { print }
' "$toml" > "$toml.tmp" && mv "$toml.tmp" "$toml"

# refresh Cargo.lock's keel entry, if cargo is available
if command -v cargo >/dev/null 2>&1; then
  ( cd "$root" && cargo update -p keel --precise "$V" >/dev/null 2>&1 || cargo check --quiet >/dev/null 2>&1 || true )
fi

echo "keel version: $old -> $V"
echo "next: update CHANGELOG.md, commit, open a PR; merging to develop releases it."
