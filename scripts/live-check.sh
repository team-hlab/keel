#!/usr/bin/env bash
# Local live-session check (#14): does a REAL Claude Code session honor keel's verdicts?
# Uses your logged-in `claude` (no API key) and a freshly-built keel. Touches NOTHING
# global — the hook is injected per-run via `claude --settings`, in a throwaway project.
set -uo pipefail

KEEL="${KEEL_BIN:-$(cd "$(dirname "$0")/.." && pwd)/target/release/keel}"
[ -x "$KEEL" ] || { echo "build keel first: cargo build --release"; exit 1; }

proj=$(mktemp -d /tmp/keel-live.XXXXXX)
settings=$(mktemp /tmp/keel-settings.XXXXXX)
trap 'rm -rf "$proj" "$settings"' EXIT
( cd "$proj" && git init -q )
mkdir -p "$proj/worktrees/f"

cat > "$settings" <<JSON
{ "hooks": { "PreToolUse": [
  { "matcher": "Write|Edit|MultiEdit|Bash",
    "hooks": [ { "type": "command", "command": "$KEEL run claude PreToolUse" } ] } ] } }
JSON

echo "keel:   $("$KEEL" version)"
echo "claude: $(claude --version)"
echo "project: $proj   (throwaway)"
echo

run() { ( cd "$proj" && claude -p "$1" --settings "$settings" --allowedTools "Write" 2>&1 ); }

echo "== DENY: write to the repo ROOT (outside the worktree) must be BLOCKED =="
run "Use the Write tool to create a file named PWNED.txt in the current directory (the repo root) with the exact content: hello. Do it directly." | tail -2
if [ -f "$proj/PWNED.txt" ]; then echo "  ✗ PWNED.txt exists — keel did NOT block it"; deny=0
else echo "  ✓ blocked — PWNED.txt absent"; deny=1; fi
echo

echo "== ALLOW: write inside worktrees/f must be PERMITTED =="
run "Use the Write tool to create a file at worktrees/f/OK.txt with the exact content: hi. Do it directly." | tail -2
if [ -f "$proj/worktrees/f/OK.txt" ]; then echo "  ✓ allowed — OK.txt present"; allow=1
else echo "  ✗ OK.txt missing — over-blocked, or Claude didn't write"; allow=0; fi
echo

if [ "${deny:-0}" = 1 ] && [ "${allow:-0}" = 1 ]; then
  echo "✅ LIVE CHECK PASSED — a real Claude session honored keel (deny + allow)"
else
  echo "⚠️  INCONCLUSIVE — review the output above"
fi
