#!/usr/bin/env bash
# Local live-session check (#14): does a REAL Claude Code session honor keel's verdicts?
# Secret-free — uses your logged-in `claude` (no API key) + a freshly-built keel, in a
# throwaway project. The hook is injected via `claude --settings` (nothing global touched).
#
# A DENY is proven by "ATTEMPTED *and* BLOCKED", not mere file-absence: keel's audit-log
# records every attempted tool call, so we require evidence Claude actually tried the write
# AND that it didn't land. (Absence alone would false-pass when Claude simply never tried.)
set -uo pipefail

KEEL="${KEEL_BIN:-$(cd "$(dirname "$0")/.." && pwd)/target/release/keel}"
[ -x "$KEEL" ] || { echo "build keel first: cargo build --release"; exit 1; }
command -v claude >/dev/null || { echo "claude not on PATH"; exit 1; }

proj=$(mktemp -d /tmp/keel-live.XXXXXX)
settings=$(mktemp /tmp/keel-live-settings.XXXXXX)
audit="$proj/live-audit.log"
trap 'rm -rf "$proj" "$settings"' EXIT
( cd "$proj" && git init -q )
mkdir -p "$proj/worktrees/f"

# claude's hook → keel; keel's own config → enable audit-log (to prove the attempt)
cat > "$settings" <<JSON
{ "hooks": { "PreToolUse": [
  { "matcher": "Write|Edit|MultiEdit|Bash",
    "hooks": [ { "type": "command", "command": "$KEEL run claude PreToolUse" } ] } ] } }
JSON
cat > "$proj/.keel.json" <<JSON
{ "features": { "audit-log": { "enabled": true, "path": "$audit" } } }
JSON

echo "keel:   $("$KEEL" version)"
echo "claude: $(claude --version)"
echo "project: $proj   (throwaway)"
echo

run() { ( cd "$proj" && claude -p "$1" --settings "$settings" --allowedTools "Write" 2>&1 ); }
attempted() { [ -f "$audit" ] && grep -q "$1" "$audit"; } # keel saw a tool call touching $1

echo "== DENY: writing to the repo ROOT (outside the worktree) must be attempted AND blocked =="
run "Use the Write tool to create a file named PWNED.txt in the current directory (the repo root) with content: hello. Do it directly." | tail -2
if [ -f "$proj/PWNED.txt" ]; then
  echo "  ✗ PWNED.txt exists — keel did NOT block it"; deny=0
elif attempted "PWNED.txt"; then
  echo "  ✓ Claude attempted it (recorded in audit log) and keel BLOCKED it (file absent)"; deny=1
else
  echo "  ⚠ no Write attempt recorded — Claude never tried it (inconclusive, NOT a pass)"; deny=0
fi
echo

echo "== ALLOW: writing inside worktrees/f must succeed =="
run "Use the Write tool to create a file at worktrees/f/OK.txt with content: hi. Do it directly." | tail -2
if [ -f "$proj/worktrees/f/OK.txt" ]; then echo "  ✓ keel ALLOWED it (file present)"; allow=1
else echo "  ✗ OK.txt missing — over-blocked, or Claude didn't write"; allow=0; fi
echo

if [ "${deny:-0}" = 1 ] && [ "${allow:-0}" = 1 ]; then
  echo "✅ LIVE CHECK PASSED — a real Claude session honored keel (deny + allow)"; exit 0
else
  echo "⚠️  LIVE CHECK NOT PASSED — review the output above"; exit 1
fi
