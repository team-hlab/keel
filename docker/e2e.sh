#!/usr/bin/env bash
# Full keel lifecycle against the REAL agents (Claude Code + Codex + Antigravity `agy`)
# in an isolated container. We can't run real agent *sessions* (no API key / OAuth), so
# this covers everything that doesn't need one: install → attach → per-agent hook
# verdicts → transparent shim exec → uninstall.
set -euo pipefail

fail() { echo "✗ $*" >&2; exit 1; }
ok()   { echo "✓ $*"; }
export HOME=/root

echo "== real agents present (offline --version, no auth) =="
timeout 30 claude --version >/dev/null 2>&1 || fail "claude --version"
timeout 30 codex  --version >/dev/null 2>&1 || fail "codex --version"
timeout 30 agy    --version >/dev/null 2>&1 || fail "agy --version"
ok "claude + codex + agy installed"

echo "== keel features =="
for f in autopermit branch-guard secret-scan audit-log session-banner; do
  keel features | grep -qx "$f" || fail "feature missing: $f"
done
ok "keel features lists all 5"

echo "== keel init (attach to all agents) =="
keel init
for a in claude codex agy; do
  [ -L "$HOME/.keel/bin/$a" ] || fail "shim symlink missing: $a"
done
ok "shims created for claude/codex/agy"

echo "== hooks applied to each agent's config =="
grep -q "keel run claude PreToolUse"      "$HOME/.claude/settings.json"      || fail "claude hook not applied"
grep -q "keel run codex PreToolUse"       "$HOME/.codex/hooks.json"          || fail "codex hook not applied"
grep -q "keel run antigravity PreToolUse" "$HOME/.gemini/config/hooks.json"  || fail "antigravity hook not applied"
grep -q "__keel"                          "$HOME/.claude/settings.json"      || fail "missing __keel marker"
ok "hooks applied + tagged (claude/codex/antigravity)"

echo "== keel doctor =="
keel doctor
keel doctor | grep -q "claude" || fail "doctor missing claude"

echo "== per-agent hook verdicts =="
proj=/work
mkdir -p "$proj/worktrees/f" "$proj/projects/foo/main" "$proj/.git"
echo 'ref: refs/heads/main' > "$proj/.git/HEAD"

verdict() { # platform stage json -> stdout (compact JSON)
  printf '%s' "$3" | KEEL_ROOT="$proj" keel run "$1" "$2"
}
P_RM='{"tool_name":"Bash","cwd":"'"$proj"'","tool_input":{"command":"rm -rf /"}}'
P_RD='{"tool_name":"Read","cwd":"'"$proj"'","tool_input":{"file_path":"a.md"}}'
P_SECRET='{"tool_name":"Read","cwd":"'"$proj"'","tool_input":{"file_path":"x/.env"}}'
P_WT='{"tool_name":"Write","cwd":"'"$proj"'","tool_input":{"file_path":"worktrees/f/a"}}'
P_MAIN='{"tool_name":"Write","cwd":"'"$proj"'","tool_input":{"file_path":"projects/foo/main/A"}}'
P_COMMIT='{"tool_name":"Bash","cwd":"'"$proj"'","tool_input":{"command":"git commit -m x"}}'

verdict claude PreToolUse "$P_RM"     | grep -q '"permissionDecision":"deny"'  || fail "claude rm -rf → deny"
verdict claude PreToolUse "$P_RD"     | grep -q '"permissionDecision":"allow"' || fail "claude read → allow"
verdict claude PreToolUse "$P_SECRET" | grep -q '"permissionDecision":"ask"'   || fail "claude secret → ask"
verdict claude PreToolUse "$P_WT"     | grep -q '"permissionDecision":"allow"' || fail "claude worktree → allow"
verdict claude PreToolUse "$P_MAIN"   | grep -q '"permissionDecision":"ask"'   || fail "claude in-repo write → ask"
verdict claude PreToolUse "$P_COMMIT" | grep -q '"permissionDecision":"deny"'  || fail "branch-guard commit-on-main → deny"
verdict claude PermissionRequest "$P_SECRET" | grep -q '{"continue":true}'     || fail "permissionRequest secret → defer"
verdict codex  PreToolUse "$P_RM"     | grep -q '"permissionDecision":"deny"'  || fail "codex rm -rf → deny"
verdict antigravity PreToolUse "$P_RM" | grep -q '"decision":"deny"'           || fail "antigravity rm -rf → deny"
ok "verdicts correct across claude/codex/antigravity"

echo "== transparent shim: running the agent goes through keel and execs the REAL binary =="
export PATH="$HOME/.keel/bin:$PATH"   # shim dir first → `claude` is now the keel shim
out=$(timeout 30 claude --version 2>&1 || true)
echo "$out" | grep -qE '[0-9]+\.[0-9]+' || fail "shim did not exec real claude (got: $out)"
ok "shim exec real claude → $out"
out=$(timeout 30 codex --version 2>&1 || true)
echo "$out" | grep -qE '[0-9]+\.[0-9]+' || fail "shim did not exec real codex (got: $out)"
ok "shim exec real codex"
out=$(timeout 30 agy --version 2>&1 || true)
echo "$out" | grep -qE '[0-9]+\.[0-9]+' || fail "shim did not exec real agy (got: $out)"
ok "shim exec real agy → $out"

echo "== keel uninstall (clean reversal) =="
keel uninstall
[ -e "$HOME/.keel/bin/claude" ] && fail "shim not removed" || ok "shims removed"
grep -q "__keel" "$HOME/.claude/settings.json" && fail "keel hooks not cleaned" || ok "hooks cleaned (settings preserved)"

echo
echo "✅ keel docker e2e PASSED"
