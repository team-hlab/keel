#!/usr/bin/env bash
# carryover-e2e.sh <claude|codex|antigravity>
#
# REAL end-to-end test for keel carryover: drive the actual agent CLI through a full
# capture→inject cycle and assert on the keel-owned store — no synthetic payloads.
#
#   session 1  establishes a unique marker  → the Stop/SessionEnd hook must capture it
#   session 2  a fresh session              → the SessionStart/PreInvocation hook must
#                                             inject the digest so the model recalls it
#
# Exit: 0 PASS · 1 FAIL · 2 SKIP (CLI not installed / prerequisite missing).
# Isolated: uses a throwaway KEEL_HOME + temp git project; never touches your real store.
set -uo pipefail

AGENT="${1:-}"
[ -n "$AGENT" ] || { echo "usage: $0 <claude|codex|antigravity>"; exit 2; }
KEEL_BIN="${KEEL_BIN:-$(cd "$(dirname "$0")/.." && pwd)/target/release/keel}"
[ -x "$KEEL_BIN" ] || { echo "SKIP: keel binary not at $KEEL_BIN — run: cargo build --release"; exit 2; }

case "$AGENT" in
  claude)      CLI=claude ;;
  codex)       CLI=codex  ;;
  antigravity) CLI=agy    ;;
  *) echo "unknown agent: $AGENT"; exit 2 ;;
esac
command -v "$CLI" >/dev/null || { echo "SKIP[$AGENT]: '$CLI' not installed — cannot run a real session"; exit 2; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
export KEEL_HOME="$WORK/home"
PROJ="$WORK/proj"; mkdir -p "$PROJ/.git"; echo "ref: refs/heads/main" > "$PROJ/.git/HEAD"
printf '{"features":{"carryover":{"enabled":true}}}' > "$PROJ/.keel.json"   # opt in
cd "$PROJ"
MARK="CARRYOVER-$$-${RANDOM}"   # unique token session 1 states, session 2 must echo

# --- wire the carryover hooks for this agent (best-effort per-vendor config) ----------
cmd() { echo "$KEEL_BIN carryover-hook $AGENT $1"; }
hook() { printf '"%s":[{"hooks":[{"type":"command","command":"%s"}]}]' "$1" "$(cmd "$1")"; }
case "$AGENT" in
  claude)      mkdir -p "$PROJ/.claude"; DIR="$PROJ/.claude/settings.local.json"
               printf '{"hooks":{%s,%s,%s}}' "$(hook SessionStart)" "$(hook Stop)" "$(hook SessionEnd)" > "$DIR" ;;
  codex)       mkdir -p "$PROJ/.codex"; DIR="$PROJ/.codex/hooks.json"
               printf '{"hooks":{%s,%s,%s,%s}}' "$(hook SessionStart)" "$(hook UserPromptSubmit)" "$(hook Stop)" "$(hook PreToolUse)" > "$DIR" ;;
  antigravity) mkdir -p "$PROJ/.agents"; DIR="$PROJ/.agents/hooks.json"
               printf '{"hooks":{%s,%s,%s}}' "$(hook PreInvocation)" "$(hook Stop)" "$(hook PreToolUse)" > "$DIR" ;;
esac

# --- per-agent headless invocation ----------------------------------------------------
run_session() {
  case "$AGENT" in
    claude)      claude -p "$1" ;;
    codex)       codex exec "$1" ;;      # best-effort headless form; adjust when verified
    antigravity) agy -p "$1" ;;          # best-effort
  esac
}

snap() { find "$KEEL_HOME/.keel/carryover" -name snapshot.json 2>/dev/null | head -1; }
fail() { echo "FAIL[$AGENT]: $1"; exit 1; }

echo "── [$AGENT] session 1: establish marker $MARK ──"
run_session "Remember this exact token for later: $MARK . Reply in one short sentence acknowledging it. Do not use any tools." >/dev/null 2>&1

S="$(snap)"
[ -n "$S" ] || fail "session 1 produced no snapshot — the capture hook did not fire (agent may not trust project hooks headlessly)"
grep -q "$MARK" "$S" || { echo "--- snapshot ---"; cat "$S"; fail "marker not captured in the store"; }
echo "  ✓ capture: marker present in $KEEL_HOME/.keel/carryover/*/snapshot.json"

echo "── [$AGENT] session 2: fresh session must recall via injected carryover ──"
OUT="$(run_session "Using ONLY restored/carryover context provided at session start, repeat the exact token you were previously asked to remember. If you have no such context, reply exactly NONE. Do not use tools." 2>/dev/null)"
echo "$OUT" | grep -q "$MARK" || { echo "--- session 2 output ---"; echo "$OUT"; fail "session 2 did not recall the marker (injection not received)"; }
echo "  ✓ inject: session 2 recalled the marker from carryover"

echo "PASS[$AGENT]: real capture→inject cycle verified end-to-end"
