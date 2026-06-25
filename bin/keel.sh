#!/bin/sh
# keel.sh — runtime-preflight shim for clone-based use (guidance-only; never installs).
# Resolves a working Python and runs `python -m keel` from this checkout. For pip
# installs, use the `keel` console script directly instead.
set -u

MIN_MAJOR=3
MIN_MINOR=8
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=$(cd -- "$DIR/.." && pwd)

find_python() {
  if [ "${KEEL_PYTHON:-}" != "" ]; then
    "$KEEL_PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= ('"$MIN_MAJOR"','"$MIN_MINOR"') else 1)' 2>/dev/null \
      && { printf '%s' "$KEEL_PYTHON"; return 0; }
    return 1
  fi
  for c in python3 python; do
    if command -v "$c" >/dev/null 2>&1 && \
       "$c" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= ('"$MIN_MAJOR"','"$MIN_MINOR"') else 1)' 2>/dev/null; then
      printf '%s' "$c"; return 0
    fi
  done
  return 1
}

install_hint() {
  case "$(uname -s 2>/dev/null || echo unknown)" in
    Darwin) echo "  brew install python      # or: xcode-select --install" ;;
    Linux)
      if   command -v apt    >/dev/null 2>&1; then echo "  sudo apt install -y python3"
      elif command -v dnf    >/dev/null 2>&1; then echo "  sudo dnf install -y python3"
      elif command -v pacman >/dev/null 2>&1; then echo "  sudo pacman -S python"
      else echo "  install Python ${MIN_MAJOR}.${MIN_MINOR}+ from https://python.org"; fi ;;
    *) echo "  install Python ${MIN_MAJOR}.${MIN_MINOR}+ from https://python.org" ;;
  esac
}

if PY=$(find_python); then
  PYTHONPATH="$REPO/src${PYTHONPATH:+:$PYTHONPATH}" exec "$PY" -m keel "$@"
fi

# no Python — fail open for hook invocations so the agent is never blocked
case "${1:-}" in
  run) exit 0 ;;
  *)
    { echo "⚠ keel: Python ${MIN_MAJOR}.${MIN_MINOR}+ not found — harness disabled."; install_hint; } >&2
    exit 1 ;;
esac
