"""keel CLI — `keel run <platform> <stage>` is the hook entrypoint."""

import sys

from keel.adapters import antigravity, claude_code, codex
from keel.core import engine, registry, runtime

ADAPTERS = {
    "claude": claude_code,
    "claude-code": claude_code,
    "codex": codex,
    "antigravity": antigravity,
}

USAGE = (
    "keel — a permission/policy harness for AI coding agents.\n"
    "Every tool call passes through keel, which auto-permits, auto-denies, or asks you.\n"
    "Write the policy once; run it on Claude Code, Codex, or Antigravity.\n\n"
    "usage: keel run <claude|codex|antigravity> <stage> | features | doctor\n"
)


def _run(platform, stage):
    adapter = ADAPTERS[platform]
    raw = runtime.read_input()
    if not isinstance(raw, dict):
        raw = {}
    event = adapter.parse(raw, stage)
    event.config = runtime.load_config(event.root)
    features = registry.load(event.config)
    verdict = engine.run(event, features)
    sys.stdout.write(adapter.render(verdict, stage))


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        sys.stderr.write(USAGE)
        return 0
    cmd = argv[0]
    try:
        if cmd == "run" and len(argv) >= 3 and argv[1] in ADAPTERS:
            _run(argv[1], argv[2])
        elif cmd == "features":
            for c in registry.ALL:
                sys.stdout.write(c.name + "\n")
        elif cmd == "doctor":
            sys.stdout.write(f"keel: Python {sys.version.split()[0]} ok\n")
        else:
            sys.stderr.write(USAGE)
            return 2
    except SystemExit:
        raise
    except Exception:
        # fail-open: a hook must never break the agent
        pass
    return 0
