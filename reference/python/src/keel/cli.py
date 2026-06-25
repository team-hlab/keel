"""keel CLI — `keel run <platform> <stage>` is the hook entrypoint; `keel install` attaches it."""

import json
import os
import sys

from keel import install
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
    "usage:\n"
    "  keel run <claude|codex|antigravity> <stage>   # hook entrypoint\n"
    "  keel install <claude|codex|antigravity>        # attach keel to that agent\n"
    "        [--print] [--dir DIR] [--command CMD]\n"
    "  keel features | doctor\n"
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


def _opt(args, name):
    """Read `--name value` from a flat arg list (or None)."""
    if name in args:
        i = args.index(name)
        if i + 1 < len(args):
            return args[i + 1]
    return None


def _install(args):
    platform = args[0]
    rest = args[1:]
    root = _opt(rest, "--dir") or os.getcwd()
    prefix = _opt(rest, "--command") or "keel"
    if "--print" in rest:
        path, merged = install.plan(platform, root, prefix)
        sys.stdout.write(json.dumps(merged, indent=2) + "\n")
        sys.stderr.write(f"(dry run) would write {path}\n")
    else:
        path = install.apply(platform, root, prefix)
        sys.stderr.write(
            f"attached keel to {platform}: wrote {path}\n"
            f"  ensure `{prefix}` is on PATH (pip install keel) or pass "
            f"--command 'sh /path/to/keel/bin/keel.sh'\n"
        )


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        sys.stderr.write(USAGE)
        return 0
    cmd = argv[0]

    # the hook path must NEVER break the agent → fail open
    if cmd == "run" and len(argv) >= 3 and argv[1] in ADAPTERS:
        try:
            _run(argv[1], argv[2])
        except Exception:
            pass
        return 0

    # management commands surface their errors normally
    if cmd == "install" and len(argv) >= 2 and argv[1] in install.PLATFORMS:
        _install(argv[1:])
        return 0
    if cmd == "features":
        for c in registry.ALL:
            sys.stdout.write(c.name + "\n")
        return 0
    if cmd == "doctor":
        sys.stdout.write(f"keel: Python {sys.version.split()[0]} ok\n")
        return 0

    sys.stderr.write(USAGE)
    return 2
