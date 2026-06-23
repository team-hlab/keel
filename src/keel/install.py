"""Attach keel to a first-party agent by merging hook registration into its config.

Idempotent: re-running never duplicates entries. Merges into existing config rather
than clobbering it. Claude Code is verified; Codex/Antigravity shapes are best-effort
against their ~May-2026 hook APIs — verify before relying on them.
"""

import json
import os

# tools keel should intercept (file tools + Bash)
TOOL_MATCHER = "Read|Glob|Grep|Edit|MultiEdit|Write|NotebookEdit|Bash"

# config file (relative to project root) + which adapter family the platform uses
PLATFORMS = {
    "claude": ".claude/settings.json",
    "codex": ".codex/hooks.json",
    "antigravity": ".agents/hooks.json",
}

# stages to register: (stage, needs_tool_matcher)
_STAGES = [("PreToolUse", True), ("PermissionRequest", True), ("SessionStart", False)]


def command_for(prefix, platform, stage):
    return f"{prefix} run {platform} {stage}"


def _hooks_block_has(entries, command):
    for entry in entries or []:
        for hook in entry.get("hooks", []):
            if isinstance(hook, dict) and hook.get("command") == command:
                return True
    return False


def _merge_hooks_style(existing, platform, prefix):
    """Claude/Codex shape: { "hooks": { "<stage>": [ {matcher?, hooks:[{type,command}]} ] } }."""
    cfg = dict(existing) if isinstance(existing, dict) else {}
    hooks = cfg.setdefault("hooks", {})
    for stage, needs_matcher in _STAGES:
        arr = hooks.setdefault(stage, [])
        command = command_for(prefix, platform, stage)
        if _hooks_block_has(arr, command):
            continue
        entry = {"hooks": [{"type": "command", "command": command}]}
        if needs_matcher:
            entry = {"matcher": TOOL_MATCHER, **entry}
        arr.append(entry)
    return cfg


def _merge_antigravity(existing, platform, prefix):
    """Antigravity shape (best-effort): { "<stage>": [ {"command": "..."} ] }."""
    cfg = dict(existing) if isinstance(existing, dict) else {}
    for stage, _ in _STAGES:
        arr = cfg.setdefault(stage, [])
        command = command_for(prefix, platform, stage)
        if any(isinstance(h, dict) and h.get("command") == command for h in arr):
            continue
        arr.append({"command": command})
    return cfg


def _builder(platform):
    return _merge_antigravity if platform == "antigravity" else _merge_hooks_style


def config_path(platform, root):
    return os.path.join(root, PLATFORMS[platform])


def plan(platform, root, prefix="keel"):
    """Return (path, merged_config) without writing — used for dry-run / preview."""
    path = config_path(platform, root)
    try:
        with open(path, encoding="utf-8") as f:
            existing = json.load(f)
    except (OSError, ValueError):
        existing = {}
    merged = _builder(platform)(existing, platform, prefix)
    return path, merged


def apply(platform, root, prefix="keel"):
    """Merge + write the platform's hook config. Returns the path written."""
    path, merged = plan(platform, root, prefix)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(merged, f, indent=2)
        f.write("\n")
    return path
