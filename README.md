# keel

**Write your agent's safety policy once, run it on any agent.**

`keel` is a lean hook harness for first-party AI coding agents — **Claude Code**, **OpenAI Codex**, and **Google Antigravity**. It sits between the agent and its tools and, on every tool call, returns one of **auto-permit / auto-deny / ask-the-user**, decided by pluggable *features*.

- **Zero external libraries** — pure Python stdlib + a tiny `sh` preflight. `dependencies = []`, enforced by a test.
- **One policy, every agent** — the decision logic is a pure core; each agent is a thin *adapter*. The dependency arrow goes `keel → harness`, never the other way.
- **Fails open** — a bug or a missing Python runtime never blocks the agent; it falls back to the platform's normal prompt.
- **Extensible** — features implement a ~10-line interface. Add your org's rules without forking the engine.

## Why

Each agent has its own hook system, JSON schema, and config — but the *rule you want* ("don't write outside a worktree", "never read `.env` without asking", "block `git push --force`") is identical everywhere. Without keel you re-implement it three times in three dialects. And default agent permissions force a bad trade: prompt-for-everything (fatigue) or full-auto (unsafe). keel auto-permits the boring-safe, hard-denies the catastrophic, and only interrupts you for the genuinely ambiguous.

You **don't** need keel if you use a single agent and its built-in allow/deny lists already cover you. It earns its place when you use more than one agent, your policy is path-/command-aware beyond static globs, or you want auditing and custom rules.

## Install

```sh
pip install keel          # or: pipx install keel
```

Zero external dependencies, so it installs instantly and can't pull in anything surprising.

## Wire it into an agent

The hook command is always `keel run <platform> <stage>`. Example — Claude Code (`.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Read|Glob|Grep|Edit|MultiEdit|Write|NotebookEdit|Bash",
        "hooks": [{ "type": "command", "command": "keel run claude PreToolUse" }] }
    ],
    "PermissionRequest": [
      { "matcher": "Read|Glob|Grep|Edit|MultiEdit|Write|NotebookEdit|Bash",
        "hooks": [{ "type": "command", "command": "keel run claude PermissionRequest" }] }
    ],
    "SessionStart": [
      { "hooks": [{ "type": "command", "command": "keel run claude SessionStart" }] }
    ]
  }
}
```

Codex (`.codex/hooks.json`) and Antigravity (`.agents/hooks.json`) use the same command with `codex` / `antigravity` in place of `claude`. (Codex and Antigravity adapters are best-effort against their ~May-2026 hook APIs — verify against their live docs.)

If Python might be missing in the agent's environment, register the preflight shim instead — `sh <path>/bin/keel.sh run claude PreToolUse` — which resolves Python and fails open.

## Built-in features

| Feature | Stage(s) | What it does |
|---|---|---|
| **autopermit** | PreToolUse, PermissionRequest | auto-permit non-secret reads & worktree writes & safe shell; `ask` on secrets; `deny` writes outside a worktree and catastrophic commands |
| **branch-guard** | PreToolUse | deny mutating `git` commands while HEAD is on a protected branch (`main`/`master`/`develop`) |
| **secret-scan** | PreToolUse | `ask` when a write's *content* looks like a credential (AWS/GitHub/Slack tokens, PEM keys) |
| **audit-log** | PreToolUse, PostToolUse | append every tool call + stage to a JSONL log (observer) |
| **session-banner** | SessionStart | print active features + runtime status to stderr |

Verdicts aggregate **most-restrictive-wins**: `deny > ask > pass > allow`. Configure/disable features in `.keel.json`:

```json
{ "features": { "branch-guard": { "protected": ["main", "release"] },
                "audit-log": { "enabled": false } } }
```

## Write a feature

```python
from keel.features.base import Feature
from keel.core.model import Verdict, DENY

class NoFridayDeploys(Feature):
    name = "no-friday-deploys"
    def stages(self): return {"PreToolUse"}
    def evaluate(self, event):
        if event.tool == "Bash" and "deploy" in (event.command or ""):
            return Verdict(DENY, "no deploys on a Friday", self.name)
        return None   # abstain
```

## Develop

```sh
pip install -e .                 # dev convenience only; users just `pip install keel`
python -m pytest                 # (or run the stdlib unittest files directly)
python tests/test_no_external_deps.py
```

## License

MIT © hubtwork
