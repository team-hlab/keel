# Attaching keel to an agent

`keel install <platform>` merges the hook registration into that agent's config file —
**idempotently** (re-running never duplicates) and **non-destructively** (it preserves
your existing config). Run it from your project root.

```sh
pip install keel

keel install claude          # → .claude/settings.json
keel install codex           # → .codex/hooks.json
keel install antigravity     # → .agents/hooks.json
```

Options:

| Flag | Meaning |
|---|---|
| `--print` | Dry run — print the merged config, write nothing |
| `--dir DIR` | Target a project root other than the current directory |
| `--command CMD` | Override the hook command prefix (default `keel`) |

Preview before writing:

```sh
keel install claude --print
```

## What it registers

For each platform it wires three stages, with a matcher on the tool stages:

- **PreToolUse** — `keel run <platform> PreToolUse` (matcher: `Read|Glob|Grep|Edit|MultiEdit|Write|NotebookEdit|Bash`)
- **PermissionRequest** — `keel run <platform> PermissionRequest` (same matcher)
- **SessionStart** — `keel run <platform> SessionStart` (no matcher)

## If `keel` isn't on PATH

The registered command is `keel …`, which assumes `pip install keel` put the console
script on PATH in the environment the agent spawns. If that's not guaranteed, register the
**preflight shim** instead — it resolves Python and fails open if it's missing:

```sh
keel install claude --command "sh /abs/path/to/keel/bin/keel.sh"
```

## Verify it's live

```sh
echo '{"tool_name":"Bash","cwd":"'$PWD'","tool_input":{"command":"rm -rf /"}}' \
  | keel run claude PreToolUse
# → {"hookSpecificOutput": {... "permissionDecision": "deny" ...}}
```

## Platform notes

- **Claude Code** — verified against `code.claude.com/docs` (hooks & permissions).
- **Codex** / **Antigravity** — the registration shapes are best-effort against their
  ~May-2026 hook APIs (Antigravity's docs weren't machine-verifiable). Confirm the config
  path and schema against the live docs for your version before relying on them.
