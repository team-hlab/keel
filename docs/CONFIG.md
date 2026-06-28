# Configuration — `.keel.json`

keel reads optional config from **`$KEEL_CONFIG`** if set, otherwise **`<root>/.keel.json`**,
otherwise built-in defaults. `<root>` is `$KEEL_ROOT` or the nearest `.git` ancestor of the
tool call's `cwd`. **Everything is optional** — keel works with no config file, and any
missing key falls back to its default.

## Shape (all values shown are the defaults)

```json
{
  "features": {
    "autopermit": {
      "enabled": true,
      "sensitiveFilePatterns": [".env*", "*.key", "*.pem", "credentials*", "*secret*"],
      "worktrees": "worktrees",
      "projects": "projects"
    },
    "branch-guard":   { "enabled": true, "protected": ["main", "master", "develop"] },
    "secret-scan":    { "enabled": true },
    "audit-log":      { "enabled": false, "path": ".keel/audit.log" },
    "session-banner": { "enabled": true }
  }
}
```

## Feature toggles

Every feature accepts **`enabled`** (bool). Gating features default **on**; `audit-log`
defaults **off** because it writes files (opt-in).

| Feature | Default | Stage(s) |
|---|---|---|
| `autopermit` | on | PreToolUse, PermissionRequest |
| `branch-guard` | on | PreToolUse |
| `secret-scan` | on | PreToolUse |
| `audit-log` | **off** | PreToolUse |
| `session-banner` | on | SessionStart |

```json
{ "features": { "audit-log": { "enabled": true }, "session-banner": { "enabled": false } } }
```

## Per-feature options

### `autopermit`
| Key | Type | Default | Meaning |
|---|---|---|---|
| `sensitiveFilePatterns` | string[] | `[".env*","*.key","*.pem","credentials*","*secret*"]` | Basename globs (`*`, `?`, case-insensitive). A read/write whose **filename** matches → **ask**. |
| `worktrees` | string | `"worktrees"` | Path-segment name treated as a safe write area — writes under `<root>/worktrees/…` → **allow**. |
| `projects` | string | `"projects"` | Enables nested layouts: writes under `<root>/projects/*/worktrees/…` (one or two levels) are also allowed. |
| `protectedWrites` | `"ask"` \| `"deny"` | `"ask"` | What to do with an in-repo write **outside** the worktree areas. `"ask"` (default) confirms; `"deny"` is strict worktree-confinement. Catastrophic commands + protected-branch git **always deny** regardless. |

Outside those areas, writes **inside** `<root>` → **ask** (or **deny** with `protectedWrites:"deny"`); writes **outside** `<root>` → **pass** (defer). Reads of non-sensitive files → **allow**. Shell commands are parsed segment-by-segment (chains, pipes, subshells, `cd`, `git -C`, redirects).

### `branch-guard`
| Key | Type | Default | Meaning |
|---|---|---|---|
| `protected` | string[] | `["main","master","develop"]` | Mutating git (`commit`/`push`/`merge`/`rebase`/`reset`/…) while `HEAD` is on one of these → **deny**. |

### `secret-scan`
No options (just `enabled`). Flags writes whose **content** matches built-in credential
patterns — AWS key id, PEM private key, GitHub/Slack tokens, `api_key=…`/`secret=…` — → **ask**.

### `audit-log`
| Key | Type | Default | Meaning |
|---|---|---|---|
| `path` | string | `<root>/.keel/audit.log` | JSONL file; one record (ts, stage, tool, cwd, file/command) appended per PreToolUse call. |

### `session-banner`
No options (just `enabled`). Prints the active feature list to **stderr** at SessionStart.

## Environment overrides

| Variable | Effect |
|---|---|
| `KEEL_CONFIG` | Path to the config file (overrides `<root>/.keel.json`). |
| `KEEL_ROOT` | Force the project root (otherwise the nearest `.git`). |
| `KEEL_HOME` | Override `$HOME` for install/shim paths (mainly for testing). |

## Notes

- Verdicts across features aggregate **most-restrictive-wins**: `deny > ask > pass > allow`.
- keel **fails open**: with no config file (or an unreadable one) it uses defaults and never blocks the agent on its own error.
