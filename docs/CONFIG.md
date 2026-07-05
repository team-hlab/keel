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
    "session-banner": { "enabled": true }
  },
  "log": { "enabled": false, "path": "~/.keel/decisions.jsonl", "maxSizeMb": 5 }
}
```

## Feature toggles

Every feature accepts **`enabled`** (bool); all default **on**.

| Feature | Default | Stage(s) |
|---|---|---|
| `autopermit` | on | PreToolUse, PermissionRequest |
| `branch-guard` | on | PreToolUse |
| `secret-scan` | on | PreToolUse |
| `session-banner` | on | SessionStart |

```json
{ "features": { "session-banner": { "enabled": false } } }
```

## Per-feature options

### `autopermit`
| Key | Type | Default | Meaning |
|---|---|---|---|
| `sensitiveFilePatterns` | string[] | `[".env*","*.key","*.pem","credentials*","*secret*"]` | Basename globs (`*`, `?`, case-insensitive). A read/write whose **filename** matches → **ask**. |
| `worktrees` | string | `"worktrees"` | Path-segment name treated as a safe write area — writes under `<root>/worktrees/…` → **allow**. |
| `projects` | string | `"projects"` | Enables nested layouts: writes under `<root>/projects/*/worktrees/…` (one or two levels) are also allowed. |
| `protectedWrites` | `"ask"` \| `"deny"` \| `"pass"` \| `"allow"` | `"ask"` | What to do with an in-repo write **outside** the worktree areas. `"ask"` (default) confirms — great interactively, but **blocks headless/autonomous runs** (no one to confirm); `"deny"` is strict worktree-confinement; **`"pass"` defers to the agent's own permissions (best for autonomous use); `"allow"` permits outright**. Catastrophic commands + protected-branch git **always deny** regardless. |

Outside those areas, writes **inside** `<root>` → **ask** (or **deny** with `protectedWrites:"deny"`); writes **outside** `<root>` → **pass** (defer). Reads of non-sensitive files → **allow**. Shell commands are parsed segment-by-segment (chains, pipes, subshells, `cd`, `git -C`, redirects).

### `branch-guard`
| Key | Type | Default | Meaning |
|---|---|---|---|
| `protected` | string[] | `["main","master","develop"]` | Mutating git (`commit`/`push`/`merge`/`rebase`/`reset`/…) while `HEAD` is on one of these → **deny**. |

### `secret-scan`
No options (just `enabled`). Flags writes whose **content** matches built-in credential
patterns — AWS key id, PEM private key, GitHub/Slack tokens, `api_key=…`/`secret=…` — → **ask**.

### `session-banner`
No options (just `enabled`). Prints the active feature list to **stderr** at SessionStart.

## Decision log (`log`) — top-level, not a feature

One JSONL line per hook call recording the **final verdict** (`op`, `resource`, `verdict`,
`reason`, `source`), so you can tune the policy from real usage. **Opt-in; zero cost when off.**

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `false` | Turn the log on. |
| `path` | string | `~/.keel/decisions.jsonl` | Log file (`~` expands to `$HOME`). |
| `maxSizeMb` | number | `5` | Size-roll: past this the file rolls to `<name>.1` (bounded ≤ ~2×). |

Summarize it — verdict mix + what's driving `ask` — with **`keel stats [logfile]`**.

## Environment overrides

| Variable | Effect |
|---|---|
| `KEEL_CONFIG` | Path to the config file (overrides `<root>/.keel.json`). |
| `KEEL_ROOT` | Force the project root (otherwise the nearest `.git`). |
| `KEEL_HOME` | Override `$HOME` for install/shim paths (mainly for testing). |

## Notes

- Verdicts across features aggregate **most-restrictive-wins**: `deny > ask > pass > allow`.
- keel **fails open**: with no config file (or an unreadable one) it uses defaults and never blocks the agent on its own error.
