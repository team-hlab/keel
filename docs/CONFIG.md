# Configuration — `.keel.json`

keel reads optional config from **`$KEEL_CONFIG`** if set, otherwise **`<root>/.keel.json`**,
otherwise built-in defaults. `<root>` is `$KEEL_ROOT` or the nearest `.git` ancestor of the
tool call's `cwd`. **Everything is optional** — keel works with no config file, and any
missing key falls back to its default.

## Shape (values shown are the defaults — see the table below for the full lists)

```json
{
  "features": {
    "autopermit": {
      "enabled": true,
      "sensitiveFilePatterns": [".env*", "*.key", "*.pem", "credentials*", "*secret*", "id_rsa*", "…"],
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
| `sensitiveFilePatterns` | string[] | env/keys/creds set (`.env*`, `*.key`, `*.pem`, `credentials*`, `*secret*`, `id_rsa*`, `id_ed25519*`, `.npmrc`, `.netrc`, `.pgpass`, `*.p12`, `*.pfx`, `*.keystore`, `*.kdbx`, `kubeconfig`, `*.ovpn`, …) | Basename globs (`*`, `?`, case-insensitive). A read/write whose **filename** matches → **ask**. Applies to file tools **and** shell content-reads (`cat`/`head`/`grep`/`base64`/…), so `cat ~/.ssh/id_rsa` asks just like the Read tool would. Setting this **replaces** the default set. |
| `worktrees` | string | `"worktrees"` | Path-segment name treated as a safe write area — writes under `<root>/worktrees/…` → **allow**. |
| `projects` | string | `"projects"` | Enables nested layouts: writes under `<root>/projects/*/worktrees/…` (one or two levels) are also allowed. |
| `protectedWrites` | `"ask"` \| `"deny"` \| `"pass"` \| `"allow"` | `"ask"` | What to do with an in-repo write **outside** the worktree areas. `"ask"` (default) confirms — great interactively, but **blocks headless/autonomous runs** (no one to confirm); `"deny"` is strict worktree-confinement; **`"pass"` defers to the agent's own permissions (best for autonomous use); `"allow"` permits outright**. Catastrophic commands + protected-branch git **always deny** regardless. |

Outside those areas, writes **inside** `<root>` → **ask** (or **deny** with `protectedWrites:"deny"`); writes **outside** `<root>` → **pass** (defer). Reads of non-sensitive files → **allow**; reads of sensitive files → **ask** — including shell content-dumps (`cat`, `head`, `tail`, `less`, `grep`, `base64`, `xxd`, `strings`, …), so gating a secret can't be bypassed by shelling out. Metadata-only commands (`ls`, `stat`, `file`, `find`) don't reveal contents and stay **allow**. Shell commands are parsed segment-by-segment (chains, pipes, subshells, `cd`, `git -C`, redirects).

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
`reason`, `source`). **Opt-in; zero cost when off.**

**Why it exists.** Each record is one decision — `(op, resource) → verdict`. Three jobs:
1. **Tune the policy.** `keel stats` shows what's driving `ask` (the friction) → promote the
   confidently-safe cases to `allow`, instead of guessing.
2. **Surface adapter gaps.** `op: "other"` is a tool keel doesn't map yet (e.g. an agent's
   read/network tool) → the coverage TODO. The log turns "audit the adapters" into a readout.
3. **Audit.** A bounded, `0600` record of what the agent tried and what keel decided.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `false` | Turn the log on. |
| `path` | string | `~/.keel/decisions.jsonl` | Log file (`~` expands to `$HOME`). |
| `maxSizeMb` | number | `5` | Size-roll: past this the file rolls to `<name>.1` (bounded ≤ ~2×). |

Summarize it — verdict mix + what's driving `ask` — with **`keel stats [logfile]`** (no arg → the
configured `log.path`, else the default).

> **Sensitivity:** the log records resource **paths** and **command text**, which can contain
> secrets (e.g. `TOKEN=… curl …`). keel creates it `0600` (owner-only) — treat it as sensitive
> and don't commit or share it. It never records file *content*.

## Environment overrides

| Variable | Effect |
|---|---|
| `KEEL_CONFIG` | Path to the config file (overrides `<root>/.keel.json`). |
| `KEEL_ROOT` | Force the project root (otherwise the nearest `.git`). |
| `KEEL_HOME` | Override `$HOME` for install/shim paths (mainly for testing). |

## Notes

- Verdicts across features aggregate **most-restrictive-wins**: `deny > ask > pass > allow`.
- keel **fails open**: with no config file (or an unreadable one) it uses defaults and never blocks the agent on its own error.
