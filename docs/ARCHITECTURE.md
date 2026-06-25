# keel — Architecture

keel is a **ports-and-adapters (hexagonal)** harness. All platform variance lives at the
edges (adapters); the decision logic is a pure, platform-neutral core. The dependency
arrow points **keel → each agent**, never the other way.

```
                 ┌──────────────────────────────────────────┐
   platform in   │                  CORE                     │   platform out
  ┌───────────┐  │  ┌────────────────────────────────────┐  │  ┌───────────┐
  │ Claude    │─▶│  │  features → Verdict (per stage)     │  │─▶│ Claude    │
  │ Codex     │─▶│  │  engine.aggregate(most-restrictive) │  │─▶│ Codex     │
  │Antigravity│─▶│  └────────────────────────────────────┘  │─▶│Antigravity│
  └───────────┘  │   Event in · Verdict out · no I/O here    │  └───────────┘
   (adapters)    └──────────────────────────────────────────┘   (adapters)
```

## The two contracts

Everything the core knows is `Event` (in) and `Verdict` (out) — see `keel/core/model.py`.

```
Event    { stage, tool, tool_input, cwd, root, config, raw }
           .file_path / .command convenience accessors
Verdict  { decision: allow|deny|ask|pass,  reason,  source }
```

`pass` means *abstain* — a feature returns `None` and the engine treats it as no opinion.

## Request lifecycle

```
agent tool call
   │  (adapter.parse → Event, with root resolved)
   ▼
engine.run(event, features)
   │   for each feature subscribed to event.stage: evaluate(event) → Verdict | None
   │   aggregate: most-restrictive-wins  (deny > ask > pass > allow)
   ▼
adapter.render(verdict, stage) → that platform's hook JSON on stdout
```

A misbehaving feature is swallowed (per-feature fail-open); a malformed payload or
missing runtime falls back to `pass`. **The harness never blocks the agent.**

## Verdict aggregation

`deny > ask > pass > allow` — the strongest verdict from any feature wins. So one feature
denying overrides another allowing; an abstaining feature never weakens a real verdict.

## The load-bearing-stage rule

Read-only tools are auto-allowed by every agent **without a prompt**, so a
`PermissionRequest`-style hook never fires for them. Therefore guarantees that must
*always* hold — secret-read confirmation (`ask`), protected-write denial (`deny`) — are
emitted at the **always-runs pre-tool stage**. The permission-request stage is a secondary
layer that re-derives the *same* verdict, so the two can never disagree. Adapters render
`ask`/`pass` at the permission-request stage as "defer to the real prompt."

## Components

| Layer | Module | Responsibility |
|---|---|---|
| core | `core/model.py` | `Event`, `Verdict`, decision ranks |
| core | `core/engine.py` | route to features + aggregate |
| core | `core/registry.py` | instantiate enabled features from config |
| core | `core/runtime.py` | stdin, root discovery, config load, path resolve (the I/O) |
| adapters | `adapters/{claude_code,codex,antigravity}.py` | parse platform JSON ⇄ render verdict |
| features | `features/base.py` | the `Feature` protocol |
| features | `features/autopermit/` | files (`policy.py`) + shell (`shell.py`) + `feature.py` |
| features | `features/{branch_guard,secret_scan,audit_log,session_banner}.py` | the rest |
| edge | `cli.py` · `install.py` · `bin/keel.sh` | entrypoint, attach command, runtime preflight |

## Adding a feature

Implement `keel.features.base.Feature` and register it in `core/registry.py`:

```python
class Feature:
    name = "..."
    def stages(self): return {"PreToolUse"}          # which hook stages
    def evaluate(self, event): return Verdict(...) or None   # None = abstain
```

Permission features return a `Verdict`; observer features (logging, banners) act and
return `None`. Keep `evaluate` pure where possible; do I/O through `core/runtime.py`.

## Adding / fixing an adapter

An adapter is two functions: `parse(raw, stage) -> Event` and
`render(verdict, stage) -> str` (the platform's hook JSON). Cite the doc you verified
against in the module docstring. **Claude Code is verified; Codex and Antigravity are
best-effort** against their ~May-2026 hook APIs — confirm against live docs before relying
on them.

## Cross-platform model

All three agents converged on the same shape — a pre-run hook returning
`allow`/`deny`/`ask`. Only field names and output schema differ, which is exactly what the
adapters absorb. See the visual decks in this folder:

- [`autopermit-architecture.html`](autopermit-architecture.html) — the Claude lifecycle in depth
- [`autopermit-platforms.html`](autopermit-platforms.html) — Claude vs Codex vs Antigravity
- [`autopermit-target.html`](autopermit-target.html) — this ports-and-adapters target

(The HTML decks predate the rename; "autopermit" there is now keel's flagship feature.)
