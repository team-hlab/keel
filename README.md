# keel

**Write your agent's safety policy once, run it on any agent.**

`keel` is a lean, single-binary hook harness for first-party AI coding agents — **Claude Code**, **OpenAI Codex**, **Google Antigravity**. Every tool call passes through keel, which **auto-permits** the safe, **auto-denies** the catastrophic, and **asks** you about the ambiguous.

- **Single static binary** — Rust, ~1 MB, **zero runtime dependencies**.
- **Busybox-style** — one binary, two modes: a transparent shim and the `keel` CLI.
- **Transparent install** — `brew install keel && keel init` wires keel's hooks into every detected agent; you keep running `claude` exactly as before.
- **Fails open** — a bug or a missing piece never blocks the agent.
- **Extensible** — features are small compiled-in applets behind one trait.

## How it works

1. **Shim (PATH hijack + busybox).** `keel init` symlinks `~/.keel/bin/{claude,codex,agy}` to the keel binary (Antigravity's CLI is `agy`), ahead of the real CLIs on PATH. Running `claude` runs keel (by `argv[0]`), which re-applies the latest hooks (idempotent, non-destructive via a `__keel` marker), then `exec`s the real `claude` — same PID, invisible in `ps`.
2. **Hook handler.** At tool-use time the applied hooks call `keel run claude PreToolUse`; the policy engine returns allow / deny / ask (or defers).

See **[docs/keel-architecture.html](docs/keel-architecture.html)** for the full picture.

## Install

```sh
brew tap team-hlab/keel
brew install keel
keel init                 # attach to your installed agents
brew upgrade keel         # update later
```

## Status

keel is Rust, its behavior covered by the Rust test suite (unit + integration + a dockerized e2e against the real agent CLIs). It began life as a verified Python implementation that served as the spec/oracle during the port; that coverage has since been ported to Rust and the Python retired.

- ✅ **Hook engine** — `keel run <platform> <stage>`, the `autopermit` feature (files **and** full shell parsing), and Claude/Codex/Antigravity adapters.
- ✅ **Transparent shim** — `keel init` / `apply` / `uninstall` / `doctor`: PATH-hijack symlinks, non-destructive `__keel` markers, `exec`s the real agent.
- ✅ **All five features** — autopermit, branch-guard, secret-scan, audit-log (opt-in), session-banner. **53 Rust tests** (unit + integration, incl. edge-case & fault-tolerance) **plus a dockerized e2e** that installs the real Claude/Codex/`agy` CLIs and exercises the full lifecycle; clippy/fmt clean.

## Features

| Feature | Stage(s) | What it does |
|---|---|---|
| **autopermit** | PreToolUse, PermissionRequest | permit non-secret reads + worktree writes + safe shell; `ask` secrets & in-repo writes outside a worktree (set `protectedWrites:"deny"` for strict); `deny` catastrophic commands |
| **branch-guard** | PreToolUse | `deny` mutating git on a protected branch |
| **secret-scan** | PreToolUse | `ask` when a write's content looks like a credential |
| **audit-log** | PreToolUse | append every call to JSONL (opt-in — it writes files) |
| **session-banner** | SessionStart | announce active features |

Verdicts aggregate **most-restrictive-wins**: `deny > ask > pass > allow`. Tunable via `.keel.json` — see **[docs/CONFIG.md](docs/CONFIG.md)**.

## Develop

```sh
cargo test            # unit + integration tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo build --release # → target/release/keel  (~1 MB)
```

For the full lifecycle against the real agent CLIs in a container, see **[docker/README.md](docker/README.md)**.

CI runs fmt + clippy + test + release build, plus a **dockerized e2e** that installs the real
Claude/Codex/Antigravity (`agy`) CLIs and runs keel's full install → attach → verdict → shim → uninstall
lifecycle, on every push and PR. Releases are merge-triggered (bump `Cargo.toml`) — see [docs/RELEASING.md](docs/RELEASING.md).

## License

MIT © team-hlab
