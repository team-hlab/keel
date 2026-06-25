# keel

**Write your agent's safety policy once, run it on any agent.**

`keel` is a lean, single-binary hook harness for first-party AI coding agents — **Claude Code**, **OpenAI Codex**, **Google Antigravity**. Every tool call passes through keel, which **auto-permits** the safe, **auto-denies** the catastrophic, and **asks** you about the ambiguous.

- **Single static binary** — Rust, ~1 MB, **zero runtime dependencies**.
- **Busybox-style** — one binary, two modes: a transparent shim and the `keel` CLI.
- **Transparent install** — `brew install keel && keel init` wires keel's hooks into every detected agent; you keep running `claude` exactly as before.
- **Fails open** — a bug or a missing piece never blocks the agent.
- **Extensible** — features are small compiled-in applets behind one trait.

## How it works

1. **Shim (PATH hijack + busybox).** `keel init` symlinks `~/.keel/bin/{claude,codex,antigravity}` to the keel binary, ahead of the real CLIs on PATH. Running `claude` runs keel (by `argv[0]`), which re-applies the latest hooks (idempotent, non-destructive via a `__keel` marker), then `exec`s the real `claude` — same PID, invisible in `ps`.
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

This repo is mid-port from a verified Python implementation to Rust (the Python lives in `reference/python/` as the spec + test oracle, and is being retired).

- ✅ **Hook engine** — `keel run <platform> <stage>`, the `autopermit` feature (files **and** full shell parsing), and Claude/Codex/Antigravity adapters. 14 Rust tests; **behavior verified 1:1 against the Python oracle.**
- 🚧 **Transparent shim** (`keel init` / `apply` / `uninstall`) and the remaining features (branch-guard, secret-scan, audit-log, session-banner) — in progress.

## Features

| Feature | Stage(s) | What it does |
|---|---|---|
| **autopermit** | PreToolUse, PermissionRequest | permit non-secret reads + worktree writes + safe shell; `ask` secrets; `deny` out-of-worktree writes & catastrophic commands |
| branch-guard 🚧 | PreToolUse | `deny` mutating git on a protected branch |
| secret-scan 🚧 | PreToolUse | `ask` when a write's content looks like a credential |
| audit-log 🚧 | Pre/PostToolUse | append every call + verdict to JSONL |
| session-banner 🚧 | SessionStart | announce active features |

Verdicts aggregate **most-restrictive-wins**: `deny > ask > pass > allow`. Tunable via `.keel.json`.

## Develop

```sh
cargo test            # unit + golden-vector tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo build --release # → target/release/keel  (~1 MB)
```

CI runs fmt + clippy + test + release build, plus the Python oracle tests, on every push and PR.

## License

MIT © team-hlab
