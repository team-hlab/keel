# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com);
versions follow [SemVer](https://semver.org). `Cargo.toml` is the single source of truth for
the version — see [docs/RELEASING.md](docs/RELEASING.md).

## [Unreleased]

### Changed
- Ported the Python reference test suite (policy, shell, engine, features, install,
  e2e, no-external-deps) into Rust unit/integration tests, retired the `python-oracle`
  CI job, and removed `reference/python/`. The Rust source + tests are now the single
  source of truth (53 tests). The `no_external_deps` guard becomes a `Cargo.toml`
  dependency allowlist (`tests/deps.rs`).

### Fixed
- Antigravity adapter now shims the real CLI binary **`agy`** (plain `antigravity` is the
  GUI IDE launcher, not a hookable CLI). Platform name (`antigravity`) and config path
  (`~/.gemini/config/hooks.json`) are unchanged. Busybox dispatch now derives shim names
  from the registered agents rather than a hard-coded list. `init`/`doctor` surface the
  shimmed binary (e.g. `antigravity (agy)`) so it's clear what keel actually wraps.
  Verified Antigravity's global hooks path is `~/.gemini/config/hooks.json` (the path keel
  already uses); the `agy` binary and `PreToolUse` event are confirmed too.

## [0.1.0] — 2026-06-25

### Added
- **keel** as a single static Rust binary (~1 MB, zero runtime dependencies).
- Core: platform-neutral `Event`/`Verdict` model, most-restrictive-wins engine
  (`deny > ask > pass > allow`) with per-feature fail-open, runtime (root discovery,
  config, realpath-style resolution).
- Adapters: Claude Code (verified), OpenAI Codex and Google Antigravity (best-effort).
- Features: `autopermit` (files + full shell parsing), `branch-guard`, `secret-scan`,
  `audit-log` (opt-in), `session-banner`.
- Transparent **busybox shim** (`keel init`/`apply`/`uninstall`/`doctor`/`status`):
  PATH-hijack symlinks, non-destructive `__keel` markers, `exec`s the real agent with
  a fork-bomb guard.
- CLI: `keel run <platform> <stage>`, `features`, `version`.
- 40 tests (24 unit + 16 binary-level e2e), incl. edge-case & fault-tolerance.
- CI (fmt/clippy/test + Python oracle); merge-triggered release workflow; Homebrew tap.

[Unreleased]: https://github.com/team-hlab/keel/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/team-hlab/keel/releases/tag/v0.1.0
