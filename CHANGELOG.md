# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versions follow SemVer.

## [Unreleased]

### Added
- Initial harness: platform-neutral `Event`/`Verdict` model, feature registry,
  most-restrictive-wins aggregation engine.
- Adapters: Claude Code (verified), OpenAI Codex and Google Antigravity (best-effort).
- Features: `autopermit`, `branch-guard`, `secret-scan`, `audit-log`, `session-banner`.
- `keel` CLI: `run <platform> <stage>`, `features`, `doctor`.
- `bin/keel.sh` runtime-preflight shim (resolves Python, fails open).
- Zero external runtime dependencies, enforced by a test.
