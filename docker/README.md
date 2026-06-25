# keel — dockerized e2e

Runs keel's full install → attach → per-agent verdicts → transparent shim → uninstall
lifecycle against the **real** Claude Code, Codex, and Antigravity (`agy`) CLIs — all
install headlessly with offline `--version`. Real agent *sessions* aren't run (no API
key/OAuth in CI), so this covers everything that doesn't need one.

## Pieces

- **`base.Dockerfile`** — prebaked base: the slow part (real agent CLIs) installed once.
  Published to `ghcr.io/team-hlab/keel-e2e-base:latest` by `docker-base.yml`.
- **`e2e.sh`** — the lifecycle test (asserts shims, hooks, verdicts, shim-exec, uninstall).
- CI: `docker-e2e.yml` builds keel, mounts it into the base, runs `e2e.sh`, and attaches
  evidence (log + rendered PNG) as an artifact **and** a sticky PR comment.

## Run locally

```sh
# 1. base (or: docker pull ghcr.io/team-hlab/keel-e2e-base:latest)
docker build -f docker/base.Dockerfile -t keel-e2e-base .

# 2. build a Linux keel for the container
docker run --rm -v "$PWD:/src" -w /src -e CARGO_TARGET_DIR=/src/target-linux \
  rust:1-bookworm cargo build --release

# 3. run the lifecycle
docker run --rm \
  -v "$PWD/target-linux/release/keel:/usr/local/bin/keel:ro" \
  -v "$PWD/docker/e2e.sh:/e2e.sh:ro" \
  keel-e2e-base bash /e2e.sh
```
