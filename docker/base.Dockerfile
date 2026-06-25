# Prebaked base image for the keel e2e. Bakes the slow part ONCE — the real agent
# CLIs (Claude Code + Codex + Antigravity `agy`) — and is published to GHCR by
# docker-base.yml. The e2e then just mounts a freshly-built keel binary + the test
# script and runs against this image (fast: no per-run installs). PNG rendered on the runner.
FROM node:20-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# real agent CLIs — all install headlessly; `--version` works offline / no auth.
RUN for i in 1 2 3; do npm install -g @anthropic-ai/claude-code @openai/codex && break || sleep 5; done
RUN for i in 1 2 3; do curl -fsSL https://antigravity.google/cli/install.sh | bash && break || sleep 5; done
# the antigravity installer drops `agy` here
ENV PATH="/root/.local/bin:${PATH}"
