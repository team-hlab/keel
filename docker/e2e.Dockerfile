# Dockerized end-to-end test: build keel from source, install the REAL Claude Code
# and Codex CLIs (Antigravity is stubbed — no headless install), then exercise keel's
# full install/attach/shim/uninstall lifecycle against them. See docker/e2e.sh.
#
#   docker build -f docker/e2e.Dockerfile -t keel-e2e . && docker run --rm keel-e2e

FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release

FROM node:20-bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
# Real agent CLIs — `--version` works offline with no auth (retry for registry blips).
RUN for i in 1 2 3; do \
      npm install -g @anthropic-ai/claude-code @openai/codex && break || sleep 5; \
    done
COPY --from=build /src/target/release/keel /usr/local/bin/keel
COPY docker/e2e.sh /usr/local/bin/keel-e2e.sh
RUN chmod +x /usr/local/bin/keel-e2e.sh
CMD ["bash", "/usr/local/bin/keel-e2e.sh"]
