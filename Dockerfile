# syntax=docker/dockerfile:1.7

FROM rust:trixie AS builder
WORKDIR /app

# Keep dependency metadata in its own layer when a lockfile exists.
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
COPY migrations ./migrations

RUN cargo build --locked --release 2>/dev/null || cargo build --release

FROM debian:trixie-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 streambot \
    && useradd --system --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin streambot

COPY --from=builder --chown=streambot:streambot /app/target/release/streambot-remote-backend /usr/local/bin/streambot-remote-backend

USER streambot:streambot
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/streambot-remote-backend"]
