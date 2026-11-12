# syntax=docker/dockerfile:1.7

FROM rust:alpine AS builder
WORKDIR /app

# ring (used by rustls) compiles C code; musl-dev provides the libc headers.
RUN apk add --no-cache musl-dev

# Keep dependency metadata in its own layer when a lockfile exists.
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
COPY migrations ./migrations

RUN cargo build --locked --release 2>/dev/null || cargo build --release

FROM alpine:3.22 AS runtime

RUN apk add --no-cache ca-certificates \
    && addgroup -S -g 10001 streambot \
    && adduser -S -D -H -u 10001 -G streambot -h /nonexistent -s /sbin/nologin streambot

COPY --from=builder --chown=streambot:streambot /app/target/release/streambot-remote-backend /usr/local/bin/streambot-remote-backend

USER streambot:streambot
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/streambot-remote-backend"]
