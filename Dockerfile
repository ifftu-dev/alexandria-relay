# Relay image and release binaries from one build.
# Build context is the repository root (standalone crate).
#
#   docker build .                                   runtime image (default)
#   docker buildx build --target binary \
#     --output type=local,dest=dist .                static binary only
#
# The builder is Alpine, so the binary links musl statically and runs on any
# Linux of the same architecture. CI attaches that same binary to releases.
FROM rust:1.89-alpine AS builder

RUN apk add --no-cache musl-dev file

WORKDIR /app

# Copy manifest first for dependency layer caching
COPY Cargo.toml Cargo.lock ./

# Create stub src for dependency-only build (cached unless Cargo.toml changes)
RUN mkdir -p src && echo "fn main(){}" > src/main.rs
RUN cargo build --locked --release || true

# Copy real source and rebuild. Fail here, not on an operator's host, if the
# binary ever picks up a dynamic dependency.
COPY src/ src/
RUN touch src/main.rs && cargo build --locked --release \
 && file target/release/alexandria-relay \
 && file target/release/alexandria-relay | grep -Eq 'static(-pie)? linked|statically linked'

# `--target binary` exports just the executable.
FROM scratch AS binary
COPY --from=builder /app/target/release/alexandria-relay /alexandria-relay

# Runtime — minimal Debian, kept for a shell (`fly ssh console`) and CA roots.
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' ca-certificates)" ge 20250419~deb12u2 \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 relay \
 && useradd --system --uid 10001 --gid relay --home-dir /data --no-create-home \
      --shell /usr/sbin/nologin relay \
 && install -d -o relay -g relay -m 0750 /data
COPY --from=builder /app/target/release/alexandria-relay /usr/local/bin/

# The relay runs as uid/gid 10001. /data belongs to that user: a named Docker
# volume or a Fly volume mounted there inherits the ownership; a bind mount
# must be chowned to 10001:10001 by the host.
ENV RELAY_DATA_DIR=/data
WORKDIR /data
USER 10001:10001

EXPOSE 4001/tcp 4001/udp 9090/tcp
ENTRYPOINT ["alexandria-relay"]
CMD ["--port", "4001"]
