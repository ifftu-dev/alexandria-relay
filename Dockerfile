# Multi-stage build for minimal relay image
# Build context is the alexandria-relay/ directory itself (standalone crate)
FROM rust:1.88-slim AS builder

WORKDIR /app

# Copy manifest first for dependency layer caching
COPY Cargo.toml Cargo.lock ./

# Create stub src for dependency-only build (cached unless Cargo.toml changes)
RUN mkdir -p src && echo "fn main(){}" > src/main.rs
RUN cargo build --release || true

# Copy real source and rebuild
COPY src/ src/
RUN touch src/main.rs && cargo build --release

# Runtime — minimal Debian
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/alexandria-relay /usr/local/bin/
EXPOSE 4001/tcp 4001/udp 9090/tcp
ENTRYPOINT ["alexandria-relay"]
CMD ["--port", "4001"]
