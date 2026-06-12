# alexandria-relay/

**Generated:** 2026-03-20

## Standing Instructions

- **Documentation review after code changes**: After completing any code changes, always assess whether README and other docs need updating. Ask the user for permission before modifying any documentation files.

## Overview

Standalone P2P relay + DHT bootstrap server + username-receipt registry (src/username_reg.rs: countersigned first-seen claims + DHT record mirror, persisted under RELAY_DATA_DIR). Single binary, Fly.io deployment.

## BUILD & RUN

```bash
cargo run -- --port 4001        # Dev
cargo build --release           # Release
docker build -t alexandria-relay .  # Docker
```

## DEPLOYMENT

**Fly.io** (see `fly.toml`):
- Region: Mumbai (bom)
- Resources: 1GB RAM, `relay_data` volume (Frankfurt; Mumbai ephemeral), 1 CPU
- Ports: TCP + UDP/QUIC on 4001
- Deterministic PeerId via `RELAY_SEED` env var

**Docker** (`Dockerfile`):
- Builder: `rust:1.88-slim`
- Runtime: `debian:bookworm-slim`
- Multi-platform capable (Docker buildx)

## ARCHITECTURE

- Entry: `src/main.rs` — libp2p relay + DHT bootstrap
- Same libp2p 0.56 as main app
- MSRV: 1.88.0
- Release profile: codegen-units=1, lto=true, opt-level="s", panic=abort, strip=true

## KEY GOSSIPSUB TOPICS

The relay is topic-agnostic — it relays whatever flows through
gossipsub. For the canonical list of all 13 gossip topics carried
by the network, see [`alexandria/docs/protocol-specification.md` §6.5](../alexandria/docs/protocol-specification.md).
