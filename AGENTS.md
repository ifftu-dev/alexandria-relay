# alexandria-relay/

**Generated:** 2026-03-20

## Standing Instructions

- **Documentation review after code changes**: After completing any code changes, always assess whether README and other docs need updating. Ask the user for permission before modifying any documentation files.

## Overview

Standalone P2P relay + DHT bootstrap server. Single binary, Fly.io deployment.

## BUILD & RUN

```bash
cargo run -- --port 4001        # Dev
cargo build --release           # Release
docker build -t alexandria-relay .  # Docker
```

## DEPLOYMENT

**Fly.io** (see `fly.toml`):
- Region: Mumbai (bom)
- Resources: 256MB RAM, 1 CPU
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
gossipsub. The full set of topics carried by the network at HEAD:

```
/alexandria/catalog/1.0
/alexandria/evidence/1.0
/alexandria/taxonomy/1.0
/alexandria/governance/1.0
/alexandria/profiles/1.0
/alexandria/opinions/1.0          # Field Commentary opinions
/alexandria/peer-exchange/1.0
/alexandria/vc-did/1.0            # VC: DID doc + key rotation
/alexandria/vc-status/1.0         # VC: status list snapshots/deltas
/alexandria/vc-presentation/1.0   # VC: selective-disclosure presentations
/alexandria/pinboard/1.0          # VC: PinBoard pinning commitments
```

Plus a libp2p `request-response` protocol (NOT a gossip topic, not
carried by the relay) for authority-respecting credential pull:

```
/alexandria/vc-fetch/1.0          # 1-to-1 request-response
```
