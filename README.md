# Alexandria Relay

**Production relay server for the Alexandria P2P network.**

> Circuit Relay v2 + Kademlia DHT bootstrap + Identify — a single Rust binary that helps nodes find each other and traverse NAT.

## Security Model

The relay has no special authority. It cannot read, modify, or censor content flowing through the network. It provides three functions:

1. **NAT traversal** — Circuit Relay v2 allows mobile and firewalled nodes to receive inbound connections through the relay.
2. **Peer discovery** — A private Kademlia DHT (`/alexandria/kad/1.0`) lets nodes find each other by querying providers on a shared namespace key.
3. **Protocol handshake** — Identify announces the relay's supported protocols and agent version to connecting peers.

Any node can run a relay. The network does not depend on a single instance.

## Production Hardening

| Limit | Value |
|-------|-------|
| Max connections (total) | 512 |
| Max connections per peer | 4 |
| Max relay reservations | 256 |
| Max relay circuits | 512 |
| Max data per circuit | 2 MB |
| Max circuit duration | 2 minutes |
| Health log interval | 5 minutes |

Graceful shutdown on SIGTERM and SIGINT — closes the listener, drains active connections, and exits cleanly.

## Quick Start

```bash
# Run with default settings (port 4001)
cargo run -- --port 4001

# Generate a new keypair seed (prints hex seed + derived PeerId)
cargo run -- --generate-key
```

The relay listens on both TCP and QUIC (UDP) on the same port.

## Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `--port` | CLI flag | `4001` | Listen port (TCP + QUIC/UDP) |
| `--generate-key` | CLI flag | — | Generate a keypair seed and exit |
| `RELAY_SEED` | Env var | — | 32-byte hex seed for deterministic PeerId. If unset, generates a random keypair on each start. |
| `RUST_LOG` | Env var | `info` | Log level (`debug`, `info`, `warn`, `error`) |

For production, always set `RELAY_SEED` so the PeerId is stable across restarts and redeployments.

## Deployment

The relay is deployed on [Fly.io](https://fly.io) using the included `Dockerfile` and `fly.toml`.

```bash
# First-time launch
fly launch --no-deploy
fly secrets set RELAY_SEED="<32-byte-hex-seed>"
fly deploy

# Subsequent deploys
fly deploy

# Check status
fly status
fly logs
```

The `fly.toml` allocates a dedicated IPv4 address and exposes port 4001 for both TCP and UDP (QUIC). The Dockerfile uses a multi-stage build with `rust:1.88-slim` to produce a minimal final image.

## Architecture

A single Rust binary (`src/main.rs`, ~340 lines) built on libp2p 0.56:

```
┌─────────────────────────────────┐
│         Alexandria Relay        │
├─────────────────────────────────┤
│  Circuit Relay v2               │  NAT traversal for mobile nodes
│  Kademlia DHT                   │  /alexandria/kad/1.0 — peer discovery
│  Identify                       │  Protocol negotiation + agent version
├─────────────────────────────────┤
│  TCP + Noise + Yamux            │  Encrypted multiplexed transport
│  QUIC                           │  UDP transport (0-RTT)
├─────────────────────────────────┤
│  Connection Limits              │  512 total, 4 per peer
│  Relay Limits                   │  256 reservations, 512 circuits
│  Health Logger                  │  Peer/reservation counts every 5 min
│  Graceful Shutdown              │  SIGTERM / SIGINT
└─────────────────────────────────┘
```

| Component | Technology |
|-----------|------------|
| Language | Rust (2021 edition, MSRV 1.88) |
| Networking | libp2p 0.56 (relay, kad, identify, tcp, quic, noise, yamux) |
| Async runtime | tokio |
| CLI | clap 4 |
| Container | Multi-stage Docker (rust:1.88-slim → debian:bookworm-slim) |
| Hosting | Fly.io (Mumbai region) |

## Current Deployment

| Item | Value |
|------|-------|
| PeerId | `12D3KooWENHQjSydcHUXVTuq4wVNvCP4VGXzxueBtdKi1D3mS6wR` |
| Hostname | `alexandria-relay.fly.dev` |
| IPv4 | `168.220.86.30` |
| Port | `4001` (TCP + QUIC/UDP) |
| Region | `bom` (Mumbai) |

Multiaddrs for client configuration:

```
/dns4/alexandria-relay.fly.dev/tcp/4001/p2p/12D3KooWENHQjSydcHUXVTuq4wVNvCP4VGXzxueBtdKi1D3mS6wR
/dns4/alexandria-relay.fly.dev/udp/4001/quic-v1/p2p/12D3KooWENHQjSydcHUXVTuq4wVNvCP4VGXzxueBtdKi1D3mS6wR
/ip4/168.220.86.30/tcp/4001/p2p/12D3KooWENHQjSydcHUXVTuq4wVNvCP4VGXzxueBtdKi1D3mS6wR
/ip4/168.220.86.30/udp/4001/quic-v1/p2p/12D3KooWENHQjSydcHUXVTuq4wVNvCP4VGXzxueBtdKi1D3mS6wR
```

## License

TBD
