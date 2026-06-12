# Alexandria Relay

[![CI](https://github.com/ifftu-dev/alexandria-relay/actions/workflows/ci.yml/badge.svg)](https://github.com/ifftu-dev/alexandria-relay/actions/workflows/ci.yml)

**Relay server for the Alexandria P2P network.**

> Circuit Relay v2 + Kademlia DHT bootstrap + Identify + metrics HTTP server — a single Rust binary that helps nodes find each other and traverse NAT.

## Security Model

The relay cannot read, modify, or censor content flowing through the network (traffic is end-to-end encrypted). It provides four functions:

1. **NAT traversal** — Circuit Relay v2 allows mobile and firewalled nodes to receive inbound connections through the relay.
2. **Peer discovery** — A private Kademlia DHT (`/alexandria/kad/1.0`) lets nodes find each other by querying providers on a shared namespace key. Inbound DHT records are mirrored to disk so the registry survives restarts.
3. **Protocol handshake** — Identify announces the relay's supported protocols and agent version to connecting peers.
4. **Username receipts** — countersigns first-seen username claims over `/alexandria/username-reg/1.0` (persisted in sqlite under `RELAY_DATA_DIR`) and serves `GET /username/:name` for signup-time availability checks.

One honest caveat to "no special authority": for username receipts the relay *is* a trusted first-seen timestamp oracle (tier 1). That trust is bounded — claims gather receipts from every relay and order by the median time, and Cardano-anchored claims (tier 2) beat any receipt. See the main repo's `docs/username-registry.md`.

Any node can run a relay. The network does not depend on a single instance.

### Hardening

- **Per-peer limits** — Max 4 connections per PeerId, 512 total
- **Per-IP rate limiting** — Max 16 concurrent connections per IP, max 32 new connections per IP per minute. Prevents PeerId rotation attacks.
- **Relay circuit caps** — 2 MB / 2 min per circuit, 256 reservations, 512 circuits
- **Kademlia store cap** — 64K records, 64 KB max per record
- **Address filtering** — Rejects private (RFC 1918), CGNAT, link-local, ULA, IPv4-mapped, multicast, and site-local addresses from the DHT routing table
- **Idle timeout** — Connections reaped after 10 minutes of inactivity
- **Seed hygiene** — `RELAY_SEED` is read and cleared from the process environment before the async runtime starts; key material is zeroed on the stack

## Limits

| Limit | Value |
|-------|-------|
| Max connections (total) | 1024 |
| Max connections per peer | 8 |
| Max connections per IP | 32 |
| Max new connections per IP / min | 32 |
| Max relay reservations | 1024 (16 per peer, 1h duration) |
| Max relay circuits | 2048 (128 per peer) |
| Max data per circuit | 128 MB |
| Max circuit duration | 15 minutes |
| DHT records | 16,384 max (64 KB each) |
| Idle connection timeout | 10 minutes |
| Health log interval | 5 minutes |

**IP rate limits** are tuned for normal residential / mobile NATs (a household typically carries 5-10 simultaneous peers). If you run synthetic load tests from a single IP (CI runners, dev clusters), `MAX_CONNECTIONS_PER_IP` and `MAX_NEW_CONNS_PER_IP_PER_WINDOW` will reject connections — bump them or whitelist the source for the duration of the test.

**Per-peer circuit cap (128)** is the knob most likely to need tuning if you grow the active-observer count. Each crawler/observer that fan-dials peers via circuits contributes against this limit *as the source peer*. A network with multiple high-frequency observers should push this higher (256-512) before the global `RELAY_MAX_CIRCUITS` becomes the bottleneck.

## Quick Start

```bash
# Run with default settings (libp2p on 4001, metrics HTTP on 9090)
cargo run -- --port 4001

# Generate a new keypair seed (prints hex seed + derived PeerId)
cargo run -- --generate-key
```

The relay listens on both TCP and QUIC (UDP) on the same port, plus an HTTP metrics server on a separate port.

## Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `--port` | CLI | `4001` | TCP listen port |
| `--quic-port` | CLI | `4001` | QUIC (UDP) listen port |
| `--metrics-port` | CLI | `9090` | HTTP metrics/health port |
| `--generate-key` | CLI | — | Generate a keypair seed and exit |
| `RELAY_SEED` | Env | — | 32-byte hex seed for deterministic PeerId. If unset, generates a random keypair on each start. |
| `RUST_LOG` | Env | `info` | Log level (`debug`, `info`, `warn`, `error`) |

Always set `RELAY_SEED` in production so the PeerId is stable across restarts and redeployments.

## Monitoring

The relay exposes an HTTP server on the metrics port (default `9090`):

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Lightweight health check — returns `{"status":"ok","peer_id":"...","uptime_seconds":N,"connections":N}` |
| `GET /health/alerts` | Alert-friendly health check — `200` when healthy, `503` when any threshold trips. JSON body lists which alerts are firing (e.g., `circuit_denial_majority`, `connections_near_cap`) and the rolling 60s denial rates. Suitable for UptimeRobot / healthchecks.io / Fly's own checks without external delta math. |
| `GET /metrics` | Full relay metrics JSON — connections, circuits, reservations, DHT updates, identify events, listener errors, IP rate limits, plus rolling-minute denial counters |

The `alexandria-monitoring` observer scrapes `/metrics` every 30 seconds and persists the data to SQLite. The dashboard displays a "Relay Node Health" panel with real-time metrics.

Set `RELAY_METRICS_URL` on the observer to point to your relay's metrics endpoint (comma-separated for multiple relays).

### External alerting

Wire `https://alexandria-relay.fly.dev/health/alerts` into UptimeRobot or healthchecks.io as an HTTP GET monitor. Any `5xx` response indicates one or more thresholds tripped — current triggers:

- `connections_near_cap` — connections > 80% of `MAX_CONNECTIONS`
- `circuits_denied_per_min_high` — > 100 denials / min
- `circuit_denial_majority` — denials > accepts in last minute (with > 20 total)
- `reservations_denied_per_min_high` — > 10 reservation denials / min
- `listener_errors_observed` — any cumulative listener errors

You'll want to alert on `5xx` and inspect the JSON body for which signal fired.

## Deployment

The relay is deployed on [Fly.io](https://fly.io) using the included `Dockerfile` and `fly.toml`.

```bash
# First-time launch
fly launch --no-deploy
fly secrets set RELAY_SEED="<64-char-hex-seed>"
fly volumes create relay_data --region <region> --size 1  # once per persistent region
fly deploy

# Subsequent deploys
fly deploy

# Check status
fly status
fly logs
```

The `fly.toml` exposes three services:
- Port `4001` TCP — libp2p (relay, Kademlia, identify)
- Port `4001` UDP — QUIC transport
- Port `9090` HTTP — health checks and metrics (with Fly.io health check configured)

The Dockerfile uses a multi-stage build with `rust:1.88-slim` to produce a minimal final image.

### Multi-Region Deployment

Deploy additional relays in other regions for redundancy and lower latency:

```bash
# 1. Generate a new keypair for the EU relay
cargo run -- --generate-key
# Save the seed and PeerId from the output

# 2. Create the Fly.io app (uses fly-eu.toml)
fly apps create alexandria-relay-eu
fly secrets set RELAY_SEED="<new-64-char-hex-seed>" -a alexandria-relay-eu

# 3. Deploy
fly deploy -c fly-eu.toml

# 4. Get the allocated IPv4 address
fly ips list -a alexandria-relay-eu

# 5. Update the main app's discovery.rs:
#    - Uncomment the EU relay entry in the RELAYS array
#    - Fill in the PeerId, hostname, and IPv4 from steps 1 and 4

# 6. Update the monitoring observer:
#    RELAY_METRICS_URL=http://<bom-ip>:9090/metrics,http://<fra-ip>:9090/metrics
```

Each relay operates independently with its own Kademlia routing table. Peers connected to different relays discover each other through DHT propagation.

Included configs: `fly.toml` (Mumbai/bom), `fly-eu.toml` (Frankfurt/fra).

### High availability inside one region

Each region currently runs **one Fly machine**. A restart drops every reservation through that relay; clients reconnect within ~30s but the user-visible blip is real. To run two machines per region:

```bash
fly scale count 2 --region bom -a alexandria-relay
fly scale count 2 --region fra -a alexandria-relay-eu
```

Both machines share the same `RELAY_SEED` (so PeerId is stable) and Fly load-balances incoming connections. The cost is ~one extra `shared-1x-cpu@1024MB` instance per region. Recommended once active users exceed a few hundred — until then, the single-machine blast radius is small enough that the spend isn't justified. (Auto-scaling on circuit-pressure is a future enhancement; today it's a manual switch.)

## Architecture

A single Rust binary (`src/main.rs`, ~1,150 lines) built on libp2p 0.56:

```
┌──────────────────────────────────────────────────┐
│                 Alexandria Relay                  │
├──────────────────────────────────────────────────┤
│  Circuit Relay v2          NAT traversal         │
│  Kademlia DHT              /alexandria/kad/1.0   │
│  Identify                  Protocol negotiation  │
├──────────────────────────────────────────────────┤
│  TCP + Noise + Yamux       Encrypted mux         │
│  QUIC                      UDP transport (0-RTT) │
├──────────────────────────────────────────────────┤
│  Connection Limits         1024 total, 8/peer    │
│  IP Rate Limiting          32/IP, 32 new/IP/min  │
│  Relay Limits              1024 res, 2048 circs  │
│  Metrics HTTP Server       /health + /metrics    │
│  Health Logger             5-min interval        │
│  Graceful Shutdown         SIGTERM / SIGINT      │
└──────────────────────────────────────────────────┘
```

| Component | Technology |
|-----------|------------|
| Language | Rust (2021 edition, MSRV 1.88) |
| Networking | libp2p 0.56 (relay, kad, identify, tcp, quic, noise, yamux) |
| HTTP | Axum 0.7 (health checks + metrics) |
| Async runtime | tokio |
| CLI | clap 4 |
| Container | Multi-stage Docker (rust:1.88-slim -> debian:bookworm-slim) |
| Hosting | Fly.io |

## Current Deployments

### Mumbai (primary)

| Item | Value |
|------|-------|
| PeerId | `12D3KooWENHQjSydcHUXVTuq4wVNvCP4VGXzxueBtdKi1D3mS6wR` |
| Hostname | `alexandria-relay.fly.dev` |
| IPv4 | `168.220.86.30` |
| Ports | `4001` (TCP + QUIC/UDP), `9090` (HTTP metrics) |
| Region | `bom` (Mumbai) |

### Frankfurt (EU)

| Item | Value |
|------|-------|
| PeerId | `12D3KooWFDVfPBwa6EVEp8v8cqXpgmiksV7qMarHCYLF174XV9xj` |
| Hostname | `alexandria-relay-eu.fly.dev` |
| IPv4 | `66.51.123.68` |
| Ports | `4001` (TCP + QUIC/UDP), `9090` (HTTP metrics) |
| Region | `fra` (Frankfurt) |

### Multiaddrs

Mumbai:
```
/dns4/alexandria-relay.fly.dev/tcp/4001/p2p/12D3KooWENHQjSydcHUXVTuq4wVNvCP4VGXzxueBtdKi1D3mS6wR
/dns4/alexandria-relay.fly.dev/udp/4001/quic-v1/p2p/12D3KooWENHQjSydcHUXVTuq4wVNvCP4VGXzxueBtdKi1D3mS6wR
```

Frankfurt:
```
/dns4/alexandria-relay-eu.fly.dev/tcp/4001/p2p/12D3KooWFDVfPBwa6EVEp8v8cqXpgmiksV7qMarHCYLF174XV9xj
/dns4/alexandria-relay-eu.fly.dev/udp/4001/quic-v1/p2p/12D3KooWFDVfPBwa6EVEp8v8cqXpgmiksV7qMarHCYLF174XV9xj
```

## CI/CD

GitHub Actions runs on every push and PR to `main`:

| Job | What it does |
|-----|-------------|
| **Check** | `cargo check --locked` — compilation errors |
| **Clippy** | `cargo clippy -- -D warnings` — lint (warnings are errors) |
| **Format** | `cargo fmt --check` — style enforcement |
| **Test** | `cargo test --locked` — unit tests |
| **Docker** | Validates the Dockerfile builds (BuildKit + GHA cache) |

**Deploy** runs only on version tags or manual dispatch:

```bash
# Tag and push to trigger deploy
git tag v0.1.0
git push --tags

# Or trigger manually from GitHub Actions UI
```

Requires `FLY_API_TOKEN` in GitHub repository secrets.

## License

TBD
