# Alexandria Relay

[![CI](https://github.com/ifftu-dev/alexandria-relay/actions/workflows/ci.yml/badge.svg)](https://github.com/ifftu-dev/alexandria-relay/actions/workflows/ci.yml)

Relay and bootstrap node for the Alexandria P2P network: one Rust binary
(libp2p 0.56) that helps nodes find each other and get through NAT.

## What it does

| Function | How |
|---|---|
| NAT traversal | Circuit Relay v2, so mobile and firewalled nodes can accept inbound connections |
| Peer discovery | Private Kademlia DHT (`/alexandria/kad/1.0`); inbound records are mirrored to disk so they survive restarts |
| Handshake | Identify announces supported protocols and agent version |
| Username receipts | Countersigns first-seen username claims over `/alexandria/username-reg/1.0` and serves `GET /username/:name` |

## Why it's safe to run

- Traffic is end-to-end encrypted. The relay can't read, change or censor it.
- It does not run GossipSub, AutoNAT or DCUtR, and holds no special authority
  except one: it is a trusted first-seen timestamp for username receipts.
  That trust is bounded. Claims collect receipts from every relay, and
  Cardano-anchored claims beat any receipt
  (see [username-registry.md](https://github.com/ifftu-dev/alexandria/blob/main/docs/username-registry.md)).
- Connection, per-IP, circuit and DHT-store limits are capped, and private
  addresses are kept out of the DHT routing table
  ([limits](docs/operations.md#limits-and-hardening)).
- Operational endpoints need a bearer token and answer `404` without it.
- Any node can run a relay. The network does not depend on one instance.

## Quick start

```bash
cargo run -- --generate-key   # print a new hex seed and its PeerId, then exit
cargo run -- --port 4001      # libp2p on TCP + QUIC 4001, HTTP on 9090
curl localhost:9090/health   # from another shell
```

## Configuration

Every flag also reads the matching `RELAY_*` variable; `--help` lists them
all with their defaults. Limits (connections, circuits, DHT records, receipt
and lookup budgets) are in
[docs/operations.md](docs/operations.md#limits-and-hardening).

| Flag / variable | Default | Description |
|---|---|---|
| `--port` / `RELAY_PORT` | `4001` | TCP listen port (`0` = ephemeral) |
| `--quic-port` / `RELAY_QUIC_PORT` | `4001` | QUIC (UDP) listen port |
| `--listen-ip4` / `RELAY_LISTEN_IP4` | `0.0.0.0` | IPv4 address the libp2p listeners bind |
| `--listen-ip6` / `RELAY_LISTEN_IP6` | `::` | IPv6 address the libp2p listeners also bind (best-effort), or `off` |
| `--metrics-port` / `RELAY_METRICS_PORT` | `9090` | HTTP health, metrics and lookup port |
| `--metrics-bind` / `RELAY_METRICS_BIND` | `0.0.0.0` | HTTP listen address; `127.0.0.1` keeps it behind a local reverse proxy |
| `--trusted-proxy-header` / `RELAY_TRUSTED_PROXY_HEADER` | unset | Read the HTTP client address from this header (`Fly-Client-IP` when given without a value). Only behind a proxy that overwrites it; see [client addresses](docs/operations.md#client-addresses-behind-a-proxy) |
| `--public-host` / `RELAY_PUBLIC_HOST` | unset | Public hostname. Advertised (with its resolved IPs) in reservation responses; without it clients reject reservations |
| `--data-dir` / `RELAY_DATA_DIR` | `./relay-data` | Receipts database and DHT record mirror |
| `--generate-key` | — | Print a keypair seed and exit |
| `RELAY_SEED` (env only) | random | 32-byte hex seed for a stable PeerId. Read, then cleared from the environment at startup |
| `RELAY_ADMIN_TOKEN` (env only) | unset | Bearer token for `/peers`, `/metrics` and `/health/alerts`; at least 16 characters, otherwise those endpoints stay off |
| `RUST_LOG` (env only) | `info` | Log level |

Set `RELAY_SEED` and `RELAY_PUBLIC_HOST` in production. Generate an admin
token with `openssl rand -base64 32`; the monitoring observer needs the same
value.

## Architecture

TCP (Noise + Yamux) and QUIC transports carry Circuit Relay v2, Kademlia and
Identify, plus the username-receipt request/response protocol. An Axum
router, served over HTTP/1.1 by hyper with header and request timeouts,
serves health, metrics and username lookups. The library's `start`
runs a whole relay from one configuration value; `src/main.rs` parses flags
and waits for a signal. Modules: `config` (flags and limits), `swarm`
(behaviour and event loop), `http` (routes), `store` (SQLite receipts and DHT
mirror), `username_reg` (receipt wire types and claim verification) and
`addr` (address helpers). `tests/` drives a relay over loopback.

## Deployed relays

Relay PeerIds, hostnames and fallback IPs are owned by the app's network
profile:
[`src-tauri/resources/networks/preprod.json`](https://github.com/ifftu-dev/alexandria/blob/main/src-tauri/resources/networks/preprod.json).
Two Fly.io apps run today: `fly.toml` (Mumbai, `bom`) and `fly-eu.toml`
(Frankfurt, `fra`).

## Documentation

| Doc | Contents |
|---|---|
| [docs/operations.md](docs/operations.md) | Endpoints, alerting, limits, deployment, adding a region |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Local checks, CI and releases, commit messages |
| [docs/audits/security-2026-08.md](docs/audits/security-2026-08.md) | Security audit (2026-08, remediated) |

## License

MIT (Expat), except anything under an `ee/` directory, which has its own
license. See [LICENSE.md](LICENSE.md).
