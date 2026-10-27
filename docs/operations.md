# Relay operations

Status: live
Updated: 2026-10-27

How to run, watch and deploy the relay. Configuration flags and env vars are
in the [README](../README.md#configuration).

## HTTP endpoints

The HTTP server listens on the metrics port (default `9090`). On Fly it is
also served over TLS on `443`; `9090` is kept for the platform healthcheck.

Operational endpoints need `Authorization: Bearer $RELAY_ADMIN_TOKEN`. They
answer `404`, not `401`, when the token is missing, wrong or not configured,
so a scanner can't tell that they exist.

| Endpoint | Auth | Returns |
|---|---|---|
| `GET /health` | public | `{"status":"ok","peer_id":…,"uptime_seconds":…,"connections":…}` |
| `GET /username/:name` | public | Username availability from the receipt registry. Clients resolve names against it |
| `GET /health/alerts` | bearer | `200` when healthy, `503` when any alert fires; the body lists firing alerts and rolling 60 s rates |
| `GET /metrics` | bearer | Connections, circuits, reservations, DHT updates, identify events, listener errors, IP rate limits, rolling-minute denials |
| `GET /peers` | bearer | `{peer_id, source_prefix, has_reservation}` per peer. `source_prefix` is a `/24` (IPv4) or `/48` (IPv6) network, never a full address |

## Monitoring

The `alexandria-monitoring` observer scrapes `/metrics` every 10 seconds
(and `/peers`, for geo attribution of NATted peers) and shows a relay health
panel. On the observer, set `RELAY_METRICS_URL` to the relays' `https://…/metrics`
URLs (comma-separated) and `RELAY_ADMIN_TOKEN` to the relay's token.

## External alerting

Point an HTTP monitor (UptimeRobot, healthchecks.io) at
`https://<relay-host>/health/alerts` with the bearer header. Alert on any
`5xx` and read the JSON body to see which signal fired.

| Alert | Fires when |
|---|---|
| `connections_near_cap` | connections > 80% of the 1,024 cap |
| `circuits_denied_per_min_high` | > 100 circuit denials in the last minute |
| `circuit_denial_majority` | denials > accepts in the last minute, with > 20 total |
| `reservations_denied_per_min_high` | > 10 reservation denials in the last minute |
| `listener_errors_observed` | any listener error since start |

## Limits and hardening

Values are constants in `src/main.rs` and `src/username_reg.rs`.

| Limit | Value |
|---|---|
| Connections | 1,024 total, 8 per PeerId |
| Connections per IP | 32 concurrent, 32 new per minute |
| Relay reservations | 1,024 total, 16 per peer, 1 h each |
| Relay circuits | 2,048 total, 128 per peer, 128 MB and 15 min each |
| DHT records | 16,384 (memory store and disk mirror), 64 KB each |
| Username receipt requests | 5 per PeerId per minute |
| Username lookups (`/username/:name`) | 30 per minute per client IP |
| Idle connection timeout | 10 min |
| Health log interval | 5 min |

Other hardening:
- Private, CGNAT, link-local, ULA, IPv4-mapped, multicast and site-local
  addresses are kept out of the DHT routing table.
- `RELAY_SEED` is cleared from the environment before the async runtime
  starts, and the seed buffer is zeroed after use.
- SIGTERM and SIGINT shut down gracefully.

Tuning notes:
- The per-IP limits suit residential and mobile NATs. Load tests from one IP
  (CI runners, dev clusters) will hit them; raise them for the test.
- The per-peer circuit cap (128) is the first limit to raise if you add
  observers that fan-dial peers through circuits, since each counts as the
  source peer. With several high-frequency observers, try 256–512 before the
  global circuit cap becomes the bottleneck.

## Deployment (Fly.io)

The `Dockerfile` builds with `rust:1.88-slim-bookworm` and runs on
`debian:bookworm-slim`. Both stages refuse to build if `ca-certificates` is
older than `20250419~deb12u2` (the eMudhra trust-store fix). Cargo uses the
committed lockfile. Updating the repository does not update running machines:
rebuild and redeploy.

Fly services (`fly.toml`, `fly-eu.toml`):

| Port | Protocol | Use |
|---|---|---|
| `4001` | TCP | libp2p (relay, Kademlia, Identify, username receipts) |
| `4001` | UDP | QUIC |
| `443` | TCP, TLS | HTTP endpoints |
| `9090` | TCP | HTTP endpoints; Fly healthcheck on `/health` |

First launch of a region:

```bash
fly launch --no-deploy
fly secrets set RELAY_SEED="<64-char hex seed>" RELAY_ADMIN_TOKEN="<token>"
fly volumes create relay_data --region <region> --size 1
fly deploy
fly status && fly logs
```

Also set `RELAY_PUBLIC_HOST` to the app's hostname. `fly-eu.toml` mounts
`relay_data` at `/data`. `fly.toml` (Mumbai) has no mount, because `bom` has
refused volume creation, so its receipt history resets on restart. Issued
receipts stay valid, because they are signed.

Routine deploys run from CI on `v*` tags or manual dispatch (see
[CONTRIBUTING.md](../CONTRIBUTING.md#ci-and-releases)).

### One machine per region

The receipt store is a single-writer SQLite database, and each volume mounts
on one machine. Run exactly one machine per region; CI enforces this with
`flyctl scale count 1`. Redundancy comes from running more regions. A restart
drops that relay's reservations; clients reconnect, usually within about 30 s.

### Adding a region

1. `cargo run -- --generate-key` and keep the seed and PeerId.
2. Copy `fly-eu.toml` with a new `app` and `primary_region`, then
   `fly apps create <app>` and set its secrets as above.
3. `fly deploy -c <config>`, then `fly ips list -a <app>` for the IPv4.
4. Add the relay (PeerId, DNS name, port, fallback IP, registry origin) to
   `relays`, and its PeerId to `receipt_issuer_keys`, in the app's
   [`preprod.json`](https://github.com/ifftu-dev/alexandria/blob/main/src-tauri/resources/networks/preprod.json).
5. Add its metrics URL to the observer's `RELAY_METRICS_URL`.
6. Add a matrix entry to the `deploy` job in `.github/workflows/ci.yml`.

Each relay keeps its own Kademlia routing table. Peers connected to different
relays find each other through DHT propagation.
