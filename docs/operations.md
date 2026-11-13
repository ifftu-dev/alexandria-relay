# Relay operations

Status: live
Updated: 2026-11-13

How to run, watch and deploy the relay. Listener and identity settings are
in the [README](../README.md#configuration); limits are below.

## HTTP endpoints

The HTTP server listens on `--metrics-bind` and `--metrics-port` (default
`0.0.0.0:9090`). On Fly it is also served over TLS on `443`; `9090` is kept
for the platform healthcheck.

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
| `connections_near_cap` | connections > 80% of `--max-connections` (default 1,024) |
| `circuits_denied_per_min_high` | > 100 circuit denials in the last minute |
| `circuit_denial_majority` | denials > accepts in the last minute, with > 20 total |
| `reservations_denied_per_min_high` | > 10 reservation denials in the last minute |
| `listener_errors_observed` | any listener error since start |

## Limits and hardening

Every limit is a flag with a matching environment variable, read at
startup; `alexandria-relay --help` lists them with their defaults. Durations
are in seconds.

| Limit | Flag | Variable | Default |
|---|---|---|---|
| Connections in total | `--max-connections` | `RELAY_MAX_CONNECTIONS` | 1024 |
| Connections per PeerId | `--max-connections-per-peer` | `RELAY_MAX_CONNECTIONS_PER_PEER` | 8 |
| Incoming connections still in the handshake | `--max-pending-incoming` | `RELAY_MAX_PENDING_INCOMING` | 256 |
| Concurrent connections per IP | `--max-connections-per-ip` | `RELAY_MAX_CONNECTIONS_PER_IP` | 32 |
| New connections per IP per window | `--max-new-connections-per-ip` | `RELAY_MAX_NEW_CONNECTIONS_PER_IP` | 32 |
| Per-IP connection window | `--ip-rate-window-secs` | `RELAY_IP_RATE_WINDOW_SECS` | 60 |
| Idle connection timeout | `--idle-timeout-secs` | `RELAY_IDLE_TIMEOUT_SECS` | 600 |
| Identify addresses added per peer | `--max-identify-addrs` | `RELAY_MAX_IDENTIFY_ADDRS` | 16 |
| Kademlia query timeout | `--kad-query-timeout-secs` | `RELAY_KAD_QUERY_TIMEOUT_SECS` | 60 |
| Kademlia replication factor | `--kad-replication-factor` | `RELAY_KAD_REPLICATION_FACTOR` | 20 |
| DHT records (memory store and disk mirror) | `--kad-max-records` | `RELAY_KAD_MAX_RECORDS` | 16384 |
| DHT record size, bytes | `--kad-max-record-bytes` | `RELAY_KAD_MAX_RECORD_BYTES` | 65536 |
| Reservations in total | `--max-reservations` | `RELAY_MAX_RESERVATIONS` | 1024 |
| Reservations per peer | `--max-reservations-per-peer` | `RELAY_MAX_RESERVATIONS_PER_PEER` | 16 |
| Reservation lifetime | `--reservation-duration-secs` | `RELAY_RESERVATION_DURATION_SECS` | 3600 |
| Circuits in total | `--max-circuits` | `RELAY_MAX_CIRCUITS` | 2048 |
| Circuits per peer | `--max-circuits-per-peer` | `RELAY_MAX_CIRCUITS_PER_PEER` | 128 |
| Bytes per circuit | `--max-circuit-bytes` | `RELAY_MAX_CIRCUIT_BYTES` | 134217728 (128 MiB) |
| Circuit lifetime | `--max-circuit-duration-secs` | `RELAY_MAX_CIRCUIT_DURATION_SECS` | 900 |
| Username receipt requests per PeerId per window | `--receipt-limit` | `RELAY_RECEIPT_LIMIT` | 5 |
| Receipt window | `--receipt-window-secs` | `RELAY_RECEIPT_WINDOW_SECS` | 60 |
| Username lookups per client IP per window | `--lookup-limit` | `RELAY_LOOKUP_LIMIT` | 30 |
| Lookup window | `--lookup-window-secs` | `RELAY_LOOKUP_WINDOW_SECS` | 60 |
| Client IPs the lookup limiter tracks | `--lookup-max-tracked` | `RELAY_LOOKUP_MAX_TRACKED` | 10000 |
| Health log interval | `--health-log-interval-secs` | `RELAY_HEALTH_LOG_INTERVAL_SECS` | 300 |

Two bounds are part of the wire format and are not configurable: a username
receipt request is at most 8 KiB, and its DID at most 64 characters.

### DHT records and the store

The relay keeps one SQLite database, `username_registry.db`, in
`--data-dir`. It holds username receipts and a mirror of every DHT record the
in-memory store accepted, with each record's expiry and publisher, so a
restart reloads the records with the time they had left. The database runs
in write-ahead-log mode, so the directory also holds `-wal` and `-shm` files
and must be writable, not only the database file. All database work runs on
one dedicated thread; a burst of DHT writes never delays circuits or HTTP.
If that thread falls 1,024 requests behind, new mirror writes are dropped
(the record stays in memory) and receipt requests are refused with "relay
busy".

- Expired records are skipped on reload and deleted every 10 minutes.
- When the mirror is over `--kad-max-records`, it evicts expired records
  first, then the soonest-expiring, then the oldest-inserted.
- A database written by an older binary is recreated empty at startup. The
  project is pre-launch, so there are no migrations.

Memory and disk: the records the app writes are signed username claims,
about 300 bytes bare and 0.8 to 1.5 KB with relay receipts, an anchor and a
release. With per-record overhead, budget about 2 KB per record: the default
16,384 records come to about 32 MiB of memory, and a similar amount on disk.
The cap on record size (`--kad-max-record-bytes`, 64 KiB) is what someone
writing junk records could reach, about 1 GiB at the default record cap;
lower `--kad-max-records` on a small machine.

Provider announcements are not mirrored; they expire on their own. The
memory store keeps at most 20 providers per key (libp2p's default, the
Kademlia `k`) and ignores further providers until one expires. The
relay-discovery key is a single key, so at most 20 announcing relays are
listed on any one relay at a time.

Other hardening:
- Private, CGNAT, link-local, ULA, IPv4-mapped, multicast and site-local
  addresses are kept out of the DHT routing table.
- `RELAY_SEED` is cleared from the environment before the async runtime
  starts, and the seed buffer is zeroed after use.
- SIGTERM and SIGINT shut down gracefully.

Tuning notes:
- The per-IP limits suit residential and mobile NATs. Load tests from one IP
  (CI runners, dev clusters) will hit them; start the relay under test with
  higher `--max-connections-per-ip` and `--max-new-connections-per-ip`.
- The per-peer circuit cap (`--max-circuits-per-peer`) is the first limit to
  raise if you add observers that fan-dial peers through circuits, since
  each counts as the source peer. With several high-frequency observers, try
  256–512 before the global circuit cap becomes the bottleneck.

## Deployment (Fly.io)

The `Dockerfile` builds a static musl binary with `rust:1.89-alpine` and runs
it on `debian:bookworm-slim` as uid/gid `10001`, with `RELAY_DATA_DIR=/data`.
The runtime stage refuses to build if `ca-certificates` is older than
`20250419~deb12u2` (the eMudhra trust-store fix). Cargo uses the committed
lockfile. Updating the repository does not update running machines: tag a
release or run the workflow to redeploy.

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
