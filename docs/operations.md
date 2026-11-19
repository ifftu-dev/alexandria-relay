# Relay operations

Status: live
Updated: 2026-11-19

How to run, watch and deploy the relay. Listener and identity settings are
in the [README](../README.md#configuration); limits are below. To run a
relay of your own, start with [self-hosting.md](self-hosting.md); this page
also covers the project's Fly deployment.

## HTTP endpoints

The HTTP server listens on `--metrics-bind` and `--metrics-port` (default
`0.0.0.0:9090`). On Fly it is also served over TLS on `443`; `9090` is kept
for the platform healthcheck.

Operational endpoints need `Authorization: Bearer $RELAY_ADMIN_TOKEN`. They
answer `404`, not `401`, when the token is missing, wrong or not configured,
so a scanner can't tell that they exist.

| Endpoint | Auth | Returns |
|---|---|---|
| `GET /health` | public | `{"status":"ok","version":…,"peer_id":…,"uptime_seconds":…,"connections":…,"profile_relays":…,"reachable_relays":…,"bootstrap_status":…}`. `connections` is the live count of connected peers |
| `GET /username/:name` | public | Username availability from the receipt registry. Clients resolve names against it |
| `GET /health/alerts` | bearer | `200` when healthy, `503` when any alert fires; the body lists firing alerts and rolling 60 s rates |
| `GET /metrics` | bearer | Connections (also established by transport), circuits, reservations, receipt requests, DHT updates, identify events, listener errors, IP rate limits, PROXY header refusals, QUIC budget refusals, rolling-minute denials, mesh state. JSON, or Prometheus text when `Accept` names `text/plain` ([names](#prometheus)) |
| `GET /peers` | bearer | `{peer_id, source_prefix, has_reservation}` per peer. `source_prefix` is a `/24` (IPv4) or `/48` (IPv6) network, never a full address |

Mesh state, on both routes: `profile_relays` is how many other relays the
network profile names (0 without `--network-profile`), `reachable_relays` how
many of them this relay is connected to, and `bootstrap_status` is
`disabled` (no profile), `pending` (no bootstrap finished yet), `ok` or
`failed` (the last bootstrap timed out).

## Monitoring

The `alexandria-monitoring` observer scrapes `/metrics` every 10 seconds
(and `/peers`, for geo attribution of NATted peers) and shows a relay health
panel. On the observer, set `RELAY_METRICS_URL` to the relays' `https://…/metrics`
URLs (comma-separated) and `RELAY_ADMIN_TOKEN` to the relay's token.

### Prometheus

A request whose `Accept` header names `text/plain`, as Prometheus's scraper
does, gets the text exposition format (0.0.4); anything else gets JSON. Same
bearer token. Each JSON counter becomes `relay_<field>_total`
(`relay_circuits_accepted_total`; `total_connections_served` becomes
`relay_connections_served_total`), each gauge `relay_<field>`
(`relay_connections`, `relay_reachable_relays`, `relay_uptime_seconds`).
`relay_bootstrap_status{status="…"}` is 1 for the current state and 0 for
the others, and `relay_info{peer_id,version}` is always 1.
`relay_connections_established_total{transport="tcp"|"quic"}` splits
established connections by transport (JSON: `connections_established`).
PROXY header refusals are `relay_proxy_header_{missing,invalid,timeout,overflow}_total`;
QUIC budget refusals are `relay_quic_pending_denied_total`, with the last
full minute's count in `relay_quic_pending_denied_per_min`. Nothing per peer
is exported. A scrape configuration is in
[self-hosting.md](self-hosting.md#prometheus).

### Logs

At the default `info` level the relay logs startup, mesh changes, errors
and one `HEALTH` line every `--health-log-interval-secs`, with the circuits,
reservations and receipt requests (accepted and denied) since the previous
line. Per-connection, per-circuit, per-reservation and per-receipt lines
are at `debug` (`RUST_LOG=alexandria_relay=debug`). Each kind has its own
target, so `RUST_LOG=alexandria_relay::event::<kind>=debug` turns on one kind
alone: `connection`, `identify`, `reservation`, `circuit`, `receipt` or `kad`.

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
| `proxy_header_refusal_majority` | with PROXY protocol on, refusals for a missing, malformed or late header are at least 10 and more than half of inbound TCP connections, in the last full minute or the one in progress. Usually the proxy stopped sending the header: see [rollback](#rollback) |
| `quic_pending_denied_sustained` | > 60 QUIC handshakes refused by the pending budget in the last full minute |

## Limits and hardening

Every limit is a flag with a matching environment variable, read at
startup; `alexandria-relay --help` lists them with their defaults. Durations
are in seconds.

| Limit | Flag | Variable | Default |
|---|---|---|---|
| Connections in total | `--max-connections` | `RELAY_MAX_CONNECTIONS` | 1024 |
| Connections per PeerId | `--max-connections-per-peer` | `RELAY_MAX_CONNECTIONS_PER_PEER` | 8 |
| Incoming connections still in the handshake (also caps TCP sockets awaiting a PROXY header) | `--max-pending-incoming` | `RELAY_MAX_PENDING_INCOMING` | 256 |
| Time a TCP connection has to send its PROXY header | `--proxy-header-timeout-secs` | `RELAY_PROXY_HEADER_TIMEOUT_SECS` | 5 |
| Incoming QUIC connections still in the handshake, within the cap above | `--quic-max-pending-incoming` | `RELAY_QUIC_MAX_PENDING_INCOMING` | 64 |
| QUIC receive window per stream, bytes | `--quic-max-stream-data` | `RELAY_QUIC_MAX_STREAM_DATA` | 262144 (256 KiB) |
| QUIC receive window per connection, bytes | `--quic-max-connection-data` | `RELAY_QUIC_MAX_CONNECTION_DATA` | 524288 (512 KiB) |
| QUIC handshake timeout | `--quic-handshake-timeout-secs` | `RELAY_QUIC_HANDSHAKE_TIMEOUT_SECS` | 5 |
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
| Time for an HTTP request's headers to arrive | `--http-header-read-timeout-secs` | `RELAY_HTTP_HEADER_READ_TIMEOUT_SECS` | 10 |
| Time from HTTP request headers to response (then `503`) | `--http-request-timeout-secs` | `RELAY_HTTP_REQUEST_TIMEOUT_SECS` | 15 |
| Concurrent HTTP connections (more wait in the listen backlog) | `--http-max-connections` | `RELAY_HTTP_MAX_CONNECTIONS` | 256 |
| Health log interval | `--health-log-interval-secs` | `RELAY_HEALTH_LOG_INTERVAL_SECS` | 300 |

The QUIC windows bound receive buffers at 512 MiB with 1,024 connections
(quinn's defaults would allow about 15 GiB) and cap one relayed circuit
over QUIC near 256 KiB per round trip. UDP sources are spoofable, so the
QUIC budget has no per-IP part.

Two bounds are part of the wire format and are not configurable: a username
receipt request is at most 8 KiB, and its DID at most 64 characters.

"Per IP" means per client bucket: the full IPv4 address, or the /64 an IPv6
address belongs to, since one subscriber holds a whole /64. The relay's
connection limiter, the lookup limiter and the source prefixes behind
`/peers` all use it.

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
- A peer enters the DHT routing table only from the addresses it reports
  through Identify, never from the address its connection came from.
  Private, CGNAT, link-local, ULA, IPv4-mapped, multicast and site-local
  addresses are kept out.
- The HTTP listener speaks HTTP/1.1 only and closes connections whose
  headers do not arrive within the header timeout, idle keep-alive
  connections included.
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

## Client addresses behind a proxy

Every per-address limit keys on the address a connection comes from. When a
proxy sits in front of the relay, that is the proxy's address, and the limit
then either throttles every user as one client or, with a high ceiling,
protects nothing.

**libp2p listener.** On a host that delivers connections with their
original source address (a VM or bare-metal host with a public IP, or a
load balancer in pass-through mode) nothing needs setting. Behind a TCP
proxy that sends PROXY protocol v2, set `--tcp-proxy-protocol v2`
(`RELAY_TCP_PROXY_PROTOCOL`): every inbound TCP connection must then open
with a v2 header, and the relay attributes it to the header's source
address, so the per-IP connection limiter, libp2p's per-IP reservation and
circuit limiters, Identify's observed address and `/peers` all see the
client. A LOCAL header (platform health checks) keeps the socket address.
Anything else is closed and counted: no header as `proxy_header_missing`;
a version 1 (text), malformed, UNIX-family or over-1 KiB header as
`proxy_header_invalid`; a header that does not arrive within
`--proxy-header-timeout-secs` as `proxy_header_timeout`; a socket beyond
the waiting cap as `proxy_header_overflow`. Outbound dials are unaffected.

The relay trusts the first header on a connection, so turn `v2` on only
when every connection comes through the proxy. On Fly the public addresses
reach the machine only through Fly's proxy, which writes its header first;
machines on the organisation's private network can reach the port directly
and are trusted. The Fly relays run with `v2` (the `proxy_proto` handler in
`fly.toml` and `fly-eu.toml`). Behind a proxy that cannot send the header,
these limiters see the proxy instead:

- the relay's per-IP connection limiter (`--max-connections-per-ip`,
  `--max-new-connections-per-ip`);
- libp2p's built-in per-IP reservation and circuit rate limiters, which are
  not configurable and key on the full address.

Per-PeerId limits and the global caps are unaffected.

**HTTP listener.** PROXY protocol does not apply here; the username
lookup limiter keys on the socket address unless you set
`--trusted-proxy-header` (`RELAY_TRUSTED_PROXY_HEADER`). Set it only when
every request reaches the listener through a proxy that writes the
client address into a header, overwriting anything the client sent. Given
without a value it reads `Fly-Client-IP`, which Fly's `http` handler sets;
behind nginx or Caddy, name the header the proxy sets (for example
`X-Real-IP`). For an appending header such as `X-Forwarded-For`, the relay
reads the last entry. A request without the header is charged to the socket
address. Leave the flag unset on a listener that clients can reach directly:
any client could then write a new address into the header for every request
and never hit the lookup limit. Behind a local reverse proxy, bind the
listener to loopback with `--metrics-bind 127.0.0.1`.

**QUIC on Fly does not work, so it is off there.** A 2026-11 experiment on
a throwaway Fly app found that QUIC from an outside client reached the
machine on two to four connections after each restart, then no packets
arrived (a packet capture saw none) until the next restart. Fly machines
dialing the app's anycast address got nothing, and both production relays
failed every attempt. The drops happen inside Fly, before the machine,
whichever address the server binds, and Fly's documentation says QUIC is
not supported. The Fly relays therefore run with `RELAY_QUIC=false` and no
UDP service: no UDP listener, no QUIC address in Identify or reservations.
Re-test before turning it back on, for example with a `staging_quic` run of
the [staging rehearsal](#staging-rehearsal). With QUIC on (the default
elsewhere), handshakes have their own pending budget and smaller windows
([limits](#limits-and-hardening)).

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
| `4001` | TCP, PROXY v2 | libp2p (relay, Kademlia, Identify, username receipts) |
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

Also set `RELAY_PUBLIC_HOST` to the app's hostname, and keep a dedicated
IPv4 (`fly ips allocate-v4`): raw TCP over IPv4 needs one on Fly, and the
network profile's fallback addresses point at it. `fly-eu.toml` mounts
`relay_data` at `/data`. `fly.toml` (Singapore) has no mount: the app started
in `bom`, which refused volume creation, and Fly has since retired `bom`. Its
receipt history resets on restart. Issued receipts stay valid, because they
are signed.

Routine deploys run from CI on `v*` tags or a manual run with
`target: production` (see
[CONTRIBUTING.md](../CONTRIBUTING.md#ci-and-releases)). CI deploys
Frankfurt, probes it from the runner with `probe`, and only on a pass
deploys and probes Singapore.

### Rollback

The Fly config and the image must agree about the PROXY header. An image
without PROXY support behind the `proxy_proto` handler refuses every TCP
connection, and so does an image with `v2` on behind a config without the
handler. CI deploys config and image together, and a rollback must too:
never roll back the image alone (`fly deploy --image` with the current
config, or `fly releases rollback`). One region at a time, Frankfurt first:

```bash
git show <previous-tag>:<config> > rollback.toml
fly deploy --config rollback.toml \
  --image ghcr.io/ifftu-dev/alexandria-relay:<previous-version>
alexandria-relay probe --host <app>.fly.dev --peer-id <PeerId>
rm rollback.toml
```

`<config>` is `fly-eu.toml`, `fly.toml` or `fly-staging.toml`, and
`<previous-version>` the previous tag without its `v`. If the probe fails,
stop before the next region.

### Staging rehearsal

Rerun this, on the release candidate (`vX.Y.Z-rc.N`) and before the release
tag, for any release that changes transports or Fly config. The staging
relay (`fly-staging.toml`, app `alexandria-relay-staging`) matches
production's TCP service and `[env]`, keeps a UDP service so QUIC can be
switched on for one check, and stays out of the mesh: no network profile,
no announce, its own identity.

Set it up:

```bash
fly apps create alexandria-relay-staging
fly ips allocate-v4 -a alexandria-relay-staging   # dedicated; raw TCP needs it
fly ips allocate-v6 -a alexandria-relay-staging
alexandria-relay --generate-key                   # fresh seed; note the PeerId
fly secrets set -a alexandria-relay-staging --stage RELAY_SEED="<seed>" \
  RELAY_ADMIN_TOKEN="<token>" RELAY_PUBLIC_HOST=alexandria-relay-staging.fly.dev
gh variable set STAGING_RELAY_PEER_ID --body "<PeerId>"
```

The repository's `FLY_API_TOKEN` must be allowed to deploy the new app (a
token scoped to the production apps is not). Then **Run workflow** on the
release candidate's tag with `target: staging`: the job builds that commit,
fails before touching Fly if `STAGING_RELAY_PEER_ID` is unset, deploys and
runs the pinned TCP probe. Probes by hand use the release candidate's image
or binary: `probe --host alexandria-relay-staging.fly.dev --peer-id
<PeerId>`. Each item passes before the release tag:

1. The workflow's staging deploy and TCP probe pass.
2. `/peers` (admin token), read while a client on a known machine is
   connected, shows that machine's address bucket, not a Fly address.
3. With `fly secrets set RELAY_MAX_CONNECTIONS_PER_IP=1` on the staging app
   and a dev app build connected, a probe from the same machine fails and
   a probe from the CI runner (rerun the job) passes. Unset it afterwards.
4. Old image, new config: an image without PROXY support deployed with
   `fly-staging.toml` makes the probe fail.
5. New image, old config: the release candidate deployed with a local copy
   of `fly-staging.toml` without the `proxy_proto` handler makes the probe
   fail and raises `proxy_header_missing` and `proxy_header_refusal_majority`.
6. Rollback: redeploying the matching image and config, following
   [rollback](#rollback) word for word, makes the probe pass again.
7. A dev app build with the staging relay added through its extra-relays
   setting gets a reservation, and the app's view of its own public address
   is the machine's real address.
8. A probe to the staging IPv6 address (`--host <IPv6 address>`) passes
   from a machine with IPv6 (CI runners have none; Docker needs IPv6
   networking, or use the binary).
9. A run with `staging_quic` ticked records in the job summary how many of
   five QUIC probes from the runner passed. Record the result either way; a
   reliable pass reopens QUIC on Fly in a new spec.
10. Teardown: `fly apps destroy alexandria-relay-staging` (releases its
    addresses) and `gh variable delete STAGING_RELAY_PEER_ID`.

Record the results in the release's spec or pull request.

### One machine per region

The receipt store is a single-writer SQLite database, and each volume mounts
on one machine. Run exactly one machine per region; CI enforces this with
`flyctl scale count 1`. Redundancy comes from running more regions. A restart
drops that relay's reservations; clients reconnect, usually within about 30 s.

### Adding a region

1. `cargo run -- --generate-key` and keep the seed and PeerId.
2. Copy `fly-eu.toml` with a new `app` and `primary_region`, then
   `fly apps create <app>` and set its secrets as above.
3. `fly ips allocate-v4 -a <app>` (dedicated), `fly deploy -c <config>`,
   then `fly ips list -a <app>` for the IPv4.
4. Add the relay (PeerId, DNS name, port, fallback IP, registry origin) to
   `relays`, and its PeerId to `receipt_issuer_keys`, in the app's
   [`preprod.json`](https://github.com/ifftu-dev/alexandria/blob/main/src-tauri/resources/networks/preprod.json).
5. Add its metrics URL to the observer's `RELAY_METRICS_URL`.
6. Add a job to `.github/workflows/ci.yml` that calls `fly-deploy.yml`
   with the new config and `needs` the previous region's job, so it joins
   the deploy-and-probe chain.

Each relay keeps its own Kademlia routing table. Peers connected to different
relays find each other through DHT propagation.
