# Prometheus output, doctor subcommand and the self-hosting guide

Status: implemented
Updated: 2026-11-13
Triage: done
Repos: alexandria-relay
Part of: alexandria-relay/docs/relay-hardening-spec.md
Blocked by: alexandria-relay/docs/relay-hardening/03-runtime-config-and-black-box-seam.md, alexandria-relay/docs/relay-hardening/04-release-artifacts.md, alexandria-relay/docs/relay-hardening/06-mesh-join.md

## Task

Give an operator the three things they need after the binary runs: metrics
their stack can read, a way to prove the relay is reachable, and one page that
tells them how to run it.

1. `/metrics` serves Prometheus text exposition when the `Accept` header asks
   for it and JSON otherwise, behind the same bearer gate. Counters and gauges
   mirror the JSON fields with a `relay_` prefix; no per-peer data is
   exported.
2. `/health` adds the crate version and reads the live connection count from
   the swarm instead of the five-minute sample.
3. Per-circuit, per-reservation and per-receipt-request log lines move to
   debug. The periodic health line gains deltas since the previous line.
4. Add a `doctor` subcommand. It loads the same configuration, starts the
   relay, dials each advertised external address over TCP and QUIC from a
   second in-process swarm, reports which succeeded, lists the reservation
   address set, checks the data directory is writable, reports whether an
   admin token is configured and accepted by the local HTTP listener, and
   exits non-zero if no advertised address is reachable. Without an external
   host it says so and exits non-zero.
5. Write `docs/self-hosting.md` (`Status: live`): what a relay does and does
   not grant (connectivity relay versus receipt issuer, in the first
   section); requirements (public address, ports, disk); VPS with systemd
   unit and environment file; Docker Compose using the published image;
   reverse-proxy TLS example for the HTTP listener with `--metrics-bind` on
   loopback and the trusted-proxy header; joining the mesh with
   `--network-profile` and `--announce`; running `doctor`; Prometheus scrape
   snippet; the Fly limiter caveat with a link to the operations doc. Link it
   from the README quick start and keep the README under its line limit.

Acceptance: black-box tests show the Prometheus body on the text `Accept`
type and JSON otherwise, both gated; `doctor` exits zero against a relay
started with a reachable external address and non-zero without one; log level
of the per-event lines is verified by configuration, not by asserting on log
text. Every command in the self-hosting guide has been run once on a Linux
host or container and the output pasted into the ticket's completion note.
`scripts/check-docs.sh` passes; fmt, clippy and tests pass.

## Implementation workflow

Read the parent spec and the repository `AGENTS.md`. Use the TDD skill at the
black-box seam. Branch from the tip containing 03, 04 and 06; confirm
ancestry. Return commits, red/green evidence, the guide walkthrough output and
unresolved blockers. Tracker updates are authorized by the invoked
implement-spec workflow.

## Notes

- 2026-11-13: Done.
  - `/metrics` answers in Prometheus text format 0.0.4 when `Accept` names
    `text/plain` (Prometheus's scraper does; the observer does not) and in
    JSON otherwise, behind the same bearer gate. Counters are
    `relay_<field>_total`, gauges `relay_<field>`, plus
    `relay_bootstrap_status{status}` (1 for the current state) and
    `relay_info{peer_id,version}`; nothing per peer. The JSON gains one
    additive field, `receipt_requests`.
  - `/health` adds `version`; `connections` and `total_connections_served`
    update on every connection event, and `uptime_seconds` is computed on
    read.
  - Reservation, circuit and receipt-request lines (accepted, denied and
    rate-limited) are at debug. The `HEALTH` line reports circuits,
    reservations and receipt requests since the previous line.
  - `alexandria-relay doctor` (`src/doctor.rs`) starts the relay from the
    same flags and environment, dials every advertised address over its own
    transport from a second swarm (resolving DNS forms itself, since the
    crate has no DNS transport), makes a reservation and lists the
    addresses it carries, probes the data directory with a create/remove,
    and tries the admin token on `/metrics`. Exit 1 when no public host is
    set or no advertised address answers. `RelayHandle::external_addrs()`
    is new. Every flag is now `global` so flags can follow the subcommand.
  - `docs/self-hosting.md` (live), linked from the README quick start and
    documentation table; `docs/operations.md` names the Prometheus metrics
    and log levels. `--generate-key` points at the guide.
- Red/green: `tests/observability.rs` failed first (JSON served on the
  Prometheus `Accept`; `/health` without `version`), then passed. In
  `tests/logging.rs` a level-recording logger saw four info records while
  one reservation and three receipt requests were served; after the change
  it sees none. The check is the record level from the relay's targets,
  not the text. `tests/doctor.rs` runs the real binary: before the
  subcommand existed all three cases failed (`unexpected argument
  'doctor'`); now it exits 0 with `--public-host localhost`, and 1 without a
  host or with an unresolvable one (`relay.invalid`).
- Fixed on the way: with port zero and IPv6 on, startup took the IPv6
  listener's separate ephemeral port for the external addresses. Startup
  now collects only the IPv4 listeners' addresses, as `listen_addrs()`
  documents. Doctor found this on its first run.
- Walkthrough. The image is not published yet, so it was built locally
  from this branch (`docker buildx build`, a throwaway builder) and its
  local tag replaced `ghcr.io/ifftu-dev/alexandria-relay:latest`. The
  release download was served by a local HTTP server holding the binary
  copied out of that image (arm64 host, so `-arm64`) and a `SHA256SUMS`
  made the way CI makes it. All seeds, tokens and the network profile were
  synthetic: a profile for network `walkthrough` naming one peer relay,
  another container of the same image. The systemd host was a
  `debian:bookworm-slim` container running systemd as PID 1 (privileged),
  with `caddy` and `prometheus` from Debian. Compose ran inside a
  `docker:27-dind` container. Containers, images, the network and the
  builder and its cache were removed afterwards. Condensed output:

  ```
  # VPS with systemd
  sha256sum -c SHA256SUMS --ignore-missing   -> alexandria-relay-linux-arm64: OK
  alexandria-relay --generate-key            -> seed, PeerId, profile + guide pointers
  systemd-analyze verify ...service          -> exit 0, no warnings
  systemctl enable --now alexandria-relay    -> active (running), User=alexandria-relay
  journalctl -u alexandria-relay             -> "External addresses registered:
     [/dns4/relay.example.org/tcp/4001, /dns4/relay.example.org/udp/4001/quic-v1,
      /ip4/172.26.0.3/tcp/4001, /ip4/172.26.0.3/udp/4001/quic-v1]"
  ufw allow 4001/tcp|4001/udp|9090/tcp       -> Rules updated (v4 + v6)
  curl localhost:9090/health                 -> {"bootstrap_status":"disabled",
     "connections":0,...,"status":"ok","version":"0.1.0"}
  /var/lib/alexandria-relay                  -> 0750 alexandria-relay, db + -wal + -shm

  # doctor (systemctl stop; systemd-run ... doctor; systemctl start)
  ok    /dns4/relay.example.org/tcp/4001 (dialled /ip4/172.26.0.3/tcp/4001)
  ok    /dns4/relay.example.org/udp/4001/quic-v1 (dialled .../udp/4001/quic-v1)
  ok    /ip4/172.26.0.3/tcp/4001   ok /ip4/172.26.0.3/udp/4001/quic-v1
  Reachable on 4 of 4 advertised addresses
  Reservation accepted; it carries 4 address(es): .../p2p-circuit/p2p/...
  data directory /var/lib/alexandria-relay: writable
  admin token: configured, accepted by http://127.0.0.1:9090/metrics
  Result: reachable                          -> exit 0; relay active again
  nc -vz relay.example.org 4001 (other container) -> succeeded

  # Joining the mesh (profile from the local server, both lines uncommented)
  first run: "invalid network profile: cannot open .../network.json:
     Permission denied" -> guide fixed (/etc/alexandria-relay 0755, env 0600)
  curl localhost:9090/health                 -> "bootstrap_status":"ok",
     "profile_relays":1,"reachable_relays":1
  log: "MESH connected to profile relay ...", "MESH announced this relay ..."

  # TLS (Caddy; `local_certs` prepended since no public certificate here)
  ss -ltn                                    -> 127.0.0.1:9090 only
  caddy validate                             -> Valid configuration
  systemctl reload caddy; ufw allow 443/tcp; ufw delete allow 9090/tcp
  curl https://relay.example.org/health      -> {"bootstrap_status":"ok",...}
  31 lookups through Caddy, each claiming a new X-Real-IP
                                             -> 1..30: 200, 31: 429
  http://relay.example.org:9090 from outside -> refused
  ufw allow 22/tcp; ufw enable               -> active; 4001, 443 open, 22 allowed

  # Prometheus (ca_file for the local CA; Prometheus on 9091, see below)
  promtool check config                      -> SUCCESS
  /api/v1/targets                            -> https://relay.example.org:443/metrics up
  relay_reachable_relays                     -> 1
  relay_bootstrap_status == 1                -> status="ok"

  # Docker Compose (inside docker:27-dind)
  docker compose up -d; logs; curl health    -> started, "status":"ok"
  docker compose stop; run --rm relay doctor -> Reachable on 4 of 4,
     data directory /data: writable, admin token accepted, exit 0
  volume line + profile lines, up -d         -> "reachable_relays":1, "bootstrap_status":"ok"
  docker compose exec relay id               -> uid=10001(relay)
  docker compose pull                        -> pull access denied (local-only tag)
  ```

- Not run as written: the real release URL and `ghcr.io` image (not
  published; substituted as above); `journalctl -f` (read once with
  `--no-pager` instead of following); the raw profile URL (a synthetic
  profile served locally instead of the app repository's); Caddy's public
  certificate (internal CA instead); `docker compose pull` (fails for the
  local-only tag; meaningful once the image is published); `nc` "from
  another machine" (another container on the same Docker network).
- Guide fixes from the walkthrough: `/etc/alexandria-relay` must be
  traversable by the relay user (the first mesh restart failed reading the
  profile), the `ufw enable` hint, and the note that Prometheus and the
  relay both default to port 9090.
- Deviations: Prometheus counters carry the `_total` suffix and
  `total_connections_served` is exported as
  `relay_connections_served_total`, rather than the bare JSON names. The
  `Accept` check matches `text/plain` anywhere in the header and always
  serves format 0.0.4, which Prometheus accepts even when it lists
  OpenMetrics first. Denied and rate-limited per-event lines also moved to
  debug, since they grow with traffic too; the counters and
  `/health/alerts` carry them. Doctor fails the run only on reachability,
  as specified; an unwritable data directory or a rejected token is
  reported as a `FAIL` line without changing the exit code.

- 2026-11-13, review fixes: every per-event line goes through one macro
  at one level constant (debug), on a per-kind target under
  `alexandria_relay::event` (`connection`, `identify`, `reservation`,
  `circuit`, `receipt`, `kad`). `tests/logging.rs` records target and
  level: nothing at info while serving, and at least one reservation and
  three receipt lines at debug. It fails if a line moves to info or is
  removed (both checked by mutation). The doctor tests gain an address
  that resolves and does not answer (`--public-host ::1`, nothing
  listening on IPv6), which fails a doctor that stops at resolution. The
  admin routes share one auth layer and the doctor shares the token
  minimum; no output changed.

### Pending maintainer verification

- 2026-11-13: one acceptance item needs published artifacts. "Every
  command in the self-hosting guide has been run" holds except for the
  commands that fetch what a tag publishes: the release download and its
  `sha256sum -c` against the published `SHA256SUMS`, and pulling the
  published image (`docker compose pull`, and `docker run` of the registry
  image). Both ran only against local substitutes. They need the first
  `v*` tag's release assets and the image set to public.
