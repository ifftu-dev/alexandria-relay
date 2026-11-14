# Self-hosting a relay

Status: live
Updated: 2026-11-13

How to run an Alexandria relay on your own machine: a VPS with systemd or
Docker Compose, TLS in front of the HTTP listener, joining the relay mesh,
checking reachability and scraping metrics. Endpoints, limits and the
project's own Fly deployment are in [operations.md](operations.md).

## What a relay does and does not grant

A relay gives connectivity. It relays circuits for peers behind NAT, serves
the private Kademlia DHT, and, with `--announce`, lets app nodes discover
it. Traffic through it is end-to-end encrypted; it cannot read or change it.

Running one grants no authority. Announcing advertises connectivity only:
it grants no username-receipt issuer trust, which comes from the network
profile's issuer list (`receipt_issuer_keys`) and the on-chain relay
registry. Your relay answers receipt requests, but clients count its
receipts only once its PeerId is on that list, which is a reviewed change to
the app's network profile. Being listed in the profile's `relays`, so that
every app dials you by default, is a separate reviewed change too. Neither
is needed to join the mesh.

## Requirements

- A Linux host (amd64 or arm64) with a public IPv4 address that delivers
  connections with their original source address: a VM or bare-metal
  server, not a platform proxy. IPv6 is optional. Behind a proxy the per-IP
  limits stop working ([why](operations.md#client-addresses-behind-a-proxy)).
- A DNS name pointing at that address, passed as `RELAY_PUBLIC_HOST`.
- Inbound ports: `4001/tcp` (libp2p), `4001/udp` (QUIC) and either
  `9090/tcp` (HTTP) or `443/tcp` with the reverse proxy below.
- 1 vCPU and 1 GiB of memory; 1 GiB of disk is plenty. The DHT record cap
  sets the memory budget ([numbers](operations.md#dht-records-and-the-store)).

Create the relay's identity and admin token once, anywhere the binary runs,
and keep both secret:

```sh
alexandria-relay --generate-key   # prints a seed and its PeerId
openssl rand -base64 32           # admin token for /metrics, /peers, /health/alerts
```

`RELAY_SEED` fixes the PeerId; changing it gives the relay a new identity.

## VPS with systemd

Download the static binary for your architecture (`-amd64` or `-arm64`)
from the latest release, check it, and install it:

```sh
base=https://github.com/ifftu-dev/alexandria-relay/releases/latest/download
curl -fsSLO "$base/alexandria-relay-linux-amd64"
curl -fsSLO "$base/SHA256SUMS"
sha256sum -c SHA256SUMS --ignore-missing
sudo install -m 0755 alexandria-relay-linux-amd64 /usr/local/bin/alexandria-relay
sudo useradd --system --no-create-home --shell /usr/sbin/nologin alexandria-relay
sudo install -d -m 0755 /etc/alexandria-relay
```

Write the environment file `/etc/alexandria-relay/relay.env` (mode `0600`,
owned by root; systemd reads it before dropping privileges, while the
directory stays readable so the relay can open the network profile there):

```sh
RELAY_SEED=<64-character hex seed>
RELAY_ADMIN_TOKEN=<token>
RELAY_PUBLIC_HOST=relay.example.org
RELAY_DATA_DIR=/var/lib/alexandria-relay
# Joining the mesh (see below):
# RELAY_NETWORK_PROFILE=/etc/alexandria-relay/network.json
# RELAY_ANNOUNCE=true
# Behind the reverse proxy (see below):
# RELAY_METRICS_BIND=127.0.0.1
# RELAY_TRUSTED_PROXY_HEADER=X-Real-IP
```

Every other flag in `alexandria-relay --help` has a `RELAY_*` variable and
can go here too. Then the unit, `/etc/systemd/system/alexandria-relay.service`:

```ini
[Unit]
Description=Alexandria relay
Wants=network-online.target
After=network-online.target

[Service]
User=alexandria-relay
Group=alexandria-relay
EnvironmentFile=/etc/alexandria-relay/relay.env
ExecStart=/usr/local/bin/alexandria-relay
StateDirectory=alexandria-relay
StateDirectoryMode=0750
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

```sh
sudo chmod 0600 /etc/alexandria-relay/relay.env
sudo systemd-analyze verify /etc/systemd/system/alexandria-relay.service
sudo systemctl daemon-reload
sudo systemctl enable --now alexandria-relay
journalctl -u alexandria-relay -f
sudo ufw allow 4001/tcp && sudo ufw allow 4001/udp && sudo ufw allow 9090/tcp
curl -s http://localhost:9090/health
```

If `ufw` is not enabled yet, allow SSH first (`sudo ufw allow 22/tcp`), then
`sudo ufw enable`. Upgrade by installing a newer binary the same way and
running `sudo systemctl restart alexandria-relay`.

## Docker Compose

The image is `ghcr.io/ifftu-dev/alexandria-relay`, tagged with each release
version and `latest`. It runs as uid/gid `10001` with its data in `/data`.
`compose.yaml`:

```yaml
services:
  relay:
    image: ghcr.io/ifftu-dev/alexandria-relay:latest
    restart: unless-stopped
    network_mode: host
    env_file: relay.env
    volumes:
      - relay-data:/data
      # - ./network.json:/etc/alexandria-relay/network.json:ro
volumes:
  relay-data:
```

Host networking keeps client source addresses intact for the per-IP limits
and lets `RELAY_METRICS_BIND=127.0.0.1` work with a proxy on the host. Use
the same `relay.env` as above without `RELAY_DATA_DIR` (the image sets it).

```sh
chmod 0600 relay.env
docker compose up -d
docker compose logs -f relay
curl -s http://localhost:9090/health
```

Upgrade with `docker compose pull && docker compose up -d`.

## TLS for the HTTP listener

To serve `/health`, `/username/:name` and `/metrics` over HTTPS on 443, keep
the listener on loopback and put a proxy in front that overwrites the client
address header. In `relay.env`:

```sh
RELAY_METRICS_BIND=127.0.0.1
RELAY_TRUSTED_PROXY_HEADER=X-Real-IP
```

A Caddy site (`/etc/caddy/Caddyfile`; Caddy obtains the certificate):

```
relay.example.org {
	reverse_proxy 127.0.0.1:9090 {
		header_up X-Real-IP {remote_host}
	}
}
```

```sh
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
sudo ufw allow 443/tcp && sudo ufw delete allow 9090/tcp
curl -s https://relay.example.org/health
```

Set the trusted header only when every request comes through the proxy. On
a listener clients can reach directly, any client could pick its own
address and escape the username lookup limit.

## Joining the mesh

The network profile lists the network's relays and its protocol namespace.
Fetch it from the app repository's
[`src-tauri/resources/networks/`](https://github.com/ifftu-dev/alexandria/tree/main/src-tauri/resources/networks)
directory, naming the network you are joining:

```sh
sudo curl -fsSL -o /etc/alexandria-relay/network.json \
  https://raw.githubusercontent.com/ifftu-dev/alexandria/main/src-tauri/resources/networks/<network>.json
```

Uncomment `RELAY_NETWORK_PROFILE` in `relay.env` (with Compose, also the
volume line) and restart. The relay dials the profile's relays, keeps them
connected and runs Kademlia bootstrap every 5 minutes. Add
`RELAY_ANNOUNCE=true` to publish this relay under the network's
relay-discovery key, so app nodes find it without configuration; announcing
needs `RELAY_PUBLIC_HOST`, or the record carries no address. Check:

```sh
curl -s http://localhost:9090/health   # reachable_relays >= 1, bootstrap_status "ok"
```

The relay reads the profile at startup only: fetch it again and restart
when the app ships a new one.

## Checking reachability: `doctor`

`alexandria-relay doctor` takes the same flags and environment, starts the
relay, dials each advertised address over TCP and QUIC from a second
in-process client, makes a reservation and lists the addresses it carries,
checks the data directory is writable and tries the admin token against the
HTTP listener. It exits non-zero when no advertised address answers, or when
`RELAY_PUBLIC_HOST` is unset. It binds the relay's ports, so stop the relay
first:

```sh
sudo systemctl stop alexandria-relay
sudo systemd-run --wait --pipe --quiet -p User=alexandria-relay \
  -p EnvironmentFile=/etc/alexandria-relay/relay.env -p StateDirectory=alexandria-relay \
  /usr/local/bin/alexandria-relay doctor
sudo systemctl start alexandria-relay
```

With Compose:

```sh
docker compose stop relay
docker compose run --rm relay doctor
docker compose start relay
```

The dials leave from the relay's own host. A pass shows that the
listeners, advertised addresses and PeerId agree; a cloud firewall or
security group can still block outside clients, so also check from another
machine, for example `nc -vz relay.example.org 4001`.

## Prometheus

`/metrics` answers in the Prometheus text format when the scraper asks for
it ([metric names](operations.md#prometheus)). Put the admin token in a file
Prometheus can read and add a job:

```yaml
scrape_configs:
  - job_name: alexandria-relay
    scheme: https
    authorization:
      credentials_file: /etc/prometheus/relay-token
    static_configs:
      - targets: ["relay.example.org"]
```

Without the proxy, use `scheme: http` and `relay.example.org:9090`.
Without the token, `/metrics` answers 404. Prometheus also defaults to port
9090, so on the relay's own host move one of them
(`--web.listen-address` or `RELAY_METRICS_PORT`).

## Fly.io and other proxied hosts

Platforms that put their own proxy in front of TCP (Fly.io among them) hide
client addresses from the libp2p listener, so the relay's per-IP limits and
libp2p's per-IP reservation and circuit limits see the proxy instead.
QUIC on Fly is unverified. The details, and which limits still work, are in
[client addresses behind a proxy](operations.md#client-addresses-behind-a-proxy).
