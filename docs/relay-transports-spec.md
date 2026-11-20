# Relay transports on Fly: real client addresses, honest QUIC

Status: implemented
Updated: 2026-11-21
Triage: done
Repos: alexandria-relay

Work is split into numbered sub-tickets under `docs/relay-transports/`; each
carries `Part of:` pointing here.

Follows the [relay hardening spec](relay-hardening-spec.md), whose findings
on proxy addresses and QUIC on Fly were stated as probable. A 2026-11
experiment on a throwaway Fly app settled both. This spec acts on the results
without leaving Fly.

## Problem Statement

The project's two relays run on Fly.io. Fly hides client addresses on raw TCP
and does not deliver QUIC reliably:

- **Per-IP limits do not see clients.** Raw TCP passes through Fly's proxy, so
  the relay sees proxy addresses. Every per-address control works against the
  proxy instead of the client: the per-IP connection cap, the new-connection
  rate limit, libp2p's per-IP reservation and circuit limits, the client
  buckets in `/peers`. The same goes for Identify's observed address, which
  clients use to learn their public address.
- **QUIC to the Fly relays does not work.** In the experiment, QUIC from an
  outside client reached the machine on about one connection in five after
  each restart, then not at all until the next restart. Fly machines dialing
  the app's anycast address got nothing. Both production relays failed every
  attempt. The drops happened inside Fly, before the machine, whichever
  address the server bound. Fly's documentation says QUIC is not supported
  and to expect breakage.
- **The relays advertise QUIC anyway.** They listen on UDP, register QUIC
  external addresses and hand them out through Identify. Clients and
  monitoring spend dials and handshake timeouts on addresses that never
  answer, and the relays look half-broken in monitoring.
- **Identify leaks internal addresses.** The relay reports its listen
  addresses, which on Fly are private machine addresses no client can reach.
- **QUIC has no protections of its own.** Pending QUIC handshakes share the
  swarm's pending-incoming budget with TCP, so a QUIC flood (spoofable over
  UDP) can starve TCP. Flow-control windows are quinn's defaults: 10 MB per
  stream, 15 MB per connection, far beyond what a one-vCPU, 1 GB machine can
  hold for a thousand connections. Self-hosted relays run QUIC by default.
- **Nothing checks a deploy from outside.** `doctor` dials from the relay's
  own host, so a pass does not prove clients get in. Both regions deploy in
  parallel, so a bad release takes down both relays at once.

## Solution

The experiment showed that Fly's proxy can prepend a PROXY protocol v2 header
to every raw TCP connection, carrying the real client address and port. The
relay learns to read it. Each connection then gets the client's address
before libp2p sees it, and every limit, `/peers` and Identify work as
designed.

QUIC gets an off switch. Both Fly relays turn it off: they no longer listen
on UDP or advertise QUIC, and Fly's UDP service is removed. The binary keeps
QUIC on by default for self-hosters, now with a pending-handshake budget
separate from TCP's, smaller flow-control windows and its own counters.

Identify stops reporting listen addresses once external addresses are known.

A new `probe` subcommand checks a relay from outside: it dials over TCP (QUIC
opt-in), checks the PeerId against a pinned value and waits for the relay's
Identify. CI deploys Frankfurt first, probes it from the runner, and deploys
Singapore only on a pass.

Before any of that reaches production, the release candidate runs on a
temporary staging relay on Fly, configured like production and kept out of
the mesh. A checklist exercises it from outside: real client addresses, the
per-IP cap, both kinds of header mismatch and their recovery, IPv6, a real
app connecting through it, and QUIC from a vantage outside Fly and the
original test client's ISP. `v0.4.0` is tagged only after the checklist
passes.

## User Stories

1. As a relay operator on Fly, I want the relay to see each TCP client's real
   address, so that the per-IP connection cap limits one client rather than
   the proxy.
2. As a relay operator on Fly, I want the new-connection rate limit keyed on
   the real client address, so that one client reconnecting in a loop is
   throttled without throttling everyone.
3. As a relay operator on Fly, I want libp2p's per-IP reservation and circuit
   limits to see real addresses, so that one address cannot take every
   reservation slot.
4. As a user behind NAT, I want Identify to report my real public address, so
   that my node learns its external address and hole punching has a chance.
5. As the monitoring observer, I want `/peers` to show real client buckets, so
   that geo attribution and peer counts describe clients, not the proxy.
6. As a relay operator, I want PROXY protocol off by default, so that a relay
   on a plain server works unchanged.
7. As a relay operator, I want the relay to drop any TCP connection that lacks
   a valid header when PROXY protocol is on, so that nothing can skip the
   proxy and present an address of its choosing.
8. As a relay operator, I want a client that connects but never sends a header
   to be cut off after a short timeout, so that idle sockets cannot pile up
   before libp2p's limits see them.
9. As a relay operator, I want a cap on connections still waiting for their
   header, so that a flood of silent sockets cannot exhaust memory or file
   descriptors.
10. As a relay operator, I want an oversized header refused, so that a header
    cannot make the relay buffer arbitrary data.
11. As a relay operator, I want a header with the LOCAL command accepted with
    the socket's own address, so that platform health checks that send LOCAL
    keep working.
12. As a relay operator, I want an IPv6 source in the header turned into an
    IPv6 address, so that IPv6 clients are bucketed by their /64 like
    everywhere else.
13. As a relay operator, I want counters for connections refused for a
    missing, malformed or late header, so that I can tell a misconfigured
    proxy from an attack.
14. As a relay operator, I want `/health/alerts` to flag when most inbound TCP
    connections are refused for a missing header, so that a proxy that stops
    sending headers pages someone instead of silently refusing every user.
15. As a relay operator, I want outbound dials unaffected by PROXY protocol,
    so that mesh dials to other relays keep working.
16. As a relay operator, I want a switch that turns QUIC off entirely, so that
    a relay on a platform without working UDP neither listens on UDP nor
    advertises QUIC.
17. As a client, I want a relay with QUIC off to hand out no QUIC addresses,
    so that I don't waste dials and handshake timeouts on them.
18. As a relay operator, I want QUIC on by default, so that self-hosted relays
    on plain servers keep their faster transport.
19. As a client, I want Identify to stop reporting a relay's listen addresses
    once it has external addresses, so that I am never handed private machine
    addresses I cannot reach.
20. As a relay operator, I want pending QUIC handshakes held to their own
    budget, so that a spoofed UDP flood cannot use up the pending slots TCP
    clients need.
21. As a relay operator, I want QUIC flow-control windows small enough that a
    full relay fits in memory, so that a thousand connections cannot commit
    gigabytes of buffers.
22. As a relay operator, I want the QUIC handshake timeout, windows and
    pending budget as settings, so that I can tune them without recompiling.
23. As a relay operator, I want counters for QUIC handshakes refused by the
    budget and for established connections by transport, so that I can see
    which transport clients use and whether QUIC is under attack.
24. As a relay operator, I want `/health/alerts` to flag sustained QUIC budget
    refusals, so that a QUIC flood is visible.
25. As a relay operator, I want `doctor` to print which transports are on and
    whether PROXY protocol is required, so that I can confirm the effective
    configuration at a glance.
26. As a relay operator with PROXY protocol on, I want `doctor` to say its
    on-host dials pass only if they go through the proxy, so that a refused
    self-dial is not mistaken for a broken relay.
27. As a relay operator, I want a `probe` subcommand that dials my relay from
    another machine over TCP and reports PASS or FAIL, so that I can check
    reachability from where clients actually are.
28. As a relay operator, I want `probe` to check the relay's PeerId against an
    expected value, so that a relay answering with the wrong identity fails.
29. As the maintainer, I want `probe` to take the expected PeerId from the
    network profile, so that CI checks the identity the app trusts without
    copying it anywhere.
30. As a self-hoster without a profile entry, I want `probe` to fall back to
    the PeerId my relay's `/health` reports, so that I can still check
    reachability.
31. As a relay operator, I want `probe --quic` to check QUIC as well, so that a
    self-hosted relay can verify both transports, while Fly checks skip QUIC.
32. As a relay operator, I want `probe` to wait for the relay's Identify with
    the Alexandria protocol version, so that a pass means an Alexandria relay
    answered, not just an open port.
33. As a relay operator, I want `probe` to retry for a bounded time, so that a
    machine still booting after a deploy is not reported as down.
34. As the maintainer, I want CI to deploy Frankfurt first, probe it and
    deploy Singapore only on a pass, so that a bad release takes down one
    region, not both.
35. As the maintainer, I want the CI probe to run the published image by
    digest in a step with no secrets, so that the check tests exactly what was
    deployed and cannot leak credentials.
36. As the maintainer, I want CI to probe Singapore after its deploy too, so
    that the workflow fails visibly when the second region is broken.
37. As the maintainer, I want a pre-release tag to exercise the build, publish
    and probe path without deploying, so that the pipeline is proven before
    the real release.
38. As the maintainer, I want the Fly configs to turn on the proxy header and
    turn off QUIC in the same deploy as the image, so that the proxy and the
    relay never disagree about the header.
39. As the maintainer, I want the rollback steps for a header mismatch
    written down, so that rolling back the image alone, which would break
    every TCP connection, does not happen by accident.
40. As the maintainer, I want the relays' dedicated IPv4 addresses kept when
    the UDP service goes, so that the profile's fallback addresses stay
    valid.
41. As a self-hoster, I want the self-hosting guide to say when to turn PROXY
    protocol on (behind a proxy that sends it) and when to turn QUIC off, so
    that I configure my platform correctly.
42. As an operator reading the operations doc, I want it to record that QUIC
    does not work on Fly and why, so that nobody re-enables it without
    re-testing.
43. As the maintainer, I want to deploy a release candidate to a staging
    relay on Fly with the production proxy settings, so that Fly's side of
    the PROXY header is proven before either production relay changes.
44. As the maintainer, I want the staging relay to have its own identity and
    stay out of the mesh, so that a broken staging build never reaches users,
    the production relays or monitoring.
45. As the maintainer, I want a manual workflow run to deploy the staging
    relay and probe it with a pinned PeerId, so that staging uses the same
    image, deploy step and probe as production.
46. As the maintainer, I want to rehearse both header mismatches and the
    rollback on staging, so that the rollback procedure is known to work
    before production needs it.
47. As the maintainer, I want a real app build to connect through the staging
    relay, so that reservations and the app's view of its own public address
    are checked end to end.
48. As the maintainer, I want staging probed over IPv6 and, with QUIC
    briefly on, from a CI runner, so that the experiment's two open caveats
    are settled.
49. As the maintainer, I want production deploys to need an explicit choice
    in a manual workflow run, so that running the workflow by hand cannot
    deploy both relays by default.

## Implementation Decisions

- **One release, staged.** This work ships as relay 0.4.0 together with the
  hardening and libp2p 0.57 work already merged and not yet deployed. The
  `Cargo.toml` version bump to 0.4.0 is its own chore commit. Order:
  `v0.4.0-rc.2` tag (build, publish), staging rehearsal on that image (see
  below), results recorded in this spec's notes, then the `v0.4.0` tag,
  which deploys production.

### PROXY protocol v2 on TCP

- **Setting.** `--tcp-proxy-protocol` / `RELAY_TCP_PROXY_PROTOCOL`, values
  `off` (default) and `v2`. With `v2`, every inbound TCP connection must open
  with a valid v2 header; anything else is closed. With `off`, nothing is
  parsed, and a header is garbage to multistream, so the connection fails.
  Version 1 (text) headers are refused; the relay reads v2 only.
- **Where it sits.** A transport wrapper around libp2p's tokio TCP
  transport, in a new module. On each inbound socket the wrapper reads the
  header before telling the swarm about the connection, then reports the
  connection with its send-back address rewritten to the header's source
  (`/ip4/<src>/tcp/<port>` or `/ip6/...`). The swarm, the connection-limits
  behaviour, the per-IP limiter, libp2p's relay limiters, Identify's observed
  address and `/peers` all read that address, so none of them change.
- **Transport assembly.** The swarm builder's TCP phase cannot take a wrapped
  transport, so the transport is assembled by hand: TCP (wrapped or not),
  noise and yamux, combined with an optional QUIC transport, passed in
  through the builder's custom-transport hook. That also gives the QUIC off
  switch a single place to live.
- **Parser.** An in-tree parser for the v2 binary format: 12-byte signature,
  version and command, family and protocol, length, addresses, then TLVs,
  which are skipped. No new dependency. Total header size is capped at 1 KiB;
  anything larger is refused. LOCAL command, or the UNSPEC family, means
  "use the socket address". UNIX family is refused.
- **Bounds before libp2p.** Sockets waiting for their header are not yet
  pending connections to the swarm, so they get their own bounds. Header read
  timeout `--proxy-header-timeout-secs` / `RELAY_PROXY_HEADER_TIMEOUT_SECS`,
  default 5 s (Fly's proxy writes the header as soon as it connects). The
  number of sockets waiting for a header is capped at the same value as
  `RELAY_MAX_PENDING_INCOMING`; a socket beyond the cap is closed on accept.
- **Counters.** `proxy_header_missing`, `proxy_header_invalid`,
  `proxy_header_timeout` and `proxy_header_overflow` (the waiting cap), in
  the existing `/metrics` output.
- **Alert.** `/health/alerts` gains a header-refusal alert: over the
  existing rolling window, refused-for-header connections exceed half of
  inbound TCP attempts, with at least a small minimum count so a single
  scanner does not trip it.
- **Trust model.** With `v2` on, the relay trusts the first header on a
  connection. On Fly, the public addresses only reach the machine through the
  proxy, and the proxy writes its header first; a header a client sends
  arrives after the proxy's and breaks multistream. Machines on the
  organisation's private network can reach the port directly; they are
  operator-controlled. The self-hosting guide states that `v2` must only be
  on when every connection comes through a proxy that sends the header.
- **Outbound unchanged.** Only inbound sockets are read. Mesh dials,
  Kademlia and doctor's client swarm are untouched.

### QUIC

- **Off switch.** `--quic` / `RELAY_QUIC`, boolean, default `true`. Off means
  no QUIC transport, no UDP listener, and no QUIC external addresses: neither
  the `dns4` QUIC form from `RELAY_PUBLIC_HOST` nor the resolved-IP forms.
  `tcp_and_quic` and the external-address code take the switch into account.
- **No bind-host work.** The experiment found replies leave with the right
  source address from a wildcard bind (quinn sets the reply source itself).
  The relay keeps binding QUIC like TCP. No bind-host setting, no IPv6-only
  QUIC switch, no Fly detection in `doctor`.
- **Pending budget.** `--quic-max-pending-incoming` /
  `RELAY_QUIC_MAX_PENDING_INCOMING`, default 64, below the shared cap
  (`RELAY_MAX_PENDING_INCOMING`, 256) so TCP always keeps most of it. A small
  behaviour counts pending inbound connections whose local address is QUIC,
  denies new ones above the budget in the pending-inbound hook, and releases
  a slot when the connection is established or fails. No per-IP pending cap:
  UDP sources are spoofable, so a per-IP cap would let an attacker lock out
  chosen addresses.
- **Windows.** `RELAY_QUIC_MAX_STREAM_DATA` default 256 KiB,
  `RELAY_QUIC_MAX_CONNECTION_DATA` default 512 KiB. At the default 1024
  connections that bounds receive buffers at 512 MiB worst case, against
  15 GiB at quinn's defaults. A relayed circuit is one stream, so a single
  circuit's QUIC throughput tops out near 256 KiB per round trip (about
  1.3 MB/s at 200 ms), which is more than relayed traffic needs; direct
  connections do not pass through the relay.
- **Handshake timeout.** `RELAY_QUIC_HANDSHAKE_TIMEOUT_SECS`, default 5 s
  (libp2p's default, now tunable). Shorter values hurt lossy mobile links.
- **Kept as is.** Idle timeout, keep-alive, path MTU discovery and the 3x
  anti-amplification bound stay at libp2p and quinn defaults.
- **Counters and alert.** `quic_pending_denied` counter;
  `connections_established` split by transport (`tcp`, `quic`). An alert
  fires when budget denials are sustained over the rolling window.

### Identify

- With at least one external address registered, Identify is built with
  hidden listen addresses, so it reports only external addresses. With none,
  it keeps reporting listen addresses (a relay on a plain server with no
  public host set relies on them).

### Doctor

- Prints one transport line: TCP with PROXY protocol on or off, QUIC on or
  off. QUIC dials are skipped when QUIC is off.
- With PROXY protocol on, doctor notes that its dials pass only when they go
  through the proxy, and suggests `probe` from another machine.

### Probe

- `alexandria-relay probe --host <dns-name-or-ip> [--port <n>]`, with the
  expected PeerId from one of: `--peer-id <id>`; `--network-profile <file>`
  (picks the relay entry whose `dns_name` equals the host); or neither, in
  which case it reads `peer_id` from `--health-url <url>` and prints that the
  identity was not pinned.
- Dials `/dns4/<host>/tcp/<port>/p2p/<peer-id>`, plus the QUIC form with
  `--quic`. A dial passes when the connection is established with the
  expected PeerId and the relay's Identify arrives with protocol version
  `/alexandria/id/1.0`. A PeerId mismatch is a FAIL that prints expected and
  actual.
- Retries each transport until `--timeout-secs` (default 120). Prints one
  PASS or FAIL line per transport; exit code 0 only if every requested
  transport passed.
- Uses no relay secrets and writes nothing to disk.

### CI deploy

- The deploy job's two-region matrix becomes a chain: deploy Frankfurt,
  probe Frankfurt, deploy Singapore, probe Singapore. A failed Frankfurt
  probe stops the chain with Singapore untouched.
- Each probe step runs `probe` from the published image by digest
  (`docker run <image>@<digest> probe ...`), in a step that has no secrets
  in its environment. It fetches the network profile from the app
  repository's default branch over HTTPS and passes it with
  `--network-profile`. No QUIC check on Fly.
- Pre-release tags keep skipping deploy; the probe step's command is
  exercised by running `probe --help` from the published image, so the
  release candidate proves the image and the subcommand exist.
- The manual trigger's `deploy` boolean (default true) becomes a `target`
  choice: `staging` (default), `production` or `none`. Production deploys
  from a manual run only with `production` chosen; release tags deploy
  production as before.

### Fly configs

- Both `fly.toml` and `fly-eu.toml`: the 4001/tcp service gets
  `handlers = ["proxy_proto"]` and `proxy_proto_options = { version = "v2" }`;
  the UDP service is removed; `[env]` sets `RELAY_TCP_PROXY_PROTOCOL = "v2"`
  and `RELAY_QUIC = "false"`. Config and image deploy together in one
  `flyctl deploy`.
- The dedicated IPv4 addresses stay allocated. The network profile's
  fallback addresses point at them.
- **Rollback.** An image without PROXY support behind a proxy that sends the
  header refuses every TCP connection, and the reverse fails the same way.
  Rolling back means deploying the previous image with the previous commit's
  Fly config, never the image alone. The operations doc gets this procedure.

### Staging rehearsal

- **Config.** A third Fly config, `fly-staging.toml`, for a staging app
  (`alexandria-relay-staging`), one machine, no volume. Its TCP service and
  `[env]` match production: `proxy_proto` v2, `RELAY_TCP_PROXY_PROTOCOL = "v2"`,
  `RELAY_QUIC = "false"`. Unlike production it keeps a UDP service on 4001,
  so QUIC can be switched on for one check without a config change.
- **Isolation.** The staging relay gets a fresh `RELAY_SEED`, so its PeerId
  is in no network profile. It runs without `RELAY_NETWORK_PROFILE` and
  without `RELAY_ANNOUNCE`, so it neither dials the production relays nor
  announces itself. Monitoring never sees it. Its secrets (`RELAY_SEED`,
  `RELAY_ADMIN_TOKEN`, `RELAY_PUBLIC_HOST`) live only on the staging app.
- **Lifecycle.** The app is created by hand for a rehearsal and destroyed
  afterwards, releasing its addresses. It needs a dedicated IPv4 (raw TCP
  over IPv4 needs one on Fly) and an IPv6 address. The config file stays in
  the repository for the next rehearsal.
- **Workflow.** A `staging` job runs on a manual trigger with
  `target: staging`. It deploys `fly-staging.toml` with the run's published
  image, then runs the same secret-free probe step as production with
  `--peer-id` from a repository variable (`STAGING_RELAY_PEER_ID`; a PeerId
  is public). It fails if the variable is unset; staging is never probed
  unpinned in CI. A `staging_quic` boolean input (default false) deploys
  with `RELAY_QUIC=true` and adds a `probe --quic` step whose result is
  recorded but does not fail the job, since QUIC on Fly is expected to fail.
- **Probe addition.** `--host` also takes an IP literal, which is dialed as
  `/ip4` or `/ip6`, so staging can be probed over IPv6 directly.
- **Checklist.** Run on the `v0.4.0-rc.2` image. Each item passes before
  `v0.4.0` is tagged:
  1. The workflow's staging deploy and TCP probe pass.
  2. `/peers` (admin token), read while a probe from a known machine is
     connected, shows that machine's public address bucket, not a Fly
     address.
  3. With `RELAY_MAX_CONNECTIONS_PER_IP=1` set on the staging app and a dev
     app build connected, a probe from the same machine fails and a probe
     from the CI runner passes.
  4. Old image, new config: the `v0.4.0-rc.1` image (no PROXY support)
     deployed with the staging config makes the probe fail.
  5. New image, old config: the release candidate deployed with a local copy
     of the staging config without the `proxy_proto` handler makes the probe
     fail, raises `proxy_header_missing` and the header-refusal alert.
  6. Rollback: redeploying the matching image and config pair makes the
     probe pass again, following the operations doc's procedure word for
     word.
  7. A dev app build with the staging relay added through its extra-relays
     setting gets a reservation, and the app's view of its own public
     address is the machine's real address.
  8. A probe over IPv6 to the staging IPv6 address passes, from any machine
     with IPv6 (CI runners have none).
  9. A `staging_quic` run records whether QUIC from the runner reaches the
     staging relay over several attempts. Pass or fail, the result is
     recorded; a reliable pass reopens the question of QUIC on Fly in a new
     spec.
  10. The staging app is destroyed.

### Docs

- `operations.md`: the client-addresses section says PROXY v2 fixes TCP on
  Fly; the QUIC-on-Fly paragraph records the experiment's result and that
  QUIC is off there; the ports table drops 4001/udp for Fly; rollback
  procedure; new settings and counters; a short staging-rehearsal section
  (create the app, set its secrets and the PeerId variable, run the
  checklist, destroy it), to rerun for any release that changes transports
  or Fly config.
- `self-hosting.md`: when to set `RELAY_TCP_PROXY_PROTOCOL=v2` and
  `RELAY_QUIC=false`; how to run `probe` against your relay.
- `README.md` settings table: the new settings.
- Examples use placeholders (`relay.example.org`, documentation address
  ranges), never values from the network profile.

## Testing Decisions

- A good test drives the relay as a client would and asserts on what the
  client or an operator observes: connection outcome, Identify contents,
  `/peers`, `/metrics`, `/health/alerts`, CLI exit codes and output. Tests do
  not inspect swarm internals or log lines. Prior art: `tests/limits.rs`,
  `tests/observability.rs` and `tests/doctor.rs`.
- **Black-box tests** use `TestRelay::start_with` and `TestClient` from
  `tests/common`, extended with a PROXY shim: a loopback TCP forwarder that
  writes a chosen v2 header (a documentation-range source address) and then
  pipes bytes to the relay. Covered:
  - with `v2` on, a client through the shim connects; `/peers` shows the
    shim's source bucket; the client's Identify observed address is the
    shim's source;
  - per-IP connection cap counts by header address: two shims with the same
    source hit a cap of one, two different sources do not;
  - with `v2` on, a direct connection without a header is refused and
    `proxy_header_missing` increments; a silent socket is closed after the
    (test-shortened) timeout and `proxy_header_timeout` increments; a
    v1 text header and an oversized header are refused;
  - a LOCAL-command header is accepted and attributed to the socket address;
  - with `v2` off, a connection through the shim fails;
  - header-refusal alert appears when refusals dominate;
  - QUIC off: no UDP listener, no QUIC address in Identify or in the
    reservation's address set, TCP still serves reservations;
  - Identify reports no listen addresses when a public host is set, and
    reports them when none is;
  - QUIC on: a client reserves over QUIC with the smaller windows, and
    `connections_established` counts it under `quic`.
- **Pending budget** is tested through the behaviour's pending-inbound and
  swarm-event hooks directly: denials above the budget, slots released on
  establish and on failure, TCP pending connections never counted. The
  behaviour takes no clock, so no fake clock is needed.
- **Parser unit tests**: IPv4, IPv6, LOCAL, UNSPEC, UNIX refused, TLVs
  skipped, truncated input, bad signature, length over the cap.
- **CLI tests** run the built binary, as `tests/doctor.rs` does: `probe`
  passes against a loopback relay over TCP and with `--quic`; fails with a
  wrong `--peer-id` and prints both PeerIds; reads the PeerId from a profile
  file and from `/health`; dials an IPv4 or IPv6 literal host; fails within
  its timeout against a closed port. `doctor` prints the transport line for each combination.
- Fly's side, which no local test can reach, is verified by the staging
  rehearsal checklist on the `v0.4.0-rc.2` image. The checklist results are
  appended to this spec's notes.
- The CI chain is verified by the `v0.4.0-rc.2` run (publish plus probe
  command), the staging job (deploy plus pinned probe), and then the
  `v0.4.0` deploy itself, which must pass both probes.

## Out of Scope

- QUIC on the Fly relays. It stays off until Fly delivers UDP reliably.
- Moving the relays off Fly.
- PROXY protocol on the HTTP listener. It already has the trusted-header
  setting.
- QUIC Retry (stateless address validation). libp2p accepts incoming QUIC
  connections immediately, so it needs an upstream change.
- An automatic QUIC flood breaker and a longer QUIC idle timeout. Deferred to
  a follow-up spec opened when a production relay first serves QUIC.
- Per-IP checks at the pending stage. The header makes TCP source addresses
  trustworthy there, but the established-stage limits are enough for now.
- App and monitoring changes. They keep dialing QUIC to the Fly relays in
  parallel with TCP; those dials fail and TCP wins.
- iOS QUIC, app-side idle timeout and keep-alive.

## Further Notes

- **Experiment summary (2026-11).** A throwaway Fly app in Singapore ran a
  QUIC server on UDP and a TCP server behind `proxy_proto` v2. Every TCP
  connection carried a v2 header with the client's real address and port.
  QUIC from an outside client succeeded on two to four connections after
  each machine restart, then inbound packets stopped arriving at the machine
  (packet capture showed none) until the next restart; idling did not
  recover it, and turning off path MTU discovery did not help. Fly machines
  in other regions dialing the anycast address got no packets at all. The
  same client reached a large public QUIC service every time. When packets
  did arrive, the server saw the client's real address and port, with either
  bind address.
- **Caveat.** No test ran from outside both Fly and the test client's ISP, so
  ISP filtering of UDP on unusual ports is not fully ruled out. Only IPv4 was
  tested; the PROXY header on Fly's IPv6 TCP path is assumed to match.
  Checklist items 8 and 9 of the staging rehearsal settle both.
- **Follow-ups, recorded and not built:**
  1. A per-relay transport hint in the network profile, so the app and
     monitoring stop dialing QUIC to relays that do not serve it. App, relay
     and monitoring change together.
  2. Re-test Fly UDP when Fly ships edge QUIC support, which its docs list
     as planned.
- The [hardening spec](relay-hardening-spec.md) lists PROXY parsing on the
  libp2p listener as out of scope because the TCP transport does not support
  it. This spec supersedes that line: the parsing sits in a wrapper outside
  the TCP transport.

## Notes

- 2026-11-19: Implemented. All six tickets are done; deviations are recorded
  in each ticket's notes. A two-axis code review (standards and spec) found
  an alert-window underflow, QUIC addresses still added for mesh peers with
  QUIC off, two PROXY header classification gaps, and a staging job that
  could only rebuild rather than deploy the existing release-candidate
  image; all were fixed in the same series. The manual trigger now takes an
  `image` input for staging, and releases upload assets only on tag pushes.
  159 tests pass. Not yet done: the `v0.4.0-rc.2` tag, the staging
  rehearsal checklist (whose results belong here) and the `v0.4.0` deploy.
- 2026-11-20: Staging rehearsal on the `v0.4.0-rc.2` image. Passed: 1, 2
  (`/peers` showed the connected machine's own /24, not a Fly address), 4,
  5 (`proxy_header_missing` counted and `/health/alerts` answered 503 with
  `proxy_header_refusal_majority`), 6 and 8 (IPv6 probe from a machine
  with IPv6). Item 9: four of five QUIC probes passed from the runner and
  four of five from a residential connection, so QUIC stays off on Fly.
  Items 3 and 7 are deferred: the app builds every extra relay as a `/dns4`
  address and its swarm has no DNS transport, so a dev build never dials
  the staging relay. Item 2 already shows the source address the per-IP
  limiter and Identify read; rerun 3 and 7 once the app can dial an extra
  relay. The rehearsal also found that the repository's Fly token had been
  revoked (replaced by an organisation token) and that a second staging run
  from the same ref deployed Fly's cached image for the reused
  `sha-<commit>` tag, which voided the first item 4 run; item 4 was redone
  by deploying the old image by digest, and the Fly tag now names the
  source image's digest. Two limits remain: the CI probe runs from the
  deployed image, so it cannot probe images older than 0.4.0, and the
  staging relay is kept up for the deferred items.
- 2026-11-21: `v0.4.0` released and deployed: Frankfurt, then Singapore,
  each probed over TCP by CI, and both probed again from a residential
  connection against the network profile's PeerIds. Both run PROXY v2 with
  QUIC off.
- 2026-11-21: Rehearsal items 3 and 7 passed against the app fix (app
  `docs/extra-relay-addresses-spec.md`), using a node test that starts the
  real app node with the staging relay as its only extra relay. Item 7: it
  connected by DNS name, got a reservation, and Identify reported the
  machine's real IPv4 and IPv6 addresses. Item 3, with the per-IP limit at
  1: while the node held the machine's IPv4 slot, an IPv4 probe from the
  same machine was refused (`ip_rate_limited` rose by one per attempt), an
  IPv6 probe from it passed, and the node kept its reservation; a CI rerun
  also passed. A rerun restarts the relay and drops the held connection,
  so the operations checklist now probes from the second address while the
  client is connected. Staging also turned out to be reachable from the
  production relays once a client had connected to both, through Kademlia.
  Item 10 done: the staging app is destroyed and `STAGING_RELAY_PEER_ID`
  deleted.
