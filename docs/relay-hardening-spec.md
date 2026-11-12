# Relay hardening and self-hosting

Status: draft
Updated: 2026-11-12
Triage: ready-for-agent
Repos: alexandria-relay

Parent spec. Work is split into numbered sub-tickets under
`docs/relay-hardening/`; each carries `Part of:` pointing here. Findings come
from the 2026-11 assessment of performance, security and scalability, which
also compared the relay against the earlier
[security audit](audits/security-2026-08.md).

## Problem Statement

Two relays run today, both on Fly.io, operated by the project. Anyone is
supposed to be able to run one, and the network is supposed to stop depending
on any single instance. Neither is true yet:

- A release cannot ship. The dependency audit that gates the deploy job fails
  on an SQLite advisory and nine DNS-library advisories, so tagging a version
  deploys nothing.
- One cheap request can stall a relay. A username-receipt request carries an
  unbounded DID string that is base58-decoded, which is quadratic, before any
  length check. The wire codec accepts requests up to 1 MiB, and the request
  budget is keyed on PeerIds, which are free to mint.
- The per-address limits probably do not see client addresses. On Fly, raw
  TCP and HTTP both pass through the platform proxy, so the relay sees proxy
  addresses. Every per-IP limiter (ours and libp2p's reservation and circuit
  limiters) then either throttles all users as one client or protects
  nothing. QUIC binds the wildcard address, which Fly documents as producing
  wrong-source replies.
- The relay's only persistent state, the SQLite store, is written
  synchronously inside the swarm event loop and inside HTTP handlers, with a
  full-table count on every DHT write. On a one-vCPU machine a burst of DHT
  puts or receipts stalls circuits, Kademlia and HTTP together.
- The DHT mirror caps at 16,384 records and evicts the oldest-inserted first.
  Past that many usernames the earliest users' records go first, and records
  reloaded at boot never expire.
- Relays are islands. The binary has no bootstrap list, never calls Kademlia
  bootstrap and never announces itself. Two relays meet only through clients
  connected to both; a third-party relay is invisible unless a user pastes
  it into the app's extra-relays setting.
- Every limit is a compile-time constant. Tuning means recompiling, and the
  operations doc says so. There is no published image or binary, no
  self-hosting guide, no Prometheus output, and no way for an operator to
  check that their relay is reachable.
- Nothing tests the relay over the wire. Reservation and receipt regressions
  surface in production.

## Solution

Make the relay something a stranger can run in an afternoon and trust: fix the
release pipeline and the input-handling holes first, then make limits runtime
configuration, give the relay one black-box seam that tests drive over
loopback, move the store off the event loop, let a relay join the mesh by
bootstrapping from the network profile and announcing itself, publish images
and binaries on every tag, expose Prometheus metrics, and ship a one-page
self-hosting guide with a reachability check built into the binary.

## User Stories

1. As the maintainer, I want the dependency audit green, so that tagging a
   version deploys again.
2. As the maintainer, I want every remaining audit ignore to name the advisory
   and the condition that would make it reachable, so that a real advisory is
   never buried.
3. As a relay operator, I want a receipt request with an oversized or
   malformed DID refused before any expensive decoding, so that one request
   cannot stall my relay.
4. As a relay operator, I want the receipt request codec to cap request size
   at a few kilobytes, so that the swarm never buffers a megabyte for a claim
   that fits in a few hundred bytes.
5. As a relay operator, I want a cap on connections still in the handshake
   stage, so that a flood of half-open connections cannot exhaust memory
   before any post-handshake limit applies.
6. As a relay operator, I want seed material cleared from every buffer that
   held it, so that a memory dump does not recover the relay identity.
7. As a relay operator behind a trusted reverse proxy or platform proxy, I
   want to opt in to reading the client address from a named header on the
   HTTP side, so that the username-lookup limiter buckets real clients.
8. As a relay operator, I want the relay to refuse the trusted-proxy header
   unless I opted in, so that a direct client cannot spoof its address.
9. As a relay operator, I want IPv6 clients bucketed by /64, so that one
   subscriber prefix cannot bypass per-address limits.
10. As a relay operator, I want the operations doc to state plainly which
    limiters work behind Fly's proxy and which do not, so that I can decide
    where to host.
11. As a relay operator, I want the relay to add only addresses confirmed via
    Identify to its routing table, so that other peers are not handed
    undialable NAT ports.
12. As a relay operator, I want HTTP connections to time out on slow headers
    and be bounded in number, so that the health listener survives a
    slowloris.
13. As a relay operator, I want the container to run as a non-root user, so
    that a process compromise does not own the container.
14. As a relay operator, I want every limit (connections, per-IP, per-peer,
    reservations, circuits, circuit bytes and duration, DHT records, receipt
    and lookup budgets, idle timeout) settable by flag or environment
    variable with today's values as defaults, so that I tune without
    recompiling.
15. As a relay operator, I want `--help` to document every flag and its
    environment variable, so that the binary is its own reference.
16. As a relay operator, I want a `--metrics-bind` address, so that I can keep
    the HTTP listener on loopback behind my own reverse proxy.
17. As a contributor, I want a function that starts a whole relay from a
    config value on ephemeral ports and returns its PeerId, bound addresses
    and a shutdown handle, so that tests drive a real relay over loopback.
18. As a contributor, I want an integration test that reserves a circuit,
    requests a receipt and puts a DHT record against a running relay, so that
    wire regressions fail CI, not production.
19. As a contributor, I want the single large source file split into config,
    swarm, HTTP and store modules, so that I can find and change one concern
    without reading all of them.
20. As a relay operator, I want store writes off the swarm event loop, so that
    a burst of DHT puts or receipt requests does not stall circuits.
21. As a relay operator, I want the store in write-ahead-log mode with normal
    synchronous writes, so that each write does not cost a full fsync.
22. As a relay operator, I want the DHT mirror to remember each record's
    expiry and drop expired records, so that stale records do not live
    forever after a restart.
23. As a relay operator, I want mirror eviction to prefer expired or
    soonest-expiring records over the oldest-inserted, so that early users'
    records are not the first to go.
24. As a relay operator, I want the DHT record cap configurable and the
    memory estimate stated honestly, so that I size a machine from real
    numbers.
25. As a relay operator, I want the relay to dial the network profile's relays
    at startup and run periodic Kademlia bootstrap, so that my relay is part
    of the same DHT as the others.
26. As a relay operator, I want to point the relay at a network profile file
    and have it read relay coordinates and the protocol namespace from there,
    so that no profile value is copied into relay code or flags.
27. As a relay operator, I want an `--announce` option that publishes my relay
    as a provider under the network's relay-discovery key, so that app nodes
    discover it without manual configuration.
28. As a relay operator, I want announcing to be opt-in and clearly
    separate from receipt-issuer trust, so that I understand running a
    connectivity relay grants no username authority.
29. As a relay operator, I want a versioned, multi-architecture container
    image published on every tag, so that I run a relay with one `docker run`.
30. As a relay operator, I want static Linux binaries attached to each
    release, so that I run a relay without Docker or a Rust toolchain.
31. As a relay operator, I want `/metrics` to serve Prometheus exposition when
    asked for it, so that my existing Prometheus and Grafana scrape it.
32. As a relay operator, I want `/health` to carry the binary version and a
    current connection count, so that my uptime monitor shows what is
    running.
33. As a relay operator, I want per-event logs at debug level and a periodic
    summary at info, so that logs do not grow with every circuit.
34. As a relay operator, I want a `doctor` subcommand that dials my own
    external address, checks the reservation address set, data-dir
    permissions and admin-token state, so that I know the relay is reachable
    before I publish it.
35. As a relay operator, I want a one-page self-hosting guide covering VPS
    with systemd, Docker Compose, reverse-proxy TLS, firewall ports and an
    example environment file, so that I do not reverse-engineer the Fly
    configs.
36. As a relay operator, I want `--generate-key` to tell me where the PeerId
    goes today, so that I am not pointed at a file that no longer exists.
37. As the monitoring observer, I want the JSON `/metrics` and `/peers`
    shapes unchanged, so that the existing scrape keeps working.
38. As an app user, I want the username-availability check to keep working
    under load, so that signup never fails because every user shares one
    rate-limit bucket.
39. As an app user, I want relays to find each other, so that a peer behind
    one relay can reach a peer behind another.
40. As a reviewer, I want the operations doc, README and this spec's
    sub-tickets to describe the same limits and flags, so that the docs stay
    the source of truth after the constants move.

## Implementation Decisions

- **Ticket order.** Release unblock and input hardening (01) ships first and
  alone; it is small and independent. Runtime configuration and the black-box
  seam (03) land before the rest, since every later ticket adds a flag or a
  wire-level test.
- **Dependency audit.** Bump the SQLite binding to the current major (needs
  Rust 1.89, so the CI toolchain pin and the Docker build image move with
  it). The DNS-library advisories stay ignored, each with its reason: the DNS
  features of libp2p are not enabled and the crate is not in the compiled
  tree. Re-evaluate the ignore when a libp2p release moves to a fixed
  version.
- **DID input bound.** A `did:key` for Ed25519 is a fixed short string.
  Reject any DID over a small fixed length before base58 decoding. The same
  bound belongs in the app's verification crate; that is noted for the app
  repo and is out of scope here.
- **Codec cap.** The receipt request/response codec sets a request maximum of
  a few kilobytes. Response maximum stays at its default.
- **Pending-connection cap.** Connection limits gain a maximum for pending
  incoming connections. Default in the low hundreds; configurable.
- **Zeroization.** Seed handling uses a zeroizing wrapper for the decoded
  bytes and the environment string, not only the fixed array.
- **Client address.** HTTP handlers resolve the client address through one
  function: the socket peer address by default, or a configured header
  (`--trusted-proxy-header`, defaulting to the Fly client-IP header name when
  the flag is given without a value) only when the operator opted in. The
  flag's help text states that it must be off when clients reach the
  listener directly. The libp2p side cannot read PROXY protocol, so the
  operations doc states that per-address limits on the libp2p listener
  require a host that preserves source addresses, and that on Fly they do
  not. Fly QUIC binding is documented as unverified with the platform's
  stated requirement.
- **IPv6 bucketing.** All per-address keys (connection limiter, lookup
  limiter, truncation for `/peers`) derive from one function that keeps the
  full IPv4 address and the /64 of an IPv6 address. `/peers` output keeps
  /24 and /48 as today.
- **Routing-table admission.** Connected peers are added to Kademlia from
  Identify-reported addresses that pass the routability filter, not from the
  connection's remote address.
- **HTTP hardening.** Header read timeout, request timeout and a concurrency
  limit on the HTTP server. GET only; no body handling changes.
- **Runtime configuration.** One configuration struct built by the CLI parser
  from flags and environment variables, with every current constant as the
  default. The struct is the single input to starting a relay. Limits are
  logged at startup as today. Environment names follow the existing
  `RELAY_*` pattern.
- **Black-box seam.** One function starts a relay from the configuration
  struct and returns a handle with the PeerId, bound libp2p addresses, bound
  HTTP address and a shutdown trigger. The binary's entry point calls it;
  tests call it with ephemeral ports and a temporary data directory. This is
  the only new seam; `RegistryStore` keeps its existing unit seam.
- **Module split.** Configuration, swarm construction and event loop, HTTP
  router, store, and address helpers become separate modules. Behaviour is
  unchanged by the split.
- **Store offload.** The store runs on a dedicated blocking thread owned by a
  small actor; the event loop and HTTP handlers send it messages and await
  replies. No `std::sync::Mutex` is held across an await and no SQLite call
  runs on a runtime worker. The store opens in write-ahead-log mode with
  normal synchronous writes and a busy timeout, and keeps a cached row count
  instead of counting per insert.
- **Mirror expiry.** The mirror stores each record's expiry (absolute Unix
  time) and publisher. Reload sets the expiry on the in-memory record;
  expired rows are skipped on load and pruned periodically. Eviction order is
  expired first, then soonest-expiring, then oldest-inserted. The record cap
  becomes configuration. Provider announcements are not mirrored; they
  expire on their own.
- **Mesh join.** A `--network-profile` flag takes a path to a profile JSON.
  The relay parses only the fields it needs (relay coordinates, protocol
  namespace) with the same fail-closed strictness the app applies to those
  fields, and refuses a profile whose namespace does not match its
  `network_id`. With a profile, the relay dials every profile relay other
  than itself at startup, runs Kademlia bootstrap on a fixed interval, and,
  when `--announce` is also given, publishes a provider record under the
  network's relay-discovery key on the provider record interval. Without a
  profile, behaviour is as today. No profile value is copied into code or a
  default. This respects the bundled-network-profile decision: the relay
  reads the profile, it does not keep a copy.
- **Announce scope.** Announcing advertises connectivity only. Receipt-issuer
  trust remains governed by the on-chain relay registry and the profile's
  issuer list; the self-hosting guide says so in its first section.
- **Release artifacts.** On `v*` tags CI publishes a multi-architecture
  (amd64, arm64) container image to the GitHub registry tagged with the
  version and `latest`, and attaches statically linked Linux binaries for
  both architectures to the GitHub release. The runtime image declares a
  non-root user. The audit job uses the maintained audit action instead of
  installing the tool on every run.
- **Prometheus.** `/metrics` serves the Prometheus text format when the
  `Accept` header asks for it, and JSON otherwise, so the observer's scrape
  is unchanged. Same bearer gate. Counters and gauges mirror the JSON fields;
  per-peer data is never exported.
- **Health.** `/health` adds the crate version and reads the live connection
  count from the swarm rather than the five-minute sample.
- **Logging.** Per-circuit, per-reservation and per-receipt-request lines
  move to debug. The periodic health line gains counts of circuits,
  reservations and receipts since the last line.
- **Doctor.** A `doctor` subcommand loads the same configuration, starts the
  relay on the configured ports, dials its own advertised external addresses
  over TCP and QUIC, reports which succeeded, reports the reservation
  address set, the data directory's writability, whether an admin token is
  configured and accepted, and exits non-zero if the relay is unreachable on
  every advertised address.
- **Key generation output.** `--generate-key` points at the network
  profile's relay list and receipt-issuer list and at the self-hosting
  guide; it no longer names a source file.
- **Docs.** `docs/self-hosting.md` (live) is the operator entry point; the
  README quick start links to it; `docs/operations.md` keeps the
  project-owned Fly deployment and gains the limiter caveat. The README stays
  under its line limit.

## Testing Decisions

- A good test drives the relay as a client would and asserts on what the
  client observes: the response to a reservation, receipt or lookup, the
  HTTP status and body, the metrics counters. Tests do not reach into the
  event loop or assert on log lines.
- **Black-box tests** use the start function with ephemeral ports and a
  temporary data directory, a second libp2p swarm as the client, and a plain
  HTTP client. Covered: reservation accepted with a non-empty address set when
  an external address is configured; receipt granted, re-issued with the same
  first-seen time on refresh, refused for a second DID; oversized DID refused
  without measurable delay; DHT put stored, mirrored, and still present with
  its expiry after restart from the same data directory; expired mirrored
  record absent after restart; admin routes answer 404 without the token and
  200 with it; trusted-proxy header honoured only when configured; lookup
  limiter buckets by header address when configured; Prometheus body on
  `Accept: text/plain`, JSON otherwise; pending-incoming cap reached yields
  refused dials; two relays started with each other as bootstrap peers see
  each other in the routing table; an announcing relay appears as a provider
  under the discovery key on its bootstrap peer.
- **Unit tests** keep covering pure helpers (address bucketing, truncation,
  auth, limiter windows) and `RegistryStore` (expiry, eviction order, cached
  count). Prior art: the existing limiter and store tests in the crate.
- **Doctor** is tested through its exit code and summary against a relay
  started with and without an external address.
- CI runs the integration tests in the existing `cargo test --locked` job.
  Tests that need a second swarm run in-process; nothing needs the network.

## Out of Scope

- Changing wire protocol IDs to the namespaced form. That is a coordinated
  app, relay and monitoring deployment.
- Parsing PROXY protocol on the libp2p listener; rust-libp2p's TCP transport
  does not support it.
- Moving the project's relays off Fly, or changing regions, machine sizes or
  the one-machine-per-region rule.
- An aggregate bandwidth cap. Beyond libp2p's per-circuit byte and duration
  limits there is no in-process control; an egress alert is an operations
  task.
- The matching DID-length guard in the app's verification crate (same
  quadratic decode). Noted for the app repo.
- Monitoring observer changes. The JSON shapes it scrapes do not change.
- Making community relays receipt issuers. That path is the on-chain relay
  registry.
- Upgrading libp2p. The relay tracks the app's version; bump them together.

## Further Notes

- Both live relays answer `/health`, refuse `/metrics` without a token, and
  negotiate multistream and Noise on TCP 4001. A libp2p-level probe from the
  assessment machine could not complete handshakes to any internet node,
  including a public IPFS bootstrap, so the proxy-address and QUIC findings
  are stated as probable, not confirmed. The one-line check is to read
  `/peers` with the admin token: unique-local prefixes mean the relay sees
  proxy addresses.
- Hosting on a plain VPS with a public address is the configuration under
  which every limiter works as designed, and it is the configuration the
  self-hosting guide describes first.
