# Make per-address limits see clients and bound the handshake surface

Triage: ready-for-agent
Repos: alexandria-relay
Part of: alexandria-relay/docs/relay-hardening-spec.md
Blocked by: alexandria-relay/docs/relay-hardening/03-runtime-config-and-black-box-seam.md

## Task

Every per-address limiter keys on the socket peer address. Behind the Fly
proxy, and behind any reverse proxy an operator puts in front of the HTTP
listener, that address is the proxy's. Fix what can be fixed in-process and
document what cannot.

1. Add an opt-in `--trusted-proxy-header` flag (environment variable too). When
   set, HTTP handlers take the client address from that header; when unset,
   they use the socket address and ignore the header. Given without a value,
   the flag defaults to the Fly client-IP header name. Help text states the
   spoofing risk of enabling it on a directly reachable listener.
2. Route every per-address key through one bucketing function: full IPv4
   address, /64 for IPv6. Apply it to the connection limiter, the lookup
   limiter and the metrics source map. `/peers` keeps its /24 and /48
   presentation.
3. Stop adding the connection's remote address to the Kademlia routing table
   on connect; add only Identify-reported addresses that pass the routability
   filter, as the Identify handler already does.
4. Add a header read timeout, a request timeout and a concurrency limit to
   the HTTP server, all configurable with sane defaults.
5. Run the container as a non-root user.
6. In the operations doc, add a section stating that per-address limits on
   the libp2p listener require a host that preserves source addresses; that
   Fly's TCP and HTTP services do not; which limiters are affected (the
   relay's connection limiter, libp2p's default per-IP reservation and
   circuit limiters, and the lookup limiter unless the header flag is set);
   and that QUIC on Fly requires binding the platform's global-services
   address, which the relay does not do, so QUIC reachability there is
   unverified.

Acceptance: black-box tests show the lookup limiter buckets by the header
address only when the flag is set and ignores the header otherwise; two IPv6
clients in one /64 share a budget; a connected peer's ephemeral remote address
does not appear in the routing table while its Identify addresses do; a
connection that sends no HTTP headers is closed at the timeout. `/peers` JSON
shape is unchanged. Docs pass `scripts/check-docs.sh`.

## Implementation workflow

Read the parent spec, the repository `AGENTS.md`, and ticket 03 for the
configuration struct and the start function; add the new flags there. Use the
TDD skill at the black-box seam. Branch from the integration tip that contains
03; confirm ancestry before editing. Return commits, red/green evidence and
unresolved blockers. Tracker updates are authorized by the invoked
implement-spec workflow.
