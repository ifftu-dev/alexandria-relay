# Make per-address limits see clients and bound the handshake surface

Status: implemented
Triage: done
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

## Notes

- 2026-11-13: Done. `client_bucket` in `src/addr.rs` (full IPv4 address,
  IPv6 /64, IPv4-mapped addresses unmapped first) keys the libp2p
  connection limiter, the lookup limiter and the `/peers` source map;
  `/peers` still presents /24 and /48. `--trusted-proxy-header`
  (`RELAY_TRUSTED_PROXY_HEADER`, `Fly-Client-IP` when given without a
  value) feeds one `client_ip` function in `src/http.rs`; unset, headers
  are ignored. Connection remote addresses no longer enter the routing
  table. The HTTP listener is now served through hyper directly with a
  header read timeout (10 s), a request timeout (15 s, then `503`) and a
  concurrent-connection cap (256), each a flag. Item 5 was already
  satisfied by ticket 04 (the image runs as uid 10001); nothing changed
  here. The operations doc has the client-address section. Red: in
  `tests/limits.rs`, with the config fields added but no behaviour, five
  of six cases failed (header address still charged to the socket
  address, a neighbouring /64 refused, the relay handed out the
  advertiser's `127.0.0.1` ephemeral address, a silent connection stayed
  open past ten seconds, a second connection was served while the only
  slot was held); green: all six pass, plus unit tests for the bucketing
  and header parsing.
- Deviations: the bucketing lives inside the lookup limiter, so callers
  pass raw addresses. An appending header such as `X-Forwarded-For` is
  read from its last entry, and a missing or unparsable header falls back
  to the socket address. The HTTP server dropped HTTP/2 (every client
  speaks HTTP/1.1). Connections past the cap wait in the listen backlog
  rather than being refused. libp2p's own per-IP reservation and circuit
  limiters still key on the full address; they are not configurable and
  are listed as affected in the operations doc. The Fly configs do not
  enable the header flag; that is a deploy decision.
