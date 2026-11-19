# PROXY protocol v2 on TCP

Triage: done
Updated: 2026-11-19
Repos: alexandria-relay
Part of: alexandria-relay/docs/relay-transports-spec.md
Blocked by: alexandria-relay/docs/relay-transports/01-transport-assembly-and-quic-switch.md

## Task

Spec section "PROXY protocol v2 on TCP" in full, plus the doctor note for
PROXY mode. User stories 1–15, 26.

1. In-tree v2 parser (new module) with unit tests listed in Testing Decisions.
2. Inbound TCP wrapper that reads the header before reporting the connection
   and rewrites the send-back address; timeout and waiting-socket cap.
3. Settings `RELAY_TCP_PROXY_PROTOCOL` (`off`|`v2`) and
   `RELAY_PROXY_HEADER_TIMEOUT_SECS`.
4. Counters and the header-refusal alert.
5. PROXY shim in `tests/common` and the black-box cases in Testing Decisions.
6. Doctor's transport line shows PROXY on/off and prints the proxy note.

## Notes

2026-11-19: Done. `src/proxy.rs` holds the v2 parser (`parse`, 1 KiB cap,
LOCAL and UNSPEC mean the socket address, UNIX refused, TLVs skipped) and
`ProxyTcp`, which wraps the tokio TCP transport inside `transport::tcp()`:
with `--tcp-proxy-protocol v2` it reads each inbound socket's header exactly
(no buffering) before emitting `Incoming` with the header's source as
`send_back_addr`; `off` is a pass-through. Sockets waiting for a header are
bounded by `--proxy-header-timeout-secs` (default 5) and capped at
`RELAY_MAX_PENDING_INCOMING`. The counters are atomics shared with
`RelayMetrics` (`proxy_header_missing|invalid|timeout|overflow` in both
`/metrics` forms). Classification: no signature (direct clients, scanners,
an empty connect-and-close) is missing; a v1 `PROXY ` line, bad
version/command, UNIX, truncated or oversized is invalid. The
`proxy_header_refusal_majority` alert fires when missing, invalid or late
refusals are at least 10 and more than half of inbound TCP accepts, judged
over the last complete minute or the minute in progress, so it pages without
waiting for the sampler tick and tests need no 60 s wait. Doctor prints
`TCP (PROXY protocol off|v2)` and, for v2, a note that its TCP dials pass
only through the proxy, pointing at `probe`. Covered by parser unit tests,
`tests/proxy_protocol.rs` (shim in `tests/common`), config unit tests and
two doctor CLI tests. IPv4-mapped IPv6 sources are kept as sent;
`addr::client_bucket` already unmaps them.
