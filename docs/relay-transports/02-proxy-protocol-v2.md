# PROXY protocol v2 on TCP

Triage: ready-for-agent
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
