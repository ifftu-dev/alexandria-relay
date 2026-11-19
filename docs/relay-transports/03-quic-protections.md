# QUIC protections

Triage: ready-for-agent
Updated: 2026-11-19
Repos: alexandria-relay
Part of: alexandria-relay/docs/relay-transports-spec.md
Blocked by: alexandria-relay/docs/relay-transports/01-transport-assembly-and-quic-switch.md

## Task

Spec section "QUIC" items Pending budget, Windows, Handshake timeout,
Counters and alert. User stories 20–24.

1. `RELAY_QUIC_MAX_PENDING_INCOMING` (64) budget behaviour; tests through its
   hooks as Testing Decisions describes.
2. `RELAY_QUIC_MAX_STREAM_DATA`, `RELAY_QUIC_MAX_CONNECTION_DATA`,
   `RELAY_QUIC_HANDSHAKE_TIMEOUT_SECS` applied to the QUIC config.
3. `quic_pending_denied` counter, `connections_established` by transport,
   sustained-denial alert.
4. Black-box: QUIC reservation with the smaller windows counted under `quic`.
