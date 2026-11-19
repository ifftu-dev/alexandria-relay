# QUIC protections

Triage: done
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

## Notes

2026-11-19: Done. `src/quic_budget.rs` holds `QuicPendingBudget`, the first
field of `RelayBehaviour`: it tracks pending inbound connections whose local
address is QUIC by connection id, denies new ones with `QuicBudgetExceeded`
once the budget is full, and frees a slot on the established hook, on
`ConnectionEstablished` and on `ListenFailure`. The four settings live in a
`QuicLimits` struct at `Limits::quic` (flags `--quic-max-pending-incoming`,
`--quic-max-stream-data`, `--quic-max-connection-data`,
`--quic-handshake-timeout-secs`, all refusing 0); `transport::quic_config`
applies the windows and timeout. The event loop counts budget denials from
`IncomingConnectionError` by downcasting the cause, and counts every
established connection by transport. `/metrics` gains
`connections_established` (`tcp`, `quic`), `quic_pending_denied` and
`quic_pending_denied_per_min` (Prometheus:
`relay_connections_established_total{transport=...}`,
`relay_quic_pending_denied_total`, `relay_quic_pending_denied_per_min`).
`/health/alerts` raises `quic_pending_denied_sustained` when the last full
minute saw more than 60 refusals (one a second). Covered by hook-level unit
tests, a `quic_config` unit test, config tests, an alert route test and
black-box QUIC and TCP reservation tests in `tests/transports.rs`.
