# Probe subcommand

Triage: ready-for-agent
Updated: 2026-11-19
Repos: alexandria-relay
Part of: alexandria-relay/docs/relay-transports-spec.md

## Task

Spec section "Probe", plus "Probe addition" (IP literal host) under Staging
rehearsal. User stories 27–33.

1. `alexandria-relay probe` with `--host`, `--port`, `--peer-id`,
   `--network-profile`, `--health-url`, `--quic`, `--timeout-secs`.
2. PASS/FAIL line per transport, exit code, PeerId mismatch message,
   bounded retry, Identify protocol version check.
3. CLI tests listed in Testing Decisions.
