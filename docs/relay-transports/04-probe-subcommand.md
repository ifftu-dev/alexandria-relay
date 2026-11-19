# Probe subcommand

Triage: done
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

## Notes

2026-11-19: Done in `src/probe.rs`, reusing doctor's client swarm and DNS
resolution; `tests/probe.rs` covers every CLI case in Testing Decisions plus
a non-Alexandria Identify and a host missing from the profile. Choices the
spec left open: TCP and QUIC are dialled on the one `--port` and checked
concurrently; a PeerId mismatch or a wrong Identify protocol version fails at
once instead of retrying; `--health-url` is plain `http://` only (no TLS
client in the dependency tree) and is retried like a dial; a profile without
the host is a FAIL, not a fallback. Probe's `--port` and `--network-profile`
shadow the relay's global flags, and `Cli::parse_args` stops `RELAY_PORT` and
`RELAY_NETWORK_PROFILE` from leaking into them. If ticket 01 adds a global
`--quic`, probe's local `--quic` shadows it the same way.
