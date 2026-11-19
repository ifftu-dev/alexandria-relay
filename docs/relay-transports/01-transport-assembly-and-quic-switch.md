# Transport assembly, QUIC off switch, Identify listen addresses

Triage: done
Updated: 2026-11-19
Repos: alexandria-relay
Part of: alexandria-relay/docs/relay-transports-spec.md

## Task

Spec sections: "Transport assembly" (under PROXY protocol v2), "QUIC", "Identify",
"Doctor" (transport line only). User stories 16–19, 25.

1. Assemble the swarm transport by hand (TCP + noise + yamux, optionally
   combined with QUIC) and pass it through the builder's custom-transport
   hook, so later tickets can wrap TCP and configure QUIC in one place.
2. `--quic` / `RELAY_QUIC` (default true). Off: no QUIC transport, no UDP
   listener, no QUIC external addresses (dns4 form or resolved-IP forms).
3. Identify hides listen addresses when at least one external address is
   registered.
4. `doctor` prints one transport line (TCP, PROXY protocol off for now; QUIC
   on/off) and skips QUIC dials when QUIC is off.
5. Black-box tests per the spec's Testing Decisions for QUIC off and
   Identify; doctor CLI test for the transport line.

## Notes

2026-11-19: Done. `src/transport.rs` builds the swarm transport by hand
(`transport::build`) and the swarm takes it through `with_other_transport`;
its private `tcp()` is the one place the TCP transport is built and
`quic_config()` the one place the QUIC config is set. `--quic` /
`RELAY_QUIC` takes a value (`--quic false`; boolish, so `off`/`0` work) and
is `RelayConfig::quic`; off, the QUIC listeners, the dns4 QUIC form and the
resolved-IP QUIC forms are all skipped (`addr::tcp_and_quic` now takes an
optional QUIC port). Identify hides listen addresses when `--public-host`
forms a valid dns4 address, since those forms are always registered and the
choice is fixed before registration. `doctor` prints `Transports: TCP (PROXY
protocol off), QUIC on|off` and filters QUIC targets when off. Probe's own
`--quic` ignores an inherited `RELAY_QUIC` through `Cli::parse_args`.
Covered by `tests/transports.rs`, `tests/doctor.rs`, a probe CLI test and
config unit tests. Left as is: mesh dials still include QUIC forms of
profile relays; with QUIC off those addresses are refused by the transport
and TCP carries the connection.
