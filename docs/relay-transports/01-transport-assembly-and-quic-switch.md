# Transport assembly, QUIC off switch, Identify listen addresses

Triage: ready-for-agent
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
