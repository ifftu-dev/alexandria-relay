# Prometheus output, doctor subcommand and the self-hosting guide

Triage: ready-for-agent
Repos: alexandria-relay
Part of: alexandria-relay/docs/relay-hardening-spec.md
Blocked by: alexandria-relay/docs/relay-hardening/03-runtime-config-and-black-box-seam.md, alexandria-relay/docs/relay-hardening/04-release-artifacts.md, alexandria-relay/docs/relay-hardening/06-mesh-join.md

## Task

Give an operator the three things they need after the binary runs: metrics
their stack can read, a way to prove the relay is reachable, and one page that
tells them how to run it.

1. `/metrics` serves Prometheus text exposition when the `Accept` header asks
   for it and JSON otherwise, behind the same bearer gate. Counters and gauges
   mirror the JSON fields with a `relay_` prefix; no per-peer data is
   exported.
2. `/health` adds the crate version and reads the live connection count from
   the swarm instead of the five-minute sample.
3. Per-circuit, per-reservation and per-receipt-request log lines move to
   debug. The periodic health line gains deltas since the previous line.
4. Add a `doctor` subcommand. It loads the same configuration, starts the
   relay, dials each advertised external address over TCP and QUIC from a
   second in-process swarm, reports which succeeded, lists the reservation
   address set, checks the data directory is writable, reports whether an
   admin token is configured and accepted by the local HTTP listener, and
   exits non-zero if no advertised address is reachable. Without an external
   host it says so and exits non-zero.
5. Write `docs/self-hosting.md` (`Status: live`): what a relay does and does
   not grant (connectivity relay versus receipt issuer, in the first
   section); requirements (public address, ports, disk); VPS with systemd
   unit and environment file; Docker Compose using the published image;
   reverse-proxy TLS example for the HTTP listener with `--metrics-bind` on
   loopback and the trusted-proxy header; joining the mesh with
   `--network-profile` and `--announce`; running `doctor`; Prometheus scrape
   snippet; the Fly limiter caveat with a link to the operations doc. Link it
   from the README quick start and keep the README under its line limit.

Acceptance: black-box tests show the Prometheus body on the text `Accept`
type and JSON otherwise, both gated; `doctor` exits zero against a relay
started with a reachable external address and non-zero without one; log level
of the per-event lines is verified by configuration, not by asserting on log
text. Every command in the self-hosting guide has been run once on a Linux
host or container and the output pasted into the ticket's completion note.
`scripts/check-docs.sh` passes; fmt, clippy and tests pass.

## Implementation workflow

Read the parent spec and the repository `AGENTS.md`. Use the TDD skill at the
black-box seam. Branch from the tip containing 03, 04 and 06; confirm
ancestry. Return commits, red/green evidence, the guide walkthrough output and
unresolved blockers. Tracker updates are authorized by the invoked
implement-spec workflow.
