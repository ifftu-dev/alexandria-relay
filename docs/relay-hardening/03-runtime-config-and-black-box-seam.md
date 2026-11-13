# Runtime configuration, module split and the black-box test seam

Status: implemented
Triage: done
Repos: alexandria-relay
Part of: alexandria-relay/docs/relay-hardening-spec.md

## Task

Turn the compile-time limits into runtime configuration and give the relay one
seam that tests can drive over loopback. Every later ticket depends on this.

1. Define one configuration struct holding every tunable: ports and bind
   addresses (including a new `--metrics-bind`), external host, data
   directory, admin token, and every limit that is a constant today
   (connections total, per peer, per IP concurrent and per window, idle
   timeout, Kademlia query timeout and replication factor, record cap and
   size, reservation and circuit caps and durations, circuit bytes, Identify
   address cap, receipt and lookup budgets and windows, lookup tracked-IP
   cap, health log interval, pending-incoming cap). The CLI parser builds it
   from flags and `RELAY_*` environment variables with today's values as
   defaults. `--help` documents each flag and its variable.
2. Add a start function that takes the configuration and returns a handle
   exposing the PeerId, the bound libp2p listen addresses, the bound HTTP
   address and a shutdown trigger that performs the same graceful shutdown
   SIGTERM does. The binary's entry point calls it and waits on signals.
   Port zero binds an ephemeral port and the handle reports the real one.
3. Split the single source file into modules: configuration, swarm
   (behaviour construction and event loop), HTTP router, store, address
   helpers. No behaviour change in the split; existing unit tests move with
   their code.
4. Add an integration test module that starts a relay with ephemeral ports and
   a temporary data directory, connects a second libp2p swarm, and covers:
   reservation accepted with a non-empty address set when an external
   address is configured and refused address-less otherwise; receipt
   granted, re-issued with the same first-seen time on refresh, refused for a
   second DID; admin routes 404 without the token and 200 with it; `/health`
   public. A test helper owns relay startup so later tickets add cases, not
   scaffolding.
5. Replace the limits table in the operations doc with the flag and variable
   names and defaults, and drop the "raise them for the test" recompile
   advice. Update the README configuration table. Fix the `--generate-key`
   output to point at the network profile's relay and issuer lists.

Acceptance: `cargo test --locked` runs the integration tests in-process with no
network access; the binary's observable behaviour with no flags matches
today's; `cargo run -- --help` lists every limit; `scripts/check-docs.sh`
passes; fmt, clippy and tests pass.

## Implementation workflow

Read the parent spec and the repository `AGENTS.md`. Use the TDD skill: the
first red test is the start function returning bound addresses. Branch from
`main` after ticket 01 lands; confirm ancestry before editing. Return
commits, red/green evidence and unresolved blockers. Tracker updates are
authorized by the invoked implement-spec workflow.

## Notes

- 2026-11-13: Done. The crate is now a library plus a thin binary, with
  modules `config`, `swarm`, `http`, `store`, `username_reg` and `addr`; the
  split commit moves code and unit tests unchanged. `RelayConfig` holds every
  tunable, `Cli` builds it from flags and `RELAY_*` variables with the old
  constants as defaults (a unit test pins them to the historical literals),
  and `--help` lists every limit. `start(config)` returns a `RelayHandle`
  with the PeerId, bound listen addresses, bound HTTP address and a graceful
  `shutdown()`; the binary waits on SIGTERM/SIGINT and calls it. Red: the
  first integration test failed to compile because `start`, `RelayConfig`
  and `RelayHandle` did not exist; green: seven loopback tests in
  `tests/relay.rs` pass in-process (bound ports, reservation with and
  without an external host, receipt first-seen order, admin gating,
  `/health`, shutdown releasing listeners), and the binary started on
  ephemeral ports and shut down cleanly on SIGTERM.
- Deviations: secrets (`RELAY_SEED`, `RELAY_ADMIN_TOKEN`) stay
  environment-only rather than gaining flags, and are listed in `--help`.
  `--listen-ip4` and `--listen-ip6` are new alongside `--metrics-bind`.
  The disk mirror now follows the configured record cap and size instead of
  its own copy of the defaults. The receipt request size cap (8 KiB) and
  the negotiating-stream cap stay constants, since they are wire bounds.
