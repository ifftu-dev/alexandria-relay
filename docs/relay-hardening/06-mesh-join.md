# Join the mesh: bootstrap from the network profile and announce

Status: implemented
Updated: 2026-11-13
Triage: done
Repos: alexandria-relay
Part of: alexandria-relay/docs/relay-hardening-spec.md
Blocked by: alexandria-relay/docs/relay-hardening/03-runtime-config-and-black-box-seam.md

## Task

A relay today never dials another relay, never runs Kademlia bootstrap and
never announces itself. Make a new relay part of the same DHT as the others,
and let it advertise connectivity without anyone editing a client.

1. Add `--network-profile <path>` (and variable). The relay parses only the
   fields it needs: the relay list (PeerId, DNS name, port, fallback IPs),
   `network_id` and `protocol_namespace`. Apply the same fail-closed checks
   the app applies to those fields, and refuse a namespace that is not
   `/alexandria/<network_id>`. No profile value appears as a code constant or
   flag default; without a profile the relay behaves as today.
2. With a profile, dial every listed relay other than itself at startup over
   DNS and fallback addresses, add them to the routing table, and run
   Kademlia bootstrap on a fixed interval. Reconnect with backoff when a
   relay drops.
3. Add `--announce`. When given together with a profile, publish a provider
   record under the network's relay-discovery key (the hash of the namespace
   plus the relay suffix, computed exactly as the app computes it) on the
   provider-record republish interval. `--announce` without a profile is a
   startup error.
4. Log a one-line statement at startup that announcing advertises
   connectivity only and grants no receipt-issuer trust; repeat it in
   `--help`.
5. Add a reachable-relay count and bootstrap status to the JSON metrics and
   health output.

Acceptance: black-box tests start two relays with a synthetic profile naming
both, and show each has the other in its routing table; an announcing relay
appears as a provider under the discovery key when queried through its
bootstrap peer; a profile with a mismatched namespace is refused at startup;
`--announce` without `--network-profile` is refused. Monitoring's scraped
fields are additive only. Fmt, clippy, tests and `scripts/check-docs.sh` pass.

## Implementation workflow

Read the parent spec, the repository `AGENTS.md`, the bundled-network-profile
ADR in the app repository and the app's network-profile validation rules for
the fields parsed here. Use the TDD skill at the black-box seam. Branch from
the tip containing 03; confirm ancestry. Return commits, red/green evidence
and unresolved blockers. Tracker updates are authorized by the invoked
implement-spec workflow.

## Notes

- 2026-11-13: Done. `--network-profile` / `RELAY_NETWORK_PROFILE` loads
  `src/profile.rs`, which reads `schema_version`, `network_id`, `relays`
  (PeerId, DNS name, port, fallback IPs) and `protocol_namespace` and applies
  the app's checks for those fields (cited to the app's
  `src-tauri/src/network_profile.rs`): 64 KiB cap, schema version 1,
  identifier rules, non-empty relay list, namespace equal to
  `/alexandria/<network_id>`, unique parseable PeerIds, unique valid DNS
  names, non-zero port, non-empty public fallback IPs, placeholder markers.
  `src/mesh.rs` keeps the other relays connected: the event loop resolves
  each name through the OS resolver, dials TCP and QUIC on the profile port,
  redials with backoff from 1 s doubling to 5 min, adds profile addresses to
  the routing table on connect, and bootstraps on joining and every
  5 minutes. `--announce` / `RELAY_ANNOUNCE` calls `start_providing` on the
  app's relay-discovery key (SHA-256 of `"{namespace}.relays"`, from the
  app's `src-tauri/src/p2p/discovery.rs`) when the relay joins, and
  Kademlia republishes it on its provider-record interval. The startup log
  and `--help` say announcing grants no receipt-issuer trust. `/health` and
  the JSON `/metrics` add `profile_relays`, `reachable_relays` and
  `bootstrap_status`; nothing was removed or renamed.
- Red/green: the first tests in `tests/mesh.rs` failed to compile
  (`RelayConfig` had no `announce` or `network_profile`), the namespace case
  then started a relay it should refuse, and the two-relay case timed out
  with `reachable_relays` absent. Green: five loopback tests pass (refusals,
  two relays finding each other through a Kademlia client's closest-peers
  query, the announcer found as a provider through its bootstrap peer, and a
  dropped relay redialled). Removing the announce call or the redial
  schedule makes the matching test fail.
- Deviations: fields the relay does not read are ignored rather than
  rejected, so a new app-side field cannot stop relays; duplicates of the
  fields it reads are still refused. Fallback IPs are dialled only when the
  DNS name resolves to nothing (DNS goes through the OS resolver, so
  libp2p's `dns` feature and hickory stay out of the build). The test
  profiles name the relays `localhost` and `127.0.0.1`, which the app's
  DNS-name rule accepts, so no case needs a network lookup.

- 2026-11-13, review fixes: `--announce` now publishes as the event loop
  starts instead of only when the first profile relay connects, so a
  relay alone in its profile, or whose peers are all down, still holds
  and serves its own provider record. Joining the mesh announces again,
  and Kademlia republishes on its provider-record interval. New loopback
  test: a relay whose profile names only itself is found as a provider
  under the discovery key; it timed out before the fix.
