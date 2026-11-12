# Join the mesh: bootstrap from the network profile and announce

Triage: ready-for-agent
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
