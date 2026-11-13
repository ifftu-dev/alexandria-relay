# Move the store off the event loop and let the DHT mirror expire

Triage: ready-for-agent
Repos: alexandria-relay
Part of: alexandria-relay/docs/relay-hardening-spec.md
Blocked by: alexandria-relay/docs/relay-hardening/03-runtime-config-and-black-box-seam.md

## Task

The SQLite store is written synchronously inside the swarm event loop and
HTTP handlers, counts the whole mirror table on every insert, and reloads
mirrored records without expiry. Fix the execution model and the retention
model.

1. Run the store on a dedicated blocking thread behind a small actor. The
   event loop and HTTP handlers send requests over a channel and await
   replies. No SQLite call runs on a runtime worker and no standard mutex is
   held across an await.
2. Open the database in write-ahead-log mode with normal synchronous writes
   and a busy timeout. Keep a cached row count for the mirror instead of
   counting per insert.
3. Persist each mirrored record's expiry (absolute Unix seconds, nullable)
   and publisher. On load, skip expired rows and set the expiry on the
   in-memory record. Prune expired rows on a periodic tick.
4. Change mirror eviction to: expired first, then soonest-expiring, then
   oldest-inserted. Make the record cap configuration (ticket 03) and restate
   the memory estimate in the operations doc using the actual record-size
   distribution rather than the worst case.
5. Provider announcements remain unmirrored; they expire on their own. State
   the per-key provider cap (libp2p's default) in the operations doc, since
   the relay-discovery key is a single key.
6. Keep the pre-launch rule: the schema change replaces the table definition;
   no data migration. A store created by an older binary is recreated.

Acceptance: black-box tests show a DHT put survives a restart from the same
data directory with its expiry intact, an expired mirrored record is absent
after restart, and the lookup endpoint answers while a burst of DHT puts is
in flight (bounded latency, no timeout). Unit tests cover eviction order and
the cached count. Fmt, clippy, tests and `scripts/check-docs.sh` pass.

## Implementation workflow

Read the parent spec and the repository `AGENTS.md`. Use the TDD skill at the
black-box seam from ticket 03 and the existing store unit seam. Branch from
the tip containing 03; confirm ancestry. Return commits, red/green evidence
and unresolved blockers. Tracker updates are authorized by the invoked
implement-spec workflow.
