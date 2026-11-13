# Move the store off the event loop and let the DHT mirror expire

Status: implemented
Updated: 2026-11-13
Triage: done
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

## Notes

- 2026-11-13: Done. `RegistryStore` runs on a dedicated `relay-store`
  thread behind `StoreHandle`, a cloneable handle over a bounded channel.
  The event loop queues mirror writes and receipt requests without waiting
  and sends each receipt response when the store answers; HTTP lookups
  await their reply; startup warm-loads through the same handle, and
  shutdown waits for the queue to drain. The database opens in WAL mode
  with `synchronous=NORMAL` and a busy timeout, keeps a cached mirror row
  count, and carries a schema version: any other version is recreated
  empty. Mirrored records keep their absolute expiry and publisher;
  expired rows are skipped on load, pruned at startup and every ten
  minutes, and evicted first, then the soonest-expiring, then the
  oldest-inserted. `docs/operations.md` describes the store, restates the
  memory budget from the size of real username-claim records, and states
  the per-key provider cap of 20.
- Red: against the pre-ticket source, the restart test got the record back
  without its publisher or expiry, and the expiry test got the expired
  record back after the restart. Green: three loopback tests in
  `tests/store.rs` (restart keeps expiry and publisher, expired record
  absent after restart, lookups answer within one second during a burst
  of 2,000 puts) and unit tests for eviction order, the cached count,
  expiry on load, WAL mode and schema recreation. The eviction and count
  tests were checked by mutation (insertion-order eviction, counting
  upserts) and failed as expected.
- Deviations: the record cap was already configuration from ticket 03. The
  burst test also passes against the old store on a developer laptop,
  where an fsync is cheap; it guards bounded latency rather than
  reproducing the stall. The prune interval is a constant, not a flag. A
  full store queue drops the mirror write and refuses the receipt with
  "relay busy" rather than blocking the event loop.

- 2026-11-13, review fixes: the store now opens on its own thread
  (`StoreHandle::open`), so a locked database no longer holds a runtime
  worker for the five-second busy timeout; a ticker on a one-thread
  runtime stalled 5.2 s before and not at all after. `/username/:name`
  answers 503 when the store is not running, its queue is full or the
  query fails, where it used to report the name available. Store errors
  tell busy from stopped. The burst test's claim is narrowed in its
  comment: it guards lookup latency and passes against a store on the
  runtime wherever writes are cheap. A new test holds the database's
  write lock from another connection while DHT puts arrive: the puts are
  acknowledged and `/health` answers within a second. With the event loop
  waiting on the store it fails after 32 s (checked by mutation).
