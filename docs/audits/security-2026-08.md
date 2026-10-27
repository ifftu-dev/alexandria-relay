# Alexandria Relay — Security Audit

Status: implemented
Updated: 2026-10-27

**Date**: 2026-08-18 (first pass)
**Scope**: `src/main.rs` (libp2p relay/DHT node, HTTP metrics server),
`src/username_reg.rs` (username claim receipts + DHT record mirror),
`Dockerfile`, `fly.toml`, `fly-eu.toml`, and the Cargo dependency tree.

**Summary**: 1 critical, 1 high, 3 medium, 3 low, 2 informational.

### Remediation status (2026-08-18)

| Finding | Status | Notes |
|---------|--------|-------|
| AR-C1 | **FIXED** | `/peers` now requires `RELAY_ADMIN_TOKEN` (404 without it) **and** returns a truncated `source_prefix` (`/24` v4, `/48` v6) instead of `source_ip`. Both layers, so neither alone is load-bearing. |
| AR-H1 | **FIXED** | `quinn-proto` 0.11.13 → 0.11.17 |
| AR-M1 | **FIXED** | Records are offered to the memory store first and mirrored only if accepted; `save_kad_record` enforces its own 16,384-record ceiling with oldest-first eviction and re-checks the 64 KB value cap |
| AR-M2 | **FIXED** | Per-PeerId token window on receipt requests (`USERNAME_RATE_LIMIT` 5 / 60 s), pruned alongside the IP windows |
| AR-M3 | **FIXED** | `rustls-webpki` 0.103.9 → 0.103.14, `crossbeam-epoch` 0.9.18 → 0.9.20 |
| AR-L1 | **FIXED** | `/metrics` and `/health/alerts` moved behind the same bearer token; TLS listener added on 443 in both fly configs; `/health` and `/username/:name` stay public by design |
| AR-L2 | **FIXED** | `countersign()` returns `Option`; a signing failure now refuses the receipt instead of granting one with an empty signature |
| AR-L3 | **ACCEPTED** | `hickory-proto` is in `Cargo.lock` but not in the build graph — libp2p's `dns`/`mdns` features are not enabled (`cargo tree -e normal \| grep -c hickory` → 0). Recorded in `.cargo/audit.toml` with the condition that would make it reachable again. |

`cargo audit` now reports zero vulnerabilities. A `Dependency audit` CI job was
added and the deploy job gated on it.

The relay is public infrastructure with no authentication in front of it, so
everything here is remotely reachable by definition. The header comment in
`main.rs:18-33` sets out the intended posture — *"The relay has NO special
authority"* — and the design mostly honours it. The findings below are places
where the implementation gives the relay operator, or an unauthenticated
observer, more than that.

| # | Severity | Finding |
|---|----------|---------|
| AR-C1 | CRITICAL | `GET /peers` publicly exposes `peer_id → source_ip` for every connected user |
| AR-H1 | HIGH | Remotely exploitable QUIC advisories in `quinn-proto` (CVSS 8.7 and 7.5) |
| AR-M1 | MEDIUM | Inbound DHT records are mirrored to disk with no cap — disk exhaustion |
| AR-M2 | MEDIUM | Username receipts have no per-peer rate limit — mass squatting |
| AR-M3 | MEDIUM | Four `rustls-webpki` advisories, including a reachable parsing panic |
| AR-L1 | LOW | Metrics/health/username HTTP surface is plaintext and unauthenticated |
| AR-L2 | LOW | `keypair.sign(...).unwrap_or_default()` mints an empty receipt signature on failure |
| AR-L3 | LOW | `hickory-proto` O(n²) name compression and unbounded NSEC3 loop |
| AR-I1 | INFO | Connection, circuit and IP-rate limits are thorough and well tuned |
| AR-I2 | INFO | Username validation is a strict ASCII allowlist — no confusable-homograph surface |

---

## CRITICAL

### AR-C1: `GET /peers` deanonymises every connected user

**File**: `src/main.rs:1009-1027`; exposure defined in `fly.toml:40-53`

```rust
.route("/peers", get(move || {
    let m = peers_metrics.clone();
    async move {
        let lock = m.read().await;
        let entries: Vec<PeerSourceEntry> = lock.peer_source_ips.iter()
            .map(|(pid, ip)| PeerSourceEntry {
                peer_id:  pid.to_string(),
                source_ip: ip.to_string(),
                has_reservation: lock.peers_with_reservation.contains(pid),
            })
            .collect();
        Json(entries)
    }
}))
```

The route is mounted on the metrics server, which `fly.toml` publishes to the
public internet:

```toml
[[services]]
  internal_port = 9090
  [[services.ports]]
    port = 9090
    handlers = ["http"]
```

`handlers = ["http"]` — plaintext, no TLS handler, no authentication anywhere
in `run_metrics_server`.

The codebase already knows this data is sensitive. `main.rs:243` reads:

> `/// Skipped from /metrics to avoid leaking IPs into general telemetry.`

The IPs were correctly withheld from the Prometheus exposition and then served
wholesale, as JSON, on a sibling route.

**Impact**: anyone — no credential, no relationship to the network — can
`curl http://<relay>:9090/peers` and receive a live mapping from libp2p PeerId
to source IP address for every peer currently connected. In a P2P system whose
value proposition is that learners hold their own credentials and their own
data, this is the single worst thing to publish. Combine it with the
monitoring dashboard's geo-IP enrichment (see
`alexandria-monitoring/docs/audits/security-2026-08.md`, `AM-H1`) and a PeerId observed
in gossip resolves to a city.

The relay is also the point of centralisation the
`project_relay_decentralization` work exists to remove — this endpoint is a
concrete instance of why.

**Fix**, in order:
1. Remove `/peers` from the public listener now. If the dashboard needs it,
   serve it on a separate bind address reachable only over the Fly private
   network (`fly-local-6pn`), or behind the same Bearer-token check
   `alexandria-cloud` uses for `/metrics`.
2. Return PeerIds without IPs, or IPs truncated to a /24 (v4) and /48 (v6),
   for any consumer that only needs a topology view.
3. Change `handlers = ["http"]` to `["tls", "http"]` so nothing on 9090 is
   plaintext.
4. Audit `peer_source_ips` retention — it should hold current connections only,
   not accumulate.

---

## HIGH

### AR-H1: Remotely exploitable QUIC advisories

`cargo audit`, 2026-08-18:

| Advisory | Crate | CVSS | Effect |
|----------|-------|------|--------|
| RUSTSEC-2026-0037 | `quinn-proto` <0.11.14 | **8.7** | Denial of service in Quinn endpoints |
| RUSTSEC-2026-0185 | `quinn-proto` <0.11.15 | 7.5 | Remote memory exhaustion via unbounded out-of-order stream reassembly |

Reached through `libp2p-quic 0.13.0` → `libp2p 0.56.0`. The relay listens on
QUIC by design (`main.rs:450`, `fly.toml` UDP service on 4001), so both are
reachable pre-handshake by any host that can send UDP.

`libp2p_connection_limits` and the IP rate limiter (AR-I1) bound *connection
counts*; neither bounds per-connection memory inside the QUIC state machine,
which is what RUSTSEC-2026-0185 abuses.

**Fix**: `cargo update -p quinn-proto --precise 0.11.15` (or bump `libp2p` to a
release that pulls it), redeploy both regions. This is the highest-value change
in this repo after AR-C1 and costs a lockfile bump.

---

## MEDIUM

### AR-M1: Inbound DHT records are mirrored to disk with no cap

**Files**: `src/main.rs:776-798`, `src/username_reg.rs:308-314`

`FilterBoth` mode routes every inbound `PutRecord` through the event loop,
which writes it to SQLite before offering it to the in-memory store:

```rust
if record.value.len() <= KAD_MAX_RECORD_SIZE {
    if let Some(store) = registry_store.as_ref().and_then(|s| s.lock().ok()) {
        store.save_kad_record(record.key.as_ref(), &record.value);
    }
    let _ = swarm.behaviour_mut().kademlia.store_mut().put(record.clone());
}
```

```rust
pub fn save_kad_record(&self, key: &[u8], value: &[u8]) {
    let _ = self.conn.execute(
        "INSERT INTO kad_records (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value", ...);
}
```

The `MemoryStore` is capped at `KAD_MAX_RECORDS = 16_384`
(`main.rs:104,1148`). The disk mirror has no cap at all — not on record count,
not on total bytes, not per peer. Note the ordering: the disk write happens
*before* `store_mut().put()`, so records the memory store rejects for exceeding
its cap are still persisted.

At `KAD_MAX_RECORD_SIZE = 65_536` bytes per record and unique attacker-chosen
keys, filling a 1 GB Fly volume takes roughly 16k requests. Record contents are
never validated, and `load_kad_records` pulls everything back at boot
(`main.rs:422-434`), so a filled volume also degrades startup.

**Fix**: enforce the same 16,384-record and total-byte ceiling on the SQLite
mirror; evict oldest-first on overflow. Track per-peer put counts and refuse
beyond a quota. Only mirror records the memory store actually accepted — move
the `save_kad_record` call after a successful `put`.

---

### AR-M2: Username receipts have no per-peer rate limit

**File**: `src/username_reg.rs:196-300`, dispatched from `src/main.rs:809+`

`handle_receipt` verifies the claimant's signature over
`(username, did, claimed_at)` and applies first-seen semantics — both correct.
What it does not do is limit how many distinct usernames one peer may claim.
Generating a fresh `did:key` and a fresh signature is free and offline, so a
single connection can enumerate and receipt the entire viable namespace.

The name policy (`verify_claim`, 3–32 chars, `[a-z0-9_]`) makes the interesting
subset small: every dictionary word and every plausible handle can be claimed
in one session. Once receipted, the row is held until the owner tombstones it —
and only the owner can (`RELEASE_GRACE_SECS`), so squatted names never free up.

`claimed_at` is signed but never range-checked; priority comes from server-side
`received_at`, which is the right choice, but it means the claim timestamp is
carried and ignored.

**Fix**: rate-limit receipt grants per source IP and per connection, reusing
the `ip_rate_windows` machinery already present at `main.rs:544-578`. Consider
requiring proof of work, a small on-chain anchor, or a cost signal for a first
claim from an unseen DID. Add an expiry so an unrenewed receipt lapses.

---

### AR-M3: `rustls-webpki` advisories

Four, all reached through the TLS stack:

| Advisory | Effect |
|----------|--------|
| RUSTSEC-2026-0104 | Reachable panic parsing a certificate revocation list |
| RUSTSEC-2026-0098 | Name constraints for URI names incorrectly accepted |
| RUSTSEC-2026-0099 | Name constraints accepted for certificates asserting a wildcard name |
| RUSTSEC-2026-0049 | CRLs not treated as authoritative by distribution point (faulty matching) |

The panic is the one that matters for availability on a public node.

Also flagged in the same run: `crossbeam-epoch` <0.9.20 (RUSTSEC-2026-0204,
invalid pointer dereference in a `fmt::Pointer` impl), `anyhow`
(RUSTSEC-2026-0190, unsoundness in `Error::downcast_mut`), `rand` 0.9.2
(RUSTSEC-2026-0097, unsound with a custom logger), and `core2` 0.4.0 —
**yanked, all versions, unmaintained** (RUSTSEC-2026-0105).

**Fix**: bump to `rustls-webpki` ≥0.103.13 and `crossbeam-epoch` ≥0.9.20. Trace
`core2` with `cargo tree -i core2` and remove the path that pulls a
fully-yanked crate into a public-facing binary.

---

## LOW

### AR-L1: The whole HTTP surface is plaintext and unauthenticated

**File**: `src/main.rs:872-1040`, `fly.toml:40-53`

Beyond `/peers` (AR-C1), port 9090 serves `/metrics`, `/health`,
`/health/alerts` and `/username/:name` — all anonymous, all over plaintext
HTTP. `/metrics` and `/health/alerts` publish circuit accept/deny rates,
reservation counts and per-minute deltas: useful operational intelligence for
someone timing an attack against the relay. `/username/:name` is a public
username→DID oracle, enumerable across the whole `[a-z0-9_]{3,32}` namespace.

`/health` should stay public for the platform healthcheck. Everything else
should not be.

**Fix**: split the listener — `/health` public, the rest bound to the Fly
private network or behind a Bearer token. Add the `tls` handler.

---

### AR-L2: An empty signature is minted on signing failure

**File**: `src/username_reg.rs:~281,~290`

```rust
let sig = hex::encode(keypair.sign(&bytes).unwrap_or_default());
```

`unwrap_or_default()` on a failed sign yields `Vec::new()`, which hex-encodes
to `""`. That empty string is then stored in `receipts.receipt_sig` and
returned to the claimant inside `ReceiptResponse::Granted` — a receipt that
reads as granted and carries no signature. Any client that treats the presence
of a `Granted` response as the trust signal, rather than verifying the
countersignature, accepts it.

**Fix**: return `ReceiptResponse::Refused { reason: "relay signing failed" }`
on a signing error. Never persist a row with an empty `receipt_sig`.

---

### AR-L3: `hickory-proto` DNS advisories

RUSTSEC-2026-0119 (CPU exhaustion during message encoding, O(n²) name
compression — fixed in ≥0.26.1) and RUSTSEC-2026-0118 (NSEC3 closest-encloser
proof validation enters an unbounded loop on cross-zone responses — **no fix
available**). Reached via `libp2p-dns` and `libp2p-mdns`. Exposure depends on
whether the relay resolves attacker-influenced names; bootstrap multiaddrs are
IP-literal, which limits it.

---

## INFO (positive findings)

### AR-I1: Connection and circuit limiting is thorough

**File**: `src/main.rs:87-131,544-578`

Layered and each layer justified in a comment: `libp2p_connection_limits` for
per-peer and total connection caps; a separate IP-level rate window
(`IP_RATE_LIMIT` per `IP_RATE_WINDOW`) specifically to defeat PeerId rotation,
with stale windows pruned; per-circuit bandwidth and duration caps; reservation
limits. The comment at `:120` cites an observed incident (`circuits_denied`
7910:47) as the reason for a particular value — tuning driven by production
data rather than by guesswork.

This is why AR-M1 and AR-M2 stand out: the resource-exhaustion thinking is
clearly present and thorough at the connection layer, and simply was not
extended to the two persistence surfaces.

### AR-I2: Username validation is a strict ASCII allowlist

**File**: `src/username_reg.rs:134-146`

```rust
if claim.username.len() < 3 || claim.username.len() > 32
    || !claim.username.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
```

Lowercase-only removes case-collision impersonation; ASCII-only removes the
entire Unicode-confusable class (Cyrillic `а` for Latin `a`, zero-width joiners,
RTL overrides) that bites most naming systems. Length-bounded. The lookup path
normalises with `.trim().trim_start_matches('@').to_lowercase()` before
querying, so the read and write paths agree.

Claim verification itself is also correct: `did_key_to_verifying_key` checks the
multicodec prefix (`0xed 0x01`) and length before use, and `verify_strict` is
used rather than `verify`.

---

## Remediation priority

| # | Finding | Effort | Impact |
|---|---------|--------|--------|
| 1 | AR-C1: take `/peers` off the public listener | Trivial | Stops live deanonymisation of every user |
| 2 | AR-H1: bump `quinn-proto` to ≥0.11.15 | Trivial | Two remote DoS advisories, one CVSS 8.7 |
| 3 | AR-M3: bump `rustls-webpki`, `crossbeam-epoch`; drop `core2` | Low | Reachable panic; yanked crate in a public binary |
| 4 | AR-M1: cap and evict the SQLite DHT mirror | Low | Disk exhaustion at ~1 GB per 16k requests |
| 5 | AR-M2: rate-limit username receipts | Medium | Namespace squatting is currently free |
| 6 | AR-L1: split the listener, add TLS | Low | Removes the remaining anonymous surface |
| 7 | AR-L2: refuse rather than mint an empty signature | Trivial | Correctness |

---

## Not covered in this pass

- The libp2p relay behaviour's interaction with `alexandria`'s
  `relay_discovery` / `relay_registry` / `registry_chain` modules — whether a
  malicious relay can influence which relays clients select. This is the core
  question of the `project_relay_decentralization` work and needs both sides
  read together.
- `Dockerfile` build provenance and base-image pinning.
- The `fly-eu.toml` deployment specifically; findings above were verified
  against `fly.toml` and the two files share the same service shape.
