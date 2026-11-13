//! Persistent registry store: username receipts and the Kademlia record
//! mirror, in one SQLite database under the data directory.
//!
//! First-seen semantics for receipts are described in [`crate::username_reg`].
//! The mirror keeps inbound DHT records, with their expiry and publisher, so
//! the in-memory Kademlia store can be refilled after a restart.
//!
//! [`RegistryStore`] is synchronous. The running relay never calls it from an
//! async task: [`StoreHandle::open`] opens it on a dedicated thread and keeps
//! it there, and the event loop and HTTP handlers talk to that thread over a
//! bounded channel.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use libp2p::identity::Keypair;
use libp2p::kad;
use libp2p::PeerId;
use rusqlite::{Connection, OptionalExtension};
use tokio::sync::{mpsc, oneshot};

use crate::config::{DEFAULT_KAD_MAX_RECORDS, DEFAULT_KAD_MAX_RECORD_BYTES};
use crate::username_reg::{
    canonical_receipt_bytes, countersign, release_frees_at, release_valid, verify_claim,
    ReceiptResponse, RelayReceipt, UsernameClaim,
};

/// Schema version, kept in SQLite's `user_version`. A database with any
/// other version was written by another binary and is recreated: the project
/// is pre-launch and its data disposable, so there are no migrations.
const SCHEMA_VERSION: i64 = 2;

/// How long a write waits on a locked database before failing.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Requests that may wait for the store thread. A burst beyond this drops
/// mirror writes (the record still lives in memory) and refuses receipts
/// rather than stalling the event loop.
const QUEUE_CAPACITY: usize = 1024;

/// How often the event loop asks the store to drop expired mirror rows.
pub(crate) const MIRROR_PRUNE_INTERVAL: Duration = Duration::from_secs(600);

/// Expiry sort key: a record without an expiry sorts after every real one.
/// The same expression backs the eviction index, so the two must match.
const EXPIRY_ORDER: &str = "COALESCE(expires_at, 9223372036854775807)";

pub(crate) fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// One mirrored DHT record, as stored on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MirroredRecord {
    pub(crate) key: Vec<u8>,
    pub(crate) value: Vec<u8>,
    /// The publisher's PeerId bytes, when the record names one.
    pub(crate) publisher: Option<Vec<u8>>,
    /// Absolute Unix seconds; `None` means the record never expires.
    pub(crate) expires_at: Option<i64>,
}

impl MirroredRecord {
    /// The on-disk form of `record`, with its expiry made absolute against
    /// the wall clock. `None` if it has already expired.
    pub(crate) fn from_kad(record: &kad::Record) -> Option<Self> {
        let expires_at = match record.expires {
            Some(at) => {
                let left = at.checked_duration_since(Instant::now())?;
                Some(unix_now().saturating_add(left.as_secs() as i64))
            }
            None => None,
        };
        Some(MirroredRecord {
            key: record.key.to_vec(),
            value: record.value.clone(),
            publisher: record.publisher.map(|p| p.to_bytes()),
            expires_at,
        })
    }

    /// The in-memory form, with the absolute expiry turned back into an
    /// [`Instant`].
    pub(crate) fn into_kad(self) -> kad::Record {
        let now = unix_now();
        let expires = self.expires_at.map(|at| {
            let left = u64::try_from(at.saturating_sub(now)).unwrap_or(0);
            Instant::now() + Duration::from_secs(left)
        });
        kad::Record {
            key: kad::RecordKey::new(&self.key),
            value: self.value,
            publisher: self
                .publisher
                .and_then(|bytes| PeerId::from_bytes(&bytes).ok()),
            expires,
        }
    }
}

pub struct RegistryStore {
    conn: Connection,
    /// Ceiling on the on-disk Kademlia mirror, the same cap as the memory
    /// store's. Held here so the store bounds itself without reaching back
    /// into the swarm.
    kad_max_records: usize,
    /// Ceiling on a single mirrored value. The caller checks this too;
    /// checked again here so the storage layer cannot be made to write an
    /// unbounded blob by a future caller that forgets.
    kad_max_value_bytes: usize,
    /// Rows in `kad_records`, counted once at open and kept in step with
    /// every insert and delete, so a write never scans the table.
    mirror_count: usize,
}

impl RegistryStore {
    /// Bound the Kademlia mirror to `max_records` records of at most
    /// `max_value_bytes` each. [`RegistryStore::open`] starts with the
    /// default limits.
    pub fn with_kad_caps(mut self, max_records: usize, max_value_bytes: usize) -> Self {
        self.kad_max_records = max_records;
        self.kad_max_value_bytes = max_value_bytes;
        self
    }

    pub fn open(data_dir: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(data_dir).map_err(|e| format!("create data dir: {e}"))?;
        let conn = Connection::open(data_dir.join("username_registry.db"))
            .map_err(|e| format!("open registry db: {e}"))?;
        conn.busy_timeout(BUSY_TIMEOUT)
            .map_err(|e| format!("set busy timeout: {e}"))?;
        // Write-ahead log with normal sync: a commit appends to the log
        // without an fsync; only checkpoints sync. A crash can lose the last
        // few commits but never corrupts the database.
        let mode: String = conn
            .pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get(0))
            .map_err(|e| format!("enable WAL: {e}"))?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(format!("enable WAL: journal mode is {mode}"));
        }
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(|e| format!("set synchronous: {e}"))?;

        let version: i64 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(|e| format!("read schema version: {e}"))?;
        if version != SCHEMA_VERSION {
            let existing: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'",
                    [],
                    |r| r.get(0),
                )
                .map_err(|e| format!("inspect registry db: {e}"))?;
            if existing > 0 {
                log::warn!(
                    "Registry store has schema version {version}, expected {SCHEMA_VERSION} \
                     — recreating it empty"
                );
            }
            conn.execute_batch(&format!(
                "BEGIN;
                 DROP TABLE IF EXISTS receipts;
                 DROP TABLE IF EXISTS kad_records;
                 CREATE TABLE receipts (
                     username    TEXT PRIMARY KEY,
                     did         TEXT NOT NULL,
                     claim_sig   TEXT NOT NULL,
                     received_at INTEGER NOT NULL,
                     receipt_sig TEXT NOT NULL,
                     released_at INTEGER
                 );
                 CREATE TABLE kad_records (
                     key        BLOB PRIMARY KEY,
                     value      BLOB NOT NULL,
                     publisher  BLOB,
                     expires_at INTEGER
                 );
                 CREATE INDEX kad_records_eviction ON kad_records ({EXPIRY_ORDER});
                 PRAGMA user_version = {SCHEMA_VERSION};
                 COMMIT;"
            ))
            .map_err(|e| format!("create registry schema: {e}"))?;
        }

        let mirror_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM kad_records", [], |r| r.get(0))
            .map_err(|e| format!("count mirrored records: {e}"))?;
        Ok(RegistryStore {
            conn,
            kad_max_records: DEFAULT_KAD_MAX_RECORDS,
            kad_max_value_bytes: DEFAULT_KAD_MAX_RECORD_BYTES,
            mirror_count: usize::try_from(mirror_count).unwrap_or(0),
        })
    }

    /// Handle a receipt request: verify, apply first-seen semantics,
    /// countersign with the relay key.
    pub fn handle_receipt(
        &mut self,
        keypair: &Keypair,
        relay_peer_id: &str,
        claim: &UsernameClaim,
    ) -> ReceiptResponse {
        if let Err(e) = verify_claim(claim) {
            return ReceiptResponse::Refused {
                reason: format!("invalid claim: {e}"),
                existing_did: None,
                existing_received_at: None,
            };
        }

        let now = unix_now();

        let existing: Option<(String, String, i64, String, Option<i64>)> = self
            .conn
            .query_row(
                "SELECT did, claim_sig, received_at, receipt_sig, released_at
                 FROM receipts WHERE username = ?1",
                [&claim.username],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .ok();

        if let Some((did, claim_sig, received_at, receipt_sig, released_at)) = existing {
            // A grace-elapsed release frees the row for new claimants.
            if let Some(rel) = released_at {
                if did != claim.did && now >= release_frees_at(rel) {
                    let _ = self.conn.execute(
                        "DELETE FROM receipts WHERE username = ?1",
                        [&claim.username],
                    );
                    return self.handle_receipt(keypair, relay_peer_id, claim);
                }
            }
            if did == claim.did {
                // Owner submitting a tombstone: record the release.
                if claim.release.is_some() && release_valid(claim) {
                    let rel_at = claim.release.as_ref().map(|r| r.released_at).unwrap_or(now);
                    let _ = self.conn.execute(
                        "UPDATE receipts SET released_at = ?2 WHERE username = ?1",
                        rusqlite::params![claim.username, rel_at],
                    );
                } else if released_at.is_some() && claim.release.is_none() {
                    // Owner re-claiming within grace — undo the release.
                    let _ = self.conn.execute(
                        "UPDATE receipts SET released_at = NULL WHERE username = ?1",
                        [&claim.username],
                    );
                }
                // Same owner refreshing — re-issue the original receipt
                // if the claim is byte-identical; otherwise countersign
                // the new claim sig at the ORIGINAL first-seen time so
                // priority is preserved.
                let sig = if claim_sig == claim.sig {
                    receipt_sig
                } else {
                    let bytes = canonical_receipt_bytes(&claim.sig, received_at, relay_peer_id);
                    let Some(sig) = countersign(keypair, &bytes) else {
                        return ReceiptResponse::Refused {
                            reason: "relay signing failed".to_string(),
                            existing_did: None,
                            existing_received_at: None,
                        };
                    };
                    let _ = self.conn.execute(
                        "UPDATE receipts SET claim_sig = ?2, receipt_sig = ?3 WHERE username = ?1",
                        rusqlite::params![claim.username, claim.sig, sig],
                    );
                    sig
                };
                return ReceiptResponse::Granted(RelayReceipt {
                    relay_peer_id: relay_peer_id.to_string(),
                    received_at,
                    sig,
                });
            }
            return ReceiptResponse::Refused {
                reason: "username already receipted to another DID".to_string(),
                existing_did: Some(did),
                existing_received_at: Some(received_at),
            };
        }

        let received_at = unix_now();
        let bytes = canonical_receipt_bytes(&claim.sig, received_at, relay_peer_id);
        let Some(sig) = countersign(keypair, &bytes) else {
            return ReceiptResponse::Refused {
                reason: "relay signing failed".to_string(),
                existing_did: None,
                existing_received_at: None,
            };
        };

        if let Err(e) = self.conn.execute(
            "INSERT INTO receipts (username, did, claim_sig, received_at, receipt_sig)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![claim.username, claim.did, claim.sig, received_at, sig],
        ) {
            return ReceiptResponse::Refused {
                reason: format!("store error: {e}"),
                existing_did: None,
                existing_received_at: None,
            };
        }

        ReceiptResponse::Granted(RelayReceipt {
            relay_peer_id: relay_peer_id.to_string(),
            received_at,
            sig,
        })
    }

    /// Mirror a kad record for restart persistence, then hold the mirror to
    /// its record cap. `now` is the current Unix time.
    pub(crate) fn save_kad_record(&mut self, record: &MirroredRecord, now: i64) {
        if record.value.len() > self.kad_max_value_bytes {
            return;
        }
        if record.expires_at.is_some_and(|at| at <= now) {
            return;
        }
        let known = self
            .conn
            .prepare_cached("SELECT 1 FROM kad_records WHERE key = ?1")
            .and_then(|mut stmt| {
                stmt.query_row([&record.key], |_| Ok(()))
                    .optional()
                    .map(|row| row.is_some())
            });
        let Ok(known) = known else {
            return;
        };
        let written = self
            .conn
            .prepare_cached(
                "INSERT INTO kad_records (key, value, publisher, expires_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(key) DO UPDATE SET
                     value = excluded.value,
                     publisher = excluded.publisher,
                     expires_at = excluded.expires_at",
            )
            .and_then(|mut stmt| {
                stmt.execute(rusqlite::params![
                    record.key,
                    record.value,
                    record.publisher,
                    record.expires_at
                ])
            });
        if written.is_ok() && !known {
            self.mirror_count += 1;
        }
        self.trim_kad_records(now);
    }

    /// Hold the mirror to its record cap.
    ///
    /// The in-memory Kademlia store has its own ceiling, but it is emptied on
    /// every restart and refilled from here — so without a ceiling on the table
    /// itself, records that were long ago evicted from memory stay on disk
    /// forever and the volume grows without bound.
    ///
    /// Expired records go first, then the soonest-expiring, then (among equal
    /// expiries, and records that never expire) the oldest-inserted: `rowid`
    /// is insertion order, since an `ON CONFLICT` update keeps the original.
    /// Evicting by insertion order alone would drop the earliest users'
    /// records first however long they had left.
    fn trim_kad_records(&mut self, now: i64) {
        if self.mirror_count <= self.kad_max_records {
            return;
        }
        self.prune_expired(now);
        let excess = self.mirror_count.saturating_sub(self.kad_max_records);
        if excess == 0 {
            return;
        }
        let deleted = self.conn.execute(
            &format!(
                "DELETE FROM kad_records WHERE rowid IN (
                     SELECT rowid FROM kad_records ORDER BY {EXPIRY_ORDER} ASC, rowid ASC
                     LIMIT ?1
                 )"
            ),
            rusqlite::params![excess as i64],
        );
        if let Ok(n) = deleted {
            self.mirror_count = self.mirror_count.saturating_sub(n);
        }
    }

    /// Delete every mirrored record that has expired by `now`. Returns how
    /// many went.
    pub(crate) fn prune_expired(&mut self, now: i64) -> usize {
        let deleted = self
            .conn
            .execute(
                "DELETE FROM kad_records WHERE expires_at IS NOT NULL AND expires_at <= ?1",
                [now],
            )
            .unwrap_or(0);
        self.mirror_count = self.mirror_count.saturating_sub(deleted);
        deleted
    }

    /// Mirrored records still live at `now`, for warm-loading the
    /// MemoryStore at boot.
    pub(crate) fn load_kad_records(&self, now: i64) -> Vec<MirroredRecord> {
        let Ok(mut stmt) = self.conn.prepare(
            "SELECT key, value, publisher, expires_at FROM kad_records
             WHERE expires_at IS NULL OR expires_at > ?1",
        ) else {
            return Vec::new();
        };
        stmt.query_map([now], |r| {
            Ok(MirroredRecord {
                key: r.get(0)?,
                value: r.get(1)?,
                publisher: r.get(2)?,
                expires_at: r.get(3)?,
            })
        })
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
    }

    /// Rows in the mirror, from the cached count.
    #[cfg(test)]
    pub(crate) fn mirror_count(&self) -> usize {
        self.mirror_count
    }

    pub fn receipt_count(&self) -> i64 {
        self.conn
            .query_row("SELECT COUNT(*) FROM receipts", [], |r| r.get(0))
            .unwrap_or(0)
    }

    /// Current holder of a username (receipted claims only), for the
    /// HTTP availability endpoint. `Ok(None)` means nobody holds it; a
    /// failed query is an error, never a free name.
    pub fn lookup_username(&self, username: &str) -> rusqlite::Result<Option<(String, i64)>> {
        let now = unix_now();
        let row = self
            .conn
            .query_row(
                "SELECT did, received_at, released_at FROM receipts WHERE username = ?1",
                [username],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, Option<i64>>(2)?,
                    ))
                },
            )
            .optional()?;
        Ok(row
            .filter(|(_, _, rel)| match rel {
                Some(rel_at) => now < release_frees_at(*rel_at),
                None => true,
            })
            .map(|(did, received_at, _)| (did, received_at)))
    }
}

// ── Store actor ──────────────────────────────────────────────────────

/// What the store thread can be asked to do.
enum Command {
    Receipt {
        claim: Box<UsernameClaim>,
        reply: oneshot::Sender<ReceiptResponse>,
    },
    Lookup {
        username: String,
        reply: oneshot::Sender<rusqlite::Result<Option<(String, i64)>>>,
    },
    Mirror(MirroredRecord),
    LoadMirror {
        reply: oneshot::Sender<Vec<MirroredRecord>>,
    },
    PruneExpired,
    ReceiptCount {
        reply: oneshot::Sender<i64>,
    },
    Close {
        reply: oneshot::Sender<()>,
    },
}

/// Why the store could not answer a request.
#[derive(Debug)]
pub(crate) enum StoreError {
    /// The queue was full; the request was not taken.
    Busy,
    /// The store thread has stopped, or never started.
    Stopped,
    /// The store took the request and the query failed.
    Query(rusqlite::Error),
    /// The store could not be opened.
    Open(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Open(e) => write!(f, "{e}"),
            StoreError::Busy => write!(f, "the store queue is full"),
            StoreError::Stopped => write!(f, "the store is not running"),
            StoreError::Query(e) => write!(f, "store query failed: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

/// The store thread's loop: answer each request in arrival order until
/// told to close or every handle is gone.
fn serve(mut store: RegistryStore, keypair: &Keypair, mut rx: mpsc::Receiver<Command>) {
    let relay_peer_id = keypair.public().to_peer_id().to_string();
    while let Some(command) = rx.blocking_recv() {
        match command {
            Command::Receipt { claim, reply } => {
                let _ = reply.send(store.handle_receipt(keypair, &relay_peer_id, &claim));
            }
            Command::Lookup { username, reply } => {
                let _ = reply.send(store.lookup_username(&username));
            }
            Command::Mirror(record) => store.save_kad_record(&record, unix_now()),
            Command::LoadMirror { reply } => {
                let _ = reply.send(store.load_kad_records(unix_now()));
            }
            Command::PruneExpired => {
                let n = store.prune_expired(unix_now());
                if n > 0 {
                    log::debug!("Pruned {n} expired DHT records from the mirror");
                }
            }
            Command::ReceiptCount { reply } => {
                let _ = reply.send(store.receipt_count());
            }
            Command::Close { reply } => {
                drop(store);
                let _ = reply.send(());
                return;
            }
        }
    }
}

/// A cheap, cloneable handle to the store thread. Every SQLite call runs on
/// that thread, in the order requests arrive.
#[derive(Clone)]
pub(crate) struct StoreHandle {
    tx: mpsc::Sender<Command>,
}

impl StoreHandle {
    /// Open the store under `data_dir` on a dedicated thread, its mirror
    /// capped at `max_records` records of at most `max_value_bytes`, and
    /// return a handle once it is open. Opening (creating the directory,
    /// switching to WAL, checking the schema) runs on that thread too, so a
    /// slow or locked database never holds up a runtime worker. `keypair`
    /// countersigns receipts there. The thread stops on
    /// [`StoreHandle::close`] or when every handle is dropped.
    pub(crate) async fn open(
        data_dir: PathBuf,
        max_records: usize,
        max_value_bytes: usize,
        keypair: Keypair,
    ) -> Result<Self, StoreError> {
        let (tx, rx) = mpsc::channel(QUEUE_CAPACITY);
        let (opened_tx, opened_rx) = oneshot::channel();
        std::thread::Builder::new()
            .name("relay-store".to_string())
            .spawn(move || match RegistryStore::open(&data_dir) {
                Ok(store) => {
                    let _ = opened_tx.send(Ok(()));
                    serve(
                        store.with_kad_caps(max_records, max_value_bytes),
                        &keypair,
                        rx,
                    );
                }
                Err(e) => {
                    let _ = opened_tx.send(Err(e));
                }
            })
            .map_err(|e| StoreError::Open(format!("spawn store thread: {e}")))?;
        opened_rx
            .await
            .map_err(|_| StoreError::Stopped)?
            .map_err(StoreError::Open)?;
        Ok(StoreHandle { tx })
    }

    /// Queue a receipt request without waiting. The returned receiver
    /// yields the response once the store thread has handled it.
    pub(crate) fn request_receipt(
        &self,
        claim: UsernameClaim,
    ) -> Result<oneshot::Receiver<ReceiptResponse>, StoreError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .try_send(Command::Receipt {
                claim: Box::new(claim),
                reply,
            })
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => StoreError::Busy,
                mpsc::error::TrySendError::Closed(_) => StoreError::Stopped,
            })?;
        Ok(rx)
    }

    /// Queue a record for the mirror without waiting. `false` if the queue
    /// was full and the write was dropped.
    pub(crate) fn mirror(&self, record: MirroredRecord) -> bool {
        self.tx.try_send(Command::Mirror(record)).is_ok()
    }

    /// Queue a prune of expired mirror rows without waiting.
    pub(crate) fn prune_expired(&self) {
        let _ = self.tx.try_send(Command::PruneExpired);
    }

    pub(crate) async fn lookup_username(
        &self,
        username: String,
    ) -> Result<Option<(String, i64)>, StoreError> {
        self.ask(|reply| Command::Lookup { username, reply })
            .await?
            .map_err(StoreError::Query)
    }

    pub(crate) async fn load_kad_records(&self) -> Result<Vec<MirroredRecord>, StoreError> {
        self.ask(|reply| Command::LoadMirror { reply }).await
    }

    pub(crate) async fn receipt_count(&self) -> Result<i64, StoreError> {
        self.ask(|reply| Command::ReceiptCount { reply }).await
    }

    /// Finish every request queued so far, close the database and stop the
    /// thread.
    pub(crate) async fn close(&self) {
        let _ = self.ask(|reply| Command::Close { reply }).await;
    }

    async fn ask<T>(
        &self,
        command: impl FnOnce(oneshot::Sender<T>) -> Command,
    ) -> Result<T, StoreError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(command(reply))
            .await
            .map_err(|_| StoreError::Stopped)?;
        rx.await.map_err(|_| StoreError::Stopped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::username_reg::{
        canonical_claim_bytes, canonical_release_bytes, Release, MAX_DID_KEY_LEN,
    };
    use ed25519_dalek::{Signer, SigningKey};

    fn make_claim(seed: u8, username: &str, claimed_at: i64) -> UsernameClaim {
        let key = SigningKey::from_bytes(&[seed; 32]);
        // did:key encoding: z + base58(0xed 0x01 + pubkey)
        let mut bytes = vec![0xed, 0x01];
        bytes.extend_from_slice(key.verifying_key().as_bytes());
        let did = format!("did:key:z{}", bs58::encode(bytes).into_string());
        let sig = key.sign(&canonical_claim_bytes(username, &did, claimed_at));
        UsernameClaim {
            version: 1,
            username: username.to_string(),
            did,
            claimed_at,
            sig: hex::encode(sig.to_bytes()),
            receipt: None,
            anchor: None,
            release: None,
        }
    }

    fn store() -> (RegistryStore, libp2p::identity::Keypair, String) {
        let dir = std::env::temp_dir().join(format!("relay-test-{}", rand::random::<u64>()));
        let store = RegistryStore::open(&dir).unwrap();
        let kp = libp2p::identity::Keypair::generate_ed25519();
        let pid = kp.public().to_peer_id().to_string();
        (store, kp, pid)
    }

    #[test]
    fn grants_first_claim_and_verifies() {
        let (mut s, kp, pid) = store();
        let claim = make_claim(1, "ada_99", 1000);
        match s.handle_receipt(&kp, &pid, &claim) {
            ReceiptResponse::Granted(r) => {
                assert_eq!(r.relay_peer_id, pid);
                // Receipt signature verifies with the relay pubkey.
                let bytes = canonical_receipt_bytes(&claim.sig, r.received_at, &pid);
                assert!(kp.public().verify(&bytes, &hex::decode(r.sig).unwrap()));
            }
            other => panic!("expected Granted, got {other:?}"),
        }
    }

    #[test]
    fn refuses_second_did_same_username() {
        let (mut s, kp, pid) = store();
        let first = make_claim(1, "ada_99", 1000);
        let second = make_claim(2, "ada_99", 500); // earlier self-asserted time!
        assert!(matches!(
            s.handle_receipt(&kp, &pid, &first),
            ReceiptResponse::Granted(_)
        ));
        match s.handle_receipt(&kp, &pid, &second) {
            ReceiptResponse::Refused { existing_did, .. } => {
                assert_eq!(existing_did, Some(first.did));
            }
            other => panic!("expected Refused, got {other:?}"),
        }
    }

    #[test]
    fn same_did_refresh_keeps_original_time() {
        let (mut s, kp, pid) = store();
        let claim = make_claim(1, "ada_99", 1000);
        let r1 = match s.handle_receipt(&kp, &pid, &claim) {
            ReceiptResponse::Granted(r) => r,
            other => panic!("{other:?}"),
        };
        let r2 = match s.handle_receipt(&kp, &pid, &claim) {
            ReceiptResponse::Granted(r) => r,
            other => panic!("{other:?}"),
        };
        assert_eq!(r1.received_at, r2.received_at);
        assert_eq!(r1.sig, r2.sig);
    }

    #[test]
    fn an_ed25519_did_key_fits_the_length_bound() {
        // The bound must never refuse a real key. All-0xff key bytes give the
        // longest base58 encoding a 34-byte payload can have.
        let mut bytes = vec![0xed, 0x01];
        bytes.extend_from_slice(&[0xff; 32]);
        let did = format!("did:key:z{}", bs58::encode(bytes).into_string());
        assert!(did.len() <= MAX_DID_KEY_LEN, "{} > bound", did.len());
        let claim = make_claim(1, "ada_99", 1000);
        assert!(claim.did.len() <= MAX_DID_KEY_LEN);
    }

    #[test]
    fn an_oversized_did_is_refused_before_decoding() {
        // Base58 decoding is quadratic: a 200k-character DID takes seconds to
        // decode (far longer in a debug build). Refusing it has to be
        // immediate, so the elapsed-time bound below separates the two paths
        // by orders of magnitude rather than measuring anything fine-grained.
        let (mut s, kp, pid) = store();
        let mut claim = make_claim(1, "ada_99", 1000);
        claim.did = format!("did:key:z{}", "2".repeat(200_000));
        let started = std::time::Instant::now();
        let response = s.handle_receipt(&kp, &pid, &claim);
        let elapsed = started.elapsed();
        match response {
            ReceiptResponse::Refused { reason, .. } => {
                assert!(reason.starts_with("invalid claim"), "{reason}");
            }
            other => panic!("expected Refused, got {other:?}"),
        }
        assert!(
            elapsed < std::time::Duration::from_millis(100),
            "oversized DID took {elapsed:?} to refuse"
        );
        // The release path decodes the same DID and must be bounded too.
        assert!(!release_valid(&UsernameClaim {
            release: Some(Release {
                released_at: 0,
                sig: "00".repeat(64),
            }),
            ..claim
        }));
    }

    #[test]
    fn rejects_forged_claim() {
        let (mut s, kp, pid) = store();
        let mut claim = make_claim(1, "ada_99", 1000);
        claim.username = "stolen".to_string();
        assert!(matches!(
            s.handle_receipt(&kp, &pid, &claim),
            ReceiptResponse::Refused { .. }
        ));
    }

    #[test]
    fn release_frees_name_after_grace() {
        let (mut s, kp, pid) = store();
        let key1 = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let mut released = make_claim(1, "ada_99", 1000);
        assert!(matches!(
            s.handle_receipt(&kp, &pid, &released),
            ReceiptResponse::Granted(_)
        ));
        // Owner tombstones the name (released_at far in the past so
        // the grace window is already elapsed for the test).
        let rel_at = 0i64;
        let sig = key1.sign(&canonical_release_bytes(
            &released.username,
            &released.did,
            rel_at,
        ));
        released.release = Some(Release {
            released_at: rel_at,
            sig: hex::encode(sig.to_bytes()),
        });
        assert!(release_valid(&released));
        assert!(matches!(
            s.handle_receipt(&kp, &pid, &released),
            ReceiptResponse::Granted(_)
        ));
        // Grace elapsed (released_at=0) → lookup hides it, and a new
        // DID can claim the name.
        assert!(s.lookup_username("ada_99").unwrap().is_none());
        let newcomer = make_claim(2, "ada_99", 2000);
        match s.handle_receipt(&kp, &pid, &newcomer) {
            ReceiptResponse::Granted(_) => {}
            other => panic!("expected Granted for newcomer, got {other:?}"),
        }
        assert_eq!(
            s.lookup_username("ada_99").unwrap().map(|(did, _)| did),
            Some(newcomer.did)
        );
    }

    #[test]
    fn a_release_dated_near_the_end_of_time_never_frees_the_name() {
        // `released_at` is whatever the owner signed. Adding the grace
        // window to a value near i64::MAX must not overflow: in a debug
        // build that panics the store thread, and in a release build it
        // wraps negative and frees the name at once.
        let (mut s, kp, pid) = store();
        let key1 = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let mut claim = make_claim(1, "ada_99", 1000);
        assert!(matches!(
            s.handle_receipt(&kp, &pid, &claim),
            ReceiptResponse::Granted(_)
        ));
        let rel_at = i64::MAX - 10;
        let sig = key1.sign(&canonical_release_bytes(
            &claim.username,
            &claim.did,
            rel_at,
        ));
        claim.release = Some(Release {
            released_at: rel_at,
            sig: hex::encode(sig.to_bytes()),
        });
        assert!(matches!(
            s.handle_receipt(&kp, &pid, &claim),
            ReceiptResponse::Granted(_)
        ));

        assert!(s.lookup_username("ada_99").unwrap().is_some());
        let other = make_claim(2, "ada_99", 2000);
        assert!(matches!(
            s.handle_receipt(&kp, &pid, &other),
            ReceiptResponse::Refused { .. }
        ));
    }

    #[test]
    fn a_lookup_that_fails_is_an_error_not_a_free_name() {
        let (s, _, _) = store();
        s.conn.execute_batch("DROP TABLE receipts").unwrap();
        assert!(s.lookup_username("ada_99").is_err());
    }

    #[test]
    fn reclaim_within_grace_undoes_release() {
        let (mut s, kp, pid) = store();
        let key1 = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let mut claim = make_claim(1, "ada_99", 1000);
        assert!(matches!(
            s.handle_receipt(&kp, &pid, &claim),
            ReceiptResponse::Granted(_)
        ));
        // Release now (within grace), then re-claim without release.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let sig = key1.sign(&canonical_release_bytes(&claim.username, &claim.did, now));
        claim.release = Some(Release {
            released_at: now,
            sig: hex::encode(sig.to_bytes()),
        });
        let _ = s.handle_receipt(&kp, &pid, &claim);
        // Still within grace: visible, and another DID is refused.
        assert!(s.lookup_username("ada_99").unwrap().is_some());
        let other = make_claim(2, "ada_99", 2000);
        assert!(matches!(
            s.handle_receipt(&kp, &pid, &other),
            ReceiptResponse::Refused { .. }
        ));
        // Owner re-claims (no release) → release cleared.
        claim.release = None;
        let _ = s.handle_receipt(&kp, &pid, &claim);
        let rel: Option<i64> = s
            .conn
            .query_row(
                "SELECT released_at FROM receipts WHERE username = 'ada_99'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(rel.is_none());
    }

    /// A record that expires at `expires_at` (Unix seconds), or never.
    fn rec(key: &str, expires_at: Option<i64>) -> MirroredRecord {
        MirroredRecord {
            key: key.as_bytes().to_vec(),
            value: b"v".to_vec(),
            publisher: None,
            expires_at,
        }
    }

    fn keys(s: &RegistryStore, now: i64) -> Vec<String> {
        let mut keys: Vec<String> = s
            .load_kad_records(now)
            .into_iter()
            .map(|r| String::from_utf8(r.key).unwrap())
            .collect();
        keys.sort();
        keys
    }

    fn temp_dir() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("relay-test-{}", rand::random::<u64>()))
    }

    const NOW: i64 = 1_000_000;

    #[test]
    fn kad_record_mirror_round_trips() {
        let (mut s, _, _) = store();
        let publisher = libp2p::PeerId::random().to_bytes();
        let first = MirroredRecord {
            key: b"k1".to_vec(),
            value: b"v1".to_vec(),
            publisher: Some(publisher.clone()),
            expires_at: Some(NOW + 100),
        };
        let updated = MirroredRecord {
            value: b"v2".to_vec(),
            expires_at: Some(NOW + 200),
            ..first.clone()
        };
        s.save_kad_record(&first, NOW);
        s.save_kad_record(&updated, NOW); // upsert
        s.save_kad_record(&rec("k2", None), NOW);
        let mut records = s.load_kad_records(NOW);
        records.sort_by(|a, b| a.key.cmp(&b.key));
        assert_eq!(records, vec![updated, rec("k2", None)]);
    }

    #[test]
    fn the_mirror_holds_the_configured_caps() {
        // The record cap and value size are configuration; the mirror must
        // follow them, not the defaults.
        let (s, _, _) = store();
        let mut s = s.with_kad_caps(2, 8);
        s.save_kad_record(&rec("k1", None), NOW);
        s.save_kad_record(&rec("k2", None), NOW);
        s.save_kad_record(&rec("k3", None), NOW);
        let mut big = rec("big", None);
        big.value = vec![0u8; 9];
        s.save_kad_record(&big, NOW);
        assert_eq!(keys(&s, NOW), ["k2", "k3"]);
    }

    #[test]
    fn eviction_takes_expired_then_soonest_expiring_then_oldest() {
        let (s, _, _) = store();
        let mut s = s.with_kad_caps(4, 64);
        // Inserted oldest first. "early" is the oldest and expires latest,
        // so insertion-order eviction would drop it first.
        s.save_kad_record(&rec("early", Some(NOW + 900)), NOW);
        s.save_kad_record(&rec("forever-a", None), NOW);
        s.save_kad_record(&rec("soon", Some(NOW + 100)), NOW);
        s.save_kad_record(&rec("lapsing", Some(NOW + 10)), NOW);
        let later = NOW + 50; // "lapsing" has now expired

        s.save_kad_record(&rec("forever-b", None), later);
        assert_eq!(
            keys(&s, NOW),
            ["early", "forever-a", "forever-b", "soon"],
            "the expired record goes first"
        );

        s.save_kad_record(&rec("forever-c", None), later);
        assert_eq!(
            keys(&s, later),
            ["early", "forever-a", "forever-b", "forever-c"],
            "then the soonest-expiring"
        );

        s.save_kad_record(&rec("forever-d", None), later);
        assert_eq!(
            keys(&s, later),
            ["forever-a", "forever-b", "forever-c", "forever-d"],
            "a record that never expires outlives one that does"
        );

        s.save_kad_record(&rec("forever-e", None), later);
        assert_eq!(
            keys(&s, later),
            ["forever-b", "forever-c", "forever-d", "forever-e"],
            "among records that never expire, the oldest goes"
        );
    }

    #[test]
    fn the_cached_count_follows_inserts_upserts_evictions_and_prunes() {
        let dir = temp_dir();
        let mut s = RegistryStore::open(&dir).unwrap().with_kad_caps(3, 64);
        assert_eq!(s.mirror_count(), 0);
        s.save_kad_record(&rec("a", Some(NOW + 10)), NOW);
        s.save_kad_record(&rec("b", Some(NOW + 20)), NOW);
        s.save_kad_record(&rec("a", Some(NOW + 30)), NOW); // upsert
        assert_eq!(s.mirror_count(), 2);
        s.save_kad_record(&rec("c", None), NOW);
        s.save_kad_record(&rec("d", None), NOW); // evicts one
        assert_eq!(s.mirror_count(), 3);
        assert_eq!(s.prune_expired(NOW + 30), 1, "\"a\" lapsed at +30");
        assert_eq!(s.mirror_count(), 2);
        drop(s);

        // Reopening counts the table once.
        let s = RegistryStore::open(&dir).unwrap();
        assert_eq!(s.mirror_count(), 2);
        assert_eq!(keys(&s, NOW + 30), ["c", "d"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expired_rows_are_skipped_on_load_and_never_written() {
        let (mut s, _, _) = store();
        s.save_kad_record(&rec("live", Some(NOW + 60)), NOW);
        s.save_kad_record(&rec("lapsing", Some(NOW + 5)), NOW);
        s.save_kad_record(&rec("stale", Some(NOW - 1)), NOW);
        assert_eq!(
            s.mirror_count(),
            2,
            "an already-expired record is not written"
        );
        assert_eq!(keys(&s, NOW + 5), ["live"]);
    }

    #[test]
    fn a_record_keeps_its_expiry_and_publisher_through_the_mirror() {
        let publisher = libp2p::PeerId::random();
        let record = kad::Record {
            key: kad::RecordKey::new(&b"k"),
            value: b"v".to_vec(),
            publisher: Some(publisher),
            expires: Some(Instant::now() + Duration::from_secs(3600)),
        };
        let back = MirroredRecord::from_kad(&record).unwrap().into_kad();
        assert_eq!(back.key, record.key);
        assert_eq!(back.publisher, Some(publisher));
        let left = back
            .expires
            .unwrap()
            .duration_since(Instant::now())
            .as_secs();
        assert!((3598..=3600).contains(&left), "{left}s left");

        let expired = kad::Record {
            expires: Some(Instant::now() - Duration::from_secs(1)),
            ..record
        };
        assert!(MirroredRecord::from_kad(&expired).is_none());
    }

    #[test]
    fn the_store_opens_in_wal_mode_with_normal_sync() {
        let (s, _, _) = store();
        let mode: String = s
            .conn
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .unwrap();
        let sync: i64 = s
            .conn
            .pragma_query_value(None, "synchronous", |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        assert_eq!(sync, 1, "NORMAL");
    }

    #[test]
    fn a_store_from_an_older_binary_is_recreated() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let old = Connection::open(dir.join("username_registry.db")).unwrap();
        old.execute_batch(
            "CREATE TABLE receipts (username TEXT PRIMARY KEY, did TEXT NOT NULL,
                 claim_sig TEXT NOT NULL, received_at INTEGER NOT NULL,
                 receipt_sig TEXT NOT NULL);
             CREATE TABLE kad_records (key BLOB PRIMARY KEY, value BLOB NOT NULL);
             INSERT INTO kad_records VALUES (x'6f6c64', x'00');",
        )
        .unwrap();
        drop(old);

        let mut s = RegistryStore::open(&dir).unwrap();
        assert_eq!(s.mirror_count(), 0);
        s.save_kad_record(&rec("new", Some(NOW + 1)), NOW);
        assert_eq!(keys(&s, NOW), ["new"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
