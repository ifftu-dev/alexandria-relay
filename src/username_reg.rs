//! Username-claim receipts — `/alexandria/username-reg/1.0`.
//!
//! The relay countersigns username claims with a first-seen timestamp,
//! giving free-tier users a trusted ordering signal (tier 1) between
//! bare self-asserted claims (tier 0) and Cardano-anchored claims
//! (tier 2). Wire format matches `domain::username_claim` in the main
//! app — the repos share no code, only the JSON/CBOR shape.
//!
//! First-seen semantics:
//!   - First claim ever seen for a username → receipt granted, row
//!     persisted.
//!   - Same DID again (refresh/republish) → the ORIGINAL receipt is
//!     re-issued; refreshing never resets priority.
//!   - Different DID → refused, with the existing holder's first-seen
//!     time so the client can explain the conflict.
//!
//! The store also mirrors Kademlia records so the DHT survives relay
//! restarts (the kad store itself is in-memory).

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

pub const PROTOCOL: &str = "/alexandria/username-reg/1.0";

/// Grace window before a released username frees up (mirrors the main
/// app's `RELEASE_GRACE_SECS`).
pub const RELEASE_GRACE_SECS: i64 = 30 * 24 * 3600;

// ── Wire types (mirror the main app's domain::username_claim) ──────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RelayReceipt {
    pub relay_peer_id: String,
    pub received_at: i64,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Release {
    pub released_at: i64,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CardanoAnchor {
    pub tx_hash: String,
    pub slot: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UsernameClaim {
    pub version: u32,
    pub username: String,
    pub did: String,
    pub claimed_at: i64,
    pub sig: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<RelayReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<CardanoAnchor>,
    /// Owner-signed tombstone — frees the name after the grace window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release: Option<Release>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptRequest {
    pub claim: UsernameClaim,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReceiptResponse {
    Granted(RelayReceipt),
    Refused {
        reason: String,
        existing_did: Option<String>,
        existing_received_at: Option<i64>,
    },
}

// ── Claim verification (did:key → ed25519) ─────────────────────────

/// Extract the Ed25519 verifying key from a `did:key:z6Mk…` string.
/// Multibase 'z' (base58btc) over multicodec 0xed 0x01 + 32 key bytes.
fn did_key_to_verifying_key(did: &str) -> Result<ed25519_dalek::VerifyingKey, String> {
    let body = did
        .strip_prefix("did:key:z")
        .ok_or("not a did:key with base58btc multibase")?;
    let bytes = bs58::decode(body)
        .into_vec()
        .map_err(|e| format!("bad base58: {e}"))?;
    if bytes.len() != 34 || bytes[0] != 0xed || bytes[1] != 0x01 {
        return Err("not an ed25519 did:key".to_string());
    }
    let key: [u8; 32] = bytes[2..].try_into().map_err(|_| "bad key length")?;
    ed25519_dalek::VerifyingKey::from_bytes(&key).map_err(|e| format!("bad key: {e}"))
}

fn canonical_release_bytes(username: &str, did: &str, released_at: i64) -> Vec<u8> {
    format!("alexandria-username-release-v1|{username}|{did}|{released_at}").into_bytes()
}

/// Verify a claim's release tombstone against the claim's own DID key.
pub fn release_valid(claim: &UsernameClaim) -> bool {
    let Some(ref rel) = claim.release else {
        return false;
    };
    let Ok(vk) = did_key_to_verifying_key(&claim.did) else {
        return false;
    };
    let Ok(bytes) = hex::decode(&rel.sig) else {
        return false;
    };
    let Ok(sig_bytes) = <[u8; 64]>::try_from(bytes) else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    vk.verify_strict(
        &canonical_release_bytes(&claim.username, &claim.did, rel.released_at),
        &sig,
    )
    .is_ok()
}

fn canonical_claim_bytes(username: &str, did: &str, claimed_at: i64) -> Vec<u8> {
    format!("alexandria-username-claim-v1|{username}|{did}|{claimed_at}").into_bytes()
}

/// Verify the claim's owner signature. Same canonical bytes as the
/// main app.
pub fn verify_claim(claim: &UsernameClaim) -> Result<(), String> {
    if claim.version != 1 {
        return Err(format!("unsupported claim version {}", claim.version));
    }
    if claim.username.len() < 3
        || claim.username.len() > 32
        || !claim
            .username
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return Err("invalid username".to_string());
    }
    let vk = did_key_to_verifying_key(&claim.did)?;
    let sig_bytes: [u8; 64] = hex::decode(&claim.sig)
        .map_err(|e| format!("bad sig hex: {e}"))?
        .try_into()
        .map_err(|_| "bad sig length".to_string())?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    vk.verify_strict(
        &canonical_claim_bytes(&claim.username, &claim.did, claim.claimed_at),
        &sig,
    )
    .map_err(|_| "signature verification failed".to_string())
}

/// Bytes the relay countersigns. Covers the owner sig (binding the
/// receipt to this exact claim), the first-seen time, and the relay id.
pub fn canonical_receipt_bytes(claim_sig: &str, received_at: i64, relay_peer_id: &str) -> Vec<u8> {
    format!("alexandria-username-receipt-v1|{claim_sig}|{received_at}|{relay_peer_id}").into_bytes()
}

// ── Persistent store ────────────────────────────────────────────────

pub struct RegistryStore {
    conn: Connection,
}

impl RegistryStore {
    pub fn open(data_dir: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(data_dir).map_err(|e| format!("create data dir: {e}"))?;
        let conn = Connection::open(data_dir.join("username_registry.db"))
            .map_err(|e| format!("open registry db: {e}"))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS receipts (
                 username    TEXT PRIMARY KEY,
                 did         TEXT NOT NULL,
                 claim_sig   TEXT NOT NULL,
                 received_at INTEGER NOT NULL,
                 receipt_sig TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS kad_records (
                 key   BLOB PRIMARY KEY,
                 value BLOB NOT NULL
             );",
        )
        .map_err(|e| format!("init registry schema: {e}"))?;
        // Older stores predate releases — guarded ALTER.
        let _ = conn.execute("ALTER TABLE receipts ADD COLUMN released_at INTEGER", []);
        Ok(RegistryStore { conn })
    }

    /// Handle a receipt request: verify, apply first-seen semantics,
    /// countersign with the relay key.
    pub fn handle_receipt(
        &mut self,
        keypair: &libp2p::identity::Keypair,
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

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

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
                if did != claim.did && now >= rel + RELEASE_GRACE_SECS {
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
                    let sig = hex::encode(keypair.sign(&bytes).unwrap_or_default());
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

        let received_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let bytes = canonical_receipt_bytes(&claim.sig, received_at, relay_peer_id);
        let sig = hex::encode(keypair.sign(&bytes).unwrap_or_default());

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

    /// Mirror a kad record for restart persistence.
    pub fn save_kad_record(&self, key: &[u8], value: &[u8]) {
        let _ = self.conn.execute(
            "INSERT INTO kad_records (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            rusqlite::params![key, value],
        );
    }

    /// All mirrored kad records, for warm-loading the MemoryStore at boot.
    pub fn load_kad_records(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let Ok(mut stmt) = self.conn.prepare("SELECT key, value FROM kad_records") else {
            return Vec::new();
        };
        stmt.query_map([], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
        })
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
    }

    pub fn receipt_count(&self) -> i64 {
        self.conn
            .query_row("SELECT COUNT(*) FROM receipts", [], |r| r.get(0))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert!(s.lookup_username("ada_99").is_none());
        let newcomer = make_claim(2, "ada_99", 2000);
        match s.handle_receipt(&kp, &pid, &newcomer) {
            ReceiptResponse::Granted(_) => {}
            other => panic!("expected Granted for newcomer, got {other:?}"),
        }
        assert_eq!(
            s.lookup_username("ada_99").map(|(did, _)| did),
            Some(newcomer.did)
        );
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
        assert!(s.lookup_username("ada_99").is_some());
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

    #[test]
    fn kad_record_mirror_round_trips() {
        let (s, _, _) = store();
        s.save_kad_record(b"k1", b"v1");
        s.save_kad_record(b"k1", b"v2"); // upsert
        s.save_kad_record(b"k2", b"v3");
        let mut records = s.load_kad_records();
        records.sort();
        assert_eq!(
            records,
            vec![
                (b"k1".to_vec(), b"v2".to_vec()),
                (b"k2".to_vec(), b"v3".to_vec())
            ]
        );
    }
}

impl RegistryStore {
    /// Current holder of a username (receipted claims only), for the
    /// HTTP availability endpoint.
    pub fn lookup_username(&self, username: &str) -> Option<(String, i64)> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.conn
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
            .ok()
            .filter(|(_, _, rel)| match rel {
                Some(rel_at) => now < rel_at + RELEASE_GRACE_SECS,
                None => true,
            })
            .map(|(did, received_at, _)| (did, received_at))
    }
}
