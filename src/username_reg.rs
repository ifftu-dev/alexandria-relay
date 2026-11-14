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
//! Receipts persist in [`crate::store::RegistryStore`], which also mirrors
//! Kademlia records so the DHT survives relay restarts (the kad store itself
//! is in-memory).

use serde::{Deserialize, Serialize};

pub const PROTOCOL: &str = "/alexandria/username-reg/1.0";

/// Grace window before a released username frees up (mirrors the main
/// app's `RELEASE_GRACE_SECS`).
pub const RELEASE_GRACE_SECS: i64 = 30 * 24 * 3600;

/// When a name released at `released_at` frees up. The release time is
/// owner-signed and unchecked, so the sum saturates: a release dated near
/// the end of time keeps the name held rather than wrapping into the past.
pub(crate) fn release_frees_at(released_at: i64) -> i64 {
    released_at.saturating_add(RELEASE_GRACE_SECS)
}

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

impl ReceiptResponse {
    /// A refusal that names no existing holder.
    pub fn refused(reason: impl Into<String>) -> Self {
        ReceiptResponse::Refused {
            reason: reason.into(),
            existing_did: None,
            existing_received_at: None,
        }
    }
}

// ── Claim verification (did:key → ed25519) ─────────────────────────

/// Longest `did` string accepted before any decoding.
///
/// An Ed25519 `did:key` is fixed-width: the 8-byte `did:key:` prefix, the
/// multibase `z`, and base58btc of 34 bytes (multicodec `0xed 0x01` plus the
/// 32-byte key), which is at most 47 characters — 56 in total. The bound
/// leaves a little slack and exists because base58 decoding is quadratic in
/// its input: without it, one receipt request carrying a DID near the codec's
/// size limit pins the swarm's event loop for seconds, and request budgets are
/// keyed on PeerIds, which cost nothing to mint.
pub const MAX_DID_KEY_LEN: usize = 64;

/// Extract the Ed25519 verifying key from a `did:key:z6Mk…` string.
/// Multibase 'z' (base58btc) over multicodec 0xed 0x01 + 32 key bytes.
fn did_key_to_verifying_key(did: &str) -> Result<ed25519_dalek::VerifyingKey, String> {
    if did.len() > MAX_DID_KEY_LEN {
        return Err("did too long for an ed25519 did:key".to_string());
    }
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

pub(crate) fn canonical_release_bytes(username: &str, did: &str, released_at: i64) -> Vec<u8> {
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

pub(crate) fn canonical_claim_bytes(username: &str, did: &str, claimed_at: i64) -> Vec<u8> {
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

/// Countersign `bytes` with the relay key, or `None` if signing failed.
///
/// Returning `None` rather than an empty signature is the point. The previous
/// `keypair.sign(..).unwrap_or_default()` hex-encoded an empty `Vec` to `""`
/// on failure and then stored and returned it inside a `Granted` response — a
/// receipt that reads as granted and carries no signature at all. Any client
/// that treats `Granted` as the trust signal, rather than verifying the
/// countersignature, would have accepted it.
pub(crate) fn countersign(keypair: &libp2p::identity::Keypair, bytes: &[u8]) -> Option<String> {
    match keypair.sign(bytes) {
        Ok(sig) if !sig.is_empty() => Some(hex::encode(sig)),
        Ok(_) => {
            log::error!("relay countersign produced an empty signature — refusing the receipt");
            None
        }
        Err(e) => {
            log::error!("relay countersign failed: {e}");
            None
        }
    }
}

/// Bytes the relay countersigns. Covers the owner sig (binding the
/// receipt to this exact claim), the first-seen time, and the relay id.
pub fn canonical_receipt_bytes(claim_sig: &str, received_at: i64, relay_peer_id: &str) -> Vec<u8> {
    format!("alexandria-username-receipt-v1|{claim_sig}|{received_at}|{relay_peer_id}").into_bytes()
}
