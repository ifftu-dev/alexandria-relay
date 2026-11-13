//! Relay configuration: limits, the command-line interface and the identity.

use std::time::Duration;

use clap::Parser;
use libp2p::identity::Keypair;
use zeroize::Zeroizing;

// ── Configuration Constants ──────────────────────────────────────────

/// Maximum total concurrent connections the relay will accept.
pub(crate) const MAX_CONNECTIONS: usize = 1024;

/// Maximum concurrent connections from a single peer.
/// Allows TCP+QUIC × inbound/outbound × small reconnect overlap.
pub(crate) const MAX_CONNECTIONS_PER_PEER: u32 = 8;

/// Maximum concurrent connections from a single IP address.
/// Households / shared NATs commonly carry 5-10 simultaneous peers.
pub(crate) const MAX_CONNECTIONS_PER_IP: usize = 32;

/// Maximum incoming connections still in the transport handshake.
///
/// The established-connection limits above apply only after Noise and the
/// muxer have been negotiated, so without this a flood of half-open
/// connections holds handshake state with no ceiling at all.
pub(crate) const MAX_PENDING_INCOMING: u32 = 256;

/// Largest username-receipt request the codec will read.
///
/// A claim is a few hundred bytes: a username of at most 32 characters, a
/// fixed-width `did:key`, a 128-character signature, and the app's receipts
/// list (about 220 bytes per relay that has already countersigned). 8 KiB
/// leaves room for a few dozen relays. The codec's default is 1 MiB, which
/// the swarm would otherwise buffer and deserialize for every request.
pub(crate) const USERNAME_REQUEST_MAX_BYTES: u64 = 8 * 1024;

/// Maximum new connections from a single IP per rate window.
pub(crate) const MAX_NEW_CONNS_PER_IP_PER_WINDOW: usize = 32;

/// Rate window duration for IP-level connection rate limiting.
pub(crate) const IP_RATE_WINDOW: Duration = Duration::from_secs(60);

/// Maximum username-receipt requests one peer may make per
/// [`USERNAME_RATE_WINDOW`].
///
/// Generating a fresh `did:key` and a valid claim signature is free and
/// offline, so without this a single connection can receipt the entire viable
/// `[a-z0-9_]{3,32}` namespace — and because only the owner can release a
/// name, squatted names never free up. A real client claims a username once
/// and refreshes it rarely, so this is far above legitimate use.
pub(crate) const USERNAME_RATE_LIMIT: usize = 5;

/// Rate window for username-receipt requests.
pub(crate) const USERNAME_RATE_WINDOW: Duration = Duration::from_secs(60);

/// Maximum `/username/:name` lookups one client IP may make per
/// [`USERNAME_LOOKUP_WINDOW`].
///
/// The lookup is public by design — clients resolve names against it — but
/// it was completely unthrottled, unlike the p2p receipt path. The namespace
/// is `[a-z0-9_]{3,32}`, so with no limit the whole registry (username → DID →
/// first-seen time, for every user) is enumerable for the cost of a loop, and
/// every hit is a SQLite read on the same listener the relay's real work
/// shares. A person checking a handful of names never comes near this.
pub(crate) const USERNAME_LOOKUP_LIMIT: usize = 30;

/// Rate window for `/username/:name` lookups.
pub(crate) const USERNAME_LOOKUP_WINDOW: Duration = Duration::from_secs(60);

/// Cap on tracked client IPs for the lookup limiter, so the map cannot
/// itself become the memory leak.
pub(crate) const USERNAME_LOOKUP_MAX_TRACKED: usize = 10_000;

/// How long an idle connection stays open before being reaped.
pub(crate) const IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(600); // 10 min

/// Kademlia query timeout.
pub(crate) const KAD_QUERY_TIMEOUT: Duration = Duration::from_secs(60);

/// Kademlia replication factor (k-buckets).
pub(crate) const KAD_REPLICATION_FACTOR: usize = 20;

/// Maximum number of records in the Kademlia memory store.
/// 16k × 64 KB ≈ 1 GB worst case — fits a 1 GB Fly machine with headroom.
pub(crate) const KAD_MAX_RECORDS: usize = 16_384;

/// Maximum size of a single Kademlia record value.
pub(crate) const KAD_MAX_RECORD_SIZE: usize = 65_536; // 64 KB

/// Relay: max number of active circuit reservations.
pub(crate) const RELAY_MAX_RESERVATIONS: usize = 1024;

/// Relay: max number of active circuits (relayed connections).
pub(crate) const RELAY_MAX_CIRCUITS: usize = 2048;

/// Relay: max number of reservation requests per peer.
pub(crate) const RELAY_MAX_RESERVATIONS_PER_PEER: usize = 16;

/// Relay: max number of circuits per peer.
/// Was 16 — observer + crawlers fan-out enough simultaneous circuit dials
/// to saturate that limit, causing cascade `circuits_denied` (saw 7910:47
/// denied:accepted ratio in production). 128 leaves headroom for active
/// observers without exposing the relay to a single peer monopolising it.
pub(crate) const RELAY_MAX_CIRCUITS_PER_PEER: usize = 128;

/// Relay: per-circuit bandwidth limit (bytes).
/// 2 MB was too tight for VC bundles + content sync. 128 MB still caps
/// abuse but won't truncate normal payloads.
pub(crate) const RELAY_MAX_CIRCUIT_BYTES: u64 = 128 * 1024 * 1024; // 128 MB

/// Relay: per-circuit duration limit.
/// 120 s caused gossipsub mesh churn — every 2 min all circuits closed
/// and re-dialed. 15 min lets meshes stabilise; DCUtR (client-side) should
/// upgrade most circuits to direct connections well within this window.
pub(crate) const RELAY_MAX_CIRCUIT_DURATION: Duration = Duration::from_secs(900); // 15 min

/// Relay: how long a reservation is valid.
pub(crate) const RELAY_RESERVATION_DURATION: Duration = Duration::from_secs(3600); // 1 hour

/// Maximum number of addresses to accept per peer via Identify.
pub(crate) const MAX_ADDRS_PER_PEER: usize = 16;

/// How often to log health status.
pub(crate) const HEALTH_LOG_INTERVAL: Duration = Duration::from_secs(300); // 5 min

// ── CLI ──────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "alexandria-relay",
    about = "Alexandria P2P relay + bootstrap node",
    version
)]
pub struct Args {
    /// TCP listen port
    #[arg(long, default_value = "4001")]
    pub port: u16,

    /// QUIC (UDP) listen port
    #[arg(long, default_value = "4001")]
    pub quic_port: u16,

    /// HTTP metrics/health port
    #[arg(long, default_value = "9090")]
    pub metrics_port: u16,

    /// Publicly resolvable hostname this relay is reachable at (e.g.
    /// `alexandria-relay.fly.dev`). Registered as the relay's external
    /// address so reservation responses include a dialable multiaddr.
    /// The hostname is also resolved at startup and the current IPs are
    /// registered, so DNS-blocked clients can reach us by IP without us
    /// hardcoding addresses that go stale on re-provisioning.
    /// Without this, clients receive an empty address list and reject
    /// the reservation with `NoAddressesInReservation`.
    #[arg(long, env = "RELAY_PUBLIC_HOST")]
    pub public_host: Option<String>,

    /// Generate a new keypair seed and exit
    #[arg(long)]
    pub generate_key: bool,

    /// Directory for persistent state (username receipts + mirrored
    /// DHT records). On Fly, point this at a mounted volume.
    #[arg(long, env = "RELAY_DATA_DIR", default_value = "./relay-data")]
    pub data_dir: std::path::PathBuf,
}

// ── Keypair Utilities ────────────────────────────────────────────────

/// Build the relay keypair from a hex seed.
///
/// Every buffer that holds seed material is zeroized when it drops: the
/// decoded bytes and the 32-byte key copy here, and the hex string at the
/// caller. `ed25519_from_bytes` also zeroizes the slice it is given.
pub fn keypair_from_seed(seed_hex: &str) -> Keypair {
    let seed_bytes = Zeroizing::new(hex::decode(seed_hex).expect("RELAY_SEED must be valid hex"));
    assert!(
        seed_bytes.len() >= 32,
        "RELAY_SEED must be at least 32 bytes (64 hex chars)"
    );
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&seed_bytes[..32]);
    Keypair::ed25519_from_bytes(&mut *key).expect("valid ed25519 seed")
}

/// A fresh random seed, hex-encoded.
pub fn generate_seed() -> String {
    let random_bytes: [u8; 32] = rand::random();
    hex::encode(random_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_seed_keypair_is_deterministic() {
        // Zeroizing the seed buffers must not change the derived identity.
        let seed = "11".repeat(32);
        assert_eq!(
            keypair_from_seed(&seed).public().to_peer_id(),
            keypair_from_seed(&seed).public().to_peer_id()
        );
    }
}
