//! Relay configuration: the [`RelayConfig`] that [`crate::start`] takes, the
//! [`Limits`] inside it, and the command-line parser ([`Cli`]) that builds
//! both from flags and `RELAY_*` environment variables.
//!
//! Every default below is the value the relay ran with when these were
//! compile-time constants. Adding a tunable means a field on [`Limits`] (or
//! [`RelayConfig`]), a `DEFAULT_*` constant, a flag on [`Cli`], and a line in
//! [`Cli::into_config`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use clap::Parser;
use libp2p::identity::Keypair;
use zeroize::Zeroizing;

// ── Defaults ─────────────────────────────────────────────────────────

/// Maximum total concurrent connections the relay will accept.
pub const DEFAULT_MAX_CONNECTIONS: u32 = 1024;

/// Maximum concurrent connections from a single peer.
/// Allows TCP+QUIC × inbound/outbound × small reconnect overlap.
pub const DEFAULT_MAX_CONNECTIONS_PER_PEER: u32 = 8;

/// Maximum concurrent connections from a single IP address.
/// Households / shared NATs commonly carry 5-10 simultaneous peers.
pub const DEFAULT_MAX_CONNECTIONS_PER_IP: usize = 32;

/// Maximum incoming connections still in the transport handshake.
///
/// The established-connection limits apply only after Noise and the muxer
/// have been negotiated, so without this a flood of half-open connections
/// holds handshake state with no ceiling at all.
pub const DEFAULT_MAX_PENDING_INCOMING: u32 = 256;

/// Maximum new connections from a single IP per rate window.
pub const DEFAULT_MAX_NEW_CONNECTIONS_PER_IP: usize = 32;

/// Rate window for IP-level connection rate limiting, in seconds.
pub const DEFAULT_IP_RATE_WINDOW_SECS: u64 = 60;

/// Maximum username-receipt requests one peer may make per receipt window.
///
/// Generating a fresh `did:key` and a valid claim signature is free and
/// offline, so without this a single connection can receipt the entire viable
/// `[a-z0-9_]{3,32}` namespace — and because only the owner can release a
/// name, squatted names never free up. A real client claims a username once
/// and refreshes it rarely, so this is far above legitimate use.
pub const DEFAULT_RECEIPT_LIMIT: usize = 5;

/// Rate window for username-receipt requests, in seconds.
pub const DEFAULT_RECEIPT_WINDOW_SECS: u64 = 60;

/// Maximum `/username/:name` lookups one client IP may make per lookup window.
///
/// The lookup is public by design — clients resolve names against it — but
/// without a limit the whole registry (username → DID → first-seen time, for
/// every user) is enumerable for the cost of a loop, and every hit is a
/// SQLite read on the same listener the relay's real work shares. A person
/// checking a handful of names never comes near this.
pub const DEFAULT_LOOKUP_LIMIT: usize = 30;

/// Rate window for `/username/:name` lookups, in seconds.
pub const DEFAULT_LOOKUP_WINDOW_SECS: u64 = 60;

/// Cap on tracked client IPs for the lookup limiter, so the map cannot
/// itself become the memory leak.
pub const DEFAULT_LOOKUP_MAX_TRACKED: usize = 10_000;

/// How long an idle connection stays open before being reaped, in seconds.
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 600;

/// Kademlia query timeout, in seconds.
pub const DEFAULT_KAD_QUERY_TIMEOUT_SECS: u64 = 60;

/// Kademlia replication factor (k-buckets).
pub const DEFAULT_KAD_REPLICATION_FACTOR: usize = 20;

/// Maximum number of records in the Kademlia memory store and its disk mirror.
/// 16k × 64 KB ≈ 1 GB worst case — fits a 1 GB machine with headroom.
pub const DEFAULT_KAD_MAX_RECORDS: usize = 16_384;

/// Maximum size of a single Kademlia record value, in bytes.
pub const DEFAULT_KAD_MAX_RECORD_BYTES: usize = 65_536;

/// Relay: max number of active circuit reservations.
pub const DEFAULT_MAX_RESERVATIONS: usize = 1024;

/// Relay: max number of reservation requests per peer.
pub const DEFAULT_MAX_RESERVATIONS_PER_PEER: usize = 16;

/// Relay: how long a reservation is valid, in seconds.
pub const DEFAULT_RESERVATION_DURATION_SECS: u64 = 3600;

/// Relay: max number of active circuits (relayed connections).
pub const DEFAULT_MAX_CIRCUITS: usize = 2048;

/// Relay: max number of circuits per peer.
/// Was 16 — observer + crawlers fan-out enough simultaneous circuit dials
/// to saturate that limit, causing cascade `circuits_denied` (saw 7910:47
/// denied:accepted ratio in production). 128 leaves headroom for active
/// observers without exposing the relay to a single peer monopolising it.
pub const DEFAULT_MAX_CIRCUITS_PER_PEER: usize = 128;

/// Relay: per-circuit byte limit.
/// 2 MB was too tight for VC bundles + content sync. 128 MB still caps
/// abuse but won't truncate normal payloads.
pub const DEFAULT_MAX_CIRCUIT_BYTES: u64 = 128 * 1024 * 1024;

/// Relay: per-circuit duration limit, in seconds.
/// 120 s caused gossipsub mesh churn — every 2 min all circuits closed
/// and re-dialed. 15 min lets meshes stabilise; DCUtR (client-side) should
/// upgrade most circuits to direct connections well within this window.
pub const DEFAULT_MAX_CIRCUIT_DURATION_SECS: u64 = 900;

/// Maximum number of Identify-reported addresses added per peer.
pub const DEFAULT_MAX_IDENTIFY_ADDRS: usize = 16;

/// How often to log health status, in seconds.
pub const DEFAULT_HEALTH_LOG_INTERVAL_SECS: u64 = 300;

/// Largest username-receipt request the codec will read.
///
/// A claim is a few hundred bytes: a username of at most 32 characters, a
/// fixed-width `did:key`, a 128-character signature, and the app's receipts
/// list (about 220 bytes per relay that has already countersigned). 8 KiB
/// leaves room for a few dozen relays. The codec's default is 1 MiB, which
/// the swarm would otherwise buffer and deserialize for every request.
/// A wire-format bound, not a tunable.
pub(crate) const USERNAME_REQUEST_MAX_BYTES: u64 = 8 * 1024;

// ── Configuration ────────────────────────────────────────────────────

/// Every limit the relay enforces. [`Limits::default`] is the set the relay
/// runs with when no flag or variable overrides it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_connections: u32,
    pub max_connections_per_peer: u32,
    pub max_pending_incoming: u32,
    pub max_connections_per_ip: usize,
    pub max_new_connections_per_ip: usize,
    pub ip_rate_window: Duration,
    pub idle_timeout: Duration,
    pub kad_query_timeout: Duration,
    pub kad_replication_factor: NonZeroUsize,
    pub kad_max_records: usize,
    pub kad_max_record_bytes: usize,
    pub max_reservations: usize,
    pub max_reservations_per_peer: usize,
    pub reservation_duration: Duration,
    pub max_circuits: usize,
    pub max_circuits_per_peer: usize,
    pub max_circuit_bytes: u64,
    pub max_circuit_duration: Duration,
    pub max_identify_addrs: usize,
    pub receipt_limit: usize,
    pub receipt_window: Duration,
    pub lookup_limit: usize,
    pub lookup_window: Duration,
    pub lookup_max_tracked: usize,
    pub health_log_interval: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_connections_per_peer: DEFAULT_MAX_CONNECTIONS_PER_PEER,
            max_pending_incoming: DEFAULT_MAX_PENDING_INCOMING,
            max_connections_per_ip: DEFAULT_MAX_CONNECTIONS_PER_IP,
            max_new_connections_per_ip: DEFAULT_MAX_NEW_CONNECTIONS_PER_IP,
            ip_rate_window: Duration::from_secs(DEFAULT_IP_RATE_WINDOW_SECS),
            idle_timeout: Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS),
            kad_query_timeout: Duration::from_secs(DEFAULT_KAD_QUERY_TIMEOUT_SECS),
            kad_replication_factor: NonZeroUsize::new(DEFAULT_KAD_REPLICATION_FACTOR)
                .expect("non-zero default"),
            kad_max_records: DEFAULT_KAD_MAX_RECORDS,
            kad_max_record_bytes: DEFAULT_KAD_MAX_RECORD_BYTES,
            max_reservations: DEFAULT_MAX_RESERVATIONS,
            max_reservations_per_peer: DEFAULT_MAX_RESERVATIONS_PER_PEER,
            reservation_duration: Duration::from_secs(DEFAULT_RESERVATION_DURATION_SECS),
            max_circuits: DEFAULT_MAX_CIRCUITS,
            max_circuits_per_peer: DEFAULT_MAX_CIRCUITS_PER_PEER,
            max_circuit_bytes: DEFAULT_MAX_CIRCUIT_BYTES,
            max_circuit_duration: Duration::from_secs(DEFAULT_MAX_CIRCUIT_DURATION_SECS),
            max_identify_addrs: DEFAULT_MAX_IDENTIFY_ADDRS,
            receipt_limit: DEFAULT_RECEIPT_LIMIT,
            receipt_window: Duration::from_secs(DEFAULT_RECEIPT_WINDOW_SECS),
            lookup_limit: DEFAULT_LOOKUP_LIMIT,
            lookup_window: Duration::from_secs(DEFAULT_LOOKUP_WINDOW_SECS),
            lookup_max_tracked: DEFAULT_LOOKUP_MAX_TRACKED,
            health_log_interval: Duration::from_secs(DEFAULT_HEALTH_LOG_INTERVAL_SECS),
        }
    }
}

/// The single input to [`crate::start`].
///
/// Not `Debug`: it carries the identity keypair and the admin token.
#[derive(Clone)]
pub struct RelayConfig {
    /// Relay identity. `None` generates an ephemeral keypair, so the PeerId
    /// changes on every start.
    pub keypair: Option<Keypair>,
    /// IPv4 address the libp2p TCP and QUIC listeners bind.
    pub listen_ip4: Ipv4Addr,
    /// IPv6 address the libp2p listeners also bind, best-effort. `None` skips
    /// IPv6.
    pub listen_ip6: Option<Ipv6Addr>,
    /// TCP listen port. `0` binds an ephemeral port.
    pub tcp_port: u16,
    /// QUIC (UDP) listen port. `0` binds an ephemeral port.
    pub quic_port: u16,
    /// Address the HTTP health, metrics and lookup listener binds.
    pub metrics_bind: IpAddr,
    /// HTTP listen port. `0` binds an ephemeral port.
    pub metrics_port: u16,
    /// Publicly resolvable hostname, advertised (with its resolved IPs) as the
    /// relay's external address.
    pub public_host: Option<String>,
    /// Directory for the receipt store and DHT record mirror.
    pub data_dir: PathBuf,
    /// Bearer token for the operational HTTP routes. `None`, empty or shorter
    /// than 16 characters leaves those routes answering 404.
    pub admin_token: Option<String>,
    pub limits: Limits,
}

impl Default for RelayConfig {
    fn default() -> Self {
        RelayConfig {
            keypair: None,
            listen_ip4: Ipv4Addr::UNSPECIFIED,
            listen_ip6: Some(Ipv6Addr::UNSPECIFIED),
            tcp_port: 4001,
            quic_port: 4001,
            metrics_bind: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            metrics_port: 9090,
            public_host: None,
            data_dir: PathBuf::from("./relay-data"),
            admin_token: None,
            limits: Limits::default(),
        }
    }
}

// ── CLI ──────────────────────────────────────────────────────────────

/// An IPv6 listen address, or `off` to skip IPv6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Listen(pub Option<Ipv6Addr>);

impl FromStr for Ipv6Listen {
    type Err = std::net::AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("off") {
            return Ok(Ipv6Listen(None));
        }
        s.parse().map(|ip| Ipv6Listen(Some(ip)))
    }
}

const ENV_ONLY_HELP: &str = "\
Environment-only settings (kept off the command line because they are secrets):
  RELAY_SEED         64-char hex seed for a stable PeerId; random when unset.
                     Read, then cleared from the environment at startup.
  RELAY_ADMIN_TOKEN  Bearer token for /peers, /metrics and /health/alerts;
                     at least 16 characters, otherwise those routes stay off.
  RUST_LOG           Log filter (default: info).";

/// Command-line interface. Every setting except the secrets is a flag with a
/// matching `RELAY_*` environment variable.
#[derive(Parser, Debug)]
#[command(
    name = "alexandria-relay",
    about = "Alexandria P2P relay + bootstrap node",
    version,
    after_help = ENV_ONLY_HELP
)]
pub struct Cli {
    /// Generate a new keypair seed and exit
    #[arg(long)]
    pub generate_key: bool,

    /// TCP listen port (0 = ephemeral)
    #[arg(long, env = "RELAY_PORT", default_value_t = 4001)]
    pub port: u16,

    /// QUIC (UDP) listen port (0 = ephemeral)
    #[arg(long, env = "RELAY_QUIC_PORT", default_value_t = 4001)]
    pub quic_port: u16,

    /// IPv4 address the libp2p TCP and QUIC listeners bind
    #[arg(long, env = "RELAY_LISTEN_IP4", default_value_t = Ipv4Addr::UNSPECIFIED)]
    pub listen_ip4: Ipv4Addr,

    /// IPv6 address the libp2p listeners also bind (best-effort), or `off`
    #[arg(long, env = "RELAY_LISTEN_IP6", default_value = "::")]
    pub listen_ip6: Ipv6Listen,

    /// HTTP health, metrics and lookup port (0 = ephemeral)
    #[arg(long, env = "RELAY_METRICS_PORT", default_value_t = 9090)]
    pub metrics_port: u16,

    /// Address the HTTP listener binds. Use 127.0.0.1 to keep it behind a
    /// local reverse proxy
    #[arg(long, env = "RELAY_METRICS_BIND", default_value_t = IpAddr::V4(Ipv4Addr::UNSPECIFIED))]
    pub metrics_bind: IpAddr,

    /// Publicly resolvable hostname this relay is reachable at. Registered,
    /// with the IPs it resolves to at startup, as the relay's external
    /// address so reservation responses include a dialable multiaddr.
    /// Without it, clients reject reservations with
    /// `NoAddressesInReservation`
    #[arg(long, env = "RELAY_PUBLIC_HOST")]
    pub public_host: Option<String>,

    /// Directory for persistent state (username receipts and mirrored DHT
    /// records). On a container host, point this at a mounted volume
    #[arg(long, env = "RELAY_DATA_DIR", default_value = "./relay-data")]
    pub data_dir: PathBuf,

    /// Maximum concurrent connections in total
    #[arg(long, env = "RELAY_MAX_CONNECTIONS", default_value_t = DEFAULT_MAX_CONNECTIONS, help_heading = "Connection limits")]
    pub max_connections: u32,

    /// Maximum concurrent connections per PeerId
    #[arg(long, env = "RELAY_MAX_CONNECTIONS_PER_PEER", default_value_t = DEFAULT_MAX_CONNECTIONS_PER_PEER, help_heading = "Connection limits")]
    pub max_connections_per_peer: u32,

    /// Maximum incoming connections still in the transport handshake
    #[arg(long, env = "RELAY_MAX_PENDING_INCOMING", default_value_t = DEFAULT_MAX_PENDING_INCOMING, help_heading = "Connection limits")]
    pub max_pending_incoming: u32,

    /// Maximum concurrent connections per client IP
    #[arg(long, env = "RELAY_MAX_CONNECTIONS_PER_IP", default_value_t = DEFAULT_MAX_CONNECTIONS_PER_IP, help_heading = "Connection limits")]
    pub max_connections_per_ip: usize,

    /// Maximum new connections per client IP per rate window
    #[arg(long, env = "RELAY_MAX_NEW_CONNECTIONS_PER_IP", default_value_t = DEFAULT_MAX_NEW_CONNECTIONS_PER_IP, help_heading = "Connection limits")]
    pub max_new_connections_per_ip: usize,

    /// Per-IP connection rate window, in seconds
    #[arg(long, env = "RELAY_IP_RATE_WINDOW_SECS", default_value_t = DEFAULT_IP_RATE_WINDOW_SECS, value_parser = clap::value_parser!(u64).range(1..), help_heading = "Connection limits")]
    pub ip_rate_window_secs: u64,

    /// Idle connection timeout, in seconds
    #[arg(long, env = "RELAY_IDLE_TIMEOUT_SECS", default_value_t = DEFAULT_IDLE_TIMEOUT_SECS, value_parser = clap::value_parser!(u64).range(1..), help_heading = "Connection limits")]
    pub idle_timeout_secs: u64,

    /// Maximum Identify-reported addresses added to the routing table per peer
    #[arg(long, env = "RELAY_MAX_IDENTIFY_ADDRS", default_value_t = DEFAULT_MAX_IDENTIFY_ADDRS, help_heading = "Connection limits")]
    pub max_identify_addrs: usize,

    /// Kademlia query timeout, in seconds
    #[arg(long, env = "RELAY_KAD_QUERY_TIMEOUT_SECS", default_value_t = DEFAULT_KAD_QUERY_TIMEOUT_SECS, value_parser = clap::value_parser!(u64).range(1..), help_heading = "DHT limits")]
    pub kad_query_timeout_secs: u64,

    /// Kademlia replication factor
    #[arg(long, env = "RELAY_KAD_REPLICATION_FACTOR", default_value_t = NonZeroUsize::new(DEFAULT_KAD_REPLICATION_FACTOR).expect("non-zero default"), help_heading = "DHT limits")]
    pub kad_replication_factor: NonZeroUsize,

    /// Maximum DHT records held in memory and mirrored to disk
    #[arg(long, env = "RELAY_KAD_MAX_RECORDS", default_value_t = DEFAULT_KAD_MAX_RECORDS, help_heading = "DHT limits")]
    pub kad_max_records: usize,

    /// Maximum size of one DHT record value, in bytes
    #[arg(long, env = "RELAY_KAD_MAX_RECORD_BYTES", default_value_t = DEFAULT_KAD_MAX_RECORD_BYTES, help_heading = "DHT limits")]
    pub kad_max_record_bytes: usize,

    /// Maximum active circuit reservations in total
    #[arg(long, env = "RELAY_MAX_RESERVATIONS", default_value_t = DEFAULT_MAX_RESERVATIONS, help_heading = "Circuit relay limits")]
    pub max_reservations: usize,

    /// Maximum circuit reservations per peer
    #[arg(long, env = "RELAY_MAX_RESERVATIONS_PER_PEER", default_value_t = DEFAULT_MAX_RESERVATIONS_PER_PEER, help_heading = "Circuit relay limits")]
    pub max_reservations_per_peer: usize,

    /// How long a reservation lasts, in seconds
    #[arg(long, env = "RELAY_RESERVATION_DURATION_SECS", default_value_t = DEFAULT_RESERVATION_DURATION_SECS, value_parser = clap::value_parser!(u64).range(1..), help_heading = "Circuit relay limits")]
    pub reservation_duration_secs: u64,

    /// Maximum active circuits in total
    #[arg(long, env = "RELAY_MAX_CIRCUITS", default_value_t = DEFAULT_MAX_CIRCUITS, help_heading = "Circuit relay limits")]
    pub max_circuits: usize,

    /// Maximum active circuits per peer
    #[arg(long, env = "RELAY_MAX_CIRCUITS_PER_PEER", default_value_t = DEFAULT_MAX_CIRCUITS_PER_PEER, help_heading = "Circuit relay limits")]
    pub max_circuits_per_peer: usize,

    /// Maximum bytes relayed per circuit
    #[arg(long, env = "RELAY_MAX_CIRCUIT_BYTES", default_value_t = DEFAULT_MAX_CIRCUIT_BYTES, help_heading = "Circuit relay limits")]
    pub max_circuit_bytes: u64,

    /// Maximum circuit lifetime, in seconds
    #[arg(long, env = "RELAY_MAX_CIRCUIT_DURATION_SECS", default_value_t = DEFAULT_MAX_CIRCUIT_DURATION_SECS, value_parser = clap::value_parser!(u64).range(1..), help_heading = "Circuit relay limits")]
    pub max_circuit_duration_secs: u64,

    /// Username-receipt requests allowed per PeerId per receipt window
    #[arg(long, env = "RELAY_RECEIPT_LIMIT", default_value_t = DEFAULT_RECEIPT_LIMIT, help_heading = "Username registry limits")]
    pub receipt_limit: usize,

    /// Username-receipt rate window, in seconds
    #[arg(long, env = "RELAY_RECEIPT_WINDOW_SECS", default_value_t = DEFAULT_RECEIPT_WINDOW_SECS, value_parser = clap::value_parser!(u64).range(1..), help_heading = "Username registry limits")]
    pub receipt_window_secs: u64,

    /// `/username/:name` lookups allowed per client IP per lookup window
    #[arg(long, env = "RELAY_LOOKUP_LIMIT", default_value_t = DEFAULT_LOOKUP_LIMIT, help_heading = "Username registry limits")]
    pub lookup_limit: usize,

    /// Username lookup rate window, in seconds
    #[arg(long, env = "RELAY_LOOKUP_WINDOW_SECS", default_value_t = DEFAULT_LOOKUP_WINDOW_SECS, value_parser = clap::value_parser!(u64).range(1..), help_heading = "Username registry limits")]
    pub lookup_window_secs: u64,

    /// Client IPs the lookup limiter tracks before it prunes
    #[arg(long, env = "RELAY_LOOKUP_MAX_TRACKED", default_value_t = DEFAULT_LOOKUP_MAX_TRACKED, help_heading = "Username registry limits")]
    pub lookup_max_tracked: usize,

    /// Interval between health log lines, in seconds
    #[arg(long, env = "RELAY_HEALTH_LOG_INTERVAL_SECS", default_value_t = DEFAULT_HEALTH_LOG_INTERVAL_SECS, value_parser = clap::value_parser!(u64).range(1..))]
    pub health_log_interval_secs: u64,
}

impl Cli {
    /// The relay configuration these flags describe. The secrets
    /// (`keypair`, `admin_token`) are environment-only and left `None`; the
    /// binary fills them in.
    pub fn into_config(self) -> RelayConfig {
        RelayConfig {
            keypair: None,
            listen_ip4: self.listen_ip4,
            listen_ip6: self.listen_ip6.0,
            tcp_port: self.port,
            quic_port: self.quic_port,
            metrics_bind: self.metrics_bind,
            metrics_port: self.metrics_port,
            public_host: self.public_host,
            data_dir: self.data_dir,
            admin_token: None,
            limits: Limits {
                max_connections: self.max_connections,
                max_connections_per_peer: self.max_connections_per_peer,
                max_pending_incoming: self.max_pending_incoming,
                max_connections_per_ip: self.max_connections_per_ip,
                max_new_connections_per_ip: self.max_new_connections_per_ip,
                ip_rate_window: Duration::from_secs(self.ip_rate_window_secs),
                idle_timeout: Duration::from_secs(self.idle_timeout_secs),
                kad_query_timeout: Duration::from_secs(self.kad_query_timeout_secs),
                kad_replication_factor: self.kad_replication_factor,
                kad_max_records: self.kad_max_records,
                kad_max_record_bytes: self.kad_max_record_bytes,
                max_reservations: self.max_reservations,
                max_reservations_per_peer: self.max_reservations_per_peer,
                reservation_duration: Duration::from_secs(self.reservation_duration_secs),
                max_circuits: self.max_circuits,
                max_circuits_per_peer: self.max_circuits_per_peer,
                max_circuit_bytes: self.max_circuit_bytes,
                max_circuit_duration: Duration::from_secs(self.max_circuit_duration_secs),
                max_identify_addrs: self.max_identify_addrs,
                receipt_limit: self.receipt_limit,
                receipt_window: Duration::from_secs(self.receipt_window_secs),
                lookup_limit: self.lookup_limit,
                lookup_window: Duration::from_secs(self.lookup_window_secs),
                lookup_max_tracked: self.lookup_max_tracked,
                health_log_interval: Duration::from_secs(self.health_log_interval_secs),
            },
        }
    }
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

    /// With no flags the relay must run exactly as it did when these were
    /// constants. The expected values are the pre-configuration constants,
    /// written out rather than read back from the defaults.
    #[test]
    fn no_flags_gives_the_historical_limits() {
        let config = Cli::try_parse_from(["alexandria-relay"])
            .expect("no flags parse")
            .into_config();
        assert_eq!(config.tcp_port, 4001);
        assert_eq!(config.quic_port, 4001);
        assert_eq!(config.listen_ip4, Ipv4Addr::UNSPECIFIED);
        assert_eq!(config.listen_ip6, Some(Ipv6Addr::UNSPECIFIED));
        assert_eq!(config.metrics_port, 9090);
        assert_eq!(config.metrics_bind, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(config.data_dir, PathBuf::from("./relay-data"));
        let secs = Duration::from_secs;
        assert_eq!(
            config.limits,
            Limits {
                max_connections: 1024,
                max_connections_per_peer: 8,
                max_pending_incoming: 256,
                max_connections_per_ip: 32,
                max_new_connections_per_ip: 32,
                ip_rate_window: secs(60),
                idle_timeout: secs(600),
                kad_query_timeout: secs(60),
                kad_replication_factor: NonZeroUsize::new(20).unwrap(),
                kad_max_records: 16_384,
                kad_max_record_bytes: 65_536,
                max_reservations: 1024,
                max_reservations_per_peer: 16,
                reservation_duration: secs(3600),
                max_circuits: 2048,
                max_circuits_per_peer: 128,
                max_circuit_bytes: 128 * 1024 * 1024,
                max_circuit_duration: secs(900),
                max_identify_addrs: 16,
                receipt_limit: 5,
                receipt_window: secs(60),
                lookup_limit: 30,
                lookup_window: secs(60),
                lookup_max_tracked: 10_000,
                health_log_interval: secs(300),
            }
        );
        assert_eq!(config.limits, Limits::default());
    }

    #[test]
    fn flags_override_the_defaults() {
        let config = Cli::try_parse_from([
            "alexandria-relay",
            "--port",
            "0",
            "--listen-ip6",
            "off",
            "--metrics-bind",
            "127.0.0.1",
            "--max-circuits-per-peer",
            "256",
            "--receipt-window-secs",
            "30",
        ])
        .expect("flags parse")
        .into_config();
        assert_eq!(config.tcp_port, 0);
        assert_eq!(config.listen_ip6, None);
        assert_eq!(config.metrics_bind, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(config.limits.max_circuits_per_peer, 256);
        assert_eq!(config.limits.receipt_window, Duration::from_secs(30));
    }

    #[test]
    fn a_zero_duration_is_refused() {
        // A zero interval panics the health timer; refuse it at parse time.
        assert!(
            Cli::try_parse_from(["alexandria-relay", "--health-log-interval-secs", "0"]).is_err()
        );
    }

    #[test]
    fn help_lists_every_limit_with_its_variable() {
        use clap::CommandFactory;
        let help = Cli::command().render_long_help().to_string();
        for var in [
            "RELAY_MAX_CONNECTIONS",
            "RELAY_MAX_PENDING_INCOMING",
            "RELAY_MAX_CONNECTIONS_PER_IP",
            "RELAY_KAD_MAX_RECORDS",
            "RELAY_MAX_CIRCUIT_BYTES",
            "RELAY_RECEIPT_LIMIT",
            "RELAY_LOOKUP_MAX_TRACKED",
            "RELAY_HEALTH_LOG_INTERVAL_SECS",
            "RELAY_METRICS_BIND",
            "RELAY_SEED",
            "RELAY_ADMIN_TOKEN",
        ] {
            assert!(help.contains(var), "--help does not mention {var}");
        }
    }

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
