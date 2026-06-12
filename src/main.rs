//! Alexandria Relay + Bootstrap Node
//!
//! A libp2p relay designed to run on a public VPS.
//! Provides three critical services for the Alexandria P2P network:
//!
//! 1. **Circuit Relay v2** — NATted peers (phones, laptops behind routers)
//!    can relay traffic through this node to reach each other.
//!
//! 2. **Kademlia DHT** — Uses the private `/alexandria/kad/1.0` protocol.
//!    Peers register in the DHT on connect. The relay always runs in
//!    Kademlia server mode (publicly reachable bootstrap node).
//!
//! 3. **Identify** — Exchanges peer metadata (listen addresses, protocols)
//!    so Kademlia can function correctly.
//!
//! ## Security Model
//!
//! The relay has NO special authority. It cannot:
//! - Read encrypted traffic (all peer-to-peer traffic is Noise-encrypted)
//! - Forge identities (PeerIds are Ed25519 public keys)
//! - Censor content (it doesn't inspect payloads)
//! - Grant or deny access (any peer can join the DHT)
//!
//! It IS a single point of bootstrapping failure — if this relay goes down,
//! new peers cannot discover existing peers. Existing peers that already
//! know each other (via the known_peers DB) continue to function.
//!
//! ## Hardening
//!
//! - Connection limits (per-peer, per-IP, and total) prevent resource exhaustion
//! - IP-level rate limiting prevents PeerId rotation attacks
//! - Relay circuit limits (bandwidth, duration, reservations) prevent abuse
//! - Kademlia memory store size is capped
//! - Idle connection timeout prevents connection leaks
//! - Graceful shutdown on SIGTERM/SIGINT
//! - Periodic health logging (connection count, uptime)
//! - HTTP health check + metrics endpoint for monitoring
//!
//! ## Usage
//!
//! ```bash
//! # Generate a stable keypair (run once, save the seed)
//! alexandria-relay --generate-key
//!
//! # Run with a seed (deterministic PeerId across restarts)
//! RELAY_SEED=<64-char-hex> alexandria-relay --port 4001
//!
//! # Or run with an ephemeral keypair (PeerId changes each restart)
//! alexandria-relay --port 4001
//! ```

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::routing::get;
use axum::{Json, Router};
use clap::Parser;
use futures::StreamExt;
use libp2p::identity::Keypair;
use libp2p::kad::store::MemoryStore;
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{identify, kad, noise, relay, yamux, Multiaddr, PeerId, StreamProtocol, SwarmBuilder};

mod username_reg;
use serde::Serialize;
use tokio::sync::RwLock;
use username_reg::{ReceiptRequest, ReceiptResponse, RegistryStore};

// ── Configuration Constants ──────────────────────────────────────────

/// Maximum total concurrent connections the relay will accept.
const MAX_CONNECTIONS: usize = 1024;

/// Maximum concurrent connections from a single peer.
/// Allows TCP+QUIC × inbound/outbound × small reconnect overlap.
const MAX_CONNECTIONS_PER_PEER: u32 = 8;

/// Maximum concurrent connections from a single IP address.
/// Households / shared NATs commonly carry 5-10 simultaneous peers.
const MAX_CONNECTIONS_PER_IP: usize = 32;

/// Maximum new connections from a single IP per rate window.
const MAX_NEW_CONNS_PER_IP_PER_WINDOW: usize = 32;

/// Rate window duration for IP-level connection rate limiting.
const IP_RATE_WINDOW: Duration = Duration::from_secs(60);

/// How long an idle connection stays open before being reaped.
const IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(600); // 10 min

/// Kademlia query timeout.
const KAD_QUERY_TIMEOUT: Duration = Duration::from_secs(60);

/// Kademlia replication factor (k-buckets).
const KAD_REPLICATION_FACTOR: usize = 20;

/// Maximum number of records in the Kademlia memory store.
/// 16k × 64 KB ≈ 1 GB worst case — fits a 1 GB Fly machine with headroom.
const KAD_MAX_RECORDS: usize = 16_384;

/// Maximum size of a single Kademlia record value.
const KAD_MAX_RECORD_SIZE: usize = 65_536; // 64 KB

/// Relay: max number of active circuit reservations.
const RELAY_MAX_RESERVATIONS: usize = 1024;

/// Relay: max number of active circuits (relayed connections).
const RELAY_MAX_CIRCUITS: usize = 2048;

/// Relay: max number of reservation requests per peer.
const RELAY_MAX_RESERVATIONS_PER_PEER: usize = 16;

/// Relay: max number of circuits per peer.
/// Was 16 — observer + crawlers fan-out enough simultaneous circuit dials
/// to saturate that limit, causing cascade `circuits_denied` (saw 7910:47
/// denied:accepted ratio in production). 128 leaves headroom for active
/// observers without exposing the relay to a single peer monopolising it.
const RELAY_MAX_CIRCUITS_PER_PEER: usize = 128;

/// Relay: per-circuit bandwidth limit (bytes).
/// 2 MB was too tight for VC bundles + content sync. 128 MB still caps
/// abuse but won't truncate normal payloads.
const RELAY_MAX_CIRCUIT_BYTES: u64 = 128 * 1024 * 1024; // 128 MB

/// Relay: per-circuit duration limit.
/// 120 s caused gossipsub mesh churn — every 2 min all circuits closed
/// and re-dialed. 15 min lets meshes stabilise; DCUtR (client-side) should
/// upgrade most circuits to direct connections well within this window.
const RELAY_MAX_CIRCUIT_DURATION: Duration = Duration::from_secs(900); // 15 min

/// Relay: how long a reservation is valid.
const RELAY_RESERVATION_DURATION: Duration = Duration::from_secs(3600); // 1 hour

/// Maximum number of addresses to accept per peer via Identify.
const MAX_ADDRS_PER_PEER: usize = 16;

/// How often to log health status.
const HEALTH_LOG_INTERVAL: Duration = Duration::from_secs(300); // 5 min

// ── CLI ──────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "alexandria-relay",
    about = "Alexandria P2P relay + bootstrap node",
    version
)]
struct Args {
    /// TCP listen port
    #[arg(long, default_value = "4001")]
    port: u16,

    /// QUIC (UDP) listen port
    #[arg(long, default_value = "4001")]
    quic_port: u16,

    /// HTTP metrics/health port
    #[arg(long, default_value = "9090")]
    metrics_port: u16,

    /// Publicly resolvable hostname this relay is reachable at (e.g.
    /// `alexandria-relay.fly.dev`). Registered as the relay's external
    /// address so reservation responses include a dialable multiaddr.
    /// The hostname is also resolved at startup and the current IPs are
    /// registered, so DNS-blocked clients can reach us by IP without us
    /// hardcoding addresses that go stale on re-provisioning.
    /// Without this, clients receive an empty address list and reject
    /// the reservation with `NoAddressesInReservation`.
    #[arg(long, env = "RELAY_PUBLIC_HOST")]
    public_host: Option<String>,

    /// Generate a new keypair seed and exit
    #[arg(long)]
    generate_key: bool,

    /// Directory for persistent state (username receipts + mirrored
    /// DHT records). On Fly, point this at a mounted volume.
    #[arg(long, env = "RELAY_DATA_DIR", default_value = "./relay-data")]
    data_dir: std::path::PathBuf,
}

// ── Network Behaviour ────────────────────────────────────────────────

/// Composed behaviour: relay server + Kademlia + identify + username-reg receipts.
///
/// Intentionally minimal — the relay does NOT run GossipSub, AutoNAT,
/// or DCUtR. It only needs enough to bootstrap peers into the DHT
/// and relay traffic for NATted peers.
#[derive(NetworkBehaviour)]
struct RelayBehaviour {
    connection_limits: libp2p_connection_limits::Behaviour,
    relay: relay::Behaviour,
    kademlia: kad::Behaviour<MemoryStore>,
    identify: identify::Behaviour,
    /// Username-claim receipts — `/alexandria/username-reg/1.0`.
    /// Inbound only: clients request, the relay countersigns.
    username_reg: request_response::cbor::Behaviour<ReceiptRequest, ReceiptResponse>,
}

// ── Metrics ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
struct RelayMetrics {
    peer_id: String,
    uptime_seconds: u64,
    connections: usize,
    total_connections_served: u64,
    reservations_accepted: u64,
    reservations_denied: u64,
    circuits_accepted: u64,
    circuits_denied: u64,
    circuits_closed: u64,
    kad_routing_updated: u64,
    identify_received: u64,
    listener_errors: u64,
    ip_rate_limited: u64,

    // Rolling 60-second window snapshots — populated by a background
    // sampling task in `run_metrics_server`. Drives /health/alerts.
    #[serde(skip)]
    prev_minute_circuits_denied: u64,
    #[serde(skip)]
    prev_minute_circuits_accepted: u64,
    #[serde(skip)]
    prev_minute_reservations_denied: u64,
    /// Circuits denied in the most recent completed 60s window. Surfaced
    /// at /health/alerts so external healthcheckers can flag spikes
    /// without doing their own delta math.
    circuits_denied_per_min: u64,
    circuits_accepted_per_min: u64,
    reservations_denied_per_min: u64,

    /// Source IPs of currently-connected peers, captured from the
    /// connection's remote address at ConnectionEstablished. Surfaced
    /// via /peers so the observer can attribute geo to NATted peers
    /// (whose own listen_addrs only include private LAN + circuit
    /// addrs and so never reveal their WAN IP through libp2p Identify).
    /// Skipped from /metrics to avoid leaking IPs into general telemetry.
    #[serde(skip)]
    peer_source_ips: HashMap<PeerId, IpAddr>,
    /// Subset of `peer_source_ips` keys that hold an active circuit
    /// reservation with this relay — i.e. they're using us as a
    /// rendezvous point. This is the more interesting set for the
    /// observer (ad-hoc dialers come and go).
    #[serde(skip)]
    peers_with_reservation: HashSet<PeerId>,
}

/// Wire format for /peers — one entry per connected peer with the WAN
/// IP we saw them dial in from. `has_reservation` distinguishes peers
/// using us as a relay rendezvous from peers that just opened a one-off
/// connection (e.g. observer crawlers).
#[derive(Debug, Clone, Serialize)]
struct PeerSourceEntry {
    peer_id: String,
    source_ip: String,
    has_reservation: bool,
}

// ── Keypair Utilities ────────────────────────────────────────────────

fn keypair_from_seed(seed_hex: &str) -> Keypair {
    let seed_bytes = hex::decode(seed_hex).expect("RELAY_SEED must be valid hex");
    assert!(
        seed_bytes.len() >= 32,
        "RELAY_SEED must be at least 32 bytes (64 hex chars)"
    );
    let mut key = [0u8; 32];
    key.copy_from_slice(&seed_bytes[..32]);
    let keypair = Keypair::ed25519_from_bytes(&mut key).expect("valid ed25519 seed");
    // Zero seed material from memory
    key.fill(0);
    keypair
}

fn generate_seed() -> String {
    let random_bytes: [u8; 32] = rand::random();
    hex::encode(random_bytes)
}

// ── IP Extraction ───────────────────────────────────────────────────

fn extract_ip(addr: &Multiaddr) -> Option<IpAddr> {
    addr.iter().find_map(|proto| match proto {
        Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
        Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    })
}

// ── Main ─────────────────────────────────────────────────────────────

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    if args.generate_key {
        let seed = generate_seed();
        let keypair = keypair_from_seed(&seed);
        let peer_id = keypair.public().to_peer_id();
        println!("Generated relay keypair:");
        println!("  Seed (save this):  {seed}");
        println!("  PeerId:            {peer_id}");
        println!();
        println!("Deploy with:");
        println!("  RELAY_SEED={seed} alexandria-relay --port 4001");
        println!();
        println!("Add to main app's discovery.rs:");
        println!("  const RELAY_PEER_ID: &str = \"{peer_id}\";");
        return;
    }

    // Read and clear RELAY_SEED while single-threaded (safe — no tokio runtime yet)
    let seed = std::env::var("RELAY_SEED").ok();
    if seed.is_some() {
        std::env::remove_var("RELAY_SEED");
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(async_main(args, seed));
}

async fn async_main(args: Args, seed: Option<String>) {
    // ── Keypair ──────────────────────────────────────────────────────
    let keypair = match seed {
        Some(ref s) => {
            log::info!("Using deterministic keypair from RELAY_SEED");
            keypair_from_seed(s)
        }
        None => {
            log::warn!(
                "No RELAY_SEED set — using ephemeral keypair (PeerId will change on restart)"
            );
            Keypair::generate_ed25519()
        }
    };

    let local_peer_id = keypair.public().to_peer_id();
    log::info!("Relay PeerId: {local_peer_id}");

    // ── Persistent registry store ────────────────────────────────────
    // Username receipts + mirrored DHT records. Countersigning needs
    // the keypair after the swarm takes ownership, so keep a clone.
    let signing_keypair = keypair.clone();
    let registry_store = match RegistryStore::open(&args.data_dir) {
        Ok(s) => {
            log::info!(
                "Registry store at {:?} ({} receipts)",
                args.data_dir,
                s.receipt_count()
            );
            // Shared with the HTTP server: /username/:name lets clients
            // check availability over plain HTTPS before they have a
            // P2P identity (signup-time check).
            Some(std::sync::Arc::new(std::sync::Mutex::new(s)))
        }
        Err(e) => {
            log::error!("Registry store unavailable ({e}) — receipts disabled this run");
            None
        }
    };

    // ── Shared Metrics ───────────────────────────────────────────────
    let metrics = Arc::new(RwLock::new(RelayMetrics {
        peer_id: local_peer_id.to_string(),
        uptime_seconds: 0,
        connections: 0,
        total_connections_served: 0,
        reservations_accepted: 0,
        reservations_denied: 0,
        circuits_accepted: 0,
        circuits_denied: 0,
        circuits_closed: 0,
        kad_routing_updated: 0,
        identify_received: 0,
        listener_errors: 0,
        ip_rate_limited: 0,
        prev_minute_circuits_denied: 0,
        prev_minute_circuits_accepted: 0,
        prev_minute_reservations_denied: 0,
        circuits_denied_per_min: 0,
        circuits_accepted_per_min: 0,
        reservations_denied_per_min: 0,
        peer_source_ips: HashMap::new(),
        peers_with_reservation: HashSet::new(),
    }));

    // ── Start Metrics HTTP Server ────────────────────────────────────
    tokio::spawn(run_metrics_server(
        metrics.clone(),
        registry_store.clone(),
        args.metrics_port,
    ));

    // ── Build Swarm ──────────────────────────────────────────────────
    let mut swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .expect("TCP transport")
        .with_quic()
        .with_behaviour(|key| build_behaviour(key))
        .expect("swarm behaviour")
        .with_swarm_config(|c| {
            c.with_idle_connection_timeout(IDLE_CONNECTION_TIMEOUT)
                .with_max_negotiating_inbound_streams(128)
        })
        .build();

    // Warm-load mirrored DHT records so the registry survives restarts.
    if let Some(store) = registry_store.as_ref().and_then(|s| s.lock().ok()) {
        let records = store.load_kad_records();
        let n = records.len();
        for (key, value) in records {
            let record = kad::Record {
                key: kad::RecordKey::new(&key),
                value,
                publisher: None,
                expires: None,
            };
            use libp2p::kad::store::RecordStore;
            let _ = swarm.behaviour_mut().kademlia.store_mut().put(record);
        }
        if n > 0 {
            log::info!("Warm-loaded {n} DHT records from disk");
        }
    }

    // ── Listen Addresses ─────────────────────────────────────────────

    // IPv4 TCP
    let tcp_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", args.port)
        .parse()
        .expect("valid TCP multiaddr");
    swarm.listen_on(tcp_addr).expect("TCP listen");

    // IPv4 QUIC
    let quic_addr: Multiaddr = format!("/ip4/0.0.0.0/udp/{}/quic-v1", args.quic_port)
        .parse()
        .expect("valid QUIC multiaddr");
    swarm.listen_on(quic_addr).expect("QUIC listen");

    // IPv6 TCP (best-effort)
    if let Ok(addr) = format!("/ip6/::/tcp/{}", args.port).parse::<Multiaddr>() {
        let _ = swarm.listen_on(addr);
    }

    // IPv6 QUIC (best-effort)
    if let Ok(addr) = format!("/ip6/::/udp/{}/quic-v1", args.quic_port).parse::<Multiaddr>() {
        let _ = swarm.listen_on(addr);
    }

    // Register external addresses so reservation responses include
    // dialable multiaddrs. libp2p-relay sends `self.external_addresses`
    // to the client in the reservation accept; an empty list causes the
    // client to reject with `NoAddressesInReservation` and the circuit
    // listener to close — meaning no one can be circuit-dialed via us.
    let mut external_registered: Vec<String> = Vec::new();
    if let Some(host) = &args.public_host {
        // DNS forms. These survive Fly.io re-provisioning since Fly DNS
        // tracks the current IP.
        for tmpl in [
            format!("/dns4/{host}/tcp/{}", args.port),
            format!("/dns4/{host}/udp/{}/quic-v1", args.quic_port),
        ] {
            if let Ok(addr) = tmpl.parse::<Multiaddr>() {
                external_registered.push(addr.to_string());
                swarm.add_external_address(addr);
            }
        }

        // IP literal forms for clients whose DNS is blocked. Resolve at
        // startup rather than hardcoding so the addresses stay current
        // across Fly.io re-provisioning — each relay restart picks up
        // whatever IP the DNS name currently points at.
        match tokio::net::lookup_host(format!("{host}:{}", args.port)).await {
            Ok(addrs) => {
                for sa in addrs {
                    let ip = sa.ip();
                    let forms = match ip {
                        IpAddr::V4(v4) => vec![
                            format!("/ip4/{v4}/tcp/{}", args.port),
                            format!("/ip4/{v4}/udp/{}/quic-v1", args.quic_port),
                        ],
                        IpAddr::V6(v6) => vec![
                            format!("/ip6/{v6}/tcp/{}", args.port),
                            format!("/ip6/{v6}/udp/{}/quic-v1", args.quic_port),
                        ],
                    };
                    for tmpl in forms {
                        if let Ok(addr) = tmpl.parse::<Multiaddr>() {
                            external_registered.push(addr.to_string());
                            swarm.add_external_address(addr);
                        }
                    }
                }
            }
            Err(e) => {
                log::warn!("Failed to resolve public_host {host}: {e}. DNS-only addrs will still be advertised.");
            }
        }
    }
    if external_registered.is_empty() {
        log::warn!(
            "No --public-host set; reservation responses will contain no addresses and \
             circuit clients will reject with NoAddressesInReservation. Set \
             RELAY_PUBLIC_HOST for production."
        );
    } else {
        log::info!("External addresses registered: {external_registered:?}");
    }

    log::info!(
        "Relay starting — TCP:{} QUIC/UDP:{} Metrics HTTP:{}",
        args.port,
        args.quic_port,
        args.metrics_port,
    );
    log::info!(
        "Limits — max_conn:{MAX_CONNECTIONS} max_conn/peer:{MAX_CONNECTIONS_PER_PEER} \
         max_conn/ip:{MAX_CONNECTIONS_PER_IP} \
         relay_reservations:{RELAY_MAX_RESERVATIONS} relay_circuits:{RELAY_MAX_CIRCUITS}"
    );

    // ── Event Loop ───────────────────────────────────────────────────

    let start_time = Instant::now();
    let mut total_connections_served: u64 = 0;
    let mut health_interval = tokio::time::interval(HEALTH_LOG_INTERVAL);
    health_interval.tick().await; // consume immediate tick

    // IP-level rate limiting state
    let mut ip_active_connections: HashMap<IpAddr, usize> = HashMap::new();
    let mut ip_rate_windows: HashMap<IpAddr, (usize, Instant)> = HashMap::new();

    // Graceful shutdown on SIGTERM/SIGINT
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("SIGTERM handler");
    let sigint = tokio::signal::ctrl_c();
    tokio::pin!(sigint);
    let mut shutdown = false;

    while !shutdown {
        tokio::select! {
            // Health logging
            _ = health_interval.tick() => {
                let uptime = start_time.elapsed();
                let hours = uptime.as_secs() / 3600;
                let minutes = (uptime.as_secs() % 3600) / 60;
                let connections = swarm.connected_peers().count();
                log::info!(
                    "HEALTH — uptime:{hours}h{minutes}m connections:{connections} \
                     total_served:{total_connections_served} peer_id:{local_peer_id}"
                );

                // Update metrics
                {
                    let mut m = metrics.write().await;
                    m.uptime_seconds = uptime.as_secs();
                    m.connections = connections;
                    m.total_connections_served = total_connections_served;
                }

                // Prune stale IP rate window entries
                let now = Instant::now();
                ip_rate_windows.retain(|_, (_, started)| now.duration_since(*started) < IP_RATE_WINDOW * 2);
            }
            // Graceful shutdown
            _ = sigterm.recv() => {
                log::info!("Received SIGTERM, shutting down gracefully...");
                shutdown = true;
            }
            _ = &mut sigint => {
                log::info!("Received SIGINT, shutting down gracefully...");
                shutdown = true;
            }
            // Swarm events
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        log::info!("Listening on {address}/p2p/{local_peer_id}");
                    }

                    // ── Connection Management ────────────────────────
                    SwarmEvent::ConnectionEstablished {
                        peer_id: pid,
                        endpoint,
                        ..
                    } => {
                        total_connections_served += 1;
                        let remote_addr = endpoint.get_remote_address();
                        log::debug!(
                            "CONNECT peer:{pid} endpoint:{remote_addr} total_served:{total_connections_served}"
                        );

                        // Record peer's WAN IP so /peers can publish it.
                        // We capture on every Established and overwrite on
                        // reconnect — last-known address wins.
                        if let Some(ip) = extract_ip(remote_addr) {
                            metrics.write().await.peer_source_ips.insert(pid, ip);
                        }

                        // IP-level rate limiting
                        if let Some(ip) = extract_ip(remote_addr) {
                            let active = ip_active_connections.entry(ip).or_insert(0);
                            *active += 1;

                            let (attempts, window_start) =
                                ip_rate_windows.entry(ip).or_insert((0, Instant::now()));
                            if window_start.elapsed() > IP_RATE_WINDOW {
                                *attempts = 0;
                                *window_start = Instant::now();
                            }
                            *attempts += 1;

                            if *active > MAX_CONNECTIONS_PER_IP
                                || *attempts > MAX_NEW_CONNS_PER_IP_PER_WINDOW
                            {
                                log::warn!(
                                    "IP rate limit exceeded for {ip} (active:{active}, attempts:{attempts}), \
                                     disconnecting {pid}"
                                );
                                let _ = swarm.disconnect_peer_id(pid);
                                let mut m = metrics.write().await;
                                m.ip_rate_limited += 1;
                            }
                        }

                        // Add to Kademlia routing table
                        swarm
                            .behaviour_mut()
                            .kademlia
                            .add_address(&pid, remote_addr.clone());
                    }
                    SwarmEvent::ConnectionClosed {
                        peer_id: pid,
                        num_established,
                        endpoint,
                        ..
                    } => {
                        // Decrement IP active connection count
                        if let Some(ip) = extract_ip(endpoint.get_remote_address()) {
                            if let Some(active) = ip_active_connections.get_mut(&ip) {
                                *active = active.saturating_sub(1);
                                if *active == 0 {
                                    ip_active_connections.remove(&ip);
                                }
                            }
                        }

                        // When the peer has zero remaining connections,
                        // forget the peer's WAN IP and reservation flag.
                        // (libp2p delivers `num_established` post-decrement.)
                        if num_established == 0 {
                            let mut m = metrics.write().await;
                            m.peer_source_ips.remove(&pid);
                            m.peers_with_reservation.remove(&pid);
                        }

                        log::debug!(
                            "DISCONNECT peer:{pid} remaining_for_peer:{num_established}"
                        );
                    }

                    // ── Identify ─────────────────────────────────────
                    SwarmEvent::Behaviour(RelayBehaviourEvent::Identify(
                        identify::Event::Received { peer_id: pid, info, .. },
                    )) => {
                        log::debug!(
                            "IDENTIFY peer:{pid} proto:{} agent:{}",
                            info.protocol_version,
                            info.agent_version
                        );
                        {
                            let mut m = metrics.write().await;
                            m.identify_received += 1;
                        }
                        // Add reported listen addresses to Kademlia, filtering
                        // out unroutable addresses and capping per-peer count.
                        let mut added = 0usize;
                        for addr in &info.listen_addrs {
                            if added >= MAX_ADDRS_PER_PEER {
                                break;
                            }
                            if is_globally_routable(addr) {
                                swarm
                                    .behaviour_mut()
                                    .kademlia
                                    .add_address(&pid, addr.clone());
                                added += 1;
                            }
                        }
                    }

                    // ── Relay Events ─────────────────────────────────
                    SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(event)) => {
                        match &event {
                            relay::Event::ReservationReqAccepted {
                                src_peer_id,
                                ..
                            } => {
                                log::info!("RELAY reservation accepted for {src_peer_id}");
                                let mut m = metrics.write().await;
                                m.reservations_accepted += 1;
                                m.peers_with_reservation.insert(*src_peer_id);
                            }
                            relay::Event::CircuitReqAccepted {
                                src_peer_id,
                                dst_peer_id,
                                ..
                            } => {
                                log::info!(
                                    "RELAY circuit {src_peer_id} → {dst_peer_id}"
                                );
                                let mut m = metrics.write().await;
                                m.circuits_accepted += 1;
                            }
                            relay::Event::CircuitClosed {
                                src_peer_id,
                                dst_peer_id,
                                ..
                            } => {
                                log::debug!(
                                    "RELAY circuit closed {src_peer_id} → {dst_peer_id}"
                                );
                                let mut m = metrics.write().await;
                                m.circuits_closed += 1;
                            }
                            relay::Event::ReservationReqDenied { src_peer_id, .. } => {
                                log::warn!("RELAY reservation denied for {src_peer_id}");
                                let mut m = metrics.write().await;
                                m.reservations_denied += 1;
                            }
                            relay::Event::CircuitReqDenied {
                                src_peer_id,
                                dst_peer_id,
                                ..
                            } => {
                                log::warn!(
                                    "RELAY circuit denied {src_peer_id} → {dst_peer_id}"
                                );
                                let mut m = metrics.write().await;
                                m.circuits_denied += 1;
                            }
                            _ => {
                                log::debug!("RELAY event: {event:?}");
                            }
                        }
                    }

                    // ── Kademlia Events ──────────────────────────────
                    SwarmEvent::Behaviour(RelayBehaviourEvent::Kademlia(event)) => {
                        match &event {
                            kad::Event::RoutingUpdated {
                                peer, addresses, ..
                            } => {
                                log::debug!(
                                    "KAD routing updated peer:{peer} addrs:{}",
                                    addresses.len()
                                );
                                let mut m = metrics.write().await;
                                m.kad_routing_updated += 1;
                            }
                            kad::Event::InboundRequest {
                                request:
                                    kad::InboundRequest::PutRecord {
                                        record: Some(record),
                                        ..
                                    },
                            } => {
                                // FilterBoth mode: store explicitly + mirror to
                                // disk so records survive relay restarts.
                                if record.value.len() <= KAD_MAX_RECORD_SIZE {
                                    if let Some(store) =
                                        registry_store.as_ref().and_then(|s| s.lock().ok())
                                    {
                                        store.save_kad_record(record.key.as_ref(), &record.value);
                                    }
                                    use libp2p::kad::store::RecordStore;
                                    let _ = swarm
                                        .behaviour_mut()
                                        .kademlia
                                        .store_mut()
                                        .put(record.clone());
                                }
                            }
                            kad::Event::InboundRequest { request } => {
                                log::debug!("KAD inbound request: {request:?}");
                            }
                            _ => {
                                log::trace!("KAD event: {event:?}");
                            }
                        }
                    }

                    // ── Username receipt requests ────────────────────
                    SwarmEvent::Behaviour(RelayBehaviourEvent::UsernameReg(
                        request_response::Event::Message {
                            peer,
                            message:
                                request_response::Message::Request {
                                    request, channel, ..
                                },
                            ..
                        },
                    )) => {
                        log::info!(
                            "username-reg: receipt request from {peer} for @{}",
                            request.claim.username
                        );
                        let response = match registry_store.as_ref().and_then(|s| s.lock().ok()) {
                            Some(mut store) => store.handle_receipt(
                                &signing_keypair,
                                &local_peer_id.to_string(),
                                &request.claim,
                            ),
                            None => ReceiptResponse::Refused {
                                reason: "registry store unavailable".to_string(),
                                existing_did: None,
                                existing_received_at: None,
                            },
                        };
                        let _ = swarm
                            .behaviour_mut()
                            .username_reg
                            .send_response(channel, response);
                    }
                    SwarmEvent::Behaviour(RelayBehaviourEvent::UsernameReg(event)) => {
                        log::debug!("username-reg event: {event:?}");
                    }

                    // ── Other Events ─────────────────────────────────
                    SwarmEvent::ListenerError { listener_id, error } => {
                        log::error!(
                            "Listener {listener_id:?} error: {error}"
                        );
                        let mut m = metrics.write().await;
                        m.listener_errors += 1;
                    }
                    SwarmEvent::ListenerClosed {
                        listener_id,
                        reason,
                        ..
                    } => {
                        log::warn!(
                            "Listener {listener_id:?} closed: {reason:?}"
                        );
                    }
                    _ => {}
                }
            }
        }
    }

    log::info!("Relay shutdown complete. Served {total_connections_served} total connections.");
}

// ── Metrics HTTP Server ─────────────────────────────────────────────

async fn run_metrics_server(
    metrics: Arc<RwLock<RelayMetrics>>,
    registry: Option<std::sync::Arc<std::sync::Mutex<RegistryStore>>>,
    port: u16,
) {
    // Sample rolling-minute deltas in the background. Lets /health/alerts
    // serve a denial-rate without external alerters doing delta math.
    {
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            tick.tick().await; // consume immediate tick
            loop {
                tick.tick().await;
                let mut m = metrics.write().await;
                m.circuits_denied_per_min = m
                    .circuits_denied
                    .saturating_sub(m.prev_minute_circuits_denied);
                m.circuits_accepted_per_min = m
                    .circuits_accepted
                    .saturating_sub(m.prev_minute_circuits_accepted);
                m.reservations_denied_per_min = m
                    .reservations_denied
                    .saturating_sub(m.prev_minute_reservations_denied);
                m.prev_minute_circuits_denied = m.circuits_denied;
                m.prev_minute_circuits_accepted = m.circuits_accepted;
                m.prev_minute_reservations_denied = m.reservations_denied;
            }
        });
    }

    let health_metrics = metrics.clone();
    let alerts_metrics = metrics.clone();
    let peers_metrics = metrics.clone();
    let full_metrics = metrics;

    let app = Router::new()
        .route(
            "/username/:name",
            get(
                move |axum::extract::Path(name): axum::extract::Path<String>| {
                    let registry = registry.clone();
                    async move {
                        let name = name.trim().trim_start_matches('@').to_lowercase();
                        let holder = registry.as_ref().and_then(|r| {
                            r.lock().ok().and_then(|store| store.lookup_username(&name))
                        });
                        match holder {
                            Some((did, received_at)) => Json(serde_json::json!({
                                "username": name,
                                "available": false,
                                "did": did,
                                "received_at": received_at,
                            })),
                            None => Json(serde_json::json!({
                                "username": name,
                                "available": true,
                            })),
                        }
                    }
                },
            ),
        )
        .route(
            "/health",
            get(move || {
                let m = health_metrics.clone();
                async move {
                    let lock = m.read().await;
                    Json(serde_json::json!({
                        "status": "ok",
                        "peer_id": lock.peer_id,
                        "uptime_seconds": lock.uptime_seconds,
                        "connections": lock.connections,
                    }))
                }
            }),
        )
        .route(
            "/health/alerts",
            get(move || {
                let m = alerts_metrics.clone();
                async move {
                    let lock = m.read().await;
                    // Thresholds chosen so a healthy relay sits at "ok"
                    // and a saturated one trips before clients notice.
                    let connections_ratio = lock.connections as f64 / MAX_CONNECTIONS as f64;
                    let denial_rate = lock.circuits_denied_per_min;
                    let accept_rate = lock.circuits_accepted_per_min;
                    let denial_share = if accept_rate + denial_rate == 0 {
                        0.0
                    } else {
                        denial_rate as f64 / (accept_rate + denial_rate) as f64
                    };

                    let mut alerts: Vec<&str> = Vec::new();
                    if connections_ratio > 0.8 {
                        alerts.push("connections_near_cap");
                    }
                    if denial_rate > 100 {
                        alerts.push("circuits_denied_per_min_high");
                    }
                    if denial_share > 0.5 && (denial_rate + accept_rate) > 20 {
                        alerts.push("circuit_denial_majority");
                    }
                    if lock.reservations_denied_per_min > 10 {
                        alerts.push("reservations_denied_per_min_high");
                    }
                    if lock.listener_errors > 0 {
                        alerts.push("listener_errors_observed");
                    }

                    let level = if alerts.is_empty() { "ok" } else { "warn" };
                    let status_code = if alerts.is_empty() {
                        axum::http::StatusCode::OK
                    } else {
                        // 503 makes most healthcheckers (UptimeRobot,
                        // healthchecks.io, Fly's own checks) flag the
                        // relay without manually parsing JSON.
                        axum::http::StatusCode::SERVICE_UNAVAILABLE
                    };
                    (
                        status_code,
                        Json(serde_json::json!({
                            "level": level,
                            "alerts": alerts,
                            "circuits_denied_per_min": denial_rate,
                            "circuits_accepted_per_min": accept_rate,
                            "circuit_denial_share": denial_share,
                            "reservations_denied_per_min": lock.reservations_denied_per_min,
                            "connections_ratio": connections_ratio,
                            "max_connections": MAX_CONNECTIONS,
                        })),
                    )
                }
            }),
        )
        .route(
            "/peers",
            get(move || {
                let m = peers_metrics.clone();
                async move {
                    let lock = m.read().await;
                    let entries: Vec<PeerSourceEntry> = lock
                        .peer_source_ips
                        .iter()
                        .map(|(pid, ip)| PeerSourceEntry {
                            peer_id: pid.to_string(),
                            source_ip: ip.to_string(),
                            has_reservation: lock.peers_with_reservation.contains(pid),
                        })
                        .collect();
                    Json(entries)
                }
            }),
        )
        .route(
            "/metrics",
            get(move || {
                let m = full_metrics.clone();
                async move {
                    let lock = m.read().await;
                    Json(lock.clone())
                }
            }),
        );

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect("bind metrics server");
    log::info!("Metrics server listening on 0.0.0.0:{port}");
    if let Err(e) = axum::serve(listener, app).await {
        log::error!("Metrics server error: {e}");
    }
}

// ── Address Validation ───────────────────────────────────────────────

/// Returns `true` if the multiaddr starts with a globally routable IP.
/// Rejects loopback, private (RFC 1918 / RFC 4193), link-local, and
/// unspecified addresses to prevent Kademlia routing table pollution.
fn is_globally_routable(addr: &Multiaddr) -> bool {
    match addr.iter().next() {
        Some(Protocol::Ip4(ip)) => {
            let ip = IpAddr::V4(ip);
            !(ip.is_loopback() || ip.is_unspecified() || is_private_v4(ip))
        }
        Some(Protocol::Ip6(ip)) => {
            let segments = ip.segments();
            !(IpAddr::V6(ip).is_loopback()
                || IpAddr::V6(ip).is_unspecified()
                // ULA: fc00::/7
                || (segments[0] & 0xfe00) == 0xfc00
                // Link-local: fe80::/10
                || (segments[0] & 0xffc0) == 0xfe80
                // IPv4-mapped: ::ffff:0:0/96
                || (segments[0] == 0
                    && segments[1] == 0
                    && segments[2] == 0
                    && segments[3] == 0
                    && segments[4] == 0
                    && segments[5] == 0xffff)
                // Multicast: ff00::/8
                || (segments[0] & 0xff00) == 0xff00
                // Deprecated site-local: fec0::/10
                || (segments[0] & 0xffc0) == 0xfec0)
        }
        // DNS addresses are allowed (e.g. /dns4/example.com/tcp/4001)
        Some(Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_)) => true,
        _ => false,
    }
}

/// Check if an IP is in a private/reserved range.
/// Covers RFC 1918 (10/8, 172.16/12, 192.168/16), link-local (169.254/16),
/// and CGNAT (100.64/10).
fn is_private_v4(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 10.0.0.0/8
            octets[0] == 10
            // 172.16.0.0/12
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))
            // 192.168.0.0/16
            || (octets[0] == 192 && octets[1] == 168)
            // 169.254.0.0/16 (link-local)
            || (octets[0] == 169 && octets[1] == 254)
            // 100.64.0.0/10 (CGNAT)
            || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        }
        _ => false,
    }
}

// ── Behaviour Builder ────────────────────────────────────────────────

fn build_behaviour(
    key: &libp2p::identity::Keypair,
) -> Result<RelayBehaviour, Box<dyn std::error::Error + Send + Sync>> {
    let local_peer_id = key.public().to_peer_id();

    // ── Connection Limits (enforced at transport layer) ──────────────
    let limits = libp2p_connection_limits::ConnectionLimits::default()
        .with_max_established(Some(MAX_CONNECTIONS as u32))
        .with_max_established_per_peer(Some(MAX_CONNECTIONS_PER_PEER));
    let connection_limits = libp2p_connection_limits::Behaviour::new(limits);

    // ── Circuit Relay v2 (server) ────────────────────────────────────
    // Rate-limited and resource-capped to prevent abuse.
    let relay_config = relay::Config {
        max_reservations: RELAY_MAX_RESERVATIONS,
        max_circuits: RELAY_MAX_CIRCUITS,
        max_reservations_per_peer: RELAY_MAX_RESERVATIONS_PER_PEER,
        max_circuits_per_peer: RELAY_MAX_CIRCUITS_PER_PEER,
        max_circuit_bytes: RELAY_MAX_CIRCUIT_BYTES,
        max_circuit_duration: RELAY_MAX_CIRCUIT_DURATION,
        reservation_duration: RELAY_RESERVATION_DURATION,
        ..Default::default()
    };
    let relay = relay::Behaviour::new(local_peer_id, relay_config);

    // ── Kademlia DHT ─────────────────────────────────────────────────
    // Private Alexandria DHT (`/alexandria/kad/1.0`).
    // The relay always runs in server mode — it's the bootstrap node.
    let mut kademlia_config = kad::Config::new(libp2p::StreamProtocol::new("/alexandria/kad/1.0"));
    kademlia_config.set_query_timeout(KAD_QUERY_TIMEOUT);
    kademlia_config.set_replication_factor(NonZeroUsize::new(KAD_REPLICATION_FACTOR).unwrap());
    // Cap the in-memory store to prevent unbounded growth
    kademlia_config.set_max_packet_size(KAD_MAX_RECORD_SIZE);
    // Surface inbound PutRecord requests so the event loop can store
    // them explicitly and mirror them to disk (MemoryStore alone loses
    // everything on restart).
    kademlia_config.set_record_filtering(kad::StoreInserts::FilterBoth);

    let store_config = kad::store::MemoryStoreConfig {
        max_records: KAD_MAX_RECORDS,
        max_value_bytes: KAD_MAX_RECORD_SIZE,
        ..Default::default()
    };

    let store = MemoryStore::with_config(local_peer_id, store_config);
    let mut kademlia = kad::Behaviour::with_config(local_peer_id, store, kademlia_config);
    kademlia.set_mode(Some(kad::Mode::Server));

    // ── Username receipt protocol ────────────────────────────────────
    let username_reg = request_response::cbor::Behaviour::<ReceiptRequest, ReceiptResponse>::new(
        [(
            StreamProtocol::new(username_reg::PROTOCOL),
            ProtocolSupport::Inbound,
        )],
        request_response::Config::default(),
    );

    // ── Identify ─────────────────────────────────────────────────────
    let identify = identify::Behaviour::new(
        identify::Config::new("/alexandria/id/1.0".to_string(), key.public())
            .with_push_listen_addr_updates(true)
            .with_agent_version(format!("alexandria-relay/{}", env!("CARGO_PKG_VERSION"))),
    );

    Ok(RelayBehaviour {
        connection_limits,
        relay,
        kademlia,
        identify,
        username_reg,
    })
}
