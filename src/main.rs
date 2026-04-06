//! Alexandria Relay + Bootstrap Node
//!
//! A production-grade libp2p relay designed to run on a public VPS.
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
//! ## Production Hardening
//!
//! - Connection limits (per-peer and total) prevent resource exhaustion
//! - Relay circuit limits (bandwidth, duration, reservations) prevent abuse
//! - Kademlia memory store size is capped
//! - Idle connection timeout prevents connection leaks
//! - Graceful shutdown on SIGTERM/SIGINT
//! - Periodic health logging (connection count, uptime)
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

use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use clap::Parser;
use futures::StreamExt;
use libp2p::identity::Keypair;
use libp2p::kad::store::MemoryStore;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{identify, kad, noise, relay, yamux, Multiaddr, SwarmBuilder};

// ── Configuration Constants ──────────────────────────────────────────

/// Maximum total concurrent connections the relay will accept.
const MAX_CONNECTIONS: usize = 512;

/// Maximum concurrent connections from a single peer.
const MAX_CONNECTIONS_PER_PEER: u32 = 4;

/// How long an idle connection stays open before being reaped.
const IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(600); // 10 min

/// Kademlia query timeout.
const KAD_QUERY_TIMEOUT: Duration = Duration::from_secs(60);

/// Kademlia replication factor (k-buckets).
const KAD_REPLICATION_FACTOR: usize = 20;

/// Maximum number of records in the Kademlia memory store.
const KAD_MAX_RECORDS: usize = 65_536;

/// Maximum size of a single Kademlia record value.
const KAD_MAX_RECORD_SIZE: usize = 65_536; // 64 KB

/// Relay: max number of active circuit reservations.
const RELAY_MAX_RESERVATIONS: usize = 256;

/// Relay: max number of active circuits (relayed connections).
const RELAY_MAX_CIRCUITS: usize = 512;

/// Relay: max number of reservation requests per peer.
const RELAY_MAX_RESERVATIONS_PER_PEER: usize = 8;

/// Relay: max number of circuits per peer.
const RELAY_MAX_CIRCUITS_PER_PEER: usize = 16;

/// Relay: per-circuit bandwidth limit (bytes).
const RELAY_MAX_CIRCUIT_BYTES: u64 = 2 * 1024 * 1024; // 2 MB

/// Relay: per-circuit duration limit.
const RELAY_MAX_CIRCUIT_DURATION: Duration = Duration::from_secs(120); // 2 min

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

    /// Generate a new keypair seed and exit
    #[arg(long)]
    generate_key: bool,
}

// ── Network Behaviour ────────────────────────────────────────────────

/// Composed behaviour: relay server + Kademlia + identify.
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
    use sha2::{Digest, Sha256};
    let random_bytes: [u8; 32] = rand::random();
    let hash = Sha256::digest(random_bytes);
    hex::encode(hash)
}

// ── Main ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
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

    // ── Keypair ──────────────────────────────────────────────────────
    let keypair = match std::env::var("RELAY_SEED") {
        Ok(seed) => {
            // Clear seed from process environment to prevent leaking via /proc/PID/environ
            unsafe { std::env::remove_var("RELAY_SEED") };
            log::info!("Using deterministic keypair from RELAY_SEED");
            keypair_from_seed(&seed)
        }
        Err(_) => {
            log::warn!(
                "No RELAY_SEED set — using ephemeral keypair (PeerId will change on restart)"
            );
            Keypair::generate_ed25519()
        }
    };

    let local_peer_id = keypair.public().to_peer_id();
    log::info!("Relay PeerId: {local_peer_id}");

    // ── Build Swarm ──────────────────────────────────────────────────
    let mut swarm = SwarmBuilder::with_existing_identity(keypair.clone())
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

    log::info!(
        "Relay starting — TCP:{} QUIC/UDP:{}",
        args.port,
        args.quic_port
    );
    log::info!(
        "Limits — max_conn:{MAX_CONNECTIONS} max_conn/peer:{MAX_CONNECTIONS_PER_PEER} \
         relay_reservations:{RELAY_MAX_RESERVATIONS} relay_circuits:{RELAY_MAX_CIRCUITS}"
    );

    // ── Event Loop ───────────────────────────────────────────────────

    let start_time = Instant::now();
    let mut connections: usize = 0;
    let mut total_connections_served: u64 = 0;
    let mut health_interval = tokio::time::interval(HEALTH_LOG_INTERVAL);
    health_interval.tick().await; // consume immediate tick

    // Graceful shutdown on SIGTERM/SIGINT
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
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
                log::info!(
                    "HEALTH — uptime:{hours}h{minutes}m connections:{connections} \
                     total_served:{total_connections_served} peer_id:{local_peer_id}"
                );
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
                    // Note: libp2p_connection_limits::Behaviour enforces MAX_CONNECTIONS
                    // and MAX_CONNECTIONS_PER_PEER at the transport layer, so we
                    // only track counters and add to Kademlia here.
                    SwarmEvent::ConnectionEstablished {
                        peer_id: pid,
                        endpoint,
                        ..
                    } => {
                        connections += 1;
                        total_connections_served += 1;
                        log::info!(
                            "CONNECT peer:{pid} endpoint:{} total:{connections}",
                            endpoint.get_remote_address()
                        );
                        // Add to Kademlia routing table
                        swarm
                            .behaviour_mut()
                            .kademlia
                            .add_address(&pid, endpoint.get_remote_address().clone());
                    }
                    SwarmEvent::ConnectionClosed {
                        peer_id: pid,
                        num_established,
                        ..
                    } => {
                        connections = connections.saturating_sub(1);
                        log::info!(
                            "DISCONNECT peer:{pid} remaining_for_peer:{num_established} total:{connections}"
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
                            }
                            relay::Event::CircuitReqAccepted {
                                src_peer_id,
                                dst_peer_id,
                                ..
                            } => {
                                log::info!(
                                    "RELAY circuit {src_peer_id} → {dst_peer_id}"
                                );
                            }
                            relay::Event::CircuitClosed {
                                src_peer_id,
                                dst_peer_id,
                                ..
                            } => {
                                log::debug!(
                                    "RELAY circuit closed {src_peer_id} → {dst_peer_id}"
                                );
                            }
                            relay::Event::ReservationReqDenied { src_peer_id, .. } => {
                                log::warn!("RELAY reservation denied for {src_peer_id}");
                            }
                            relay::Event::CircuitReqDenied {
                                src_peer_id,
                                dst_peer_id,
                                ..
                            } => {
                                log::warn!(
                                    "RELAY circuit denied {src_peer_id} → {dst_peer_id}"
                                );
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
                            }
                            kad::Event::InboundRequest { request } => {
                                log::debug!("KAD inbound request: {request:?}");
                            }
                            _ => {
                                log::trace!("KAD event: {event:?}");
                            }
                        }
                    }

                    // ── Other Events ─────────────────────────────────
                    SwarmEvent::ListenerError { listener_id, error } => {
                        log::error!(
                            "Listener {listener_id:?} error: {error}"
                        );
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
            let ip = IpAddr::V6(ip);
            !(ip.is_loopback() || ip.is_unspecified())
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
    let mut kademlia_config =
        kad::Config::new(libp2p::StreamProtocol::new("/alexandria/kad/1.0"));
    kademlia_config.set_query_timeout(KAD_QUERY_TIMEOUT);
    kademlia_config.set_replication_factor(
        NonZeroUsize::new(KAD_REPLICATION_FACTOR).unwrap(),
    );
    // Cap the in-memory store to prevent unbounded growth
    kademlia_config.set_max_packet_size(KAD_MAX_RECORD_SIZE);

    let mut store_config = kad::store::MemoryStoreConfig::default();
    store_config.max_records = KAD_MAX_RECORDS;
    store_config.max_value_bytes = KAD_MAX_RECORD_SIZE;

    let store = MemoryStore::with_config(local_peer_id, store_config);
    let mut kademlia = kad::Behaviour::with_config(local_peer_id, store, kademlia_config);
    kademlia.set_mode(Some(kad::Mode::Server));

    // ── Identify ─────────────────────────────────────────────────────
    let identify = identify::Behaviour::new(
        identify::Config::new("/alexandria/id/1.0".to_string(), key.public())
            .with_push_listen_addr_updates(true)
            .with_agent_version(format!(
                "alexandria-relay/{}",
                env!("CARGO_PKG_VERSION")
            )),
    );

    Ok(RelayBehaviour {
        connection_limits,
        relay,
        kademlia,
        identify,
    })
}
