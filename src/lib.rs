//! Alexandria Relay + Bootstrap Node
//!
//! A libp2p relay designed to run on a public VPS.
//! Provides three critical services for the Alexandria P2P network:
//!
//! 1. **Circuit Relay v2** — NATted peers (phones, laptops behind routers)
//!    can relay traffic through this node to reach each other.
//!
//! 2. **Kademlia DHT** — Uses the private `/alexandria/kad/1.0` protocol.
//!    Peers enter the routing table from the routable addresses they report
//!    through Identify, never from a connection's source address. The relay
//!    always runs in Kademlia server mode (publicly reachable bootstrap
//!    node).
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
//!
//! # Join the network's relay mesh, and advertise this relay for discovery
//! alexandria-relay --network-profile preprod.json --announce
//! ```

//!
//! ## Library seam
//!
//! [`start`] runs a whole relay from a [`RelayConfig`] and returns a
//! [`RelayHandle`]. The binary calls it and waits for a signal; the
//! black-box tests call it on ephemeral loopback ports.

mod addr;
pub mod config;
pub mod doctor;
mod http;
mod mesh;
pub mod profile;
mod store;
mod swarm;
pub mod username_reg;

use std::net::SocketAddr;
use std::sync::Arc;

use libp2p::identity::Keypair;
use libp2p::{Multiaddr, PeerId};
use tokio::sync::{watch, RwLock};
use tokio::task::JoinHandle;

pub use config::{Cli, Limits, RelayConfig};

use crate::http::RelayMetrics;
use crate::store::{RegistryStore, StoreHandle};

/// Why [`start`] could not bring the relay up.
pub type StartError = Box<dyn std::error::Error + Send + Sync>;

/// A running relay. Dropping it without [`RelayHandle::shutdown`] also stops
/// the relay, without waiting for it.
pub struct RelayHandle {
    peer_id: PeerId,
    listen_addrs: Vec<Multiaddr>,
    external_addrs: Vec<Multiaddr>,
    http_addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
    store: Option<StoreHandle>,
}

impl RelayHandle {
    /// The relay's PeerId.
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// The libp2p addresses the IPv4 listeners reported at startup, with
    /// real ports where port zero was configured.
    pub fn listen_addrs(&self) -> &[Multiaddr] {
        &self.listen_addrs
    }

    /// The external addresses registered from `--public-host` (DNS forms
    /// and the IPs the name resolved to at startup): the set reservation
    /// responses carry. Empty without a public host.
    pub fn external_addrs(&self) -> &[Multiaddr] {
        &self.external_addrs
    }

    /// The address the HTTP listener is bound to.
    pub fn http_addr(&self) -> SocketAddr {
        self.http_addr
    }

    /// Shut down gracefully — the same path SIGTERM takes in the binary —
    /// and wait until the event loop and HTTP server have stopped and the
    /// store has written everything queued to it.
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        for task in self.tasks {
            let _ = task.await;
        }
        if let Some(store) = self.store {
            store.close().await;
        }
    }
}

/// Start a relay: open the store, bind the HTTP and libp2p listeners,
/// register external addresses and spawn the event loop. Returns once every
/// listener is bound. Must be called inside a Tokio runtime.
pub async fn start(config: RelayConfig) -> Result<RelayHandle, StartError> {
    if config.announce && config.network_profile.is_none() {
        let why = "--announce needs --network-profile: the relay-discovery key comes \
                   from the profile's protocol namespace";
        return Err(why.into());
    }
    let profile = match &config.network_profile {
        Some(path) => Some(profile::NetworkProfile::load(path)?),
        None => None,
    };

    // ── Keypair ──────────────────────────────────────────────────────
    let keypair = match config.keypair.clone() {
        Some(k) => {
            log::info!("Using deterministic keypair from RELAY_SEED");
            k
        }
        None => {
            log::warn!(
                "No RELAY_SEED set — using ephemeral keypair (PeerId will change on restart)"
            );
            Keypair::generate_ed25519()
        }
    };
    let peer_id = keypair.public().to_peer_id();
    log::info!("Relay PeerId: {peer_id}");

    // ── Persistent registry store ────────────────────────────────────
    // Username receipts + mirrored DHT records, on the store's own thread.
    let opened = RegistryStore::open(&config.data_dir).and_then(|s| {
        let s = s.with_kad_caps(
            config.limits.kad_max_records,
            config.limits.kad_max_record_bytes,
        );
        StoreHandle::spawn(s, keypair.clone()).map_err(|e| format!("spawn store thread: {e}"))
    });
    let registry_store = match opened {
        Ok(store) => {
            log::info!(
                "Registry store at {:?} ({} receipts)",
                config.data_dir,
                store.receipt_count().await.unwrap_or(0)
            );
            // Shared with the HTTP server: /username/:name lets clients
            // check availability over plain HTTPS before they have a
            // P2P identity (signup-time check).
            Some(store)
        }
        Err(e) => {
            log::error!("Registry store unavailable ({e}) — receipts disabled this run");
            None
        }
    };

    let metrics = Arc::new(RwLock::new(RelayMetrics {
        peer_id: peer_id.to_string(),
        bootstrap_status: if profile.is_some() {
            mesh::BootstrapStatus::Pending
        } else {
            mesh::BootstrapStatus::Disabled
        }
        .as_str(),
        started: Some(std::time::Instant::now()),
        ..RelayMetrics::default()
    }));
    let (shutdown, shutdown_rx) = watch::channel(false);

    // ── HTTP server ──────────────────────────────────────────────────
    let http_listener =
        tokio::net::TcpListener::bind(SocketAddr::new(config.metrics_bind, config.metrics_port))
            .await
            .map_err(|e| format!("bind HTTP listener: {e}"))?;
    let http_addr = http_listener.local_addr()?;
    let http_task = {
        let metrics = metrics.clone();
        let registry = registry_store.clone();
        let admin_token = config.admin_token.clone();
        let trusted_proxy_header = config.trusted_proxy_header.clone();
        let limits = config.limits.clone();
        let shutdown_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            http::serve(
                http_listener,
                metrics,
                registry,
                admin_token.as_deref(),
                trusted_proxy_header,
                &limits,
                shutdown_rx,
            )
            .await;
        })
    };

    // ── Swarm ────────────────────────────────────────────────────────
    let started = match swarm::start_swarm(
        &config,
        keypair,
        registry_store.clone(),
        metrics,
        http_addr.port(),
        profile,
    )
    .await
    {
        Ok(started) => started,
        Err(e) => {
            let _ = shutdown.send(true);
            let _ = http_task.await;
            if let Some(store) = registry_store {
                store.close().await;
            }
            return Err(e);
        }
    };
    let swarm_task = tokio::spawn(started.event_loop.run(shutdown_rx));

    Ok(RelayHandle {
        peer_id,
        listen_addrs: started.listen_addrs,
        external_addrs: started.external_addrs,
        http_addr,
        shutdown,
        tasks: vec![swarm_task, http_task],
        store: registry_store,
    })
}
