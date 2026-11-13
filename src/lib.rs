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

mod addr;
pub mod config;
mod http;
mod store;
mod swarm;
pub mod username_reg;

pub use swarm::run;
