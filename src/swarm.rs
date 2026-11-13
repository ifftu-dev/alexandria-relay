//! Swarm: behaviour construction and the event loop.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Instant;

use futures::StreamExt;
use libp2p::identity::Keypair;
use libp2p::kad::store::MemoryStore;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{identify, kad, noise, relay, yamux, Multiaddr, PeerId, StreamProtocol, SwarmBuilder};
use tokio::sync::RwLock;
use zeroize::Zeroizing;

use crate::addr::{extract_ip, is_globally_routable};
use crate::config::*;
use crate::http::{run_metrics_server, RelayMetrics};
use crate::store::RegistryStore;
use crate::username_reg::{self, ReceiptRequest, ReceiptResponse};

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

pub async fn run(args: Args, seed: Option<Zeroizing<String>>) {
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
    // Per-peer rate limiting for username-receipt requests. Keyed by PeerId
    // rather than IP because the claim is bound to a DID, not to a network
    // location, and the connection-level IP limiter already covers the
    // network side.
    let mut username_rate_windows: HashMap<PeerId, (usize, Instant)> = HashMap::new();

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
                username_rate_windows
                    .retain(|_, (_, started)| now.duration_since(*started) < USERNAME_RATE_WINDOW * 2);
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
                        accept_provider_announcement(&mut swarm.behaviour_mut().kademlia, &event);
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
                                //
                                // Offer to the memory store FIRST and mirror only
                                // what it accepted. The memory store enforces
                                // KAD_MAX_RECORDS; mirroring before that check
                                // meant records it rejected were still written to
                                // disk, so the SQLite table had no ceiling at all
                                // and an attacker could fill the volume with
                                // unique keys at 64 KB apiece.
                                if record.value.len() <= KAD_MAX_RECORD_SIZE {
                                    use libp2p::kad::store::RecordStore;
                                    let accepted = swarm
                                        .behaviour_mut()
                                        .kademlia
                                        .store_mut()
                                        .put(record.clone())
                                        .is_ok();
                                    if accepted {
                                        if let Some(store) =
                                            registry_store.as_ref().and_then(|s| s.lock().ok())
                                        {
                                            store.save_kad_record(
                                                record.key.as_ref(),
                                                &record.value,
                                            );
                                        }
                                    }
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
                        // Per-peer budget. Claim signatures are free to mint
                        // offline, so without this one connection can receipt
                        // the whole namespace.
                        let (count, window_start) = username_rate_windows
                            .entry(peer)
                            .or_insert((0, Instant::now()));
                        if window_start.elapsed() > USERNAME_RATE_WINDOW {
                            *count = 0;
                            *window_start = Instant::now();
                        }
                        *count += 1;
                        let rate_limited = *count > USERNAME_RATE_LIMIT;
                        if rate_limited {
                            log::warn!(
                                "username-reg: rate limiting {peer} ({count} requests in window)"
                            );
                        }

                        let response = if rate_limited {
                            ReceiptResponse::Refused {
                                reason: "too many username claims — try again shortly".to_string(),
                                existing_did: None,
                                existing_received_at: None,
                            }
                        } else {
                            match registry_store.as_ref().and_then(|s| s.lock().ok()) {
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
                            }
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

// ── Behaviour Builder ────────────────────────────────────────────────

fn accept_provider_announcement(kademlia: &mut kad::Behaviour<MemoryStore>, event: &kad::Event) {
    if let kad::Event::InboundRequest {
        request: kad::InboundRequest::AddProvider {
            record: Some(record),
        },
    } = event
    {
        use libp2p::kad::store::RecordStore;
        if let Err(error) = kademlia.store_mut().add_provider(record.clone()) {
            log::warn!("DHT provider announcement rejected by bounded store: {error}");
        }
    }
}

/// Wire codec for `/alexandria/username-reg/1.0`, with the request size capped
/// at [`USERNAME_REQUEST_MAX_BYTES`]. A request over the cap is read only up to
/// the cap, fails to decode, and the stream is dropped without a response.
type UsernameRegCodec = request_response::cbor::codec::Codec<ReceiptRequest, ReceiptResponse>;

fn username_reg_codec() -> UsernameRegCodec {
    UsernameRegCodec::default().set_request_size_maximum(USERNAME_REQUEST_MAX_BYTES)
}

fn build_behaviour(
    key: &libp2p::identity::Keypair,
) -> Result<RelayBehaviour, Box<dyn std::error::Error + Send + Sync>> {
    let local_peer_id = key.public().to_peer_id();

    // ── Connection Limits (enforced at transport layer) ──────────────
    let limits = libp2p_connection_limits::ConnectionLimits::default()
        .with_max_pending_incoming(Some(MAX_PENDING_INCOMING))
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
    let username_reg = request_response::cbor::Behaviour::with_codec(
        username_reg_codec(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn filtered_provider_announcements_are_retained_for_discovery() {
        use libp2p::kad::store::RecordStore;
        let identity = libp2p::identity::Keypair::generate_ed25519();
        let mut behaviour = build_behaviour(&identity).unwrap();
        let provider = PeerId::random();
        let key = kad::RecordKey::new(&b"alexandria-discovery-test");
        let address = "/ip4/203.0.113.1/tcp/4001".parse().unwrap();
        let expires = Some(std::time::Instant::now() + Duration::from_secs(60));
        let announcement = kad::ProviderRecord {
            key: key.clone(),
            provider,
            expires,
            addresses: vec![address],
        };
        assert!(behaviour.kademlia.store_mut().providers(&key).is_empty());
        accept_provider_announcement(
            &mut behaviour.kademlia,
            &kad::Event::InboundRequest {
                request: kad::InboundRequest::AddProvider {
                    record: Some(announcement.clone()),
                },
            },
        );
        let stored = behaviour.kademlia.store_mut().providers(&key);
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].provider, provider);
        assert_eq!(stored[0].addresses, announcement.addresses);
        assert_eq!(stored[0].expires, expires);
        accept_provider_announcement(
            &mut behaviour.kademlia,
            &kad::Event::InboundRequest {
                request: kad::InboundRequest::AddProvider {
                    record: Some(announcement),
                },
            },
        );
        assert_eq!(behaviour.kademlia.store_mut().providers(&key).len(), 1);
    }

    #[test]
    fn provider_announcements_still_respect_store_capacity() {
        use libp2p::kad::store::{MemoryStoreConfig, RecordStore};
        let local = PeerId::random();
        let store = MemoryStore::with_config(
            local,
            MemoryStoreConfig {
                max_provided_keys: 1,
                ..Default::default()
            },
        );
        let mut kademlia = kad::Behaviour::new(local, store);
        for value in [b"first", b"other"] {
            accept_provider_announcement(
                &mut kademlia,
                &kad::Event::InboundRequest {
                    request: kad::InboundRequest::AddProvider {
                        record: Some(kad::ProviderRecord {
                            key: kad::RecordKey::new(value),
                            provider: PeerId::random(),
                            expires: None,
                            addresses: vec![],
                        }),
                    },
                },
            );
        }
        assert_eq!(
            kademlia
                .store_mut()
                .providers(&kad::RecordKey::new(&b"first"))
                .len(),
            1
        );
        assert!(kademlia
            .store_mut()
            .providers(&kad::RecordKey::new(&b"other"))
            .is_empty());
    }

    /// The request shape the app sends: its claim carries a `receipts` list
    /// (one per relay that has already countersigned), which the relay's own
    /// claim type does not model and ignores.
    #[derive(serde::Serialize, serde::Deserialize)]
    struct AppReceiptRequest {
        claim: AppClaim,
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    struct AppClaim {
        version: u32,
        username: String,
        did: String,
        claimed_at: i64,
        sig: String,
        receipts: Vec<username_reg::RelayReceipt>,
    }

    fn app_request(username: &str, receipts: usize) -> AppReceiptRequest {
        AppReceiptRequest {
            claim: AppClaim {
                version: 1,
                username: username.to_string(),
                did: format!("did:key:z6Mk{}", "a".repeat(44)),
                claimed_at: 1_700_000_000,
                sig: "ab".repeat(64),
                receipts: (0..receipts)
                    .map(|_| username_reg::RelayReceipt {
                        relay_peer_id: PeerId::random().to_string(),
                        received_at: 1_700_000_000,
                        sig: "cd".repeat(64),
                    })
                    .collect(),
            },
        }
    }

    /// Encode `request` the way the app's codec does, then read it with the
    /// relay's codec.
    fn read_with_relay_codec(request: AppReceiptRequest) -> std::io::Result<ReceiptRequest> {
        use libp2p::request_response::Codec;
        futures::executor::block_on(async {
            let protocol = StreamProtocol::new(username_reg::PROTOCOL);
            let mut app_codec = request_response::cbor::codec::Codec::<
                AppReceiptRequest,
                ReceiptResponse,
            >::default();
            let mut wire = Vec::new();
            app_codec
                .write_request(&protocol, &mut wire, request)
                .await
                .unwrap();
            username_reg_codec()
                .read_request(&protocol, &mut futures::io::Cursor::new(wire))
                .await
        })
    }

    #[test]
    fn the_receipt_codec_reads_a_realistic_claim() {
        // Thirty relays' receipts is far more than the network runs; it must
        // still fit, or the cap would refuse real refreshes.
        let decoded = read_with_relay_codec(app_request("ada_99", 30)).unwrap();
        assert_eq!(decoded.claim.username, "ada_99");
    }

    #[test]
    fn the_receipt_codec_refuses_a_request_over_the_cap() {
        // Without the cap the codec reads up to 1 MiB per request.
        let oversized = "a".repeat(USERNAME_REQUEST_MAX_BYTES as usize);
        assert!(read_with_relay_codec(app_request(&oversized, 0)).is_err());
    }
}
