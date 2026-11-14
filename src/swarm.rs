//! Swarm: behaviour construction, startup (listeners, external addresses,
//! warm-loading the DHT mirror) and the event loop.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::future::BoxFuture;
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt};
use libp2p::core::transport::ListenerId;
use libp2p::core::ConnectedPoint;
use libp2p::identity::Keypair;
use libp2p::kad::store::MemoryStore;
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{identify, kad, noise, relay, yamux, Multiaddr, PeerId, StreamProtocol, SwarmBuilder};
use tokio::sync::{mpsc, watch, RwLock};

use crate::addr::{client_bucket, extract_ip, is_globally_routable, tcp_and_quic};
use crate::config::{Limits, RelayConfig, USERNAME_REQUEST_MAX_BYTES};
use crate::http::RelayMetrics;
use crate::mesh::{self, Mesh, Resolved};
use crate::profile::NetworkProfile;
use crate::rate::RateWindows;
use crate::store::{MirroredRecord, StoreHandle, MIRROR_PRUNE_INTERVAL};
use crate::username_reg::{self, ReceiptRequest, ReceiptResponse};
use crate::StartError;

/// How long startup waits for the IPv4 listeners to report their addresses.
const LISTEN_TIMEOUT: Duration = Duration::from_secs(10);

// ── Per-event logging ────────────────────────────────────────────────

/// The level of every per-event line: one per connection, Identify,
/// reservation, circuit, receipt request or Kademlia request. These grow
/// with traffic, so they stay below the default `info` filter; the counters
/// and the periodic health line carry their totals.
const EVENT_LEVEL: log::Level = log::Level::Debug;

/// Targets of the per-event lines, one per kind, all under
/// `alexandria_relay::event`: `RUST_LOG=alexandria_relay::event=debug` turns
/// every one on, `RUST_LOG=alexandria_relay::event::receipt=debug` one kind.
mod event_target {
    pub(super) const CONNECTION: &str = "alexandria_relay::event::connection";
    pub(super) const IDENTIFY: &str = "alexandria_relay::event::identify";
    pub(super) const RESERVATION: &str = "alexandria_relay::event::reservation";
    pub(super) const CIRCUIT: &str = "alexandria_relay::event::circuit";
    pub(super) const RECEIPT: &str = "alexandria_relay::event::receipt";
    pub(super) const KAD: &str = "alexandria_relay::event::kad";
}

/// Log a per-event line on `target` at [`EVENT_LEVEL`].
macro_rules! event {
    ($target:expr, $($arg:tt)+) => {
        log::log!(target: $target, EVENT_LEVEL, $($arg)+)
    };
}

type RelaySwarm = libp2p::Swarm<RelayBehaviour>;

// ── Network Behaviour ────────────────────────────────────────────────

/// Composed behaviour: relay server + Kademlia + identify + username-reg receipts.
///
/// Intentionally minimal — the relay does NOT run GossipSub, AutoNAT,
/// or DCUtR. It only needs enough to bootstrap peers into the DHT
/// and relay traffic for NATted peers.
#[derive(NetworkBehaviour)]
pub(crate) struct RelayBehaviour {
    connection_limits: libp2p_connection_limits::Behaviour,
    relay: relay::Behaviour,
    kademlia: kad::Behaviour<MemoryStore>,
    identify: identify::Behaviour,
    /// Username-claim receipts — `/alexandria/username-reg/1.0`.
    /// Inbound only: clients request, the relay countersigns.
    username_reg: request_response::cbor::Behaviour<ReceiptRequest, ReceiptResponse>,
}

// ── Startup ──────────────────────────────────────────────────────────

/// A swarm that is listening and ready to run, plus the addresses it bound.
pub(crate) struct Started {
    pub(crate) event_loop: EventLoop,
    pub(crate) listen_addrs: Vec<Multiaddr>,
    /// The external addresses registered from `--public-host`: what
    /// reservation responses carry.
    pub(crate) external_addrs: Vec<Multiaddr>,
}

/// Build the swarm, warm-load the DHT mirror, bind the listeners and register
/// external addresses. Returns once the IPv4 TCP and QUIC listeners have
/// reported their bound addresses (so port zero resolves to the real port).
/// With a `profile`, the event loop dials the profile's other relays as soon
/// as it runs.
pub(crate) async fn start_swarm(
    config: &RelayConfig,
    keypair: Keypair,
    registry_store: Option<StoreHandle>,
    metrics: Arc<RwLock<RelayMetrics>>,
    http_port: u16,
    profile: Option<NetworkProfile>,
) -> Result<Started, StartError> {
    let local_peer_id = keypair.public().to_peer_id();
    let limits = config.limits.clone();

    let mut swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| format!("TCP transport: {e}"))?
        .with_quic()
        .with_behaviour(|key| build_behaviour(key, &limits))
        .map_err(|e| format!("swarm behaviour: {e}"))?
        .with_swarm_config(|c| {
            c.with_idle_connection_timeout(limits.idle_timeout)
                .with_max_negotiating_inbound_streams(128)
        })
        .build();

    // Warm-load mirrored DHT records, with their expiry and publisher, so
    // the registry survives restarts. Expired rows are not returned.
    if let Some(store) = registry_store.as_ref() {
        let records = store.load_kad_records().await.unwrap_or_default();
        let n = records.len();
        for record in records {
            use libp2p::kad::store::RecordStore;
            let _ = swarm
                .behaviour_mut()
                .kademlia
                .store_mut()
                .put(record.into_kad());
        }
        if n > 0 {
            log::info!("Warm-loaded {n} DHT records from disk");
        }
    }

    // ── Listen Addresses ─────────────────────────────────────────────
    let ip4 = Multiaddr::empty().with(Protocol::Ip4(config.listen_ip4));
    let tcp4 = swarm
        .listen_on(ip4.clone().with(Protocol::Tcp(config.tcp_port)))
        .map_err(|e| format!("TCP listen: {e}"))?;
    let quic4 = swarm
        .listen_on(
            ip4.with(Protocol::Udp(config.quic_port))
                .with(Protocol::QuicV1),
        )
        .map_err(|e| format!("QUIC listen: {e}"))?;
    // IPv6 is best-effort: a host without it still runs on IPv4.
    if let Some(ip6) = config.listen_ip6 {
        let ip6 = Multiaddr::empty().with(Protocol::Ip6(ip6));
        let _ = swarm.listen_on(ip6.clone().with(Protocol::Tcp(config.tcp_port)));
        let _ = swarm.listen_on(
            ip6.with(Protocol::Udp(config.quic_port))
                .with(Protocol::QuicV1),
        );
    }

    let (resolved_tx, resolved_rx) = mpsc::unbounded_channel();
    let mesh = profile.map(|p| Mesh::new(&p, local_peer_id, config.announce, resolved_tx));

    let mut event_loop = EventLoop {
        swarm,
        mesh,
        resolved_rx,
        local_peer_id,
        registry_store,
        metrics,
        limits: config.limits.clone(),
        start_time: Instant::now(),
        total_connections_served: 0,
        ip_active_connections: HashMap::new(),
        ip_rate_windows: RateWindows::new(config.limits.ip_rate_window),
        username_rate_windows: RateWindows::new(config.limits.receipt_window),
        pending_receipts: FuturesUnordered::new(),
        health_baseline: HealthCounts::default(),
    };
    let listen_addrs = event_loop.await_listeners(&[tcp4, quic4]).await?;

    // Register external addresses so reservation responses include
    // dialable multiaddrs. libp2p-relay sends its external addresses to
    // the client in the reservation accept; an empty list causes the
    // client to reject with `NoAddressesInReservation` and the circuit
    // listener to close — meaning no one can be circuit-dialed via us.
    // The ports are the bound ones, which equal the configured ports
    // unless those were zero.
    let tcp_port = first_port(&listen_addrs, false).unwrap_or(config.tcp_port);
    let quic_port = first_port(&listen_addrs, true).unwrap_or(config.quic_port);
    let mut external_registered: Vec<Multiaddr> = Vec::new();
    if let Some(host) = &config.public_host {
        // DNS forms. These survive re-provisioning since DNS tracks the
        // current IP.
        for tmpl in [
            format!("/dns4/{host}/tcp/{tcp_port}"),
            format!("/dns4/{host}/udp/{quic_port}/quic-v1"),
        ] {
            if let Ok(addr) = tmpl.parse::<Multiaddr>() {
                external_registered.push(addr.clone());
                event_loop.swarm.add_external_address(addr);
            }
        }

        // IP literal forms for clients whose DNS is blocked. Resolve at
        // startup rather than hardcoding so the addresses stay current
        // across re-provisioning — each relay restart picks up whatever IP
        // the DNS name currently points at.
        match tokio::net::lookup_host(format!("{host}:{tcp_port}")).await {
            Ok(addrs) => {
                for sa in addrs {
                    for addr in tcp_and_quic(sa.ip(), tcp_port, quic_port) {
                        external_registered.push(addr.clone());
                        event_loop.swarm.add_external_address(addr);
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

    let l = &config.limits;
    log::info!("Relay starting — TCP:{tcp_port} QUIC/UDP:{quic_port} Metrics HTTP:{http_port}");
    log::info!(
        "Limits — max_conn:{} max_conn/peer:{} max_conn/ip:{} \
         relay_reservations:{} relay_circuits:{}",
        l.max_connections,
        l.max_connections_per_peer,
        l.max_connections_per_ip,
        l.max_reservations,
        l.max_circuits,
    );
    log::debug!("All limits: {l:?}");
    if let Some(mesh) = &event_loop.mesh {
        log::info!(
            "Mesh — joining through the network profile: {} other relay(s) to dial, \
             Kademlia bootstrap every {:?}",
            mesh.configured(),
            mesh::BOOTSTRAP_INTERVAL
        );
        event_loop.metrics.write().await.profile_relays = mesh.configured();
        if mesh.announce_key().is_some() {
            log::info!("{}", crate::config::ANNOUNCE_SCOPE);
            if config.public_host.is_none() {
                log::warn!(
                    "--announce without --public-host: the provider record carries no \
                     address, so app nodes learn only this relay's PeerId"
                );
            }
        }
    }

    Ok(Started {
        event_loop,
        listen_addrs,
        external_addrs: external_registered,
    })
}

/// The port of the first address on the TCP (`quic == false`) or QUIC
/// transport.
fn first_port(addrs: &[Multiaddr], quic: bool) -> Option<u16> {
    addrs.iter().find_map(|a| {
        let is_quic = a.iter().any(|p| matches!(p, Protocol::QuicV1));
        if is_quic != quic {
            return None;
        }
        a.iter().find_map(|p| match p {
            Protocol::Tcp(port) if !quic => Some(port),
            Protocol::Udp(port) if quic => Some(port),
            _ => None,
        })
    })
}

// ── Event Loop ───────────────────────────────────────────────────────

/// The relay's swarm and the state its event handlers keep.
pub(crate) struct EventLoop {
    swarm: RelaySwarm,
    /// Mesh membership from the network profile; `None` without one.
    mesh: Option<Mesh>,
    /// Finished DNS lookups of profile relays.
    resolved_rx: mpsc::UnboundedReceiver<Resolved>,
    local_peer_id: PeerId,
    registry_store: Option<StoreHandle>,
    metrics: Arc<RwLock<RelayMetrics>>,
    limits: Limits,
    start_time: Instant,
    total_connections_served: u64,
    /// IP-level rate limiting state.
    ip_active_connections: HashMap<IpAddr, usize>,
    ip_rate_windows: RateWindows<IpAddr>,
    /// Per-peer rate limiting for username-receipt requests. Keyed by PeerId
    /// rather than IP because the claim is bound to a DID, not to a network
    /// location, and the connection-level IP limiter already covers the
    /// network side.
    username_rate_windows: RateWindows<PeerId>,
    /// Receipt requests the store thread is still answering, each paired
    /// with the channel its response goes back on.
    pending_receipts: FuturesUnordered<PendingReceipt>,
    /// Counters as of the previous health line.
    health_baseline: HealthCounts,
}

/// The per-event counters the periodic health line reports deltas of.
#[derive(Debug, Default, Clone, Copy)]
struct HealthCounts {
    circuits_accepted: u64,
    circuits_denied: u64,
    reservations_accepted: u64,
    reservations_denied: u64,
    receipt_requests: u64,
}

impl HealthCounts {
    fn of(m: &RelayMetrics) -> Self {
        HealthCounts {
            circuits_accepted: m.circuits_accepted,
            circuits_denied: m.circuits_denied,
            reservations_accepted: m.reservations_accepted,
            reservations_denied: m.reservations_denied,
            receipt_requests: m.receipt_requests,
        }
    }

    fn since(&self, earlier: &HealthCounts) -> Self {
        HealthCounts {
            circuits_accepted: self
                .circuits_accepted
                .saturating_sub(earlier.circuits_accepted),
            circuits_denied: self.circuits_denied.saturating_sub(earlier.circuits_denied),
            reservations_accepted: self
                .reservations_accepted
                .saturating_sub(earlier.reservations_accepted),
            reservations_denied: self
                .reservations_denied
                .saturating_sub(earlier.reservations_denied),
            receipt_requests: self
                .receipt_requests
                .saturating_sub(earlier.receipt_requests),
        }
    }
}

/// A receipt response on its way back from the store thread.
type PendingReceipt = BoxFuture<
    'static,
    (
        request_response::ResponseChannel<ReceiptResponse>,
        ReceiptResponse,
    ),
>;

impl EventLoop {
    /// Drive the swarm until every listener in `ids` has reported at least
    /// one address, handling every event normally on the way. Returns all
    /// addresses reported meanwhile.
    async fn await_listeners(&mut self, ids: &[ListenerId]) -> Result<Vec<Multiaddr>, StartError> {
        let mut pending: HashSet<ListenerId> = ids.iter().copied().collect();
        let mut addrs = Vec::new();
        let deadline = tokio::time::Instant::now() + LISTEN_TIMEOUT;
        while !pending.is_empty() {
            let event = tokio::time::timeout_at(deadline, self.swarm.select_next_some())
                .await
                .map_err(|_| "timed out waiting for the listeners to bind")?;
            match &event {
                SwarmEvent::NewListenAddr {
                    listener_id,
                    address,
                } if ids.contains(listener_id) => {
                    // Only the listeners asked about: an IPv6 listener on
                    // port zero gets a port of its own.
                    pending.remove(listener_id);
                    addrs.push(address.clone());
                }
                SwarmEvent::ListenerClosed {
                    listener_id,
                    reason,
                    ..
                } if pending.contains(listener_id) => {
                    return Err(format!("listener closed during startup: {reason:?}").into());
                }
                _ => {}
            }
            self.on_event(event).await;
        }
        Ok(addrs)
    }

    /// Run until `shutdown` fires (or its sender is dropped).
    pub(crate) async fn run(mut self, mut shutdown: watch::Receiver<bool>) {
        let mut health_interval = tokio::time::interval(self.limits.health_log_interval);
        // Consume the immediate tick: the first health line comes one
        // interval in.
        health_interval.tick().await;
        // The first tick fires at once: prune whatever expired while the
        // relay was down.
        let mut prune_interval = tokio::time::interval(MIRROR_PRUNE_INTERVAL);

        // Both fire immediately: the first lookups are the startup dials.
        let mut redial_interval = tokio::time::interval(mesh::REDIAL_CHECK_INTERVAL);
        let mut bootstrap_interval = tokio::time::interval(mesh::BOOTSTRAP_INTERVAL);
        let meshed = self.mesh.is_some();

        // Announce at once, whatever the mesh looks like: a relay alone in
        // its profile, or whose peers are all down, still holds its own
        // provider record and serves it to the app nodes that reach it.
        // Kademlia republishes it on its provider-record interval from here
        // on, and joining the mesh announces again to reach the new peers.
        self.announce();

        loop {
            tokio::select! {
                _ = health_interval.tick() => self.on_health_tick().await,
                _ = prune_interval.tick() => {
                    if let Some(store) = &self.registry_store {
                        store.prune_expired();
                    }
                }
                _ = redial_interval.tick(), if meshed => {
                    if let Some(mesh) = self.mesh.as_mut() {
                        mesh.start_due_lookups();
                    }
                }
                _ = bootstrap_interval.tick(), if meshed => self.bootstrap("periodic"),
                Some((peer, addrs)) = self.resolved_rx.recv(), if meshed => {
                    self.on_resolved(peer, addrs).await;
                }
                _ = shutdown.changed() => break,
                Some((channel, response)) = self.pending_receipts.next(),
                    if !self.pending_receipts.is_empty() =>
                {
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .username_reg
                        .send_response(channel, response);
                }
                event = self.swarm.select_next_some() => self.on_event(event).await,
            }
        }

        log::info!(
            "Relay shutdown complete. Served {} total connections.",
            self.total_connections_served
        );
    }

    async fn on_health_tick(&mut self) {
        let uptime = self.start_time.elapsed();
        let hours = uptime.as_secs() / 3600;
        let minutes = (uptime.as_secs() % 3600) / 60;
        let connections = self.swarm.connected_peers().count();

        // Update metrics, and take the counts this line reports deltas of.
        let now_counts = {
            let mut m = self.metrics.write().await;
            m.uptime_seconds = uptime.as_secs();
            m.connections = connections;
            m.total_connections_served = self.total_connections_served;
            HealthCounts::of(&m)
        };
        let delta = now_counts.since(&self.health_baseline);
        self.health_baseline = now_counts;
        log::info!(
            "HEALTH — uptime:{hours}h{minutes}m connections:{connections} \
             total_served:{} since last: circuits +{} denied +{}, reservations +{} \
             denied +{}, receipt requests +{} peer_id:{}",
            self.total_connections_served,
            delta.circuits_accepted,
            delta.circuits_denied,
            delta.reservations_accepted,
            delta.reservations_denied,
            delta.receipt_requests,
            self.local_peer_id
        );

        // Prune stale rate window entries
        let now = Instant::now();
        self.ip_rate_windows
            .forget_older_than(now, self.limits.ip_rate_window * 2);
        self.username_rate_windows
            .forget_older_than(now, self.limits.receipt_window * 2);
    }

    /// A lookup of profile relay `peer` finished: dial it unless it is
    /// already connected, in which case only its addresses are refreshed.
    async fn on_resolved(&mut self, peer: PeerId, addrs: Vec<Multiaddr>) {
        let Some(mesh) = self.mesh.as_mut() else {
            return;
        };
        if !mesh.on_resolved(peer, addrs.clone()) {
            for addr in addrs {
                self.swarm.behaviour_mut().kademlia.add_address(&peer, addr);
            }
            return;
        }
        let opts = DialOpts::peer_id(peer)
            .addresses(addrs)
            .condition(PeerCondition::DisconnectedAndNotDialing)
            .build();
        match self.swarm.dial(opts) {
            Ok(()) => log::debug!("MESH dialling profile relay {peer}"),
            // Connected or being dialled already: its own events follow.
            Err(libp2p::swarm::DialError::DialPeerConditionFalse(_)) => {}
            Err(e) => {
                log::warn!("MESH cannot dial profile relay {peer}: {e}");
                mesh.on_dial_failed(&peer);
            }
        }
    }

    /// Profile relay `peer` opened a connection (`dialed` is the address
    /// when this relay dialled it). Puts its profile addresses in the routing
    /// table and, if this ends isolation, bootstraps and announces at once.
    async fn on_mesh_connected(&mut self, peer: PeerId, dialed: Option<Multiaddr>) {
        let Some(mesh) = self.mesh.as_mut() else {
            return;
        };
        let joined = mesh.on_connected(&peer);
        let mut addrs = mesh.addrs(&peer).to_vec();
        if addrs.is_empty() {
            // It reached us before our own lookup finished.
            addrs.extend(dialed);
            mesh.refresh_addrs(peer);
        }
        self.metrics.write().await.reachable_relays = mesh.reachable();
        log::info!("MESH connected to profile relay {peer}");
        for addr in addrs {
            self.swarm.behaviour_mut().kademlia.add_address(&peer, addr);
        }
        if joined {
            self.bootstrap("joined the mesh");
            self.announce();
        }
    }

    /// Start a Kademlia bootstrap. With no known peer there is nothing to
    /// bootstrap from yet; the status stays as it is.
    fn bootstrap(&mut self, reason: &str) {
        if self.mesh.is_none() {
            return;
        }
        match self.swarm.behaviour_mut().kademlia.bootstrap() {
            Ok(_) => log::debug!("MESH bootstrap started ({reason})"),
            Err(e) => log::debug!("MESH bootstrap skipped ({reason}): {e}"),
        }
    }

    /// Publish the provider record under the relay-discovery key, when
    /// announcing. Kademlia then republishes it on its provider-record
    /// publication interval.
    fn announce(&mut self) {
        let Some(key) = self.mesh.as_ref().and_then(|m| m.announce_key()).cloned() else {
            return;
        };
        match self.swarm.behaviour_mut().kademlia.start_providing(key) {
            Ok(_) => log::info!("MESH announced this relay under the relay-discovery key"),
            Err(e) => log::warn!("MESH announcement rejected by the local store: {e}"),
        }
    }

    async fn on_event(&mut self, event: SwarmEvent<RelayBehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                log::info!("Listening on {address}/p2p/{}", self.local_peer_id);
            }
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => self.on_connection_established(peer_id, &endpoint).await,
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established,
                endpoint,
                ..
            } => {
                self.on_connection_closed(peer_id, num_established, &endpoint)
                    .await
            }
            SwarmEvent::Behaviour(RelayBehaviourEvent::Identify(event)) => {
                self.on_identify(event).await
            }
            SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(event)) => self.on_relay(event).await,
            SwarmEvent::Behaviour(RelayBehaviourEvent::Kademlia(event)) => self.on_kad(event).await,
            SwarmEvent::Behaviour(RelayBehaviourEvent::UsernameReg(event)) => {
                self.on_username_reg(event).await
            }
            SwarmEvent::OutgoingConnectionError {
                peer_id: Some(peer),
                error,
                ..
            } => self.on_dial_error(peer, &error),
            SwarmEvent::ListenerError { listener_id, error } => {
                log::error!("Listener {listener_id:?} error: {error}");
                self.metrics.write().await.listener_errors += 1;
            }
            SwarmEvent::ListenerClosed {
                listener_id,
                reason,
                ..
            } => {
                log::warn!("Listener {listener_id:?} closed: {reason:?}");
            }
            _ => {}
        }
    }

    // ── Connection management ────────────────────────────────────────

    async fn on_connection_established(&mut self, pid: PeerId, endpoint: &ConnectedPoint) {
        self.total_connections_served += 1;
        let remote_addr = endpoint.get_remote_address();
        event!(
            event_target::CONNECTION,
            "CONNECT peer:{pid} endpoint:{remote_addr} total_served:{}",
            self.total_connections_served
        );

        // Record the peer's client bucket so /peers can publish its
        // truncated prefix. Captured on every Established and overwritten on
        // reconnect — last-known address wins.
        let bucket = extract_ip(remote_addr).map(client_bucket);
        {
            let connections = self.swarm.connected_peers().count();
            let mut m = self.metrics.write().await;
            m.connections = connections;
            m.total_connections_served = self.total_connections_served;
            if let Some(ip) = bucket {
                m.peer_source_ips.insert(pid, ip);
            }
        }

        // IP-level rate limiting, keyed on the client bucket so one IPv6
        // subscriber cannot rotate through its /64.
        if let Some(ip) = bucket {
            let active = self.ip_active_connections.entry(ip).or_insert(0);
            *active += 1;

            let active = *active;
            let attempts = self.ip_rate_windows.hit(ip, Instant::now());

            if active > self.limits.max_connections_per_ip
                || attempts > self.limits.max_new_connections_per_ip
            {
                log::warn!(
                    "IP rate limit exceeded for {ip} (active:{active}, attempts:{attempts}), \
                     disconnecting {pid}"
                );
                let _ = self.swarm.disconnect_peer_id(pid);
                let mut m = self.metrics.write().await;
                m.ip_rate_limited += 1;
            }
        }

        // The remote address is deliberately not added to the routing table:
        // for an inbound connection it is the peer's ephemeral source port,
        // often a NAT mapping, which other peers cannot dial. The peer enters
        // the table from its Identify-reported addresses (see `on_identify`).

        if self.mesh.as_ref().is_some_and(|m| m.is_member(&pid)) {
            let dialed = endpoint.is_dialer().then(|| remote_addr.clone());
            self.on_mesh_connected(pid, dialed).await;
        }
    }

    async fn on_connection_closed(
        &mut self,
        pid: PeerId,
        num_established: u32,
        endpoint: &ConnectedPoint,
    ) {
        // Decrement IP active connection count
        if let Some(ip) = extract_ip(endpoint.get_remote_address()).map(client_bucket) {
            if let Some(active) = self.ip_active_connections.get_mut(&ip) {
                *active = active.saturating_sub(1);
                if *active == 0 {
                    self.ip_active_connections.remove(&ip);
                }
            }
        }

        // When the peer has zero remaining connections, forget the peer's
        // WAN IP and reservation flag. (libp2p delivers `num_established`
        // post-decrement.)
        if num_established == 0 {
            let connections = self.swarm.connected_peers().count();
            let mut m = self.metrics.write().await;
            m.connections = connections;
            m.peer_source_ips.remove(&pid);
            m.peers_with_reservation.remove(&pid);
            if let Some(mesh) = self.mesh.as_mut().filter(|m| m.is_member(&pid)) {
                mesh.on_unreachable(&pid);
                m.reachable_relays = mesh.reachable();
                log::info!("MESH lost profile relay {pid}; redialling with backoff");
            }
        }

        event!(
            event_target::CONNECTION,
            "DISCONNECT peer:{pid} remaining_for_peer:{num_established}"
        );
    }

    /// A dial failed. Only dials to profile relays are followed up.
    fn on_dial_error(&mut self, pid: PeerId, error: &libp2p::swarm::DialError) {
        if let Some(mesh) = self.mesh.as_mut().filter(|m| m.is_member(&pid)) {
            log::debug!("MESH dial to profile relay {pid} failed: {error}");
            mesh.on_dial_failed(&pid);
        }
    }

    // ── Identify ─────────────────────────────────────────────────────

    async fn on_identify(&mut self, event: identify::Event) {
        let identify::Event::Received {
            peer_id: pid, info, ..
        } = event
        else {
            return;
        };
        event!(
            event_target::IDENTIFY,
            "IDENTIFY peer:{pid} proto:{} agent:{}",
            info.protocol_version,
            info.agent_version
        );
        self.metrics.write().await.identify_received += 1;
        // Add reported listen addresses to Kademlia, filtering out
        // unroutable addresses and capping per-peer count.
        let mut added = 0usize;
        for addr in &info.listen_addrs {
            if added >= self.limits.max_identify_addrs {
                break;
            }
            if is_globally_routable(addr) {
                self.swarm
                    .behaviour_mut()
                    .kademlia
                    .add_address(&pid, addr.clone());
                added += 1;
            }
        }
    }

    // ── Circuit relay ────────────────────────────────────────────────

    async fn on_relay(&mut self, event: relay::Event) {
        match &event {
            relay::Event::ReservationReqAccepted { src_peer_id, .. } => {
                event!(
                    event_target::RESERVATION,
                    "RELAY reservation accepted for {src_peer_id}"
                );
                let mut m = self.metrics.write().await;
                m.reservations_accepted += 1;
                m.peers_with_reservation.insert(*src_peer_id);
            }
            relay::Event::CircuitReqAccepted {
                src_peer_id,
                dst_peer_id,
                ..
            } => {
                event!(
                    event_target::CIRCUIT,
                    "RELAY circuit {src_peer_id} → {dst_peer_id}"
                );
                self.metrics.write().await.circuits_accepted += 1;
            }
            relay::Event::CircuitClosed {
                src_peer_id,
                dst_peer_id,
                ..
            } => {
                event!(
                    event_target::CIRCUIT,
                    "RELAY circuit closed {src_peer_id} → {dst_peer_id}"
                );
                self.metrics.write().await.circuits_closed += 1;
            }
            relay::Event::ReservationReqDenied { src_peer_id, .. } => {
                event!(
                    event_target::RESERVATION,
                    "RELAY reservation denied for {src_peer_id}"
                );
                self.metrics.write().await.reservations_denied += 1;
            }
            relay::Event::CircuitReqDenied {
                src_peer_id,
                dst_peer_id,
                ..
            } => {
                event!(
                    event_target::CIRCUIT,
                    "RELAY circuit denied {src_peer_id} → {dst_peer_id}"
                );
                self.metrics.write().await.circuits_denied += 1;
            }
            _ => {
                event!(event_target::CIRCUIT, "RELAY event: {event:?}");
            }
        }
    }

    // ── Kademlia ─────────────────────────────────────────────────────

    async fn on_kad(&mut self, event: kad::Event) {
        accept_provider_announcement(&mut self.swarm.behaviour_mut().kademlia, &event);
        match &event {
            kad::Event::OutboundQueryProgressed {
                result: kad::QueryResult::Bootstrap(result),
                step,
                ..
            } if step.last => {
                if let Some(mesh) = self.mesh.as_mut() {
                    match result {
                        Ok(_) => log::debug!("MESH bootstrap complete"),
                        Err(e) => log::warn!("MESH bootstrap failed: {e}"),
                    }
                    mesh.on_bootstrap_finished(result.is_ok());
                    self.metrics.write().await.bootstrap_status = mesh.status();
                }
            }
            kad::Event::RoutingUpdated {
                peer, addresses, ..
            } => {
                event!(
                    event_target::KAD,
                    "KAD routing updated peer:{peer} addrs:{}",
                    addresses.len()
                );
                self.metrics.write().await.kad_routing_updated += 1;
            }
            kad::Event::InboundRequest {
                request:
                    kad::InboundRequest::PutRecord {
                        record: Some(record),
                        ..
                    },
            } => self.on_put_record(record),
            kad::Event::InboundRequest { request } => {
                event!(event_target::KAD, "KAD inbound request: {request:?}");
            }
            _ => {
                log::trace!("KAD event: {event:?}");
            }
        }
    }

    /// An inbound DHT put, surfaced by FilterBoth mode: store it explicitly
    /// and mirror it to disk so records survive relay restarts.
    ///
    /// Offer to the memory store FIRST and mirror only what it accepted. The
    /// memory store enforces the record cap; mirroring before that check
    /// meant records it rejected were still written to disk, so the SQLite
    /// table had no ceiling at all and an attacker could fill the volume
    /// with unique keys at the maximum record size apiece.
    fn on_put_record(&mut self, record: &kad::Record) {
        if record.value.len() > self.limits.kad_max_record_bytes {
            return;
        }
        use libp2p::kad::store::RecordStore;
        let accepted = self
            .swarm
            .behaviour_mut()
            .kademlia
            .store_mut()
            .put(record.clone())
            .is_ok();
        let mirrored = MirroredRecord::from_kad(record);
        if let (true, Some(store), Some(mirrored)) = (accepted, &self.registry_store, mirrored) {
            if !store.mirror(mirrored) {
                log::warn!("DHT mirror queue full — record kept in memory only");
            }
        }
    }

    // ── Username receipts ────────────────────────────────────────────

    async fn on_username_reg(
        &mut self,
        event: request_response::Event<ReceiptRequest, ReceiptResponse>,
    ) {
        match event {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            } => self.on_receipt_request(peer, request, channel).await,
            event => {
                event!(event_target::RECEIPT, "username-reg event: {event:?}");
            }
        }
    }

    async fn on_receipt_request(
        &mut self,
        peer: PeerId,
        request: ReceiptRequest,
        channel: request_response::ResponseChannel<ReceiptResponse>,
    ) {
        event!(
            event_target::RECEIPT,
            "username-reg: receipt request from {peer} for @{}",
            request.claim.username
        );
        self.metrics.write().await.receipt_requests += 1;
        // Per-peer budget. Claim signatures are free to mint offline, so
        // without this one connection can receipt the whole namespace.
        let count = self.username_rate_windows.hit(peer, Instant::now());
        let rate_limited = count > self.limits.receipt_limit;
        if rate_limited {
            event!(
                event_target::RECEIPT,
                "username-reg: rate limiting {peer} ({count} requests in window)"
            );
        }

        // The store thread answers; the event loop sends the response when
        // it arrives and keeps serving meanwhile.
        let pending = if rate_limited {
            Err(ReceiptResponse::refused(
                "too many username claims — try again shortly",
            ))
        } else {
            match &self.registry_store {
                Some(store) => store
                    .request_receipt(request.claim)
                    .map_err(|_| ReceiptResponse::refused("relay busy — try again shortly")),
                None => Err(ReceiptResponse::refused("registry store unavailable")),
            }
        };
        match pending {
            Ok(reply) => self.pending_receipts.push(
                async move {
                    let response = reply
                        .await
                        .unwrap_or_else(|_| ReceiptResponse::refused("registry store unavailable"));
                    (channel, response)
                }
                .boxed(),
            ),
            Err(response) => {
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .username_reg
                    .send_response(channel, response);
            }
        }
    }
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
    limits: &Limits,
) -> Result<RelayBehaviour, Box<dyn std::error::Error + Send + Sync>> {
    let local_peer_id = key.public().to_peer_id();

    // ── Connection Limits (enforced at transport layer) ──────────────
    let connection_limits = libp2p_connection_limits::ConnectionLimits::default()
        .with_max_pending_incoming(Some(limits.max_pending_incoming))
        .with_max_established(Some(limits.max_connections))
        .with_max_established_per_peer(Some(limits.max_connections_per_peer));
    let connection_limits = libp2p_connection_limits::Behaviour::new(connection_limits);

    // ── Circuit Relay v2 (server) ────────────────────────────────────
    // Rate-limited and resource-capped to prevent abuse.
    let relay_config = relay::Config {
        max_reservations: limits.max_reservations,
        max_circuits: limits.max_circuits,
        max_reservations_per_peer: limits.max_reservations_per_peer,
        max_circuits_per_peer: limits.max_circuits_per_peer,
        max_circuit_bytes: limits.max_circuit_bytes,
        max_circuit_duration: limits.max_circuit_duration,
        reservation_duration: limits.reservation_duration,
        ..Default::default()
    };
    let mut relay = relay::Behaviour::new(local_peer_id, relay_config);
    // Since libp2p-relay 0.22 the server advertises HOP only once it has a
    // confirmed external address. Relaying is this binary's job, so pin it
    // on regardless of what external addresses get registered at startup.
    relay.set_status(Some(relay::Status::Enable));

    // ── Kademlia DHT ─────────────────────────────────────────────────
    // Private Alexandria DHT (`/alexandria/kad/1.0`).
    // The relay always runs in server mode — it's the bootstrap node.
    let mut kademlia_config = kad::Config::new(libp2p::StreamProtocol::new("/alexandria/kad/1.0"));
    kademlia_config.set_query_timeout(limits.kad_query_timeout);
    kademlia_config.set_replication_factor(limits.kad_replication_factor);
    // Cap the in-memory store to prevent unbounded growth
    kademlia_config.set_max_packet_size(limits.kad_max_record_bytes);
    // Surface inbound PutRecord requests so the event loop can store
    // them explicitly and mirror them to disk (MemoryStore alone loses
    // everything on restart).
    kademlia_config.set_record_filtering(kad::StoreInserts::FilterBoth);

    let store_config = kad::store::MemoryStoreConfig {
        max_records: limits.kad_max_records,
        max_value_bytes: limits.kad_max_record_bytes,
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
        let mut behaviour = build_behaviour(&identity, &Limits::default()).unwrap();
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
