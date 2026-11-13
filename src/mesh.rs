//! Mesh membership: which profile relays to keep connected to, when to dial
//! them again, the relay-discovery key, and the bootstrap status the HTTP
//! routes report.
//!
//! The event loop in `swarm.rs` owns a [`Mesh`] when the relay was started
//! with a network profile and drives it from swarm events and timers. DNS
//! names are resolved through the OS resolver (`tokio::net::lookup_host`),
//! like `--public-host`, so libp2p's DNS transport and its resolver stay out
//! of the build.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use libp2p::kad;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::profile::NetworkProfile;

/// How often the relay runs a Kademlia bootstrap while it has a profile.
/// Matches libp2p-kad's own periodic bootstrap default.
pub(crate) const BOOTSTRAP_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// How often the event loop checks for profile relays due a dial.
pub(crate) const REDIAL_CHECK_INTERVAL: Duration = Duration::from_secs(1);

/// First wait before dialling a dropped or unreachable profile relay again.
/// Doubles on each failure up to [`REDIAL_MAX`]; a connection resets it.
const REDIAL_MIN: Duration = Duration::from_secs(1);

/// Longest wait between dials of an unreachable profile relay.
const REDIAL_MAX: Duration = Duration::from_secs(5 * 60);

/// How long one DNS lookup of a profile relay may take.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);

/// The provider-record key under which relays advertise themselves for
/// discovery: SHA-256 of `"{protocol_namespace}.relays"`, exactly as the app
/// derives it (`relay_namespace_key` in `src-tauri/src/p2p/discovery.rs`).
pub fn relay_discovery_key(protocol_namespace: &str) -> kad::RecordKey {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(format!("{protocol_namespace}.relays"));
    kad::RecordKey::new(&hash)
}

/// The addresses to dial a profile relay on: TCP and QUIC at `port` on every
/// address its DNS name resolved to, or on its fallback IPs when the name
/// resolved to nothing. The fallback IPs exist for when DNS fails; a name
/// that resolves is dialled as it resolves.
pub(crate) fn dial_addrs(resolved: &[IpAddr], fallback: &[IpAddr], port: u16) -> Vec<Multiaddr> {
    let ips = if resolved.is_empty() {
        fallback
    } else {
        resolved
    };
    ips.iter()
        .flat_map(|ip| {
            let base = Multiaddr::empty().with(match ip {
                IpAddr::V4(v4) => Protocol::Ip4(*v4),
                IpAddr::V6(v6) => Protocol::Ip6(*v6),
            });
            [
                base.clone().with(Protocol::Tcp(port)),
                base.with(Protocol::Udp(port)).with(Protocol::QuicV1),
            ]
        })
        .collect()
}

/// Bootstrap state as `/health` and `/metrics` report it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BootstrapStatus {
    /// No network profile: the relay joins no mesh.
    Disabled,
    /// No bootstrap has completed yet.
    Pending,
    /// The last bootstrap completed.
    Ok,
    /// The last bootstrap timed out.
    Failed,
}

impl BootstrapStatus {
    /// Every state, in the order metrics list them.
    pub(crate) const ALL: [BootstrapStatus; 4] = [
        BootstrapStatus::Disabled,
        BootstrapStatus::Pending,
        BootstrapStatus::Ok,
        BootstrapStatus::Failed,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            BootstrapStatus::Disabled => "disabled",
            BootstrapStatus::Pending => "pending",
            BootstrapStatus::Ok => "ok",
            BootstrapStatus::Failed => "failed",
        }
    }
}

/// A profile relay other than this one.
struct MeshRelay {
    dns_name: String,
    port: u16,
    fallback_ips: Vec<IpAddr>,
    /// The addresses the last lookup produced.
    addrs: Vec<Multiaddr>,
    connected: bool,
    /// When to dial next; `None` while a lookup or dial is in flight, or
    /// while connected.
    next_dial: Option<Instant>,
    backoff: Duration,
}

/// A finished DNS lookup: the relay and the addresses to dial it on.
pub(crate) type Resolved = (PeerId, Vec<Multiaddr>);

/// The relay's view of the mesh it joins through its network profile.
pub(crate) struct Mesh {
    relays: HashMap<PeerId, MeshRelay>,
    /// Set when `--announce` was given.
    announce_key: Option<kad::RecordKey>,
    status: BootstrapStatus,
    resolved_tx: mpsc::UnboundedSender<Resolved>,
}

impl Mesh {
    /// The mesh `profile` describes for the relay `local`, with every other
    /// relay due a dial now. Lookups report on `resolved_tx`.
    pub(crate) fn new(
        profile: &NetworkProfile,
        local: PeerId,
        announce: bool,
        resolved_tx: mpsc::UnboundedSender<Resolved>,
    ) -> Self {
        let now = Instant::now();
        let relays = profile
            .relays
            .iter()
            .filter(|r| r.peer_id != local)
            .map(|r| {
                (
                    r.peer_id,
                    MeshRelay {
                        dns_name: r.dns_name.clone(),
                        port: r.port,
                        fallback_ips: r.fallback_ips.clone(),
                        addrs: Vec::new(),
                        connected: false,
                        next_dial: Some(now),
                        backoff: REDIAL_MIN,
                    },
                )
            })
            .collect();
        Mesh {
            relays,
            announce_key: announce.then(|| relay_discovery_key(&profile.protocol_namespace)),
            status: BootstrapStatus::Pending,
            resolved_tx,
        }
    }

    /// Other relays listed in the profile.
    pub(crate) fn configured(&self) -> usize {
        self.relays.len()
    }

    /// Profile relays with at least one open connection.
    pub(crate) fn reachable(&self) -> usize {
        self.relays.values().filter(|r| r.connected).count()
    }

    pub(crate) fn status(&self) -> BootstrapStatus {
        self.status
    }

    pub(crate) fn announce_key(&self) -> Option<&kad::RecordKey> {
        self.announce_key.as_ref()
    }

    pub(crate) fn is_member(&self, peer: &PeerId) -> bool {
        self.relays.contains_key(peer)
    }

    /// The addresses the last lookup of `peer` produced.
    pub(crate) fn addrs(&self, peer: &PeerId) -> &[Multiaddr] {
        self.relays
            .get(peer)
            .map(|r| r.addrs.as_slice())
            .unwrap_or_default()
    }

    /// Start a lookup for every relay due a dial. Each lookup reports its
    /// addresses on the channel given to [`Mesh::new`].
    pub(crate) fn start_due_lookups(&mut self) {
        let now = Instant::now();
        let mut due = Vec::new();
        for (peer, relay) in &mut self.relays {
            if relay.connected || relay.next_dial.is_none_or(|at| at > now) {
                continue;
            }
            relay.next_dial = None;
            due.push(*peer);
        }
        for peer in due {
            self.spawn_lookup(peer);
        }
    }

    /// Look `peer` up again without dialling it on its own account, e.g.
    /// after it connected to us before we had its addresses.
    pub(crate) fn refresh_addrs(&self, peer: PeerId) {
        if self.relays.contains_key(&peer) {
            self.spawn_lookup(peer);
        }
    }

    fn spawn_lookup(&self, peer: PeerId) {
        let Some(relay) = self.relays.get(&peer) else {
            return;
        };
        let (name, port, fallback) = (
            relay.dns_name.clone(),
            relay.port,
            relay.fallback_ips.clone(),
        );
        let tx = self.resolved_tx.clone();
        tokio::spawn(async move {
            let resolved: Vec<IpAddr> = match tokio::time::timeout(
                RESOLVE_TIMEOUT,
                tokio::net::lookup_host((name.as_str(), port)),
            )
            .await
            {
                Ok(Ok(addrs)) => {
                    let mut ips: Vec<IpAddr> = Vec::new();
                    for ip in addrs.map(|a| a.ip()) {
                        if !ips.contains(&ip) {
                            ips.push(ip);
                        }
                    }
                    ips
                }
                Ok(Err(e)) => {
                    log::warn!("MESH cannot resolve {name}: {e}; using its fallback IPs");
                    Vec::new()
                }
                Err(_) => {
                    log::warn!("MESH resolving {name} timed out; using its fallback IPs");
                    Vec::new()
                }
            };
            // The event loop may have stopped; nothing to do then.
            let _ = tx.send((peer, dial_addrs(&resolved, &fallback, port)));
        });
    }

    /// Record a finished lookup. Returns whether to dial `peer` now.
    pub(crate) fn on_resolved(&mut self, peer: PeerId, addrs: Vec<Multiaddr>) -> bool {
        let Some(relay) = self.relays.get_mut(&peer) else {
            return false;
        };
        relay.addrs = addrs;
        !relay.connected
    }

    /// `peer` has its first open connection. Returns whether it is the
    /// first reachable profile relay, i.e. whether the relay just joined.
    pub(crate) fn on_connected(&mut self, peer: &PeerId) -> bool {
        let was_isolated = self.reachable() == 0;
        let Some(relay) = self.relays.get_mut(peer) else {
            return false;
        };
        if relay.connected {
            return false;
        }
        relay.connected = true;
        relay.next_dial = None;
        relay.backoff = REDIAL_MIN;
        was_isolated
    }

    /// `peer` closed its last connection, or a dial to it failed: schedule
    /// the next dial and lengthen the wait after that one.
    pub(crate) fn on_unreachable(&mut self, peer: &PeerId) {
        let Some(relay) = self.relays.get_mut(peer) else {
            return;
        };
        relay.connected = false;
        relay.next_dial = Some(Instant::now() + relay.backoff);
        log::debug!(
            "MESH {peer} ({}) unreachable; next dial in {:?}",
            relay.dns_name,
            relay.backoff
        );
        relay.backoff = (relay.backoff * 2).min(REDIAL_MAX);
    }

    /// A dial to `peer` failed while it may still be connected over another
    /// connection: only schedule a redial if it is not.
    pub(crate) fn on_dial_failed(&mut self, peer: &PeerId) {
        if self.relays.get(peer).is_some_and(|r| !r.connected) {
            self.on_unreachable(peer);
        }
    }

    pub(crate) fn on_bootstrap_finished(&mut self, ok: bool) {
        self.status = if ok {
            BootstrapStatus::Ok
        } else {
            BootstrapStatus::Failed
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_discovery_key_is_the_apps() {
        // SHA-256 of "/alexandria/testnet.relays", computed independently
        // (`printf %s '/alexandria/testnet.relays' | shasum -a 256`).
        let expected =
            hex::decode("d8dd9ebd0d9e36650612948903f3cdd6e815acb4f930ba45f51d7ca518d01199")
                .unwrap();
        assert_eq!(
            relay_discovery_key("/alexandria/testnet").to_vec(),
            expected
        );
    }

    #[test]
    fn a_resolved_name_is_dialled_on_tcp_and_quic_and_fallbacks_wait() {
        let resolved: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()];
        let fallback: Vec<IpAddr> = vec!["198.51.99.1".parse().unwrap()];
        let addrs: Vec<String> = dial_addrs(&resolved, &fallback, 4001)
            .iter()
            .map(|a| a.to_string())
            .collect();
        assert_eq!(
            addrs,
            [
                "/ip4/127.0.0.1/tcp/4001",
                "/ip4/127.0.0.1/udp/4001/quic-v1",
                "/ip6/::1/tcp/4001",
                "/ip6/::1/udp/4001/quic-v1",
            ]
        );
    }

    #[test]
    fn an_unresolvable_name_falls_back_to_the_profile_ips() {
        let fallback: Vec<IpAddr> = vec!["198.51.99.1".parse().unwrap()];
        let addrs: Vec<String> = dial_addrs(&[], &fallback, 4001)
            .iter()
            .map(|a| a.to_string())
            .collect();
        assert_eq!(
            addrs,
            [
                "/ip4/198.51.99.1/tcp/4001",
                "/ip4/198.51.99.1/udp/4001/quic-v1"
            ]
        );
    }
}
