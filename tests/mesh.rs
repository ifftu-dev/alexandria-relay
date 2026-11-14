//! Black-box tests for joining the mesh: relays started with a synthetic
//! network profile find each other, and an announcing relay is discoverable
//! under the network's relay-discovery key.
//!
//! The profiles here are synthetic. They have the shape of the app's network
//! profile (the relay reads only `schema_version`, `network_id`, `relays` and
//! `protocol_namespace`) and name loopback relays `localhost` and
//! `127.0.0.1`. The second is a name the app's DNS-name rule accepts and the
//! resolver answers without a lookup, so nothing leaves the machine.

mod common;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use alexandria_relay::{start, RelayConfig};
use common::{test_config, TempDir, TestRelay, STEP_TIMEOUT};
use futures::StreamExt;
use libp2p::identity::Keypair;
use libp2p::kad::{self, store::MemoryStore};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{noise, tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder};
use serde_json::json;

/// A synthetic network-profile document naming `relays` (PeerId, DNS name,
/// port). Fields the relay does not read are present, as in a real profile,
/// with made-up values.
fn profile(network_id: &str, namespace: &str, relays: &[(PeerId, &str, u16)]) -> serde_json::Value {
    let relays: Vec<_> = relays
        .iter()
        .map(|(peer, dns_name, port)| {
            json!({
                "peer_id": peer.to_string(),
                "dns_name": dns_name,
                "port": port,
                // Not dialled while the name resolves, which loopback names
                // do; the relay falls back to these only when it does not.
                "fallback_ips": ["198.51.99.1"],
                "registry_https_origin": format!("https://{dns_name}"),
            })
        })
        .collect();
    json!({
        "schema_version": 1,
        "network_id": network_id,
        "profile_revision": 1,
        "relays": relays,
        "receipt_issuer_keys": [],
        "protocol_namespace": namespace,
    })
}

/// Write `profile` into `dir` and return its path.
fn write_profile(dir: &Path, profile: &serde_json::Value) -> PathBuf {
    let path = dir.join("network.json");
    std::fs::write(&path, serde_json::to_vec_pretty(profile).unwrap()).unwrap();
    path
}

/// Start a relay with `config` and return the startup error, failing the
/// test if it starts.
async fn start_error(config: RelayConfig) -> String {
    match start(config).await {
        Ok(handle) => {
            handle.shutdown().await;
            panic!("the relay started");
        }
        Err(e) => e.to_string(),
    }
}

/// A port free on loopback for both TCP and UDP, so one relay can listen on
/// it with both transports, as a profile entry's single port implies.
fn free_port() -> u16 {
    loop {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        if std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

/// One relay of a test mesh: its identity, the port its profile entry names,
/// and the DNS name that entry gives.
struct MeshMember {
    keypair: Keypair,
    port: u16,
    dns_name: &'static str,
}

impl MeshMember {
    fn new(dns_name: &'static str) -> Self {
        MeshMember {
            keypair: Keypair::generate_ed25519(),
            port: free_port(),
            dns_name,
        }
    }

    fn peer_id(&self) -> PeerId {
        self.keypair.public().to_peer_id()
    }

    fn entry(&self) -> (PeerId, &'static str, u16) {
        (self.peer_id(), self.dns_name, self.port)
    }

    /// Start this member on its port with the profile at `profile`.
    async fn start(&self, profile: &Path, announce: bool) -> TestRelay {
        let keypair = self.keypair.clone();
        let port = self.port;
        let profile = Some(profile.to_path_buf());
        TestRelay::start_with(move |c| {
            c.keypair = Some(keypair);
            c.tcp_port = port;
            c.quic_port = port;
            c.network_profile = profile;
            c.announce = announce;
            // Gives provider records a dialable address.
            c.public_host = Some("localhost".to_string());
        })
        .await
    }
}

/// `GET /health` until `done` accepts its JSON, failing after
/// [`STEP_TIMEOUT`].
async fn health_until(relay: &TestRelay, what: &str, done: impl Fn(&serde_json::Value) -> bool) {
    let deadline = tokio::time::Instant::now() + STEP_TIMEOUT;
    loop {
        let (status, body) = relay.get("/health", None).await;
        assert_eq!(status, 200);
        let health: serde_json::Value = serde_json::from_str(&body).unwrap();
        if done(&health) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}: {health}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// ── Kademlia client ──────────────────────────────────────────────────

#[derive(NetworkBehaviour)]
struct KadClientBehaviour {
    kademlia: kad::Behaviour<MemoryStore>,
}

/// An app-like DHT client: Kademlia on the network's DHT protocol, in client
/// mode, knowing only the relay it was pointed at.
struct KadClient {
    swarm: Swarm<KadClientBehaviour>,
}

impl KadClient {
    fn new(via: &Multiaddr) -> Self {
        let mut swarm = SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .expect("client TCP transport")
            .with_behaviour(|key| {
                let peer = key.public().to_peer_id();
                let config = kad::Config::new(StreamProtocol::new("/alexandria/kad/1.0"));
                let mut kademlia =
                    kad::Behaviour::with_config(peer, MemoryStore::new(peer), config);
                kademlia.set_mode(Some(kad::Mode::Client));
                KadClientBehaviour { kademlia }
            })
            .expect("client behaviour")
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();
        let (peer, addr) = split_p2p(via);
        swarm.behaviour_mut().kademlia.add_address(&peer, addr);
        KadClient { swarm }
    }

    /// The peers a closest-peers query for `target` reaches.
    async fn closest_peers(&mut self, target: PeerId) -> HashSet<PeerId> {
        let query = self
            .swarm
            .behaviour_mut()
            .kademlia
            .get_closest_peers(target);
        let outcome = async {
            loop {
                if let SwarmEvent::Behaviour(KadClientBehaviourEvent::Kademlia(
                    kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::GetClosestPeers(result),
                        ..
                    },
                )) = self.swarm.select_next_some().await
                {
                    if id == query {
                        let peers = match result {
                            Ok(ok) => ok.peers,
                            Err(kad::GetClosestPeersError::Timeout { peers, .. }) => peers,
                        };
                        return peers.into_iter().map(|p| p.peer_id).collect();
                    }
                }
            }
        };
        tokio::time::timeout(STEP_TIMEOUT, outcome)
            .await
            .expect("closest-peers query timed out")
    }

    /// The providers one query for `key` finds.
    async fn providers(&mut self, key: kad::RecordKey) -> HashSet<PeerId> {
        let query = self.swarm.behaviour_mut().kademlia.get_providers(key);
        let mut found = HashSet::new();
        let outcome = async {
            loop {
                if let SwarmEvent::Behaviour(KadClientBehaviourEvent::Kademlia(
                    kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::GetProviders(result),
                        step,
                        ..
                    },
                )) = self.swarm.select_next_some().await
                {
                    if id != query {
                        continue;
                    }
                    if let Ok(kad::GetProvidersOk::FoundProviders { providers, .. }) = result {
                        found.extend(providers);
                    }
                    if step.last {
                        return;
                    }
                }
            }
        };
        tokio::time::timeout(STEP_TIMEOUT, outcome)
            .await
            .expect("providers query timed out");
        found
    }
}

/// Split `/…/p2p/<peer>` into the peer and the address before it.
fn split_p2p(addr: &Multiaddr) -> (PeerId, Multiaddr) {
    let mut addr = addr.clone();
    match addr.pop() {
        Some(Protocol::P2p(peer)) => (peer, addr),
        _ => panic!("{addr} has no /p2p suffix"),
    }
}

// ── Cases ────────────────────────────────────────────────────────────

#[tokio::test]
async fn announce_without_a_network_profile_is_refused() {
    let data = TempDir::new();
    let mut config = test_config(data.path());
    config.announce = true;
    config.network_profile = None;

    let error = start_error(config).await;
    assert!(error.contains("--network-profile"), "{error}");
}

#[tokio::test]
async fn a_profile_whose_namespace_does_not_match_its_network_is_refused() {
    let data = TempDir::new();
    let other_relay = PeerId::random();
    let path = write_profile(
        data.path(),
        &profile(
            "testnet",
            "/alexandria/othernet",
            &[(other_relay, "localhost", 4001)],
        ),
    );
    let mut config = test_config(data.path());
    config.network_profile = Some(path);

    let error = start_error(config).await;
    assert!(error.contains("protocol_namespace"), "{error}");
}

#[tokio::test]
async fn two_relays_sharing_a_profile_find_each_other() {
    let dir = TempDir::new();
    // B dials A by name. A's own dial to B is not needed for the mesh: B's
    // inbound connection is enough.
    let a = MeshMember::new("localhost");
    let b = MeshMember::new("127.0.0.1");
    let path = write_profile(
        dir.path(),
        &profile("testnet", "/alexandria/testnet", &[a.entry(), b.entry()]),
    );

    // A comes up first and cannot reach B yet; B reaches A at startup.
    let relay_a = a.start(&path, false).await;
    let relay_b = b.start(&path, false).await;

    for relay in [&relay_a, &relay_b] {
        health_until(relay, "the other relay to be reachable", |h| {
            h["reachable_relays"] == 1 && h["profile_relays"] == 1
        })
        .await;
    }

    // Each relay's routing table holds the other: a client that knows only
    // one of them learns the other from it.
    let mut via_a = KadClient::new(&relay_a.tcp_addr());
    let found = via_a.closest_peers(b.peer_id()).await;
    assert!(found.contains(&b.peer_id()), "{found:?}");
    let mut via_b = KadClient::new(&relay_b.tcp_addr());
    let found = via_b.closest_peers(a.peer_id()).await;
    assert!(found.contains(&a.peer_id()), "{found:?}");

    health_until(&relay_b, "a successful bootstrap", |h| {
        h["bootstrap_status"] == "ok"
    })
    .await;

    relay_b.stop().await;
    relay_a.stop().await;
}

/// The app's relay-discovery key for `namespace`: SHA-256 of
/// `"{namespace}.relays"` (`relay_namespace_key` in the app's
/// `src-tauri/src/p2p/discovery.rs`), written out here as the wire contract.
fn discovery_key(namespace: &str) -> kad::RecordKey {
    use sha2::{Digest, Sha256};
    kad::RecordKey::new(&Sha256::digest(format!("{namespace}.relays")))
}

#[tokio::test]
async fn an_announcing_relay_is_a_provider_on_its_bootstrap_peer() {
    let dir = TempDir::new();
    let bootstrap = MeshMember::new("localhost");
    let announcer = MeshMember::new("127.0.0.1");
    let path = write_profile(
        dir.path(),
        &profile(
            "testnet",
            "/alexandria/testnet",
            &[bootstrap.entry(), announcer.entry()],
        ),
    );
    let relay_bootstrap = bootstrap.start(&path, false).await;
    let relay_announcer = announcer.start(&path, true).await;

    // A client that knows only the bootstrap relay finds the announcer under
    // the discovery key. The announcement lands shortly after the two relays
    // connect, so ask until it does.
    let key = discovery_key("/alexandria/testnet");
    let mut client = KadClient::new(&relay_bootstrap.tcp_addr());
    let deadline = tokio::time::Instant::now() + STEP_TIMEOUT;
    loop {
        let providers = client.providers(key.clone()).await;
        if providers.contains(&announcer.peer_id()) {
            assert!(
                !providers.contains(&bootstrap.peer_id()),
                "a relay without --announce must not provide: {providers:?}"
            );
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "announcer never appeared as a provider: {providers:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    relay_announcer.stop().await;
    relay_bootstrap.stop().await;
}

#[tokio::test]
async fn a_relay_alone_in_its_profile_still_announces() {
    // The first relay of a network, or one whose peers are all down, has
    // nobody to connect to. It must still hold its own provider record, so
    // an app node that reaches it finds it under the discovery key.
    let dir = TempDir::new();
    let only = MeshMember::new("localhost");
    let path = write_profile(
        dir.path(),
        &profile("testnet", "/alexandria/testnet", &[only.entry()]),
    );
    let relay = only.start(&path, true).await;

    let key = discovery_key("/alexandria/testnet");
    let mut client = KadClient::new(&relay.tcp_addr());
    let deadline = tokio::time::Instant::now() + STEP_TIMEOUT;
    loop {
        let providers = client.providers(key.clone()).await;
        if providers.contains(&only.peer_id()) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the lone relay never provided: {providers:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    relay.stop().await;
}

#[tokio::test]
async fn a_relay_that_drops_is_dialled_again() {
    let dir = TempDir::new();
    // B leaves and comes back; A is the one that must reconnect.
    let a = MeshMember::new("127.0.0.1");
    let b = MeshMember::new("localhost");
    let path = write_profile(
        dir.path(),
        &profile("testnet", "/alexandria/testnet", &[a.entry(), b.entry()]),
    );
    let relay_a = a.start(&path, false).await;
    let relay_b = b.start(&path, false).await;
    health_until(&relay_a, "B to be reachable", |h| {
        h["reachable_relays"] == 1
    })
    .await;

    relay_b.stop().await;
    health_until(&relay_a, "B to be gone", |h| h["reachable_relays"] == 0).await;

    // B comes back on the same TCP port without a profile, so it dials
    // nobody: only A's own redial can reconnect them. (QUIC moves to a fresh
    // port: the old UDP socket can outlive shutdown briefly.)
    let (keypair, port) = (b.keypair.clone(), b.port);
    let relay_b = TestRelay::start_with(move |c| {
        c.keypair = Some(keypair);
        c.tcp_port = port;
    })
    .await;
    health_until(&relay_a, "A to reach B again", |h| {
        h["reachable_relays"] == 1
    })
    .await;

    relay_b.stop().await;
    relay_a.stop().await;
}
