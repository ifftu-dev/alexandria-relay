//! Shared harness for black-box relay tests.
//!
//! [`TestRelay`] owns relay startup: ephemeral ports on loopback, a throwaway
//! data directory, and a clean shutdown. Tests change the configuration
//! through [`TestRelay::start_with`] and talk to the relay only the way a
//! client would: libp2p through [`TestClient`], HTTP through
//! [`TestRelay::get`].

#![allow(dead_code)] // each test binary uses a different subset

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use alexandria_relay::username_reg::{self, ReceiptRequest, ReceiptResponse, UsernameClaim};
use alexandria_relay::{start, RelayConfig, RelayHandle};
use ed25519_dalek::{Signer, SigningKey};
use futures::StreamExt;
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{
    identify, noise, relay, tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// How long any single wire interaction may take before a test fails.
pub const STEP_TIMEOUT: Duration = Duration::from_secs(20);

/// An admin token long enough to be accepted.
pub const ADMIN_TOKEN: &str = "test-admin-token-0123456789";

/// A data directory under the system temp dir, removed on drop.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new() -> Self {
        let dir =
            std::env::temp_dir().join(format!("alexandria-relay-test-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).expect("create temp data dir");
        TempDir(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The configuration every test starts from: loopback only, every port
/// ephemeral, no IPv6, a fresh data directory, defaults for everything else.
pub fn test_config(data_dir: &Path) -> RelayConfig {
    RelayConfig {
        listen_ip4: Ipv4Addr::LOCALHOST,
        listen_ip6: None,
        tcp_port: 0,
        quic_port: 0,
        metrics_bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
        metrics_port: 0,
        data_dir: data_dir.to_path_buf(),
        ..RelayConfig::default()
    }
}

/// A relay running in-process for one test.
pub struct TestRelay {
    handle: Option<RelayHandle>,
    /// `None` when the caller owns the data directory ([`TestRelay::start_in`]).
    _data_dir: Option<TempDir>,
}

impl TestRelay {
    /// Start a relay with [`test_config`].
    pub async fn start() -> Self {
        Self::start_with(|_| {}).await
    }

    /// Start a relay with [`test_config`] adjusted by `configure`.
    pub async fn start_with(configure: impl FnOnce(&mut RelayConfig)) -> Self {
        let data_dir = TempDir::new();
        let mut relay = Self::start_in(&data_dir, configure).await;
        relay._data_dir = Some(data_dir);
        relay
    }

    /// Start a relay on a data directory the caller owns, so a second relay
    /// can start from the same directory after this one stops.
    pub async fn start_in(data_dir: &TempDir, configure: impl FnOnce(&mut RelayConfig)) -> Self {
        let _ = env_logger::builder().is_test(true).try_init();
        let mut config = test_config(data_dir.path());
        configure(&mut config);
        let handle = tokio::time::timeout(STEP_TIMEOUT, start(config))
            .await
            .expect("relay start timed out")
            .expect("relay starts");
        TestRelay {
            handle: Some(handle),
            _data_dir: None,
        }
    }

    pub fn handle(&self) -> &RelayHandle {
        self.handle.as_ref().expect("relay running")
    }

    /// The relay's loopback TCP address, with its `/p2p` suffix.
    pub fn tcp_addr(&self) -> Multiaddr {
        let handle = self.handle();
        handle
            .listen_addrs()
            .iter()
            .find(|a| a.iter().any(|p| matches!(p, Protocol::Tcp(_))))
            .expect("a TCP listen address")
            .clone()
            .with(Protocol::P2p(handle.peer_id()))
    }

    /// The relay's loopback QUIC address, with its `/p2p` suffix.
    pub fn quic_addr(&self) -> Multiaddr {
        let handle = self.handle();
        handle
            .listen_addrs()
            .iter()
            .find(|a| is_quic(a))
            .expect("a QUIC listen address")
            .clone()
            .with(Protocol::P2p(handle.peer_id()))
    }

    /// The relay's loopback TCP listener as a socket address, for raw
    /// sockets that speak no libp2p.
    pub fn tcp_socket_addr(&self) -> SocketAddr {
        let port = port_of(self.handle().listen_addrs(), false).expect("a TCP listen port");
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
    }

    /// `GET path` on the relay's HTTP listener, with an optional bearer
    /// token. Returns the status code and body.
    pub async fn get(&self, path: &str, bearer: Option<&str>) -> (u16, String) {
        http_get(self.handle().http_addr(), path, bearer).await
    }

    /// Trigger graceful shutdown and wait for it to finish.
    pub async fn stop(mut self) {
        if let Some(handle) = self.handle.take() {
            tokio::time::timeout(STEP_TIMEOUT, handle.shutdown())
                .await
                .expect("relay shutdown timed out");
        }
    }
}

/// A minimal HTTP/1.1 GET, so the tests need no HTTP client dependency.
pub async fn http_get(
    addr: std::net::SocketAddr,
    path: &str,
    bearer: Option<&str>,
) -> (u16, String) {
    let (status, _, body) = http_get_with(addr, path, bearer, &[]).await;
    (status, body)
}

/// [`http_get`] with extra request headers. Also returns the response's
/// `Content-Type` (empty when absent).
pub async fn http_get_with(
    addr: std::net::SocketAddr,
    path: &str,
    bearer: Option<&str>,
    headers: &[(&str, &str)],
) -> (u16, String, String) {
    let request = async {
        let mut stream = tokio::net::TcpStream::connect(addr).await?;
        let mut extra = bearer
            .map(|t| format!("Authorization: Bearer {t}\r\n"))
            .unwrap_or_default();
        for (name, value) in headers {
            extra.push_str(&format!("{name}: {value}\r\n"));
        }
        let req =
            format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n{extra}Connection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).await?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await?;
        Ok::<_, std::io::Error>(String::from_utf8_lossy(&raw).into_owned())
    };
    let raw = tokio::time::timeout(STEP_TIMEOUT, request)
        .await
        .expect("HTTP request timed out")
        .expect("HTTP request");
    let status = raw
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("HTTP status line");
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((raw.as_str(), ""));
    let content_type = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-type")
                .then(|| value.trim().to_string())
        })
        .unwrap_or_default();
    (status, content_type, body.to_string())
}

/// The port of the first listen address that uses `protocol`'s transport.
pub fn port_of(addrs: &[Multiaddr], quic: bool) -> Option<u16> {
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

/// True when `addr` is a QUIC address.
pub fn is_quic(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| matches!(p, Protocol::QuicV1))
}

/// Connect to the relay at `relay_addr` (with its `/p2p` suffix) from a
/// fresh TCP swarm and return the Identify info the relay sends.
pub async fn identify_relay(relay_addr: &Multiaddr) -> identify::Info {
    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .expect("client TCP transport")
        .with_behaviour(|key| {
            identify::Behaviour::new(identify::Config::new(
                "/alexandria/id/1.0".to_string(),
                key.public(),
            ))
        })
        .expect("client behaviour")
        .build();
    swarm.dial(relay_addr.clone()).expect("dial relay");
    let outcome = async {
        loop {
            match swarm.select_next_some().await {
                SwarmEvent::Behaviour(identify::Event::Received { info, .. }) => return info,
                SwarmEvent::OutgoingConnectionError { error, .. } => {
                    panic!("dial relay: {error}")
                }
                _ => {}
            }
        }
    };
    tokio::time::timeout(STEP_TIMEOUT, outcome)
        .await
        .expect("Identify timed out")
}

// ── libp2p client ────────────────────────────────────────────────────

/// What a test client speaks: circuit relay (as a client) and the
/// username-receipt protocol (outbound).
#[derive(NetworkBehaviour)]
pub struct ClientBehaviour {
    relay_client: relay::client::Behaviour,
    username_reg: request_response::cbor::Behaviour<ReceiptRequest, ReceiptResponse>,
}

impl ClientBehaviour {
    fn new(relay_client: relay::client::Behaviour) -> Self {
        ClientBehaviour {
            relay_client,
            username_reg: request_response::cbor::Behaviour::new(
                [(
                    StreamProtocol::new(username_reg::PROTOCOL),
                    ProtocolSupport::Outbound,
                )],
                request_response::Config::default(),
            ),
        }
    }
}

/// A second libp2p swarm in the same process, acting as an app node.
pub struct TestClient {
    swarm: Swarm<ClientBehaviour>,
}

impl TestClient {
    pub fn new() -> Self {
        let swarm = SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .expect("client TCP transport")
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .expect("client relay transport")
            .with_behaviour(|_, relay_client| ClientBehaviour::new(relay_client))
            .expect("client behaviour")
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();
        TestClient { swarm }
    }

    /// A client that also speaks QUIC, for dialling the relay's QUIC address.
    pub fn with_quic() -> Self {
        let swarm = SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .expect("client TCP transport")
            .with_quic()
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .expect("client relay transport")
            .with_behaviour(|_, relay_client| ClientBehaviour::new(relay_client))
            .expect("client behaviour")
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();
        TestClient { swarm }
    }

    /// Ask the relay at `relay_addr` (with its `/p2p` suffix) for a circuit
    /// reservation. `Ok` carries the relayed addresses the reservation
    /// produced; `Err` describes why the reservation listener closed.
    pub async fn reserve(&mut self, relay_addr: &Multiaddr) -> Result<Vec<Multiaddr>, String> {
        let listener = self
            .swarm
            .listen_on(relay_addr.clone().with(Protocol::P2pCircuit))
            .map_err(|e| e.to_string())?;
        let mut addrs = Vec::new();
        let mut accepted = false;
        let outcome = async {
            loop {
                match self.swarm.select_next_some().await {
                    SwarmEvent::NewListenAddr {
                        listener_id,
                        address,
                    } if listener_id == listener => {
                        addrs.push(address);
                        if accepted {
                            return Ok(addrs);
                        }
                    }
                    SwarmEvent::Behaviour(ClientBehaviourEvent::RelayClient(
                        relay::client::Event::ReservationReqAccepted { .. },
                    )) => {
                        accepted = true;
                        if !addrs.is_empty() {
                            return Ok(addrs);
                        }
                    }
                    SwarmEvent::ListenerClosed {
                        listener_id,
                        reason,
                        ..
                    } if listener_id == listener => {
                        return Err(format!("{reason:?}"));
                    }
                    _ => {}
                }
            }
        };
        tokio::time::timeout(STEP_TIMEOUT, outcome)
            .await
            .expect("reservation timed out")
    }

    /// Dial the relay at `relay_addr` (with its `/p2p` suffix) and wait
    /// until the connection is established. The connection stays open while
    /// the client lives, unless the relay closes it.
    pub async fn connect(&mut self, relay_addr: &Multiaddr) -> Result<(), String> {
        self.swarm
            .dial(relay_addr.clone())
            .map_err(|e| e.to_string())?;
        let outcome = async {
            loop {
                match self.swarm.select_next_some().await {
                    SwarmEvent::ConnectionEstablished { .. } => return Ok(()),
                    SwarmEvent::OutgoingConnectionError { error, .. } => {
                        return Err(error.to_string())
                    }
                    _ => {}
                }
            }
        };
        tokio::time::timeout(STEP_TIMEOUT, outcome)
            .await
            .unwrap_or_else(|_| Err("no answer in time".to_string()))
    }

    /// Send a username-receipt request for `claim` to the relay at
    /// `relay_addr` (with its `/p2p` suffix) and return its response.
    pub async fn request_receipt(
        &mut self,
        relay_addr: &Multiaddr,
        claim: &UsernameClaim,
    ) -> ReceiptResponse {
        let relay_peer = relay_addr
            .iter()
            .find_map(|p| match p {
                Protocol::P2p(peer) => Some(peer),
                _ => None,
            })
            .expect("relay address carries /p2p");
        let request_id = self
            .swarm
            .behaviour_mut()
            .username_reg
            .send_request_with_addresses(
                &relay_peer,
                ReceiptRequest {
                    claim: claim.clone(),
                },
                vec![relay_addr.clone()],
            );
        let outcome = async {
            loop {
                if let SwarmEvent::Behaviour(ClientBehaviourEvent::UsernameReg(event)) =
                    self.swarm.select_next_some().await
                {
                    match event {
                        request_response::Event::Message {
                            message:
                                request_response::Message::Response {
                                    request_id: id,
                                    response,
                                },
                            ..
                        } if id == request_id => return response,
                        request_response::Event::OutboundFailure {
                            request_id: id,
                            error,
                            ..
                        } if id == request_id => panic!("receipt request failed: {error}"),
                        _ => {}
                    }
                }
            }
        };
        tokio::time::timeout(STEP_TIMEOUT, outcome)
            .await
            .expect("receipt request timed out")
    }

    pub fn peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }
}

/// A validly signed username claim from the deterministic key `seed`.
///
/// The `did:key` encoding (multibase `z` + base58btc of `0xed 0x01` + key)
/// and the signed bytes are the wire contract with the app, written out here
/// rather than borrowed from the relay.
pub fn signed_claim(seed: u8, username: &str, claimed_at: i64) -> UsernameClaim {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let mut bytes = vec![0xed, 0x01];
    bytes.extend_from_slice(key.verifying_key().as_bytes());
    let did = format!("did:key:z{}", bs58::encode(bytes).into_string());
    let signed = format!("alexandria-username-claim-v1|{username}|{did}|{claimed_at}");
    let sig = key.sign(signed.as_bytes());
    UsernameClaim {
        version: 1,
        username: username.to_string(),
        did,
        claimed_at,
        sig: hex::encode(sig.to_bytes()),
        receipt: None,
        anchor: None,
        release: None,
    }
}

// ── PROXY protocol shim ──────────────────────────────────────────────

/// The PROXY protocol v2 signature.
const PROXY_V2_SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";

/// A v2 header with the PROXY command for a TCP stream from `src` to a
/// placeholder destination, written out from the protocol specification
/// rather than borrowed from the relay.
pub fn proxy_v2_header(src: SocketAddr) -> Vec<u8> {
    let mut body = Vec::new();
    let family = match src {
        SocketAddr::V4(v4) => {
            body.extend_from_slice(&v4.ip().octets());
            body.extend_from_slice(&[10, 0, 0, 1]);
            0x11
        }
        SocketAddr::V6(v6) => {
            body.extend_from_slice(&v6.ip().octets());
            body.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
            0x21
        }
    };
    body.extend_from_slice(&src.port().to_be_bytes());
    body.extend_from_slice(&4001u16.to_be_bytes());
    proxy_v2_raw(0x21, family, &body)
}

/// A v2 header with the LOCAL command, as a proxy's health check sends.
pub fn proxy_v2_local_header() -> Vec<u8> {
    proxy_v2_raw(0x20, 0x00, &[])
}

/// A v2 header from its version/command byte, family/protocol byte and
/// body.
pub fn proxy_v2_raw(version_command: u8, family: u8, body: &[u8]) -> Vec<u8> {
    let mut header = PROXY_V2_SIGNATURE.to_vec();
    header.push(version_command);
    header.push(family);
    header.extend_from_slice(&(body.len() as u16).to_be_bytes());
    header.extend_from_slice(body);
    header
}

/// A loopback TCP forwarder standing in for the proxy: it accepts, connects
/// to the relay, writes a chosen header and then pipes bytes both ways.
pub struct ProxyShim {
    port: u16,
    task: tokio::task::JoinHandle<()>,
}

impl ProxyShim {
    /// Forward to `relay`'s TCP listener, opening each connection with
    /// `header`.
    pub async fn start(relay: &TestRelay, header: Vec<u8>) -> Self {
        let target = relay.tcp_socket_addr();
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind shim");
        let port = listener.local_addr().expect("shim address").port();
        let task = tokio::spawn(async move {
            while let Ok((mut inbound, _)) = listener.accept().await {
                let header = header.clone();
                tokio::spawn(async move {
                    let Ok(mut outbound) = tokio::net::TcpStream::connect(target).await else {
                        return;
                    };
                    if outbound.write_all(&header).await.is_ok() {
                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                    }
                });
            }
        });
        ProxyShim { port, task }
    }

    /// The shim's address with the relay's `/p2p` suffix: what a client
    /// behind the proxy dials.
    pub fn addr(&self, relay: &TestRelay) -> Multiaddr {
        Multiaddr::empty()
            .with(Protocol::Ip4(Ipv4Addr::LOCALHOST))
            .with(Protocol::Tcp(self.port))
            .with(Protocol::P2p(relay.handle().peer_id()))
    }
}

impl Drop for ProxyShim {
    fn drop(&mut self) {
        self.task.abort();
    }
}
