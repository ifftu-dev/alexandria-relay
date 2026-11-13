//! Black-box tests for client addressing and the HTTP connection bounds:
//! which address a per-client budget is charged to, which addresses the
//! routing table hands out, and how the HTTP listener treats slow or
//! surplus connections.

mod common;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use axum::http::HeaderName;
use common::{TestRelay, STEP_TIMEOUT};
use futures::StreamExt;
use libp2p::kad::store::MemoryStore;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{DialError, NetworkBehaviour, SwarmEvent};
use libp2p::{identify, kad, noise, tcp, yamux, Multiaddr, PeerId, StreamProtocol, SwarmBuilder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The header the Fly proxy sets, and the flag's value-less default.
const FLY_CLIENT_IP: &str = "fly-client-ip";

/// `GET /username/:name` with `client_ip` in the proxy header. Returns the
/// status code.
async fn lookup_as(addr: SocketAddr, client_ip: &str) -> u16 {
    let request = async {
        let mut stream = tokio::net::TcpStream::connect(addr).await?;
        let req = format!(
            "GET /username/nobody HTTP/1.1\r\nHost: {addr}\r\n\
             {FLY_CLIENT_IP}: {client_ip}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).await?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await?;
        Ok::<_, std::io::Error>(String::from_utf8_lossy(&raw).into_owned())
    };
    let raw = tokio::time::timeout(STEP_TIMEOUT, request)
        .await
        .expect("lookup timed out")
        .expect("lookup");
    raw.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("HTTP status line")
}

async fn relay_with_lookup_budget(limit: usize, trusted_header: bool) -> TestRelay {
    TestRelay::start_with(|c| {
        c.limits.lookup_limit = limit;
        if trusted_header {
            c.trusted_proxy_header = Some(HeaderName::from_static(FLY_CLIENT_IP));
        }
    })
    .await
}

// ── Lookup limiter keys ──────────────────────────────────────────────

#[tokio::test]
async fn the_lookup_limiter_ignores_the_proxy_header_unless_configured() {
    // A client reaching the listener directly could otherwise mint a fresh
    // budget per request by writing a new address into the header.
    let relay = relay_with_lookup_budget(2, false).await;
    let http = relay.handle().http_addr();

    assert_eq!(lookup_as(http, "198.51.100.1").await, 200);
    assert_eq!(lookup_as(http, "198.51.100.2").await, 200);
    assert_eq!(
        lookup_as(http, "198.51.100.3").await,
        429,
        "a third header address must still be charged to the socket address"
    );

    relay.stop().await;
}

#[tokio::test]
async fn the_lookup_limiter_buckets_by_the_proxy_header_when_configured() {
    let relay = relay_with_lookup_budget(2, true).await;
    let http = relay.handle().http_addr();

    assert_eq!(lookup_as(http, "198.51.100.1").await, 200);
    assert_eq!(lookup_as(http, "198.51.100.1").await, 200);
    assert_eq!(lookup_as(http, "198.51.100.1").await, 429);
    assert_eq!(
        lookup_as(http, "198.51.100.2").await,
        200,
        "behind the proxy every client shares one socket address; the header tells them apart"
    );

    relay.stop().await;
}

#[tokio::test]
async fn ipv6_clients_in_one_64_share_a_lookup_budget() {
    // A subscriber is handed a whole /64 (or more), so keying on the full
    // address would give one client 2^64 budgets.
    let relay = relay_with_lookup_budget(2, true).await;
    let http = relay.handle().http_addr();

    assert_eq!(lookup_as(http, "2001:db8:1:2::1").await, 200);
    assert_eq!(lookup_as(http, "2001:db8:1:2:aaaa::7").await, 200);
    assert_eq!(
        lookup_as(http, "2001:db8:1:2:ffff:ffff:ffff:ffff").await,
        429,
        "a third address in the same /64 shares the budget"
    );
    assert_eq!(
        lookup_as(http, "2001:db8:1:3::1").await,
        200,
        "the neighbouring /64 is another client"
    );

    relay.stop().await;
}

// ── HTTP connection bounds ───────────────────────────────────────────

#[tokio::test]
async fn a_connection_that_sends_no_headers_is_closed_at_the_timeout() {
    let relay = TestRelay::start_with(|c| {
        c.limits.http_header_read_timeout = Duration::from_secs(1);
    })
    .await;

    let mut stream = tokio::net::TcpStream::connect(relay.handle().http_addr())
        .await
        .expect("connect");
    let started = Instant::now();
    let mut buf = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut buf)).await;
    assert!(
        read.is_ok(),
        "the relay kept a silent connection open past ten seconds"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(800),
        "closed after {:?}, before the timeout",
        started.elapsed()
    );

    relay.stop().await;
}

#[tokio::test]
async fn connections_past_the_http_limit_wait_for_a_free_slot() {
    let relay = TestRelay::start_with(|c| {
        c.limits.http_max_connections = 1;
        c.limits.http_header_read_timeout = Duration::from_secs(1);
    })
    .await;

    // Hold the only slot with a connection that never sends a request.
    let _silent = tokio::net::TcpStream::connect(relay.handle().http_addr())
        .await
        .expect("connect");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let started = Instant::now();
    let (status, _) = relay.get("/health", None).await;
    assert_eq!(status, 200);
    assert!(
        started.elapsed() >= Duration::from_millis(700),
        "served after {:?}, while the only slot was held",
        started.elapsed()
    );

    relay.stop().await;
}

// ── Handshake bound ──────────────────────────────────────────────────

/// Dial the relay at `relay_addr` (with its `/p2p` suffix) from a fresh
/// swarm. `Ok` once a connection is established, `Err` with the dial error.
async fn dial(relay_addr: &Multiaddr) -> Result<(), String> {
    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .expect("dialer TCP transport")
        .with_behaviour(|_| libp2p::swarm::dummy::Behaviour)
        .expect("dialer behaviour")
        .build();
    swarm.dial(relay_addr.clone()).map_err(|e| e.to_string())?;
    let outcome = async {
        loop {
            match swarm.select_next_some().await {
                SwarmEvent::ConnectionEstablished { .. } => return Ok(()),
                SwarmEvent::OutgoingConnectionError { error, .. } => return Err(error.to_string()),
                _ => {}
            }
        }
    };
    tokio::time::timeout(STEP_TIMEOUT, outcome)
        .await
        .expect("dial timed out")
}

#[tokio::test]
async fn dials_are_refused_while_the_pending_incoming_cap_is_reached() {
    // The established-connection limits only apply after the handshake, so
    // without this cap half-open connections hold handshake state unbounded.
    let relay = TestRelay::start_with(|c| c.limits.max_pending_incoming = 1).await;
    let relay_addr = relay.tcp_addr();
    let tcp_port = common::port_of(relay.handle().listen_addrs(), false).expect("TCP port");

    // Take the only handshake slot with a socket that never negotiates.
    let stalled = tokio::net::TcpStream::connect(("127.0.0.1", tcp_port))
        .await
        .expect("connect");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        dial(&relay_addr).await.is_err(),
        "a dial completed while the pending-incoming cap was reached"
    );

    // Closing it frees the slot.
    drop(stalled);
    let deadline = Instant::now() + STEP_TIMEOUT;
    while let Err(e) = dial(&relay_addr).await {
        assert!(
            Instant::now() < deadline,
            "dials still refused after the slot was freed: {e}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    relay.stop().await;
}

// ── Routing-table admission ──────────────────────────────────────────

/// A peer that connects to the relay and reports one external address
/// through Identify. Its swarm runs in the background until dropped.
struct Advertiser {
    peer_id: PeerId,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Advertiser {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Advertiser {
    async fn connect(relay_addr: &Multiaddr, advertised: Multiaddr) -> Self {
        let mut swarm = SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .expect("advertiser TCP transport")
            .with_behaviour(|key| {
                identify::Behaviour::new(identify::Config::new(
                    "/alexandria/id/1.0".to_string(),
                    key.public(),
                ))
            })
            .expect("advertiser behaviour")
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();
        swarm.add_external_address(advertised);
        swarm.dial(relay_addr.clone()).expect("dial relay");
        let peer_id = *swarm.local_peer_id();
        let task = tokio::spawn(async move {
            loop {
                swarm.select_next_some().await;
            }
        });
        Advertiser { peer_id, task }
    }
}

#[derive(NetworkBehaviour)]
struct QuerierBehaviour {
    kad: kad::Behaviour<MemoryStore>,
}

/// Ask the relay for the peers closest to `target` and return the addresses
/// it handed out for `target`, read from the dial attempt that follows. An
/// empty list means the relay did not return `target`.
async fn addresses_handed_out_for(relay_addr: &Multiaddr, target: PeerId) -> Vec<Multiaddr> {
    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .expect("querier TCP transport")
        .with_behaviour(|key| {
            let peer_id = key.public().to_peer_id();
            let mut kad = kad::Behaviour::with_config(
                peer_id,
                MemoryStore::new(peer_id),
                kad::Config::new(StreamProtocol::new("/alexandria/kad/1.0")),
            );
            kad.set_mode(Some(kad::Mode::Client));
            QuerierBehaviour { kad }
        })
        .expect("querier behaviour")
        .build();
    let relay_peer = relay_addr
        .iter()
        .find_map(|p| match p {
            Protocol::P2p(peer) => Some(peer),
            _ => None,
        })
        .expect("relay address carries /p2p");
    swarm
        .behaviour_mut()
        .kad
        .add_address(&relay_peer, relay_addr.clone());
    let query = swarm.behaviour_mut().kad.get_closest_peers(target);

    let mut handed_out = Vec::new();
    let outcome = async {
        loop {
            match swarm.select_next_some().await {
                SwarmEvent::OutgoingConnectionError {
                    peer_id: Some(peer),
                    error: DialError::Transport(attempts),
                    ..
                } if peer == target => {
                    handed_out.extend(attempts.into_iter().map(|(addr, _)| addr));
                }
                SwarmEvent::Behaviour(QuerierBehaviourEvent::Kad(
                    kad::Event::OutboundQueryProgressed { id, step, .. },
                )) if id == query && step.last => return,
                _ => {}
            }
        }
    };
    tokio::time::timeout(STEP_TIMEOUT, outcome)
        .await
        .expect("closest-peers query timed out");
    handed_out
}

fn has_loopback_ip(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| match p {
        Protocol::Ip4(ip) => ip.is_loopback(),
        Protocol::Ip6(ip) => ip.is_loopback(),
        _ => false,
    })
}

fn has_dns_name(addr: &Multiaddr, name: &str) -> bool {
    addr.iter()
        .any(|p| matches!(p, Protocol::Dns4(n) if n == name))
}

#[tokio::test]
async fn the_routing_table_holds_identify_addresses_not_connection_addresses() {
    // The address a peer dialled in from is an ephemeral NAT port; handing it
    // to other peers gives them something undialable. What the peer reports
    // through Identify, filtered for routability, is what it can be reached
    // at. The querier has no DNS transport, so dialling the DNS address fails
    // at once and the failure lists every address the relay handed out.
    let relay = TestRelay::start().await;
    let relay_addr = relay.tcp_addr();
    let advertised: Multiaddr = "/dns4/advertiser.example/tcp/4001".parse().unwrap();
    let advertiser = Advertiser::connect(&relay_addr, advertised).await;

    let deadline = Instant::now() + STEP_TIMEOUT;
    let handed_out = loop {
        let addrs = addresses_handed_out_for(&relay_addr, advertiser.peer_id).await;
        if addrs.iter().any(|a| has_dns_name(a, "advertiser.example")) {
            break addrs;
        }
        assert!(
            Instant::now() < deadline,
            "the Identify address never reached the routing table; handed out {addrs:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert!(
        !handed_out.iter().any(has_loopback_ip),
        "the connection's remote address was handed out: {handed_out:?}"
    );

    drop(advertiser);
    relay.stop().await;
}
