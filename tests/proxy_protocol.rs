//! PROXY protocol v2 on inbound TCP, as clients behind a proxy and the
//! operator see it: which address the relay attributes a connection to, which
//! connections it refuses, and what `/metrics` and `/health/alerts` report.

mod common;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use alexandria_relay::config::ProxyProtocol;
use alexandria_relay::RelayConfig;
use common::{
    http_get_with, identify_relay, proxy_v2_header, proxy_v2_local_header, proxy_v2_raw, ProxyShim,
    TestClient, TestRelay, ADMIN_TOKEN, STEP_TIMEOUT,
};
use libp2p::Multiaddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A client address from the documentation range (RFC 5737).
fn client(last: u8, port: u16) -> SocketAddr {
    SocketAddr::from(([192, 0, 2, last], port))
}

/// Admin token, a public host (reservations need one) and PROXY v2.
fn behind_proxy(c: &mut RelayConfig) {
    c.admin_token = Some(ADMIN_TOKEN.to_string());
    c.public_host = Some("localhost".to_string());
    c.tcp_proxy_protocol = ProxyProtocol::V2;
}

/// The `/peers` entries as `(source_prefix)` strings.
async fn peer_prefixes(relay: &TestRelay) -> Vec<String> {
    let (status, body) = relay.get("/peers", Some(ADMIN_TOKEN)).await;
    assert_eq!(status, 200, "{body}");
    let entries: Vec<serde_json::Value> = serde_json::from_str(&body).expect("JSON peers");
    entries
        .iter()
        .map(|e| e["source_prefix"].as_str().expect("prefix").to_string())
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_behind_the_proxy_is_attributed_to_the_header_source() {
    let relay = TestRelay::start_with(behind_proxy).await;
    let shim = ProxyShim::start(&relay, proxy_v2_header(client(7, 40_000))).await;

    let mut holder = TestClient::new();
    holder
        .reserve(&shim.addr(&relay))
        .await
        .expect("reservation through the proxy");
    assert_eq!(
        peer_prefixes(&relay).await,
        vec!["192.0.2.0/24".to_string()]
    );

    let info = identify_relay(&shim.addr(&relay)).await;
    let expected: Multiaddr = "/ip4/192.0.2.7/tcp/40000".parse().unwrap();
    assert_eq!(info.observed_addr, expected);
    relay.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_ipv6_source_is_attributed_to_its_64() {
    let relay = TestRelay::start_with(behind_proxy).await;
    let src: SocketAddr = "[2001:db8:1:2::9]:51000".parse().unwrap();
    let shim = ProxyShim::start(&relay, proxy_v2_header(src)).await;
    let info = identify_relay(&shim.addr(&relay)).await;
    let expected: Multiaddr = "/ip6/2001:db8:1:2::9/tcp/51000".parse().unwrap();
    assert_eq!(info.observed_addr, expected);

    let mut holder = TestClient::new();
    holder.connect(&shim.addr(&relay)).await.expect("connect");
    assert_eq!(
        peer_prefixes(&relay).await,
        vec!["2001:db8:1::/48".to_string()]
    );
    relay.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_per_ip_cap_counts_the_header_address() {
    let relay = TestRelay::start_with(|c| {
        behind_proxy(c);
        c.limits.max_connections_per_ip = 1;
    })
    .await;

    // Two sources: two clients, both kept.
    let a = ProxyShim::start(&relay, proxy_v2_header(client(7, 40_000))).await;
    let b = ProxyShim::start(
        &relay,
        proxy_v2_header(SocketAddr::from(([198, 51, 100, 7], 40_000))),
    )
    .await;
    let (mut first, mut second) = (TestClient::new(), TestClient::new());
    first.connect(&a.addr(&relay)).await.expect("first source");
    second
        .connect(&b.addr(&relay))
        .await
        .expect("second source");
    let mut prefixes = peer_prefixes(&relay).await;
    prefixes.sort();
    assert_eq!(prefixes, ["192.0.2.0/24", "198.51.100.0/24"]);
    assert_eq!(metric(&relay, "ip_rate_limited").await, 0);

    // A second client from the first source goes over the cap of one,
    // although every connection arrives from the same loopback socket
    // address.
    let a2 = ProxyShim::start(&relay, proxy_v2_header(client(7, 40_001))).await;
    let mut third = TestClient::new();
    let _ = third.connect(&a2.addr(&relay)).await;
    wait_for_metric(&relay, "ip_rate_limited", 1).await;
    relay.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_connection_without_a_header_is_refused() {
    let relay = TestRelay::start_with(behind_proxy).await;
    let direct = TestClient::new().connect(&relay.tcp_addr()).await;
    assert!(direct.is_err(), "a direct client got in");
    wait_for_metric(&relay, "proxy_header_missing", 1).await;
    relay.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_silent_socket_is_closed_at_the_header_timeout() {
    let relay = TestRelay::start_with(|c| {
        behind_proxy(c);
        c.proxy_header_timeout = Duration::from_millis(300);
    })
    .await;
    let started = Instant::now();
    let mut socket = TcpStream::connect(relay.tcp_socket_addr())
        .await
        .expect("connect");
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(STEP_TIMEOUT, socket.read(&mut buf))
        .await
        .expect("the relay closes the socket");
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
    assert!(started.elapsed() >= Duration::from_millis(300));
    wait_for_metric(&relay, "proxy_header_timeout", 1).await;
    relay.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn v1_and_oversized_headers_are_refused() {
    let relay = TestRelay::start_with(behind_proxy).await;
    let v1 = ProxyShim::start(
        &relay,
        b"PROXY TCP4 192.0.2.7 10.0.0.1 40000 4001\r\n".to_vec(),
    )
    .await;
    assert!(TestClient::new().connect(&v1.addr(&relay)).await.is_err());
    wait_for_metric(&relay, "proxy_header_invalid", 1).await;

    let mut body = vec![192, 0, 2, 7, 10, 0, 0, 1, 0x9c, 0x40, 0x0f, 0xa1];
    body.resize(1100, 0); // TLV space past the 1 KiB cap
    let oversized = ProxyShim::start(&relay, proxy_v2_raw(0x21, 0x11, &body)).await;
    assert!(TestClient::new()
        .connect(&oversized.addr(&relay))
        .await
        .is_err());
    wait_for_metric(&relay, "proxy_header_invalid", 2).await;
    assert_eq!(metric(&relay, "proxy_header_missing").await, 0);
    relay.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_local_header_is_attributed_to_the_socket_address() {
    let relay = TestRelay::start_with(behind_proxy).await;
    let shim = ProxyShim::start(&relay, proxy_v2_local_header()).await;
    let mut holder = TestClient::new();
    holder
        .connect(&shim.addr(&relay))
        .await
        .expect("LOCAL accepted");
    assert_eq!(
        peer_prefixes(&relay).await,
        vec!["127.0.0.0/24".to_string()]
    );
    relay.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn with_proxy_protocol_off_a_header_breaks_the_connection() {
    let relay = TestRelay::start_with(|c| c.admin_token = Some(ADMIN_TOKEN.to_string())).await;
    let shim = ProxyShim::start(&relay, proxy_v2_header(client(7, 40_000))).await;
    assert!(TestClient::new().connect(&shim.addr(&relay)).await.is_err());
    // Off reads nothing, so nothing is counted, and direct clients get in.
    assert_eq!(metric(&relay, "proxy_header_missing").await, 0);
    TestClient::new()
        .connect(&relay.tcp_addr())
        .await
        .expect("direct client with PROXY protocol off");
    relay.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sockets_past_the_waiting_cap_are_closed_on_accept() {
    let relay = TestRelay::start_with(|c| {
        behind_proxy(c);
        c.limits.max_pending_incoming = 2;
        c.proxy_header_timeout = Duration::from_secs(30);
    })
    .await;
    let mut waiting = Vec::new();
    for _ in 0..2 {
        waiting.push(
            TcpStream::connect(relay.tcp_socket_addr())
                .await
                .expect("connect"),
        );
    }
    // Let the relay accept both before the third arrives.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut third = TcpStream::connect(relay.tcp_socket_addr())
        .await
        .expect("connect");
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(10), third.read(&mut buf))
        .await
        .expect("the third socket is closed well before the header timeout");
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
    wait_for_metric(&relay, "proxy_header_overflow", 1).await;
    relay.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_header_refusal_alert_fires_when_refusals_dominate() {
    let relay = TestRelay::start_with(behind_proxy).await;

    // One scanner is not a misconfigured proxy.
    refuse_direct(&relay, 1).await;
    wait_for_metric(&relay, "proxy_header_missing", 1).await;
    assert!(!alerts(&relay).await.contains(&ALERT.to_string()));

    // A proxy that stops sending headers is.
    refuse_direct(&relay, 11).await;
    wait_for_metric(&relay, "proxy_header_missing", 12).await;
    let (status, body) = relay.get("/health/alerts", Some(ADMIN_TOKEN)).await;
    assert_eq!(status, 503, "{body}");
    assert!(alerts(&relay).await.contains(&ALERT.to_string()), "{body}");

    // Prometheus carries the counters too.
    let (_, _, text) = http_get_with(
        relay.handle().http_addr(),
        "/metrics",
        Some(ADMIN_TOKEN),
        &[("Accept", "text/plain")],
    )
    .await;
    assert!(
        text.contains("relay_proxy_header_missing_total 12"),
        "{text}"
    );
    assert!(
        text.contains("relay_proxy_header_overflow_total 0"),
        "{text}"
    );
    relay.stop().await;
}

const ALERT: &str = "proxy_header_refusal_majority";

/// Open `n` sockets that speak HTTP instead of sending a header.
async fn refuse_direct(relay: &TestRelay, n: usize) {
    for _ in 0..n {
        let mut socket = TcpStream::connect(relay.tcp_socket_addr())
            .await
            .expect("connect");
        socket
            .write_all(b"GET / HTTP/1.1\r\nHost: relay\r\n\r\n")
            .await
            .expect("write");
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(STEP_TIMEOUT, socket.read_to_end(&mut buf)).await;
    }
}

async fn alerts(relay: &TestRelay) -> Vec<String> {
    let (_, body) = relay.get("/health/alerts", Some(ADMIN_TOKEN)).await;
    let json: serde_json::Value = serde_json::from_str(&body).expect("JSON alerts");
    json["alerts"]
        .as_array()
        .expect("alerts array")
        .iter()
        .map(|a| a.as_str().expect("alert name").to_string())
        .collect()
}

/// A counter from the JSON form of `/metrics`.
async fn metric(relay: &TestRelay, name: &str) -> u64 {
    let (status, body) = relay.get("/metrics", Some(ADMIN_TOKEN)).await;
    assert_eq!(status, 200, "{body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("JSON metrics");
    json[name]
        .as_u64()
        .unwrap_or_else(|| panic!("{name} missing from {body}"))
}

/// Wait until the counter `name` reaches `expected`; fail if it overshoots
/// or does not get there in time.
async fn wait_for_metric(relay: &TestRelay, name: &str, expected: u64) {
    let deadline = Instant::now() + STEP_TIMEOUT;
    loop {
        let value = metric(relay, name).await;
        assert!(value <= expected, "{name} is {value}, expected {expected}");
        if value == expected {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{name} stayed at {value}, expected {expected}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
