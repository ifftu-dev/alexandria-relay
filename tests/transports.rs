//! Which transports the relay runs and which addresses it hands out, as a
//! client sees them: listen addresses, Identify, reservations, and the
//! per-transport counters an operator reads.

mod common;

use common::{http_get_with, identify_relay, is_quic, TestClient, TestRelay, ADMIN_TOKEN};
use libp2p::multiaddr::Protocol;

/// A loopback UDP port that is free right now.
fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("bind UDP")
        .local_addr()
        .expect("local addr")
        .port()
}

#[tokio::test(flavor = "multi_thread")]
async fn with_quic_off_the_relay_binds_no_udp_and_hands_out_no_quic_address() {
    let quic_port = free_udp_port();
    let relay = TestRelay::start_with(|c| {
        c.quic = false;
        c.quic_port = quic_port;
        c.public_host = Some("localhost".to_string());
    })
    .await;
    let handle = relay.handle();

    // No UDP listener: the QUIC port stays free.
    assert!(
        !handle.listen_addrs().iter().any(is_quic),
        "{:?}",
        handle.listen_addrs()
    );
    std::net::UdpSocket::bind(("127.0.0.1", quic_port)).expect("the QUIC port is still free");

    // No QUIC external address, neither the dns4 form nor the resolved ones.
    let external = handle.external_addrs();
    assert!(
        external
            .iter()
            .any(|a| a.iter().any(|p| matches!(p, Protocol::Dns4(_)))),
        "{external:?}"
    );
    assert!(
        external
            .iter()
            .any(|a| a.iter().any(|p| matches!(p, Protocol::Ip4(_)))),
        "{external:?}"
    );
    assert!(!external.iter().any(is_quic), "{external:?}");

    // Identify carries none.
    let info = identify_relay(&relay.tcp_addr()).await;
    assert!(!info.listen_addrs.is_empty(), "{:?}", info.listen_addrs);
    assert!(
        !info.listen_addrs.iter().any(is_quic),
        "{:?}",
        info.listen_addrs
    );

    // TCP still serves reservations, and their address set has no QUIC.
    let relayed = TestClient::new()
        .reserve(&relay.tcp_addr())
        .await
        .expect("reservation over TCP");
    assert!(!relayed.is_empty());
    assert!(!relayed.iter().any(is_quic), "{relayed:?}");
    relay.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn identify_reports_only_external_addresses_once_a_public_host_is_set() {
    // `invalid.` never resolves (RFC 6761), so the external addresses are
    // the dns4 forms alone and differ from every listen address.
    let relay = TestRelay::start_with(|c| c.public_host = Some("relay.invalid".to_string())).await;
    let info = identify_relay(&relay.tcp_addr()).await;
    assert!(!info.listen_addrs.is_empty());
    let mut reported = info.listen_addrs.clone();
    let mut external = relay.handle().external_addrs().to_vec();
    reported.sort();
    external.sort();
    assert_eq!(reported, external, "listen addresses stay private");
    relay.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn identify_reports_listen_addresses_without_a_public_host() {
    let relay = TestRelay::start().await;
    let info = identify_relay(&relay.tcp_addr()).await;
    for listen in relay.handle().listen_addrs() {
        assert!(
            info.listen_addrs.contains(listen),
            "{listen} missing from {:?}",
            info.listen_addrs
        );
    }
    relay.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn with_quic_on_the_relay_listens_and_advertises_quic() {
    let relay = TestRelay::start_with(|c| c.public_host = Some("localhost".to_string())).await;
    let handle = relay.handle();
    assert!(handle.listen_addrs().iter().any(is_quic));
    assert!(handle.external_addrs().iter().any(is_quic));
    let info = identify_relay(&relay.tcp_addr()).await;
    assert!(
        info.listen_addrs.iter().any(is_quic),
        "{:?}",
        info.listen_addrs
    );
    relay.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_reserves_over_quic_with_the_smaller_windows_and_is_counted_under_quic() {
    let relay = TestRelay::start_with(|c| {
        c.admin_token = Some(ADMIN_TOKEN.to_string());
        c.public_host = Some("localhost".to_string());
        c.limits.quic.max_stream_data = 64 * 1024;
        c.limits.quic.max_connection_data = 128 * 1024;
    })
    .await;

    let relayed = TestClient::with_quic()
        .reserve(&relay.quic_addr())
        .await
        .expect("reservation over QUIC");
    assert!(!relayed.is_empty());

    let (status, body) = relay.get("/metrics", Some(ADMIN_TOKEN)).await;
    assert_eq!(status, 200, "{body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("JSON metrics");
    assert_eq!(json["connections_established"]["quic"], 1, "{body}");
    assert_eq!(json["connections_established"]["tcp"], 0, "{body}");
    assert_eq!(json["quic_pending_denied"], 0, "{body}");

    let accept = [("Accept", "text/plain")];
    let (status, _, body) = http_get_with(
        relay.handle().http_addr(),
        "/metrics",
        Some(ADMIN_TOKEN),
        &accept,
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        body.contains("relay_connections_established_total{transport=\"quic\"} 1"),
        "{body}"
    );
    assert!(
        body.contains("relay_connections_established_total{transport=\"tcp\"} 0"),
        "{body}"
    );
    assert!(body.contains("relay_quic_pending_denied_total 0"), "{body}");
    relay.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tcp_connection_is_counted_under_tcp() {
    let relay = TestRelay::start_with(|c| {
        c.admin_token = Some(ADMIN_TOKEN.to_string());
        c.public_host = Some("localhost".to_string());
    })
    .await;
    TestClient::new()
        .reserve(&relay.tcp_addr())
        .await
        .expect("reservation over TCP");
    let (status, body) = relay.get("/metrics", Some(ADMIN_TOKEN)).await;
    assert_eq!(status, 200, "{body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("JSON metrics");
    assert_eq!(json["connections_established"]["tcp"], 1, "{body}");
    assert_eq!(json["connections_established"]["quic"], 0, "{body}");
    relay.stop().await;
}
