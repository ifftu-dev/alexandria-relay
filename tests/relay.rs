//! Black-box tests: a real relay on loopback, driven as a client would.
//!
//! Add a case by starting a relay with `TestRelay::start` (or `start_with` to
//! change its configuration) and asserting only on what a client observes.

mod common;

use std::time::{Duration, Instant};

use alexandria_relay::username_reg::ReceiptResponse;
use common::{port_of, signed_claim, TestClient, TestRelay, ADMIN_TOKEN};
use libp2p::multiaddr::Protocol;

#[tokio::test]
async fn start_reports_the_bound_ephemeral_addresses() {
    let relay = TestRelay::start().await;
    let handle = relay.handle();

    let tcp = port_of(handle.listen_addrs(), false).expect("a TCP listen address");
    let quic = port_of(handle.listen_addrs(), true).expect("a QUIC listen address");
    assert_ne!(tcp, 0, "port zero must be reported as the real port");
    assert_ne!(quic, 0, "port zero must be reported as the real port");

    let http = handle.http_addr();
    assert_ne!(http.port(), 0);
    let (status, _) = relay.get("/health", None).await;
    assert_eq!(status, 200, "the reported HTTP address is the bound one");

    relay.stop().await;
}

#[tokio::test]
async fn shutdown_releases_every_listener() {
    let relay = TestRelay::start().await;
    let http = relay.handle().http_addr();
    let tcp = port_of(relay.handle().listen_addrs(), false).expect("a TCP listen address");

    relay.stop().await;

    assert!(
        tokio::net::TcpStream::connect(http).await.is_err(),
        "HTTP still accepting after shutdown"
    );
    assert!(
        tokio::net::TcpStream::connect(("127.0.0.1", tcp))
            .await
            .is_err(),
        "libp2p TCP still accepting after shutdown"
    );
}

#[tokio::test]
async fn health_is_public_and_admin_routes_need_the_token() {
    let relay = TestRelay::start_with(|c| c.admin_token = Some(ADMIN_TOKEN.to_string())).await;

    let (status, body) = relay.get("/health", None).await;
    assert_eq!(status, 200);
    assert!(
        body.contains(&relay.handle().peer_id().to_string()),
        "{body}"
    );

    for path in ["/metrics", "/peers", "/health/alerts"] {
        let (status, _) = relay.get(path, None).await;
        assert_eq!(status, 404, "{path} without a token");
        let (status, _) = relay.get(path, Some("wrong-token-0123456789")).await;
        assert_eq!(status, 404, "{path} with the wrong token");
        let (status, _) = relay.get(path, Some(ADMIN_TOKEN)).await;
        assert_eq!(status, 200, "{path} with the token");
    }

    relay.stop().await;
}

#[tokio::test]
async fn a_reservation_carries_addresses_when_an_external_host_is_configured() {
    // `localhost` resolves from the hosts file, so no network is needed.
    let relay = TestRelay::start_with(|c| c.public_host = Some("localhost".to_string())).await;
    let mut client = TestClient::new();

    let relayed = client
        .reserve(&relay.tcp_addr())
        .await
        .expect("reservation accepted");
    assert!(!relayed.is_empty());
    for addr in &relayed {
        assert!(
            addr.iter().any(|p| matches!(p, Protocol::P2pCircuit)),
            "{addr} is not a relayed address"
        );
    }

    relay.stop().await;
}

#[tokio::test]
async fn a_reservation_is_refused_address_less_without_an_external_host() {
    let relay = TestRelay::start().await;
    let mut client = TestClient::new();

    let refused = client
        .reserve(&relay.tcp_addr())
        .await
        .expect_err("an address-less reservation must not produce a listener");
    assert!(refused.contains("NoAddressesInReservation"), "{refused}");

    relay.stop().await;
}

#[tokio::test]
async fn receipts_follow_first_seen_order() {
    let relay = TestRelay::start().await;
    let relay_addr = relay.tcp_addr();
    let mut client = TestClient::new();

    let first = signed_claim(1, "ada_99", 1_700_000_000);
    let granted = match client.request_receipt(&relay_addr, &first).await {
        ReceiptResponse::Granted(r) => r,
        other => panic!("expected Granted, got {other:?}"),
    };
    assert_eq!(granted.relay_peer_id, relay.handle().peer_id().to_string());

    // Refreshing the same claim re-issues the original receipt: priority is
    // the first-seen time, and a refresh never resets it.
    match client.request_receipt(&relay_addr, &first).await {
        ReceiptResponse::Granted(again) => {
            assert_eq!(again.received_at, granted.received_at);
            assert_eq!(again.sig, granted.sig);
        }
        other => panic!("expected the receipt re-issued, got {other:?}"),
    }

    // A second DID claiming the same name is refused, even with an earlier
    // self-asserted time, and told who holds it since when.
    let second = signed_claim(2, "ada_99", 1_600_000_000);
    match client.request_receipt(&relay_addr, &second).await {
        ReceiptResponse::Refused {
            existing_did,
            existing_received_at,
            ..
        } => {
            assert_eq!(existing_did, Some(first.did.clone()));
            assert_eq!(existing_received_at, Some(granted.received_at));
        }
        other => panic!("expected Refused, got {other:?}"),
    }

    // The public lookup agrees.
    let (status, body) = relay.get("/username/ada_99", None).await;
    assert_eq!(status, 200);
    assert!(body.contains(&first.did), "{body}");

    relay.stop().await;
}

#[tokio::test]
async fn an_oversized_did_is_refused_over_the_wire_without_delay() {
    // Base58 decoding is quadratic. A DID that fills the request size cap
    // must be refused before any decoding, or one request pins the event
    // loop for as long as the decode takes.
    // Lift the per-peer receipt budget: this test is about decoding, not the
    // limiter.
    let relay = TestRelay::start_with(|c| c.limits.receipt_limit = usize::MAX).await;
    let relay_addr = relay.tcp_addr();
    let mut client = TestClient::new();
    // Connect first, so the timing below covers the requests alone.
    client
        .request_receipt(&relay_addr, &signed_claim(1, "ada_99", 1_700_000_000))
        .await;

    // Just under the request size cap, so the codec reads it whole.
    let mut claim = signed_claim(2, "bob_99", 1_700_000_000);
    claim.did = format!("did:key:z{}", "2".repeat(7_500));
    let started = Instant::now();
    for _ in 0..OVERSIZED_DID_REQUESTS {
        match client.request_receipt(&relay_addr, &claim).await {
            ReceiptResponse::Refused { reason, .. } => {
                assert!(reason.starts_with("invalid claim"), "{reason}");
            }
            other => panic!("expected Refused, got {other:?}"),
        }
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < OVERSIZED_DID_BOUND,
        "{OVERSIZED_DID_REQUESTS} oversized DIDs took {elapsed:?} to refuse"
    );

    relay.stop().await;
}

/// Oversized-DID requests sent in a row, so a per-request decode adds up to
/// far more than loopback round trips do.
const OVERSIZED_DID_REQUESTS: u32 = 20;

/// How long refusing them all may take. Twenty loopback round trips take
/// tens of milliseconds even in a debug build; decoding each DID takes
/// around a hundred.
const OVERSIZED_DID_BOUND: Duration = Duration::from_millis(600);

#[tokio::test]
async fn admin_routes_stay_off_without_a_configured_token() {
    let relay = TestRelay::start().await;
    let (status, _) = relay.get("/metrics", Some(ADMIN_TOKEN)).await;
    assert_eq!(status, 404);
    relay.stop().await;
}
