//! Black-box tests for what an operator's tooling reads: the Prometheus and
//! JSON forms of `/metrics`, and `/health`.

mod common;

use common::{http_get_with, TestClient, TestRelay, ADMIN_TOKEN};

/// What Prometheus sends when it scrapes a target.
const PROMETHEUS_ACCEPT: &str = "application/openmetrics-text;version=1.0.0;q=0.5,\
     text/plain;version=0.0.4;q=0.4,*/*;q=0.1";

/// The value of the unlabelled sample `name` in a Prometheus text body.
fn sample(body: &str, name: &str) -> Option<f64> {
    body.lines().filter(|l| !l.starts_with('#')).find_map(|l| {
        let (metric, value) = l.split_once(' ')?;
        (metric == name).then(|| value.trim().parse().ok())?
    })
}

#[tokio::test]
async fn metrics_speak_prometheus_when_asked_and_json_otherwise() {
    let relay = TestRelay::start_with(|c| c.admin_token = Some(ADMIN_TOKEN.to_string())).await;
    let http = relay.handle().http_addr();
    let accept = [("Accept", PROMETHEUS_ACCEPT)];

    let (status, content_type, body) =
        http_get_with(http, "/metrics", Some(ADMIN_TOKEN), &accept).await;
    assert_eq!(status, 200);
    assert!(content_type.starts_with("text/plain"), "{content_type}");
    assert!(content_type.contains("version=0.0.4"), "{content_type}");
    assert!(
        body.contains("# TYPE relay_circuits_accepted_total counter"),
        "{body}"
    );
    assert!(body.contains("# TYPE relay_connections gauge"), "{body}");
    assert_eq!(sample(&body, "relay_circuits_accepted_total"), Some(0.0));
    assert_eq!(sample(&body, "relay_profile_relays"), Some(0.0));
    assert!(
        body.contains("relay_bootstrap_status{status=\"disabled\"} 1"),
        "{body}"
    );
    assert!(
        body.contains("relay_bootstrap_status{status=\"ok\"} 0"),
        "{body}"
    );
    // Per-peer data never leaves through metrics.
    assert!(!body.contains("source_prefix"), "{body}");
    assert!(!body.contains("127.0.0.1"), "{body}");

    // Anything else gets the JSON the monitoring observer already parses.
    for headers in [&[][..], &[("Accept", "application/json")][..]] {
        let (status, content_type, body) =
            http_get_with(http, "/metrics", Some(ADMIN_TOKEN), headers).await;
        assert_eq!(status, 200);
        assert!(
            content_type.starts_with("application/json"),
            "{content_type}"
        );
        let json: serde_json::Value = serde_json::from_str(&body).expect("JSON metrics");
        assert_eq!(json["circuits_accepted"], 0);
        assert_eq!(json["peer_id"], relay.handle().peer_id().to_string());
    }

    // Both forms sit behind the same bearer gate.
    for headers in [&accept[..], &[][..]] {
        let (status, _, body) = http_get_with(http, "/metrics", None, headers).await;
        assert_eq!(status, 404);
        assert!(!body.contains("relay_"), "{body}");
        let (status, _, _) =
            http_get_with(http, "/metrics", Some("wrong-token-0123456789"), headers).await;
        assert_eq!(status, 404);
    }

    relay.stop().await;
}

#[tokio::test]
async fn health_reports_the_version_and_live_connections() {
    let relay = TestRelay::start_with(|c| c.public_host = Some("localhost".to_string())).await;
    let http = relay.handle().http_addr();

    let (_, _, body) = http_get_with(http, "/health", None, &[]).await;
    let health: serde_json::Value = serde_json::from_str(&body).expect("JSON health");
    assert_eq!(health["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(health["connections"], 0);

    // A client holding a reservation is connected now, not at the next
    // five-minute sample.
    let mut client = TestClient::new();
    client
        .reserve(&relay.tcp_addr())
        .await
        .expect("reservation accepted");
    let (_, _, body) = http_get_with(http, "/health", None, &[]).await;
    let health: serde_json::Value = serde_json::from_str(&body).expect("JSON health");
    assert_eq!(health["connections"], 1, "{body}");

    relay.stop().await;
}
