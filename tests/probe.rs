//! `alexandria-relay probe`, run as an operator would: the real binary
//! against a relay on loopback, judged by its exit code and output.

mod common;

use std::net::Ipv6Addr;
use std::process::Output;
use std::time::{Duration, Instant};

use common::{TempDir, TestRelay};
use futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use libp2p::{identify, noise, tcp, yamux, SwarmBuilder};

/// Run `probe` with `args`.
async fn probe(args: &[&str]) -> Output {
    probe_with_env(args, &[]).await
}

/// Run `probe` with `args` and the relay variables `env` set.
async fn probe_with_env(args: &[&str], env: &[(&str, &str)]) -> Output {
    tokio::process::Command::new(env!("CARGO_BIN_EXE_alexandria-relay"))
        .arg("probe")
        .args(args)
        .env_remove("RELAY_SEED")
        .env_remove("RELAY_PORT")
        .env_remove("RELAY_NETWORK_PROFILE")
        .env_remove("RELAY_QUIC")
        .envs(env.iter().copied())
        .env("RUST_LOG", "warn")
        .output()
        .await
        .expect("run alexandria-relay probe")
}

/// Stdout and stderr together, for assertion messages.
fn output_text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The relay's loopback TCP port.
fn tcp_port(relay: &TestRelay) -> String {
    common::port_of(relay.handle().listen_addrs(), false)
        .expect("a TCP listen port")
        .to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn probe_passes_over_tcp_against_an_ipv4_literal() {
    let relay = TestRelay::start().await;
    let peer_id = relay.handle().peer_id().to_string();
    let port = tcp_port(&relay);

    let output = probe(&[
        "--host",
        "127.0.0.1",
        "--port",
        &port,
        "--peer-id",
        &peer_id,
    ])
    .await;
    let text = output_text(&output);
    assert!(output.status.success(), "{text}");
    let out = stdout(&output);
    assert!(
        out.contains(&format!(
            "PASS  tcp   /ip4/127.0.0.1/tcp/{port}/p2p/{peer_id}"
        )),
        "{text}"
    );
    assert!(
        !out.contains("quic"),
        "QUIC is checked only on request: {text}"
    );
    relay.stop().await;
}

/// A loopback port free for both TCP and UDP right now. The probe dials
/// TCP and QUIC on one port, as a production relay serves them.
fn port_free_for_tcp_and_udp() -> u16 {
    loop {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").expect("bind TCP");
        let port = tcp.local_addr().expect("local addr").port();
        if std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn probe_passes_over_tcp_and_quic() {
    let port = port_free_for_tcp_and_udp();
    let relay = TestRelay::start_with(|c| {
        c.tcp_port = port;
        c.quic_port = port;
    })
    .await;
    let peer_id = relay.handle().peer_id().to_string();
    let port = port.to_string();

    let output = probe(&[
        "--host",
        "127.0.0.1",
        "--port",
        &port,
        "--peer-id",
        &peer_id,
        "--quic",
    ])
    .await;
    let text = output_text(&output);
    assert!(output.status.success(), "{text}");
    let out = stdout(&output);
    assert!(
        out.contains(&format!(
            "PASS  tcp   /ip4/127.0.0.1/tcp/{port}/p2p/{peer_id}"
        )),
        "{text}"
    );
    assert!(
        out.contains(&format!(
            "PASS  quic  /ip4/127.0.0.1/udp/{port}/quic-v1/p2p/{peer_id}"
        )),
        "{text}"
    );
    relay.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn probe_dials_an_ipv6_literal_over_ipv6() {
    let port = port_free_for_tcp_and_udp();
    let relay = TestRelay::start_with(|c| {
        c.listen_ip6 = Some(Ipv6Addr::LOCALHOST);
        c.tcp_port = port;
        c.quic_port = port;
    })
    .await;
    let peer_id = relay.handle().peer_id().to_string();
    let port = port.to_string();

    let output = probe(&["--host", "::1", "--port", &port, "--peer-id", &peer_id]).await;
    let text = output_text(&output);
    assert!(output.status.success(), "{text}");
    assert!(
        stdout(&output).contains(&format!("PASS  tcp   /ip6/::1/tcp/{port}/p2p/{peer_id}")),
        "{text}"
    );
    relay.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn probe_dials_a_dns_name_over_ipv4() {
    let relay = TestRelay::start().await;
    let peer_id = relay.handle().peer_id().to_string();
    let port = tcp_port(&relay);

    let output = probe(&[
        "--host",
        "localhost",
        "--port",
        &port,
        "--peer-id",
        &peer_id,
    ])
    .await;
    let text = output_text(&output);
    assert!(output.status.success(), "{text}");
    assert!(
        stdout(&output).contains(&format!(
            "PASS  tcp   /dns4/localhost/tcp/{port}/p2p/{peer_id}"
        )),
        "{text}"
    );
    relay.stop().await;
}

fn random_peer_id() -> String {
    libp2p::identity::Keypair::generate_ed25519()
        .public()
        .to_peer_id()
        .to_string()
}

/// Write a network profile listing `relay_peer` at `localhost:port`, beside
/// another relay, and return its path.
fn write_profile(dir: &TempDir, relay_peer: &str, port: &str) -> String {
    let profile = serde_json::json!({
        "schema_version": 1,
        "network_id": "probe-test",
        "protocol_namespace": "/alexandria/probe-test",
        "relays": [
            {
                "peer_id": random_peer_id(),
                "dns_name": "relay-a.example.org",
                "port": 4001,
                "fallback_ips": ["1.1.1.1"]
            },
            {
                "peer_id": relay_peer,
                "dns_name": "localhost",
                "port": port.parse::<u16>().expect("port"),
                "fallback_ips": ["1.0.0.1"]
            }
        ]
    });
    let path = dir.path().join("network.json");
    std::fs::write(&path, profile.to_string()).expect("write profile");
    path.to_string_lossy().into_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn probe_reads_the_expected_peer_id_from_a_network_profile() {
    let relay = TestRelay::start().await;
    let peer_id = relay.handle().peer_id().to_string();
    let port = tcp_port(&relay);
    let dir = TempDir::new();
    let profile = write_profile(&dir, &peer_id, &port);

    let output = probe(&[
        "--host",
        "localhost",
        "--port",
        &port,
        "--network-profile",
        &profile,
    ])
    .await;
    let text = output_text(&output);
    assert!(output.status.success(), "{text}");
    let out = stdout(&output);
    assert!(out.contains("network profile"), "{text}");
    assert!(
        out.contains(&format!(
            "PASS  tcp   /dns4/localhost/tcp/{port}/p2p/{peer_id}"
        )),
        "{text}"
    );
    relay.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn probe_fails_when_the_profile_does_not_list_the_host() {
    let relay = TestRelay::start().await;
    let port = tcp_port(&relay);
    let dir = TempDir::new();
    let profile = write_profile(&dir, &random_peer_id(), &port);

    let output = probe(&[
        "--host",
        "127.0.0.1",
        "--port",
        &port,
        "--network-profile",
        &profile,
    ])
    .await;
    let text = output_text(&output);
    assert!(!output.status.success(), "{text}");
    assert!(
        stdout(&output).contains("no relay with dns_name 127.0.0.1"),
        "{text}"
    );
    relay.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn probe_reads_the_peer_id_from_health_and_says_it_is_not_pinned() {
    let relay = TestRelay::start().await;
    let peer_id = relay.handle().peer_id().to_string();
    let port = tcp_port(&relay);
    let health = format!("http://{}/health", relay.handle().http_addr());

    let output = probe(&[
        "--host",
        "127.0.0.1",
        "--port",
        &port,
        "--health-url",
        &health,
    ])
    .await;
    let text = output_text(&output);
    assert!(output.status.success(), "{text}");
    let out = stdout(&output);
    assert!(out.contains("not pinned"), "{text}");
    assert!(
        out.contains(&format!(
            "PASS  tcp   /ip4/127.0.0.1/tcp/{port}/p2p/{peer_id}"
        )),
        "{text}"
    );
    relay.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn probe_ignores_the_relays_own_port_and_profile_variables() {
    // A probe run on a relay host, where the relay's variables are set,
    // still dials the default port and takes no profile from them.
    let relay = TestRelay::start().await;
    let port = tcp_port(&relay);
    let health = format!("http://{}/health", relay.handle().http_addr());

    let output = probe_with_env(
        &[
            "--host",
            "127.0.0.1",
            "--port",
            &port,
            "--health-url",
            &health,
        ],
        &[("RELAY_NETWORK_PROFILE", "/nonexistent/network.json")],
    )
    .await;
    let text = output_text(&output);
    assert!(output.status.success(), "{text}");

    let output = probe_with_env(
        &[
            "--host",
            "127.0.0.1",
            "--peer-id",
            &random_peer_id(),
            "--timeout-secs",
            "1",
        ],
        &[("RELAY_PORT", &port)],
    )
    .await;
    let text = output_text(&output);
    assert!(
        stdout(&output).contains("/ip4/127.0.0.1/tcp/4001/"),
        "{text}"
    );
    relay.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn probe_takes_its_quic_choice_from_its_own_flag_not_relay_quic() {
    // `RELAY_QUIC` switches the local relay's QUIC; the probe's `--quic`
    // alone decides whether the probed relay is dialled over QUIC.
    let port = port_free_for_tcp_and_udp();
    let relay = TestRelay::start_with(|c| {
        c.tcp_port = port;
        c.quic_port = port;
    })
    .await;
    let peer_id = relay.handle().peer_id().to_string();
    let port = port.to_string();
    let args = [
        "--host",
        "127.0.0.1",
        "--port",
        &port,
        "--peer-id",
        &peer_id,
    ];

    let output = probe_with_env(&args, &[("RELAY_QUIC", "true")]).await;
    let text = output_text(&output);
    assert!(output.status.success(), "{text}");
    assert!(!stdout(&output).contains("quic"), "{text}");

    let with_quic: Vec<&str> = args.iter().copied().chain(["--quic"]).collect();
    let output = probe_with_env(&with_quic, &[("RELAY_QUIC", "false")]).await;
    let text = output_text(&output);
    assert!(output.status.success(), "{text}");
    assert!(stdout(&output).contains("PASS  quic"), "{text}");
    relay.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn probe_fails_without_any_source_for_the_peer_id() {
    let output = probe(&["--host", "127.0.0.1"]).await;
    let text = output_text(&output);
    assert!(!output.status.success(), "{text}");
    assert!(stdout(&output).contains("--health-url"), "{text}");
}

#[tokio::test(flavor = "multi_thread")]
async fn probe_fails_when_a_non_alexandria_node_answers() {
    // A plain libp2p node with the right PeerId but another Identify
    // protocol version: an open port that is not an Alexandria relay.
    let mut node = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .expect("TCP transport")
        .with_behaviour(|key| {
            identify::Behaviour::new(identify::Config::new(
                "/ipfs/0.1.0".to_string(),
                key.public(),
            ))
        })
        .expect("behaviour")
        .build();
    node.listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr"))
        .expect("listen");
    let port = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = node.select_next_some().await {
            break common::port_of(&[address], false).expect("TCP port");
        }
    };
    let peer_id = node.local_peer_id().to_string();
    let serve = tokio::spawn(async move {
        loop {
            node.select_next_some().await;
        }
    });

    let output = probe(&[
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--peer-id",
        &peer_id,
        "--timeout-secs",
        "5",
    ])
    .await;
    serve.abort();
    let text = output_text(&output);
    assert!(!output.status.success(), "{text}");
    let out = stdout(&output);
    assert!(out.contains("FAIL  tcp"), "{text}");
    assert!(out.contains("/ipfs/0.1.0"), "{text}");
    assert!(out.contains("/alexandria/id/1.0"), "{text}");
}

#[tokio::test(flavor = "multi_thread")]
async fn probe_fails_quic_when_only_tcp_answers() {
    // The relay's QUIC listener is on another port, so QUIC on the probed
    // port gets no answer: one transport failing fails the run.
    let relay = TestRelay::start().await;
    let peer_id = relay.handle().peer_id().to_string();
    let port = tcp_port(&relay);

    let output = probe(&[
        "--host",
        "127.0.0.1",
        "--port",
        &port,
        "--peer-id",
        &peer_id,
        "--quic",
        "--timeout-secs",
        "2",
    ])
    .await;
    let text = output_text(&output);
    assert!(!output.status.success(), "{text}");
    let out = stdout(&output);
    assert!(out.contains("PASS  tcp"), "{text}");
    assert!(out.contains("FAIL  quic"), "{text}");
    relay.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn probe_fails_on_a_wrong_peer_id_and_prints_both() {
    let relay = TestRelay::start().await;
    let actual = relay.handle().peer_id().to_string();
    let wrong = libp2p::identity::Keypair::generate_ed25519()
        .public()
        .to_peer_id()
        .to_string();
    let port = tcp_port(&relay);

    let started = Instant::now();
    let output = probe(&["--host", "127.0.0.1", "--port", &port, "--peer-id", &wrong]).await;
    let text = output_text(&output);
    assert!(!output.status.success(), "{text}");
    let out = stdout(&output);
    assert!(out.contains("FAIL  tcp"), "{text}");
    assert!(out.contains(&format!("expected {wrong}")), "{text}");
    assert!(out.contains(&format!("got {actual}")), "{text}");
    // A relay answering with the wrong identity is not retried until the
    // default 120-second timeout.
    assert!(started.elapsed() < Duration::from_secs(30), "{text}");
    relay.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn probe_fails_within_its_timeout_against_a_closed_port() {
    // A port that was free a moment ago: nothing listens on it.
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("local addr")
        .port()
        .to_string();
    let peer_id = libp2p::identity::Keypair::generate_ed25519()
        .public()
        .to_peer_id()
        .to_string();

    let started = Instant::now();
    let output = probe(&[
        "--host",
        "127.0.0.1",
        "--port",
        &closed,
        "--peer-id",
        &peer_id,
        "--timeout-secs",
        "3",
    ])
    .await;
    let elapsed = started.elapsed();
    let text = output_text(&output);
    assert!(!output.status.success(), "{text}");
    assert!(stdout(&output).contains("FAIL  tcp"), "{text}");
    // It retried for the timeout rather than giving up on the first refusal,
    // and stopped soon after.
    assert!(elapsed >= Duration::from_secs(2), "{elapsed:?}: {text}");
    assert!(elapsed < Duration::from_secs(10), "{elapsed:?}: {text}");
}
