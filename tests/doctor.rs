//! `alexandria-relay doctor`, run as an operator would: the real binary,
//! judged by its exit code and summary.

mod common;

use std::process::{Command, Output};

use common::{TempDir, ADMIN_TOKEN};

/// Run `doctor` on loopback with ephemeral ports, plus `extra` flags.
fn doctor(data_dir: &TempDir, extra: &[&str], admin_token: Option<&str>) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_alexandria-relay"));
    cmd.arg("doctor")
        .args([
            "--port",
            "0",
            "--quic-port",
            "0",
            "--listen-ip4",
            "127.0.0.1",
            "--listen-ip6",
            "off",
            "--metrics-bind",
            "127.0.0.1",
            "--metrics-port",
            "0",
        ])
        .arg("--data-dir")
        .arg(data_dir.path())
        .args(extra)
        .env_remove("RELAY_SEED")
        .env_remove("RELAY_PUBLIC_HOST")
        .env("RUST_LOG", "warn");
    match admin_token {
        Some(token) => cmd.env("RELAY_ADMIN_TOKEN", token),
        None => cmd.env_remove("RELAY_ADMIN_TOKEN"),
    };
    cmd.output().expect("run alexandria-relay doctor")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn doctor_passes_when_every_advertised_address_answers() {
    let dir = TempDir::new();
    let output = doctor(&dir, &["--public-host", "localhost"], Some(ADMIN_TOKEN));
    let summary = stdout(&output);
    assert!(
        output.status.success(),
        "{summary}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The advertised name was dialled over both transports and answered.
    // (`localhost` may also resolve to ::1, which this IPv4-only relay
    // does not listen on; the doctor reports that address as failed.)
    assert!(summary.contains("ok    /dns4/localhost/tcp/"), "{summary}");
    assert!(summary.contains("ok    /dns4/localhost/udp/"), "{summary}");
    assert!(summary.contains("Result: reachable"), "{summary}");
    // A reservation was made and its address set listed.
    assert!(summary.contains("/p2p-circuit"), "{summary}");
    assert!(summary.contains("writable"), "{summary}");
    assert!(
        summary.contains("admin token: configured, accepted"),
        "{summary}"
    );
}

#[test]
fn doctor_fails_without_an_external_host() {
    let dir = TempDir::new();
    let output = doctor(&dir, &[], None);
    let summary = stdout(&output);
    assert!(!output.status.success(), "{summary}");
    assert!(summary.contains("--public-host"), "{summary}");
    assert!(summary.contains("admin token: not configured"), "{summary}");
}

#[test]
fn doctor_fails_when_no_advertised_address_answers() {
    // `invalid.` never resolves (RFC 6761), so nothing advertised is
    // reachable.
    let dir = TempDir::new();
    let output = doctor(&dir, &["--public-host", "relay.invalid"], None);
    let summary = stdout(&output);
    assert!(!output.status.success(), "{summary}");
    assert!(summary.contains("FAIL"), "{summary}");
}
