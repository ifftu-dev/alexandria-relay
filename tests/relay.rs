//! Black-box tests: a real relay on loopback, driven as a client would.
//!
//! Add a case by starting a relay with `TestRelay::start` (or `start_with` to
//! change its configuration) and asserting only on what a client observes.

mod common;

use common::{port_of, TestRelay};

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
