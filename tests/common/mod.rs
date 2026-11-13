//! Shared harness for black-box relay tests.
//!
//! [`TestRelay`] owns relay startup: ephemeral ports on loopback, a throwaway
//! data directory, and a clean shutdown. Tests change the configuration
//! through [`TestRelay::start_with`] and talk to the relay only the way a
//! client would: libp2p through [`TestClient`], HTTP through
//! [`TestRelay::get`].

#![allow(dead_code)] // each test binary uses a different subset

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use alexandria_relay::{start, RelayConfig, RelayHandle};
use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;
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
    _data_dir: TempDir,
}

impl TestRelay {
    /// Start a relay with [`test_config`].
    pub async fn start() -> Self {
        Self::start_with(|_| {}).await
    }

    /// Start a relay with [`test_config`] adjusted by `configure`.
    pub async fn start_with(configure: impl FnOnce(&mut RelayConfig)) -> Self {
        let _ = env_logger::builder().is_test(true).try_init();
        let data_dir = TempDir::new();
        let mut config = test_config(data_dir.path());
        configure(&mut config);
        let handle = tokio::time::timeout(STEP_TIMEOUT, start(config))
            .await
            .expect("relay start timed out")
            .expect("relay starts");
        TestRelay {
            handle: Some(handle),
            _data_dir: data_dir,
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
    let request = async {
        let mut stream = tokio::net::TcpStream::connect(addr).await?;
        let auth = bearer
            .map(|t| format!("Authorization: Bearer {t}\r\n"))
            .unwrap_or_default();
        let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n{auth}Connection: close\r\n\r\n");
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
    let body = raw
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
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
