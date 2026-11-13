//! `alexandria-relay doctor`: start the relay from the operator's own
//! configuration and check, from a second in-process swarm, what a client
//! would see.
//!
//! Each advertised external address is dialled over its own transport (TCP
//! or QUIC), a circuit reservation is made to list the address set
//! reservations carry, the data directory is probed for writes and the admin
//! token is tried against the local HTTP listener. The run passes when at
//! least one advertised address answers.
//!
//! The dials leave from the same host, so a pass shows that the listeners,
//! the advertised addresses and the PeerId line up. It does not prove that a
//! firewall in front of the host lets outside clients in.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use futures::StreamExt;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::{dummy, SwarmEvent};
use libp2p::{noise, relay, tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::ADMIN_TOKEN_MIN_LEN;
use crate::{start, RelayConfig};

/// How long one dial, reservation or HTTP request may take.
const STEP_TIMEOUT: Duration = Duration::from_secs(10);

/// What a doctor run found. `Display` is the summary the binary prints.
pub struct DoctorReport {
    lines: Vec<String>,
    passed: bool,
}

impl DoctorReport {
    /// True when at least one advertised address answered. The binary
    /// exits non-zero otherwise.
    pub fn passed(&self) -> bool {
        self.passed
    }
}

impl fmt::Display for DoctorReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for line in &self.lines {
            writeln!(f, "{line}")?;
        }
        Ok(())
    }
}

/// Start a relay from `config`, check it as described in the module docs,
/// shut it down and report. The relay binds the configured ports, so a relay
/// already running on them must be stopped first.
pub async fn run(config: RelayConfig) -> DoctorReport {
    let mut lines = vec!["alexandria-relay doctor".to_string()];
    let public_host = config.public_host.clone();
    let data_dir = config.data_dir.clone();
    let admin_token = config.admin_token.clone();

    let handle = match start(config).await {
        Ok(handle) => handle,
        Err(e) => {
            lines.push(format!("FAIL  the relay did not start: {e}"));
            return DoctorReport {
                lines,
                passed: false,
            };
        }
    };
    let peer_id = handle.peer_id();
    lines.push(format!("PeerId: {peer_id}"));

    // ── Advertised addresses ─────────────────────────────────────────
    let mut reachable_tcp = None;
    let mut reachable = 0usize;
    let advertised = handle.external_addrs().to_vec();
    if public_host.is_none() {
        lines.push(
            "FAIL  no external host: set --public-host (RELAY_PUBLIC_HOST). Without it the \
             relay advertises no address, reservations carry none and there is nothing to dial"
                .to_string(),
        );
    } else {
        lines.push(format!(
            "Advertised addresses ({}), dialled from a second swarm:",
            advertised.len()
        ));
        for addr in &advertised {
            match dial(peer_id, addr).await {
                Ok(dialled) => {
                    reachable += 1;
                    let is_tcp = dialled.iter().any(|p| matches!(p, Protocol::Tcp(_)));
                    if is_tcp && reachable_tcp.is_none() {
                        reachable_tcp = Some(dialled.clone());
                    }
                    lines.push(format!("  ok    {addr} (dialled {dialled})"));
                }
                Err(e) => lines.push(format!("  FAIL  {addr}: {e}")),
            }
        }
        lines.push(format!(
            "Reachable on {reachable} of {} advertised addresses",
            advertised.len()
        ));
    }

    // ── Reservation address set ──────────────────────────────────────
    match &reachable_tcp {
        Some(addr) => match reserve(peer_id, addr).await {
            Ok(relayed) => {
                lines.push(format!(
                    "Reservation accepted; it carries {} address(es):",
                    relayed.len()
                ));
                lines.extend(relayed.iter().map(|a| format!("  {a}")));
            }
            Err(e) => lines.push(format!("FAIL  reservation through {addr}: {e}")),
        },
        None => lines.push("Reservation: skipped, no advertised TCP address answered".to_string()),
    }

    // ── Data directory ───────────────────────────────────────────────
    match probe_writable(&data_dir) {
        Ok(()) => lines.push(format!("data directory {}: writable", data_dir.display())),
        Err(e) => lines.push(format!(
            "FAIL  data directory {}: not writable ({e}); receipts are disabled",
            data_dir.display()
        )),
    }

    // ── Admin token ──────────────────────────────────────────────────
    let http = loopback(handle.http_addr());
    let token_line = match admin_token.as_deref().map(str::trim) {
        None | Some("") => {
            "admin token: not configured (/metrics, /peers and /health/alerts answer 404)"
                .to_string()
        }
        Some(token) if token.len() < ADMIN_TOKEN_MIN_LEN => format!(
            "FAIL  admin token: configured, but shorter than {ADMIN_TOKEN_MIN_LEN} characters, \
             so refused"
        ),
        Some(token) => {
            match http_status(http, "/metrics", token).await {
                Ok(200) => format!("admin token: configured, accepted by http://{http}/metrics"),
                Ok(status) => {
                    format!("FAIL  admin token: configured, but http://{http}/metrics answered {status}")
                }
                Err(e) => format!("FAIL  admin token: configured, but http://{http} failed: {e}"),
            }
        }
    };
    lines.push(token_line);

    handle.shutdown().await;

    let passed = public_host.is_some() && reachable > 0;
    lines.push(if passed {
        "Result: reachable".to_string()
    } else {
        "Result: NOT reachable on any advertised address".to_string()
    });
    DoctorReport { lines, passed }
}

/// `addr` with a DNS component replaced by the first address it resolves
/// to in the matching family, the way a client without a DNS transport
/// would dial it.
async fn resolve(addr: &Multiaddr) -> Result<Multiaddr, String> {
    let port = addr
        .iter()
        .find_map(|p| match p {
            Protocol::Tcp(port) | Protocol::Udp(port) => Some(port),
            _ => None,
        })
        .ok_or("no port")?;
    let mut out = Multiaddr::empty();
    for p in addr.iter() {
        let (host, v4, v6) = match &p {
            Protocol::Dns(h) => (h.to_string(), true, true),
            Protocol::Dns4(h) => (h.to_string(), true, false),
            Protocol::Dns6(h) => (h.to_string(), false, true),
            _ => {
                out.push(p);
                continue;
            }
        };
        let ip = tokio::time::timeout(STEP_TIMEOUT, tokio::net::lookup_host((host.as_str(), port)))
            .await
            .map_err(|_| format!("{host} did not resolve in time"))?
            .map_err(|e| format!("{host} does not resolve: {e}"))?
            .map(|sa| sa.ip())
            .find(|ip| (v4 && ip.is_ipv4()) || (v6 && ip.is_ipv6()))
            .ok_or_else(|| format!("{host} has no address of the right family"))?;
        out.push(match ip {
            IpAddr::V4(ip) => Protocol::Ip4(ip),
            IpAddr::V6(ip) => Protocol::Ip6(ip),
        });
    }
    Ok(out)
}

/// A swarm with TCP and QUIC and the given behaviour.
fn client_swarm<B: libp2p::swarm::NetworkBehaviour>(
    behaviour: impl FnOnce(&libp2p::identity::Keypair) -> B,
) -> Result<Swarm<B>, String> {
    Ok(SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| e.to_string())?
        .with_quic()
        .with_behaviour(|key| behaviour(key))
        .map_err(|e| e.to_string())?
        .with_swarm_config(|c| c.with_idle_connection_timeout(STEP_TIMEOUT))
        .build())
}

/// Dial `peer` on `addr` from a fresh swarm. Returns the address dialled.
async fn dial(peer: PeerId, addr: &Multiaddr) -> Result<Multiaddr, String> {
    let target = resolve(addr).await?;
    let mut swarm = client_swarm(|_| dummy::Behaviour)?;
    swarm
        .dial(
            DialOpts::peer_id(peer)
                .addresses(vec![target.clone()])
                .build(),
        )
        .map_err(|e| e.to_string())?;
    let outcome = async {
        loop {
            match swarm.select_next_some().await {
                SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == peer => {
                    return Ok(());
                }
                SwarmEvent::OutgoingConnectionError { error, .. } => {
                    return Err(error.to_string());
                }
                _ => {}
            }
        }
    };
    tokio::time::timeout(STEP_TIMEOUT, outcome)
        .await
        .map_err(|_| format!("no answer within {STEP_TIMEOUT:?}"))??;
    Ok(target)
}

/// Make a circuit reservation with `peer` at `addr` and return the relayed
/// addresses it produced.
async fn reserve(peer: PeerId, addr: &Multiaddr) -> Result<Vec<Multiaddr>, String> {
    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| e.to_string())?
        .with_relay_client(noise::Config::new, yamux::Config::default)
        .map_err(|e| e.to_string())?
        .with_behaviour(|_, relay_client| relay_client)
        .map_err(|e| e.to_string())?
        .with_swarm_config(|c| c.with_idle_connection_timeout(STEP_TIMEOUT))
        .build();
    let circuit = addr
        .clone()
        .with(Protocol::P2p(peer))
        .with(Protocol::P2pCircuit);
    let listener = swarm.listen_on(circuit).map_err(|e| e.to_string())?;
    let mut relayed = Vec::new();
    let mut accepted = false;
    let outcome = async {
        loop {
            match swarm.select_next_some().await {
                SwarmEvent::NewListenAddr {
                    listener_id,
                    address,
                } if listener_id == listener => {
                    relayed.push(address);
                    if accepted {
                        return Ok(());
                    }
                }
                SwarmEvent::Behaviour(relay::client::Event::ReservationReqAccepted { .. }) => {
                    accepted = true;
                    if !relayed.is_empty() {
                        return Ok(());
                    }
                }
                SwarmEvent::ListenerClosed {
                    listener_id,
                    reason,
                    ..
                } if listener_id == listener => {
                    return Err(format!("refused: {reason:?}"));
                }
                _ => {}
            }
        }
    };
    tokio::time::timeout(STEP_TIMEOUT, outcome)
        .await
        .map_err(|_| format!("no answer within {STEP_TIMEOUT:?}"))??;
    // The reservation's addresses arrive as one listen event each; collect
    // the rest of the set.
    let rest = async {
        loop {
            if let SwarmEvent::NewListenAddr {
                listener_id,
                address,
            } = swarm.select_next_some().await
            {
                if listener_id == listener {
                    relayed.push(address);
                }
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_millis(500), rest).await;
    Ok(relayed)
}

/// Create and remove a file in `dir`. The store's write-ahead log puts
/// files beside the database, so the directory itself must be writable.
fn probe_writable(dir: &Path) -> std::io::Result<()> {
    let probe = dir.join(format!(".doctor-probe-{}", rand::random::<u64>()));
    std::fs::write(&probe, b"probe")?;
    std::fs::remove_file(&probe)
}

/// A wildcard bind address replaced by the loopback address of its family.
fn loopback(addr: SocketAddr) -> SocketAddr {
    let ip = match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, addr.port())
}

/// The status code of `GET path` with a bearer token.
async fn http_status(addr: SocketAddr, path: &str, token: &str) -> Result<u16, String> {
    let request = async {
        let mut stream = tokio::net::TcpStream::connect(addr).await?;
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\n\
             Connection: close\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).await?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await?;
        Ok::<_, std::io::Error>(String::from_utf8_lossy(&raw).into_owned())
    };
    let head = tokio::time::timeout(STEP_TIMEOUT, request)
        .await
        .map_err(|_| "no answer in time".to_string())?
        .map_err(|e| e.to_string())?;
    head.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("not an HTTP response: {head:?}"))
}
