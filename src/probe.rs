//! `alexandria-relay probe`: check a running relay from another machine, the
//! way a client reaches it.
//!
//! The probe dials the relay over TCP (and QUIC with `--quic`) from a fresh
//! client swarm. A transport passes when the connection is established with
//! the expected PeerId and the relay's Identify arrives with the Alexandria
//! protocol version, so a pass means an Alexandria relay answered, not just
//! an open port. Each transport is retried until `--timeout-secs`, so a
//! machine still booting after a deploy is not reported as down.
//!
//! The probe starts no relay, needs no relay secrets and writes nothing to
//! disk.

use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use futures::StreamExt;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::{DialError, SwarmEvent};
use libp2p::{identify, Multiaddr, PeerId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;

use crate::config::DEFAULT_PORT;
use crate::doctor::{client_swarm, resolve, STEP_TIMEOUT};
use crate::profile::NetworkProfile;
use crate::swarm::IDENTIFY_PROTOCOL_VERSION;

/// Pause between attempts on one transport.
const RETRY_PAUSE: Duration = Duration::from_secs(1);

/// `probe` flags. `--port` and `--network-profile` shadow the relay's global
/// flags of the same name; [`crate::Cli::parse_args`] keeps the relay's
/// variables out of them.
#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
#[command(next_help_heading = "Probe")]
pub struct ProbeArgs {
    /// The relay's DNS name, or an IPv4 or IPv6 address. A name is dialled
    /// over IPv4 (`/dns4`), an address over its own family
    #[arg(long)]
    pub host: String,

    /// The relay's libp2p port, for TCP and QUIC alike
    #[arg(long, default_value_t = DEFAULT_PORT)]
    pub port: u16,

    /// The PeerId the relay must answer with
    #[arg(long)]
    pub peer_id: Option<PeerId>,

    /// Network profile JSON to take the expected PeerId from: the relay
    /// entry whose `dns_name` equals --host. Used when --peer-id is not given
    #[arg(long)]
    pub network_profile: Option<PathBuf>,

    /// The relay's plain-HTTP `/health` URL (`http://host:9090/health`), to
    /// take the expected PeerId from when neither --peer-id nor
    /// --network-profile is given. The identity is then the relay's own
    /// claim, not pinned. HTTPS is not supported
    #[arg(long)]
    pub health_url: Option<String>,

    /// Also dial QUIC. Leave it off for relays on Fly, which carry no QUIC
    #[arg(long)]
    pub quic: bool,

    /// How long each transport is retried before it fails, in seconds
    #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u64).range(1..))]
    pub timeout_secs: u64,
}

impl ProbeArgs {
    /// Undo what clap copied in from the relay's global flags of the same
    /// name: a value whose source is an environment variable came from
    /// `RELAY_PORT` or `RELAY_NETWORK_PROFILE`, since these flags read none.
    pub(crate) fn drop_inherited_env(&mut self, matches: &clap::ArgMatches) {
        use clap::parser::ValueSource::EnvVariable;
        if matches.value_source("port") == Some(EnvVariable) {
            self.port = DEFAULT_PORT;
        }
        if matches.value_source("network_profile") == Some(EnvVariable) {
            self.network_profile = None;
        }
    }
}

/// What a probe run found. `Display` is what the binary prints.
pub struct ProbeReport {
    lines: Vec<String>,
    passed: bool,
}

impl ProbeReport {
    /// True when every requested transport passed. The binary exits
    /// non-zero otherwise.
    pub fn passed(&self) -> bool {
        self.passed
    }
}

impl fmt::Display for ProbeReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for line in &self.lines {
            writeln!(f, "{line}")?;
        }
        Ok(())
    }
}

/// A transport the probe dials.
#[derive(Clone, Copy)]
enum Transport {
    Tcp,
    Quic,
}

impl Transport {
    fn label(self) -> &'static str {
        match self {
            Transport::Tcp => "tcp",
            Transport::Quic => "quic",
        }
    }

    /// `host` dialled on `port` over this transport, without `/p2p`.
    fn addr(self, host: &Host, port: u16) -> Multiaddr {
        let mut addr = Multiaddr::empty().with(host.protocol());
        match self {
            Transport::Tcp => addr.push(Protocol::Tcp(port)),
            Transport::Quic => {
                addr.push(Protocol::Udp(port));
                addr.push(Protocol::QuicV1);
            }
        }
        addr
    }
}

/// `--host`, parsed.
enum Host {
    Ip(IpAddr),
    Dns(String),
}

impl Host {
    fn parse(host: &str) -> Self {
        let bare = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        match bare.parse::<IpAddr>() {
            Ok(ip) => Host::Ip(ip),
            Err(_) => Host::Dns(host.to_string()),
        }
    }

    fn protocol(&self) -> Protocol<'static> {
        match self {
            Host::Ip(IpAddr::V4(ip)) => Protocol::Ip4(*ip),
            Host::Ip(IpAddr::V6(ip)) => Protocol::Ip6(*ip),
            Host::Dns(name) => Protocol::Dns4(name.clone().into()),
        }
    }
}

/// Probe the relay `args` describe and report.
pub async fn run(args: ProbeArgs) -> ProbeReport {
    let mut lines = vec![format!(
        "alexandria-relay probe: {} port {}",
        args.host, args.port
    )];
    let expected = match expected_peer(&args).await {
        Ok((peer, source)) => {
            lines.push(format!("Expected PeerId: {peer} ({source})"));
            peer
        }
        Err(reason) => {
            lines.push(format!("FAIL  expected PeerId: {reason}"));
            return ProbeReport {
                lines,
                passed: false,
            };
        }
    };

    let host = Host::parse(&args.host);
    let timeout = Duration::from_secs(args.timeout_secs);
    let mut transports = vec![Transport::Tcp];
    if args.quic {
        transports.push(Transport::Quic);
    }
    let checks = transports.iter().map(|&transport| {
        let addr = transport.addr(&host, args.port);
        async move {
            let outcome = retry(timeout, || attempt(expected, &addr)).await;
            (transport, addr, outcome.map(|((), attempts)| attempts))
        }
    });
    let mut passed = true;
    for (transport, addr, outcome) in futures::future::join_all(checks).await {
        let shown = addr.with(Protocol::P2p(expected));
        let label = transport.label();
        match outcome {
            Ok(attempts) => lines.push(format!(
                "PASS  {label:<4}  {shown} (Identify {IDENTIFY_PROTOCOL_VERSION}, \
                 attempt {attempts})"
            )),
            Err(reason) => {
                passed = false;
                lines.push(format!("FAIL  {label:<4}  {shown}: {reason}"));
            }
        }
    }
    ProbeReport { lines, passed }
}

/// The PeerId the relay must answer with, and where it came from: in order
/// of precedence `--peer-id`, `--network-profile`, `--health-url`.
async fn expected_peer(args: &ProbeArgs) -> Result<(PeerId, String), String> {
    if let Some(peer) = args.peer_id {
        return Ok((peer, "from --peer-id".to_string()));
    }
    if let Some(path) = &args.network_profile {
        let profile = NetworkProfile::load(path).map_err(|e| e.to_string())?;
        let relay = profile
            .relays
            .iter()
            .find(|r| r.dns_name == args.host)
            .ok_or_else(|| {
                format!(
                    "the network profile {} has no relay with dns_name {}",
                    path.display(),
                    args.host
                )
            })?;
        return Ok((
            relay.peer_id,
            format!("from the network profile {}", path.display()),
        ));
    }
    if let Some(url) = &args.health_url {
        let peer = peer_from_health(url, Duration::from_secs(args.timeout_secs)).await?;
        return Ok((
            peer,
            format!("from {url}; not pinned: the relay's own claim is trusted"),
        ));
    }
    Err("give --peer-id, --network-profile or --health-url".to_string())
}

/// The `peer_id` the relay's `/health` at `url` reports, retried like a dial
/// until `timeout`.
async fn peer_from_health(url: &str, timeout: Duration) -> Result<PeerId, String> {
    let (host, port, path) = parse_http_url(url)?;
    retry(timeout, || fetch_peer_id(&host, port, &path))
        .await
        .map(|(peer, _)| peer)
        .map_err(|e| format!("{url}: {e}"))
}

/// `http://host[:port][/path]` split into its parts. Host may be a bracketed
/// IPv6 address.
fn parse_http_url(url: &str) -> Result<(String, u16, String), String> {
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        format!("{url}: only http:// URLs are supported; give --peer-id or --network-profile")
    })?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !port.contains(']') => (
            host,
            port.parse()
                .map_err(|_| format!("{url}: invalid port {port:?}"))?,
        ),
        _ => (authority, 80),
    };
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if host.is_empty() {
        return Err(format!("{url}: no host"));
    }
    Ok((host.to_string(), port, path.to_string()))
}

/// One `GET path` on `host:port`, read for the JSON body's `peer_id`.
async fn fetch_peer_id(host: &str, port: u16, path: &str) -> Result<PeerId, AttemptError> {
    let retry = |e: std::io::Error| AttemptError::Retry(e.to_string());
    let mut stream = tokio::net::TcpStream::connect((host, port))
        .await
        .map_err(retry)?;
    let host_header = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.map_err(retry)?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.map_err(retry)?;
    let raw = String::from_utf8_lossy(&raw);
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
    let status = head.split_whitespace().nth(1).unwrap_or_default();
    if status != "200" {
        return Err(AttemptError::Retry(format!("answered {status:?}")));
    }
    let json: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| AttemptError::Final(format!("not a /health JSON body: {e}")))?;
    json.get("peer_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AttemptError::Final("no peer_id in the /health body".to_string()))?
        .parse()
        .map_err(|e| AttemptError::Final(format!("invalid peer_id in the /health body: {e}")))
}

/// Why one attempt failed.
enum AttemptError {
    /// Worth retrying: nothing answered yet, or the connection dropped.
    Retry(String),
    /// Something answered, and it is not the expected relay.
    Final(String),
}

/// Run `attempt` until it succeeds, fails for good or `timeout` runs out.
/// Each try gets at most [`STEP_TIMEOUT`]. Returns the value and the number
/// of the try that produced it.
async fn retry<T, F, Fut>(timeout: Duration, mut attempt: F) -> Result<(T, u32), String>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, AttemptError>>,
{
    let deadline = Instant::now() + timeout;
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        let left = deadline.saturating_duration_since(Instant::now());
        let error = match tokio::time::timeout(left.min(STEP_TIMEOUT), attempt()).await {
            Ok(Ok(value)) => return Ok((value, attempts)),
            Ok(Err(AttemptError::Final(reason))) => return Err(reason),
            Ok(Err(AttemptError::Retry(reason))) => reason,
            Err(_) => "no answer".to_string(),
        };
        if Instant::now() + RETRY_PAUSE >= deadline {
            return Err(format!(
                "{error} (gave up after {attempts} attempt(s) in {}s)",
                timeout.as_secs()
            ));
        }
        tokio::time::sleep(RETRY_PAUSE).await;
    }
}

/// One dial of `addr` from a fresh swarm, through to the relay's Identify.
async fn attempt(expected: PeerId, addr: &Multiaddr) -> Result<(), AttemptError> {
    let target = resolve(addr).await.map_err(AttemptError::Retry)?;
    let mut swarm = client_swarm(|key| {
        identify::Behaviour::new(identify::Config::new(
            IDENTIFY_PROTOCOL_VERSION.to_string(),
            key.public(),
        ))
    })
    .map_err(AttemptError::Final)?;
    swarm
        .dial(DialOpts::peer_id(expected).addresses(vec![target]).build())
        .map_err(|e| AttemptError::Retry(e.to_string()))?;
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::Behaviour(identify::Event::Received { peer_id, info, .. })
                if peer_id == expected =>
            {
                return if info.protocol_version == IDENTIFY_PROTOCOL_VERSION {
                    Ok(())
                } else {
                    Err(AttemptError::Final(format!(
                        "not an Alexandria relay: Identify protocol version {:?}, \
                         expected {IDENTIFY_PROTOCOL_VERSION:?}",
                        info.protocol_version
                    )))
                };
            }
            SwarmEvent::Behaviour(identify::Event::Error { error, .. }) => {
                return Err(AttemptError::Retry(format!("Identify failed: {error}")));
            }
            SwarmEvent::OutgoingConnectionError {
                error: DialError::WrongPeerId { obtained, .. },
                ..
            } => {
                return Err(AttemptError::Final(format!(
                    "PeerId mismatch: expected {expected}, got {obtained}"
                )));
            }
            SwarmEvent::OutgoingConnectionError { error, .. } => {
                return Err(AttemptError::Retry(error.to_string()));
            }
            SwarmEvent::ConnectionClosed { cause, .. } => {
                let cause = cause.map(|c| format!(": {c}")).unwrap_or_default();
                return Err(AttemptError::Retry(format!(
                    "connection closed before Identify arrived{cause}"
                )));
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(url: &str) -> (String, u16, String) {
        parse_http_url(url).expect("URL parses")
    }

    #[test]
    fn health_urls_split_into_host_port_and_path() {
        assert_eq!(
            parsed("http://relay.example.org:9090/health"),
            ("relay.example.org".into(), 9090, "/health".into())
        );
        assert_eq!(
            parsed("http://relay.example.org"),
            ("relay.example.org".into(), 80, "/".into())
        );
        assert_eq!(
            parsed("http://[2001:db8::1]:9090/health"),
            ("2001:db8::1".into(), 9090, "/health".into())
        );
        assert_eq!(
            parsed("http://[2001:db8::1]/health"),
            ("2001:db8::1".into(), 80, "/health".into())
        );
    }

    #[test]
    fn health_urls_other_than_plain_http_are_refused() {
        for url in [
            "https://relay.example.org/health",
            "relay.example.org/health",
            "http://:9090/health",
            "http://relay.example.org:port/health",
        ] {
            assert!(parse_http_url(url).is_err(), "{url} was accepted");
        }
    }

    #[test]
    fn hosts_dial_as_dns4_or_their_own_ip_family() {
        let addr = |host: &str| Transport::Tcp.addr(&Host::parse(host), 4001).to_string();
        assert_eq!(
            addr("relay.example.org"),
            "/dns4/relay.example.org/tcp/4001"
        );
        assert_eq!(addr("192.0.2.1"), "/ip4/192.0.2.1/tcp/4001");
        assert_eq!(addr("2001:db8::1"), "/ip6/2001:db8::1/tcp/4001");
        assert_eq!(addr("[2001:db8::1]"), "/ip6/2001:db8::1/tcp/4001");
        assert_eq!(
            Transport::Quic
                .addr(&Host::parse("relay.example.org"), 4001)
                .to_string(),
            "/dns4/relay.example.org/udp/4001/quic-v1"
        );
    }
}
