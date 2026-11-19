//! The client side `doctor` and `probe` share: a throwaway swarm that dials
//! the relay the way an app would, and resolution of the DNS names in its
//! addresses through the OS resolver (the relay carries no libp2p DNS
//! transport).

use std::net::IpAddr;
use std::time::Duration;

use libp2p::multiaddr::Protocol;
use libp2p::{noise, tcp, yamux, Multiaddr, Swarm, SwarmBuilder};

/// How long one dial, reservation, lookup or HTTP request may take.
pub(crate) const STEP_TIMEOUT: Duration = Duration::from_secs(10);

/// `addr` with a DNS component replaced by the first address it resolves
/// to in the matching family, the way a client without a DNS transport
/// would dial it.
pub(crate) async fn resolve(addr: &Multiaddr) -> Result<Multiaddr, String> {
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

/// A swarm with a fresh identity, TCP and QUIC, and the given behaviour.
pub(crate) fn client_swarm<B: libp2p::swarm::NetworkBehaviour>(
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
