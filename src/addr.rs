//! Address helpers: IP extraction, routability filtering and truncation.

use std::net::IpAddr;

use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;

/// The first IP component of a multiaddr, if any.
pub(crate) fn extract_ip(addr: &Multiaddr) -> Option<IpAddr> {
    addr.iter().find_map(|proto| match proto {
        Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
        Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    })
}

/// Drop the host bits of an address so it locates a network, not a person.
///
/// IPv4 keeps the /24; IPv6 keeps the /48 (the routing prefix — the low 80
/// bits carry the subnet and interface identifier, and on SLAAC the interface
/// identifier is stable per device).
pub(crate) fn truncate_ip(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            format!("{a}.{b}.{c}.0/24")
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
    }
}

/// Returns `true` if the multiaddr starts with a globally routable IP.
/// Rejects loopback, private (RFC 1918 / RFC 4193), link-local, and
/// unspecified addresses to prevent Kademlia routing table pollution.
pub(crate) fn is_globally_routable(addr: &Multiaddr) -> bool {
    match addr.iter().next() {
        Some(Protocol::Ip4(ip)) => {
            let ip = IpAddr::V4(ip);
            !(ip.is_loopback() || ip.is_unspecified() || is_private_v4(ip))
        }
        Some(Protocol::Ip6(ip)) => {
            let segments = ip.segments();
            !(IpAddr::V6(ip).is_loopback()
                || IpAddr::V6(ip).is_unspecified()
                // ULA: fc00::/7
                || (segments[0] & 0xfe00) == 0xfc00
                // Link-local: fe80::/10
                || (segments[0] & 0xffc0) == 0xfe80
                // IPv4-mapped: ::ffff:0:0/96
                || (segments[0] == 0
                    && segments[1] == 0
                    && segments[2] == 0
                    && segments[3] == 0
                    && segments[4] == 0
                    && segments[5] == 0xffff)
                // Multicast: ff00::/8
                || (segments[0] & 0xff00) == 0xff00
                // Deprecated site-local: fec0::/10
                || (segments[0] & 0xffc0) == 0xfec0)
        }
        // DNS addresses are allowed (e.g. /dns4/example.com/tcp/4001)
        Some(Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_)) => true,
        _ => false,
    }
}

/// Check if an IP is in a private/reserved range.
/// Covers RFC 1918 (10/8, 172.16/12, 192.168/16), link-local (169.254/16),
/// and CGNAT (100.64/10).
fn is_private_v4(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 10.0.0.0/8
            octets[0] == 10
            // 172.16.0.0/12
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))
            // 192.168.0.0/16
            || (octets[0] == 192 && octets[1] == 168)
            // 169.254.0.0/16 (link-local)
            || (octets[0] == 169 && octets[1] == 254)
            // 100.64.0.0/10 (CGNAT)
            || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn peer_addresses_are_truncated_to_a_network_not_a_host() {
        // The /peers endpoint exists so the observer can attribute geography
        // to NATted peers. A /24 answers that; a full address would hand any
        // caller a PeerId → IP map for every connected user, which is the one
        // thing this relay must never publish.
        let v4 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 47));
        assert_eq!(truncate_ip(&v4), "203.0.113.0/24");
        assert!(!truncate_ip(&v4).contains("47"));

        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xabcd, 0x1234, 0, 0, 0, 0x1));
        let out = truncate_ip(&v6);
        assert_eq!(out, "2001:db8:abcd::/48");
        // The interface identifier is stable per device under SLAAC, so it is
        // the part that must not survive truncation.
        assert!(!out.contains("1234"));
    }
}
