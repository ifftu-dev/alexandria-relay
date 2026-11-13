//! The part of the app's network profile the relay reads: `network_id`,
//! `protocol_namespace` and the relay list.
//!
//! The profile belongs to the app repository
//! (`src-tauri/resources/networks/`, parsed by
//! `src-tauri/src/network_profile.rs`). The relay reads it from a path the
//! operator gives and keeps no copy of any value in it. Each field read here
//! gets the same fail-closed checks the app's `NetworkProfile::validate`
//! applies to it, so a profile the app would refuse for these fields is
//! refused here too. Fields the relay does not read are ignored rather than
//! rejected: the app remains the authority on the whole document, and a new
//! app-side field must not stop relays from starting.

use std::collections::HashSet;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use libp2p::PeerId;
use serde::Deserialize;

/// The profile schema the app parses (`NETWORK_PROFILE_SCHEMA_VERSION` in
/// `src-tauri/src/network_profile.rs`). A different version may change what
/// the fields read here mean, so it is refused.
const SCHEMA_VERSION: u32 = 1;

/// The app's size cap (`MAX_NETWORK_PROFILE_BYTES`).
const MAX_BYTES: usize = 64 * 1024;

/// A network profile, reduced to what the relay needs to join the mesh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkProfile {
    pub network_id: String,
    pub protocol_namespace: String,
    pub relays: Vec<ProfileRelay>,
}

/// One relay listed in the profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileRelay {
    pub peer_id: PeerId,
    pub dns_name: String,
    pub port: u16,
    pub fallback_ips: Vec<IpAddr>,
}

// Unknown fields are ignored (see the module docs); a duplicate of a field
// read here is still an error, from serde's derived visitor.
#[derive(Deserialize)]
struct RawProfile {
    schema_version: u32,
    network_id: String,
    relays: Vec<RawRelay>,
    protocol_namespace: String,
}

#[derive(Deserialize)]
struct RawRelay {
    peer_id: String,
    dns_name: String,
    port: u16,
    fallback_ips: Vec<IpAddr>,
}

/// Why a profile was refused.
#[derive(Debug)]
pub struct ProfileError(String);

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid network profile: {}", self.0)
    }
}

impl std::error::Error for ProfileError {}

fn invalid<T>(message: impl Into<String>) -> Result<T, ProfileError> {
    Err(ProfileError(message.into()))
}

impl NetworkProfile {
    /// Read and validate the profile at `path`.
    pub fn load(path: &Path) -> Result<Self, ProfileError> {
        let file = std::fs::File::open(path)
            .map_err(|e| ProfileError(format!("cannot open {}: {e}", path.display())))?;
        let mut bytes = Vec::new();
        file.take(MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| ProfileError(format!("cannot read {}: {e}", path.display())))?;
        Self::parse(&bytes)
    }

    /// Parse and validate a profile document.
    pub fn parse(bytes: &[u8]) -> Result<Self, ProfileError> {
        if bytes.len() > MAX_BYTES {
            return invalid(format!("exceeds {MAX_BYTES} bytes"));
        }
        let raw: RawProfile =
            serde_json::from_slice(bytes).map_err(|e| ProfileError(format!("JSON: {e}")))?;
        raw.validate()
    }
}

impl RawProfile {
    /// The checks of `NetworkProfile::validate` in the app's
    /// `src-tauri/src/network_profile.rs` for the fields read here, in the
    /// same order, plus its placeholder scan over the same strings.
    fn validate(self) -> Result<NetworkProfile, ProfileError> {
        if self.schema_version != SCHEMA_VERSION {
            return invalid(format!(
                "unsupported schema version {}",
                self.schema_version
            ));
        }
        validate_identifier("network_id", &self.network_id)?;
        if self.relays.is_empty() {
            return invalid("at least one relay is required");
        }
        let expected_namespace = format!("/alexandria/{}", self.network_id);
        if self.protocol_namespace != expected_namespace {
            return invalid(format!("protocol_namespace must be {expected_namespace:?}"));
        }
        reject_placeholder(&self.network_id)?;
        reject_placeholder(&self.protocol_namespace)?;

        let mut relay_ids = HashSet::new();
        let mut relay_hosts = HashSet::new();
        let mut relays = Vec::with_capacity(self.relays.len());
        for relay in self.relays {
            reject_placeholder(&relay.peer_id)?;
            let peer_id = relay
                .peer_id
                .parse::<PeerId>()
                .map_err(|e| ProfileError(format!("invalid relay peer_id: {e}")))?;
            if !relay_ids.insert(peer_id) {
                return invalid(format!("duplicate relay peer_id: {}", relay.peer_id));
            }
            validate_dns_name(&relay.dns_name)?;
            reject_placeholder(&relay.dns_name)?;
            if !relay_hosts.insert(relay.dns_name.clone()) {
                return invalid(format!("duplicate relay dns_name: {}", relay.dns_name));
            }
            if relay.port == 0 {
                return invalid(format!("relay {} has port zero", relay.dns_name));
            }
            if relay.fallback_ips.is_empty() {
                return invalid(format!(
                    "relay {} requires at least one public fallback IP",
                    relay.dns_name
                ));
            }
            for ip in &relay.fallback_ips {
                if !is_public_ip(ip) {
                    return invalid(format!(
                        "relay {} has non-public fallback IP {ip}",
                        relay.dns_name
                    ));
                }
            }
            relays.push(ProfileRelay {
                peer_id,
                dns_name: relay.dns_name,
                port: relay.port,
                fallback_ips: relay.fallback_ips,
            });
        }

        Ok(NetworkProfile {
            network_id: self.network_id,
            protocol_namespace: self.protocol_namespace,
            relays,
        })
    }
}

// The helpers below are the app's, from `src-tauri/src/network_profile.rs`,
// unchanged in behaviour.

fn validate_identifier(field: &str, value: &str) -> Result<(), ProfileError> {
    if value.trim().is_empty() {
        return invalid(format!("{field} must not be blank"));
    }
    if value.len() > 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    {
        return invalid(format!(
            "{field} must contain only lowercase ASCII letters, digits, '-' or '_'"
        ));
    }
    Ok(())
}

fn validate_dns_name(value: &str) -> Result<(), ProfileError> {
    if value.trim().is_empty() {
        return invalid("relay dns_name must not be blank");
    }
    if value.len() > 253
        || value.starts_with('.')
        || value.ends_with('.')
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
    {
        return invalid(format!("invalid relay dns_name: {value}"));
    }
    Ok(())
}

/// The app's `reject_placeholders`, applied to the strings read here.
fn reject_placeholder(value: &str) -> Result<(), ProfileError> {
    let upper = value.to_ascii_uppercase();
    if ["PLACEHOLDER", "CHANGEME", "REPLACE_ME", "TODO"]
        .iter()
        .any(|marker| upper.contains(marker))
    {
        return invalid(format!("unresolved placeholder value: {value}"));
    }
    Ok(())
}

fn is_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(*ip),
        IpAddr::V6(ip) => is_public_ipv6(*ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || a == 0
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 240)
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }
    !(ip.is_loopback()
        || ip.is_multicast()
        || ip.is_unspecified()
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || (segments[0] == 0x0100 && segments[1..].iter().all(|segment| *segment == 0)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    const PEER_A: &str = "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN";

    /// A synthetic profile: two relays, plus app-only fields the relay must
    /// ignore.
    fn valid() -> Value {
        let peer_b = PeerId::random().to_string();
        json!({
            "schema_version": 1,
            "network_id": "testnet",
            "profile_revision": 1,
            "relays": [
                {
                    "peer_id": PEER_A,
                    "dns_name": "relay-a.example.org",
                    "port": 4001,
                    "fallback_ips": ["198.51.99.1"],
                    "registry_https_origin": "https://relay-a.example.org"
                },
                {
                    "peer_id": peer_b,
                    "dns_name": "relay-b.example.org",
                    "port": 4002,
                    "fallback_ips": ["198.51.99.2", "2a01:4f8::1"],
                    "registry_https_origin": "https://relay-b.example.org"
                }
            ],
            "receipt_issuer_keys": [PEER_A],
            "cloud_https_origin": null,
            "protocol_namespace": "/alexandria/testnet"
        })
    }

    fn parse(value: &Value) -> Result<NetworkProfile, ProfileError> {
        NetworkProfile::parse(&serde_json::to_vec(value).unwrap())
    }

    fn refused(value: &Value, expected: &str) {
        let error = parse(value).expect_err("profile accepted").to_string();
        assert!(error.contains(expected), "{error:?} lacks {expected:?}");
    }

    #[test]
    fn a_valid_profile_yields_the_relay_coordinates() {
        let profile = parse(&valid()).unwrap();
        assert_eq!(profile.network_id, "testnet");
        assert_eq!(profile.protocol_namespace, "/alexandria/testnet");
        assert_eq!(profile.relays.len(), 2);
        let a = &profile.relays[0];
        assert_eq!(a.peer_id.to_string(), PEER_A);
        assert_eq!(a.dns_name, "relay-a.example.org");
        assert_eq!(a.port, 4001);
        assert_eq!(
            a.fallback_ips,
            vec!["198.51.99.1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn the_namespace_must_be_bound_to_the_network_id() {
        let mut p = valid();
        p["protocol_namespace"] = json!("/alexandria/othernet");
        refused(&p, "protocol_namespace");
        p["network_id"] = json!("othernet");
        assert!(parse(&p).is_ok());
    }

    #[test]
    fn identity_fields_are_checked_like_the_app_checks_them() {
        let mut p = valid();
        p["schema_version"] = json!(2);
        refused(&p, "schema version");

        let mut p = valid();
        p["network_id"] = json!("TestNet");
        p["protocol_namespace"] = json!("/alexandria/TestNet");
        refused(&p, "network_id");

        let mut p = valid();
        p["network_id"] = json!(" ");
        refused(&p, "network_id must not be blank");

        let mut p = valid();
        p["relays"] = json!([]);
        refused(&p, "at least one relay");

        let mut p = valid();
        p["network_id"] = json!("todo-net");
        p["protocol_namespace"] = json!("/alexandria/todo-net");
        refused(&p, "placeholder");
    }

    #[test]
    fn relay_entries_are_checked_like_the_app_checks_them() {
        let cases: &[(&str, Value, &str)] = &[
            ("peer_id", json!("not-a-peer-id"), "invalid relay peer_id"),
            (
                "dns_name",
                json!("Relay.example.org"),
                "invalid relay dns_name",
            ),
            (
                "dns_name",
                json!("relay..example.org"),
                "invalid relay dns_name",
            ),
            (
                "dns_name",
                json!("-relay.example.org"),
                "invalid relay dns_name",
            ),
            ("dns_name", json!("changeme.example.org"), "placeholder"),
            ("port", json!(0), "port zero"),
            ("fallback_ips", json!([]), "at least one public fallback IP"),
            (
                "fallback_ips",
                json!(["127.0.0.1"]),
                "non-public fallback IP",
            ),
            (
                "fallback_ips",
                json!(["10.1.2.3"]),
                "non-public fallback IP",
            ),
            (
                "fallback_ips",
                json!(["100.64.0.1"]),
                "non-public fallback IP",
            ),
            (
                "fallback_ips",
                json!(["203.0.113.9"]),
                "non-public fallback IP",
            ),
            ("fallback_ips", json!(["fd00::1"]), "non-public fallback IP"),
            (
                "fallback_ips",
                json!(["2001:db8::1"]),
                "non-public fallback IP",
            ),
            (
                "fallback_ips",
                json!(["::ffff:192.168.0.1"]),
                "non-public fallback IP",
            ),
        ];
        for (field, value, expected) in cases {
            let mut p = valid();
            p["relays"][1][field] = value.clone();
            refused(&p, expected);
        }

        let mut p = valid();
        p["relays"][1]["peer_id"] = json!(PEER_A);
        refused(&p, "duplicate relay peer_id");

        let mut p = valid();
        p["relays"][1]["dns_name"] = json!("relay-a.example.org");
        refused(&p, "duplicate relay dns_name");
    }

    #[test]
    fn malformed_duplicated_and_oversized_documents_fail_closed() {
        assert!(NetworkProfile::parse(b"{").is_err());
        assert!(NetworkProfile::parse(&vec![b' '; MAX_BYTES + 1])
            .unwrap_err()
            .to_string()
            .contains("exceeds"));

        // A second `network_id` must not override the first.
        let text = serde_json::to_string(&valid()).unwrap();
        let duplicated = format!("{},\"network_id\":\"othernet\"}}", &text[..text.len() - 1]);
        assert!(NetworkProfile::parse(duplicated.as_bytes())
            .unwrap_err()
            .to_string()
            .contains("duplicate field"));

        let mut p = valid();
        p.as_object_mut().unwrap().remove("protocol_namespace");
        refused(&p, "protocol_namespace");
    }
}
