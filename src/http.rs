//! HTTP router: health, metrics, peers and the public username lookup.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::routing::get;
use axum::{Json, Router};
use libp2p::PeerId;
use serde::Serialize;
use tokio::sync::RwLock;

use crate::addr::truncate_ip;
use crate::config::{
    MAX_CONNECTIONS, USERNAME_LOOKUP_LIMIT, USERNAME_LOOKUP_MAX_TRACKED, USERNAME_LOOKUP_WINDOW,
};
use crate::store::RegistryStore;

// ── Metrics ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RelayMetrics {
    pub(crate) peer_id: String,
    pub(crate) uptime_seconds: u64,
    pub(crate) connections: usize,
    pub(crate) total_connections_served: u64,
    pub(crate) reservations_accepted: u64,
    pub(crate) reservations_denied: u64,
    pub(crate) circuits_accepted: u64,
    pub(crate) circuits_denied: u64,
    pub(crate) circuits_closed: u64,
    pub(crate) kad_routing_updated: u64,
    pub(crate) identify_received: u64,
    pub(crate) listener_errors: u64,
    pub(crate) ip_rate_limited: u64,

    // Rolling 60-second window snapshots — populated by a background
    // sampling task in `run_metrics_server`. Drives /health/alerts.
    #[serde(skip)]
    pub(crate) prev_minute_circuits_denied: u64,
    #[serde(skip)]
    pub(crate) prev_minute_circuits_accepted: u64,
    #[serde(skip)]
    pub(crate) prev_minute_reservations_denied: u64,
    /// Circuits denied in the most recent completed 60s window. Surfaced
    /// at /health/alerts so external healthcheckers can flag spikes
    /// without doing their own delta math.
    pub(crate) circuits_denied_per_min: u64,
    pub(crate) circuits_accepted_per_min: u64,
    pub(crate) reservations_denied_per_min: u64,

    /// Source IPs of currently-connected peers, captured from the
    /// connection's remote address at ConnectionEstablished. Surfaced
    /// via /peers so the observer can attribute geo to NATted peers
    /// (whose own listen_addrs only include private LAN + circuit
    /// addrs and so never reveal their WAN IP through libp2p Identify).
    /// Skipped from /metrics to avoid leaking IPs into general telemetry.
    #[serde(skip)]
    pub(crate) peer_source_ips: HashMap<PeerId, IpAddr>,
    /// Subset of `peer_source_ips` keys that hold an active circuit
    /// reservation with this relay — i.e. they're using us as a
    /// rendezvous point. This is the more interesting set for the
    /// observer (ad-hoc dialers come and go).
    #[serde(skip)]
    pub(crate) peers_with_reservation: HashSet<PeerId>,
}

/// Wire format for /peers — one entry per connected peer with the WAN
/// IP we saw them dial in from. `has_reservation` distinguishes peers
/// using us as a relay rendezvous from peers that just opened a one-off
/// connection (e.g. observer crawlers).
///
/// `source_prefix` is a **truncated** address, never the peer's full IP.
/// The consumer of this endpoint is the monitoring observer, and its stated
/// need is geo attribution for NATted peers — a /24 (v4) or /48 (v6) is
/// city-accurate for that and is not an identifier for the person behind it.
/// Serving the full address here would hand any caller a PeerId → IP map for
/// every connected user, which is the one thing a relay in this architecture
/// must never publish.
#[derive(Debug, Clone, Serialize)]
struct PeerSourceEntry {
    peer_id: String,
    source_prefix: String,
    has_reservation: bool,
}

/// Constant-time comparison for the admin bearer token.
///
/// Length is not secret — the token is a fixed size — so returning early on a
/// length mismatch leaks nothing. What must not leak is *where* two
/// same-length values first differ.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Whether the request carries the configured admin bearer token.
///
/// `None` (no `RELAY_ADMIN_TOKEN` configured) means the operational routes are
/// off entirely. Callers answer 404 rather than 401 in both the unconfigured
/// and the wrong-token case: an endpoint that says "unauthorised" has
/// confirmed it exists, and there is nothing to gain by telling a scanner that
/// this relay has operational data worth asking for.
fn admin_authorised(expected: Option<&str>, headers: &axum::http::HeaderMap) -> bool {
    let Some(expected) = expected else {
        return false;
    };
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();
    constant_time_eq(presented.as_bytes(), expected.as_bytes())
}

/// Per-IP sliding window for the public username lookup.
///
/// `std::sync::Mutex` rather than tokio's: the critical section is a map
/// lookup and an integer bump, never held across an await.
type LookupLimiter = Arc<std::sync::Mutex<HashMap<IpAddr, (usize, Instant)>>>;

/// True when `ip` is over its lookup budget. Prunes stale windows on the way
/// through so the map stays bounded without a separate sweeper.
fn lookup_rate_limited(limiter: &LookupLimiter, ip: IpAddr) -> bool {
    let Ok(mut map) = limiter.lock() else {
        // A poisoned lock means a panic mid-update. Refusing is the safe
        // direction: a caller can retry, and allowing would silently disable
        // the limiter for the process's life.
        return true;
    };
    let now = Instant::now();
    if map.len() >= USERNAME_LOOKUP_MAX_TRACKED {
        map.retain(|_, (_, started)| now.duration_since(*started) < USERNAME_LOOKUP_WINDOW);
        if map.len() >= USERNAME_LOOKUP_MAX_TRACKED {
            map.clear();
        }
    }
    let (count, started) = map.entry(ip).or_insert((0, now));
    if now.duration_since(*started) >= USERNAME_LOOKUP_WINDOW {
        *count = 0;
        *started = now;
    }
    *count += 1;
    *count > USERNAME_LOOKUP_LIMIT
}

/// The answer for an operational route that was not authorised.
fn not_found() -> (axum::http::StatusCode, Json<serde_json::Value>) {
    (
        axum::http::StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": "not found" })),
    )
}

/// Read `RELAY_ADMIN_TOKEN`, refusing one short enough to guess.
///
/// A token that reads as protection but is brute-forceable is worse than an
/// endpoint that is simply switched off, so a short value is rejected at
/// startup rather than accepted quietly.
fn admin_token_from_env() -> Option<String> {
    let token = std::env::var("RELAY_ADMIN_TOKEN").ok()?;
    let token = token.trim().to_string();
    if token.is_empty() {
        return None;
    }
    if token.len() < 16 {
        log::error!(
            "RELAY_ADMIN_TOKEN is shorter than 16 characters — refusing it. \
             Operational routes stay disabled. Generate one with `openssl rand -base64 32`."
        );
        return None;
    }
    Some(token)
}
// ── Metrics HTTP Server ─────────────────────────────────────────────

pub(crate) async fn run_metrics_server(
    metrics: Arc<RwLock<RelayMetrics>>,
    registry: Option<std::sync::Arc<std::sync::Mutex<RegistryStore>>>,
    port: u16,
) {
    // Sample rolling-minute deltas in the background. Lets /health/alerts
    // serve a denial-rate without external alerters doing delta math.
    {
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            tick.tick().await; // consume immediate tick
            loop {
                tick.tick().await;
                let mut m = metrics.write().await;
                m.circuits_denied_per_min = m
                    .circuits_denied
                    .saturating_sub(m.prev_minute_circuits_denied);
                m.circuits_accepted_per_min = m
                    .circuits_accepted
                    .saturating_sub(m.prev_minute_circuits_accepted);
                m.reservations_denied_per_min = m
                    .reservations_denied
                    .saturating_sub(m.prev_minute_reservations_denied);
                m.prev_minute_circuits_denied = m.circuits_denied;
                m.prev_minute_circuits_accepted = m.circuits_accepted;
                m.prev_minute_reservations_denied = m.reservations_denied;
            }
        });
    }

    let health_metrics = metrics.clone();
    let alerts_metrics = metrics.clone();
    let peers_metrics = metrics.clone();
    let full_metrics = metrics;

    // Operational routes (`/peers`, `/metrics`, `/health/alerts`) require a
    // bearer token. Unconfigured means off — this listener is published to the
    // public internet by `fly.toml`, so anything on it that is not `/health` or
    // the public username registry has to prove it was asked for.
    let admin_token = admin_token_from_env();
    if admin_token.is_none() {
        log::warn!(
            "RELAY_ADMIN_TOKEN is not set — /peers, /metrics and /health/alerts \
             will answer 404. Set it to enable operational endpoints."
        );
    }
    let peers_token = admin_token.clone();
    let metrics_token = admin_token.clone();
    let alerts_token = admin_token;

    let lookup_limiter: LookupLimiter = Arc::new(std::sync::Mutex::new(HashMap::new()));

    let app = Router::new()
        .route(
            "/username/:name",
            get(
                move |axum::extract::Path(name): axum::extract::Path<String>,
                      axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<
                    std::net::SocketAddr,
                >| {
                    let registry = registry.clone();
                    let limiter = lookup_limiter.clone();
                    async move {
                        if lookup_rate_limited(&limiter, addr.ip()) {
                            return (
                                axum::http::StatusCode::TOO_MANY_REQUESTS,
                                Json(serde_json::json!({
                                    "error": "too many lookups — try again in a minute"
                                })),
                            );
                        }
                        let name = name.trim().trim_start_matches('@').to_lowercase();
                        let holder = registry.as_ref().and_then(|r| {
                            r.lock().ok().and_then(|store| store.lookup_username(&name))
                        });
                        match holder {
                            Some((did, received_at)) => (
                                axum::http::StatusCode::OK,
                                Json(serde_json::json!({
                                    "username": name,
                                    "available": false,
                                    "did": did,
                                    "received_at": received_at,
                                })),
                            ),
                            None => (
                                axum::http::StatusCode::OK,
                                Json(serde_json::json!({
                                    "username": name,
                                    "available": true,
                                })),
                            ),
                        }
                    }
                },
            ),
        )
        .route(
            "/health",
            get(move || {
                let m = health_metrics.clone();
                async move {
                    let lock = m.read().await;
                    Json(serde_json::json!({
                        "status": "ok",
                        "peer_id": lock.peer_id,
                        "uptime_seconds": lock.uptime_seconds,
                        "connections": lock.connections,
                    }))
                }
            }),
        )
        .route(
            "/health/alerts",
            get(move |headers: axum::http::HeaderMap| {
                let m = alerts_metrics.clone();
                let token = alerts_token.clone();
                async move {
                    if !admin_authorised(token.as_deref(), &headers) {
                        return not_found();
                    }
                    let lock = m.read().await;
                    // Thresholds chosen so a healthy relay sits at "ok"
                    // and a saturated one trips before clients notice.
                    let connections_ratio = lock.connections as f64 / MAX_CONNECTIONS as f64;
                    let denial_rate = lock.circuits_denied_per_min;
                    let accept_rate = lock.circuits_accepted_per_min;
                    let denial_share = if accept_rate + denial_rate == 0 {
                        0.0
                    } else {
                        denial_rate as f64 / (accept_rate + denial_rate) as f64
                    };

                    let mut alerts: Vec<&str> = Vec::new();
                    if connections_ratio > 0.8 {
                        alerts.push("connections_near_cap");
                    }
                    if denial_rate > 100 {
                        alerts.push("circuits_denied_per_min_high");
                    }
                    if denial_share > 0.5 && (denial_rate + accept_rate) > 20 {
                        alerts.push("circuit_denial_majority");
                    }
                    if lock.reservations_denied_per_min > 10 {
                        alerts.push("reservations_denied_per_min_high");
                    }
                    if lock.listener_errors > 0 {
                        alerts.push("listener_errors_observed");
                    }

                    let level = if alerts.is_empty() { "ok" } else { "warn" };
                    let status_code = if alerts.is_empty() {
                        axum::http::StatusCode::OK
                    } else {
                        // 503 makes most healthcheckers (UptimeRobot,
                        // healthchecks.io, Fly's own checks) flag the
                        // relay without manually parsing JSON.
                        axum::http::StatusCode::SERVICE_UNAVAILABLE
                    };
                    (
                        status_code,
                        Json(serde_json::json!({
                            "level": level,
                            "alerts": alerts,
                            "circuits_denied_per_min": denial_rate,
                            "circuits_accepted_per_min": accept_rate,
                            "circuit_denial_share": denial_share,
                            "reservations_denied_per_min": lock.reservations_denied_per_min,
                            "connections_ratio": connections_ratio,
                            "max_connections": MAX_CONNECTIONS,
                        })),
                    )
                }
            }),
        )
        .route(
            "/peers",
            get(move |headers: axum::http::HeaderMap| {
                let m = peers_metrics.clone();
                let token = peers_token.clone();
                async move {
                    if !admin_authorised(token.as_deref(), &headers) {
                        return not_found();
                    }
                    let lock = m.read().await;
                    let entries: Vec<PeerSourceEntry> = lock
                        .peer_source_ips
                        .iter()
                        .map(|(pid, ip)| PeerSourceEntry {
                            peer_id: pid.to_string(),
                            source_prefix: truncate_ip(ip),
                            has_reservation: lock.peers_with_reservation.contains(pid),
                        })
                        .collect();
                    (axum::http::StatusCode::OK, Json(serde_json::json!(entries)))
                }
            }),
        )
        .route(
            "/metrics",
            get(move |headers: axum::http::HeaderMap| {
                let m = full_metrics.clone();
                let token = metrics_token.clone();
                async move {
                    if !admin_authorised(token.as_deref(), &headers) {
                        return not_found();
                    }
                    let lock = m.read().await;
                    (axum::http::StatusCode::OK, Json(serde_json::json!(*lock)))
                }
            }),
        );

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect("bind metrics server");
    log::info!("Metrics server listening on 0.0.0.0:{port}");
    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    {
        log::error!("Metrics server error: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    fn bearer(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        h
    }

    #[test]
    fn operational_routes_are_closed_when_no_token_is_configured() {
        // Unconfigured means off. This listener is on the public internet, so
        // "no token set" must not read as "no protection needed".
        assert!(!admin_authorised(None, &HeaderMap::new()));
        assert!(!admin_authorised(None, &bearer("anything")));
    }

    #[test]
    fn admin_authorisation_requires_the_exact_token() {
        let token = "0123456789abcdef0123";
        assert!(admin_authorised(Some(token), &bearer(token)));
        assert!(!admin_authorised(Some(token), &bearer("wrong")));
        assert!(!admin_authorised(Some(token), &HeaderMap::new()));
        // A prefix must not pass — the comparison is over the whole value.
        assert!(!admin_authorised(
            Some(token),
            &bearer("0123456789abcdef012")
        ));
    }

    #[test]
    fn constant_time_eq_matches_ordinary_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }
}

#[cfg(test)]
mod lookup_limiter_tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn fresh() -> LookupLimiter {
        Arc::new(std::sync::Mutex::new(HashMap::new()))
    }

    /// The public username oracle used to be unthrottled: the whole registry
    /// was enumerable for the cost of a loop. A client gets a budget per
    /// window and is refused past it.
    #[test]
    fn a_client_is_refused_past_its_lookup_budget() {
        let l = fresh();
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        for _ in 0..USERNAME_LOOKUP_LIMIT {
            assert!(
                !lookup_rate_limited(&l, ip),
                "within budget must be allowed"
            );
        }
        assert!(
            lookup_rate_limited(&l, ip),
            "one past the budget must be refused"
        );
    }

    /// One client exhausting its budget must not affect another.
    #[test]
    fn budgets_are_per_client() {
        let l = fresh();
        let a = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let b = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));
        for _ in 0..=USERNAME_LOOKUP_LIMIT {
            let _ = lookup_rate_limited(&l, a);
        }
        assert!(lookup_rate_limited(&l, a));
        assert!(!lookup_rate_limited(&l, b));
    }

    /// The map cannot itself become the memory leak.
    #[test]
    fn the_tracked_set_stays_bounded() {
        let l = fresh();
        for i in 0..(USERNAME_LOOKUP_MAX_TRACKED + 500) {
            let ip = IpAddr::V4(Ipv4Addr::from((i as u32).wrapping_add(0x0100_0000)));
            let _ = lookup_rate_limited(&l, ip);
        }
        assert!(l.lock().unwrap().len() <= USERNAME_LOOKUP_MAX_TRACKED);
    }
}
