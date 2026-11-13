//! HTTP router: health, metrics, peers and the public username lookup, and
//! the server loop that bounds slow and surplus connections.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, HeaderName};
use axum::routing::get;
use axum::{Json, Router};
use hyper_util::rt::{TokioIo, TokioTimer};
use libp2p::PeerId;
use serde::Serialize;
use tokio::sync::{watch, RwLock, Semaphore};
use tower::ServiceExt;

use crate::addr::{client_bucket, truncate_ip};
use crate::config::Limits;
#[cfg(test)]
use crate::config::{DEFAULT_LOOKUP_LIMIT, DEFAULT_LOOKUP_MAX_TRACKED};
use crate::store::StoreHandle;

// ── Metrics ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize)]
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
    /// Username-receipt requests received, refused ones included.
    pub(crate) receipt_requests: u64,

    /// Other relays named in the network profile (0 without a profile).
    pub(crate) profile_relays: usize,
    /// Profile relays this relay currently holds a connection to.
    pub(crate) reachable_relays: usize,
    /// `disabled` (no profile), `pending`, `ok` or `failed`: the outcome of
    /// the last Kademlia bootstrap.
    pub(crate) bootstrap_status: &'static str,

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

    /// Client buckets (see [`client_bucket`]) of currently-connected peers,
    /// captured from the connection's remote address at
    /// ConnectionEstablished; an IPv6 peer is held as its /64. Surfaced
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
    /// When the relay started; `uptime_seconds` is computed from it on read.
    #[serde(skip)]
    pub(crate) started: Option<Instant>,
}

impl RelayMetrics {
    /// A copy with `uptime_seconds` brought up to now.
    fn snapshot(&self) -> RelayMetrics {
        let mut m = self.clone();
        if let Some(started) = self.started {
            m.uptime_seconds = started.elapsed().as_secs();
        }
        m
    }

    /// Prometheus text exposition (format 0.0.4): every counter and gauge of
    /// the JSON form, prefixed `relay_`, counters also suffixed `_total`.
    /// The relay's own PeerId and version are `relay_info` labels. Nothing
    /// per peer is exported.
    fn prometheus(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        let counters: [(&str, &str, u64); 11] = [
            (
                "connections_served_total",
                "Connections established since start.",
                self.total_connections_served,
            ),
            (
                "reservations_accepted_total",
                "Circuit reservations accepted.",
                self.reservations_accepted,
            ),
            (
                "reservations_denied_total",
                "Circuit reservations denied.",
                self.reservations_denied,
            ),
            (
                "circuits_accepted_total",
                "Relayed circuits accepted.",
                self.circuits_accepted,
            ),
            (
                "circuits_denied_total",
                "Relayed circuits denied.",
                self.circuits_denied,
            ),
            (
                "circuits_closed_total",
                "Relayed circuits closed.",
                self.circuits_closed,
            ),
            (
                "kad_routing_updated_total",
                "Kademlia routing table updates.",
                self.kad_routing_updated,
            ),
            (
                "identify_received_total",
                "Identify messages received.",
                self.identify_received,
            ),
            (
                "listener_errors_total",
                "Listener errors since start.",
                self.listener_errors,
            ),
            (
                "ip_rate_limited_total",
                "Connections closed by the per-IP limiter.",
                self.ip_rate_limited,
            ),
            (
                "receipt_requests_total",
                "Username-receipt requests received.",
                self.receipt_requests,
            ),
        ];
        let gauges: [(&str, &str, u64); 7] = [
            (
                "uptime_seconds",
                "Seconds since the relay started.",
                self.uptime_seconds,
            ),
            (
                "connections",
                "Peers currently connected.",
                self.connections as u64,
            ),
            (
                "profile_relays",
                "Other relays the network profile names.",
                self.profile_relays as u64,
            ),
            (
                "reachable_relays",
                "Profile relays currently connected.",
                self.reachable_relays as u64,
            ),
            (
                "circuits_denied_per_min",
                "Circuits denied in the last full minute.",
                self.circuits_denied_per_min,
            ),
            (
                "circuits_accepted_per_min",
                "Circuits accepted in the last full minute.",
                self.circuits_accepted_per_min,
            ),
            (
                "reservations_denied_per_min",
                "Reservations denied in the last full minute.",
                self.reservations_denied_per_min,
            ),
        ];
        let kinds = counters
            .iter()
            .map(|c| (c, "counter"))
            .chain(gauges.iter().map(|g| (g, "gauge")));
        for ((name, help, value), kind) in kinds {
            let _ = writeln!(out, "# HELP relay_{name} {help}");
            let _ = writeln!(out, "# TYPE relay_{name} {kind}");
            let _ = writeln!(out, "relay_{name} {value}");
        }
        let _ = writeln!(
            out,
            "# HELP relay_bootstrap_status Kademlia bootstrap state: 1 for the current one."
        );
        let _ = writeln!(out, "# TYPE relay_bootstrap_status gauge");
        for status in crate::mesh::BootstrapStatus::ALL {
            let status = status.as_str();
            let value = u8::from(status == self.bootstrap_status);
            let _ = writeln!(out, "relay_bootstrap_status{{status=\"{status}\"}} {value}");
        }
        let _ = writeln!(out, "# HELP relay_info This relay's PeerId and version.");
        let _ = writeln!(out, "# TYPE relay_info gauge");
        let _ = writeln!(
            out,
            "relay_info{{peer_id=\"{}\",version=\"{}\"}} 1",
            self.peer_id,
            env!("CARGO_PKG_VERSION")
        );
        out
    }
}

/// Content type of [`RelayMetrics::prometheus`].
const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Whether the request asks for the Prometheus text format. Prometheus lists
/// `text/plain` in its `Accept` header; the monitoring observer and other
/// JSON clients do not.
fn wants_prometheus(headers: &HeaderMap) -> bool {
    headers
        .get_all(axum::http::header::ACCEPT)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.to_ascii_lowercase().contains("text/plain"))
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
pub(crate) struct LookupLimiter {
    windows: std::sync::Mutex<HashMap<IpAddr, (usize, Instant)>>,
    limit: usize,
    window: Duration,
    max_tracked: usize,
}

impl LookupLimiter {
    pub(crate) fn new(limits: &Limits) -> Self {
        LookupLimiter {
            windows: std::sync::Mutex::new(HashMap::new()),
            limit: limits.lookup_limit,
            window: limits.lookup_window,
            max_tracked: limits.lookup_max_tracked,
        }
    }

    /// True when `ip`'s client bucket is over its lookup budget. Prunes
    /// stale windows on the way through so the map stays bounded without a
    /// separate sweeper.
    fn is_limited(&self, ip: IpAddr) -> bool {
        let ip = client_bucket(ip);
        let Ok(mut map) = self.windows.lock() else {
            // A poisoned lock means a panic mid-update. Refusing is the safe
            // direction: a caller can retry, and allowing would silently
            // disable the limiter for the process's life.
            return true;
        };
        let now = Instant::now();
        if map.len() >= self.max_tracked {
            map.retain(|_, (_, started)| now.duration_since(*started) < self.window);
            if map.len() >= self.max_tracked {
                map.clear();
            }
        }
        let (count, started) = map.entry(ip).or_insert((0, now));
        if now.duration_since(*started) >= self.window {
            *count = 0;
            *started = now;
        }
        *count += 1;
        *count > self.limit
    }
}

/// The address an HTTP request came from.
///
/// With no trusted header configured this is the socket peer address, and
/// whatever headers the client sent are ignored: a client that reaches the
/// listener directly must not be able to choose its own address. With one
/// configured, the address is read from the last instance of that header,
/// and from its last comma-separated entry, which is the one the nearest
/// proxy wrote (`X-Forwarded-For` style headers append). A missing or
/// unparsable header falls back to the socket address, which behind a proxy
/// charges the request to the proxy's shared budget: the strict direction.
fn client_ip(socket: IpAddr, headers: &HeaderMap, trusted: Option<&HeaderName>) -> IpAddr {
    trusted
        .and_then(|name| headers.get_all(name).iter().next_back())
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.rsplit(',').next())
        .map(str::trim)
        .and_then(|entry| {
            entry
                .parse::<IpAddr>()
                .ok()
                .or_else(|| entry.parse::<SocketAddr>().ok().map(|s| s.ip()))
        })
        .unwrap_or(socket)
}

/// The answer for an operational route that was not authorised.
fn not_found() -> (axum::http::StatusCode, Json<serde_json::Value>) {
    (
        axum::http::StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": "not found" })),
    )
}

/// The configured admin token, refusing one short enough to guess.
///
/// A token that reads as protection but is brute-forceable is worse than an
/// endpoint that is simply switched off, so a short value is rejected at
/// startup rather than accepted quietly.
fn validated_admin_token(raw: Option<&str>) -> Option<String> {
    let token = raw?.trim();
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
    Some(token.to_string())
}

// ── Metrics HTTP Server ─────────────────────────────────────────────

/// Serve the HTTP routes on `listener` until `shutdown` fires, then finish
/// in-flight requests and return.
pub(crate) async fn serve(
    listener: tokio::net::TcpListener,
    metrics: Arc<RwLock<RelayMetrics>>,
    registry: Option<StoreHandle>,
    admin_token: Option<&str>,
    trusted_proxy_header: Option<HeaderName>,
    limits: &Limits,
    mut shutdown: watch::Receiver<bool>,
) {
    // Sample rolling-minute deltas in the background. Lets /health/alerts
    // serve a denial-rate without external alerters doing delta math.
    {
        let metrics = metrics.clone();
        let mut shutdown = shutdown.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            tick.tick().await; // consume immediate tick
            loop {
                tokio::select! {
                    _ = tick.tick() => {}
                    _ = shutdown.changed() => break,
                }
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
    let max_connections = limits.max_connections;

    // Operational routes (`/peers`, `/metrics`, `/health/alerts`) require a
    // bearer token. Unconfigured means off — this listener is published to the
    // public internet by `fly.toml`, so anything on it that is not `/health` or
    // the public username registry has to prove it was asked for.
    let admin_token = validated_admin_token(admin_token);
    if admin_token.is_none() {
        log::warn!(
            "RELAY_ADMIN_TOKEN is not set — /peers, /metrics and /health/alerts \
             will answer 404. Set it to enable operational endpoints."
        );
    }
    let peers_token = admin_token.clone();
    let metrics_token = admin_token.clone();
    let alerts_token = admin_token;

    let lookup_limiter = Arc::new(LookupLimiter::new(limits));

    let app = Router::new()
        .route(
            "/username/:name",
            get(
                move |axum::extract::Path(name): axum::extract::Path<String>,
                      ConnectInfo(addr): ConnectInfo<SocketAddr>,
                      headers: HeaderMap| {
                    let registry = registry.clone();
                    let limiter = lookup_limiter.clone();
                    let client = client_ip(addr.ip(), &headers, trusted_proxy_header.as_ref());
                    async move {
                        if limiter.is_limited(client) {
                            return (
                                axum::http::StatusCode::TOO_MANY_REQUESTS,
                                Json(serde_json::json!({
                                    "error": "too many lookups — try again in a minute"
                                })),
                            );
                        }
                        let name = name.trim().trim_start_matches('@').to_lowercase();
                        let holder = match &registry {
                            Some(store) => {
                                store.lookup_username(name.clone()).await.unwrap_or(None)
                            }
                            None => None,
                        };
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
                    let lock = m.read().await.snapshot();
                    Json(serde_json::json!({
                        "status": "ok",
                        "version": env!("CARGO_PKG_VERSION"),
                        "peer_id": lock.peer_id,
                        "uptime_seconds": lock.uptime_seconds,
                        "connections": lock.connections,
                        "profile_relays": lock.profile_relays,
                        "reachable_relays": lock.reachable_relays,
                        "bootstrap_status": lock.bootstrap_status,
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
                    let connections_ratio = lock.connections as f64 / f64::from(max_connections);
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
                            "max_connections": max_connections,
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
                    use axum::response::IntoResponse;
                    if !admin_authorised(token.as_deref(), &headers) {
                        return not_found().into_response();
                    }
                    let snapshot = m.read().await.snapshot();
                    if wants_prometheus(&headers) {
                        (
                            [(axum::http::header::CONTENT_TYPE, PROMETHEUS_CONTENT_TYPE)],
                            snapshot.prometheus(),
                        )
                            .into_response()
                    } else {
                        Json(serde_json::json!(snapshot)).into_response()
                    }
                }
            }),
        );

    match listener.local_addr() {
        Ok(addr) => log::info!("Metrics server listening on {addr}"),
        Err(e) => log::warn!("Metrics server listening on an unknown address: {e}"),
    }

    // ── Connection loop ─────────────────────────────────────────────
    // Served through hyper directly rather than `axum::serve`, which has
    // no header-read timeout and no connection bound. A connection takes a
    // slot before it is accepted, so past the limit new connections wait in
    // the kernel's listen backlog instead of costing memory here. HTTP/1.1
    // only: every client of this listener (health checkers, the app's
    // lookup, the observer) speaks it, and HTTP/2 would add surface for
    // nothing.
    let max_connections = limits
        .http_max_connections
        .clamp(1, Semaphore::MAX_PERMITS.min(u32::MAX as usize));
    let slots = Arc::new(Semaphore::new(max_connections));
    let request_timeout = limits.http_request_timeout;
    let mut http1 = hyper::server::conn::http1::Builder::new();
    http1
        .timer(TokioTimer::new())
        .header_read_timeout(limits.http_header_read_timeout);

    loop {
        let slot = tokio::select! {
            slot = slots.clone().acquire_owned() => match slot {
                Ok(slot) => slot,
                Err(_) => break, // never closed; unreachable in practice
            },
            _ = shutdown.changed() => break,
        };
        let (stream, remote) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(e) => {
                    // Usually descriptor exhaustion. Back off instead of
                    // spinning on an accept that keeps failing.
                    log::warn!("HTTP accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            _ = shutdown.changed() => break,
        };

        let app = app.clone();
        let service =
            hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
                req.extensions_mut().insert(ConnectInfo(remote));
                let app = app.clone();
                async move {
                    match tokio::time::timeout(request_timeout, app.oneshot(req)).await {
                        Ok(response) => response,
                        Err(_) => {
                            log::warn!("HTTP request from {remote} exceeded {request_timeout:?}");
                            Ok(axum::response::IntoResponse::into_response((
                                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                                Json(serde_json::json!({ "error": "request timed out" })),
                            )))
                        }
                    }
                }
            });
        let connection = http1.serve_connection(TokioIo::new(stream), service);
        let mut conn_shutdown = shutdown.clone();
        tokio::spawn(async move {
            let _slot = slot;
            tokio::pin!(connection);
            let result = tokio::select! {
                result = connection.as_mut() => result,
                _ = conn_shutdown.changed() => {
                    connection.as_mut().graceful_shutdown();
                    connection.await
                }
            };
            if let Err(e) = result {
                log::debug!("HTTP connection from {remote} ended: {e}");
            }
        });
    }

    // Stop accepting, then let in-flight requests finish: every open
    // connection holds a slot, so holding all of them means all are closed.
    drop(listener);
    let _ = slots.acquire_many(max_connections as u32).await;
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

    fn with_header(name: &str, values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn the_client_address_comes_from_the_trusted_header_only() {
        let socket: IpAddr = "10.0.0.1".parse().unwrap();
        let fly = HeaderName::from_static("fly-client-ip");
        let headers = with_header("fly-client-ip", &["198.51.100.7"]);
        assert_eq!(client_ip(socket, &headers, None), socket);
        assert_eq!(
            client_ip(socket, &headers, Some(&fly)),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
        // Configured but absent or garbage: the socket address.
        assert_eq!(client_ip(socket, &HeaderMap::new(), Some(&fly)), socket);
        let garbage = with_header("fly-client-ip", &["not-an-address"]);
        assert_eq!(client_ip(socket, &garbage, Some(&fly)), socket);
    }

    #[test]
    fn an_appending_header_is_read_from_its_last_entry() {
        // A client can prepend anything to X-Forwarded-For; only the entry
        // the nearest proxy appended is trustworthy.
        let socket: IpAddr = "10.0.0.1".parse().unwrap();
        let xff = HeaderName::from_static("x-forwarded-for");
        let headers = with_header(
            "x-forwarded-for",
            &["203.0.113.1", "203.0.113.2, [2001:db8::1]:443"],
        );
        assert_eq!(
            client_ip(socket, &headers, Some(&xff)),
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
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
        LookupLimiter::new(&Limits::default())
    }

    /// The public username oracle used to be unthrottled: the whole registry
    /// was enumerable for the cost of a loop. A client gets a budget per
    /// window and is refused past it.
    #[test]
    fn a_client_is_refused_past_its_lookup_budget() {
        let l = fresh();
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        for _ in 0..DEFAULT_LOOKUP_LIMIT {
            assert!(!l.is_limited(ip), "within budget must be allowed");
        }
        assert!(l.is_limited(ip), "one past the budget must be refused");
    }

    /// One client exhausting its budget must not affect another.
    #[test]
    fn budgets_are_per_client() {
        let l = fresh();
        let a = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let b = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));
        for _ in 0..=DEFAULT_LOOKUP_LIMIT {
            let _ = l.is_limited(a);
        }
        assert!(l.is_limited(a));
        assert!(!l.is_limited(b));
    }

    /// The budget is the configured one, not a constant.
    #[test]
    fn the_budget_follows_the_configuration() {
        let l = LookupLimiter::new(&Limits {
            lookup_limit: 2,
            ..Limits::default()
        });
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        assert!(!l.is_limited(ip));
        assert!(!l.is_limited(ip));
        assert!(l.is_limited(ip));
    }

    /// The map cannot itself become the memory leak.
    #[test]
    fn the_tracked_set_stays_bounded() {
        let l = fresh();
        for i in 0..(DEFAULT_LOOKUP_MAX_TRACKED + 500) {
            let ip = IpAddr::V4(Ipv4Addr::from((i as u32).wrapping_add(0x0100_0000)));
            let _ = l.is_limited(ip);
        }
        assert!(l.windows.lock().unwrap().len() <= DEFAULT_LOOKUP_MAX_TRACKED);
    }
}
