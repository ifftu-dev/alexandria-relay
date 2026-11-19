//! PROXY protocol v2 on inbound TCP.
//!
//! Behind a proxy that hides client addresses (Fly.io's, for raw TCP), the
//! proxy can open every connection with a PROXY protocol v2 header carrying
//! the client's address and port. With `--tcp-proxy-protocol v2`, [`ProxyTcp`]
//! reads that header off each inbound socket before the swarm hears of the
//! connection, and reports the connection with the header's source as its
//! remote address. Everything that keys on the remote address (the per-IP
//! limits, libp2p's relay limiters, Identify's observed address, `/peers`)
//! then sees the client instead of the proxy, without changing.
//!
//! The relay trusts the first header on a connection, so `v2` belongs only
//! on a relay that every connection reaches through such a proxy. Outbound
//! dials are never read. Sockets still waiting for their header are not yet
//! pending connections to the swarm, so they have their own bounds: a read
//! timeout and a cap on how many may wait at once.

use std::collections::HashSet;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use futures::future::{self, BoxFuture, Ready};
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt};
use libp2p::core::transport::{DialOpts, ListenerId, Transport, TransportError, TransportEvent};
use libp2p::multiaddr::Protocol;
use libp2p::{tcp, Multiaddr};
use serde::ser::{Serialize, SerializeStruct, Serializer};
use tokio::io::{AsyncRead, AsyncReadExt};

/// The v2 signature every header opens with.
const SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";

/// How a version 1 (text) header opens. The relay refuses those as invalid
/// rather than missing, so a proxy set to the wrong version shows as such.
const V1_PREFIX: &[u8] = b"PROXY ";

/// Signature, version and command, family and protocol, and the length.
const FIXED_LEN: usize = 16;

/// Largest header accepted, in bytes, TLVs included. Fly's headers are a few
/// dozen bytes; the cap stops a header from making the relay buffer
/// arbitrary data.
pub(crate) const MAX_HEADER_LEN: usize = 1024;

/// Why a connection was refused before libp2p saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum HeaderError {
    /// The connection did not open with the v2 signature: a direct client,
    /// a scanner, or a proxy that sends no header.
    #[error("no PROXY v2 header")]
    Missing,
    /// It opened with a header the relay does not accept: version 1 (text),
    /// a bad version or command, the UNIX family, a transport other than
    /// STREAM, truncated, or over [`MAX_HEADER_LEN`].
    #[error("malformed or unsupported PROXY header")]
    Invalid,
    /// The header did not arrive within the timeout.
    #[error("PROXY header timed out")]
    Timeout,
}

/// The client address in `buf`, a complete v2 header and nothing after it:
/// `Some` for a PROXY command with an IPv4 or IPv6 source over STREAM (TCP),
/// `None` (use the socket's address) for the LOCAL command or the UNSPEC
/// family. Any other family or transport protocol (DGRAM, or UNSPEC with an
/// IP family) is refused. TLVs after the addresses are skipped.
pub(crate) fn parse(buf: &[u8]) -> Result<Option<SocketAddr>, HeaderError> {
    let total = header_len(buf)?;
    let header = buf.get(..total).ok_or(HeaderError::Invalid)?;
    let body = &header[FIXED_LEN..];
    if header[12] & 0x0f == 0 {
        return Ok(None); // LOCAL: the proxy's own connection, e.g. a health check
    }
    const STREAM: u8 = 1;
    match (header[13] >> 4, header[13] & 0x0f) {
        (0, 0 | STREAM) => Ok(None),
        (1, STREAM) => {
            let b = body.get(..12).ok_or(HeaderError::Invalid)?;
            let ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            Ok(Some(SocketAddr::from((
                ip,
                u16::from_be_bytes([b[8], b[9]]),
            ))))
        }
        (2, STREAM) => {
            let b = body.get(..36).ok_or(HeaderError::Invalid)?;
            let octets: [u8; 16] = b[..16].try_into().map_err(|_| HeaderError::Invalid)?;
            let port = u16::from_be_bytes([b[32], b[33]]);
            Ok(Some(SocketAddr::from((Ipv6Addr::from(octets), port))))
        }
        _ => Err(HeaderError::Invalid), // UNIX, DGRAM, or no protocol for an IP
    }
}

/// The whole header's length, from the first bytes of a connection. Fails
/// as soon as `prefix` stops matching the signature, so a reader can give
/// up before the fixed part has arrived.
fn header_len(prefix: &[u8]) -> Result<usize, HeaderError> {
    let overlap = prefix.len().min(SIGNATURE.len());
    if prefix.is_empty() || prefix[..overlap] != SIGNATURE[..overlap] {
        return Err(if prefix.starts_with(V1_PREFIX) {
            HeaderError::Invalid // version 1, the text form
        } else {
            HeaderError::Missing
        });
    }
    if prefix.len() < FIXED_LEN {
        return Err(HeaderError::Invalid);
    }
    let (version, command) = (prefix[12] >> 4, prefix[12] & 0x0f);
    if version != 2 || command > 1 {
        return Err(HeaderError::Invalid);
    }
    let total = FIXED_LEN + usize::from(u16::from_be_bytes([prefix[14], prefix[15]]));
    if total > MAX_HEADER_LEN {
        return Err(HeaderError::Invalid);
    }
    Ok(total)
}

/// Whether `prefix`, the bytes read so far, could still open a header of
/// either version, so the reader should wait for more before classifying.
fn may_open_a_header(prefix: &[u8]) -> bool {
    let sig = prefix.len().min(SIGNATURE.len());
    prefix[..sig] == SIGNATURE[..sig]
        || (prefix.len() < V1_PREFIX.len() && V1_PREFIX.starts_with(prefix))
}

/// Read the header off a freshly accepted socket, exactly and no further:
/// what follows belongs to multistream-select. Returns the address the
/// connection is attributed to, the header's source or `socket_remote`.
async fn read_header<S: AsyncRead + Unpin>(
    stream: &mut S,
    socket_remote: Multiaddr,
) -> Result<Multiaddr, HeaderError> {
    let mut buf = vec![0u8; FIXED_LEN];
    let mut got = 0;
    while got < FIXED_LEN {
        let n = stream.read(&mut buf[got..]).await.unwrap_or(0);
        if n == 0 {
            // Closed (or reset) early: classify what did arrive.
            return Err(header_len(&buf[..got])
                .err()
                .unwrap_or(HeaderError::Invalid));
        }
        got += n;
        if !may_open_a_header(&buf[..got]) {
            return Err(header_len(&buf[..got])
                .err()
                .unwrap_or(HeaderError::Missing));
        }
    }
    let total = header_len(&buf)?;
    buf.resize(total, 0);
    stream
        .read_exact(&mut buf[FIXED_LEN..])
        .await
        .map_err(|_| HeaderError::Invalid)?;
    Ok(match parse(&buf)? {
        Some(src) => Multiaddr::empty()
            .with(Protocol::from(src.ip()))
            .with(Protocol::Tcp(src.port())),
        None => socket_remote,
    })
}

// ── Counters ─────────────────────────────────────────────────────────

/// Refusals in one window below which the header-refusal alert stays off,
/// so a lone scanner on a quiet relay cannot trip it.
const ALERT_MIN_REFUSALS: u64 = 10;

/// The wrapper's counters, shared between the transport (which cannot await
/// the metrics lock from `poll`) and the HTTP routes. Clones share one set.
/// Serializes as the `proxy_header_*` fields of `/metrics`.
#[derive(Debug, Clone, Default)]
pub(crate) struct ProxyCounters(Arc<Shared>);

/// What every clone of one [`ProxyCounters`] points at.
#[derive(Debug, Default)]
struct Shared {
    /// Inbound TCP sockets accepted while `v2` is on: the alert's base.
    attempts: AtomicU64,
    missing: AtomicU64,
    invalid: AtomicU64,
    timeout: AtomicU64,
    /// Closed on accept because the waiting cap was full.
    overflow: AtomicU64,
    window: Mutex<Window>,
}

/// Inbound TCP attempts and the refusals among them, as totals or over a
/// window.
#[derive(Debug, Default, Clone, Copy)]
struct Tally {
    attempts: u64,
    /// Refused for a missing, invalid or late header.
    refused: u64,
}

impl Tally {
    /// The counts between `start` and `self`. Saturating: the counters are
    /// read one by one without stopping writers, so a total never goes
    /// backwards but a sum read early could trail one read later.
    fn since(self, start: Tally) -> Tally {
        Tally {
            attempts: self.attempts.saturating_sub(start.attempts),
            refused: self.refused.saturating_sub(start.refused),
        }
    }

    /// Refusals are more than half of attempts and at least
    /// [`ALERT_MIN_REFUSALS`].
    fn refusals_dominate(self) -> bool {
        self.refused >= ALERT_MIN_REFUSALS && self.refused.saturating_mul(2) > self.attempts
    }
}

/// The totals at the start of the window in progress, and the counts over
/// the last complete one.
#[derive(Debug, Default)]
struct Window {
    start: Tally,
    last: Tally,
}

impl ProxyCounters {
    fn load(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }

    fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// An inbound TCP socket was accepted.
    fn accepted(&self) {
        Self::bump(&self.0.attempts);
    }

    /// An accepted socket was closed because the waiting cap was full.
    fn overflowed(&self) {
        Self::bump(&self.0.overflow);
    }

    /// An accepted socket was refused for its header.
    fn refused(&self, error: HeaderError) {
        Self::bump(match error {
            HeaderError::Missing => &self.0.missing,
            HeaderError::Invalid => &self.0.invalid,
            HeaderError::Timeout => &self.0.timeout,
        });
    }

    /// The totals so far.
    fn totals(&self) -> Tally {
        let c = &self.0;
        Tally {
            attempts: Self::load(&c.attempts),
            refused: Self::load(&c.missing) + Self::load(&c.invalid) + Self::load(&c.timeout),
        }
    }

    /// Close the window in progress and open the next. The HTTP server's
    /// rolling-minute sampler calls this once a minute.
    pub(crate) fn roll_window(&self) {
        if let Ok(mut w) = self.0.window.lock() {
            let now = self.totals();
            w.last = now.since(w.start);
            w.start = now;
        }
    }

    /// True when, over the last complete window or the one in progress,
    /// connections refused for their header are more than half of inbound
    /// TCP attempts and at least [`ALERT_MIN_REFUSALS`]. Counting the
    /// window in progress pages as soon as a proxy stops sending headers.
    pub(crate) fn header_refusal_alert(&self) -> bool {
        let Ok(w) = self.0.window.lock() else {
            return false;
        };
        // Read under the lock, so no roll lands between the read and the
        // window it is measured against.
        let current = self.totals().since(w.start);
        w.last.refusals_dominate() || current.refusals_dominate()
    }

    /// `(name, help, value)` for each counter, in `/metrics` naming.
    pub(crate) fn counters(&self) -> [(&'static str, &'static str, u64); 4] {
        let c = &self.0;
        [
            (
                "proxy_header_missing",
                "Inbound TCP connections refused for opening without a PROXY header.",
                Self::load(&c.missing),
            ),
            (
                "proxy_header_invalid",
                "Inbound TCP connections refused for a malformed or unsupported PROXY header.",
                Self::load(&c.invalid),
            ),
            (
                "proxy_header_timeout",
                "Inbound TCP connections refused for a PROXY header that did not arrive in time.",
                Self::load(&c.timeout),
            ),
            (
                "proxy_header_overflow",
                "Inbound TCP connections closed on accept because too many awaited a PROXY header.",
                Self::load(&c.overflow),
            ),
        ]
    }
}

impl Serialize for ProxyCounters {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let counters = self.counters();
        let mut s = serializer.serialize_struct("ProxyCounters", counters.len())?;
        for (name, _, value) in counters {
            s.serialize_field(name, &value)?;
        }
        s.end()
    }
}

// ── Transport wrapper ────────────────────────────────────────────────

/// What [`ProxyTcp`] does with inbound sockets.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Inbound {
    /// Report them as they are (`--tcp-proxy-protocol off`).
    PassThrough,
    /// Read a v2 header off each first.
    ReadV2 {
        /// How long a socket has to send its header.
        timeout: Duration,
        /// How many sockets may wait for their header at once.
        max_waiting: usize,
    },
}

/// A socket whose header is being read: its listener and local address, and
/// the stream with the address it is attributed to.
type Waiting = BoxFuture<
    'static,
    (
        ListenerId,
        Multiaddr,
        Result<(tcp::tokio::TcpStream, Multiaddr), HeaderError>,
    ),
>;

/// libp2p's tokio TCP transport, reading a PROXY protocol v2 header off each
/// inbound socket before reporting it (see the module docs). Listening and
/// dialling go straight to the inner transport.
pub(crate) struct ProxyTcp {
    inner: tcp::tokio::Transport,
    inbound: Inbound,
    waiting: FuturesUnordered<Waiting>,
    closed: HashSet<ListenerId>,
    counters: ProxyCounters,
}

impl ProxyTcp {
    pub(crate) fn new(
        inner: tcp::tokio::Transport,
        inbound: Inbound,
        counters: ProxyCounters,
    ) -> Self {
        ProxyTcp {
            inner,
            inbound,
            waiting: FuturesUnordered::new(),
            closed: HashSet::new(),
            counters,
        }
    }
}

/// Inner events taken per poll before yielding, so a burst of accepts
/// cannot starve the rest of the swarm.
const MAX_ACCEPTS_PER_POLL: usize = 64;

impl Transport for ProxyTcp {
    type Output = tcp::tokio::TcpStream;
    type Error = io::Error;
    type ListenerUpgrade = Ready<Result<Self::Output, io::Error>>;
    type Dial = <tcp::tokio::Transport as Transport>::Dial;

    fn listen_on(
        &mut self,
        id: ListenerId,
        addr: Multiaddr,
    ) -> Result<(), TransportError<io::Error>> {
        self.inner.listen_on(id, addr)
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        self.inner.remove_listener(id)
    }

    fn dial(
        &mut self,
        addr: Multiaddr,
        opts: DialOpts,
    ) -> Result<Self::Dial, TransportError<io::Error>> {
        self.inner.dial(addr, opts)
    }

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, io::Error>> {
        let this = self.get_mut();
        let Inbound::ReadV2 {
            timeout,
            max_waiting,
        } = this.inbound
        else {
            return Pin::new(&mut this.inner).poll(cx);
        };

        // New sockets start their header read; every other event passes
        // through unchanged.
        let mut drained = false;
        for _ in 0..MAX_ACCEPTS_PER_POLL {
            match Pin::new(&mut this.inner).poll(cx) {
                Poll::Ready(TransportEvent::Incoming {
                    listener_id,
                    upgrade,
                    local_addr,
                    send_back_addr,
                }) => {
                    this.counters.accepted();
                    let Ok(mut stream) = upgrade.into_inner() else {
                        continue;
                    };
                    if this.waiting.len() >= max_waiting {
                        this.counters.overflowed();
                        log::debug!("PROXY header: waiting cap reached, closing {send_back_addr}");
                        continue; // dropping the stream closes it
                    }
                    this.waiting.push(
                        async move {
                            let result = tokio::time::timeout(
                                timeout,
                                read_header(&mut stream.0, send_back_addr),
                            )
                            .await
                            .unwrap_or(Err(HeaderError::Timeout));
                            (listener_id, local_addr, result.map(|addr| (stream, addr)))
                        }
                        .boxed(),
                    );
                }
                Poll::Ready(event @ TransportEvent::ListenerClosed { listener_id, .. }) => {
                    this.closed.insert(listener_id);
                    return Poll::Ready(event);
                }
                Poll::Ready(event) => return Poll::Ready(event),
                Poll::Pending => {
                    drained = true;
                    break;
                }
            }
        }
        if !drained {
            cx.waker().wake_by_ref();
        }

        // Finished header reads, polled after the last push so every new
        // read has registered the waker.
        while let Poll::Ready(Some((listener_id, local_addr, result))) =
            this.waiting.poll_next_unpin(cx)
        {
            if this.closed.contains(&listener_id) {
                continue;
            }
            match result {
                Ok((stream, send_back_addr)) => {
                    return Poll::Ready(TransportEvent::Incoming {
                        listener_id,
                        upgrade: future::ok(stream),
                        local_addr,
                        send_back_addr,
                    });
                }
                Err(error) => {
                    log::debug!("PROXY header: refused an inbound connection ({error})");
                    this.counters.refused(error);
                }
            }
        }
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const SIG: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";

    /// A v2 header: `cmd` (0 LOCAL, 1 PROXY), `fam` (high nibble family, low
    /// nibble protocol) and the body after the length field.
    fn header(cmd: u8, fam: u8, body: &[u8]) -> Vec<u8> {
        let mut h = SIG.to_vec();
        h.push(0x20 | cmd);
        h.push(fam);
        h.extend_from_slice(&(body.len() as u16).to_be_bytes());
        h.extend_from_slice(body);
        h
    }

    fn inet_body() -> Vec<u8> {
        let mut b = vec![192, 0, 2, 7, 10, 0, 0, 1];
        b.extend_from_slice(&40_000u16.to_be_bytes());
        b.extend_from_slice(&4001u16.to_be_bytes());
        b
    }

    #[test]
    fn an_ipv4_source_is_the_client_address() {
        assert_eq!(
            parse(&header(1, 0x11, &inet_body())),
            Ok(Some(SocketAddr::from((
                Ipv4Addr::new(192, 0, 2, 7),
                40_000
            ))))
        );
    }

    #[test]
    fn an_ipv6_source_stays_ipv6() {
        let src: Ipv6Addr = "2001:db8:1:2::9".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let mut body = src.octets().to_vec();
        body.extend_from_slice(&dst.octets());
        body.extend_from_slice(&51_000u16.to_be_bytes());
        body.extend_from_slice(&4001u16.to_be_bytes());
        assert_eq!(
            parse(&header(1, 0x21, &body)),
            Ok(Some(SocketAddr::from((src, 51_000))))
        );
    }

    #[test]
    fn local_means_the_socket_address() {
        assert_eq!(parse(&header(0, 0x00, &[])), Ok(None));
        // LOCAL ignores any address block it carries.
        assert_eq!(parse(&header(0, 0x11, &inet_body())), Ok(None));
    }

    #[test]
    fn the_unspec_family_means_the_socket_address() {
        assert_eq!(parse(&header(1, 0x00, &[])), Ok(None));
    }

    #[test]
    fn the_unix_family_is_refused() {
        assert_eq!(
            parse(&header(1, 0x31, &[0u8; 216])),
            Err(HeaderError::Invalid)
        );
    }

    #[test]
    fn tlvs_after_the_addresses_are_skipped() {
        let mut body = inet_body();
        // PP2_TYPE_AUTHORITY "relay.example.org", then a NOOP.
        body.extend_from_slice(&[0x02, 0x00, 17]);
        body.extend_from_slice(b"relay.example.org");
        body.extend_from_slice(&[0x04, 0x00, 0x02, 0, 0]);
        assert_eq!(
            parse(&header(1, 0x11, &body)),
            Ok(Some(SocketAddr::from((
                Ipv4Addr::new(192, 0, 2, 7),
                40_000
            ))))
        );
    }

    #[test]
    fn truncated_input_is_refused() {
        let full = header(1, 0x11, &inet_body());
        for len in [0, 5, 12, 15, 16, full.len() - 1] {
            assert!(parse(&full[..len]).is_err(), "{len} bytes parsed");
        }
        // A length field shorter than the family's address block.
        assert_eq!(
            parse(&header(1, 0x11, &inet_body()[..8])),
            Err(HeaderError::Invalid)
        );
    }

    #[test]
    fn anything_without_the_signature_is_a_missing_header() {
        assert_eq!(
            parse(b"\x13/multistream/1.0.0\n/noise\n"),
            Err(HeaderError::Missing)
        );
        assert_eq!(parse(&[]), Err(HeaderError::Missing));
    }

    #[test]
    fn a_v1_text_header_is_invalid() {
        assert_eq!(
            parse(b"PROXY TCP4 192.0.2.7 10.0.0.1 40000 4001\r\n"),
            Err(HeaderError::Invalid)
        );
    }

    #[test]
    fn a_wrong_version_or_command_is_invalid() {
        let mut h = header(1, 0x11, &inet_body());
        h[12] = 0x11; // version 1
        assert_eq!(parse(&h), Err(HeaderError::Invalid));
        h[12] = 0x22; // command 2
        assert_eq!(parse(&h), Err(HeaderError::Invalid));
    }

    #[test]
    fn a_header_over_the_cap_is_refused() {
        let mut body = inet_body();
        body.resize(MAX_HEADER_LEN - 16 + 1, 0);
        assert_eq!(parse(&header(1, 0x11, &body)), Err(HeaderError::Invalid));
        body.truncate(MAX_HEADER_LEN - 16);
        assert!(parse(&header(1, 0x11, &body)).is_ok(), "exactly the cap");
    }

    #[test]
    fn the_alert_survives_a_window_rolling_while_it_reads() {
        // The sampler rolls the window while connections keep arriving and
        // `/health` asks for the alert: the alert must never compute a
        // window that starts after the totals it read.
        let counters = ProxyCounters::default();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writer = {
            let (counters, stop) = (counters.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    counters.accepted();
                    counters.refused(HeaderError::Missing);
                    counters.roll_window();
                }
            })
        };
        let reader = {
            let counters = counters.clone();
            std::thread::spawn(move || {
                for _ in 0..200_000 {
                    counters.header_refusal_alert();
                }
            })
        };
        let read = reader.join();
        stop.store(true, Ordering::Relaxed);
        writer.join().unwrap();
        assert!(read.is_ok(), "the alert panicked");
    }

    /// Hands out one chunk per read, then end of stream, the way a socket
    /// delivers what a peer wrote in separate segments.
    struct Chunks(std::collections::VecDeque<Vec<u8>>);

    impl tokio::io::AsyncRead for Chunks {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if let Some(mut chunk) = self.0.pop_front() {
                let n = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..n]);
                if n < chunk.len() {
                    self.0.push_front(chunk.split_off(n));
                }
            }
            Poll::Ready(Ok(()))
        }
    }

    fn read_chunks(chunks: &[&[u8]]) -> Result<Multiaddr, HeaderError> {
        let mut stream = Chunks(chunks.iter().map(|c| c.to_vec()).collect());
        let socket: Multiaddr = "/ip4/10.0.0.1/tcp/5000".parse().unwrap();
        futures::executor::block_on(read_header(&mut stream, socket))
    }

    #[test]
    fn a_v1_header_split_across_reads_is_invalid() {
        for split in 1..6 {
            let line = b"PROXY TCP4 192.0.2.7 10.0.0.1 40000 4001\r\n";
            let (a, b) = line.split_at(split);
            assert_eq!(read_chunks(&[a, b]), Err(HeaderError::Invalid), "{split}");
        }
    }

    #[test]
    fn a_v2_header_split_across_reads_is_read() {
        let h = header(1, 0x11, &inet_body());
        let (a, rest) = h.split_at(3);
        let (b, c) = rest.split_at(15);
        assert_eq!(
            read_chunks(&[a, b, c]).unwrap().to_string(),
            "/ip4/192.0.2.7/tcp/40000"
        );
    }

    #[test]
    fn a_connection_that_is_not_proxied_is_a_missing_header() {
        assert_eq!(
            read_chunks(&[b"\x13/multistream/1.0.0\n"]),
            Err(HeaderError::Missing)
        );
        assert_eq!(read_chunks(&[b"PR", b"OTO"]), Err(HeaderError::Missing));
        assert_eq!(read_chunks(&[]), Err(HeaderError::Missing));
    }

    #[test]
    fn inet_families_must_carry_a_stream_protocol() {
        // 0x10 / 0x20: INET / INET6 with an UNSPEC protocol; 0x12 / 0x22:
        // with DGRAM. Only STREAM (0x_1) is TCP.
        let v6_body = [0u8; 36];
        for (fam, body) in [
            (0x10, &inet_body()[..]),
            (0x12, &inet_body()[..]),
            (0x20, &v6_body[..]),
            (0x22, &v6_body[..]),
        ] {
            assert_eq!(
                parse(&header(1, fam, body)),
                Err(HeaderError::Invalid),
                "{fam:#04x}"
            );
        }
    }

    #[test]
    fn the_unspec_family_refuses_dgram() {
        assert_eq!(parse(&header(1, 0x02, &[])), Err(HeaderError::Invalid));
        assert_eq!(parse(&header(1, 0x01, &[])), Ok(None));
    }
}
