//! The relay's libp2p transport, assembled by hand: TCP with noise and
//! yamux, plus QUIC when it is switched on.
//!
//! The swarm builder's own TCP and QUIC phases take neither a wrapped TCP
//! transport nor a way to leave QUIC out, so [`build`] assembles both and
//! the swarm takes the result through the builder's custom-transport hook.
//! Everything that shapes a transport lives here: [`tcp`] is the one place
//! the TCP transport is built (and wrapped), [`quic_config`] the one place
//! the QUIC configuration is set.

use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::Boxed;
use libp2p::core::upgrade::Version;
use libp2p::core::Transport;
use libp2p::identity::Keypair;
use libp2p::{noise, quic, yamux, PeerId};

use crate::config::RelayConfig;

/// The transport the relay's swarm runs on.
pub(crate) type RelayTransport = Boxed<(PeerId, StreamMuxerBox)>;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The relay's transport for `config`: TCP always, QUIC when `config.quic`
/// is on. With QUIC off, listening on or dialling a QUIC address is refused
/// as unsupported.
pub(crate) fn build(key: &Keypair, config: &RelayConfig) -> Result<RelayTransport, BoxError> {
    let tcp = tcp(key)?;
    if !config.quic {
        return Ok(tcp);
    }
    let quic = quic::tokio::Transport::new(quic_config(key, config))
        .map(|(peer, conn), _| (peer, StreamMuxerBox::new(conn)));
    Ok(tcp
        .or_transport(quic)
        .map(|either, _| either.into_inner())
        .boxed())
}

/// TCP, upgraded with noise and yamux, as the builder's `with_tcp` would
/// build it.
fn tcp(key: &Keypair) -> Result<RelayTransport, BoxError> {
    Ok(
        libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::default())
            .upgrade(Version::V1Lazy)
            .authenticate(noise::Config::new(key)?)
            .multiplex(yamux::Config::default())
            .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
            .boxed(),
    )
}

/// The QUIC configuration: the handshake timeout and the per-stream and
/// per-connection receive windows from [`crate::config::QuicLimits`]; idle
/// timeout, keep-alive, path MTU discovery and stream limits stay at
/// libp2p's defaults. The pending-handshake budget is not a transport
/// setting: [`crate::quic_budget`] enforces it in the swarm.
fn quic_config(key: &Keypair, config: &RelayConfig) -> quic::Config {
    let limits = &config.limits.quic;
    let mut quic = quic::Config::new(key);
    quic.handshake_timeout = limits.handshake_timeout;
    quic.max_stream_data = limits.max_stream_data;
    quic.max_connection_data = limits.max_connection_data;
    quic
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::config::QuicLimits;

    #[test]
    fn the_quic_config_takes_its_windows_and_timeout_from_the_settings() {
        let key = Keypair::generate_ed25519();
        let mut config = RelayConfig::default();
        config.limits.quic = QuicLimits {
            max_pending_incoming: 64,
            max_stream_data: 1_000,
            max_connection_data: 2_000,
            handshake_timeout: Duration::from_secs(7),
        };
        let quic = quic_config(&key, &config);
        assert_eq!(quic.max_stream_data, 1_000);
        assert_eq!(quic.max_connection_data, 2_000);
        assert_eq!(quic.handshake_timeout, Duration::from_secs(7));
    }

    #[test]
    fn the_default_quic_windows_are_far_below_quinns() {
        let key = Keypair::generate_ed25519();
        let quic = quic_config(&key, &RelayConfig::default());
        assert_eq!(quic.max_stream_data, 262_144);
        assert_eq!(quic.max_connection_data, 524_288);
        assert_eq!(quic.handshake_timeout, Duration::from_secs(5));
        // Everything else stays at libp2p's defaults.
        let libp2p = quic::Config::new(&key);
        assert_eq!(quic.max_idle_timeout, libp2p.max_idle_timeout);
        assert_eq!(quic.keep_alive_interval, libp2p.keep_alive_interval);
        assert_eq!(
            quic.max_concurrent_stream_limit,
            libp2p.max_concurrent_stream_limit
        );
    }
}
