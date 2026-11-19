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

/// The QUIC configuration: libp2p's defaults for now.
fn quic_config(key: &Keypair, _config: &RelayConfig) -> quic::Config {
    quic::Config::new(key)
}
