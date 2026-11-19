//! The QUIC pending-handshake budget.
//!
//! A QUIC connection reaches the swarm as a pending inbound connection
//! before its handshake runs, and UDP sources are spoofable, so a flood of
//! QUIC handshakes could otherwise fill the pending-incoming slots that the
//! connection limits share with TCP. [`QuicPendingBudget`] holds pending QUIC
//! handshakes to their own, smaller budget. It has no per-address cap: with
//! spoofable sources, that would let an attacker lock out chosen addresses.

use std::collections::HashSet;
use std::convert::Infallible;
use std::task::{Context, Poll};

use libp2p::core::transport::PortUse;
use libp2p::core::Endpoint;
use libp2p::swarm::behaviour::{ConnectionEstablished, ListenFailure};
use libp2p::swarm::{
    dummy, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm,
};
use libp2p::{Multiaddr, PeerId};

use crate::addr::is_quic;

/// Why a QUIC handshake was refused before it started.
#[derive(Debug, thiserror::Error)]
#[error("QUIC pending-incoming budget of {0} reached")]
pub(crate) struct QuicBudgetExceeded(pub(crate) u32);

/// Counts pending inbound connections whose local address is QUIC and
/// denies new ones once `max` are pending. A slot is released when the
/// connection is established or fails, whichever behaviour ended it. TCP
/// connections pass untouched.
///
/// The swarm reports a denial as a [`QuicBudgetExceeded`] cause on
/// `SwarmEvent::IncomingConnectionError`, which is where the relay counts
/// it. The behaviour itself emits nothing.
pub(crate) struct QuicPendingBudget {
    max: u32,
    pending: HashSet<ConnectionId>,
}

impl QuicPendingBudget {
    pub(crate) fn new(max: u32) -> Self {
        QuicPendingBudget {
            max,
            pending: HashSet::new(),
        }
    }
}

impl NetworkBehaviour for QuicPendingBudget {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        if !is_quic(local_addr) {
            return Ok(());
        }
        if self.pending.len() >= self.max as usize {
            return Err(ConnectionDenied::new(QuicBudgetExceeded(self.max)));
        }
        self.pending.insert(connection_id);
        Ok(())
    }

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        _peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.pending.remove(&connection_id);
        Ok(dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _addr: &Multiaddr,
        _role_override: Endpoint,
        _port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        // A later behaviour may deny the established connection before this
        // one's hook runs; the swarm then reports a listen failure to all.
        match event {
            FromSwarm::ListenFailure(ListenFailure { connection_id, .. })
            | FromSwarm::ConnectionEstablished(ConnectionEstablished { connection_id, .. }) => {
                self.pending.remove(&connection_id);
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _peer: PeerId,
        _connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {}
    }

    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::core::ConnectedPoint;
    use libp2p::swarm::ListenError;

    fn quic_local() -> Multiaddr {
        "/ip4/0.0.0.0/udp/4001/quic-v1".parse().unwrap()
    }

    fn tcp_local() -> Multiaddr {
        "/ip4/0.0.0.0/tcp/4001".parse().unwrap()
    }

    fn remote() -> Multiaddr {
        "/ip4/198.51.100.7/udp/50000/quic-v1".parse().unwrap()
    }

    fn id(n: usize) -> ConnectionId {
        ConnectionId::new_unchecked(n)
    }

    fn pending(budget: &mut QuicPendingBudget, n: usize, local: &Multiaddr) -> bool {
        budget
            .handle_pending_inbound_connection(id(n), local, &remote())
            .is_ok()
    }

    fn fail(budget: &mut QuicPendingBudget, n: usize) {
        budget.on_swarm_event(FromSwarm::ListenFailure(ListenFailure {
            local_addr: &quic_local(),
            send_back_addr: &remote(),
            error: &ListenError::Aborted,
            connection_id: id(n),
            peer_id: None,
        }));
    }

    #[test]
    fn quic_handshakes_above_the_budget_are_denied() {
        let mut budget = QuicPendingBudget::new(2);
        assert!(pending(&mut budget, 1, &quic_local()));
        assert!(pending(&mut budget, 2, &quic_local()));
        let denied = budget
            .handle_pending_inbound_connection(id(3), &quic_local(), &remote())
            .expect_err("third QUIC handshake is over the budget");
        assert!(denied.downcast_ref::<QuicBudgetExceeded>().is_some());
    }

    #[test]
    fn tcp_pending_connections_are_never_counted() {
        let mut budget = QuicPendingBudget::new(1);
        for n in 0..100 {
            assert!(pending(&mut budget, n, &tcp_local()), "TCP is not budgeted");
        }
        assert!(
            pending(&mut budget, 100, &quic_local()),
            "the slot is still free"
        );
        assert!(!pending(&mut budget, 101, &quic_local()));
    }

    #[test]
    fn a_slot_is_released_when_the_handshake_completes() {
        let mut budget = QuicPendingBudget::new(1);
        assert!(pending(&mut budget, 1, &quic_local()));
        assert!(!pending(&mut budget, 2, &quic_local()));
        budget
            .handle_established_inbound_connection(
                id(1),
                PeerId::random(),
                &quic_local(),
                &remote(),
            )
            .expect("established");
        assert!(pending(&mut budget, 3, &quic_local()));
    }

    #[test]
    fn a_slot_is_released_when_another_behaviour_denies_the_established_connection() {
        // Fields after a denying one never see the established hook; the
        // swarm then reports a listen failure to every behaviour.
        let mut budget = QuicPendingBudget::new(1);
        assert!(pending(&mut budget, 1, &quic_local()));
        fail(&mut budget, 1);
        assert!(pending(&mut budget, 2, &quic_local()));
    }

    #[test]
    fn a_slot_is_released_on_the_connection_established_event() {
        let mut budget = QuicPendingBudget::new(1);
        assert!(pending(&mut budget, 1, &quic_local()));
        let endpoint = ConnectedPoint::Listener {
            local_addr: quic_local(),
            send_back_addr: remote(),
        };
        budget.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
            peer_id: PeerId::random(),
            connection_id: id(1),
            endpoint: &endpoint,
            failed_addresses: &[],
            other_established: 0,
        }));
        assert!(pending(&mut budget, 2, &quic_local()));
    }

    #[test]
    fn releasing_a_slot_twice_frees_only_one() {
        let mut budget = QuicPendingBudget::new(2);
        assert!(pending(&mut budget, 1, &quic_local()));
        assert!(pending(&mut budget, 2, &quic_local()));
        fail(&mut budget, 1);
        fail(&mut budget, 1);
        assert!(pending(&mut budget, 3, &quic_local()));
        assert!(!pending(&mut budget, 4, &quic_local()), "one slot, not two");
    }

    #[test]
    fn a_denied_handshake_holds_no_slot() {
        let mut budget = QuicPendingBudget::new(1);
        assert!(pending(&mut budget, 1, &quic_local()));
        assert!(!pending(&mut budget, 2, &quic_local()));
        // The swarm reports the denial back as a listen failure.
        fail(&mut budget, 2);
        assert!(
            !pending(&mut budget, 3, &quic_local()),
            "slot 1 is still held"
        );
        fail(&mut budget, 1);
        assert!(pending(&mut budget, 4, &quic_local()));
    }
}
