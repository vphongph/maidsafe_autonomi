// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#![allow(dead_code)]

use libp2p::{
    core::{transport::PortUse, Endpoint, Multiaddr},
    identity::PeerId,
    swarm::{
        dummy, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler,
        THandlerInEvent, THandlerOutEvent, ToSwarm,
    },
};
use std::{
    collections::HashMap,
    convert::Infallible,
    fmt,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;

pub const MAX_DO_NOT_DISTURB_DURATION: u64 = 5 * 60; // 5 minutes

/// A [`NetworkBehaviour`] that blocks outgoing connections to specific peers for a specified duration.
///
/// This behavior maintains a list of "blocked" peers with expiration times. When an outgoing
/// connection is attempted to a blocked peer, the connection is denied with a [`DoNotDisturbError`] error.
/// Blocked peers are automatically unblocked when their timer expires.
///
/// Only **outgoing** connections are blocked - incoming connections from blocked peers are still allowed.
///
/// # Example
///
/// ```rust,ignore
/// use std::time::Duration;
/// use libp2p_identity::PeerId;
/// use ant_networking::behaviour::do_not_disturb;
///
/// let mut behaviour = do_not_disturb::Behaviour::default();
/// let peer_id = PeerId::random();
///
/// // Block peer for 30 seconds
/// behaviour.block_peer(peer_id, Duration::from_secs(30));
///
/// // Check if peer is blocked
/// assert!(behaviour.is_blocked(&peer_id));
///
/// // Manually unblock if needed
/// behaviour.unblock_peer(&peer_id);
/// assert!(!behaviour.is_blocked(&peer_id));
/// ```
#[derive(Debug, Clone, Default)]
pub struct Behaviour {
    /// Map of blocked peers to their unblock time
    blocked_peers: HashMap<PeerId, Instant>,
}

impl Behaviour {
    /// Block outgoing connections to the specified peer for the given duration.
    ///
    /// The duration is capped at [`MAX_DO_NOT_DISTURB_DURATION`] seconds.
    /// If the peer is already blocked, this will update the block expiration time.
    pub fn block_peer(&mut self, peer_id: PeerId, duration: Duration) {
        let original_duration = duration.as_secs();
        let capped_duration =
            Duration::from_secs(duration.as_secs().min(MAX_DO_NOT_DISTURB_DURATION));
        let unblock_time = Instant::now() + capped_duration;

        let was_already_blocked = self.blocked_peers.contains_key(&peer_id);
        self.blocked_peers.insert(peer_id, unblock_time);

        if was_already_blocked {
            info!(
                "Updated block duration for peer {peer_id:?} to {duration_secs}s (was already blocked)",
                duration_secs = capped_duration.as_secs()
            );
        } else {
            info!(
                "Blocked peer {peer_id:?} from outgoing connections for {duration_secs}s. Total blocked peers: {total_blocked_peers}",
                duration_secs = capped_duration.as_secs(),
                total_blocked_peers = self.blocked_peers.len()
            );
        }

        if original_duration > MAX_DO_NOT_DISTURB_DURATION {
            warn!(
                "Block duration for peer {peer_id:?} was capped from {requested_duration}s to {capped_duration}s (maximum allowed)",
                requested_duration = original_duration,
                capped_duration = MAX_DO_NOT_DISTURB_DURATION
            );
        }
    }

    /// Remove the peer from the blocked list, allowing outgoing connections immediately.
    pub fn unblock_peer(&mut self, peer_id: &PeerId) {
        let was_blocked = self.blocked_peers.remove(peer_id).is_some();

        if was_blocked {
            info!(
                "Manually unblocked peer {peer_id:?}, allowing outgoing connections. Remaining blocked peers: {remaining_blocked_peers}",
                remaining_blocked_peers = self.blocked_peers.len()
            );
        } else {
            debug!("Attempted to unblock peer {peer_id:?} that wasn't blocked");
        }
    }

    /// Check if outgoing connections to this peer are currently blocked.
    pub fn is_blocked(&mut self, peer_id: &PeerId) -> bool {
        // Clean up expired entries first
        self.cleanup_expired();
        self.blocked_peers.contains_key(peer_id)
    }

    /// Remove expired blocks from the blocked peers list.
    /// Called automatically in the `poll` method.
    fn cleanup_expired(&mut self) {
        let now = Instant::now();

        let mut expired_peers = Vec::new();
        self.blocked_peers.retain(|peer_id, unblock_time| {
            if now >= *unblock_time {
                expired_peers.push(*peer_id);
                false
            } else {
                true
            }
        });

        let cleaned_count = expired_peers.len();
        if cleaned_count > 0 {
            debug!(
                "Cleaned up {cleaned_count} expired peer blocks. Remaining blocked: {remaining_blocked}. Expired peers: {expired_peers:?}",
                remaining_blocked = self.blocked_peers.len()
            );
        }
    }
}

/// Error indicating that a peer is currently blocked from outgoing connections.
#[derive(Debug, Clone)]
pub struct DoNotDisturbError {
    pub peer_id: PeerId,
    pub remaining_duration: Duration,
}

impl fmt::Display for DoNotDisturbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "peer {} is blocked for {} more seconds",
            self.peer_id,
            self.remaining_duration.as_secs()
        )
    }
}

impl std::error::Error for DoNotDisturbError {}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;

    fn handle_pending_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        addresses: &[Multiaddr],
        _effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        if let Some(peer_id) = maybe_peer {
            if let Some(unblock_time) = self.blocked_peers.get(&peer_id) {
                let now = Instant::now();
                if now < *unblock_time {
                    let remaining_duration = *unblock_time - now;

                    warn!(
                        "Blocked outgoing connection attempt to do-not-disturb peer {peer_id:?} (connection {connection_id:?}). Remaining: {remaining_secs}s. Total blocked peers: {total_blocked_peers}. Addresses: {addresses_count}",
                        remaining_secs = remaining_duration.as_secs(),
                        total_blocked_peers = self.blocked_peers.len(),
                        addresses_count = addresses.len()
                    );

                    let error = DoNotDisturbError {
                        peer_id,
                        remaining_duration,
                    };
                    return Err(ConnectionDenied::new(error));
                } else {
                    // This peer was expired but cleanup hasn't run yet
                    debug!(
                        "Peer {peer_id:?} block has expired, allowing connection {connection_id:?} and triggering cleanup"
                    );
                    self.cleanup_expired();
                }
            }
        } else {
            trace!(
                "Allowing outbound connection {connection_id:?} with no specific peer ID. Addresses: {addresses_count}",
                addresses_count = addresses.len()
            );
        }
        Ok(vec![])
    }

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
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

    fn on_swarm_event(&mut self, _event: FromSwarm) {
        // No specific handling needed for swarm events
    }

    fn on_connection_handler_event(
        &mut self,
        _peer_id: PeerId,
        _connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        libp2p::core::util::unreachable(event)
    }

    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        // Clean up expired blocks
        self.cleanup_expired();
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::swarm::{
        dial_opts::{DialOpts, PeerCondition},
        DialError, Swarm,
    };
    use libp2p_swarm_test::SwarmExt;
    use std::time::Duration;
    use tokio::time;

    #[test]
    fn test_block_and_unblock_peer() {
        let mut behaviour = Behaviour::default();
        let peer_id = PeerId::random();

        // Initially not blocked
        assert!(!behaviour.is_blocked(&peer_id));

        // Block peer
        behaviour.block_peer(peer_id, Duration::from_secs(10));
        assert!(behaviour.is_blocked(&peer_id));

        // Unblock peer
        behaviour.unblock_peer(&peer_id);
        assert!(!behaviour.is_blocked(&peer_id));
    }

    #[test]
    fn test_duration_capping() {
        let mut behaviour = Behaviour::default();
        let peer_id = PeerId::random();

        // Block peer for more than max duration
        let excessive_duration = Duration::from_secs(MAX_DO_NOT_DISTURB_DURATION + 100);
        behaviour.block_peer(peer_id, excessive_duration);

        // Should be blocked but not for longer than max duration
        assert!(behaviour.is_blocked(&peer_id));

        // Check that the duration was capped by inspecting the unblock time
        let unblock_time = behaviour.blocked_peers.get(&peer_id).unwrap();

        // Allow for some tolerance in timing - ensure duration doesn't exceed max
        assert!(
            unblock_time.duration_since(Instant::now()).as_secs() <= MAX_DO_NOT_DISTURB_DURATION
        );
    }

    #[test]
    fn test_update_block_duration() {
        let mut behaviour = Behaviour::default();
        let peer_id = PeerId::random();

        // Block peer for short duration
        behaviour.block_peer(peer_id, Duration::from_secs(1));
        let first_unblock_time = *behaviour.blocked_peers.get(&peer_id).unwrap();

        // Update with longer duration
        behaviour.block_peer(peer_id, Duration::from_secs(10));
        let second_unblock_time = *behaviour.blocked_peers.get(&peer_id).unwrap();

        assert!(second_unblock_time > first_unblock_time);
    }

    #[tokio::test]
    async fn test_expired_blocks_cleanup() {
        let mut behaviour = Behaviour::default();
        let peer_id = PeerId::random();

        // Block peer for very short duration
        behaviour.block_peer(peer_id, Duration::from_millis(50));

        // Verify peer is initially in the raw map
        assert!(behaviour.blocked_peers.contains_key(&peer_id));

        // Wait for expiration
        time::sleep(Duration::from_millis(100)).await;

        // Manually call cleanup to remove expired entries
        behaviour.cleanup_expired();

        // Verify peer was removed from blocked_peers map
        assert!(!behaviour.blocked_peers.contains_key(&peer_id));

        // And verify is_blocked returns false
        assert!(!behaviour.is_blocked(&peer_id));
    }

    #[tokio::test]
    async fn test_connection_denial() {
        let mut swarm1 = Swarm::new_ephemeral_tokio(|_| Behaviour::default());
        let swarm2 = Swarm::new_ephemeral_tokio(|_| Behaviour::default());

        let peer2_id = *swarm2.local_peer_id();
        let (listen_addr, _) = swarm1.listen().with_memory_addr_external().await;

        // Block peer2 on swarm1
        swarm1
            .behaviour_mut()
            .block_peer(peer2_id, Duration::from_secs(60));

        // Try to dial from swarm1 to swarm2 (should be blocked)
        match swarm1.dial(
            DialOpts::peer_id(peer2_id)
                .condition(PeerCondition::Always)
                .addresses(vec![listen_addr.clone()])
                .build(),
        ) {
            Err(DialError::Denied { cause }) => {
                let peer_blocked = cause
                    .downcast::<DoNotDisturbError>()
                    .expect("Expected DoNotDisturbError error");

                assert_eq!(peer_blocked.peer_id, peer2_id);
                assert!(peer_blocked.remaining_duration.as_secs() > 0);
            }
            Ok(_) => panic!("Expected connection to be denied"),
            Err(e) => panic!("Unexpected error: {e:?}"),
        }

        // Unblock and try again (should succeed in attempting to dial)
        swarm1.behaviour_mut().unblock_peer(&peer2_id);

        // Verify peer is no longer blocked
        assert!(!swarm1.behaviour_mut().is_blocked(&peer2_id));

        // The dial attempt should now succeed (not be denied by our behavior)
        // Note: It may still fail due to network reasons, but not due to our blocking behavior
        let dial_result = swarm1.dial(
            DialOpts::peer_id(peer2_id)
                .addresses(vec![listen_addr])
                .build(),
        );

        // The important thing is that it's not denied by our behavior
        match dial_result {
            Ok(_) => {} // This is what we expect
            Err(DialError::Denied { cause }) => {
                // Check if it was denied by our behavior
                if cause.downcast::<DoNotDisturbError>().is_ok() {
                    panic!("Connection should not be blocked after unblocking peer");
                }
                // If it was denied by something else, that's okay for this test
            }
            Err(_) => {} // Other errors are fine for this test
        }
    }

    #[tokio::test]
    async fn test_incoming_connections_not_blocked() {
        let mut swarm1 = Swarm::new_ephemeral_tokio(|_| Behaviour::default());
        let mut swarm2 = Swarm::new_ephemeral_tokio(|_| Behaviour::default());

        let peer1_id = *swarm1.local_peer_id();
        let (listen_addr, _) = swarm1.listen().with_memory_addr_external().await;

        // Block peer1 on swarm2 (this should NOT affect incoming connections to swarm1)
        swarm2
            .behaviour_mut()
            .block_peer(peer1_id, Duration::from_secs(60));

        // swarm2 should still be able to connect TO swarm1 (incoming connection to swarm1)
        // This tests that only outgoing connections are blocked
        tokio::spawn(swarm1.loop_on_next());

        let connection_result = swarm2.dial(listen_addr);
        assert!(
            connection_result.is_ok(),
            "Incoming connections should not be blocked"
        );
    }

    #[test]
    fn test_peer_blocked_error_display() {
        let peer_id = PeerId::random();
        let error = DoNotDisturbError {
            peer_id,
            remaining_duration: Duration::from_secs(30),
        };

        let error_string = format!("{error}",);
        assert!(error_string.contains(&peer_id.to_string()));
        assert!(error_string.contains("30"));
        assert!(error_string.contains("blocked"));
    }

    #[tokio::test]
    async fn test_automatic_cleanup_in_poll() {
        let mut behaviour = Behaviour::default();
        let peer_id = PeerId::random();

        // Block peer for very short duration
        behaviour.block_peer(peer_id, Duration::from_millis(50));
        assert_eq!(behaviour.blocked_peers.len(), 1);

        // Wait for expiration
        time::sleep(Duration::from_millis(100)).await;

        // Simulate poll being called (this happens automatically in real usage)
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        let _ = behaviour.poll(&mut cx);

        // Expired peer should be cleaned up
        assert_eq!(behaviour.blocked_peers.len(), 0);
    }

    #[test]
    fn test_zero_duration_block() {
        let mut behaviour = Behaviour::default();
        let peer_id = PeerId::random();

        // Block peer for zero duration - should be immediately expired
        behaviour.block_peer(peer_id, Duration::ZERO);

        // Should not be blocked since duration is zero
        assert!(!behaviour.is_blocked(&peer_id));
    }

    #[test]
    fn test_rapid_block_unblock_operations() {
        let mut behaviour = Behaviour::default();
        let peer_id = PeerId::random();

        // Rapid block/unblock operations
        for i in 0..10 {
            behaviour.block_peer(peer_id, Duration::from_secs(i + 1));
            assert!(behaviour.is_blocked(&peer_id));

            if i % 2 == 0 {
                behaviour.unblock_peer(&peer_id);
                assert!(!behaviour.is_blocked(&peer_id));
                behaviour.block_peer(peer_id, Duration::from_secs(i + 1));
            }
        }

        // Should still be blocked after all operations
        assert!(behaviour.is_blocked(&peer_id));
    }

    #[test]
    fn test_blocking_self_peer() {
        let mut behaviour = Behaviour::default();
        let self_peer_id = PeerId::random(); // Simulating self peer

        // Block self - this should work (no special handling for self)
        behaviour.block_peer(self_peer_id, Duration::from_secs(30));
        assert!(behaviour.is_blocked(&self_peer_id));

        // Can unblock self
        behaviour.unblock_peer(&self_peer_id);
        assert!(!behaviour.is_blocked(&self_peer_id));
    }

    #[test]
    fn test_handle_pending_outbound_connection_none_peer() {
        let mut behaviour = Behaviour::default();

        // Test with None peer (should always allow)
        let result = behaviour.handle_pending_outbound_connection(
            ConnectionId::new_unchecked(1),
            None, // No specific peer
            &[],
            Endpoint::Dialer,
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![]);
    }

    #[test]
    fn test_error_remaining_duration_accuracy() {
        let mut behaviour = Behaviour::default();
        let peer_id = PeerId::random();

        // Block peer for exactly 5 seconds
        behaviour.block_peer(peer_id, Duration::from_secs(5));

        // Immediately try to connect (should be blocked)
        let result = behaviour.handle_pending_outbound_connection(
            ConnectionId::new_unchecked(1),
            Some(peer_id),
            &[],
            Endpoint::Dialer,
        );

        assert!(result.is_err());

        if let Err(connection_denied) = result {
            let error = connection_denied
                .downcast::<DoNotDisturbError>()
                .expect("Expected DoNotDisturbError");

            // Remaining duration should be close to 5 seconds (allow for small timing differences)
            assert!(error.remaining_duration.as_secs() <= 5);
            assert!(error.remaining_duration.as_secs() >= 4);
            assert_eq!(error.peer_id, peer_id);
        }
    }

    #[tokio::test]
    async fn test_concurrent_cleanup_and_blocking() {
        let mut behaviour = Behaviour::default();
        let peer_id = PeerId::random();

        // Block peer for short duration
        behaviour.block_peer(peer_id, Duration::from_millis(50));

        // Verify it's in the map before cleanup
        assert!(behaviour.blocked_peers.contains_key(&peer_id));

        // Wait for expiration
        time::sleep(Duration::from_millis(100)).await;

        // Multiple rapid cleanup calls should handle this properly
        for _ in 0..10 {
            behaviour.cleanup_expired();
        }

        // Verify cleanup worked
        assert!(!behaviour.blocked_peers.contains_key(&peer_id));
    }
}
