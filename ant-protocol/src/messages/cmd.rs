// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
#![allow(clippy::mutable_key_type)] // for Bytes in NetworkAddress

use crate::storage::DataTypes;
use crate::{storage::ValidationType, NetworkAddress};
use ant_evm::ProofOfPayment;
use serde::{Deserialize, Serialize};

/// Ant protocol cmds
///
/// See the [`protocol`] module documentation for more details of the types supported by the Safe
/// Network, and their semantics.
///
/// [`protocol`]: crate
#[derive(Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum Cmd {
    /// Write operation to notify peer fetch a list of [`NetworkAddress`] from the holder.
    ///
    /// [`NetworkAddress`]: crate::NetworkAddress
    Replicate {
        /// Holder of the replication keys.
        holder: NetworkAddress,
        /// Keys of copy that shall be replicated.
        keys: Vec<(NetworkAddress, ValidationType)>,
    },
    /// Write operation to notify peer fetch a list of fresh [`NetworkAddress`] from the holder.
    ///
    /// [`NetworkAddress`]: crate::NetworkAddress
    FreshReplicate {
        /// Holder of the replication keys.
        holder: NetworkAddress,
        /// Keys of copy that shall be replicated.
        keys: Vec<(
            NetworkAddress,
            DataTypes,
            ValidationType,
            Option<ProofOfPayment>,
        )>,
    },
    /// Notify the peer it is now being considered as BAD due to the included behaviour
    PeerConsideredAsBad {
        detected_by: NetworkAddress,
        bad_peer: NetworkAddress,
        bad_behaviour: String,
    },
    /// Notify the peer to stop sending messages for a while.
    DoNotDisturb {
        /// The peer that should not be disturbed.
        peer: NetworkAddress,
        /// The duration in seconds for which the peer should not be disturbed.
        /// This will not be obeyed directly, but rather used to give some control if we require it.
        duration: u64,
    },
}

impl std::fmt::Debug for Cmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Cmd::Replicate { holder, keys } => {
                let first_ten_keys: Vec<_> = keys.iter().take(10).collect();
                f.debug_struct("Cmd::Replicate")
                    .field("holder", holder)
                    .field("keys_len", &keys.len())
                    .field("first_ten_keys", &first_ten_keys)
                    .finish()
            }
            Cmd::FreshReplicate { holder, keys } => {
                let first_ten_keys: Vec<_> = keys.iter().take(10).collect();
                f.debug_struct("Cmd::FreshReplicate")
                    .field("holder", holder)
                    .field("keys_len", &keys.len())
                    .field("first_ten_keys", &first_ten_keys)
                    .finish()
            }
            Cmd::PeerConsideredAsBad {
                detected_by,
                bad_peer,
                bad_behaviour,
            } => f
                .debug_struct("Cmd::PeerConsideredAsBad")
                .field("detected_by", detected_by)
                .field("bad_peer", bad_peer)
                .field("bad_behaviour", bad_behaviour)
                .finish(),
            Cmd::DoNotDisturb { peer, duration } => f
                .debug_struct("Cmd::DoNotDisturb")
                .field("peer", peer)
                .field("duration", duration)
                .finish(),
        }
    }
}

impl Cmd {
    /// Used to send a cmd to the close group of the address.
    pub fn dst(&self) -> NetworkAddress {
        match self {
            Cmd::Replicate { holder, .. } => holder.clone(),
            Cmd::FreshReplicate { holder, .. } => holder.clone(),
            Cmd::PeerConsideredAsBad { bad_peer, .. } => bad_peer.clone(),
            Cmd::DoNotDisturb { peer, .. } => peer.clone(),
        }
    }
}

impl std::fmt::Display for Cmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Cmd::Replicate { holder, keys } => {
                write!(
                    f,
                    "Cmd::Replicate({:?} has {} keys)",
                    holder.as_peer_id(),
                    keys.len()
                )
            }
            Cmd::FreshReplicate { holder, keys } => {
                write!(
                    f,
                    "Cmd::Replicate({:?} has {} keys)",
                    holder.as_peer_id(),
                    keys.len()
                )
            }
            Cmd::PeerConsideredAsBad {
                detected_by,
                bad_peer,
                bad_behaviour,
            } => {
                write!(
                    f,
                    "Cmd::PeerConsideredAsBad({detected_by:?} consider peer {bad_peer:?} as bad, due to {bad_behaviour:?})")
            }
            Cmd::DoNotDisturb { peer, duration } => {
                write!(
                    f,
                    "Cmd::DoNotDisturb({:?} for {duration} seconds)",
                    peer.as_peer_id()
                )
            }
        }
    }
}
