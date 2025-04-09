// Copyright 2025 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// all modules are private to this networking module
mod driver;
mod interface;
mod utils;

// export the utils
pub(crate) use utils::multiaddr_is_global;

// re-export the types our API exposes to avoid dependency version conflicts
pub use ant_evm::PaymentQuote;
pub use ant_protocol::NetworkAddress;
pub use libp2p::kad::PeerInfo;
pub use libp2p::{
    kad::{Quorum, Record},
    Multiaddr, PeerId,
};

// internal needs
use driver::NetworkDriver;
use interface::NetworkTask;
use futures::future::try_join_all;
use libp2p::futures;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use std::collections::HashMap;
use std::num::NonZeroUsize;

/// Result type for tasks responses sent by the [`crate::driver::NetworkDriver`] to the [`crate::Network`]
pub(in crate::networking) type OneShotTaskResult<T> = oneshot::Sender<Result<T, NetworkError>>;

/// Errors that can occur when interacting with the [`crate::Network`]
#[derive(Error, Debug)]
pub enum NetworkError {
    /// The network driver is offline, better restart the client
    #[error("Failed to send task to network driver")]
    NetworkDriverOffline,
    /// Failed to receive task from network driver, better restart the client
    #[error("Failed to receive task from network driver: {0}")]
    NetworkDriverReceive(#[from] tokio::sync::oneshot::error::RecvError),

    /// Error getting closest peers
    #[error("Failed to get closest peers: {0}")]
    ClosestPeersError(String),

    /// Error putting record
    #[error("Failed to put record: {0}")]
    PutRecordError(String),
    #[error(
        "Put record quorum failed, only the following peers stored the record: {0:?}, needed {1} peers"
    )]
    PutRecordQuorumFailed(Vec<PeerId>, NonZeroUsize),
    #[error("Put record timeout, only the following peers stored the record: {0:?}")]
    PutRecordTimeout(Vec<PeerId>),

    /// Error getting quote
    #[error("Failed to get quote: {0}")]
    GetQuoteError(String),
    #[error("Invalid quote: {0}")]
    InvalidQuote(String),

    /// Error getting record
    #[error("Peers have conflicting entries for this record: {0:?}")]
    SplitRecord(HashMap<PeerId, Record>),
    #[error("Get record timed out, peers found holding the record at timeout: {0:?}")]
    GetRecordTimeout(Vec<PeerId>),
}

/// The Client interface to the Autonomi Network
#[derive(Debug, Clone)]
pub struct Network {
    task_sender: tokio::sync::mpsc::Sender<NetworkTask>,
}

impl Network {
    /// Create a new network client
    /// This will start the network driver in a background thread, which is a long running task that runs until the [`Network`] is dropped
    /// The [`Network`] is cheaply cloneable, prefer cloning over creating new instances to avoid creating multiple network drivers
    pub fn new(initial_contacts: Vec<Multiaddr>) -> Self {
        let (task_sender, task_receiver) = mpsc::channel(100);
        let driver = NetworkDriver::new(task_receiver);
        let network = Self { task_sender };

        // run the network driver in a background task
        tokio::spawn(async move {
            driver.run(initial_contacts).await;
        });

        network
    }

    /// Get a record from the network
    /// Returns the record if successful
    /// If the record is not found, the result will be None
    pub async fn get_record(
        &self,
        addr: NetworkAddress,
        quorum: Quorum,
    ) -> Result<Option<Record>, NetworkError> {
        let (record, _holders) = self.get_record_and_holders(addr, quorum).await?;
        Ok(record)
    }

    /// Get a record from the network
    /// Returns the record if successful along with the peers that handed it to us
    /// If the record is not found, the result will be None and an empty list of peers
    /// If the Quorum is not met, the result will be None and the list of peers that did manage to deliver the record
    /// As soon as the quorum is met, the request will complete and the result will be returned.
    /// Note that the holders returned is not an exhaustive list of all holders of the record,
    /// it only contains the peers that responded to the request before the quorum was met.
    pub async fn get_record_and_holders(
        &self,
        addr: NetworkAddress,
        quorum: Quorum,
    ) -> Result<(Option<Record>, Vec<PeerId>), NetworkError> {
        let (tx, rx) = oneshot::channel();
        let task = NetworkTask::GetRecord {
            addr,
            quorum,
            resp: tx,
        };
        self.task_sender
            .send(task)
            .await
            .map_err(|_| NetworkError::NetworkDriverOffline)?;
        rx.await?
    }

    /// Put a record to the network
    /// When the `to` field is empty, the record is stored at the closest nodes to the record address,
    /// else it is specifically stored to the nodes in the `to` field
    pub async fn put_record(
        &self,
        record: Record,
        to: Vec<PeerId>,
        quorum: Quorum,
    ) -> Result<(), NetworkError> {
        let (tx, rx) = oneshot::channel();
        let task = NetworkTask::PutRecord {
            record,
            to,
            quorum,
            resp: tx,
        };
        self.task_sender
            .send(task)
            .await
            .map_err(|_| NetworkError::NetworkDriverOffline)?;
        rx.await?
    }

    /// Get the closest peers to an address on the Network
    pub async fn get_closest_peers(
        &self,
        addr: NetworkAddress,
    ) -> Result<Vec<PeerInfo>, NetworkError> {
        let (tx, rx) = oneshot::channel();
        let task = NetworkTask::GetClosestPeers { addr, resp: tx };
        self.task_sender
            .send(task)
            .await
            .map_err(|_| NetworkError::NetworkDriverOffline)?;
        rx.await?
    }

    /// Get a quote for a record from a Peer on the Network
    pub async fn get_quote(
        &self,
        addr: NetworkAddress,
        peer: PeerId,
        data_type: u32,
        data_size: usize,
    ) -> Result<PaymentQuote, NetworkError> {
        let (tx, rx) = oneshot::channel();
        let task = NetworkTask::GetQuote {
            addr,
            peer,
            data_type,
            data_size,
            resp: tx,
        };
        self.task_sender
            .send(task)
            .await
            .map_err(|_| NetworkError::NetworkDriverOffline)?;
        rx.await?
    }

    /// Get the quotes for a Record from the closest Peers to that address on the Network
    pub async fn get_quotes(
        &self,
        addr: NetworkAddress,
        data_type: u32,
        data_size: usize,
    ) -> Result<Vec<PaymentQuote>, NetworkError> {
        let closest_peers = self.get_closest_peers(addr.clone()).await?;
        let tasks: Vec<_> = closest_peers
            .iter()
            .map(|peer| self.get_quote(addr.clone(), peer.peer_id, data_type, data_size))
            .collect();
        let quotes = try_join_all(tasks).await?;
        Ok(quotes)
    }
}
