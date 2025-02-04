// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use ant_evm::EvmNetwork;
use ant_networking::{ResponseQuorum, RetryStrategy};
use libp2p::Multiaddr;

/// Configuration for [`crate::Client::init_with_config`].
///
/// Use [`ClientConfig::set_client_operation_config`] to set configure how the client performs operations
/// on the network.
#[derive(Debug, Clone, Default)]
pub struct ClientConfig {
    /// Whether we're expected to connect to a local network.
    pub local: bool,

    /// List of peers to connect to.
    ///
    /// If not provided, the client will use the default bootstrap peers.
    pub peers: Option<Vec<Multiaddr>>,

    /// EVM network to use for quotations and payments.
    pub evm_network: EvmNetwork,

    /// Configuration for operations on the client.
    ///
    /// This will be shared across all clones of the client and cannot be changed after initialization.
    pub operation_config: ClientOperationConfig,
}

/// Configurations for operations on the client.
///
/// Default values are used for each type of data, but you can override them here.
#[derive(Debug, Clone, Default)]
pub struct ClientOperationConfig {
    /// The retry strategy to use if we fail to store a piece of data. Every write will also verify that the data
    /// is stored on the network by fetching it back.
    ///
    /// Use the `verification_quorum` and `verification_retry_strategy` to configure the verification operation.
    pub(crate) write_retry_strategy: Option<RetryStrategy>,
    /// The number of records to wait for before considering the read after write operation successful.
    pub(crate) verification_quorum: Option<ResponseQuorum>,
    /// The retry strategy to use if the read after write operation fails.
    pub(crate) verification_retry_strategy: Option<RetryStrategy>,
    /// The number of records to wait for before considering the read operation successful.
    pub(crate) read_quorum: Option<ResponseQuorum>,
    /// The retry strategy to use if the read operation fails.
    pub(crate) read_retry_strategy: Option<RetryStrategy>,
}

impl ClientConfig {
    pub fn local(peers: Option<Vec<Multiaddr>>) -> Self {
        Self {
            local: true,
            peers,
            evm_network: EvmNetwork::new(true).unwrap_or_default(),
            operation_config: Default::default(),
        }
    }

    pub fn set_client_operation_config(&mut self, operation_config: ClientOperationConfig) {
        self.operation_config = operation_config;
    }
}

impl ClientOperationConfig {
    /// Set the retry strategy for the data write operations. Every write will also verify that the data
    /// is stored on the network by fetching it back.
    ///
    /// Use the `set_verification_quorum` and `set_verification_retry_strategy` to configure the verification
    /// operation.
    pub fn set_write_retry_strategy(&mut self, strategy: RetryStrategy) {
        self.write_retry_strategy = Some(strategy);
    }

    /// Set the quorum for the data verification operations. This is the number of records to wait for before
    /// considering the read after write operation successful.
    pub fn set_verification_quorum(&mut self, quorum: ResponseQuorum) {
        self.verification_quorum = Some(quorum);
    }

    /// Set the retry strategy for the data verification operation. This is the retry strategy to use if the read
    /// after write operation fails.
    pub fn set_verification_retry_strategy(&mut self, strategy: RetryStrategy) {
        self.verification_retry_strategy = Some(strategy);
    }

    /// Set the quorum for the set read operations. This is the number of records to wait for before considering
    /// the read operation successful.
    pub fn set_read_quorum(&mut self, quorum: ResponseQuorum) {
        self.read_quorum = Some(quorum);
    }

    /// Set the retry strategy for the data read operation. This is the retry strategy to use if the read
    /// operation fails.
    pub fn set_read_retry_strategy(&mut self, strategy: RetryStrategy) {
        self.read_retry_strategy = Some(strategy);
    }
}
