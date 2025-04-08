// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use ant_evm::EvmNetwork;

pub use ant_bootstrap::{error::Error as BootstrapError, InitialPeersConfig};

/// Configuration for the [`crate::Client`] which can be provided through: [`crate::Client::init_with_config`].
#[derive(Debug, Clone, Default)]
pub struct ClientConfig {
    /// Configurations to fetch the initial peers which is used to bootstrap the network.
    /// Also contains the configurations to the bootstrap cache.
    pub init_peers_config: InitialPeersConfig,

    /// EVM network to use for quotations and payments.
    pub evm_network: EvmNetwork,
}
