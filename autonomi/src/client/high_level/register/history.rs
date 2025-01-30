// Copyright 2025 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use ant_networking::{GetRecordError, NetworkError};

use crate::client::data_types::graph::{GraphEntryAddress, GraphError};
use crate::client::high_level::register::{
    PublicKey, RegisterAddress, RegisterError, RegisterValue,
};
use crate::client::key_derivation::MainPubkey;
use crate::client::Client;

/// A handle to the register history
pub struct RegisterHistory {
    client: Client,
    register_owner: PublicKey,
    current: GraphEntryAddress,
}

impl RegisterHistory {
    fn new(client: Client, register_owner: PublicKey, root: GraphEntryAddress) -> Self {
        Self {
            client,
            register_owner,
            current: root,
        }
    }

    /// Fetch and go to the next register value from the history
    /// Returns `Ok(None)` when we reached the end
    pub async fn next(&mut self) -> Result<Option<RegisterValue>, RegisterError> {
        let (entry, next_derivation) = match self
            .client
            .register_get_graph_entry_and_next_derivation_index(&self.current)
            .await
        {
            Ok(res) => res,
            Err(RegisterError::GraphError(GraphError::Network(NetworkError::GetRecordError(
                GetRecordError::RecordNotFound,
            )))) => return Ok(None),
            Err(e) => return Err(e),
        };
        let next_entry_pk: PublicKey = MainPubkey::from(self.register_owner)
            .derive_key(&next_derivation)
            .into();
        self.current = GraphEntryAddress::from_owner(next_entry_pk);
        Ok(Some(entry.content))
    }

    /// Get all the register values from the history
    pub async fn collect(&mut self) -> Result<Vec<RegisterValue>, RegisterError> {
        let mut values = Vec::new();
        while let Some(value) = self.next().await? {
            values.push(value);
        }
        Ok(values)
    }
}

impl Client {
    /// Get the register history, starting from the root to the latest entry
    /// This returns a [`RegisterHistory`] that can be use to get the register values from the history
    /// [`RegisterHistory::next`] can be used to get the values one by one
    /// [`RegisterHistory::collect`] can be used to get all the register values from the history
    pub fn register_history(&self, addr: &RegisterAddress) -> RegisterHistory {
        let graph_entry_addr = addr.to_underlying_graph_root();
        RegisterHistory::new(self.clone(), addr.owner, graph_entry_addr)
    }
}
