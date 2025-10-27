// Copyright 2025 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::Client;
use crate::networking::NetworkError;
use crate::networking::version::PackageVersion;
use ant_protocol::NetworkAddress;
use libp2p::kad::{PeerInfo, Record};

impl Client {
    /// Retrieve the closest peers to the given network address.
    pub async fn get_closest_to_address(
        &self,
        network_address: impl Into<NetworkAddress>,
    ) -> Result<Vec<PeerInfo>, NetworkError> {
        self.network
            .get_closest_peers_with_retries(network_address.into())
            .await
    }

    /// Get a record directly from a specific peer.
    /// Returns:
    /// - Some(Record) if the peer holds the record
    /// - None if the peer doesn't hold the record or the request fails
    pub async fn get_record_from_peer(
        &self,
        network_address: impl Into<NetworkAddress>,
        peer: PeerInfo,
    ) -> Result<Option<Record>, NetworkError> {
        self.network
            .get_record_from_peer(network_address.into(), peer)
            .await
    }

    pub async fn get_node_version(&self, peer: PeerInfo) -> Result<PackageVersion, String> {
        self.network.get_node_version(peer).await
    }
}
