// Copyright 2025 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{client::quote::CostError, Client};
use ant_evm::{Amount, AttoTokens};
use ant_networking::{GetRecordCfg, GetRecordError, NetworkError};
use ant_protocol::{
    storage::{try_deserialize_record, DataTypes, ScratchpadAddress},
    NetworkAddress,
};
use bls::SecretKey;
use libp2p::kad::Quorum;
use std::collections::HashSet;

pub use ant_protocol::storage::Scratchpad;

#[derive(Debug, thiserror::Error)]
pub enum ScratchpadError {
    #[error("Scratchpad found at {0:?} was not a valid record.")]
    CouldNotDeserializeScratchPad(ScratchpadAddress),
    #[error("Network: {0}")]
    Network(#[from] NetworkError),
    #[error("Scratchpad not found")]
    Missing,
}

impl Client {
    /// Get Scratchpad from the Network
    /// It is stored at the owner's public key
    pub async fn scratchpad_get(
        &self,
        secret_key: &SecretKey,
    ) -> Result<Scratchpad, ScratchpadError> {
        let client_pk = secret_key.public_key();

        let scratch_address = ScratchpadAddress::new(client_pk);
        let network_address = NetworkAddress::from_scratchpad_address(scratch_address);
        info!("Fetching vault from network at {network_address:?}",);
        let scratch_key = network_address.to_record_key();

        let get_cfg = GetRecordCfg {
            get_quorum: Quorum::Majority,
            retry_strategy: None,
            target_record: None,
            expected_holders: HashSet::new(),
        };

        let pad = match self
            .network
            .get_record_from_network(scratch_key.clone(), &get_cfg)
            .await
        {
            Ok(record) => {
                debug!("Got scratchpad for {scratch_key:?}");
                try_deserialize_record::<Scratchpad>(&record)
                    .map_err(|_| ScratchpadError::CouldNotDeserializeScratchPad(scratch_address))?
            }
            Err(NetworkError::GetRecordError(GetRecordError::SplitRecord { result_map })) => {
                debug!("Got multiple scratchpads for {scratch_key:?}");
                let mut pads = result_map
                    .values()
                    .map(|(record, _)| try_deserialize_record::<Scratchpad>(record))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| ScratchpadError::CouldNotDeserializeScratchPad(scratch_address))?;

                // take the latest versions
                pads.sort_by_key(|s| s.count());
                let max_version = pads.last().map(|p| p.count()).unwrap_or_else(|| {
                    error!("Got empty scratchpad vector for {scratch_key:?}");
                    u64::MAX
                });
                let latest_pads: Vec<_> = pads
                    .into_iter()
                    .filter(|s| s.count() == max_version)
                    .collect();

                // make sure we only have one of latest version
                let pad = match &latest_pads[..] {
                    [one] => one,
                    [multi, ..] => {
                        error!("Got multiple conflicting scratchpads for {scratch_key:?} with the latest version, returning the first one");
                        multi
                    }
                    [] => {
                        error!("Got empty scratchpad vector for {scratch_key:?}");
                        return Err(ScratchpadError::Missing);
                    }
                };
                pad.to_owned()
            }
            Err(e) => {
                warn!("Failed to fetch vault {network_address:?} from network: {e}");
                return Err(e)?;
            }
        };

        Ok(pad)
    }

    /// Get the cost of creating a new Scratchpad
    pub async fn scratchpad_cost(&self, owner: &SecretKey) -> Result<AttoTokens, CostError> {
        info!("Getting cost for scratchpad");
        let client_pk = owner.public_key();
        let content_type = Default::default();
        let scratch = Scratchpad::new(client_pk, content_type);
        let vault_xor = scratch.address().xorname();

        // TODO: define default size of Scratchpad
        let store_quote = self
            .get_store_quotes(
                DataTypes::Scratchpad.get_index(),
                std::iter::once((vault_xor, 256)),
            )
            .await?;

        let total_cost = AttoTokens::from_atto(
            store_quote
                .0
                .values()
                .map(|quote| quote.price())
                .sum::<Amount>(),
        );

        Ok(total_cost)
    }
}
