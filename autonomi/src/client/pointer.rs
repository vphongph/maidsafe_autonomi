// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::client::data::PayError;
use crate::client::Client;
use crate::client::ClientEvent;
use crate::client::UploadSummary;

use ant_evm::Amount;
use ant_evm::AttoTokens;
pub use ant_protocol::storage::{Pointer, PointerAddress, PointerTarget};
use bls::SecretKey;

use ant_evm::{EvmWallet, EvmWalletError};
use ant_networking::{GetRecordCfg, NetworkError, PutRecordCfg, VerificationKind};
use ant_protocol::{
    storage::{try_serialize_record, RecordKind, RetryStrategy},
    NetworkAddress,
};
use libp2p::kad::{Quorum, Record};

use super::data::CostError;

#[derive(Debug, thiserror::Error)]
pub enum PointerError {
    #[error("Cost error: {0}")]
    Cost(#[from] CostError),
    #[error("Network error")]
    Network(#[from] NetworkError),
    #[error("Serialization error")]
    Serialization,
    #[error("Pointer could not be verified (corrupt)")]
    FailedVerification,
    #[error("Payment failure occurred during pointer creation.")]
    Pay(#[from] PayError),
    #[error("Failed to retrieve wallet payment")]
    Wallet(#[from] EvmWalletError),
    #[error("Received invalid quote from node, this node is possibly malfunctioning, try another node by trying another pointer name")]
    InvalidQuote,
    #[error("Pointer already exists at this address: {0:?}")]
    PointerAlreadyExists(PointerAddress),
}

impl Client {
    /// Fetches a Pointer from the network.
    pub async fn pointer_get(
        &self,
        address: PointerAddress,
    ) -> Result<Pointer, PointerError> {
        let pointer = self.network.get_pointer(address).await?;
        Ok(pointer)
    }

    /// Stores a Pointer on the network with payment handling
    pub async fn pointer_put(
        &self,
        pointer: Pointer,
        wallet: &EvmWallet,
    ) -> Result<(), PointerError> {
        let address = pointer.network_address();

        // pay for the pointer storage
        let xor_name = address.0;
        debug!("Paying for pointer at address: {address:?}");
        let payment_proofs = self
            .pay(std::iter::once(xor_name), wallet)
            .await
            .inspect_err(|err| {
                error!("Failed to pay for pointer at address: {address:?} : {err}")
            })?;

        // verify payment was successful
        let (proof, price) = match payment_proofs.get(&xor_name) {
            Some((proof, price)) => (proof, price),
            None => {
                error!("Pointer at address: {address:?} was already paid for");
                return Err(PointerError::PointerAlreadyExists(address));
            }
        };

        // prepare the record for network storage
        let payees = proof.payees();
        let record = Record {
            key: NetworkAddress::from_pointer_address(address).to_record_key(),
            value: try_serialize_record(&(proof, &pointer), RecordKind::PointerWithPayment)
                .map_err(|_| PointerError::Serialization)?
                .to_vec(),
            publisher: None,
            expires: None,
        };

        let get_cfg = GetRecordCfg {
            get_quorum: Quorum::Majority,
            retry_strategy: Some(RetryStrategy::default()),
            target_record: None,
        };

        let put_cfg = PutRecordCfg {
            put_quorum: Quorum::Majority,
            retry_strategy: Some(RetryStrategy::default()),
            verification_kind: VerificationKind::Signature,
        };

        // store the pointer on the network
        self.network
            .put_record(record, put_cfg, get_cfg, payees)
            .await?;

        Ok(())
    }

    /// Calculate the cost of storing a pointer
    pub async fn pointer_cost(&self, key: SecretKey) -> Result<AttoTokens, PointerError> {
        let cost = self.network.get_storage_cost(key).await?;
        Ok(cost)
    }
}
