// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub mod key;
pub mod user_data;

pub use key::{derive_vault_key, VaultSecretKey};
pub use user_data::UserData;

use crate::client::datatypes::scratchpad::{Scratchpad, ScratchpadError};
use crate::client::payment::PaymentOption;
use crate::client::quote::CostError;
use crate::client::{Client, PutError};
use ant_evm::AttoTokens;
use ant_networking::{GetRecordCfg, PutRecordCfg, VerificationKind};
use ant_protocol::storage::{try_serialize_record, DataTypes, RecordKind, RetryStrategy};
use ant_protocol::Bytes;
use libp2p::kad::{Quorum, Record};
use std::collections::HashSet;
use std::hash::{DefaultHasher, Hash, Hasher};
use tracing::info;

/// The content type of the vault data
/// The number is used to determine the type of the contents of the bytes contained in a vault
/// Custom apps can use this to store their own custom types of data in vaults
/// It is recommended to use the hash of the app name or an unique identifier as the content type using [`app_name_to_vault_content_type`]
/// The value 0 is reserved for tests
pub type VaultContentType = u64;

/// For custom apps using Scratchpad, this function converts an app identifier or name to a [`VaultContentType`]
pub fn app_name_to_vault_content_type<T: Hash>(s: T) -> VaultContentType {
    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    hasher.finish()
}

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("Vault error: {0}")]
    Scratchpad(#[from] ScratchpadError),
    #[error("Protocol: {0}")]
    Protocol(#[from] ant_protocol::Error),
}

impl Client {
    /// Retrieves and returns a decrypted vault if one exists.
    /// Returns the content type of the bytes in the vault
    pub async fn fetch_and_decrypt_vault(
        &self,
        secret_key: &VaultSecretKey,
    ) -> Result<(Bytes, VaultContentType), VaultError> {
        info!("Fetching and decrypting vault...");
        let pad = self.scratchpad_get(secret_key).await?;

        let data = pad.decrypt_data(secret_key)?;
        debug!("vault data is successfully fetched and decrypted");
        Ok((data, pad.data_encoding()))
    }

    /// Get the cost of creating a new vault
    pub async fn vault_cost(&self, owner: &VaultSecretKey) -> Result<AttoTokens, CostError> {
        info!("Getting cost for vault");
        self.scratchpad_cost(owner).await
    }

    /// Put data into the client's VaultPacket
    ///
    /// Pays for a new VaultPacket if none yet created for the client.
    /// Provide the bytes to be written to the vault and the content type of those bytes.
    /// It is recommended to use the hash of the app name or unique identifier as the content type.
    pub async fn write_bytes_to_vault(
        &self,
        data: Bytes,
        payment_option: PaymentOption,
        secret_key: &VaultSecretKey,
        content_type: VaultContentType,
    ) -> Result<AttoTokens, PutError> {
        let mut total_cost = AttoTokens::zero();

        let (mut scratch, is_new) = self
            .get_or_create_scratchpad(secret_key, content_type)
            .await?;

        let _ = scratch.update_and_sign(data, secret_key);
        debug_assert!(scratch.is_valid(), "Must be valid after being signed. This is a bug, please report it by opening an issue on our github");

        let scratch_address = scratch.network_address();
        let scratch_key = scratch_address.to_record_key();

        info!("Writing to vault at {scratch_address:?}",);

        let record = if is_new {
            let (receipt, _skipped_payments) = self
                .pay_for_content_addrs(
                    DataTypes::Scratchpad.get_index(),
                    std::iter::once((scratch.xorname(), scratch.payload_size())),
                    payment_option,
                )
                .await
                .inspect_err(|err| {
                    error!("Failed to pay for new vault at addr: {scratch_address:?} : {err}");
                })?;

            let (proof, price) = match receipt.values().next() {
                Some(proof) => proof,
                None => return Err(PutError::PaymentUnexpectedlyInvalid(scratch_address)),
            };

            total_cost = *price;

            Record {
                key: scratch_key,
                value: try_serialize_record(
                    &(proof, scratch),
                    RecordKind::DataWithPayment(DataTypes::Scratchpad),
                )
                .map_err(|_| {
                    PutError::Serialization(
                        "Failed to serialize scratchpad with payment".to_string(),
                    )
                })?
                .to_vec(),
                publisher: None,
                expires: None,
            }
        } else {
            Record {
                key: scratch_key,
                value: try_serialize_record(&scratch, RecordKind::DataOnly(DataTypes::Scratchpad))
                    .map_err(|_| {
                        PutError::Serialization("Failed to serialize scratchpad".to_string())
                    })?
                    .to_vec(),
                publisher: None,
                expires: None,
            }
        };

        let put_cfg = PutRecordCfg {
            put_quorum: Quorum::Majority,
            retry_strategy: Some(RetryStrategy::Balanced),
            use_put_record_to: None,
            verification: Some((
                VerificationKind::Crdt,
                GetRecordCfg {
                    get_quorum: Quorum::Majority,
                    retry_strategy: None,
                    target_record: None,
                    expected_holders: HashSet::new(),
                },
            )),
        };

        debug!("Put record - scratchpad at {scratch_address:?} to the network");
        self.network
            .put_record(record, &put_cfg)
            .await
            .inspect_err(|err| {
                error!(
                    "Failed to put scratchpad {scratch_address:?} to the network with err: {err:?}"
                )
            })?;

        Ok(total_cost)
    }

    /// Returns an existing scratchpad or creates a new one if it does not exist.
    pub async fn get_or_create_scratchpad(
        &self,
        secret_key: &VaultSecretKey,
        content_type: VaultContentType,
    ) -> Result<(Scratchpad, bool), PutError> {
        let client_pk = secret_key.public_key();

        let pad_res = self.scratchpad_get(secret_key).await;
        let mut is_new = true;

        let scratch = if let Ok(existing_data) = pad_res {
            info!("Scratchpad already exists, returning existing data");

            info!(
                "scratch already exists, is version {:?}",
                existing_data.count()
            );

            is_new = false;

            if existing_data.owner() != &client_pk {
                return Err(PutError::VaultBadOwner);
            }

            existing_data
        } else {
            trace!("new scratchpad creation");
            Scratchpad::new(client_pk, content_type)
        };

        Ok((scratch, is_new))
    }
}
