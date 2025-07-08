// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{NetworkAddress, PrettyPrintRecordKey};
use libp2p::kad::store;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A specialised `Result` type for protocol crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Main error types for the SAFE protocol.
#[derive(Error, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Error {
    // ---------- Chunk Proof errors
    #[error("Chunk does not exist {0:?}")]
    ChunkDoesNotExist(NetworkAddress),

    // ---------- Scratchpad errors
    /// The provided SecretyKey failed to decrypt the data
    #[error("Failed to derive CipherText from encrypted_data")]
    ScratchpadCipherTextFailed,
    /// The provided cypher text is invalid
    #[error("Provided cypher text is invalid")]
    ScratchpadCipherTextInvalid,

    // ---------- payment errors
    #[error("There was an error getting the storecost from kademlia store")]
    GetStoreQuoteFailed,
    #[error("There was an error generating the payment quote")]
    QuoteGenerationFailed,

    // ---------- replication errors
    /// Replication not found.
    #[error("Peer {holder:?} cannot find Record {key:?}")]
    ReplicatedRecordNotFound {
        /// Holder that being contacted
        holder: Box<NetworkAddress>,
        /// Key of the missing record
        key: Box<NetworkAddress>,
    },

    // ---------- record errors
    // Could not Serialize/Deserialize RecordHeader from Record
    #[error("Could not Serialize/Deserialize RecordHeader to/from Record")]
    RecordHeaderParsingFailed,
    // Could not Serialize/Deserialize Record
    #[error("Could not Serialize/Deserialize Record")]
    RecordParsingFailed,
    // The record already exists at this node
    #[error("The record already exists, so do not charge for it: {0:?}")]
    RecordExists(PrettyPrintRecordKey<'static>),

    // ---------- Record Put errors
    #[error("Error handling record put: {0}")]
    PutRecordFailed(String),
    #[error("Outdated record: with counter {counter}, expected any above {expected}")]
    OutdatedRecordCounter { counter: u64, expected: u64 },

    // Dev Note: add new variants above this one for backward compatibility with older protocol versions
    // ---------- Unknown/fallback variant for retro compatibility
    /// Unknown error variant (for backward compatibility with newer protocol versions)
    #[error("Unknown error: the peer and you are using different protocol versions")]
    #[serde(other)]
    Unknown,
}

impl From<Error> for store::Error {
    fn from(_err: Error) -> Self {
        store::Error::ValueTooLarge
    }
}

impl From<store::Error> for Error {
    fn from(_err: store::Error) -> Self {
        Error::RecordParsingFailed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_retro_compatibility() {
        // Test with a new struct that has a new variant
        #[derive(Error, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[non_exhaustive]
        enum ExtendedError {
            #[error("Chunk does not exist {0:?}")]
            ChunkDoesNotExist(NetworkAddress),
            #[error("Failed to deserialize hex ScratchpadAddress")]
            ScratchpadHexDeserializeFailed,
            #[error("Failed to derive CipherText from encrypted_data")]
            ScratchpadCipherTextFailed,
            #[error("Provided cypher text is invalid")]
            ScratchpadCipherTextInvalid,
            #[error("There was an error getting the storecost from kademlia store")]
            GetStoreQuoteFailed,
            #[error("There was an error generating the payment quote")]
            QuoteGenerationFailed,
            #[error("Peer {holder:?} cannot find Record {key:?}")]
            ReplicatedRecordNotFound {
                holder: Box<NetworkAddress>,
                key: Box<NetworkAddress>,
            },
            #[error("Could not Serialize/Deserialize RecordHeader to/from Record")]
            RecordHeaderParsingFailed,
            #[error("Could not Serialize/Deserialize Record")]
            RecordParsingFailed,
            #[error("The record already exists, so do not charge for it: {0:?}")]
            RecordExists(PrettyPrintRecordKey<'static>),
            // New variant that doesn't exist in the original Error enum
            #[error("New error variant for testing")]
            NewErrorVariant,
            #[error("Unknown error variant")]
            #[serde(other)]
            Unknown,
        }

        // Test with a struct that has a missing variant (simulating older version)
        #[derive(Error, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[non_exhaustive]
        enum ReducedError {
            #[error("Chunk does not exist {0:?}")]
            ChunkDoesNotExist(NetworkAddress),
            #[error("Failed to deserialize hex ScratchpadAddress")]
            ScratchpadHexDeserializeFailed,
            // removed this variant
            // - #[error("Failed to derive CipherText from encrypted_data")]
            // - ScratchpadCipherTextFailed,
            #[error("Provided cypher text is invalid")]
            ScratchpadCipherTextInvalid,
            #[error("There was an error getting the storecost from kademlia store")]
            GetStoreQuoteFailed,
            #[error("There was an error generating the payment quote")]
            QuoteGenerationFailed,
            #[error("Peer {holder:?} cannot find Record {key:?}")]
            ReplicatedRecordNotFound {
                holder: Box<NetworkAddress>,
                key: Box<NetworkAddress>,
            },
            #[error("Could not Serialize/Deserialize RecordHeader to/from Record")]
            RecordHeaderParsingFailed,
            #[error("Could not Serialize/Deserialize Record")]
            RecordParsingFailed,
            #[error("The record already exists, so do not charge for it: {0:?}")]
            RecordExists(PrettyPrintRecordKey<'static>),
            // Missing some variants that exist in the current Error enum
            #[error("Unknown error variant")]
            #[serde(other)]
            Unknown,
        }

        // Test serialization and deserialization of ExtendedError
        let extended_error = ExtendedError::NewErrorVariant;
        let serialized = rmp_serde::to_vec(&extended_error).unwrap();

        // Test that we can deserialize into the current Error enum
        let deserialized: Error = rmp_serde::from_slice(&serialized).unwrap();
        assert_eq!(deserialized, Error::Unknown);

        // Test serialization and deserialization of current Error
        let current_error = Error::ScratchpadCipherTextInvalid;
        let serialized_current = rmp_serde::to_vec(&current_error).unwrap();

        // Test that we can deserialize into ReducedError (older version)
        let deserialized_reduced: ReducedError =
            rmp_serde::from_slice(&serialized_current).unwrap();
        assert_eq!(
            deserialized_reduced,
            ReducedError::ScratchpadCipherTextInvalid
        );

        // Test that unknown variants fall back to Unknown
        let unknown_variant = Error::ScratchpadCipherTextFailed;
        let serialized_unknown = rmp_serde::to_vec(&unknown_variant).unwrap();
        let deserialized_unknown: ReducedError =
            rmp_serde::from_slice(&serialized_unknown).unwrap();
        assert_eq!(deserialized_unknown, ReducedError::Unknown);
    }
}
