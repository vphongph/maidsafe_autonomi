// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::storage::{ChunkAddress, GraphEntryAddress, PointerAddress, ScratchpadAddress};
use bls::{Error as BlsError, PublicKey, SecretKey, Signature};
use hex::FromHexError;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use xor_name::XorName;

#[derive(Error, Debug)]
pub enum PointerError {
    #[error("Failed to decode hex string: {0}")]
    HexDecoding(#[from] FromHexError),
    #[error("Failed to create public key: {0}")]
    BlsError(#[from] BlsError),
    #[error("Invalid public key bytes length")]
    InvalidPublicKeyLength,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Pointer, a mutable address pointing to other data on the Network
/// It is stored at the owner's public key and can only be updated by the owner
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Pointer {
    owner: PublicKey,
    counter: u32,
    target: PointerTarget,
    signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PointerTarget {
    ChunkAddress(ChunkAddress),
    GraphEntryAddress(GraphEntryAddress),
    PointerAddress(PointerAddress),
    ScratchpadAddress(ScratchpadAddress),
}

impl PointerTarget {
    pub fn xorname(&self) -> XorName {
        match self {
            PointerTarget::ChunkAddress(addr) => *addr.xorname(),
            PointerTarget::GraphEntryAddress(addr) => *addr.xorname(),
            PointerTarget::PointerAddress(ptr) => *ptr.xorname(),
            PointerTarget::ScratchpadAddress(addr) => addr.xorname(),
        }
    }
}

impl Pointer {
    /// Create a new pointer, signing it with the provided secret key.
    /// This pointer would be stored on the network at the provided key's public key
    /// There can only be one pointer at a time at the same address (one per key)
    pub fn new(owner: &SecretKey, counter: u32, target: PointerTarget) -> Self {
        let pubkey = owner.public_key();
        let bytes_to_sign = Self::bytes_to_sign(&pubkey, counter, &target);
        let signature = owner.sign(&bytes_to_sign);

        Self {
            owner: pubkey,
            counter,
            target,
            signature,
        }
    }

    /// Create a new pointer with an existing signature
    pub fn new_with_signature(
        owner: PublicKey,
        counter: u32,
        target: PointerTarget,
        signature: Signature,
    ) -> Self {
        Self {
            owner,
            counter,
            target,
            signature,
        }
    }

    /// Get the bytes that the signature is calculated from
    fn bytes_to_sign(owner: &PublicKey, counter: u32, target: &PointerTarget) -> Vec<u8> {
        let mut bytes = Vec::new();
        // Add owner public key bytes
        bytes.extend_from_slice(&owner.to_bytes());
        // Add counter
        bytes.extend_from_slice(&counter.to_le_bytes());
        // Add target bytes using MessagePack serialization
        if let Ok(target_bytes) = rmp_serde::to_vec(target) {
            bytes.extend_from_slice(&target_bytes);
        }
        bytes
    }

    /// Get the address of the pointer
    pub fn address(&self) -> PointerAddress {
        PointerAddress::from_owner(self.owner)
    }

    /// Get the bytes that were signed for this pointer
    pub fn bytes_for_signature(&self) -> Vec<u8> {
        Self::bytes_to_sign(&self.owner, self.counter, &self.target)
    }

    pub fn xorname(&self) -> XorName {
        self.target.xorname()
    }

    /// Get the counter of the pointer, the higher the counter, the more recent the pointer is
    /// Similarly to counter CRDTs only the latest version (highest counter) of the pointer is kept on the network
    pub fn counter(&self) -> u32 {
        self.counter
    }

    /// Get the network address for this pointer
    pub fn network_address(&self) -> PointerAddress {
        PointerAddress::from_owner(self.owner)
    }

    /// Verifies if the pointer has a valid signature
    pub fn verify(&self) -> bool {
        let bytes = self.bytes_for_signature();
        self.owner.verify(&self.signature, &bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_pointer_creation_and_validation() {
        let owner_sk = SecretKey::random();
        let counter = 1;
        let mut rng = thread_rng();
        let target =
            PointerTarget::GraphEntryAddress(GraphEntryAddress::new(XorName::random(&mut rng)));

        // Create and sign pointer
        let pointer = Pointer::new(&owner_sk, counter, target.clone());
        assert!(pointer.verify()); // Should be valid with correct signature

        // Create pointer with wrong signature
        let wrong_sk = SecretKey::random();
        let sig = wrong_sk.sign(pointer.bytes_for_signature());
        let wrong_pointer =
            Pointer::new_with_signature(owner_sk.public_key(), counter, target.clone(), sig);
        assert!(!wrong_pointer.verify()); // Should be invalid with wrong signature
    }
}
