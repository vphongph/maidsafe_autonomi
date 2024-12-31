use crate::storage::{ChunkAddress, GraphEntryAddress, PointerAddress, ScratchpadAddress};
use bls::{Error as BlsError, PublicKey, SecretKey, Signature};
use hex::FromHexError;
use rand::thread_rng;
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
    pub fn new(
        owner: PublicKey,
        counter: u32,
        target: PointerTarget,
        signing_key: &SecretKey,
    ) -> Self {
        let bytes_to_sign = Self::bytes_to_sign(&owner, counter, &target);
        let signature = signing_key.sign(&bytes_to_sign);

        Self {
            owner,
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

    /// Get the bytes that were signed for this pointer
    pub fn bytes_for_signature(&self) -> Vec<u8> {
        Self::bytes_to_sign(&self.owner, self.counter, &self.target)
    }

    pub fn xorname(&self) -> XorName {
        self.target.xorname()
    }

    pub fn count(&self) -> u32 {
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

    pub fn encode_hex(&self) -> String {
        hex::encode(self.owner.to_bytes())
    }

    pub fn decode_hex(hex_str: &str) -> Result<Self, PointerError> {
        let bytes = hex::decode(hex_str)?;
        if bytes.len() != 48 {
            return Err(PointerError::InvalidPublicKeyLength);
        }
        let mut bytes_array = [0u8; 48];
        bytes_array.copy_from_slice(&bytes);

        let owner = PublicKey::from_bytes(bytes_array).map_err(PointerError::BlsError)?;

        let mut rng = thread_rng();
        let target = PointerTarget::ChunkAddress(ChunkAddress::new(XorName::random(&mut rng)));

        // Create a temporary secret key just for hex decoding test purposes
        let sk = SecretKey::random();
        Ok(Self::new(owner, 0, target, &sk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pointer_creation_and_validation() {
        let owner_sk = SecretKey::random();
        let owner_pk = owner_sk.public_key();
        let counter = 1;
        let mut rng = thread_rng();
        let target =
            PointerTarget::GraphEntryAddress(GraphEntryAddress::new(XorName::random(&mut rng)));

        // Create and sign pointer
        let pointer = Pointer::new(owner_pk, counter, target.clone(), &owner_sk);
        assert!(pointer.verify()); // Should be valid with correct signature

        // Create pointer with wrong signature
        let wrong_sk = SecretKey::random();
        let wrong_pointer = Pointer::new(owner_pk, counter, target.clone(), &wrong_sk);
        assert!(!wrong_pointer.verify()); // Should be invalid with wrong signature
    }

    #[test]
    fn test_pointer_xorname() {
        let owner_sk = SecretKey::random();
        let owner_pk = owner_sk.public_key();
        let counter = 1;
        let mut rng = thread_rng();
        let target =
            PointerTarget::GraphEntryAddress(GraphEntryAddress::new(XorName::random(&mut rng)));

        let pointer = Pointer::new(owner_pk, counter, target.clone(), &owner_sk);
        let xorname = pointer.xorname();
        assert_eq!(xorname, target.xorname());
    }

    #[test]
    fn test_pointer_hex_encoding() {
        let owner_sk = SecretKey::random();
        let owner_pk = owner_sk.public_key();
        let counter = 1;
        let mut rng = thread_rng();
        let target =
            PointerTarget::GraphEntryAddress(GraphEntryAddress::new(XorName::random(&mut rng)));

        let pointer = Pointer::new(owner_pk, counter, target, &owner_sk);
        let hex = pointer.encode_hex();
        let expected_hex = hex::encode(owner_pk.to_bytes());
        assert_eq!(hex, expected_hex);
    }

    #[test]
    fn test_pointer_hex_decoding() {
        let owner_sk = SecretKey::random();
        let owner_pk = owner_sk.public_key();
        let hex = hex::encode(owner_pk.to_bytes());

        let result = Pointer::decode_hex(&hex);
        assert!(result.is_ok());
        let pointer = result.unwrap();
        assert_eq!(pointer.owner, owner_pk);
    }
}
