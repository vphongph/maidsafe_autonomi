use bls::PublicKey;
use serde::{Deserialize, Serialize};
use xor_name::XorName;

/// Address of a pointer, is derived from the owner's public key
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct PointerAddress(pub XorName);

impl PointerAddress {
    pub fn from_owner(owner: PublicKey) -> Self {
        Self(XorName::from_content(&owner.to_bytes()))
    }

    pub fn new(xor_name: XorName) -> Self {
        Self(xor_name)
    }

    pub fn xorname(&self) -> &XorName {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        rmp_serde::to_vec(self).expect("Failed to serialize PointerAddress")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, rmp_serde::decode::Error> {
        rmp_serde::from_slice(bytes)
    }
}

impl std::fmt::Debug for PointerAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PointerAddress({})", &self.to_hex()[0..6])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pointer_serialization() {
        let key = bls::SecretKey::random();
        let pointer_address = PointerAddress::from_owner(key.public_key());
        let serialized = pointer_address.to_bytes();
        let deserialized = PointerAddress::from_bytes(&serialized).unwrap();
        assert_eq!(pointer_address, deserialized);
    }
}
