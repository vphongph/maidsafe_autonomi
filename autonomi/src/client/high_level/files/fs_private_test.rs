// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(test)]
mod tests {
    use super::super::super::files::DownloadError;
    use bytes::{BufMut, Bytes, BytesMut};
    use self_encryption::DataMap;
    use self_encryption_old::DataMap as OldDataMap;
    use serde::Serialize;
    use xor_name::XorName;

    /// Helper function to create test data maps with sample chunk info
    fn create_test_chunk_info(count: usize) -> Vec<self_encryption::ChunkInfo> {
        (0..count)
            .map(|i| self_encryption::ChunkInfo {
                index: i,
                dst_hash: XorName::from_content(&[i as u8; 32]),
                src_hash: XorName::from_content(&[(i + 100) as u8; 32]),
                src_size: 1024 + i,
            })
            .collect()
    }

    /// Helper function to create old format data map
    fn create_old_data_map(count: usize) -> OldDataMap {
        let chunk_infos: Vec<_> = (0..count)
            .map(|i| self_encryption_old::ChunkInfo {
                index: i,
                dst_hash: XorName::from_content(&[i as u8; 32]),
                src_hash: XorName::from_content(&[(i + 100) as u8; 32]),
                src_size: 1024 + i,
            })
            .collect();
        OldDataMap::new(chunk_infos)
    }

    /// Helper function to serialize data to bytes
    fn serialize_to_bytes<T: Serialize>(data: &T) -> Bytes {
        let mut bytes = BytesMut::with_capacity(300).writer();
        let mut serialiser = rmp_serde::Serializer::new(&mut bytes);
        data.serialize(&mut serialiser).unwrap();
        bytes.into_inner().freeze()
    }

    // Test helper struct that implements the deserialization logic for private data maps
    struct TestPrivateClientHelper;

    impl TestPrivateClientHelper {
        fn deserialize_data_map(
            &self,
            data_map_bytes: &Bytes,
        ) -> Result<self_encryption::DataMap, DownloadError> {
            // Try new format first
            if let Ok(data_map) = rmp_serde::from_slice::<self_encryption::DataMap>(data_map_bytes)
            {
                return Ok(data_map);
            }

            // Fall back to old format and convert
            let data_map_level =
                rmp_serde::from_slice::<crate::self_encryption::DataMapLevel>(data_map_bytes)
                    .map_err(|e| {
                        DownloadError::GetError(crate::client::GetError::InvalidDataMap(e))
                    })?;

            let old_data_map = match &data_map_level {
                crate::self_encryption::DataMapLevel::First(map) => map,
                crate::self_encryption::DataMapLevel::Additional(map) => map,
            };

            // Convert to new format
            let chunk_identifiers: Vec<self_encryption::ChunkInfo> = old_data_map
                .infos()
                .iter()
                .map(|ck_info| self_encryption::ChunkInfo {
                    index: ck_info.index,
                    dst_hash: ck_info.dst_hash,
                    src_hash: ck_info.src_hash,
                    src_size: ck_info.src_size,
                })
                .collect();

            Ok(self_encryption::DataMap {
                chunk_identifiers,
                child: None,
            })
        }
    }

    /// Test that deserialize_data_map works with new DataMap format (private version)
    #[test]
    fn test_deserialize_private_data_map_new_format() {
        let test_client = TestPrivateClientHelper;

        // Create test data map in new format
        let chunk_identifiers = create_test_chunk_info(3);
        let new_data_map = DataMap {
            chunk_identifiers: chunk_identifiers.clone(),
            child: None,
        };

        // Serialize to bytes
        let data_map_bytes = serialize_to_bytes(&new_data_map);

        // Test deserialization
        let result = test_client.deserialize_data_map(&data_map_bytes);

        assert!(
            result.is_ok(),
            "Failed to deserialize new format: {:?}",
            result.err()
        );
        let deserialized = result.unwrap();

        // Verify the data matches
        assert_eq!(deserialized.infos().len(), 3);
        for (original, deserialized) in chunk_identifiers.iter().zip(deserialized.infos().iter()) {
            assert_eq!(original.index, deserialized.index);
            assert_eq!(original.dst_hash, deserialized.dst_hash);
            assert_eq!(original.src_hash, deserialized.src_hash);
            assert_eq!(original.src_size, deserialized.src_size);
        }
    }

    /// Test that deserialize_data_map works with old DataMapLevel::First format (private version)
    #[test]
    fn test_deserialize_private_data_map_old_format_first() {
        let test_client = TestPrivateClientHelper;

        // Create test data map in old format (First level)
        let old_data_map = create_old_data_map(4);
        let data_map_level = crate::self_encryption::DataMapLevel::First(old_data_map.clone());

        // Serialize to bytes
        let data_map_bytes = serialize_to_bytes(&data_map_level);

        // Test deserialization
        let result = test_client.deserialize_data_map(&data_map_bytes);

        assert!(
            result.is_ok(),
            "Failed to deserialize old First format: {:?}",
            result.err()
        );
        let deserialized = result.unwrap();

        // Verify the data matches
        assert_eq!(deserialized.infos().len(), 4);
        for (original, deserialized) in old_data_map.infos().iter().zip(deserialized.infos().iter())
        {
            assert_eq!(original.index, deserialized.index);
            assert_eq!(original.dst_hash, deserialized.dst_hash);
            assert_eq!(original.src_hash, deserialized.src_hash);
            assert_eq!(original.src_size, deserialized.src_size);
        }
    }

    /// Test that deserialize_data_map works with old DataMapLevel::Additional format (private version)
    #[test]
    fn test_deserialize_private_data_map_old_format_additional() {
        let test_client = TestPrivateClientHelper;

        // Create test data map in old format (Additional level)
        let old_data_map = create_old_data_map(6);
        let data_map_level = crate::self_encryption::DataMapLevel::Additional(old_data_map.clone());

        // Serialize to bytes
        let data_map_bytes = serialize_to_bytes(&data_map_level);

        // Test deserialization
        let result = test_client.deserialize_data_map(&data_map_bytes);

        assert!(
            result.is_ok(),
            "Failed to deserialize old Additional format: {:?}",
            result.err()
        );
        let deserialized = result.unwrap();

        // Verify the data matches
        assert_eq!(deserialized.infos().len(), 6);
        for (original, deserialized) in old_data_map.infos().iter().zip(deserialized.infos().iter())
        {
            assert_eq!(original.index, deserialized.index);
            assert_eq!(original.dst_hash, deserialized.dst_hash);
            assert_eq!(original.src_hash, deserialized.src_hash);
            assert_eq!(original.src_size, deserialized.src_size);
        }
    }

    /// Test error handling for invalid data (private version)
    #[test]
    fn test_deserialize_private_data_map_invalid_data() {
        let test_client = TestPrivateClientHelper;

        // Create invalid data that can't be deserialized as either format
        let invalid_data = Bytes::from_static(b"invalid msgpack data for private test");

        // Test deserialization
        let result = test_client.deserialize_data_map(&invalid_data);

        assert!(
            result.is_err(),
            "Should have failed to deserialize invalid data"
        );
        // Verify it's the expected error type
        match result.unwrap_err() {
            DownloadError::GetError(crate::client::GetError::InvalidDataMap(_)) => {
                // This is the expected error type
            }
            other => panic!("Unexpected error type: {other:?}"),
        }
    }

    /// Test both formats produce the same result when given equivalent data
    #[test]
    fn test_deserialize_private_data_map_format_equivalence() {
        let test_client = TestPrivateClientHelper;

        // Create equivalent data in both formats
        let test_chunk_data: Vec<_> = (0..5)
            .map(|i| {
                let dst_hash = XorName::from_content(&[i as u8; 32]);
                let src_hash = XorName::from_content(&[(i + 42) as u8; 32]);
                (i, dst_hash, src_hash, 512 + i * 100)
            })
            .collect();

        // Create new format
        let new_chunk_identifiers: Vec<self_encryption::ChunkInfo> = test_chunk_data
            .iter()
            .map(
                |(index, dst_hash, src_hash, src_size)| self_encryption::ChunkInfo {
                    index: *index,
                    dst_hash: *dst_hash,
                    src_hash: *src_hash,
                    src_size: *src_size,
                },
            )
            .collect();
        let new_data_map = DataMap {
            chunk_identifiers: new_chunk_identifiers,
            child: None,
        };

        // Create equivalent old format
        let old_chunk_infos: Vec<self_encryption_old::ChunkInfo> = test_chunk_data
            .iter()
            .map(
                |(index, dst_hash, src_hash, src_size)| self_encryption_old::ChunkInfo {
                    index: *index,
                    dst_hash: *dst_hash,
                    src_hash: *src_hash,
                    src_size: *src_size,
                },
            )
            .collect();
        let old_data_map = OldDataMap::new(old_chunk_infos);
        let data_map_level = crate::self_encryption::DataMapLevel::First(old_data_map);

        // Serialize both formats
        let new_data_bytes = serialize_to_bytes(&new_data_map);
        let old_data_bytes = serialize_to_bytes(&data_map_level);

        // Deserialize both
        let new_result = test_client.deserialize_data_map(&new_data_bytes).unwrap();
        let old_result = test_client.deserialize_data_map(&old_data_bytes).unwrap();

        // Both should produce identical results
        assert_eq!(new_result.infos().len(), old_result.infos().len());
        for (new_info, old_info) in new_result.infos().iter().zip(old_result.infos().iter()) {
            assert_eq!(new_info.index, old_info.index);
            assert_eq!(new_info.dst_hash, old_info.dst_hash);
            assert_eq!(new_info.src_hash, old_info.src_hash);
            assert_eq!(new_info.src_size, old_info.src_size);
        }
    }
}
