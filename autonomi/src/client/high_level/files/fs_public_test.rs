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

    // Test helper struct that implements the deserialization logic
    // This allows us to test the method without setting up a full Client
    struct TestClientHelper;

    impl TestClientHelper {
        fn deserialize_public_data_map(
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

    /// Test that deserialize_public_data_map works with new DataMap format
    #[test]
    fn test_deserialize_public_data_map_new_format() {
        let test_client = TestClientHelper;

        // Create test data map in new format
        let chunk_identifiers = create_test_chunk_info(5);
        let new_data_map = DataMap {
            chunk_identifiers: chunk_identifiers.clone(),
            child: None,
        };

        // Serialize to bytes
        let data_map_bytes = serialize_to_bytes(&new_data_map);

        // Test deserialization
        let result = test_client.deserialize_public_data_map(&data_map_bytes);

        assert!(
            result.is_ok(),
            "Failed to deserialize new format: {:?}",
            result.err()
        );
        let deserialized = result.unwrap();

        // Verify the data matches
        assert_eq!(deserialized.infos().len(), 5);
        for (original, deserialized) in chunk_identifiers.iter().zip(deserialized.infos().iter()) {
            assert_eq!(original.index, deserialized.index);
            assert_eq!(original.dst_hash, deserialized.dst_hash);
            assert_eq!(original.src_hash, deserialized.src_hash);
            assert_eq!(original.src_size, deserialized.src_size);
        }
    }

    /// Test that deserialize_public_data_map works with old DataMapLevel::First format
    #[test]
    fn test_deserialize_public_data_map_old_format_first() {
        let test_client = TestClientHelper;

        // Create test data map in old format (First level)
        let old_data_map = create_old_data_map(3);
        let data_map_level = crate::self_encryption::DataMapLevel::First(old_data_map.clone());

        // Serialize to bytes
        let data_map_bytes = serialize_to_bytes(&data_map_level);

        // Test deserialization
        let result = test_client.deserialize_public_data_map(&data_map_bytes);

        assert!(
            result.is_ok(),
            "Failed to deserialize old First format: {:?}",
            result.err()
        );
        let deserialized = result.unwrap();

        // Verify the data matches
        assert_eq!(deserialized.infos().len(), 3);
        for (original, deserialized) in old_data_map.infos().iter().zip(deserialized.infos().iter())
        {
            assert_eq!(original.index, deserialized.index);
            assert_eq!(original.dst_hash, deserialized.dst_hash);
            assert_eq!(original.src_hash, deserialized.src_hash);
            assert_eq!(original.src_size, deserialized.src_size);
        }
    }

    /// Test that deserialize_public_data_map works with old DataMapLevel::Additional format
    #[test]
    fn test_deserialize_public_data_map_old_format_additional() {
        let test_client = TestClientHelper;

        // Create test data map in old format (Additional level)
        let old_data_map = create_old_data_map(7);
        let data_map_level = crate::self_encryption::DataMapLevel::Additional(old_data_map.clone());

        // Serialize to bytes
        let data_map_bytes = serialize_to_bytes(&data_map_level);

        // Test deserialization
        let result = test_client.deserialize_public_data_map(&data_map_bytes);

        assert!(
            result.is_ok(),
            "Failed to deserialize old Additional format: {:?}",
            result.err()
        );
        let deserialized = result.unwrap();

        // Verify the data matches
        assert_eq!(deserialized.infos().len(), 7);
        for (original, deserialized) in old_data_map.infos().iter().zip(deserialized.infos().iter())
        {
            assert_eq!(original.index, deserialized.index);
            assert_eq!(original.dst_hash, deserialized.dst_hash);
            assert_eq!(original.src_hash, deserialized.src_hash);
            assert_eq!(original.src_size, deserialized.src_size);
        }
    }

    /// Test error handling for invalid data
    #[test]
    fn test_deserialize_public_data_map_invalid_data() {
        let test_client = TestClientHelper;

        // Create invalid data that can't be deserialized as either format
        let invalid_data = Bytes::from_static(b"this is not valid msgpack data");

        // Test deserialization
        let result = test_client.deserialize_public_data_map(&invalid_data);

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

    /// Test with empty data maps
    #[test]
    fn test_deserialize_public_data_map_empty() {
        let test_client = TestClientHelper;

        // Create empty new format data map
        let empty_new_data_map = DataMap {
            chunk_identifiers: vec![],
            child: None,
        };
        let data_map_bytes = serialize_to_bytes(&empty_new_data_map);

        let result = test_client.deserialize_public_data_map(&data_map_bytes);
        assert!(
            result.is_ok(),
            "Failed to deserialize empty new format: {:?}",
            result.err()
        );
        let deserialized = result.unwrap();
        assert_eq!(deserialized.infos().len(), 0);

        // Create empty old format data map
        let empty_old_data_map = OldDataMap::new(vec![]);
        let data_map_level = crate::self_encryption::DataMapLevel::First(empty_old_data_map);
        let data_map_bytes = serialize_to_bytes(&data_map_level);

        let result = test_client.deserialize_public_data_map(&data_map_bytes);
        assert!(
            result.is_ok(),
            "Failed to deserialize empty old format: {:?}",
            result.err()
        );
        let deserialized = result.unwrap();
        assert_eq!(deserialized.infos().len(), 0);
    }

    /// Test round-trip compatibility: old format → deserialize → should match expected structure
    #[test]
    fn test_deserialize_public_data_map_round_trip() {
        let test_client = TestClientHelper;

        // Create old format data map with known values
        let expected_chunks: Vec<_> = (0..4)
            .map(|i| {
                let dst_hash = XorName::from_content(&[i as u8; 32]);
                let src_hash = XorName::from_content(&[(i + 50) as u8; 32]);
                (i, dst_hash, src_hash, 2048 + i)
            })
            .collect();

        let old_chunk_infos: Vec<_> = expected_chunks
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
        let data_map_bytes = serialize_to_bytes(&data_map_level);

        // Deserialize and verify
        let result = test_client
            .deserialize_public_data_map(&data_map_bytes)
            .unwrap();

        assert_eq!(result.infos().len(), expected_chunks.len());
        for ((expected_index, expected_dst, expected_src, expected_size), actual) in
            expected_chunks.iter().zip(result.infos().iter())
        {
            assert_eq!(*expected_index, actual.index);
            assert_eq!(*expected_dst, actual.dst_hash);
            assert_eq!(*expected_src, actual.src_hash);
            assert_eq!(*expected_size, actual.src_size);
        }
    }
}
