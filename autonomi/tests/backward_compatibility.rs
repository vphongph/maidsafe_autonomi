// Copyright 2025 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use bytes::Bytes;
use self_encryption::{ChunkInfo, DataMap, EncryptedChunk, MAX_CHUNK_SIZE, decrypt};
use self_encryption_old::encrypt as old_encrypt;

/// Test backward compatibility between old and new self_encryption versions
///
/// This test verifies that data encrypted with version (0.30.0) can be
/// decrypted with the new version.
#[test]
fn test_self_encryption_backward_compatibility() -> Result<(), Box<dyn std::error::Error>> {
    // Test 1 Encrypt with old version, decrypt with new version
    test_old_encrypt_new_decrypt()?;

    Ok(())
}

/// Test encrypting data with new version and decrypting with old version
fn test_old_encrypt_new_decrypt() -> Result<(), Box<dyn std::error::Error>> {
    let content_size: usize = 20 * MAX_CHUNK_SIZE + 100;
    let mut content = vec![0u8; content_size];
    for (i, c) in content.iter_mut().enumerate().take(content_size) {
        *c = (i % 17) as u8;
    }
    let content_bytes = Bytes::from(content);

    let (old_data_map, old_encrypted_chunks) = old_encrypt(content_bytes.clone())?;

    // Convert old format of DataMap and EncryptedChunk into new
    let chunk_identifiers: Vec<ChunkInfo> = old_data_map
        .infos()
        .iter()
        .map(|ck_info| ChunkInfo {
            index: ck_info.index,
            dst_hash: ck_info.dst_hash,
            src_hash: ck_info.src_hash,
            src_size: ck_info.src_size,
        })
        .collect();
    let data_map = DataMap {
        chunk_identifiers,
        child: None,
    };
    let encrypted_chunks: Vec<EncryptedChunk> = old_encrypted_chunks
        .iter()
        .map(|enc| EncryptedChunk {
            content: enc.content.clone(),
        })
        .collect();

    let decrypted_content = decrypt(&data_map, &encrypted_chunks)?;

    assert_eq!(decrypted_content, content_bytes);
    Ok(())
}
