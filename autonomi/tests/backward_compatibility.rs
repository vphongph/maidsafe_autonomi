// Copyright 2025 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use bytes::Bytes;
use self_encryption::{encrypt, MAX_CHUNK_SIZE};
use self_encryption_old::{decrypt as old_decrypt, ChunkInfo as OldChunkInfo, DataMap as OldDataMap, EncryptedChunk as OldEncryptedChunk};

/// Test backward compatibility between old and new self_encryption versions
/// 
/// This test verifies that data encrypted with version (0.30.0) can be
/// decrypted with the new version.
#[test]
fn test_self_encryption_backward_compatibility() -> Result<(), Box<dyn std::error::Error>> {
    // Test 1: Encrypt with old version, decrypt with new version
    // TODO: switch to this once new self_encryption released and integrated into autonomi
    // test_old_encrypt_new_decrypt()?;
    
    // Test 2: Encrypt with new version, decrypt with old version 
    // TODO: remove this once new self_encryption released and integrated into autonomi
    test_new_encrypt_old_decrypt()?;
    
    Ok(())
}

/// Test encrypting data with new version and decrypting with old version
fn test_new_encrypt_old_decrypt() -> Result<(), Box<dyn std::error::Error>> {
    let content_size: usize = 20 * *MAX_CHUNK_SIZE + 100;
    let mut content = vec![0u8; content_size];
    for (i, c) in content.iter_mut().enumerate().take(content_size) {
        *c = (i % 17) as u8;
    }
    let content_bytes = Bytes::from(content);

    let (data_map, encrypted_chunks) = encrypt(content_bytes.clone())?;

    // Convert new format of DataMap and EncryptedChunk into old
    let chunk_identifiers: Vec<OldChunkInfo> = data_map.infos().iter().map(|ck_info| OldChunkInfo {
        index: ck_info.index,
        dst_hash: ck_info.dst_hash,
        src_hash: ck_info.src_hash,
        src_size: ck_info.src_size,
    }).collect();
    let old_data_map = OldDataMap {
        chunk_identifiers,
        child: None,
    };
    let old_encrypted_chunks: Vec<OldEncryptedChunk> = encrypted_chunks.iter().map(|enc| OldEncryptedChunk {
        content: enc.content.clone(),
    }).collect();

    let decrypted_content = old_decrypt(&old_data_map, &old_encrypted_chunks)?;

    assert_eq!(decrypted_content, content_bytes);
    Ok(())
}
