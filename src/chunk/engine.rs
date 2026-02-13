use crate::core::{Result, AeadCipher, CipherType, KeyDerivation};
use crate::container::format::ChunkRecord;
use crate::cllx_math::CllxTransform;
use rayon::prelude::*;
use sha3::{Digest, Shake256};
use sha3::digest::{Update, ExtendableOutput, XofReader};

/// Enhanced chunk engine with AAD and masking
pub struct ChunkEngineV2 {
    chunk_size: usize,
    cipher: AeadCipher,
    enable_masking: bool,
    cllx_transform: Option<CllxTransform>,
}

/// Additional Authenticated Data for chunk encryption
#[derive(Debug, Clone)]
pub struct ChunkAAD {
    pub chunk_id: u64,
    pub container_version: u32,
    pub file_id: [u8; 32],
    pub total_chunks: u64,
}

impl ChunkAAD {
    pub fn encode(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(56);
        aad.extend_from_slice(&self.chunk_id.to_le_bytes());
        aad.extend_from_slice(&self.container_version.to_le_bytes());
        aad.extend_from_slice(&self.file_id);
        aad.extend_from_slice(&self.total_chunks.to_le_bytes());
        aad
    }
}

impl ChunkEngineV2 {
    pub fn new(chunk_size: usize, cipher_type: CipherType, enable_masking: bool) -> Self {
        Self {
            chunk_size,
            cipher: AeadCipher::new(cipher_type),
            enable_masking,
            cllx_transform: None,
        }
    }
    
    /// 创建 engine with cllX-Math transform enabled
    pub fn with_cllx_transform(chunk_size: usize, cipher_type: CipherType, enable_masking: bool, master_key: &[u8; 32]) -> Result<Self> {
        let cllx_transform = CllxTransform::new(master_key)?;
        Ok(Self {
            chunk_size,
            cipher: AeadCipher::new(cipher_type),
            enable_masking,
            cllx_transform: Some(cllx_transform),
        })
    }

    /// Split data into chunks
    pub fn split<'a>(&self, data: &'a [u8]) -> Vec<&'a [u8]> {
        data.chunks(self.chunk_size).collect()
    }

    /// 加密 chunks with full AAD and optional masking
    pub fn encrypt_chunks_v2(
        &self,
        chunks: &[Vec<u8>],
        tree_root_key: &[u8; 32],
        mask_key: &[u8; 32],
        file_nonce: &[u8; 12],
        aad_template: &ChunkAAD,
    ) -> Result<Vec<(Vec<u8>, ChunkRecord)>> {
        chunks
            .par_iter()
            .enumerate()
            .map(|(i, chunk)| {
                // Derive chunk-specific key
                let chunk_key = KeyDerivation::derive_chunk_key(tree_root_key, i as u64)?;
                
                // Calculate pre-encryption hash
                let chunk_hash = blake3::hash(chunk);
                
                // Apply masking if enabled
                let mut data_to_encrypt = if self.enable_masking {
                    let mask = self.generate_mask(mask_key, chunk_hash.as_bytes());
                    self.xor_mask(chunk, &mask)
                } else {
                    chunk.clone()
                };
                
                // Apply cllX-Math transform if enabled (NEW LAYER)
                if let Some(ref transform) = self.cllx_transform {
                    data_to_encrypt = transform.pre_encrypt(&data_to_encrypt, file_nonce, i as u64)?;
                }
                
                // 构建 nonce with chunk index
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(file_nonce);
                nonce[8..].copy_from_slice(&(i as u32).to_le_bytes());
                
                // 构建 AAD
                let mut aad = aad_template.clone();
                aad.chunk_id = i as u64;
                let aad_bytes = aad.encode();
                
                // Encrypt
                let ciphertext = self.cipher.encrypt(&chunk_key, &nonce, &data_to_encrypt, &aad_bytes)?;
                
                // Extract tag (last 16 bytes)
                let tag_start = ciphertext.len().saturating_sub(16);
                let mut tag = [0u8; 16];
                tag.copy_from_slice(&ciphertext[tag_start..]);
                
                // 创建 chunk record
                let record = ChunkRecord {
                    chunk_id: i as u64,
                    offset: 0, // Will be set by writer
                    length: ciphertext.len() as u32,
                    tag,
                    hash: *chunk_hash.as_bytes(),
                };
                
                Ok((ciphertext, record))
            })
            .collect()
    }

    /// 解密 chunks with AAD verification
    pub fn decrypt_chunks_v2(
        &self,
        ciphertexts: &[(Vec<u8>, ChunkRecord)],
        tree_root_key: &[u8; 32],
        mask_key: &[u8; 32],
        file_nonce: &[u8; 12],
        aad_template: &ChunkAAD,
    ) -> Result<Vec<Vec<u8>>> {
        ciphertexts
            .par_iter()
            .enumerate()
            .map(|(i, (ct, record))| {
                // Derive chunk-specific key
                let chunk_key = KeyDerivation::derive_chunk_key(tree_root_key, i as u64)?;
                
                // 构建 nonce
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(file_nonce);
                nonce[8..].copy_from_slice(&(i as u32).to_le_bytes());
                
                // 构建 AAD
                let mut aad = aad_template.clone();
                aad.chunk_id = i as u64;
                let aad_bytes = aad.encode();
                
                // Decrypt
                let mut plaintext = self.cipher.decrypt(&chunk_key, &nonce, ct, &aad_bytes)?;
                
                // Apply cllX-Math inverse transform if enabled (NEW LAYER)
                if let Some(ref transform) = self.cllx_transform {
                    plaintext = transform.post_decrypt(&plaintext, file_nonce, i as u64)?;
                }
                
                // Remove masking if enabled
                let final_data = if self.enable_masking {
                    let mask = self.generate_mask(mask_key, &record.hash);
                    self.xor_mask(&plaintext, &mask)
                } else {
                    plaintext
                };
                
                // 验证 hash
                let computed_hash = blake3::hash(&final_data);
                if computed_hash.as_bytes() != &record.hash {
                    return Err(crate::core::Error::IntegrityFailed);
                }
                
                Ok(final_data)
            })
            .collect()
    }

    /// 生成 XOR mask using SHAKE256
    fn generate_mask(&self, mask_key: &[u8; 32], chunk_hash: &[u8]) -> Vec<u8> {
        let mut hasher = Shake256::default();
        hasher.update(mask_key);
        hasher.update(chunk_hash);
        let mut reader = hasher.finalize_xof();
        
        let mut mask = vec![0u8; self.chunk_size];
        reader.read(&mut mask);
        mask
    }

    /// XOR data with mask
    fn xor_mask(&self, data: &[u8], mask: &[u8]) -> Vec<u8> {
        data.iter()
            .zip(mask.iter())
            .map(|(d, m)| d ^ m)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::MasterKey;

    #[test]
    fn test_chunk_engine_v2_with_aad() {
        let data = b"Test data for chunk engine v2";
        let master = MasterKey::generate();
        let tree_root = KeyDerivation::derive_tree_root(&master).unwrap();
        let mask_key = KeyDerivation::derive_mask_key(&master).unwrap();
        let file_nonce = [0u8; 12];
        
        let aad = ChunkAAD {
            chunk_id: 0,
            container_version: 1,
            file_id: [0u8; 32],
            total_chunks: 1,
        };
        
        let engine = ChunkEngineV2::new(1024, CipherType::Aes256Gcm, true);
        let chunks = vec![data.to_vec()];
        
        let encrypted = engine.encrypt_chunks_v2(&chunks, &tree_root, &mask_key, &file_nonce, &aad).unwrap();
        let decrypted = engine.decrypt_chunks_v2(&encrypted, &tree_root, &mask_key, &file_nonce, &aad).unwrap();
        
        assert_eq!(decrypted[0], data);
    }
    
    #[test]
    fn test_chunk_engine_v2_with_cllx_math() {
        let data = b"Test data for chunk engine v2 with cllX-Math transform layer";
        let master = MasterKey::generate();
        let tree_root = KeyDerivation::derive_tree_root(&master).unwrap();
        let mask_key = KeyDerivation::derive_mask_key(&master).unwrap();
        let file_nonce = [1u8; 12];
        
        let aad = ChunkAAD {
            chunk_id: 0,
            container_version: 1,
            file_id: [1u8; 32],
            total_chunks: 1,
        };
        
        // 创建 engine with cllX-Math transform
        let engine = ChunkEngineV2::with_cllx_transform(1024, CipherType::Aes256Gcm, true, master.as_bytes()).unwrap();
        let chunks = vec![data.to_vec()];
        
        let encrypted = engine.encrypt_chunks_v2(&chunks, &tree_root, &mask_key, &file_nonce, &aad).unwrap();
        let decrypted = engine.decrypt_chunks_v2(&encrypted, &tree_root, &mask_key, &file_nonce, &aad).unwrap();
        
        assert_eq!(decrypted[0], data);
        println!("✓ cllX-Math integration test passed!");
    }
    
    #[test]
    fn test_chunk_engine_v2_cllx_math_multiple_chunks() {
        let data: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
        let master = MasterKey::generate();
        let tree_root = KeyDerivation::derive_tree_root(&master).unwrap();
        let mask_key = KeyDerivation::derive_mask_key(&master).unwrap();
        let file_nonce = [2u8; 12];
        
        let aad = ChunkAAD {
            chunk_id: 0,
            container_version: 1,
            file_id: [2u8; 32],
            total_chunks: 4,
        };
        
        // 创建 engine with cllX-Math transform
        let engine = ChunkEngineV2::with_cllx_transform(1024, CipherType::Aes256Gcm, true, master.as_bytes()).unwrap();
        
        // Split into 4 chunks
        let chunks: Vec<Vec<u8>> = data.chunks(1024).map(|c| c.to_vec()).collect();
        
        let encrypted = engine.encrypt_chunks_v2(&chunks, &tree_root, &mask_key, &file_nonce, &aad).unwrap();
        let decrypted = engine.decrypt_chunks_v2(&encrypted, &tree_root, &mask_key, &file_nonce, &aad).unwrap();
        
        // 验证 all chunks
        for (i, chunk) in chunks.iter().enumerate() {
            assert_eq!(&decrypted[i], chunk);
        }
        
        println!("✓ cllX-Math multiple chunks test passed!");
    }
}
