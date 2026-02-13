pub mod engine;

use crate::core::{Result, AeadCipher, CipherType, KeyDerivation};
use rayon::prelude::*;

pub use engine::{ChunkEngineV2, ChunkAAD};

pub struct ChunkEngine {
    chunk_size: usize,
    cipher: AeadCipher,
}

impl ChunkEngine {
    pub fn new(chunk_size: usize, cipher_type: CipherType) -> Self {
        Self {
            chunk_size,
            cipher: AeadCipher::new(cipher_type),
        }
    }

    /// Split data into chunks
    pub fn split<'a>(&self, data: &'a [u8]) -> Vec<&'a [u8]> {
        data.chunks(self.chunk_size).collect()
    }

    /// 加密 all chunks in parallel
    pub fn encrypt_chunks(
        &self,
        chunks: &[Vec<u8>],
        tree_root_key: &[u8; 32],
        file_nonce: &[u8; 12],
    ) -> Result<Vec<Vec<u8>>> {
        chunks
            .par_iter()
            .enumerate()
            .map(|(i, chunk)| {
                let chunk_key = KeyDerivation::derive_chunk_key(tree_root_key, i as u64)?;
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(file_nonce);
                // Mix chunk index into nonce
                nonce[8..].copy_from_slice(&(i as u32).to_le_bytes());
                
                let aad = Self::build_aad(i as u64, chunk.len());
                self.cipher.encrypt(&chunk_key, &nonce, chunk, &aad)
            })
            .collect()
    }

    /// 解密 all chunks in parallel
    pub fn decrypt_chunks(
        &self,
        ciphertexts: &[Vec<u8>],
        tree_root_key: &[u8; 32],
        file_nonce: &[u8; 12],
        original_sizes: &[usize],
    ) -> Result<Vec<Vec<u8>>> {
        ciphertexts
            .par_iter()
            .enumerate()
            .map(|(i, ct)| {
                let chunk_key = KeyDerivation::derive_chunk_key(tree_root_key, i as u64)?;
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(file_nonce);
                nonce[8..].copy_from_slice(&(i as u32).to_le_bytes());
                
                let original_size = original_sizes.get(i).copied().unwrap_or(0);
                let aad = Self::build_aad(i as u64, original_size);
                self.cipher.decrypt(&chunk_key, &nonce, ct, &aad)
            })
            .collect()
    }

    fn build_aad(chunk_id: u64, size: usize) -> Vec<u8> {
        let mut aad = Vec::with_capacity(16);
        aad.extend_from_slice(&chunk_id.to_le_bytes());
        aad.extend_from_slice(&(size as u64).to_le_bytes());
        aad
    }
}
