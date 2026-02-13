// cllX-Math: Main transform interface
// Combines encoding, diffusion, and masking

use crate::core::Result;
use super::encode::{encode_chunk, decode_chunk};
use super::matrix::DiffusionMatrix;
use super::mask::{generate_mask, apply_mask, remove_mask};

/// cllX-Math Transform
pub struct CllxTransform {
    matrix: DiffusionMatrix,
    k_mask: [u8; 32],
}

impl CllxTransform {
    /// 创建 new transform from master key
    pub fn new(master_key: &[u8; 32]) -> Result<Self> {
        // Derive matrix seed from master key
        let matrix_seed = Self::derive_matrix_seed(master_key);
        
        // Derive mask key from master key
        let k_mask = Self::derive_mask_key(master_key);
        
        // 生成 diffusion matrix (16x16 for now)
        let matrix = DiffusionMatrix::generate(&matrix_seed, 16)?;
        
        Ok(Self { matrix, k_mask })
    }
    
    /// Pre-encrypt transform: chunk -> cllX-Math -> ready for AEAD
    pub fn pre_encrypt(
        &self,
        chunk: &[u8],
        file_nonce: &[u8; 12],
        chunk_id: u64,
    ) -> Result<Vec<u8>> {
        // 1. Encode to polynomial
        let poly = encode_chunk(chunk);
        
        // 2. Apply diffusion
        let poly1 = self.matrix.diffuse(&poly);
        
        // 3. Generate and apply mask
        let mask = generate_mask(&self.k_mask, file_nonce, chunk_id, poly1.len());
        let poly2 = apply_mask(&poly1, &mask);
        
        // 4. Decode back to bytes
        Ok(decode_chunk(&poly2))
    }
    
    /// Post-decrypt transform: AEAD output -> cllX-Math inverse -> original chunk
    pub fn post_decrypt(
        &self,
        data: &[u8],
        file_nonce: &[u8; 12],
        chunk_id: u64,
    ) -> Result<Vec<u8>> {
        // 1. Encode to polynomial
        let poly2 = encode_chunk(data);
        
        // 2. Generate and remove mask
        let mask = generate_mask(&self.k_mask, file_nonce, chunk_id, poly2.len());
        let poly1 = remove_mask(&poly2, &mask);
        
        // 3. Apply inverse diffusion
        let poly = self.matrix.diffuse_inv(&poly1);
        
        // 4. Decode back to bytes
        Ok(decode_chunk(&poly))
    }
    
    /// Derive matrix seed using HKDF
    fn derive_matrix_seed(master_key: &[u8; 32]) -> [u8; 32] {
        use hkdf::Hkdf;
        use sha3::Sha3_256;
        
        let hk = Hkdf::<Sha3_256>::new(None, master_key);
        let mut seed = [0u8; 32];
        hk.expand(b"cllx_matrix", &mut seed)
            .expect("HKDF expand failed");
        seed
    }
    
    /// Derive mask key using HKDF
    fn derive_mask_key(master_key: &[u8; 32]) -> [u8; 32] {
        use hkdf::Hkdf;
        use sha3::Sha3_256;
        
        let hk = Hkdf::<Sha3_256>::new(None, master_key);
        let mut key = [0u8; 32];
        hk.expand(b"cllx_mask", &mut key)
            .expect("HKDF expand failed");
        key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transform_roundtrip() {
        let master_key = [42u8; 32];
        let transform = CllxTransform::new(&master_key).unwrap();
        
        let original = b"Hello, cllX-FS! This is a test message for the transform.";
        let file_nonce = [1u8; 12];
        let chunk_id = 0;
        
        // Pre-encrypt
        let transformed = transform.pre_encrypt(original, &file_nonce, chunk_id).unwrap();
        
        // Post-decrypt
        let recovered = transform.post_decrypt(&transformed, &file_nonce, chunk_id).unwrap();
        
        // Verify
        assert_eq!(&recovered[..original.len()], original);
    }

    #[test]
    fn test_transform_different_chunks() {
        let master_key = [42u8; 32];
        let transform = CllxTransform::new(&master_key).unwrap();
        
        let chunk1 = b"Chunk 1 data";
        let chunk2 = b"Chunk 2 data";
        let file_nonce = [1u8; 12];
        
        let t1 = transform.pre_encrypt(chunk1, &file_nonce, 0).unwrap();
        let t2 = transform.pre_encrypt(chunk2, &file_nonce, 1).unwrap();
        
        // Different chunks should produce different outputs
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_transform_large_chunk() {
        let master_key = [42u8; 32];
        let transform = CllxTransform::new(&master_key).unwrap();
        
        // 1MB chunk
        let original: Vec<u8> = (0..1048576).map(|i| (i % 256) as u8).collect();
        let file_nonce = [1u8; 12];
        let chunk_id = 0;
        
        let transformed = transform.pre_encrypt(&original, &file_nonce, chunk_id).unwrap();
        let recovered = transform.post_decrypt(&transformed, &file_nonce, chunk_id).unwrap();
        
        assert_eq!(recovered[..original.len()], original[..]);
    }
}
