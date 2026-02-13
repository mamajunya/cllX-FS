// cllX-Math: ChaCha20-based mask generation
// Secure, deterministic mask for XOR operation

use crate::core::Result;
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};

/// 生成 mask using ChaCha20
/// Key: K_mask (32 bytes)
/// Nonce: file_nonce (8 bytes) || chunk_id (8 bytes)
pub fn generate_mask(
    k_mask: &[u8; 32],
    file_nonce: &[u8; 12],
    chunk_id: u64,
    len: usize,
) -> Vec<u32> {
    // Combine file_nonce with chunk_id to create unique nonce per chunk
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..8].copy_from_slice(&file_nonce[..8]);
    nonce_bytes[8..].copy_from_slice(&chunk_id.to_le_bytes()[..4]);
    
    // 生成 mask bytes using ChaCha20
    let mut mask_bytes = vec![0u8; len * 4];
    let mut cipher = ChaCha20::new(k_mask.into(), &nonce_bytes.into());
    cipher.apply_keystream(&mut mask_bytes);
    
    // 转换 to u32 vector
    mask_bytes
        .chunks(4)
        .map(|bytes| {
            let mut arr = [0u8; 4];
            arr.copy_from_slice(bytes);
            u32::from_le_bytes(arr)
        })
        .collect()
}

/// Apply mask: poly[i] = (poly[i] + mask[i]) mod 2^32
pub fn apply_mask(poly: &[u32], mask: &[u32]) -> Vec<u32> {
    poly.iter()
        .zip(mask.iter())
        .map(|(&p, &m)| p.wrapping_add(m))
        .collect()
}

/// Remove mask: poly[i] = (poly[i] - mask[i]) mod 2^32
pub fn remove_mask(poly: &[u32], mask: &[u32]) -> Vec<u32> {
    poly.iter()
        .zip(mask.iter())
        .map(|(&p, &m)| p.wrapping_sub(m))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_generation() {
        let k_mask = [42u8; 32];
        let file_nonce = [1u8; 12];
        let chunk_id = 0;
        
        let mask = generate_mask(&k_mask, &file_nonce, chunk_id, 256);
        assert_eq!(mask.len(), 256);
    }

    #[test]
    fn test_mask_deterministic() {
        let k_mask = [42u8; 32];
        let file_nonce = [1u8; 12];
        let chunk_id = 5;
        
        let mask1 = generate_mask(&k_mask, &file_nonce, chunk_id, 256);
        let mask2 = generate_mask(&k_mask, &file_nonce, chunk_id, 256);
        
        assert_eq!(mask1, mask2);
    }

    #[test]
    fn test_mask_different_chunks() {
        let k_mask = [42u8; 32];
        let file_nonce = [1u8; 12];
        
        let mask1 = generate_mask(&k_mask, &file_nonce, 0, 256);
        let mask2 = generate_mask(&k_mask, &file_nonce, 1, 256);
        
        assert_ne!(mask1, mask2);
    }

    #[test]
    fn test_apply_remove_mask_roundtrip() {
        let k_mask = [42u8; 32];
        let file_nonce = [1u8; 12];
        let chunk_id = 0;
        
        let original = vec![1u32, 2, 3, 4, 5, 6, 7, 8];
        let mask = generate_mask(&k_mask, &file_nonce, chunk_id, original.len());
        
        let masked = apply_mask(&original, &mask);
        let unmasked = remove_mask(&masked, &mask);
        
        assert_eq!(original, unmasked);
    }
}
