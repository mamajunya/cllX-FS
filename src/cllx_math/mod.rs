// cllX-Math: Original mathematical transform layer
// Provides diffusion and confusion before AEAD encryption
//
// Design principles:
// - All integer operations (no floating point)
// - Completely reversible
// - No dependency on chunk content hash
// - Deterministic based on chunk_id
//
// Security model:
// - AEAD provides confidentiality and authenticity
// - cllX-Math provides additional diffusion and structural innovation

pub mod encode;
pub mod matrix;
pub mod mask;
pub mod transform;

pub use transform::CllxTransform;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cllx_math_integration() {
        let master_key = [42u8; 32];
        let transform = CllxTransform::new(&master_key).unwrap();
        
        let test_data = b"Integration test for cllX-Math layer";
        let file_nonce = [1u8; 12];
        let chunk_id = 0;
        
        // 变换 and inverse
        let transformed = transform.pre_encrypt(test_data, &file_nonce, chunk_id).unwrap();
        let recovered = transform.post_decrypt(&transformed, &file_nonce, chunk_id).unwrap();
        
        assert_eq!(&recovered[..test_data.len()], test_data);
    }
}
