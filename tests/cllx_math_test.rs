// Integration test for cllX-Math layer
// Verifies complete reversibility: original -> transform -> inverse -> original

use cllx_fs_pro::cllx_math::CllxTransform;

#[test]
fn test_cllx_math_basic_roundtrip() {
    let master_key = [42u8; 32];
    let transform = CllxTransform::new(&master_key).unwrap();
    
    let original = b"Hello, cllX-FS! This is a basic test.";
    let file_nonce = [1u8; 12];
    let chunk_id = 0;
    
    // Transform
    let transformed = transform.pre_encrypt(original, &file_nonce, chunk_id).unwrap();
    
    // Inverse transform
    let recovered = transform.post_decrypt(&transformed, &file_nonce, chunk_id).unwrap();
    
    // 验证 exact match
    assert_eq!(&recovered[..original.len()], original, "Basic roundtrip failed!");
    println!("✓ Basic roundtrip test passed");
}

#[test]
fn test_cllx_math_random_data() {
    let master_key = [123u8; 32];
    let transform = CllxTransform::new(&master_key).unwrap();
    
    // 生成 random-like data
    let original: Vec<u8> = (0..1024).map(|i| ((i * 7 + 13) % 256) as u8).collect();
    let file_nonce = [2u8; 12];
    let chunk_id = 5;
    
    let transformed = transform.pre_encrypt(&original, &file_nonce, chunk_id).unwrap();
    let recovered = transform.post_decrypt(&transformed, &file_nonce, chunk_id).unwrap();
    
    assert_eq!(&recovered[..original.len()], &original[..], "Random data roundtrip failed!");
    println!("✓ Random data test passed");
}

#[test]
fn test_cllx_math_large_chunk() {
    let master_key = [255u8; 32];
    let transform = CllxTransform::new(&master_key).unwrap();
    
    // 64KB chunk
    let original: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();
    let file_nonce = [3u8; 12];
    let chunk_id = 10;
    
    let transformed = transform.pre_encrypt(&original, &file_nonce, chunk_id).unwrap();
    let recovered = transform.post_decrypt(&transformed, &file_nonce, chunk_id).unwrap();
    
    assert_eq!(&recovered[..original.len()], &original[..], "Large chunk roundtrip failed!");
    println!("✓ Large chunk test passed (64KB)");
}

#[test]
fn test_cllx_math_different_chunks_different_output() {
    let master_key = [42u8; 32];
    let transform = CllxTransform::new(&master_key).unwrap();
    
    let data = b"Same data for both chunks";
    let file_nonce = [1u8; 12];
    
    let t1 = transform.pre_encrypt(data, &file_nonce, 0).unwrap();
    let t2 = transform.pre_encrypt(data, &file_nonce, 1).unwrap();
    
    // Same data with different chunk_id should produce different output
    assert_ne!(t1, t2, "Different chunk IDs should produce different outputs!");
    println!("✓ Different chunk IDs produce different outputs");
}

#[test]
fn test_cllx_math_all_zeros() {
    let master_key = [42u8; 32];
    let transform = CllxTransform::new(&master_key).unwrap();
    
    let original = vec![0u8; 1024];
    let file_nonce = [1u8; 12];
    let chunk_id = 0;
    
    let transformed = transform.pre_encrypt(&original, &file_nonce, chunk_id).unwrap();
    let recovered = transform.post_decrypt(&transformed, &file_nonce, chunk_id).unwrap();
    
    assert_eq!(&recovered[..original.len()], &original[..], "All zeros roundtrip failed!");
    println!("✓ All zeros test passed");
}

#[test]
fn test_cllx_math_all_ones() {
    let master_key = [42u8; 32];
    let transform = CllxTransform::new(&master_key).unwrap();
    
    let original = vec![0xFFu8; 1024];
    let file_nonce = [1u8; 12];
    let chunk_id = 0;
    
    let transformed = transform.pre_encrypt(&original, &file_nonce, chunk_id).unwrap();
    let recovered = transform.post_decrypt(&transformed, &file_nonce, chunk_id).unwrap();
    
    assert_eq!(&recovered[..original.len()], &original[..], "All ones roundtrip failed!");
    println!("✓ All ones test passed");
}

#[test]
fn test_cllx_math_multiple_chunks_sequence() {
    let master_key = [42u8; 32];
    let transform = CllxTransform::new(&master_key).unwrap();
    
    let file_nonce = [1u8; 12];
    
    // Simulate multiple chunks from a file
    for chunk_id in 0..10 {
        let original: Vec<u8> = (0..512).map(|i| ((i + chunk_id * 100) % 256) as u8).collect();
        
        let transformed = transform.pre_encrypt(&original, &file_nonce, chunk_id as u64).unwrap();
        let recovered = transform.post_decrypt(&transformed, &file_nonce, chunk_id as u64).unwrap();
        
        assert_eq!(&recovered[..original.len()], &original[..], 
                   "Chunk {} roundtrip failed!", chunk_id);
    }
    
    println!("✓ Multiple chunks sequence test passed (10 chunks)");
}

#[test]
fn test_cllx_math_real_world_text() {
    let master_key = [42u8; 32];
    let transform = CllxTransform::new(&master_key).unwrap();
    
    let original = b"The quick brown fox jumps over the lazy dog. \
                     This is a real-world text example with punctuation, \
                     numbers like 12345, and special chars: !@#$%^&*()";
    let file_nonce = [1u8; 12];
    let chunk_id = 0;
    
    let transformed = transform.pre_encrypt(original, &file_nonce, chunk_id).unwrap();
    let recovered = transform.post_decrypt(&transformed, &file_nonce, chunk_id).unwrap();
    
    assert_eq!(&recovered[..original.len()], original, "Real-world text roundtrip failed!");
    println!("✓ Real-world text test passed");
}
