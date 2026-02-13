use cllx_fs_pro::core::{MasterKey, KeyDerivation, AeadCipher, CipherType};
use cllx_fs_pro::chunk::ChunkEngine;
use cllx_fs_pro::merkle::MerkleTree;

#[test]
fn test_key_derivation() {
    let master = MasterKey::generate();
    let tree_root = KeyDerivation::derive_tree_root(&master).unwrap();
    let chunk_key = KeyDerivation::derive_chunk_key(&tree_root, 0).unwrap();
    
    assert_eq!(tree_root.len(), 32);
    assert_eq!(chunk_key.len(), 32);
}

#[test]
fn test_chunk_encryption() {
    let data = b"Hello, cllX-FS-Pro!";
    let master = MasterKey::generate();
    let tree_root = KeyDerivation::derive_tree_root(&master).unwrap();
    let file_nonce = [0u8; 12];
    
    let engine = ChunkEngine::new(1024, CipherType::Aes256Gcm);
    let chunks: Vec<Vec<u8>> = vec![data.to_vec()];
    let original_sizes: Vec<usize> = chunks.iter().map(|c| c.len()).collect();
    
    let encrypted = engine.encrypt_chunks(&chunks, &tree_root, &file_nonce).unwrap();
    let decrypted = engine.decrypt_chunks(&encrypted, &tree_root, &file_nonce, &original_sizes).unwrap();
    
    assert_eq!(decrypted[0], data);
}

#[test]
fn test_merkle_tree() {
    let chunk1 = b"chunk 1";
    let chunk2 = b"chunk 2";
    
    let hash1 = MerkleTree::hash_chunk(chunk1);
    let hash2 = MerkleTree::hash_chunk(chunk2);
    
    let tree = MerkleTree::build(&[hash1, hash2]);
    
    assert!(tree.verify_chunk(0, &hash1));
    assert!(tree.verify_chunk(1, &hash2));
}
