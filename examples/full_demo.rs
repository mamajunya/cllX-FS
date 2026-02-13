use cllx_fs_pro::{ContainerBuilder, core::*};
use cllx_fs_pro::chunk::ChunkEngine;
use cllx_fs_pro::merkle::MerkleTree;
use cllx_fs_pro::timelock::TimeLock;
use cllx_fs_pro::antiransom::WriteJournal;
use cllx_fs_pro::dedup::RollingHash;
use cllx_fs_pro::stealth::StealthMode;

fn main() -> anyhow::Result<()> {
    println!("🔐 cllX-FS-Pro Full Demo\n");
    
    // 1. Key Derivation
    println!("1️⃣  Key Derivation");
    let master_key = MasterKey::generate();
    let tree_root = KeyDerivation::derive_tree_root(&master_key)?;
    let auth_key = KeyDerivation::derive_auth_key(&master_key)?;
    let mask_key = KeyDerivation::derive_mask_key(&master_key)?;
    println!("   ✓ Master key generated");
    println!("   ✓ Tree root derived");
    println!("   ✓ Auth key derived");
    println!("   ✓ Mask key derived\n");
    
    // 2. Chunk Encryption
    println!("2️⃣  Chunk Encryption");
    let data = b"Hello, cllX-FS-Pro! This is a secure file system.";
    let engine = ChunkEngine::new(1024, CipherType::Aes256Gcm);
    let file_nonce = [0u8; 12];
    
    let chunks: Vec<Vec<u8>> = vec![data.to_vec()];
    let original_sizes: Vec<usize> = chunks.iter().map(|c| c.len()).collect();
    
    let encrypted = engine.encrypt_chunks(&chunks, &tree_root, &file_nonce)?;
    println!("   ✓ Encrypted {} bytes", data.len());
    println!("   ✓ Ciphertext size: {} bytes", encrypted[0].len());
    
    let decrypted = engine.decrypt_chunks(&encrypted, &tree_root, &file_nonce, &original_sizes)?;
    println!("   ✓ Decrypted successfully");
    assert_eq!(decrypted[0], data);
    println!("   ✓ Data integrity verified\n");
    
    // 3. Merkle Tree
    println!("3️⃣  Merkle Tree Integrity");
    let chunk_hashes: Vec<[u8; 32]> = chunks.iter()
        .map(|c| MerkleTree::hash_chunk(c))
        .collect();
    let tree = MerkleTree::build(&chunk_hashes);
    println!("   ✓ Merkle tree built");
    println!("   ✓ Root hash: {:02x}...", tree.root_hash[0]);
    println!("   ✓ Chunk verification: {}\n", tree.verify_chunk(0, &chunk_hashes[0]));
    
    // 4. Container Builder
    println!("4️⃣  Container Creation");
    let container = ContainerBuilder::new()
        .chunk_size(1024 * 1024)
        .anti_ransom(true)
        .stealth_mode(false)
        .timelock(false)
        .dedup(true)
        .build()?;
    println!("   ✓ Container created");
    println!("   ✓ Chunk size: {} bytes", container.header.chunk_size);
    println!("   ✓ Anti-ransomware: {}", container.policy.anti_ransom_mode);
    println!("   ✓ Dedup mode: {}\n", container.policy.dedup_mode);
    
    // 5. Anti-Ransomware
    println!("5️⃣  Anti-Ransomware Protection");
    let mut journal = WriteJournal::new(100);
    journal.record_write(0, data)?;
    println!("   ✓ Write operation logged");
    println!("   ✓ Journal entries: {}", journal.entries.len());
    println!("   ✓ Write count: {}\n", journal.write_count);
    
    // 6. Time-Lock
    println!("6️⃣  Time-Lock Encryption");
    let future_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() + 3600; // 1 hour from now
    let timelock = TimeLock::new(future_time);
    println!("   ✓ Time-lock created");
    println!("   ✓ Unlock time: {} (Unix timestamp)", timelock.unlock_time);
    println!("   ✓ Currently locked: {}\n", !timelock.is_unlocked());
    
    // 7. Deduplication
    println!("7️⃣  Deduplication");
    let rolling = RollingHash::new(64);
    let fingerprint = rolling.fingerprint(data);
    println!("   ✓ Rolling hash computed");
    println!("   ✓ Fingerprint: 0x{:016x}", fingerprint);
    
    let boundaries = rolling.find_boundaries(data, 16);
    println!("   ✓ Content-defined chunks: {}\n", boundaries.len() - 1);
    
    // 8. Stealth Mode
    println!("8️⃣  Stealth Mode");
    let offset = StealthMode::calculate_header_offset(&master_key, 1024 * 1024);
    println!("   ✓ Pseudo-random offset: {}", offset);
    
    let padding = StealthMode::generate_padding(32, &[0u8; 32]);
    println!("   ✓ Random padding generated: {} bytes\n", padding.len());
    
    println!("✅ All features demonstrated successfully!");
    println!("\n📊 Summary:");
    println!("   • Encryption: AES-256-GCM ✓");
    println!("   • Key derivation: HKDF-SHA3 ✓");
    println!("   • Integrity: Merkle Tree (Blake3) ✓");
    println!("   • Anti-ransomware: Write journaling ✓");
    println!("   • Time-lock: Timestamp-based ✓");
    println!("   • Dedup: Rolling hash ✓");
    println!("   • Stealth: Obfuscated container ✓");
    
    Ok(())
}
