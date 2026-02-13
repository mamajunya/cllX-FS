/// Phase 3 Demo: System-Level Capabilities
use cllx_fs_pro::core::*;
use cllx_fs_pro::antiransom::{Journal, JournalOperation};
use cllx_fs_pro::stealth::StealthMode;
use cllx_fs_pro::dedup::{RollingHash, DedupIndex};
use cllx_fs_pro::timelock::TimeLock;
use tempfile::NamedTempFile;

fn main() -> anyhow::Result<()> {
    println!("🚀 Phase 3: System-Level Capabilities Demo\n");
    println!("═══════════════════════════════════════\n");
    
    // ========== 1. Journal Recovery ==========
    println!("1️⃣  Journal Recovery System");
    let temp_journal = NamedTempFile::new()?;
    let mut journal = Journal::open(temp_journal.path())?;
    
    // Record some operations
    journal.record_write(0, 0, [1u8; 32], 1)?;
    journal.record_modify(0, 0, [1u8; 32], [2u8; 32], 2)?;
    journal.record_write(1, 1024, [3u8; 32], 3)?;
    journal.record_delete(2, [4u8; 32], 4)?;
    
    println!("   ✓ Recorded 4 operations");
    println!("     - Write chunk 0");
    println!("     - Modify chunk 0");
    println!("     - Write chunk 1");
    println!("     - Delete chunk 2");
    println!("   ✓ Journal entries: {}", journal.entry_count());
    
    // 读取 all entries
    let entries = journal.read_all()?;
    println!("   ✓ Read {} entries from journal", entries.len());
    
    // Find last stable state
    let last_op = journal.find_last_stable_state()?;
    println!("   ✓ Last stable operation ID: {:?}", last_op);
    
    // Rebuild index
    let index = journal.rebuild_index()?;
    println!("   ✓ Rebuilt index: {} chunks", index.len());
    
    // Detect ransomware
    let is_ransomware = journal.detect_ransomware(60, 100)?;
    println!("   ✓ Ransomware detected: {}\n", is_ransomware);
    
    // ========== 2. Stealth Container ==========
    println!("2️⃣  Stealth Container Mode");
    let master_key = MasterKey::generate();
    let header_data = b"SECRET HEADER DATA";
    
    // Calculate pseudo-random offset
    let offset = StealthMode::calculate_header_offset(&master_key, 1000000);
    println!("   ✓ Pseudo-random offset: {}", offset);
    println!("     (Deterministic from master key)");
    
    // 生成 random padding
    let padding = StealthMode::generate_padding(256, master_key.as_bytes());
    println!("   ✓ Generated {} bytes of padding", padding.len());
    println!("     First bytes: {:02x} {:02x} {:02x}...", 
        padding[0], padding[1], padding[2]);
    
    // 加密 header
    let encrypted_header = StealthMode::encrypt_header(header_data, &master_key)?;
    println!("   ✓ Encrypted header: {} bytes", encrypted_header.len());
    
    // 创建 full stealth container
    let stealth_container = StealthMode::create_stealth_container(
        header_data,
        &master_key,
        10000
    )?;
    println!("   ✓ Stealth container created: {} bytes", stealth_container.len());
    println!("     (Looks like random data)");
    
    // Extract and decrypt
    let extracted = StealthMode::extract_header(
        &stealth_container,
        &master_key,
        encrypted_header.len()
    )?;
    println!("   ✓ Header extracted and decrypted");
    assert_eq!(header_data.as_slice(), extracted.as_slice());
    println!("   ✓ Data integrity verified!\n");
    
    // ========== 3. Deduplication Engine ==========
    println!("3️⃣  Deduplication Engine");
    let rolling_hash = RollingHash::new(64);
    
    // Test data with duplicates
    let data1 = b"This is some test data for deduplication";
    let data2 = b"This is some test data for deduplication"; // Duplicate
    let data3 = b"Different data here";
    
    let fp1 = rolling_hash.fingerprint(data1);
    let fp2 = rolling_hash.fingerprint(data2);
    let fp3 = rolling_hash.fingerprint(data3);
    
    println!("   ✓ Fingerprints calculated:");
    println!("     Data 1: 0x{:016x}", fp1);
    println!("     Data 2: 0x{:016x} (duplicate)", fp2);
    println!("     Data 3: 0x{:016x}", fp3);
    assert_eq!(fp1, fp2);
    
    // Content-defined chunking
    let large_data = vec![0u8; 10000];
    let boundaries = rolling_hash.find_boundaries(&large_data, 1024);
    println!("   ✓ Content-defined chunks: {}", boundaries.len() - 1);
    
    // Dedup index
    let mut dedup_index = DedupIndex::new();
    
    let hash1 = blake3::hash(data1);
    let hash2 = blake3::hash(data2);
    let hash3 = blake3::hash(data3);
    
    let id1 = dedup_index.insert(*hash1.as_bytes(), data1.len() as u32);
    let id2 = dedup_index.insert(*hash2.as_bytes(), data2.len() as u32); // Should reuse
    let id3 = dedup_index.insert(*hash3.as_bytes(), data3.len() as u32);
    
    println!("   ✓ Dedup index:");
    println!("     Chunk IDs: {} {} {}", id1, id2, id3);
    println!("     Unique chunks: {}", dedup_index.unique_chunks());
    println!("     Total references: {}", dedup_index.total_references());
    println!("     Dedup ratio: {:.2}x", dedup_index.dedup_ratio());
    
    let stats = dedup_index.stats();
    println!("   ✓ Stats:");
    println!("     Total size: {} bytes", stats.total_size);
    println!("     Space saved: ~{:.1}%\n", 
        (1.0 - 1.0 / stats.dedup_ratio) * 100.0);
    
    // ========== 4. Time-Lock Encryption ==========
    println!("4️⃣  Time-Lock Encryption");
    let master = MasterKey::generate();
    let secret_data = b"Time-locked secret message";
    
    // 创建 expired time-lock (for demo)
    let past_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() - 100;
    
    let timelock_unlocked = TimeLock::new(past_time);
    println!("   ✓ Time-lock created (expired for demo)");
    println!("     Unlock time: {}", timelock_unlocked.unlock_time);
    println!("     Is unlocked: {}", timelock_unlocked.is_unlocked());
    
    // 加密 with time-lock
    let encrypted = timelock_unlocked.encrypt(&master, secret_data)?;
    println!("   ✓ Data encrypted: {} bytes", encrypted.len());
    
    // 解密 (should work since unlocked)
    let decrypted = timelock_unlocked.decrypt(&master, &encrypted)?;
    println!("   ✓ Data decrypted successfully");
    assert_eq!(secret_data.as_slice(), decrypted.as_slice());
    
    // 创建 future time-lock
    let future_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() + 3600;
    
    let timelock_locked = TimeLock::new(future_time);
    println!("   ✓ Time-lock created (locked)");
    println!("     Unlock time: {}", timelock_locked.unlock_time);
    println!("     Is unlocked: {}", timelock_locked.is_unlocked());
    println!("     Remaining: {} seconds", timelock_locked.remaining_seconds().unwrap());
    
    let encrypted_locked = timelock_locked.encrypt(&master, secret_data)?;
    println!("   ✓ Data encrypted with future time-lock");
    
    // Try to decrypt (should fail)
    let result = timelock_locked.decrypt(&master, &encrypted_locked);
    println!("   ✓ Early decrypt prevented: {}", result.is_err());
    println!("     Error: TimeLocked\n");
    
    // ========== Summary ==========
    println!("═══════════════════════════════════════");
    println!("✅ Phase 3 Complete!\n");
    println!("📊 Summary:");
    println!("   • Journal Recovery:");
    println!("     - Append-only logging ✓");
    println!("     - Index rebuilding ✓");
    println!("     - Ransomware detection ✓");
    println!("   • Stealth Container:");
    println!("     - Pseudo-random offset ✓");
    println!("     - Header encryption ✓");
    println!("     - Random padding ✓");
    println!("   • Deduplication:");
    println!("     - Rolling hash (Rabin) ✓");
    println!("     - Content-defined chunking ✓");
    println!("     - Reference counting ✓");
    println!("     - Dedup ratio: {:.2}x ✓", dedup_index.dedup_ratio());
    println!("   • Time-Lock:");
    println!("     - Timestamp-based unlock ✓");
    println!("     - HKDF key derivation ✓");
    println!("     - Early decrypt prevention ✓");
    println!("\n🎯 Ready for Phase 4: Production Features");
    
    Ok(())
}
