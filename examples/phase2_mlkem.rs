/// Phase 2 Demo: ML-KEM Capsule + Multi-Recipient
use cllx_fs_pro::core::*;
use cllx_fs_pro::capsule::mlkem::*;

fn main() -> anyhow::Result<()> {
    println!("🚀 Phase 2: ML-KEM Capsule Demo\n");
    println!("═══════════════════════════════════════\n");
    
    // ========== 1. ML-KEM Key Generation ==========
    println!("1️⃣  ML-KEM-768 Key Generation");
    let alice_keypair = MlKemKeyPair::generate()?;
    let bob_keypair = MlKemKeyPair::generate()?;
    let charlie_keypair = MlKemKeyPair::generate()?;
    
    println!("   ✓ Alice's keypair generated");
    println!("     Public key: {} bytes", alice_keypair.public_key_bytes().len());
    println!("     Secret key: {} bytes", alice_keypair.secret_key_bytes().len());
    println!("   ✓ Bob's keypair generated");
    println!("   ✓ Charlie's keypair generated\n");
    
    // ========== 2. Master Key & Mask Seed ==========
    println!("2️⃣  Master Key & Mask Seed");
    let master_key = MasterKey::generate();
    let mask_seed = [42u8; 32];
    println!("   ✓ Master key: {:02x}...", master_key.as_bytes()[0]);
    println!("   ✓ Mask seed: {:02x}...\n", mask_seed[0]);
    
    // ========== 3. Single Capsule Encapsulation ==========
    println!("3️⃣  Single Capsule Encapsulation");
    let capsule = CapsuleV2::encapsulate(
        alice_keypair.public_key_bytes(),
        &master_key,
        &mask_seed
    )?;
    
    println!("   ✓ Capsule created for Alice");
    println!("     Recipient ID: {:02x}{:02x}...", 
        capsule.recipient_id_hash[0], capsule.recipient_id_hash[1]);
    println!("     Public Ring (ciphertext): {} bytes", capsule.capsule.public_ring.len());
    println!("     Trapdoor Ring: {:02x}...", capsule.capsule.trapdoor_ring[0]);
    println!("     Mask Ring: {} bytes", capsule.capsule.mask_ring.len());
    println!("     Encrypted Master Key: {} bytes\n", capsule.encrypted_master_key.len());
    
    // ========== 4. Capsule Decapsulation ==========
    println!("4️⃣  Capsule Decapsulation");
    let (decrypted_master, decrypted_mask) = capsule.decapsulate(
        alice_keypair.secret_key_bytes()
    )?;
    
    println!("   ✓ Capsule decrypted successfully");
    println!("   ✓ Master key verified: {}", 
        master_key.as_bytes() == decrypted_master.as_bytes());
    println!("   ✓ Mask seed verified: {}\n", mask_seed == decrypted_mask);
    
    // ========== 5. Multi-Recipient Capsule ==========
    println!("5️⃣  Multi-Recipient Capsule");
    let mut multi_capsule = MultiRecipientCapsule::new();
    
    multi_capsule.add_recipient(
        alice_keypair.public_key_bytes(),
        &master_key,
        &mask_seed
    )?;
    println!("   ✓ Added Alice as recipient");
    
    multi_capsule.add_recipient(
        bob_keypair.public_key_bytes(),
        &master_key,
        &mask_seed
    )?;
    println!("   ✓ Added Bob as recipient");
    
    multi_capsule.add_recipient(
        charlie_keypair.public_key_bytes(),
        &master_key,
        &mask_seed
    )?;
    println!("   ✓ Added Charlie as recipient");
    
    println!("   ✓ Total recipients: {}\n", multi_capsule.recipient_count());
    
    // ========== 6. Multi-Recipient Decryption ==========
    println!("6️⃣  Multi-Recipient Decryption");
    
    // Alice decrypts
    let (alice_master, alice_mask) = multi_capsule.try_decrypt(
        alice_keypair.secret_key_bytes(),
        alice_keypair.public_key_bytes()
    )?;
    println!("   ✓ Alice decrypted successfully");
    assert_eq!(master_key.as_bytes(), alice_master.as_bytes());
    assert_eq!(mask_seed, alice_mask);
    
    // Bob decrypts
    let (bob_master, bob_mask) = multi_capsule.try_decrypt(
        bob_keypair.secret_key_bytes(),
        bob_keypair.public_key_bytes()
    )?;
    println!("   ✓ Bob decrypted successfully");
    assert_eq!(master_key.as_bytes(), bob_master.as_bytes());
    assert_eq!(mask_seed, bob_mask);
    
    // Charlie decrypts
    let (charlie_master, charlie_mask) = multi_capsule.try_decrypt(
        charlie_keypair.secret_key_bytes(),
        charlie_keypair.public_key_bytes()
    )?;
    println!("   ✓ Charlie decrypted successfully");
    assert_eq!(master_key.as_bytes(), charlie_master.as_bytes());
    assert_eq!(mask_seed, charlie_mask);
    
    println!("   ✓ All recipients verified!\n");
    
    // ========== 7. Three-Ring Structure ==========
    println!("7️⃣  Three-Ring Capsule Structure");
    println!("   Public Ring (ML-KEM ciphertext):");
    println!("     Size: {} bytes", capsule.capsule.public_ring.len());
    println!("     First bytes: {:02x} {:02x} {:02x}...", 
        capsule.capsule.public_ring[0],
        capsule.capsule.public_ring[1],
        capsule.capsule.public_ring[2]);
    
    println!("   Trapdoor Ring (verification):");
    println!("     Hash: {:02x}{:02x}...", 
        capsule.capsule.trapdoor_ring[0],
        capsule.capsule.trapdoor_ring[1]);
    
    println!("   Mask Ring (encrypted seed):");
    println!("     Size: {} bytes\n", capsule.capsule.mask_ring.len());
    
    // ========== 8. Security Properties ==========
    println!("8️⃣  Security Properties");
    println!("   ✓ Post-quantum secure (ML-KEM-768)");
    println!("   ✓ NIST Level 3 security");
    println!("   ✓ Trapdoor verification");
    println!("   ✓ HKDF key wrapping");
    println!("   ✓ AEAD encryption (AES-256-GCM)");
    println!("   ✓ Multi-recipient support");
    println!("   ✓ Recipient identification (Blake3)\n");
    
    // ========== Summary ==========
    println!("═══════════════════════════════════════");
    println!("✅ Phase 2 Complete!\n");
    println!("📊 Summary:");
    println!("   • ML-KEM-768 key generation: ✓");
    println!("   • Capsule encapsulation: ✓");
    println!("   • Capsule decapsulation: ✓");
    println!("   • Three-ring structure: ✓");
    println!("   • Multi-recipient support: ✓");
    println!("   • Trapdoor verification: ✓");
    println!("   • Master key + mask seed: ✓");
    println!("\n🎯 Ready for Phase 3: System-Level Capabilities");
    
    Ok(())
}
