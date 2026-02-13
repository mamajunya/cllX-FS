use sha3::{Digest, Sha3_256};
use crate::core::{Result, MasterKey};

/// Stealth mode - hide container structure
pub struct StealthMode;

impl StealthMode {
    /// Calculate pseudo-random header offset
    pub fn calculate_header_offset(master_key: &MasterKey, max_offset: u64) -> u64 {
        let mut hasher = Sha3_256::new();
        hasher.update(b"cllx-stealth-offset");
        hasher.update(master_key.as_bytes());
        let hash = hasher.finalize();
        
        let offset_bytes = &hash[0..8];
        let offset = u64::from_le_bytes(offset_bytes.try_into().unwrap());
        offset % max_offset
    }

    /// 生成 random padding
    pub fn generate_padding(size: usize, seed: &[u8]) -> Vec<u8> {
        use sha3::Shake256;
        use sha3::digest::{Update, ExtendableOutput, XofReader};
        
        let mut hasher = Shake256::default();
        hasher.update(seed);
        let mut reader = hasher.finalize_xof();
        
        let mut padding = vec![0u8; size];
        reader.read(&mut padding);
        padding
    }

    /// 加密 header for stealth mode
    pub fn encrypt_header(header_bytes: &[u8], master_key: &MasterKey) -> Result<Vec<u8>> {
        use crate::core::crypto::{AeadCipher, CipherType};
        
        let cipher = AeadCipher::new(CipherType::Aes256Gcm);
        let nonce = [0u8; 12]; // Deterministic nonce for header
        
        cipher.encrypt(
            master_key.as_bytes(),
            &nonce,
            header_bytes,
            b"cllx-stealth-header"
        )
    }

    /// 解密 header from stealth mode
    pub fn decrypt_header(encrypted_header: &[u8], master_key: &MasterKey) -> Result<Vec<u8>> {
        use crate::core::crypto::{AeadCipher, CipherType};
        
        let cipher = AeadCipher::new(CipherType::Aes256Gcm);
        let nonce = [0u8; 12];
        
        cipher.decrypt(
            master_key.as_bytes(),
            &nonce,
            encrypted_header,
            b"cllx-stealth-header"
        )
    }

    /// 创建 stealth container with obfuscation
    pub fn create_stealth_container(
        header_bytes: &[u8],
        master_key: &MasterKey,
        total_size: u64,
    ) -> Result<Vec<u8>> {
        // Calculate pseudo-random offset
        let max_offset = (total_size / 2).min(1024 * 1024); // Max 1MB offset
        let header_offset = Self::calculate_header_offset(master_key, max_offset);
        
        // 生成 padding before header
        let mut seed_before = Vec::new();
        seed_before.extend_from_slice(master_key.as_bytes());
        seed_before.extend_from_slice(b"before");
        let padding_before = Self::generate_padding(header_offset as usize, &seed_before);
        
        // 加密 header
        let encrypted_header = Self::encrypt_header(header_bytes, master_key)?;
        
        // 生成 padding after header
        let remaining = total_size.saturating_sub(header_offset + encrypted_header.len() as u64);
        let mut seed_after = Vec::new();
        seed_after.extend_from_slice(master_key.as_bytes());
        seed_after.extend_from_slice(b"after");
        let padding_after = Self::generate_padding(remaining as usize, &seed_after);
        
        // Combine all parts
        let mut container = Vec::new();
        container.extend_from_slice(&padding_before);
        container.extend_from_slice(&encrypted_header);
        container.extend_from_slice(&padding_after);
        
        Ok(container)
    }

    /// Extract header from stealth container
    pub fn extract_header(
        container: &[u8],
        master_key: &MasterKey,
        header_size: usize,
    ) -> Result<Vec<u8>> {
        // Calculate offset
        let max_offset = (container.len() / 2).min(1024 * 1024);
        let header_offset = Self::calculate_header_offset(master_key, max_offset as u64) as usize;
        
        // Extract encrypted header
        let encrypted_header = &container[header_offset..header_offset + header_size];
        
        // 解密 header
        Self::decrypt_header(encrypted_header, master_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_offset_deterministic() {
        let master = MasterKey::generate();
        let offset1 = StealthMode::calculate_header_offset(&master, 1000000);
        let offset2 = StealthMode::calculate_header_offset(&master, 1000000);
        assert_eq!(offset1, offset2);
    }

    #[test]
    fn test_header_encryption() {
        let master = MasterKey::generate();
        let header = b"test header data";
        
        let encrypted = StealthMode::encrypt_header(header, &master).unwrap();
        let decrypted = StealthMode::decrypt_header(&encrypted, &master).unwrap();
        
        assert_eq!(header.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_stealth_container_roundtrip() {
        let master = MasterKey::generate();
        let header = b"my secret header";
        
        let container = StealthMode::create_stealth_container(
            header,
            &master,
            10000
        ).unwrap();
        
        // Container should look random
        assert!(container.len() >= 10000);
        
        // Extract and decrypt
        let encrypted_size = StealthMode::encrypt_header(header, &master).unwrap().len();
        let extracted = StealthMode::extract_header(&container, &master, encrypted_size).unwrap();
        
        assert_eq!(header.as_slice(), extracted.as_slice());
    }
}

