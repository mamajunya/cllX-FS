use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::core::{Result, Error, MasterKey};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeLock {
    pub unlock_time: u64,  // Unix timestamp
    pub time_salt: [u8; 32],
}

impl TimeLock {
    pub fn new(unlock_time: u64) -> Self {
        let mut time_salt = [0u8; 32];
        rand::Rng::fill(&mut rand::thread_rng(), &mut time_salt);
        
        Self {
            unlock_time,
            time_salt,
        }
    }

    /// 创建 time-lock with duration from now
    pub fn from_duration(duration_seconds: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self::new(now + duration_seconds)
    }

    /// Check if time-lock has expired
    pub fn is_unlocked(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now >= self.unlock_time
    }

    /// Get remaining time in seconds
    pub fn remaining_seconds(&self) -> Option<u64> {
        if self.is_unlocked() {
            None
        } else {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            Some(self.unlock_time - now)
        }
    }

    /// Derive time-locked key
    pub fn derive_key(&self, master_key: &MasterKey) -> Result<[u8; 32]> {
        if !self.is_unlocked() {
            return Err(Error::TimeLocked);
        }
        
        // Combine master key with time proof
        let mut ikm = Vec::new();
        ikm.extend_from_slice(master_key.as_bytes());
        ikm.extend_from_slice(&self.unlock_time.to_le_bytes());
        ikm.extend_from_slice(&self.time_salt);
        
        use hkdf::Hkdf;
        use sha3::Sha3_256;
        let hk = Hkdf::<Sha3_256>::new(None, &ikm);
        let mut okm = [0u8; 32];
        hk.expand(b"cllx-timelock", &mut okm)
            .map_err(|e| Error::Crypto(format!("Time-lock HKDF failed: {}", e)))?;
        Ok(okm)
    }

    /// 加密 data with time-lock
    pub fn encrypt(&self, master_key: &MasterKey, data: &[u8]) -> Result<Vec<u8>> {
        use crate::core::crypto::{AeadCipher, CipherType};
        
        // Derive time-locked key (without checking if unlocked)
        let mut ikm = Vec::new();
        ikm.extend_from_slice(master_key.as_bytes());
        ikm.extend_from_slice(&self.unlock_time.to_le_bytes());
        ikm.extend_from_slice(&self.time_salt);
        
        use hkdf::Hkdf;
        use sha3::Sha3_256;
        let hk = Hkdf::<Sha3_256>::new(None, &ikm);
        let mut key = [0u8; 32];
        hk.expand(b"cllx-timelock", &mut key)
            .map_err(|e| Error::Crypto(format!("Time-lock HKDF failed: {}", e)))?;
        
        let cipher = AeadCipher::new(CipherType::Aes256Gcm);
        let nonce = [0u8; 12];
        
        cipher.encrypt(&key, &nonce, data, b"cllx-timelock-data")
    }

    /// 解密 data with time-lock (only if unlocked)
    pub fn decrypt(&self, master_key: &MasterKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if !self.is_unlocked() {
            return Err(Error::TimeLocked);
        }
        
        use crate::core::crypto::{AeadCipher, CipherType};
        
        let key = self.derive_key(master_key)?;
        let cipher = AeadCipher::new(CipherType::Aes256Gcm);
        let nonce = [0u8; 12];
        
        cipher.decrypt(&key, &nonce, ciphertext, b"cllx-timelock-data")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timelock_unlocked() {
        // 创建 time-lock that's already expired
        let past_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() - 100;
        
        let timelock = TimeLock::new(past_time);
        assert!(timelock.is_unlocked());
        assert!(timelock.remaining_seconds().is_none());
    }

    #[test]
    fn test_timelock_locked() {
        // 创建 time-lock for future
        let future_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() + 3600;
        
        let timelock = TimeLock::new(future_time);
        assert!(!timelock.is_unlocked());
        assert!(timelock.remaining_seconds().is_some());
    }

    #[test]
    fn test_timelock_encrypt_decrypt() {
        let master = MasterKey::generate();
        let data = b"secret data";
        
        // 创建 expired time-lock
        let past_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() - 100;
        
        let timelock = TimeLock::new(past_time);
        
        let encrypted = timelock.encrypt(&master, data).unwrap();
        let decrypted = timelock.decrypt(&master, &encrypted).unwrap();
        
        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_timelock_prevents_early_decrypt() {
        let master = MasterKey::generate();
        let data = b"secret data";
        
        // 创建 future time-lock
        let future_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() + 3600;
        
        let timelock = TimeLock::new(future_time);
        
        let encrypted = timelock.encrypt(&master, data).unwrap();
        
        // Should fail to decrypt
        let result = timelock.decrypt(&master, &encrypted);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::TimeLocked));
    }
}
