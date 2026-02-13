use pqc_ml_kem::{ML_KEM_512, ML_KEM_768, ML_KEM_1024};
use crate::core::{Result, Error, MasterKey};
use crate::core::crypto::{AeadCipher, CipherType};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ML-KEM-768 parameters (NIST Level 3 security)
pub const MLKEM_PUBLIC_KEY_SIZE: usize = 1184;
pub const MLKEM_SECRET_KEY_SIZE: usize = 2400;
pub const MLKEM_CIPHERTEXT_SIZE: usize = 1088;
pub const MLKEM_SHARED_SECRET_SIZE: usize = 32;

/// ML-KEM Key Pair
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKemKeyPair {
    #[zeroize(skip)]
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl MlKemKeyPair {
    /// 生成 a new ML-KEM-768 key pair
    pub fn generate() -> Result<Self> {
        let (ek, dk) = ML_KEM_768.keygen();
        
        Ok(Self {
            public_key: ek,
            secret_key: dk,
        })
    }

    /// Get public key bytes
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }

    /// Get secret key bytes
    pub fn secret_key_bytes(&self) -> &[u8] {
        &self.secret_key
    }
    
    /// 创建 from existing secret key bytes
    pub fn from_secret_key(secret_key: Vec<u8>) -> Result<Self> {
        if secret_key.len() != MLKEM_SECRET_KEY_SIZE {
            return Err(Error::InvalidInput(format!(
                "Invalid secret key size: expected {}, got {}",
                MLKEM_SECRET_KEY_SIZE,
                secret_key.len()
            )));
        }
        
        // Extract public key from secret key
        // ML-KEM-768 secret key format includes the public key
        let public_key = secret_key[..MLKEM_PUBLIC_KEY_SIZE].to_vec();
        
        Ok(Self {
            public_key,
            secret_key,
        })
    }
}

/// Three-Ring Capsule Structure (cllX style)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreeRingCapsule {
    /// Public Ring: ML-KEM ciphertext
    pub public_ring: Vec<u8>,
    
    /// Trapdoor Ring: Verification data
    pub trapdoor_ring: [u8; 32],
    
    /// Mask Ring: Encrypted mask seed
    pub mask_ring: Vec<u8>,
}

/// Capsule with recipient identification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapsuleV2 {
    pub recipient_id_hash: [u8; 32],
    pub capsule: ThreeRingCapsule,
    pub encrypted_master_key: Vec<u8>,
}

impl CapsuleV2 {
    /// Encapsulate master key for a recipient
    pub fn encapsulate(
        recipient_public_key: &[u8],
        master_key: &MasterKey,
        mask_seed: &[u8; 32],
    ) -> Result<Self> {
        // Encapsulate to get shared secret
        let (shared_secret, ciphertext) = ML_KEM_768.encaps(recipient_public_key);
        
        // Derive wrap key from shared secret
        let wrap_key = Self::derive_wrap_key(&shared_secret);
        
        // 加密 master key
        let cipher = AeadCipher::new(CipherType::Aes256Gcm);
        let nonce = [0u8; 12]; // Deterministic nonce (safe with unique wrap_key)
        let encrypted_master_key = cipher.encrypt(
            &wrap_key,
            &nonce,
            master_key.as_bytes(),
            b"cllx-master-key"
        )?;
        
        // 加密 mask seed
        let mask_nonce = [1u8; 12];
        let encrypted_mask_seed = cipher.encrypt(
            &wrap_key,
            &mask_nonce,
            mask_seed,
            b"cllx-mask-seed"
        )?;
        
        // Calculate recipient ID hash
        let recipient_id_hash = blake3::hash(recipient_public_key);
        
        // Calculate trapdoor (verification hash)
        let mut trapdoor_input = Vec::new();
        trapdoor_input.extend_from_slice(&ciphertext);
        trapdoor_input.extend_from_slice(&encrypted_master_key);
        let trapdoor_ring = *blake3::hash(&trapdoor_input).as_bytes();
        
        Ok(Self {
            recipient_id_hash: *recipient_id_hash.as_bytes(),
            capsule: ThreeRingCapsule {
                public_ring: ciphertext,
                trapdoor_ring,
                mask_ring: encrypted_mask_seed,
            },
            encrypted_master_key,
        })
    }

    /// Decapsulate to recover master key
    pub fn decapsulate(
        &self,
        recipient_secret_key: &[u8],
    ) -> Result<(MasterKey, [u8; 32])> {
        // Decapsulate to get shared secret
        let shared_secret = ML_KEM_768.decaps(recipient_secret_key, &self.capsule.public_ring);
        
        // Derive wrap key
        let wrap_key = Self::derive_wrap_key(&shared_secret);
        
        // 验证 trapdoor
        let mut trapdoor_input = Vec::new();
        trapdoor_input.extend_from_slice(&self.capsule.public_ring);
        trapdoor_input.extend_from_slice(&self.encrypted_master_key);
        let computed_trapdoor = *blake3::hash(&trapdoor_input).as_bytes();
        
        if computed_trapdoor != self.capsule.trapdoor_ring {
            return Err(Error::IntegrityFailed);
        }
        
        // 解密 master key
        let cipher = AeadCipher::new(CipherType::Aes256Gcm);
        let nonce = [0u8; 12];
        let master_key_bytes = cipher.decrypt(
            &wrap_key,
            &nonce,
            &self.encrypted_master_key,
            b"cllx-master-key"
        )?;
        
        let master_key_array: [u8; 32] = master_key_bytes
            .try_into()
            .map_err(|_| Error::Crypto("Invalid master key size".to_string()))?;
        
        // 解密 mask seed
        let mask_nonce = [1u8; 12];
        let mask_seed_bytes = cipher.decrypt(
            &wrap_key,
            &mask_nonce,
            &self.capsule.mask_ring,
            b"cllx-mask-seed"
        )?;
        
        let mask_seed: [u8; 32] = mask_seed_bytes
            .try_into()
            .map_err(|_| Error::Crypto("Invalid mask seed size".to_string()))?;
        
        Ok((MasterKey::from_bytes(master_key_array), mask_seed))
    }

    /// Derive wrap key from shared secret using HKDF
    fn derive_wrap_key(shared_secret: &[u8]) -> [u8; 32] {
        use hkdf::Hkdf;
        use sha3::Sha3_256;
        
        let hk = Hkdf::<Sha3_256>::new(None, shared_secret);
        let mut wrap_key = [0u8; 32];
        hk.expand(b"cllx-capsule-wrap", &mut wrap_key)
            .expect("HKDF expand failed");
        wrap_key
    }
}

/// Multi-recipient capsule manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiRecipientCapsule {
    pub capsules: Vec<CapsuleV2>,
}

impl MultiRecipientCapsule {
    pub fn new() -> Self {
        Self {
            capsules: Vec::new(),
        }
    }

    /// Add a recipient
    pub fn add_recipient(
        &mut self,
        recipient_public_key: &[u8],
        master_key: &MasterKey,
        mask_seed: &[u8; 32],
    ) -> Result<()> {
        let capsule = CapsuleV2::encapsulate(recipient_public_key, master_key, mask_seed)?;
        self.capsules.push(capsule);
        Ok(())
    }

    /// Try to decrypt with any matching secret key
    pub fn try_decrypt(
        &self,
        recipient_secret_key: &[u8],
        recipient_public_key: &[u8],
    ) -> Result<(MasterKey, [u8; 32])> {
        let recipient_id = *blake3::hash(recipient_public_key).as_bytes();
        
        for capsule in &self.capsules {
            if capsule.recipient_id_hash == recipient_id {
                return capsule.decapsulate(recipient_secret_key);
            }
        }
        
        Err(Error::CapsuleDecryptFailed)
    }

    /// Get number of recipients
    pub fn recipient_count(&self) -> usize {
        self.capsules.len()
    }
}

impl Default for MultiRecipientCapsule {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlkem_keypair_generation() {
        let keypair = MlKemKeyPair::generate().unwrap();
        assert_eq!(keypair.public_key_bytes().len(), MLKEM_PUBLIC_KEY_SIZE);
        assert_eq!(keypair.secret_key_bytes().len(), MLKEM_SECRET_KEY_SIZE);
    }

    #[test]
    fn test_capsule_roundtrip() {
        let keypair = MlKemKeyPair::generate().unwrap();
        let master_key = MasterKey::generate();
        let mask_seed = [42u8; 32];
        
        let capsule = CapsuleV2::encapsulate(
            &keypair.public_key,
            &master_key,
            &mask_seed
        ).unwrap();
        
        let (decrypted_master, decrypted_mask) = capsule.decapsulate(&keypair.secret_key).unwrap();
        
        assert_eq!(master_key.as_bytes(), decrypted_master.as_bytes());
        assert_eq!(mask_seed, decrypted_mask);
    }

    #[test]
    fn test_multi_recipient() {
        let keypair1 = MlKemKeyPair::generate().unwrap();
        let keypair2 = MlKemKeyPair::generate().unwrap();
        let master_key = MasterKey::generate();
        let mask_seed = [99u8; 32];
        
        let mut multi = MultiRecipientCapsule::new();
        multi.add_recipient(&keypair1.public_key, &master_key, &mask_seed).unwrap();
        multi.add_recipient(&keypair2.public_key, &master_key, &mask_seed).unwrap();
        
        assert_eq!(multi.recipient_count(), 2);
        
        // 解密 with first key
        let (dec1, mask1) = multi.try_decrypt(&keypair1.secret_key, &keypair1.public_key).unwrap();
        assert_eq!(master_key.as_bytes(), dec1.as_bytes());
        assert_eq!(mask_seed, mask1);
        
        // 解密 with second key
        let (dec2, mask2) = multi.try_decrypt(&keypair2.secret_key, &keypair2.public_key).unwrap();
        assert_eq!(master_key.as_bytes(), dec2.as_bytes());
        assert_eq!(mask_seed, mask2);
    }
}
