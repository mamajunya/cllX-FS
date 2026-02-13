use hkdf::Hkdf;
use rand::RngCore;
use sha3::Sha3_256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::core::Result;

/// 主密钥 for file encryption (256-bit)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Self(key)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// 密钥派生 using HKDF
pub struct KeyDerivation;

impl KeyDerivation {
    /// Derive tree root key
    pub fn derive_tree_root(master: &MasterKey) -> Result<[u8; 32]> {
        Self::derive(master.as_bytes(), b"cllx-fs-tree-root")
    }

    /// Derive chunk-specific key
    pub fn derive_chunk_key(tree_root: &[u8; 32], chunk_id: u64) -> Result<[u8; 32]> {
        let info = format!("chunk-{}", chunk_id);
        Self::derive(tree_root, info.as_bytes())
    }

    /// Derive authentication key
    pub fn derive_auth_key(master: &MasterKey) -> Result<[u8; 32]> {
        Self::derive(master.as_bytes(), b"cllx-fs-auth")
    }

    /// Derive mask key for XOR obfuscation
    pub fn derive_mask_key(master: &MasterKey) -> Result<[u8; 32]> {
        Self::derive(master.as_bytes(), b"cllx-fs-mask")
    }

    fn derive(ikm: &[u8], info: &[u8]) -> Result<[u8; 32]> {
        let hk = Hkdf::<Sha3_256>::new(None, ikm);
        let mut okm = [0u8; 32];
        hk.expand(info, &mut okm)
            .map_err(|e| crate::core::Error::Crypto(format!("HKDF failed: {}", e)))?;
        Ok(okm)
    }
}
