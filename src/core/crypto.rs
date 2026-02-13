use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::{Aead, Payload};
use chacha20poly1305::ChaCha20Poly1305;

use crate::core::{Error, Result};

#[derive(Debug, Clone, Copy)]
pub enum CipherType {
    Aes256Gcm,
    ChaCha20Poly1305,
}

pub struct AeadCipher {
    cipher_type: CipherType,
}

impl AeadCipher {
    pub fn new(cipher_type: CipherType) -> Self {
        Self { cipher_type }
    }

    /// 加密 chunk with AEAD
    pub fn encrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        match self.cipher_type {
            CipherType::Aes256Gcm => {
                let cipher = Aes256Gcm::new(key.into());
                let nonce = Nonce::from_slice(nonce);
                let payload = Payload { msg: plaintext, aad };
                cipher.encrypt(nonce, payload)
                    .map_err(|e| Error::Crypto(format!("AES-GCM encrypt failed: {}", e)))
            }
            CipherType::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new(key.into());
                let nonce = Nonce::from_slice(nonce);
                let payload = Payload { msg: plaintext, aad };
                cipher.encrypt(nonce, payload)
                    .map_err(|e| Error::Crypto(format!("ChaCha20 encrypt failed: {}", e)))
            }
        }
    }

    /// 解密 chunk with AEAD
    pub fn decrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        match self.cipher_type {
            CipherType::Aes256Gcm => {
                let cipher = Aes256Gcm::new(key.into());
                let nonce = Nonce::from_slice(nonce);
                let payload = Payload { msg: ciphertext, aad };
                cipher.decrypt(nonce, payload)
                    .map_err(|_| Error::AuthFailed)
            }
            CipherType::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new(key.into());
                let nonce = Nonce::from_slice(nonce);
                let payload = Payload { msg: ciphertext, aad };
                cipher.decrypt(nonce, payload)
                    .map_err(|_| Error::AuthFailed)
            }
        }
    }
}
