// Simple container format for cllX-FS-Pro
// This is a minimal but complete implementation

use crate::core::{Result, Error, MasterKey};
use crate::capsule::mlkem::CapsuleV2;
use serde::{Serialize, Deserialize};
use std::io::{Read, Write};

/// Simple container format
/// Format: [Header][Capsule][Chunk Sizes][Encrypted Chunks]
#[derive(Debug, Serialize, Deserialize)]
pub struct SimpleContainer {
    pub magic: [u8; 8],           // "CLLXFS01"
    pub version: u32,              // Version 1
    pub chunk_size: u32,           // Chunk size in bytes
    pub total_chunks: u32,         // Total number of chunks
    pub file_nonce: [u8; 12],      // File nonce for encryption
    pub capsule_size: u32,         // Size of serialized capsule
    pub capsule_data: Vec<u8>,     // 序列化d capsule
    pub chunk_sizes: Vec<u32>,     // Size of each encrypted chunk (including AEAD tag)
    pub encrypted_data: Vec<u8>,   // All encrypted chunks concatenated
    pub original_filename: Option<String>, // Original filename with extension
    pub embedded_key: Option<Vec<u8>>, // Optional embedded secret key (for convenience mode)
}

impl SimpleContainer {
    pub const MAGIC: [u8; 8] = *b"CLLXFS01";
    
    pub fn new(
        chunk_size: u32,
        total_chunks: u32,
        file_nonce: [u8; 12],
        capsule: &CapsuleV2,
        chunk_sizes: Vec<u32>,
        encrypted_data: Vec<u8>,
        original_filename: Option<String>,
        embedded_key: Option<Vec<u8>>,
    ) -> Result<Self> {
        let capsule_data = bincode::serialize(capsule)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        
        Ok(Self {
            magic: Self::MAGIC,
            version: 1,
            chunk_size,
            total_chunks,
            file_nonce,
            capsule_size: capsule_data.len() as u32,
            capsule_data,
            chunk_sizes,
            encrypted_data,
            original_filename,
            embedded_key,
        })
    }
    
    pub fn serialize(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| Error::Serialization(e.to_string()))
    }
    
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let container: Self = bincode::deserialize(data)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        
        // 验证 magic
        if container.magic != Self::MAGIC {
            return Err(Error::InvalidFormat);
        }
        
        Ok(container)
    }
    
    pub fn write_to_file<W: Write>(&self, writer: &mut W) -> Result<()> {
        let data = self.serialize()?;
        writer.write_all(&data)
            .map_err(|e| Error::Io(e))?;
        Ok(())
    }
    
    pub fn read_from_file<R: Read>(reader: &mut R) -> Result<Self> {
        let mut data = Vec::new();
        reader.read_to_end(&mut data)
            .map_err(|e| Error::Io(e))?;
        Self::deserialize(&data)
    }
    
    pub fn get_capsule(&self) -> Result<CapsuleV2> {
        bincode::deserialize(&self.capsule_data)
            .map_err(|e| Error::Serialization(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_container_roundtrip() {
        use crate::capsule::mlkem::MlKemKeyPair;
        
        // 生成 test data
        let keypair = MlKemKeyPair::generate().unwrap();
        let master_key = MasterKey::generate();
        let mask_seed = [0u8; 32];
        
        let capsule = CapsuleV2::encapsulate(
            keypair.public_key_bytes(),
            &master_key,
            &mask_seed
        ).unwrap();
        
        let encrypted_data = vec![1, 2, 3, 4, 5];
        let chunk_sizes = vec![encrypted_data.len() as u32];
        
        // 创建 container
        let container = SimpleContainer::new(
            1024,
            5,
            [0u8; 12],
            &capsule,
            chunk_sizes,
            encrypted_data.clone(),
        ).unwrap();
        
        // 序列化 and deserialize
        let serialized = container.serialize().unwrap();
        let deserialized = SimpleContainer::deserialize(&serialized).unwrap();
        
        // Verify
        assert_eq!(deserialized.magic, SimpleContainer::MAGIC);
        assert_eq!(deserialized.chunk_size, 1024);
        assert_eq!(deserialized.total_chunks, 5);
        assert_eq!(deserialized.encrypted_data, encrypted_data);
    }
}
