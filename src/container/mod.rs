pub mod header;
pub mod builder;
pub mod format;
pub mod simple_format;

use serde::{Deserialize, Serialize};
use crate::core::{Result, MasterKey};
use crate::capsule::Capsule;
use crate::merkle::MerkleTree;

pub use header::{SuperHeader, SecurityPolicy};
pub use builder::ContainerBuilder;
pub use format::{
    ContainerFormat, SuperHeaderV1, CapsuleData, KeyMetadata,
    ChunkIndexTable, ChunkRecord, MerkleData, ContainerWriter, ContainerReader,
    flags, CONTAINER_VERSION
};
pub use simple_format::SimpleContainer;

#[derive(Debug, Serialize, Deserialize)]
pub struct Container {
    pub header: SuperHeader,
    pub policy: SecurityPolicy,
    pub capsules: Vec<Capsule>,
    pub chunk_index: ChunkIndex,
    pub merkle_tree: Option<MerkleTree>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkIndex {
    pub entries: Vec<ChunkEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkEntry {
    pub chunk_id: u64,
    pub offset: u64,
    pub size: u32,
    pub hash: [u8; 32],
}

impl Container {
    pub fn builder() -> ContainerBuilder {
        ContainerBuilder::new()
    }

    pub fn decrypt_master_key(&self, secret_key: &[u8]) -> Result<MasterKey> {
        // 解密 from first matching capsule
        for capsule in &self.capsules {
            if let Ok(key) = capsule.decrypt(secret_key) {
                return Ok(key);
            }
        }
        Err(crate::core::Error::CapsuleDecryptFailed)
    }
}
