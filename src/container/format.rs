use serde::{Deserialize, Serialize};
use std::io::{Read, Write, Seek, SeekFrom};
use crate::core::{Result, Error};

/// Container file format version
pub const CONTAINER_VERSION: u32 = 1;

/// Complete container format with all sections
#[derive(Debug, Serialize, Deserialize)]
pub struct ContainerFormat {
    pub super_header: SuperHeaderV1,
    pub capsules: Vec<CapsuleData>,
    pub key_metadata: KeyMetadata,
    pub chunk_index: ChunkIndexTable,
    pub merkle_data: MerkleData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuperHeaderV1 {
    pub magic: [u8; 11],           // "CLLXFS-PRO\0"
    pub version: u32,
    pub chunk_size: u32,
    pub cipher_id: u8,             // 0=AES-GCM, 1=ChaCha20
    pub kdf_id: u8,                // 0=HKDF-SHA3
    pub kem_id: u8,                // 0=MLKEM (future)
    pub file_nonce: [u8; 12],
    pub flags: u32,                // Bitflags for features
    pub total_chunks: u64,
    pub original_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapsuleData {
    pub recipient_id_hash: [u8; 32],
    pub kem_ciphertext: Vec<u8>,
    pub encrypted_master_key: Vec<u8>,
    pub encrypted_mask_seed: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub container_id: [u8; 32],
    pub file_id: [u8; 32],
    pub creation_time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkIndexTable {
    pub entries: Vec<ChunkRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkRecord {
    pub chunk_id: u64,
    pub offset: u64,
    pub length: u32,
    pub tag: [u8; 16],             // AEAD tag
    pub hash: [u8; 32],            // Pre-encryption hash
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleData {
    pub root_hash: [u8; 32],
    pub nodes: Vec<[u8; 32]>,
    pub leaf_count: usize,
}

/// Container flags
pub mod flags {
    pub const ANTI_RANSOM: u32 = 1 << 0;
    pub const STEALTH_MODE: u32 = 1 << 1;
    pub const TIMELOCK: u32 = 1 << 2;
    pub const DEDUP: u32 = 1 << 3;
    pub const COMPRESSED: u32 = 1 << 4;
}

impl SuperHeaderV1 {
    pub fn new(chunk_size: u32, cipher_id: u8, file_nonce: [u8; 12]) -> Self {
        Self {
            magic: *b"CLLXFS-PRO\0",
            version: CONTAINER_VERSION,
            chunk_size,
            cipher_id,
            kdf_id: 0,
            kem_id: 0,
            file_nonce,
            flags: 0,
            total_chunks: 0,
            original_size: 0,
        }
    }

    pub fn has_flag(&self, flag: u32) -> bool {
        (self.flags & flag) != 0
    }

    pub fn set_flag(&mut self, flag: u32) {
        self.flags |= flag;
    }
}

/// Container Writer - writes encrypted container to file
pub struct ContainerWriter<W: Write + Seek> {
    writer: W,
    header_offset: u64,
}

impl<W: Write + Seek> ContainerWriter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            header_offset: 0,
        }
    }

    /// 写入 complete container to file
    pub fn write_container(&mut self, container: &ContainerFormat) -> Result<()> {
        // 写入 super header
        let header_bytes = bincode::serialize(&container.super_header)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        self.writer.write_all(&header_bytes)?;

        // 写入 capsules
        let capsules_bytes = bincode::serialize(&container.capsules)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        self.writer.write_all(&capsules_bytes)?;

        // 写入 key metadata
        let metadata_bytes = bincode::serialize(&container.key_metadata)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        self.writer.write_all(&metadata_bytes)?;

        // 写入 chunk index
        let index_bytes = bincode::serialize(&container.chunk_index)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        self.writer.write_all(&index_bytes)?;

        // 写入 merkle data
        let merkle_bytes = bincode::serialize(&container.merkle_data)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        self.writer.write_all(&merkle_bytes)?;

        self.writer.flush()?;
        Ok(())
    }

    /// 写入 encrypted chunk data
    pub fn write_chunk(&mut self, chunk_id: u64, data: &[u8]) -> Result<u64> {
        let offset = self.writer.stream_position()?;
        self.writer.write_all(data)?;
        Ok(offset)
    }
}

/// Container Reader - reads encrypted container from file
pub struct ContainerReader<R: Read + Seek> {
    reader: R,
}

impl<R: Read + Seek> ContainerReader<R> {
    pub fn new(reader: R) -> Self {
        Self { reader }
    }

    /// 读取 and parse container format
    pub fn read_container(&mut self) -> Result<ContainerFormat> {
        // 读取 super header
        let super_header: SuperHeaderV1 = bincode::deserialize_from(&mut self.reader)
            .map_err(|e| Error::Serialization(e.to_string()))?;

        // 验证 magic
        if &super_header.magic != b"CLLXFS-PRO\0" {
            return Err(Error::InvalidFormat);
        }

        // 读取 capsules
        let capsules: Vec<CapsuleData> = bincode::deserialize_from(&mut self.reader)
            .map_err(|e| Error::Serialization(e.to_string()))?;

        // 读取 key metadata
        let key_metadata: KeyMetadata = bincode::deserialize_from(&mut self.reader)
            .map_err(|e| Error::Serialization(e.to_string()))?;

        // 读取 chunk index
        let chunk_index: ChunkIndexTable = bincode::deserialize_from(&mut self.reader)
            .map_err(|e| Error::Serialization(e.to_string()))?;

        // 读取 merkle data
        let merkle_data: MerkleData = bincode::deserialize_from(&mut self.reader)
            .map_err(|e| Error::Serialization(e.to_string()))?;

        Ok(ContainerFormat {
            super_header,
            capsules,
            key_metadata,
            chunk_index,
            merkle_data,
        })
    }

    /// 读取 specific chunk by ID
    pub fn read_chunk(&mut self, record: &ChunkRecord) -> Result<Vec<u8>> {
        self.reader.seek(SeekFrom::Start(record.offset))?;
        let mut buffer = vec![0u8; record.length as usize];
        self.reader.read_exact(&mut buffer)?;
        Ok(buffer)
    }
}
