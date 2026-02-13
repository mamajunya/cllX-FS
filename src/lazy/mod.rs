// Lazy loading module for large files
use crate::core::{Result, Error};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

pub struct LazyChunkLoader {
    file: File,
    chunk_size: usize,
    total_chunks: u64,
    chunk_offsets: Vec<u64>,
}

impl LazyChunkLoader {
    pub fn new<P: AsRef<Path>>(path: P, chunk_size: usize) -> Result<Self> {
        let file = File::open(path)?;
        
        let file_size = file.metadata()?.len();
        
        let total_chunks = (file_size + chunk_size as u64 - 1) / chunk_size as u64;
        
        // 构建 chunk offset table
        let mut chunk_offsets = Vec::with_capacity(total_chunks as usize);
        for i in 0..total_chunks {
            chunk_offsets.push(i * chunk_size as u64);
        }

        Ok(Self {
            file,
            chunk_size,
            total_chunks,
            chunk_offsets,
        })
    }

    pub fn load_chunk(&mut self, chunk_id: u64) -> Result<Vec<u8>> {
        if chunk_id >= self.total_chunks {
            return Err(Error::InvalidInput("Chunk ID out of range".to_string()));
        }

        let offset = self.chunk_offsets[chunk_id as usize];
        self.file.seek(SeekFrom::Start(offset))?;

        let mut buffer = vec![0u8; self.chunk_size];
        let bytes_read = self.file.read(&mut buffer)?;
        
        buffer.truncate(bytes_read);
        Ok(buffer)
    }

    pub fn total_chunks(&self) -> u64 {
        self.total_chunks
    }

    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }
}

pub struct ChunkCache {
    cache: std::collections::HashMap<u64, Vec<u8>>,
    max_size: usize,
}

impl ChunkCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: std::collections::HashMap::new(),
            max_size,
        }
    }

    pub fn get(&self, chunk_id: u64) -> Option<&Vec<u8>> {
        self.cache.get(&chunk_id)
    }

    pub fn insert(&mut self, chunk_id: u64, data: Vec<u8>) {
        if self.cache.len() >= self.max_size {
            // Simple eviction: remove first entry
            if let Some(key) = self.cache.keys().next().copied() {
                self.cache.remove(&key);
            }
        }
        self.cache.insert(chunk_id, data);
    }

    pub fn clear(&mut self) {
        self.cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_chunk_cache() {
        let mut cache = ChunkCache::new(2);
        cache.insert(0, vec![1, 2, 3]);
        cache.insert(1, vec![4, 5, 6]);
        
        assert_eq!(cache.get(0), Some(&vec![1, 2, 3]));
        assert_eq!(cache.get(1), Some(&vec![4, 5, 6]));
        
        // Insert third item, should evict first
        cache.insert(2, vec![7, 8, 9]);
        assert_eq!(cache.cache.len(), 2);
    }
}
