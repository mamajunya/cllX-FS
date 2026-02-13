use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Rolling hash for content-defined chunking
pub struct RollingHash {
    window_size: usize,
    modulus: u64,
}

impl RollingHash {
    pub fn new(window_size: usize) -> Self {
        Self {
            window_size,
            modulus: 0xFFFFFFFF,
        }
    }

    /// Rabin fingerprint for deduplication
    pub fn fingerprint(&self, data: &[u8]) -> u64 {
        let mut hash = 0u64;
        for &byte in data {
            hash = hash.wrapping_mul(31).wrapping_add(byte as u64);
            hash %= self.modulus;
        }
        hash
    }

    /// Find chunk boundaries using rolling hash
    pub fn find_boundaries(&self, data: &[u8], avg_size: usize) -> Vec<usize> {
        let mut boundaries = vec![0];
        let mask = (1 << 13) - 1; // Target ~8KB chunks
        
        let mut hash = 0u64;
        for (i, &byte) in data.iter().enumerate() {
            hash = hash.wrapping_mul(31).wrapping_add(byte as u64);
            
            if (hash & mask) == 0 || i - *boundaries.last().unwrap() >= avg_size * 2 {
                boundaries.push(i);
            }
        }
        
        if *boundaries.last().unwrap() != data.len() {
            boundaries.push(data.len());
        }
        
        boundaries
    }
}

/// Chunk reference for deduplication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkRef {
    pub hash: [u8; 32],
    pub chunk_id: u64,
    pub ref_count: u32,
    pub size: u32,
}

/// Deduplication index
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DedupIndex {
    chunks: HashMap<[u8; 32], ChunkRef>,
    next_chunk_id: u64,
}

impl DedupIndex {
    pub fn new() -> Self {
        Self {
            chunks: HashMap::new(),
            next_chunk_id: 0,
        }
    }

    /// Check if chunk exists and return reference
    pub fn lookup(&self, hash: &[u8; 32]) -> Option<&ChunkRef> {
        self.chunks.get(hash)
    }

    /// Add chunk to index or increment reference count
    pub fn insert(&mut self, hash: [u8; 32], size: u32) -> u64 {
        if let Some(chunk_ref) = self.chunks.get_mut(&hash) {
            // Chunk exists, increment reference count
            chunk_ref.ref_count += 1;
            chunk_ref.chunk_id
        } else {
            // New chunk
            let chunk_id = self.next_chunk_id;
            self.next_chunk_id += 1;
            
            self.chunks.insert(hash, ChunkRef {
                hash,
                chunk_id,
                ref_count: 1,
                size,
            });
            
            chunk_id
        }
    }

    /// Decrement reference count
    pub fn decrement_ref(&mut self, hash: &[u8; 32]) -> bool {
        if let Some(chunk_ref) = self.chunks.get_mut(hash) {
            chunk_ref.ref_count = chunk_ref.ref_count.saturating_sub(1);
            
            // Remove if no more references
            if chunk_ref.ref_count == 0 {
                self.chunks.remove(hash);
                return true; // Chunk can be deleted
            }
        }
        false
    }

    /// Get total number of unique chunks
    pub fn unique_chunks(&self) -> usize {
        self.chunks.len()
    }

    /// Get total reference count
    pub fn total_references(&self) -> u32 {
        self.chunks.values().map(|c| c.ref_count).sum()
    }

    /// Calculate deduplication ratio
    pub fn dedup_ratio(&self) -> f64 {
        let total_refs = self.total_references() as f64;
        let unique = self.unique_chunks() as f64;
        
        if unique == 0.0 {
            1.0
        } else {
            total_refs / unique
        }
    }

    /// Get statistics
    pub fn stats(&self) -> DedupStats {
        DedupStats {
            unique_chunks: self.unique_chunks(),
            total_references: self.total_references(),
            dedup_ratio: self.dedup_ratio(),
            total_size: self.chunks.values().map(|c| c.size as u64).sum(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DedupStats {
    pub unique_chunks: usize,
    pub total_references: u32,
    pub dedup_ratio: f64,
    pub total_size: u64,
}

impl Default for DedupIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rolling_hash_deterministic() {
        let rh = RollingHash::new(64);
        let data = b"test data for rolling hash";
        
        let fp1 = rh.fingerprint(data);
        let fp2 = rh.fingerprint(data);
        
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_dedup_index() {
        let mut index = DedupIndex::new();
        
        let hash1 = [1u8; 32];
        let hash2 = [2u8; 32];
        
        // Insert first chunk
        let id1 = index.insert(hash1, 1024);
        assert_eq!(id1, 0);
        assert_eq!(index.unique_chunks(), 1);
        
        // Insert same chunk again (should increment ref count)
        let id2 = index.insert(hash1, 1024);
        assert_eq!(id2, 0); // Same ID
        assert_eq!(index.unique_chunks(), 1); // Still 1 unique
        
        // Insert different chunk
        let id3 = index.insert(hash2, 2048);
        assert_eq!(id3, 1);
        assert_eq!(index.unique_chunks(), 2);
        
        // Check dedup ratio
        assert_eq!(index.total_references(), 3);
        assert_eq!(index.dedup_ratio(), 1.5);
    }

    #[test]
    fn test_dedup_decrement() {
        let mut index = DedupIndex::new();
        let hash = [1u8; 32];
        
        index.insert(hash, 1024);
        index.insert(hash, 1024);
        
        assert_eq!(index.unique_chunks(), 1);
        
        // Decrement once
        let should_delete = index.decrement_ref(&hash);
        assert!(!should_delete);
        assert_eq!(index.unique_chunks(), 1);
        
        // Decrement again (should remove)
        let should_delete = index.decrement_ref(&hash);
        assert!(should_delete);
        assert_eq!(index.unique_chunks(), 0);
    }
}

