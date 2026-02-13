pub mod journal;

use serde::{Deserialize, Serialize};
use crate::core::{Result, Error};

pub use journal::{Journal, JournalEntry as JournalEntryV2, Operation as JournalOperation};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteJournal {
    pub entries: Vec<JournalEntry>,
    pub write_count: usize,
    pub threshold: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    pub timestamp: u64,
    pub chunk_id: u64,
    pub operation: Operation,
    pub fast_hash: [u8; 16],
    pub deep_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Operation {
    Write,
    Modify,
    Delete,
}

impl WriteJournal {
    pub fn new(threshold: usize) -> Self {
        Self {
            entries: Vec::new(),
            write_count: 0,
            threshold,
        }
    }

    /// Record a write operation
    pub fn record_write(&mut self, chunk_id: u64, data: &[u8]) -> Result<()> {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let fast_hash = Self::fast_hash(data);
        let deep_hash = blake3::hash(data);
        
        self.entries.push(JournalEntry {
            timestamp,
            chunk_id,
            operation: Operation::Write,
            fast_hash,
            deep_hash: *deep_hash.as_bytes(),
        });
        
        self.write_count += 1;
        
        // Check for ransomware behavior
        if self.write_count > self.threshold {
            self.detect_ransomware()?;
        }
        
        Ok(())
    }

    /// Detect suspicious write patterns
    fn detect_ransomware(&self) -> Result<()> {
        let recent_window = 60; // 60 seconds
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let recent_writes = self.entries.iter()
            .filter(|e| now - e.timestamp < recent_window)
            .count();
        
        // If too many writes in short time, trigger protection
        if recent_writes > self.threshold / 2 {
            return Err(Error::RansomwareDetected);
        }
        
        Ok(())
    }

    fn fast_hash(data: &[u8]) -> [u8; 16] {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        
        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        let hash = hasher.finish();
        
        let mut result = [0u8; 16];
        result[0..8].copy_from_slice(&hash.to_le_bytes());
        result[8..16].copy_from_slice(&hash.to_be_bytes());
        result
    }
}
