use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Write, BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use crate::core::{Result, Error};

/// Journal entry for write operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    pub timestamp: u64,
    pub chunk_id: u64,
    pub operation: Operation,
    pub write_offset: u64,
    pub old_hash: Option<[u8; 32]>,
    pub new_hash: [u8; 32],
    pub operation_id: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum Operation {
    Write,
    Modify,
    Delete,
}

/// Append-only journal for recovery
pub struct Journal {
    file: File,
    entry_count: u64,
    path: std::path::PathBuf,
}

impl Journal {
    /// 创建 or open a journal file
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)?;
        
        // Count existing entries
        let entry_count = Self::count_entries(&path)?;
        
        Ok(Self {
            file,
            entry_count,
            path,
        })
    }

    /// Append a new entry to the journal
    pub fn append(&mut self, entry: JournalEntry) -> Result<()> {
        let serialized = bincode::serialize(&entry)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        
        // 写入 length prefix
        let len = serialized.len() as u32;
        self.file.write_all(&len.to_le_bytes())?;
        
        // 写入 entry
        self.file.write_all(&serialized)?;
        self.file.flush()?;
        
        self.entry_count += 1;
        Ok(())
    }

    /// Record a write operation
    pub fn record_write(
        &mut self,
        chunk_id: u64,
        write_offset: u64,
        new_hash: [u8; 32],
        operation_id: u64,
    ) -> Result<()> {
        let entry = JournalEntry {
            timestamp: Self::current_timestamp(),
            chunk_id,
            operation: Operation::Write,
            write_offset,
            old_hash: None,
            new_hash,
            operation_id,
        };
        
        self.append(entry)
    }

    /// Record a modify operation
    pub fn record_modify(
        &mut self,
        chunk_id: u64,
        write_offset: u64,
        old_hash: [u8; 32],
        new_hash: [u8; 32],
        operation_id: u64,
    ) -> Result<()> {
        let entry = JournalEntry {
            timestamp: Self::current_timestamp(),
            chunk_id,
            operation: Operation::Modify,
            write_offset,
            old_hash: Some(old_hash),
            new_hash,
            operation_id,
        };
        
        self.append(entry)
    }

    /// Record a delete operation
    pub fn record_delete(
        &mut self,
        chunk_id: u64,
        old_hash: [u8; 32],
        operation_id: u64,
    ) -> Result<()> {
        let entry = JournalEntry {
            timestamp: Self::current_timestamp(),
            chunk_id,
            operation: Operation::Delete,
            write_offset: 0,
            old_hash: Some(old_hash),
            new_hash: [0u8; 32],
            operation_id,
        };
        
        self.append(entry)
    }

    /// 读取 all entries from the journal
    pub fn read_all(&self) -> Result<Vec<JournalEntry>> {
        let file = File::open(&self.path)?;
        let mut reader = BufReader::new(file);
        let mut entries = Vec::new();
        
        loop {
            // 读取 length prefix
            let mut len_bytes = [0u8; 4];
            match reader.read_exact(&mut len_bytes) {
                Ok(_) => {},
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(Error::Io(e)),
            }
            
            let len = u32::from_le_bytes(len_bytes) as usize;
            
            // 读取 entry
            let mut entry_bytes = vec![0u8; len];
            reader.read_exact(&mut entry_bytes)?;
            
            let entry: JournalEntry = bincode::deserialize(&entry_bytes)
                .map_err(|e| Error::Serialization(e.to_string()))?;
            
            entries.push(entry);
        }
        
        Ok(entries)
    }

    /// Find last stable state (last successful operation)
    pub fn find_last_stable_state(&self) -> Result<Option<u64>> {
        let entries = self.read_all()?;
        
        if entries.is_empty() {
            return Ok(None);
        }
        
        // Find the last operation ID
        Ok(entries.last().map(|e| e.operation_id))
    }

    /// Rebuild index from journal
    pub fn rebuild_index(&self) -> Result<Vec<(u64, [u8; 32])>> {
        let entries = self.read_all()?;
        let mut index = std::collections::HashMap::new();
        
        for entry in entries {
            match entry.operation {
                Operation::Write | Operation::Modify => {
                    index.insert(entry.chunk_id, entry.new_hash);
                }
                Operation::Delete => {
                    index.remove(&entry.chunk_id);
                }
            }
        }
        
        Ok(index.into_iter().collect())
    }

    /// Get entry count
    pub fn entry_count(&self) -> u64 {
        self.entry_count
    }

    /// Detect suspicious write patterns (ransomware)
    pub fn detect_ransomware(&self, window_seconds: u64, threshold: usize) -> Result<bool> {
        let entries = self.read_all()?;
        let now = Self::current_timestamp();
        
        let recent_writes = entries.iter()
            .filter(|e| now - e.timestamp < window_seconds)
            .count();
        
        Ok(recent_writes > threshold)
    }

    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn count_entries<P: AsRef<Path>>(path: P) -> Result<u64> {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(Error::Io(e)),
        };
        
        let mut reader = BufReader::new(file);
        let mut count = 0u64;
        
        loop {
            let mut len_bytes = [0u8; 4];
            match reader.read_exact(&mut len_bytes) {
                Ok(_) => {},
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(Error::Io(e)),
            }
            
            let len = u32::from_le_bytes(len_bytes) as usize;
            reader.seek(SeekFrom::Current(len as i64))?;
            count += 1;
        }
        
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_journal_write_read() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();
        
        let mut journal = Journal::open(path).unwrap();
        
        journal.record_write(0, 0, [1u8; 32], 1).unwrap();
        journal.record_write(1, 1024, [2u8; 32], 2).unwrap();
        
        let entries = journal.read_all().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].chunk_id, 0);
        assert_eq!(entries[1].chunk_id, 1);
    }

    #[test]
    fn test_journal_rebuild_index() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();
        
        let mut journal = Journal::open(path).unwrap();
        
        journal.record_write(0, 0, [1u8; 32], 1).unwrap();
        journal.record_modify(0, 0, [1u8; 32], [2u8; 32], 2).unwrap();
        journal.record_write(1, 1024, [3u8; 32], 3).unwrap();
        
        let index = journal.rebuild_index().unwrap();
        assert_eq!(index.len(), 2);
        
        // Find chunk 0 (should have hash [2u8; 32])
        let chunk0 = index.iter().find(|(id, _)| *id == 0).unwrap();
        assert_eq!(chunk0.1, [2u8; 32]);
    }
}
