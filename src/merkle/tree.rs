use blake3::Hasher;
use serde::{Deserialize, Serialize};
use crate::core::Result;

/// Enhanced Merkle tree with verification capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTreeV2 {
    pub root_hash: [u8; 32],
    pub nodes: Vec<[u8; 32]>,
    pub leaf_count: usize,
    pub tree_height: usize,
}

/// Merkle proof for chunk verification
#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub leaf_index: usize,
    pub leaf_hash: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
}

impl MerkleTreeV2 {
    /// 构建 Merkle tree from chunk hashes
    pub fn build(chunk_hashes: &[[u8; 32]]) -> Self {
        if chunk_hashes.is_empty() {
            return Self {
                root_hash: [0u8; 32],
                nodes: vec![],
                leaf_count: 0,
                tree_height: 0,
            };
        }

        let mut nodes = chunk_hashes.to_vec();
        let leaf_count = nodes.len();
        let mut tree_height = 0;
        
        // 构建 tree bottom-up
        let mut level_size = nodes.len();
        while level_size > 1 {
            tree_height += 1;
            let mut next_level = Vec::new();
            
            for i in (0..level_size).step_by(2) {
                let left = &nodes[nodes.len() - level_size + i];
                let right = if i + 1 < level_size {
                    &nodes[nodes.len() - level_size + i + 1]
                } else {
                    left // Duplicate if odd
                };
                
                let parent = Self::hash_pair(left, right);
                next_level.push(parent);
            }
            
            nodes.extend(next_level.clone());
            level_size = next_level.len();
        }
        
        let root_hash = *nodes.last().unwrap();
        
        Self {
            root_hash,
            nodes,
            leaf_count,
            tree_height,
        }
    }

    /// 验证 a single chunk
    pub fn verify_chunk(&self, chunk_index: usize, chunk_hash: &[u8; 32]) -> bool {
        if chunk_index >= self.leaf_count {
            return false;
        }
        self.nodes[chunk_index] == *chunk_hash
    }

    /// 验证 a range of chunks
    pub fn verify_range(&self, start: usize, end: usize, chunk_hashes: &[[u8; 32]]) -> bool {
        if end > self.leaf_count || start >= end {
            return false;
        }
        
        for (i, hash) in chunk_hashes.iter().enumerate() {
            let chunk_idx = start + i;
            if chunk_idx >= end || !self.verify_chunk(chunk_idx, hash) {
                return false;
            }
        }
        true
    }

    /// 验证 entire tree
    pub fn verify_full(&self, chunk_hashes: &[[u8; 32]]) -> bool {
        if chunk_hashes.len() != self.leaf_count {
            return false;
        }
        
        let rebuilt = Self::build(chunk_hashes);
        rebuilt.root_hash == self.root_hash
    }

    /// 生成 Merkle proof for a chunk
    pub fn generate_proof(&self, chunk_index: usize) -> Option<MerkleProof> {
        if chunk_index >= self.leaf_count {
            return None;
        }

        let leaf_hash = self.nodes[chunk_index];
        let mut siblings = Vec::new();
        let mut index = chunk_index;
        let mut level_start = 0;
        let mut level_size = self.leaf_count;

        while level_size > 1 {
            let sibling_index = if index % 2 == 0 {
                index + 1
            } else {
                index - 1
            };

            if sibling_index < level_size {
                siblings.push(self.nodes[level_start + sibling_index]);
            } else {
                siblings.push(self.nodes[level_start + index]);
            }

            level_start += level_size;
            level_size = (level_size + 1) / 2;
            index /= 2;
        }

        Some(MerkleProof {
            leaf_index: chunk_index,
            leaf_hash,
            siblings,
        })
    }

    /// 验证 a Merkle proof
    pub fn verify_proof(&self, proof: &MerkleProof) -> bool {
        let mut current_hash = proof.leaf_hash;
        let mut index = proof.leaf_index;

        for sibling in &proof.siblings {
            current_hash = if index % 2 == 0 {
                Self::hash_pair(&current_hash, sibling)
            } else {
                Self::hash_pair(sibling, &current_hash)
            };
            index /= 2;
        }

        current_hash == self.root_hash
    }

    /// Hash a pair of nodes
    fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(left);
        hasher.update(right);
        *hasher.finalize().as_bytes()
    }

    /// Hash a chunk
    pub fn hash_chunk(data: &[u8]) -> [u8; 32] {
        *blake3::hash(data).as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_v2() {
        let chunk1 = b"chunk 1";
        let chunk2 = b"chunk 2";
        let chunk3 = b"chunk 3";
        
        let hash1 = MerkleTreeV2::hash_chunk(chunk1);
        let hash2 = MerkleTreeV2::hash_chunk(chunk2);
        let hash3 = MerkleTreeV2::hash_chunk(chunk3);
        
        let tree = MerkleTreeV2::build(&[hash1, hash2, hash3]);
        
        assert!(tree.verify_chunk(0, &hash1));
        assert!(tree.verify_chunk(1, &hash2));
        assert!(tree.verify_chunk(2, &hash3));
        assert!(tree.verify_full(&[hash1, hash2, hash3]));
    }

    #[test]
    fn test_merkle_proof() {
        let hashes: Vec<[u8; 32]> = (0..4)
            .map(|i| MerkleTreeV2::hash_chunk(&[i]))
            .collect();
        
        let tree = MerkleTreeV2::build(&hashes);
        
        for i in 0..4 {
            let proof = tree.generate_proof(i).unwrap();
            assert!(tree.verify_proof(&proof));
        }
    }
}
