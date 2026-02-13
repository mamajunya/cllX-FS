pub mod tree;

use blake3::Hasher;
use serde::{Deserialize, Serialize};

pub use tree::{MerkleTreeV2, MerkleProof};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    pub root_hash: [u8; 32],
    pub nodes: Vec<[u8; 32]>,
    pub leaf_count: usize,
}

impl MerkleTree {
    /// 构建 Merkle tree from chunk hashes
    pub fn build(chunk_hashes: &[[u8; 32]]) -> Self {
        let mut nodes = chunk_hashes.to_vec();
        let leaf_count = nodes.len();
        
        // 构建 tree bottom-up
        let mut level_size = nodes.len();
        while level_size > 1 {
            let mut next_level = Vec::new();
            for i in (0..level_size).step_by(2) {
                let left = &nodes[i];
                let right = if i + 1 < level_size {
                    &nodes[i + 1]
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
        }
    }

    /// 验证 a chunk against the tree
    pub fn verify_chunk(&self, chunk_index: usize, chunk_hash: &[u8; 32]) -> bool {
        if chunk_index >= self.leaf_count {
            return false;
        }
        self.nodes[chunk_index] == *chunk_hash
    }

    fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(left);
        hasher.update(right);
        *hasher.finalize().as_bytes()
    }

    pub fn hash_chunk(data: &[u8]) -> [u8; 32] {
        *blake3::hash(data).as_bytes()
    }
}
