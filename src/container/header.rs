use serde::{Deserialize, Serialize};

pub const MAGIC: &[u8; 11] = b"CLLXFS-PRO\0";
pub const VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuperHeader {
    pub magic: [u8; 11],
    pub version: u32,
    pub n: u32,              // MLWE parameter
    pub q: u32,              // MLWE modulus
    pub chunk_size: u32,     // Default 1MB
    pub ntt_flag: bool,
    pub capsule_count: u32,
    pub tree_hash_algo: HashAlgo,
    pub file_nonce: [u8; 12],
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum HashAlgo {
    Blake3,
    Sha3_256,
}

impl Default for SuperHeader {
    fn default() -> Self {
        let mut file_nonce = [0u8; 12];
        rand::Rng::fill(&mut rand::thread_rng(), &mut file_nonce);
        
        Self {
            magic: *MAGIC,
            version: VERSION,
            n: 1024,
            q: 12289,
            chunk_size: 1024 * 1024, // 1MB
            ntt_flag: true,
            capsule_count: 0,
            tree_hash_algo: HashAlgo::Blake3,
            file_nonce,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    pub anti_ransom_mode: bool,
    pub stealth_mode: bool,
    pub timelock_flag: bool,
    pub share_mode: bool,
    pub dedup_mode: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            anti_ransom_mode: false,
            stealth_mode: false,
            timelock_flag: false,
            share_mode: false,
            dedup_mode: false,
        }
    }
}
