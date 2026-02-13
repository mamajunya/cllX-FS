use crate::container::{Container, SuperHeader, SecurityPolicy, ChunkIndex};
use crate::core::{Result, MasterKey};

pub struct ContainerBuilder {
    header: SuperHeader,
    policy: SecurityPolicy,
    master_key: Option<MasterKey>,
}

impl ContainerBuilder {
    pub fn new() -> Self {
        Self {
            header: SuperHeader::default(),
            policy: SecurityPolicy::default(),
            master_key: None,
        }
    }

    pub fn chunk_size(mut self, size: u32) -> Self {
        self.header.chunk_size = size;
        self
    }

    pub fn anti_ransom(mut self, enabled: bool) -> Self {
        self.policy.anti_ransom_mode = enabled;
        self
    }

    pub fn stealth_mode(mut self, enabled: bool) -> Self {
        self.policy.stealth_mode = enabled;
        self
    }

    pub fn timelock(mut self, enabled: bool) -> Self {
        self.policy.timelock_flag = enabled;
        self
    }

    pub fn dedup(mut self, enabled: bool) -> Self {
        self.policy.dedup_mode = enabled;
        self
    }

    pub fn master_key(mut self, key: MasterKey) -> Self {
        self.master_key = Some(key);
        self
    }

    pub fn build(self) -> Result<Container> {
        let master_key = self.master_key.unwrap_or_else(|| MasterKey::generate());
        
        Ok(Container {
            header: self.header,
            policy: self.policy,
            capsules: Vec::new(),
            chunk_index: ChunkIndex { entries: Vec::new() },
            merkle_tree: None,
        })
    }
}

impl Default for ContainerBuilder {
    fn default() -> Self {
        Self::new()
    }
}
