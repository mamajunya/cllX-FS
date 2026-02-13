use cllx_fs_pro::{Container, ContainerBuilder};
use cllx_fs_pro::core::MasterKey;

fn main() -> anyhow::Result<()> {
    // 生成 master key
    let master_key = MasterKey::generate();
    
    // 构建 container with security features
    let container = ContainerBuilder::new()
        .chunk_size(1024 * 1024)  // 1MB chunks
        .anti_ransom(true)
        .dedup(true)
        .master_key(master_key)
        .build()?;
    
    println!("Container created successfully!");
    println!("Chunk size: {} bytes", container.header.chunk_size);
    println!("Anti-ransomware: {}", container.policy.anti_ransom_mode);
    
    Ok(())
}
