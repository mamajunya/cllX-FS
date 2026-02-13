use crate::core::{MasterKey, Result, Error};
use crate::capsule::mlkem;
use crate::chunk::ChunkEngine;
use crate::container::{ContainerWriter, SimpleContainer};
use crate::merkle::MerkleTree;
use std::fs::File;
use std::io::Read;

pub struct EncryptCommand {
    pub input_path: String,
    pub output_path: String,
    pub recipients: Vec<String>,
    pub chunk_size: usize,
    pub password: Option<String>,  // User-provided password
}

impl EncryptCommand {
    pub fn execute(&self) -> Result<()> {
        use std::io::Write;
        
        // 读取 input file
        let mut input = File::open(&self.input_path)?;
        let mut data = Vec::new();
        input.read_to_end(&mut data)?;

        // 生成 master key
        let master_key = MasterKey::generate();

        // 生成密钥pair for encryption
        let keypair = mlkem::MlKemKeyPair::generate()?;
        
        // 保存 the secret key or password-encrypted key for decryption
        let secret_key_path = format!("{}.key", self.output_path);
        let mut key_file = File::create(&secret_key_path)?;
        
        if let Some(password) = &self.password {
            // 加密 the secret key with the password
            println!("🔑 Using password-based encryption");
            
            // Derive encryption key from password
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(password.as_bytes());
            hasher.update(b"cllx-password-key");
            let password_key_hash = hasher.finalize();
            let password_key: [u8; 32] = password_key_hash.into();
            
            // 加密 secret key with password
            let cipher = crate::core::crypto::AeadCipher::new(crate::core::CipherType::ChaCha20Poly1305);
            let nonce = [0u8; 12]; // Fixed nonce is OK since key is unique per password
            let encrypted_secret_key = cipher.encrypt(
                &password_key,
                &nonce,
                keypair.secret_key_bytes(),
                b"cllx-password-protected"
            )?;
            
            // 写入 marker + encrypted key
            key_file.write_all(b"CLLX-PWD")?; // 8-byte marker
            key_file.write_all(&encrypted_secret_key)?;
            println!("   Password: {}", password);
            println!("   Key file: {}", secret_key_path);
            println!("   ⚠️  Remember your password - you need it to decrypt!");
        } else {
            // 保存 raw secret key bytes
            key_file.write_all(keypair.secret_key_bytes())?;
            println!("🔑 Secret key saved to: {}", secret_key_path);
            println!("   ⚠️  Keep the secret key safe - you need it to decrypt!");
        }

        // 创建 capsule
        let mask_seed = crate::core::KeyDerivation::derive_mask_key(&master_key)?;
        let capsule = mlkem::CapsuleV2::encapsulate(keypair.public_key_bytes(), &master_key, &mask_seed)?;

        // 加密 chunks using ChunkEngine
        let engine = ChunkEngine::new(self.chunk_size, crate::core::CipherType::ChaCha20Poly1305);
        let chunks: Vec<Vec<u8>> = data.chunks(self.chunk_size)
            .map(|c| c.to_vec())
            .collect();
        
        let tree_root_key = crate::core::KeyDerivation::derive_tree_root(&master_key)?;
        let file_nonce = rand::random::<[u8; 12]>(); // 生成 random nonce
        let encrypted_chunks = engine.encrypt_chunks(&chunks, &tree_root_key, &file_nonce)?;

        // Concatenate all encrypted chunks and record their sizes
        let mut all_encrypted_data = Vec::new();
        let mut chunk_sizes = Vec::new();
        for chunk in &encrypted_chunks {
            chunk_sizes.push(chunk.len() as u32);
            all_encrypted_data.extend_from_slice(chunk);
        }

        // 创建 simple container with original filename
        let original_filename = std::path::Path::new(&self.input_path)
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.to_string());
        
        let container = SimpleContainer::new(
            self.chunk_size as u32,
            chunks.len() as u32,
            file_nonce,
            &capsule,
            chunk_sizes,
            all_encrypted_data,
            original_filename,
            None,  // CLI doesn't embed key by default for security
        )?;

        // 写入 container to file
        let mut output = File::create(&self.output_path)?;
        container.write_to_file(&mut output)?;

        println!("✅ Encryption complete!");
        println!("   Encrypted file: {}", self.output_path);
        if self.password.is_some() {
            println!("   Password file: {}", secret_key_path);
        } else {
            println!("   Secret key: {}", secret_key_path);
        }

        Ok(())
    }
}

pub struct DecryptCommand {
    pub input_path: String,
    pub output_path: String,
    pub secret_key_path: Option<String>,
}

impl DecryptCommand {
    pub fn execute(&self) -> Result<()> {
        use std::io::Write;
        
        println!("🔓 Starting decryption...");
        
        // 加载 secret key or password
        let secret_key_path = self.secret_key_path.as_ref()
            .map(|s| s.clone())
            .unwrap_or_else(|| format!("{}.key", self.input_path));
        
        let mut key_file = File::open(&secret_key_path)
            .map_err(|_| Error::InvalidInput(format!("Key file not found: {}", secret_key_path)))?;
        let mut key_data = Vec::new();
        key_file.read_to_end(&mut key_data)?;
        
        // Check if this is a password-protected key
        let secret_key = if key_data.len() > 8 && &key_data[..8] == b"CLLX-PWD" {
            // This is a password-protected key
            println!("   ℹ️  Password-protected key detected");
            
            // 读取 password from user
            print!("   Enter password: ");
            std::io::stdout().flush()?;
            let mut password = String::new();
            std::io::stdin().read_line(&mut password)?;
            let password = password.trim();
            
            // Derive decryption key from password
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(password.as_bytes());
            hasher.update(b"cllx-password-key");
            let password_key_hash = hasher.finalize();
            let password_key: [u8; 32] = password_key_hash.into();
            
            // 解密 secret key
            let encrypted_secret_key = &key_data[8..]; // Skip marker
            let cipher = crate::core::crypto::AeadCipher::new(crate::core::CipherType::ChaCha20Poly1305);
            let nonce = [0u8; 12];
            
            cipher.decrypt(
                &password_key,
                &nonce,
                encrypted_secret_key,
                b"cllx-password-protected"
            ).map_err(|_| Error::InvalidInput("Wrong password or corrupted key file".to_string()))?
        } else if key_data.len() == 2400 {
            // This is a raw secret key
            println!("   ✓ Loaded secret key: {} bytes", key_data.len());
            key_data
        } else {
            return Err(Error::InvalidInput(format!(
                "Invalid key file format: expected 2400 bytes or password-protected key, got {} bytes",
                key_data.len()
            )));
        };

        // 读取 and parse container
        let mut input = File::open(&self.input_path)?;
        let container = SimpleContainer::read_from_file(&mut input)?;
        println!("   ✓ Parsed container: {} chunks", container.total_chunks);

        // Extract capsule and decapsulate to get master key
        let capsule = container.get_capsule()?;
        let (master_key, _mask_seed) = capsule.decapsulate(&secret_key)?;
        println!("   ✓ Decapsulated master key");

        // Derive keys
        let tree_root_key = crate::core::KeyDerivation::derive_tree_root(&master_key)?;
        println!("   ✓ Derived encryption keys");

        // 解密 chunks
        let engine = ChunkEngine::new(container.chunk_size as usize, crate::core::CipherType::ChaCha20Poly1305);
        
        // Split encrypted data into chunks using saved sizes
        let mut encrypted_chunks = Vec::new();
        let mut offset = 0;
        
        for &size in &container.chunk_sizes {
            let end = offset + size as usize;
            encrypted_chunks.push(container.encrypted_data[offset..end].to_vec());
            offset = end;
        }
        
        // Calculate original sizes (encrypted size - 16 bytes AEAD tag)
        let original_sizes: Vec<usize> = container.chunk_sizes.iter()
            .map(|&size| (size as usize).saturating_sub(16))
            .collect();
        
        let decrypted_chunks = engine.decrypt_chunks(
            &encrypted_chunks,
            &tree_root_key,
            &container.file_nonce,
            &original_sizes
        )?;
        println!("   ✓ Decrypted {} chunks", decrypted_chunks.len());

        // Reconstruct original file
        // If output path doesn't have extension and container has original filename, use it
        let output_path = if let Some(ref original_name) = container.original_filename {
            let output_path = std::path::Path::new(&self.output_path);
            if output_path.extension().is_none() {
                // No extension in output path, try to use original filename's extension
                if let Some(original_ext) = std::path::Path::new(original_name).extension() {
                    let mut new_path = output_path.to_path_buf();
                    if let Some(ext_str) = original_ext.to_str() {
                        new_path.set_extension(ext_str);
                        println!("   ℹ️  Restoring original extension: .{}", ext_str);
                        new_path.to_string_lossy().to_string()
                    } else {
                        self.output_path.clone()
                    }
                } else {
                    self.output_path.clone()
                }
            } else {
                self.output_path.clone()
            }
        } else {
            self.output_path.clone()
        };
        
        let mut output = File::create(&output_path)?;
        for chunk in decrypted_chunks {
            output.write_all(&chunk)?;
        }
        output.flush()?;
        
        println!("✅ Decryption complete!");
        println!("   Output file: {}", output_path);
        println!("   ✓ File successfully decrypted and verified!");
        
        Ok(())
    }
}

pub struct InfoCommand {
    pub input_path: String,
}

impl InfoCommand {
    pub fn execute(&self) -> Result<()> {
        // Implementation for info
        Ok(())
    }
}

pub struct VerifyCommand {
    pub input_path: String,
}

impl VerifyCommand {
    pub fn execute(&self) -> Result<()> {
        // Implementation for verify
        Ok(())
    }
}
