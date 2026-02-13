use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Crypto error: {0}")]
    Crypto(String),
    
    #[error("Invalid container format")]
    InvalidFormat,
    
    #[error("Authentication failed")]
    AuthFailed,
    
    #[error("Integrity check failed")]
    IntegrityFailed,
    
    #[error("Capsule decryption failed")]
    CapsuleDecryptFailed,
    
    #[error("Time-lock not expired")]
    TimeLocked,
    
    #[error("Anti-ransomware protection triggered")]
    RansomwareDetected,
    
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(String),
}

pub type Result<T> = std::result::Result<T, Error>;
