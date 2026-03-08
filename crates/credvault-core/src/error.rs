use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Source not found: {0}")]
    SourceNotFound(String),

    #[error("Credential not found: {0}")]
    CredentialNotFound(String),

    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Authentication required for {0}: {1}")]
    AuthRequired(String, String),

    #[error("Source is locked: {0}")]
    SourceLocked(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Invalid bundle: {0}")]
    InvalidBundle(String),

    #[error("Bundle decryption failed — wrong password or corrupted data")]
    BundleDecryptionFailed,

    #[error("Platform not supported: {0}")]
    PlatformNotSupported(String),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("{0}")]
    Other(String),
}
