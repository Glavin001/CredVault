use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CredVaultError {
    #[error("no sources were configured")]
    NoSourcesConfigured,
    #[error("fixture directory does not exist: {0}")]
    FixtureDirectoryMissing(PathBuf),
    #[error("fixture file is invalid: {0}")]
    FixtureFileInvalid(PathBuf),
    #[error("export file is invalid: {0}")]
    ExportFileInvalid(PathBuf),
    #[error("source not found: {0}")]
    SourceNotFound(String),
    #[error("credential not found: {0}")]
    CredentialNotFound(String),
    #[error("bundle password is required for credvault format")]
    MissingBundlePassword,
    #[error("bundle format is not supported for reading")]
    UnsupportedBundleRead,
    #[error("bundle data is invalid")]
    InvalidBundleData,
    #[error("bundle decryption failed")]
    BundleDecryptionFailed,
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("csv error: {0}")]
    Csv(#[from] csv::Error),
}

pub type Result<T> = std::result::Result<T, CredVaultError>;
