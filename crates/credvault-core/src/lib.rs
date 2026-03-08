//! CredVault Core — credential extraction, indexing, and bundling library.
//!
//! This crate provides the core functionality for discovering credential sources
//! on a machine, listing credentials (metadata only), extracting secrets on-demand,
//! and packaging them into encrypted bundles.

pub mod adapter;
pub mod bundle;
pub mod crypto;
pub mod discovery;
pub mod error;
pub mod index;
pub mod platform;
pub mod types;

pub use error::{Error, Result};
pub use types::*;

/// Scan the system for all available credential sources.
pub async fn discover_sources() -> Result<Vec<CredentialSource>> {
    discovery::scan_sources().await
}

/// List all credentials from specified sources (metadata only, no secrets).
pub async fn list_credentials(
    sources: Option<&[&str]>,
    filter: Option<&CredentialFilter>,
) -> Result<CredentialIndex> {
    index::list_credentials(sources, filter).await
}

/// Extract full credentials (with secrets) for selected entries.
/// This is where OS auth prompts may be triggered.
pub async fn extract_credentials(entry_ids: &[&str]) -> Result<Vec<Credential>> {
    index::extract_credentials(entry_ids).await
}

/// Create an encrypted bundle from extracted credentials.
pub fn create_bundle(
    credentials: &[Credential],
    options: &BundleOptions,
) -> Result<Vec<u8>> {
    bundle::create_bundle(credentials, options)
}

/// Read and decrypt a bundle.
pub fn read_bundle(data: &[u8], password: &secrecy::SecretString) -> Result<BundleContents> {
    bundle::read_bundle(data, password)
}
