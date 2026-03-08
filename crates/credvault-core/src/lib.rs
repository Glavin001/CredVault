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

use std::path::PathBuf;

/// Configuration for CredVault operations.
/// Allows overriding default paths and keys for testing.
#[derive(Debug, Clone, Default)]
pub struct VaultConfig {
    /// Override the data directory for Chromium browsers.
    /// When set, a single Chromium adapter is created using this directory.
    pub chromium_data_dir: Option<PathBuf>,
    /// Override the encryption key (bypasses OS keychain lookup).
    pub encryption_key: Option<String>,
}

/// Create adapters based on config.
fn get_configured_adapters(config: &VaultConfig) -> Vec<Box<dyn adapter::SourceAdapter>> {
    let mut adapters: Vec<Box<dyn adapter::SourceAdapter>> = Vec::new();

    if let (Some(ref data_dir), Some(ref key)) =
        (&config.chromium_data_dir, &config.encryption_key)
    {
        // Test mode: single adapter with overrides
        let browser_config = adapter::chromium::chromium_configs().into_iter().next().unwrap();
        let adapter = adapter::chromium::ChromiumAdapter::with_test_overrides(
            browser_config,
            data_dir.clone(),
            key.clone(),
        );
        adapters.push(Box::new(adapter));
    } else {
        // Production mode: all browsers
        for browser_config in adapter::chromium::chromium_configs() {
            adapters.push(Box::new(adapter::chromium::ChromiumAdapter::new(browser_config)));
        }
    }

    adapters
}

/// Scan the system for all available credential sources.
pub async fn discover_sources() -> Result<Vec<CredentialSource>> {
    discover_sources_with_config(&VaultConfig::default()).await
}

/// Scan with custom config.
pub async fn discover_sources_with_config(
    config: &VaultConfig,
) -> Result<Vec<CredentialSource>> {
    let adapters = get_configured_adapters(config);
    discovery::scan_with_adapters(&adapters)
}

/// List all credentials from specified sources (metadata only, no secrets).
pub async fn list_credentials(
    sources: Option<&[&str]>,
    filter: Option<&CredentialFilter>,
) -> Result<CredentialIndex> {
    list_credentials_with_config(&VaultConfig::default(), sources, filter).await
}

/// List credentials with custom config.
pub async fn list_credentials_with_config(
    config: &VaultConfig,
    sources: Option<&[&str]>,
    filter: Option<&CredentialFilter>,
) -> Result<CredentialIndex> {
    let adapters = get_configured_adapters(config);
    index::list_with_adapters(&adapters, sources, filter)
}

/// Extract full credentials (with secrets) for selected entries.
pub async fn extract_credentials(entry_ids: &[&str]) -> Result<Vec<Credential>> {
    extract_credentials_with_config(&VaultConfig::default(), entry_ids).await
}

/// Extract credentials with custom config.
pub async fn extract_credentials_with_config(
    config: &VaultConfig,
    entry_ids: &[&str],
) -> Result<Vec<Credential>> {
    let adapters = get_configured_adapters(config);
    index::extract_with_adapters(&adapters, entry_ids)
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
