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
    /// Override the data directory for Firefox profiles.
    /// Used for testing the high-level discovery and listing APIs.
    pub firefox_data_dir: Option<PathBuf>,
    /// Override the encryption key (bypasses OS keychain lookup).
    pub encryption_key: Option<String>,
}

/// Create adapters based on config.
fn get_configured_adapters(config: &VaultConfig) -> Vec<Box<dyn adapter::SourceAdapter>> {
    let mut adapters: Vec<Box<dyn adapter::SourceAdapter>> = Vec::new();
    let chromium_override = if let (Some(ref data_dir), Some(ref key)) =
        (&config.chromium_data_dir, &config.encryption_key)
    {
        // Test mode: single adapter with overrides. Keep using stable Chrome so
        // test fixtures and source IDs remain predictable even as more Linux
        // browser channels are added.
        let browser_config = adapter::chromium::chromium_configs()
            .into_iter()
            .find(|config| config.name == "Chrome")
            .unwrap();
        let adapter = adapter::chromium::ChromiumAdapter::with_test_overrides(
            browser_config,
            data_dir.clone(),
            key.clone(),
        );
        adapters.push(Box::new(adapter));
        true
    } else {
        // Production mode: all Chromium-family browsers supported on this platform.
        for browser_config in adapter::chromium::chromium_configs() {
            adapters.push(Box::new(adapter::chromium::ChromiumAdapter::new(
                browser_config,
            )));
        }
        false
    };

    if let Some(ref firefox_dir) = config.firefox_data_dir {
        adapters.push(Box::new(
            adapter::firefox::FirefoxAdapter::with_test_overrides(firefox_dir.clone()),
        ));
    } else if !chromium_override {
        adapters.push(Box::new(adapter::firefox::FirefoxAdapter::new()));
    }

    adapters
}

/// Scan the system for all available credential sources.
pub async fn discover_sources() -> Result<Vec<CredentialSource>> {
    discover_sources_with_config(&VaultConfig::default()).await
}

/// Scan with custom config.
pub async fn discover_sources_with_config(config: &VaultConfig) -> Result<Vec<CredentialSource>> {
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
pub fn create_bundle(credentials: &[Credential], options: &BundleOptions) -> Result<Vec<u8>> {
    bundle::create_bundle(credentials, options)
}

/// Read and decrypt a bundle.
pub fn read_bundle(data: &[u8], password: &secrecy::SecretString) -> Result<BundleContents> {
    bundle::read_bundle(data, password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::chromium::{create_test_login_db, test_encryption_key, TestLoginEntry};
    use serde_json::json;
    use tempfile::TempDir;

    fn create_test_firefox_profile(base_dir: &std::path::Path) -> PathBuf {
        let profile_dir = base_dir.join("test.default-release");
        std::fs::create_dir_all(&profile_dir).unwrap();
        std::fs::write(
            base_dir.join("profiles.ini"),
            "[Profile0]\nName=default-release\nIsRelative=1\nPath=test.default-release\n",
        )
        .unwrap();
        std::fs::write(
            profile_dir.join("logins.json"),
            json!({
                "nextId": 1,
                "logins": [{
                    "hostname": "https://firefox.example.com",
                    "encryptedUsername": "dGVzdA==",
                    "encryptedPassword": "dGVzdA==",
                    "timeCreated": 1704067200000i64,
                    "timeLastUsed": 1704067200000i64,
                    "timePasswordChanged": 1704067200000i64
                }]
            })
            .to_string(),
        )
        .unwrap();

        profile_dir
    }

    #[tokio::test]
    async fn test_default_config_registers_firefox_adapter() {
        let adapters = get_configured_adapters(&VaultConfig::default());
        assert!(adapters
            .iter()
            .any(|adapter| adapter.source_type() == SourceType::Browser(BrowserKind::Firefox)));
    }

    #[tokio::test]
    async fn test_discover_and_list_with_firefox_override() {
        let chromium = TempDir::new().unwrap();
        let firefox = TempDir::new().unwrap();
        create_test_firefox_profile(firefox.path());

        let config = VaultConfig {
            chromium_data_dir: Some(chromium.path().to_path_buf()),
            firefox_data_dir: Some(firefox.path().to_path_buf()),
            encryption_key: Some(test_encryption_key().to_string()),
            ..Default::default()
        };

        let sources = discover_sources_with_config(&config).await.unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(
            sources[0].source_type,
            SourceType::Browser(BrowserKind::Firefox)
        );

        let index = list_credentials_with_config(&config, None, None)
            .await
            .unwrap();
        assert_eq!(index.entries.len(), 1);
        assert_eq!(index.entries[0].domain, "firefox.example.com");
    }

    #[tokio::test]
    async fn test_discover_and_list_with_chrome_and_firefox_overrides() {
        let chromium = TempDir::new().unwrap();
        let profile_dir = chromium.path().join("Default");
        std::fs::create_dir_all(&profile_dir).unwrap();
        create_test_login_db(
            &profile_dir.join("Login Data"),
            &[TestLoginEntry {
                url: "https://chrome.example.com/login".to_string(),
                username: "chrome-user".to_string(),
                password: "chrome-pass".to_string(),
                date_created: None,
                date_last_used: None,
                date_modified: None,
            }],
            test_encryption_key(),
        )
        .unwrap();

        let firefox = TempDir::new().unwrap();
        create_test_firefox_profile(firefox.path());

        let config = VaultConfig {
            chromium_data_dir: Some(chromium.path().to_path_buf()),
            firefox_data_dir: Some(firefox.path().to_path_buf()),
            encryption_key: Some(test_encryption_key().to_string()),
        };

        let sources = discover_sources_with_config(&config).await.unwrap();
        assert_eq!(sources.len(), 2);
        assert!(sources
            .iter()
            .any(|source| source.source_type == SourceType::Browser(BrowserKind::Chrome)));
        assert!(sources
            .iter()
            .any(|source| source.source_type == SourceType::Browser(BrowserKind::Firefox)));

        let index = list_credentials_with_config(&config, None, None)
            .await
            .unwrap();
        assert_eq!(index.entries.len(), 2);
        assert!(index
            .entries
            .iter()
            .any(|entry| entry.domain == "chrome.example.com"));
        assert!(index
            .entries
            .iter()
            .any(|entry| entry.domain == "firefox.example.com"));
    }
}
