//! Source adapters for different credential stores.

pub mod chromium;

use crate::types::*;
use crate::Result;

/// Trait that all credential source adapters must implement.
pub trait SourceAdapter: Send + Sync {
    /// Check if this source is present on the current machine.
    fn detect(&self) -> Result<Vec<DetectedSource>>;

    /// List credentials from this source (metadata only).
    fn list_credentials(&self, profile: &Profile) -> Result<Vec<CredentialEntry>>;

    /// Extract credentials with their secret values.
    fn extract_credentials(&self, profile: &Profile, entry_ids: &[&str])
        -> Result<Vec<Credential>>;

    /// What authentication is required to access this source.
    fn auth_requirement(&self) -> AuthRequirement;

    /// Which platforms this adapter supports.
    fn supported_platforms(&self) -> &[Platform];

    /// The source type this adapter handles.
    fn source_type(&self) -> SourceType;
}

/// Result of detecting a source on the system.
#[derive(Debug, Clone)]
pub struct DetectedSource {
    pub source: CredentialSource,
}

/// Get all registered adapters for the current platform.
pub fn get_adapters() -> Vec<Box<dyn SourceAdapter>> {
    let mut adapters: Vec<Box<dyn SourceAdapter>> = Vec::new();

    // Chromium-based browsers
    for config in chromium::chromium_configs() {
        adapters.push(Box::new(chromium::ChromiumAdapter::new(config)));
    }

    adapters
}
