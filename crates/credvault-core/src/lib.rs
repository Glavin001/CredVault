mod adapter;
mod bundle;
mod error;
mod registry;
mod types;

use std::path::Path;

pub use crate::error::{CredVaultError, Result};
pub use crate::types::{
    BrowserKind, BundleArtifact, BundleContents, BundleFormat, BundleOptions, Credential,
    CredentialEntry, CredentialFilter, CredentialIndex, CredentialSource, CredentialType,
    DuplicateGroup, ManagerKind, Platform, Profile, SourceStatus, SourceType,
};
use registry::SourceRegistry;

pub struct CredVault {
    registry: SourceRegistry,
}

impl CredVault {
    pub fn from_fixture_dir(directory: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            registry: SourceRegistry::from_fixture_dir(directory)?,
        })
    }

    pub fn discover_sources(&self) -> Vec<CredentialSource> {
        self.registry.discover_sources()
    }

    pub fn list_credentials(
        &self,
        sources: Option<&[String]>,
        filter: Option<&CredentialFilter>,
    ) -> Result<CredentialIndex> {
        self.registry.list_credentials(sources, filter)
    }

    pub fn extract_credentials(&self, entry_ids: &[String]) -> Result<Vec<Credential>> {
        self.registry.extract_credentials(entry_ids)
    }

    pub fn create_bundle(
        &self,
        credentials: &[Credential],
        options: &BundleOptions,
    ) -> Result<BundleArtifact> {
        create_bundle(credentials, options)
    }

    pub fn read_bundle(
        &self,
        data: &[u8],
        password: &secrecy::SecretString,
    ) -> Result<BundleContents> {
        read_bundle(data, password)
    }
}

pub fn create_bundle(
    credentials: &[Credential],
    options: &BundleOptions,
) -> Result<BundleArtifact> {
    bundle::create_bundle(credentials, options)
}

pub fn read_bundle(data: &[u8], password: &secrecy::SecretString) -> Result<BundleContents> {
    bundle::read_bundle(data, password)
}
