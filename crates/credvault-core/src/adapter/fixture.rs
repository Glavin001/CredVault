use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use secrecy::SecretString;
use serde::Deserialize;

use crate::{
    adapter::{DynSourceAdapter, SourceAdapter},
    error::{CredVaultError, Result},
    types::{
        BrowserKind, Credential, CredentialEntry, CredentialSource, CredentialType, Platform,
        Profile, SourceStatus, SourceType,
    },
};

#[derive(Debug, Clone, Deserialize)]
struct FixtureSourceFile {
    pub id: String,
    pub name: String,
    pub platform: Option<Platform>,
    pub browser_kind: Option<BrowserKind>,
    #[serde(default)]
    pub profiles: Vec<Profile>,
    #[serde(default)]
    pub entries: Vec<FixtureEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct FixtureEntry {
    pub id: String,
    pub credential_type: CredentialType,
    pub domain: String,
    pub url: Option<String>,
    pub username: Option<String>,
    pub label: Option<String>,
    pub created: Option<chrono::DateTime<chrono::Utc>>,
    pub last_used: Option<chrono::DateTime<chrono::Utc>>,
    pub modified: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub secret: String,
}

#[derive(Debug)]
pub struct FixtureAdapter {
    source: CredentialSource,
    entries: Vec<FixtureEntry>,
    index_by_id: HashMap<String, usize>,
}

impl FixtureAdapter {
    fn from_path(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)?;
        let parsed: FixtureSourceFile = serde_json::from_str(&raw)
            .map_err(|_| CredVaultError::FixtureFileInvalid(path.into()))?;

        let source = CredentialSource {
            id: parsed.id,
            name: parsed.name,
            source_type: parsed
                .browser_kind
                .map(SourceType::Browser)
                .unwrap_or(SourceType::Fixture),
            platform: parsed.platform.unwrap_or(Platform::Fixture),
            status: SourceStatus::Accessible,
            credential_count: Some(parsed.entries.len() as u32),
            profiles: parsed.profiles,
        };

        let index_by_id = parsed
            .entries
            .iter()
            .enumerate()
            .map(|(idx, entry)| (entry.id.clone(), idx))
            .collect();

        Ok(Self {
            source,
            entries: parsed.entries,
            index_by_id,
        })
    }

    fn to_entry(&self, fixture: &FixtureEntry) -> CredentialEntry {
        CredentialEntry {
            id: fixture.id.clone(),
            source_id: self.source.id.clone(),
            credential_type: fixture.credential_type.clone(),
            domain: fixture.domain.clone(),
            url: fixture.url.clone(),
            username: fixture.username.clone(),
            label: fixture.label.clone(),
            created: fixture.created,
            last_used: fixture.last_used,
            modified: fixture.modified,
            tags: fixture.tags.clone(),
            duplicate_group: None,
        }
    }
}

impl SourceAdapter for FixtureAdapter {
    fn source(&self) -> &CredentialSource {
        &self.source
    }

    fn list_credentials(&self) -> Result<Vec<CredentialEntry>> {
        Ok(self
            .entries
            .iter()
            .map(|entry| self.to_entry(entry))
            .collect())
    }

    fn extract_credentials(&self, entry_ids: &[String]) -> Result<Vec<Credential>> {
        entry_ids
            .iter()
            .map(|entry_id| {
                let index = self
                    .index_by_id
                    .get(entry_id)
                    .ok_or_else(|| CredVaultError::CredentialNotFound(entry_id.clone()))?;
                let fixture = &self.entries[*index];
                Ok(Credential {
                    entry: self.to_entry(fixture),
                    secret: SecretString::new(fixture.secret.clone().into_boxed_str()),
                })
            })
            .collect()
    }
}

pub fn load_fixture_adapters(directory: impl AsRef<Path>) -> Result<Vec<DynSourceAdapter>> {
    let directory = directory.as_ref();
    if !directory.exists() {
        return Err(CredVaultError::FixtureDirectoryMissing(
            directory.to_path_buf(),
        ));
    }

    let mut files: Vec<PathBuf> = fs::read_dir(directory)?
        .filter_map(|entry| entry.ok().map(|value| value.path()))
        .filter(|path| {
            path.extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("json"))
                .unwrap_or(false)
        })
        .collect();

    files.sort();

    files
        .into_iter()
        .map(|path| {
            FixtureAdapter::from_path(&path).map(|adapter| Arc::new(adapter) as DynSourceAdapter)
        })
        .collect()
}
