use chrono::{DateTime, Utc};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Platform {
    MacOs,
    Windows,
    Linux,
    Fixture,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BrowserKind {
    Chrome,
    Chromium,
    Brave,
    Edge,
    Firefox,
    Safari,
    Arc,
    Vivaldi,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ManagerKind {
    OnePassword,
    KeePassXc,
    Bitwarden,
    LastPass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
pub enum SourceType {
    Browser(BrowserKind),
    OsKeychain,
    PasswordManager(ManagerKind),
    Fixture,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceStatus {
    Accessible,
    Locked,
    RequiresAuth,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialType {
    Password,
    Cookie,
    ApiKey,
    Certificate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub path: Option<String>,
    pub is_default: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialSource {
    pub id: String,
    pub name: String,
    pub source_type: SourceType,
    pub platform: Platform,
    pub status: SourceStatus,
    pub credential_count: Option<u32>,
    #[serde(default)]
    pub profiles: Vec<Profile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialEntry {
    pub id: String,
    pub source_id: String,
    pub credential_type: CredentialType,
    pub domain: String,
    pub url: Option<String>,
    pub username: Option<String>,
    pub label: Option<String>,
    pub created: Option<DateTime<Utc>>,
    pub last_used: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub duplicate_group: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuplicateGroup {
    pub id: String,
    pub domain: String,
    pub username: Option<String>,
    pub entry_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CredentialFilter {
    pub domains: Option<Vec<String>>,
    pub sources: Option<Vec<String>>,
    pub types: Option<Vec<CredentialType>>,
    pub search: Option<String>,
    pub min_last_used: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialIndex {
    pub entries: Vec<CredentialEntry>,
    pub duplicates: Vec<DuplicateGroup>,
    pub sources_scanned: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Credential {
    pub entry: CredentialEntry,
    pub secret: SecretString,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BundleFormat {
    CredVault,
    Csv,
    Env,
    AgentConfig,
}

#[derive(Debug, Clone)]
pub struct BundleOptions {
    pub format: BundleFormat,
    pub password: Option<SecretString>,
    pub label: String,
    pub expires: Option<DateTime<Utc>>,
    pub include_metadata: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleArtifact {
    pub format: BundleFormat,
    pub encrypted: bool,
    pub file_extension: &'static str,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct BundleContents {
    pub bundle_id: String,
    pub label: String,
    pub created: DateTime<Utc>,
    pub expires: Option<DateTime<Utc>>,
    pub credentials: Vec<Credential>,
}
