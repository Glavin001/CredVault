use chrono::{DateTime, Utc};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

// ============================================================
// Source Discovery Types
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSource {
    pub id: String,
    pub name: String,
    pub source_type: SourceType,
    pub platform: Platform,
    pub status: SourceStatus,
    pub credential_count: Option<u32>,
    pub profiles: Vec<Profile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SourceType {
    Browser(BrowserKind),
    OsKeychain,
    PasswordManager(ManagerKind),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum BrowserKind {
    Chrome,
    Edge,
    Brave,
    Firefox,
    Safari,
    Vivaldi,
    Opera,
    Arc,
}

impl BrowserKind {
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Chrome => "Chrome",
            Self::Edge => "Edge",
            Self::Brave => "Brave",
            Self::Firefox => "Firefox",
            Self::Safari => "Safari",
            Self::Vivaldi => "Vivaldi",
            Self::Opera => "Opera",
            Self::Arc => "Arc",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ManagerKind {
    OnePassword,
    KeePassXc,
    Bitwarden,
    LastPass,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Platform {
    MacOS,
    Windows,
    Linux,
}

impl Platform {
    pub fn current() -> Self {
        if cfg!(target_os = "macos") {
            Self::MacOS
        } else if cfg!(target_os = "windows") {
            Self::Windows
        } else {
            Self::Linux
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SourceStatus {
    Accessible,
    Locked,
    RequiresAuth,
    NotFound,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub path: String,
}

// ============================================================
// Credential Types
// ============================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CredentialType {
    Password,
    Cookie,
    ApiKey,
    Certificate,
    SessionToken,
}

/// Credential metadata — no secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

/// Full credential with the secret value.
#[derive(Debug, Clone)]
pub struct Credential {
    pub entry: CredentialEntry,
    pub secret: SecretString,
}

// ============================================================
// Credential Index
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialIndex {
    pub entries: Vec<CredentialEntry>,
    pub duplicates: Vec<DuplicateGroup>,
    pub sources_scanned: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateGroup {
    pub domain: String,
    pub username: Option<String>,
    pub entry_ids: Vec<String>,
}

// ============================================================
// Filtering
// ============================================================

#[derive(Debug, Clone, Default)]
pub struct CredentialFilter {
    pub domains: Option<Vec<String>>,
    pub sources: Option<Vec<String>>,
    pub types: Option<Vec<CredentialType>>,
    pub search: Option<String>,
}

impl CredentialFilter {
    pub fn matches(&self, entry: &CredentialEntry) -> bool {
        if let Some(ref domains) = self.domains {
            let domain_match = domains.iter().any(|d| {
                if let Some(stripped) = d.strip_prefix('*') {
                    entry.domain.ends_with(stripped)
                } else {
                    entry.domain == *d
                }
            });
            if !domain_match {
                return false;
            }
        }

        if let Some(ref sources) = self.sources {
            if !sources.contains(&entry.source_id) {
                return false;
            }
        }

        if let Some(ref types) = self.types {
            if !types.contains(&entry.credential_type) {
                return false;
            }
        }

        if let Some(ref search) = self.search {
            let search_lower = search.to_lowercase();
            let in_domain = entry.domain.to_lowercase().contains(&search_lower);
            let in_username = entry
                .username
                .as_ref()
                .is_some_and(|u| u.to_lowercase().contains(&search_lower));
            let in_label = entry
                .label
                .as_ref()
                .is_some_and(|l| l.to_lowercase().contains(&search_lower));
            if !in_domain && !in_username && !in_label {
                return false;
            }
        }

        true
    }
}

// ============================================================
// Bundle / Export Types
// ============================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum BundleFormat {
    CredVault,
    Csv,
    Env,
    AgentConfig,
}

impl std::fmt::Display for BundleFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CredVault => write!(f, "credvault"),
            Self::Csv => write!(f, "csv"),
            Self::Env => write!(f, "env"),
            Self::AgentConfig => write!(f, "agent-config"),
        }
    }
}

impl std::str::FromStr for BundleFormat {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "credvault" => Ok(Self::CredVault),
            "csv" => Ok(Self::Csv),
            "env" => Ok(Self::Env),
            "agent-config" | "agent_config" | "agentconfig" => Ok(Self::AgentConfig),
            _ => Err(format!("Unknown format: {s}")),
        }
    }
}

pub struct BundleOptions {
    pub format: BundleFormat,
    pub password: SecretString,
    pub label: String,
    pub expires: Option<DateTime<Utc>>,
    pub include_metadata: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleContents {
    pub label: String,
    pub created: DateTime<Utc>,
    pub expires: Option<DateTime<Utc>>,
    pub bundle_id: String,
    pub credentials: Vec<BundleCredential>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleCredential {
    pub domain: String,
    pub url: Option<String>,
    pub username: Option<String>,
    pub password: String,
    pub credential_type: CredentialType,
    pub label: Option<String>,
}

// ============================================================
// Auth Types
// ============================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthRequirement {
    None,
    OsPrompt,
    MasterPassword,
    FileKey,
}
