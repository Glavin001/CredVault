//! Firefox browser adapter.
//!
//! Firefox stores credentials differently from Chromium:
//! - Passwords in `logins.json` (JSON, not SQLite)
//! - Encryption keys in `key4.db` (SQLite, NSS/PKCS#11)
//! - Profiles listed in `profiles.ini`

use crate::adapter::{DetectedSource, SourceAdapter};
use crate::crypto::firefox;
use crate::platform;
use crate::types::*;
use crate::{Error, Result};
use secrecy::SecretString;
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Adapter for Firefox browser.
pub struct FirefoxAdapter {
    /// If set, use this as the Firefox base directory instead of detecting from platform.
    override_base_dir: Option<PathBuf>,
}

impl Default for FirefoxAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl FirefoxAdapter {
    pub fn new() -> Self {
        Self {
            override_base_dir: None,
        }
    }

    /// Create an adapter with a test override directory.
    pub fn with_test_overrides(base_dir: PathBuf) -> Self {
        Self {
            override_base_dir: Some(base_dir),
        }
    }

    /// Get the Firefox base directory (contains profiles.ini and profile dirs).
    fn base_dir(&self) -> Option<PathBuf> {
        if let Some(ref dir) = self.override_base_dir {
            return Some(dir.clone());
        }
        platform::firefox_base_dir()
    }

    /// Discover Firefox profiles from the filesystem.
    fn discover_profiles(&self, base_dir: &Path) -> Result<Vec<Profile>> {
        let mut profiles = Vec::new();

        // Try parsing profiles.ini first
        let profiles_ini = base_dir.join("profiles.ini");
        if profiles_ini.exists() {
            if let Ok(content) = std::fs::read_to_string(&profiles_ini) {
                profiles.extend(parse_profiles_ini(&content, base_dir));
            }
        }

        // Fallback: scan for directories containing logins.json
        if profiles.is_empty() {
            if let Ok(entries) = std::fs::read_dir(base_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() && path.join("logins.json").exists() {
                        let name = entry.file_name().to_string_lossy().to_string();
                        profiles.push(Profile {
                            id: name.clone(),
                            name,
                            path: path.to_string_lossy().to_string(),
                        });
                    }
                }
            }
        }

        Ok(profiles)
    }

    /// Count credentials in a Firefox profile.
    fn count_credentials(&self, profile_path: &Path) -> u32 {
        let logins_path = profile_path.join("logins.json");
        if let Ok(data) = std::fs::read_to_string(&logins_path) {
            if let Ok(logins_file) = serde_json::from_str::<LoginsFile>(&data) {
                return logins_file.logins.len() as u32;
            }
        }
        0
    }

    /// Get the master decryption key for a Firefox profile.
    fn get_master_key(&self, profile_path: &Path) -> Result<Vec<u8>> {
        let key4_path = profile_path.join("key4.db");
        if !key4_path.exists() {
            return Err(Error::SourceNotFound(format!(
                "key4.db not found at {}",
                key4_path.display()
            )));
        }

        // Copy key4.db to temp to avoid lock conflicts
        let temp_dir = std::env::temp_dir();
        let temp_db = temp_dir.join(format!("credvault_key4_{}.db", uuid::Uuid::new_v4()));
        std::fs::copy(&key4_path, &temp_db)?;

        let result = (|| {
            let global_salt = firefox::read_key4_metadata(&temp_db)?;
            firefox::extract_master_key(&temp_db, &global_salt)
        })();

        let _ = std::fs::remove_file(&temp_db);
        result
    }
}

impl SourceAdapter for FirefoxAdapter {
    fn detect(&self) -> Result<Vec<DetectedSource>> {
        let base_dir = match self.base_dir() {
            Some(d) if d.exists() => d,
            _ => return Ok(vec![]),
        };

        let profiles = self.discover_profiles(&base_dir)?;
        if profiles.is_empty() {
            return Ok(vec![]);
        }

        let mut total_count = 0u32;
        for profile in &profiles {
            total_count += self.count_credentials(Path::new(&profile.path));
        }

        let source_id = format!(
            "firefox-{}",
            profiles.first().map_or("unknown", |p| p.id.as_str())
        )
        .to_lowercase()
        .replace(' ', "-");

        Ok(vec![DetectedSource {
            source: CredentialSource {
                id: source_id,
                name: format!(
                    "Firefox ({})",
                    if profiles.len() == 1 {
                        profiles[0].name.clone()
                    } else {
                        format!("{} profiles", profiles.len())
                    }
                ),
                source_type: SourceType::Browser(BrowserKind::Firefox),
                platform: Platform::current(),
                status: SourceStatus::Accessible,
                credential_count: Some(total_count),
                profiles,
            },
        }])
    }

    fn list_credentials(&self, profile: &Profile) -> Result<Vec<CredentialEntry>> {
        let profile_path = Path::new(&profile.path);
        let logins_path = profile_path.join("logins.json");

        let data = std::fs::read_to_string(&logins_path)
            .map_err(|e| Error::SourceNotFound(format!("Cannot read logins.json: {e}")))?;

        let logins_file: LoginsFile = serde_json::from_str(&data)?;
        let source_id = format!("firefox-{}", profile.id.to_lowercase().replace(' ', "-"));

        Ok(logins_file
            .logins
            .iter()
            .enumerate()
            .map(|(i, login)| {
                let domain = extract_hostname_domain(&login.hostname);
                CredentialEntry {
                    id: format!("{source_id}:login:{i:04}"),
                    source_id: source_id.clone(),
                    credential_type: CredentialType::Password,
                    domain,
                    url: Some(login.hostname.clone()),
                    username: None, // Username is encrypted in Firefox
                    label: None,
                    created: firefox_timestamp_to_datetime(login.time_created),
                    last_used: firefox_timestamp_to_datetime(login.time_last_used),
                    modified: firefox_timestamp_to_datetime(login.time_password_changed),
                }
            })
            .collect())
    }

    fn extract_credentials(
        &self,
        profile: &Profile,
        entry_ids: &[&str],
    ) -> Result<Vec<Credential>> {
        let profile_path = Path::new(&profile.path);
        let logins_path = profile_path.join("logins.json");

        let data = std::fs::read_to_string(&logins_path)
            .map_err(|e| Error::SourceNotFound(format!("Cannot read logins.json: {e}")))?;

        let logins_file: LoginsFile = serde_json::from_str(&data)?;
        let source_id = format!("firefox-{}", profile.id.to_lowercase().replace(' ', "-"));

        let master_key = self.get_master_key(profile_path)?;

        let mut credentials = Vec::new();

        for (i, login) in logins_file.logins.iter().enumerate() {
            let entry_id = format!("{source_id}:login:{i:04}");

            if !entry_ids.is_empty() && !entry_ids.contains(&entry_id.as_str()) {
                continue;
            }

            let username =
                match firefox::decrypt_login_field(&master_key, &login.encrypted_username) {
                    Ok(u) => u,
                    Err(e) => {
                        tracing::warn!(
                            "Failed to decrypt Firefox username for {}: {e}",
                            login.hostname
                        );
                        continue;
                    }
                };

            let password =
                match firefox::decrypt_login_field(&master_key, &login.encrypted_password) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!(
                            "Failed to decrypt Firefox password for {}: {e}",
                            login.hostname
                        );
                        continue;
                    }
                };

            let domain = extract_hostname_domain(&login.hostname);

            credentials.push(Credential {
                entry: CredentialEntry {
                    id: entry_id,
                    source_id: source_id.clone(),
                    credential_type: CredentialType::Password,
                    domain,
                    url: Some(login.hostname.clone()),
                    username: if username.is_empty() {
                        None
                    } else {
                        Some(username)
                    },
                    label: None,
                    created: firefox_timestamp_to_datetime(login.time_created),
                    last_used: firefox_timestamp_to_datetime(login.time_last_used),
                    modified: firefox_timestamp_to_datetime(login.time_password_changed),
                },
                secret: SecretString::from(password),
            });
        }

        Ok(credentials)
    }

    fn auth_requirement(&self) -> AuthRequirement {
        AuthRequirement::None
    }

    fn supported_platforms(&self) -> &[Platform] {
        &[Platform::MacOS, Platform::Linux, Platform::Windows]
    }

    fn source_type(&self) -> SourceType {
        SourceType::Browser(BrowserKind::Firefox)
    }
}

// ============================================================
// Firefox JSON structures
// ============================================================

#[derive(Deserialize)]
struct LoginsFile {
    logins: Vec<LoginEntry>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginEntry {
    hostname: String,
    encrypted_username: String,
    encrypted_password: String,
    #[serde(default)]
    time_created: Option<i64>,
    #[serde(default)]
    time_last_used: Option<i64>,
    #[serde(default)]
    time_password_changed: Option<i64>,
}

// ============================================================
// Helpers
// ============================================================

/// Extract domain from a Firefox hostname (which is typically a full URL like "https://example.com").
fn extract_hostname_domain(hostname: &str) -> String {
    hostname
        .split("://")
        .nth(1)
        .unwrap_or(hostname)
        .split('/')
        .next()
        .unwrap_or(hostname)
        .split(':')
        .next()
        .unwrap_or(hostname)
        .to_string()
}

/// Convert a Firefox timestamp (milliseconds since Unix epoch) to DateTime.
fn firefox_timestamp_to_datetime(timestamp: Option<i64>) -> Option<chrono::DateTime<chrono::Utc>> {
    let ts = timestamp?;
    if ts == 0 {
        return None;
    }
    let secs = ts / 1000;
    let nsecs = ((ts % 1000) * 1_000_000) as u32;
    chrono::DateTime::from_timestamp(secs, nsecs)
}

/// Parse Firefox profiles.ini to find profile directories.
fn parse_profiles_ini(content: &str, base_dir: &Path) -> Vec<Profile> {
    let mut profiles = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_path: Option<String> = None;
    let mut current_is_relative = true;

    for line in content.lines() {
        let line = line.trim();

        if line.starts_with('[') {
            // Save previous profile if valid
            if let (Some(name), Some(path)) = (current_name.take(), current_path.take()) {
                let full_path = if current_is_relative {
                    base_dir.join(&path)
                } else {
                    PathBuf::from(&path)
                };
                if full_path.join("logins.json").exists() {
                    profiles.push(Profile {
                        id: name.clone(),
                        name,
                        path: full_path.to_string_lossy().to_string(),
                    });
                }
            }
            current_is_relative = true;
        } else if let Some(value) = line.strip_prefix("Name=") {
            current_name = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("Path=") {
            current_path = Some(value.to_string());
        } else if line == "IsRelative=0" {
            current_is_relative = false;
        }
    }

    // Don't forget the last profile
    if let (Some(name), Some(path)) = (current_name, current_path) {
        let full_path = if current_is_relative {
            base_dir.join(&path)
        } else {
            PathBuf::from(&path)
        };
        if full_path.join("logins.json").exists() {
            profiles.push(Profile {
                id: name.clone(),
                name,
                path: full_path.to_string_lossy().to_string(),
            });
        }
    }

    profiles
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_hostname_domain() {
        assert_eq!(extract_hostname_domain("https://github.com"), "github.com");
        assert_eq!(
            extract_hostname_domain("https://accounts.google.com"),
            "accounts.google.com"
        );
        assert_eq!(
            extract_hostname_domain("http://localhost:8080"),
            "localhost"
        );
        assert_eq!(extract_hostname_domain("github.com"), "github.com");
    }

    #[test]
    fn test_firefox_timestamp() {
        // 2024-01-01 00:00:00 UTC = 1704067200000 ms
        let dt = firefox_timestamp_to_datetime(Some(1704067200000));
        assert!(dt.is_some());
        assert_eq!(dt.unwrap().timestamp(), 1704067200);

        assert!(firefox_timestamp_to_datetime(Some(0)).is_none());
        assert!(firefox_timestamp_to_datetime(None).is_none());
    }

    #[test]
    fn test_parse_profiles_ini() {
        let temp = tempfile::TempDir::new().unwrap();

        // Create a profile dir with logins.json
        let profile_dir = temp.path().join("abc123.default-release");
        std::fs::create_dir_all(&profile_dir).unwrap();
        std::fs::write(profile_dir.join("logins.json"), r#"{"logins":[]}"#).unwrap();

        let ini = "[Profile0]\nName=default-release\nIsRelative=1\nPath=abc123.default-release\n\n\
             [Profile1]\nName=old\nIsRelative=1\nPath=xyz.old\n"
            .to_string();

        let profiles = parse_profiles_ini(&ini, temp.path());
        // Only the first profile has logins.json
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "default-release");
    }

    #[test]
    fn test_list_credentials_from_logins_json() {
        let temp = tempfile::TempDir::new().unwrap();
        let profile_dir = temp.path().join("test-profile");
        std::fs::create_dir_all(&profile_dir).unwrap();

        // Create a test logins.json
        let logins = serde_json::json!({
            "nextId": 3,
            "logins": [
                {
                    "hostname": "https://github.com",
                    "encryptedUsername": "dGVzdA==",
                    "encryptedPassword": "dGVzdA==",
                    "timeCreated": 1704067200000i64,
                    "timeLastUsed": 1704153600000i64,
                    "timePasswordChanged": 1704067200000i64
                },
                {
                    "hostname": "https://accounts.google.com",
                    "encryptedUsername": "dGVzdA==",
                    "encryptedPassword": "dGVzdA==",
                    "timeCreated": 1703980800000i64,
                    "timeLastUsed": 1704240000000i64,
                    "timePasswordChanged": 1703980800000i64
                }
            ]
        });

        std::fs::write(
            profile_dir.join("logins.json"),
            serde_json::to_string(&logins).unwrap(),
        )
        .unwrap();

        let adapter = FirefoxAdapter::with_test_overrides(temp.path().to_path_buf());
        let profile = Profile {
            id: "test-profile".to_string(),
            name: "test-profile".to_string(),
            path: profile_dir.to_string_lossy().to_string(),
        };

        let entries = adapter.list_credentials(&profile).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].domain, "github.com");
        assert_eq!(entries[0].credential_type, CredentialType::Password);
        assert_eq!(entries[1].domain, "accounts.google.com");
        assert!(entries[0].created.is_some());
    }
}
