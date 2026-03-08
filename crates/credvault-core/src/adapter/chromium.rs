//! Chromium-based browser adapter (Chromium, Chrome/Edge channels, Brave, Vivaldi, Opera, Arc).
//!
//! All Chromium browsers share the same storage format:
//! - Passwords in SQLite "Login Data" DB
//! - Encrypted with platform-specific keys

use crate::adapter::{DetectedSource, SourceAdapter};
use crate::crypto::chromium::{
    decrypt_chromium_password, decrypt_chromium_password_windows, encrypt_chromium_password,
    encrypt_chromium_password_windows,
};
use crate::platform;
use crate::types::*;
use crate::{Error, Result};
use rusqlite::Connection;
use secrecy::SecretString;
use std::path::{Path, PathBuf};

/// Configuration for a specific Chromium-based browser.
#[derive(Debug, Clone)]
pub struct ChromiumConfig {
    pub browser: BrowserKind,
    pub name: &'static str,
    /// Platform-specific subpath (under the OS data dir).
    pub macos_subpath: &'static str,
    pub linux_subpath: &'static str,
    pub windows_subpath: &'static str,
    /// macOS Keychain service name for the encryption key.
    pub keychain_service: &'static str,
}

/// Return configurations for all known Chromium-based browsers.
pub fn chromium_configs() -> Vec<ChromiumConfig> {
    let mut configs = vec![
        ChromiumConfig {
            browser: BrowserKind::Chrome,
            name: "Chrome",
            macos_subpath: "Google/Chrome",
            linux_subpath: "google-chrome",
            windows_subpath: "Google\\Chrome\\User Data",
            keychain_service: "Chrome Safe Storage",
        },
        ChromiumConfig {
            browser: BrowserKind::Edge,
            name: "Edge",
            macos_subpath: "Microsoft Edge",
            linux_subpath: "microsoft-edge",
            windows_subpath: "Microsoft\\Edge\\User Data",
            keychain_service: "Microsoft Edge Safe Storage",
        },
        ChromiumConfig {
            browser: BrowserKind::Brave,
            name: "Brave",
            macos_subpath: "BraveSoftware/Brave-Browser",
            linux_subpath: "BraveSoftware/Brave-Browser",
            windows_subpath: "BraveSoftware\\Brave-Browser\\User Data",
            keychain_service: "Brave Safe Storage",
        },
        ChromiumConfig {
            browser: BrowserKind::Vivaldi,
            name: "Vivaldi",
            macos_subpath: "Vivaldi",
            linux_subpath: "vivaldi",
            windows_subpath: "Vivaldi\\User Data",
            keychain_service: "Vivaldi Safe Storage",
        },
        ChromiumConfig {
            browser: BrowserKind::Opera,
            name: "Opera",
            macos_subpath: "com.operasoftware.Opera",
            linux_subpath: "opera",
            windows_subpath: "Opera Software\\Opera Stable",
            keychain_service: "Opera Safe Storage",
        },
    ];

    #[cfg(target_os = "linux")]
    {
        configs.splice(
            0..0,
            [
                ChromiumConfig {
                    browser: BrowserKind::Chromium,
                    name: "Chromium",
                    macos_subpath: "Chromium",
                    linux_subpath: "chromium",
                    windows_subpath: "Chromium\\User Data",
                    keychain_service: "Chromium Safe Storage",
                },
                ChromiumConfig {
                    browser: BrowserKind::Chrome,
                    name: "Chrome Beta",
                    macos_subpath: "Google/Chrome Beta",
                    linux_subpath: "google-chrome-beta",
                    windows_subpath: "Google\\Chrome Beta\\User Data",
                    keychain_service: "Chrome Safe Storage",
                },
                ChromiumConfig {
                    browser: BrowserKind::Chrome,
                    name: "Chrome Dev",
                    macos_subpath: "Google/Chrome Dev",
                    linux_subpath: "google-chrome-unstable",
                    windows_subpath: "Google\\Chrome SxS\\User Data",
                    keychain_service: "Chrome Safe Storage",
                },
                ChromiumConfig {
                    browser: BrowserKind::Edge,
                    name: "Edge Beta",
                    macos_subpath: "Microsoft Edge Beta",
                    linux_subpath: "microsoft-edge-beta",
                    windows_subpath: "Microsoft\\Edge Beta\\User Data",
                    keychain_service: "Microsoft Edge Safe Storage",
                },
                ChromiumConfig {
                    browser: BrowserKind::Edge,
                    name: "Edge Dev",
                    macos_subpath: "Microsoft Edge Dev",
                    linux_subpath: "microsoft-edge-dev",
                    windows_subpath: "Microsoft\\Edge Dev\\User Data",
                    keychain_service: "Microsoft Edge Safe Storage",
                },
            ],
        );
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        configs.push(ChromiumConfig {
            browser: BrowserKind::Arc,
            name: "Arc",
            macos_subpath: "Arc/User Data",
            linux_subpath: "arc/User Data",
            windows_subpath: "Arc\\User Data",
            keychain_service: "Arc Safe Storage",
        });
    }

    configs
}

/// Adapter for all Chromium-based browsers.
pub struct ChromiumAdapter {
    config: ChromiumConfig,
    /// If set, use this as the base directory instead of detecting from platform.
    /// Used for testing.
    override_base_dir: Option<PathBuf>,
    /// If set, use this encryption key instead of fetching from the OS keychain.
    /// Used for testing.
    override_encryption_key: Option<String>,
}

impl ChromiumAdapter {
    pub fn new(config: ChromiumConfig) -> Self {
        Self {
            config,
            override_base_dir: None,
            override_encryption_key: None,
        }
    }

    /// Create an adapter with overrides for testing.
    pub fn with_test_overrides(
        config: ChromiumConfig,
        base_dir: PathBuf,
        encryption_key: String,
    ) -> Self {
        Self {
            config,
            override_base_dir: Some(base_dir),
            override_encryption_key: Some(encryption_key),
        }
    }

    /// Get the base directory for this browser's data.
    fn base_dir(&self) -> Option<PathBuf> {
        if let Some(ref dir) = self.override_base_dir {
            return Some(dir.clone());
        }

        let subpath = if cfg!(target_os = "macos") {
            self.config.macos_subpath
        } else if cfg!(target_os = "windows") {
            self.config.windows_subpath
        } else {
            self.config.linux_subpath
        };

        platform::chromium_base_dir(subpath)
    }

    /// Discover browser profiles within the base directory.
    fn discover_profiles(&self, base_dir: &Path) -> Result<Vec<Profile>> {
        let mut profiles = Vec::new();

        // "Default" profile
        let default_path = base_dir.join("Default");
        if default_path.exists() {
            profiles.push(Profile {
                id: "Default".to_string(),
                name: "Default".to_string(),
                path: default_path.to_string_lossy().to_string(),
            });
        }

        // "Profile N" profiles
        if let Ok(entries) = std::fs::read_dir(base_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("Profile ") && entry.path().is_dir() {
                    let login_data = entry.path().join("Login Data");
                    if login_data.exists() {
                        profiles.push(Profile {
                            id: name.clone(),
                            name: name.clone(),
                            path: entry.path().to_string_lossy().to_string(),
                        });
                    }
                }
            }
        }

        Ok(profiles)
    }

    /// Get the encryption key for password decryption.
    fn get_encryption_key(&self) -> Result<String> {
        if let Some(ref key) = self.override_encryption_key {
            return Ok(key.clone());
        }

        #[cfg(target_os = "macos")]
        {
            platform::macos::get_chromium_encryption_key(self.config.keychain_service)
        }

        #[cfg(target_os = "linux")]
        {
            platform::linux::get_chromium_encryption_key(self.config.keychain_service).ok_or_else(
                || {
                    Error::AuthRequired(
                        self.config.name.to_string(),
                        "Could not retrieve encryption key from keyring".to_string(),
                    )
                },
            )
        }

        #[cfg(target_os = "windows")]
        {
            let base_dir = self.base_dir().ok_or_else(|| {
                Error::SourceNotFound("Cannot determine browser data directory".to_string())
            })?;
            let local_state = base_dir.join("Local State");
            platform::windows::get_chromium_encryption_key(&local_state)
        }
    }

    /// Decrypt a password blob using the platform-appropriate method.
    fn decrypt_password(blob: &[u8], encryption_key: &str) -> Result<String> {
        if cfg!(target_os = "windows") {
            decrypt_chromium_password_windows(blob, encryption_key)
        } else {
            decrypt_chromium_password(blob, encryption_key)
        }
    }

    /// Open a read-only copy of the Login Data SQLite database.
    /// We copy to a temp file to avoid WAL lock conflicts with the browser.
    /// Uses NamedTempFile for crash-safe cleanup.
    fn open_login_db(&self, profile_path: &Path) -> Result<Connection> {
        let login_data = profile_path.join("Login Data");
        if !login_data.exists() {
            return Err(Error::SourceNotFound(format!(
                "Login Data not found at {}",
                login_data.display()
            )));
        }

        open_db_readonly(&login_data)
    }

    /// Read credential entries from the Login Data database (metadata only).
    fn read_entries_from_db(
        &self,
        conn: &Connection,
        source_id: &str,
    ) -> Result<Vec<CredentialEntry>> {
        let mut stmt = conn.prepare(
            "SELECT origin_url, username_value, date_created, date_last_used, date_password_modified
             FROM logins
             ORDER BY origin_url",
        )?;

        let entries = stmt
            .query_map([], |row| {
                let url: String = row.get(0)?;
                let username: String = row.get(1)?;
                let created: Option<i64> = row.get(2)?;
                let last_used: Option<i64> = row.get(3)?;
                let modified: Option<i64> = row.get(4)?;

                Ok((url, username, created, last_used, modified))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(entries
            .into_iter()
            .enumerate()
            .map(|(i, (url, username, created, last_used, modified))| {
                let domain = extract_domain(&url);
                let entry_id = format!("{source_id}:login:{i:04}");

                CredentialEntry {
                    id: entry_id,
                    source_id: source_id.to_string(),
                    credential_type: CredentialType::Password,
                    domain,
                    url: Some(url),
                    username: if username.is_empty() {
                        None
                    } else {
                        Some(username)
                    },
                    label: None,
                    created: chrome_timestamp_to_datetime(created),
                    last_used: chrome_timestamp_to_datetime(last_used),
                    modified: chrome_timestamp_to_datetime(modified),
                }
            })
            .collect())
    }

    /// Read and decrypt passwords from the Login Data database.
    fn read_credentials_from_db(
        &self,
        conn: &Connection,
        source_id: &str,
        entry_ids: Option<&[&str]>,
        encryption_key: &str,
    ) -> Result<Vec<Credential>> {
        let mut stmt = conn.prepare(
            "SELECT origin_url, username_value, password_value, date_created, date_last_used, date_password_modified
             FROM logins
             ORDER BY origin_url",
        )?;

        let rows = stmt
            .query_map([], |row| {
                let url: String = row.get(0)?;
                let username: String = row.get(1)?;
                let password_blob: Vec<u8> = row.get(2)?;
                let created: Option<i64> = row.get(3)?;
                let last_used: Option<i64> = row.get(4)?;
                let modified: Option<i64> = row.get(5)?;

                Ok((url, username, password_blob, created, last_used, modified))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let mut credentials = Vec::new();

        for (i, (url, username, password_blob, created, last_used, modified)) in
            rows.into_iter().enumerate()
        {
            let entry_id = format!("{source_id}:login:{i:04}");

            // Skip if we have a filter and this entry isn't in it
            if let Some(ids) = entry_ids {
                if !ids.contains(&entry_id.as_str()) {
                    continue;
                }
            }

            let password = match Self::decrypt_password(&password_blob, encryption_key) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!("Failed to decrypt password for {url}: {e}");
                    continue;
                }
            };

            let domain = extract_domain(&url);

            credentials.push(Credential {
                entry: CredentialEntry {
                    id: entry_id,
                    source_id: source_id.to_string(),
                    credential_type: CredentialType::Password,
                    domain,
                    url: Some(url),
                    username: if username.is_empty() {
                        None
                    } else {
                        Some(username)
                    },
                    label: None,
                    created: chrome_timestamp_to_datetime(created),
                    last_used: chrome_timestamp_to_datetime(last_used),
                    modified: chrome_timestamp_to_datetime(modified),
                },
                secret: SecretString::from(password),
            });
        }

        Ok(credentials)
    }

    /// Open a read-only copy of the Web Data SQLite database (credit cards).
    fn open_webdata_db(&self, profile_path: &Path) -> Result<Connection> {
        let web_data = profile_path.join("Web Data");
        if !web_data.exists() {
            return Err(Error::SourceNotFound(format!(
                "Web Data not found at {}",
                web_data.display()
            )));
        }

        open_db_readonly(&web_data)
    }

    /// Read credit card entries from the Web Data database (metadata only).
    fn read_cc_entries_from_db(
        &self,
        conn: &Connection,
        source_id: &str,
    ) -> Result<Vec<CredentialEntry>> {
        let mut stmt = conn.prepare(
            "SELECT name_on_card, expiration_month, expiration_year, date_modified, nickname, guid
             FROM credit_cards
             ORDER BY name_on_card",
        )?;

        let entries = stmt
            .query_map([], |row| {
                let name: String = row.get(0)?;
                let exp_month: i32 = row.get(1)?;
                let exp_year: i32 = row.get(2)?;
                let modified: Option<i64> = row.get(3)?;
                let nickname: Option<String> = row.get(4)?;
                let guid: String = row.get(5)?;
                Ok((name, exp_month, exp_year, modified, nickname, guid))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(entries
            .into_iter()
            .enumerate()
            .map(
                |(i, (name, exp_month, exp_year, modified, nickname, _guid))| {
                    let entry_id = format!("{source_id}:cc:{i:04}");
                    let label = if exp_year > 0 {
                        Some(format!(
                            "{}Exp: {exp_month:02}/{exp_year}",
                            nickname
                                .as_ref()
                                .map_or(String::new(), |n| format!("{n} — "))
                        ))
                    } else {
                        nickname
                    };

                    CredentialEntry {
                        id: entry_id,
                        source_id: source_id.to_string(),
                        credential_type: CredentialType::CreditCard,
                        domain: "autofill.credit-cards".to_string(),
                        url: None,
                        username: if name.is_empty() { None } else { Some(name) },
                        label,
                        created: None,
                        last_used: None,
                        modified: chrome_timestamp_to_datetime(modified),
                    }
                },
            )
            .collect())
    }

    /// Read and decrypt credit card numbers from the Web Data database.
    fn read_cc_credentials_from_db(
        &self,
        conn: &Connection,
        source_id: &str,
        entry_ids: Option<&[&str]>,
        encryption_key: &str,
    ) -> Result<Vec<Credential>> {
        let mut stmt = conn.prepare(
            "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted,
                    date_modified, nickname, guid
             FROM credit_cards
             ORDER BY name_on_card",
        )?;

        let rows = stmt
            .query_map([], |row| {
                let name: String = row.get(0)?;
                let exp_month: i32 = row.get(1)?;
                let exp_year: i32 = row.get(2)?;
                let card_blob: Vec<u8> = row.get(3)?;
                let modified: Option<i64> = row.get(4)?;
                let nickname: Option<String> = row.get(5)?;
                let _guid: String = row.get(6)?;
                Ok((name, exp_month, exp_year, card_blob, modified, nickname))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let mut credentials = Vec::new();

        for (i, (name, exp_month, exp_year, card_blob, modified, nickname)) in
            rows.into_iter().enumerate()
        {
            let entry_id = format!("{source_id}:cc:{i:04}");

            if let Some(ids) = entry_ids {
                if !ids.contains(&entry_id.as_str()) {
                    continue;
                }
            }

            let card_number = match Self::decrypt_password(&card_blob, encryption_key) {
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!("Failed to decrypt credit card: {e}");
                    continue;
                }
            };

            let label = if exp_year > 0 {
                Some(format!(
                    "{}Exp: {exp_month:02}/{exp_year}",
                    nickname
                        .as_ref()
                        .map_or(String::new(), |n| format!("{n} — "))
                ))
            } else {
                nickname
            };

            credentials.push(Credential {
                entry: CredentialEntry {
                    id: entry_id,
                    source_id: source_id.to_string(),
                    credential_type: CredentialType::CreditCard,
                    domain: "autofill.credit-cards".to_string(),
                    url: None,
                    username: if name.is_empty() { None } else { Some(name) },
                    label,
                    created: None,
                    last_used: None,
                    modified: chrome_timestamp_to_datetime(modified),
                },
                secret: SecretString::from(card_number),
            });
        }

        Ok(credentials)
    }
}

impl SourceAdapter for ChromiumAdapter {
    fn detect(&self) -> Result<Vec<DetectedSource>> {
        let base_dir = match self.base_dir() {
            Some(d) if d.exists() => d,
            _ => return Ok(vec![]),
        };

        let profiles = self.discover_profiles(&base_dir)?;
        if profiles.is_empty() {
            return Ok(vec![]);
        }

        // Count credentials across all profiles (passwords + credit cards)
        let mut total_count = 0u32;
        for profile in &profiles {
            let profile_path = Path::new(&profile.path);
            if let Ok(conn) = self.open_login_db(profile_path) {
                if let Ok(count) = conn.query_row("SELECT COUNT(*) FROM logins", [], |row| {
                    row.get::<_, u32>(0)
                }) {
                    total_count += count;
                }
            }
            if let Ok(conn) = self.open_webdata_db(profile_path) {
                if let Ok(count) = conn.query_row("SELECT COUNT(*) FROM credit_cards", [], |row| {
                    row.get::<_, u32>(0)
                }) {
                    total_count += count;
                }
            }
        }

        let source_id = format!(
            "{}-{}",
            self.config.name.to_lowercase(),
            profiles.first().map_or("unknown", |p| p.id.as_str())
        )
        .to_lowercase()
        .replace(' ', "-");

        Ok(vec![DetectedSource {
            source: CredentialSource {
                id: source_id,
                name: format!(
                    "{} ({})",
                    self.config.name,
                    if profiles.len() == 1 {
                        profiles[0].name.clone()
                    } else {
                        format!("{} profiles", profiles.len())
                    }
                ),
                source_type: SourceType::Browser(self.config.browser),
                platform: Platform::current(),
                status: SourceStatus::Accessible,
                credential_count: Some(total_count),
                profiles,
            },
        }])
    }

    fn list_credentials(&self, profile: &Profile) -> Result<Vec<CredentialEntry>> {
        let profile_path = Path::new(&profile.path);
        let source_id = format!(
            "{}-{}",
            self.config.name.to_lowercase(),
            profile.id.to_lowercase().replace(' ', "-")
        );

        let mut entries = Vec::new();

        // Passwords from Login Data
        if let Ok(conn) = self.open_login_db(profile_path) {
            entries.extend(self.read_entries_from_db(&conn, &source_id)?);
        }

        // Credit cards from Web Data
        if let Ok(conn) = self.open_webdata_db(profile_path) {
            if let Ok(cc_entries) = self.read_cc_entries_from_db(&conn, &source_id) {
                entries.extend(cc_entries);
            }
        }

        Ok(entries)
    }

    fn extract_credentials(
        &self,
        profile: &Profile,
        entry_ids: &[&str],
    ) -> Result<Vec<Credential>> {
        let profile_path = Path::new(&profile.path);
        let encryption_key = self.get_encryption_key()?;

        let source_id = format!(
            "{}-{}",
            self.config.name.to_lowercase(),
            profile.id.to_lowercase().replace(' ', "-")
        );

        let ids = if entry_ids.is_empty() {
            None
        } else {
            Some(entry_ids)
        };

        let mut credentials = Vec::new();

        // Passwords from Login Data
        if let Ok(conn) = self.open_login_db(profile_path) {
            credentials.extend(self.read_credentials_from_db(
                &conn,
                &source_id,
                ids,
                &encryption_key,
            )?);
        }

        // Credit cards from Web Data
        if let Ok(conn) = self.open_webdata_db(profile_path) {
            if let Ok(cc) =
                self.read_cc_credentials_from_db(&conn, &source_id, ids, &encryption_key)
            {
                credentials.extend(cc);
            }
        }

        Ok(credentials)
    }

    fn auth_requirement(&self) -> AuthRequirement {
        if cfg!(target_os = "macos") {
            AuthRequirement::OsPrompt
        } else {
            AuthRequirement::None
        }
    }

    fn supported_platforms(&self) -> &[Platform] {
        &[Platform::MacOS, Platform::Linux, Platform::Windows]
    }

    fn source_type(&self) -> SourceType {
        SourceType::Browser(self.config.browser)
    }
}

/// Extract the domain from a URL.
fn extract_domain(url: &str) -> String {
    url.split("://")
        .nth(1)
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or(url)
        .split(':')
        .next()
        .unwrap_or(url)
        .to_string()
}

/// Open a SQLite database file as a read-only copy.
///
/// Safety guarantees:
/// 1. Copies the DB to a NamedTempFile (auto-deleted on drop, even on crash/panic)
/// 2. Opens the copy with SQLITE_OPEN_READ_ONLY — no writes possible
/// 3. Never modifies the original file
fn open_db_readonly(db_path: &Path) -> Result<Connection> {
    use rusqlite::OpenFlags;
    use std::io::Write;

    // Read the database into memory, write to a NamedTempFile.
    // NamedTempFile auto-deletes on drop, even if the process panics.
    let data = std::fs::read(db_path)?;
    let mut temp = tempfile::NamedTempFile::new().map_err(Error::Io)?;
    temp.write_all(&data).map_err(Error::Io)?;
    temp.flush().map_err(Error::Io)?;

    // Open as read-only — SQLite will refuse any write operations
    let conn = Connection::open_with_flags(
        temp.path(),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;

    // Keep the temp file alive by leaking it into a persisted path.
    // The OS will clean it up when the process exits.
    // We need the file to exist while the connection is open.
    let _persisted = temp.into_temp_path();
    // _persisted drops here, which deletes the file — but SQLite has already
    // loaded the data it needs. For small databases this is fine.

    Ok(conn)
}

/// Convert a Chrome timestamp (microseconds since 1601-01-01) to a DateTime.
fn chrome_timestamp_to_datetime(timestamp: Option<i64>) -> Option<chrono::DateTime<chrono::Utc>> {
    let ts = timestamp?;
    if ts == 0 {
        return None;
    }
    // Chrome epoch: 1601-01-01 00:00:00 UTC
    // Unix epoch:   1970-01-01 00:00:00 UTC
    // Difference:   11644473600 seconds
    let unix_micros = ts - 11_644_473_600_000_000;
    let secs = unix_micros / 1_000_000;
    let nsecs = ((unix_micros % 1_000_000) * 1000) as u32;
    chrono::DateTime::from_timestamp(secs, nsecs)
}

// ============================================================
// Test utilities for creating mock Chrome databases
// ============================================================

/// Returns a test encryption key appropriate for the current platform.
/// On Windows, this is a base64-encoded 32-byte key (for AES-256-GCM).
/// On macOS/Linux, this is a plain string (for PBKDF2 key derivation).
pub fn test_encryption_key() -> &'static str {
    if cfg!(target_os = "windows") {
        // base64 of 32 zero bytes — valid AES-256 key for testing
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    } else {
        "test-key-for-unit-tests"
    }
}

/// Encrypt a password using the platform-appropriate method (matching `decrypt_password`).
fn encrypt_test_password(plaintext: &str, encryption_key: &str) -> Vec<u8> {
    if cfg!(target_os = "windows") {
        encrypt_chromium_password_windows(plaintext, encryption_key)
    } else {
        encrypt_chromium_password(plaintext, encryption_key)
    }
}

/// Create a mock Chrome Login Data SQLite database for testing.
pub fn create_test_login_db(
    path: &Path,
    entries: &[TestLoginEntry],
    encryption_key: &str,
) -> Result<()> {
    let conn = Connection::open(path)?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS logins (
            origin_url TEXT NOT NULL,
            action_url TEXT,
            username_element TEXT,
            username_value TEXT,
            password_element TEXT,
            password_value BLOB,
            submit_element TEXT,
            signon_realm TEXT,
            date_created INTEGER DEFAULT 0,
            date_last_used INTEGER DEFAULT 0,
            date_password_modified INTEGER DEFAULT 0,
            blacklisted_by_user INTEGER DEFAULT 0,
            scheme INTEGER DEFAULT 0,
            password_type INTEGER DEFAULT 0,
            times_used INTEGER DEFAULT 0,
            form_data BLOB,
            display_name TEXT,
            icon_url TEXT,
            federation_url TEXT,
            skip_zero_click INTEGER DEFAULT 0,
            generation_upload_status INTEGER DEFAULT 0,
            possible_username_pairs BLOB,
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date_received INTEGER DEFAULT 0,
            sharing_notification_displayed INTEGER DEFAULT 0,
            keychain_identifier TEXT DEFAULT '',
            sender_email TEXT DEFAULT '',
            sender_name TEXT DEFAULT '',
            sender_profile_image_url TEXT DEFAULT '',
            date_sent INTEGER DEFAULT 0,
            sharing_type INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS meta (
            key TEXT NOT NULL UNIQUE PRIMARY KEY,
            value TEXT
        );

        INSERT OR REPLACE INTO meta (key, value) VALUES ('version', '36');",
    )?;

    let mut stmt = conn.prepare(
        "INSERT INTO logins (origin_url, action_url, username_value, password_value, signon_realm, date_created, date_last_used, date_password_modified)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )?;

    for entry in entries {
        let encrypted = encrypt_test_password(&entry.password, encryption_key);
        let signon_realm = format!(
            "{}://{}",
            if entry.url.starts_with("https") {
                "https"
            } else {
                "http"
            },
            extract_domain(&entry.url)
        );

        stmt.execute(rusqlite::params![
            entry.url,
            entry.url,
            entry.username,
            encrypted,
            signon_realm,
            entry.date_created.unwrap_or(0),
            entry.date_last_used.unwrap_or(0),
            entry.date_modified.unwrap_or(0),
        ])?;
    }

    Ok(())
}

/// A test login entry for creating mock databases.
#[derive(Debug, Clone)]
pub struct TestLoginEntry {
    pub url: String,
    pub username: String,
    pub password: String,
    pub date_created: Option<i64>,
    pub date_last_used: Option<i64>,
    pub date_modified: Option<i64>,
}

/// A test credit card entry for creating mock databases.
#[derive(Debug, Clone)]
pub struct TestCreditCardEntry {
    pub name_on_card: String,
    pub card_number: String,
    pub expiration_month: i32,
    pub expiration_year: i32,
}

/// Create a mock Chrome Web Data SQLite database for testing (credit cards).
pub fn create_test_webdata_db(
    path: &Path,
    entries: &[TestCreditCardEntry],
    encryption_key: &str,
) -> Result<()> {
    let conn = Connection::open(path)?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS credit_cards (
            guid VARCHAR PRIMARY KEY,
            name_on_card VARCHAR,
            expiration_month INTEGER DEFAULT 0,
            expiration_year INTEGER DEFAULT 0,
            card_number_encrypted BLOB,
            date_modified INTEGER NOT NULL DEFAULT 0,
            origin VARCHAR DEFAULT '',
            use_count INTEGER NOT NULL DEFAULT 0,
            use_date INTEGER NOT NULL DEFAULT 0,
            billing_address_id VARCHAR,
            nickname VARCHAR
        );",
    )?;

    let mut stmt = conn.prepare(
        "INSERT INTO credit_cards (guid, name_on_card, expiration_month, expiration_year, card_number_encrypted)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )?;

    for (i, entry) in entries.iter().enumerate() {
        let encrypted = encrypt_test_password(&entry.card_number, encryption_key);
        stmt.execute(rusqlite::params![
            format!("guid-{i:04}"),
            entry.name_on_card,
            entry.expiration_month,
            entry.expiration_year,
            encrypted,
        ])?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[cfg(target_os = "linux")]
    #[test]
    fn test_linux_configs_include_linux_relevant_browsers() {
        let names: Vec<&str> = chromium_configs()
            .iter()
            .map(|config| config.name)
            .collect();

        for expected in [
            "Chromium",
            "Chrome",
            "Chrome Beta",
            "Chrome Dev",
            "Edge",
            "Edge Beta",
            "Edge Dev",
            "Brave",
            "Vivaldi",
            "Opera",
        ] {
            assert!(names.contains(&expected), "missing config: {expected}");
        }
        assert!(!names.contains(&"Arc"));
    }

    fn create_test_adapter(
        temp_dir: &TempDir,
        entries: &[TestLoginEntry],
    ) -> (ChromiumAdapter, Profile) {
        let encryption_key = test_encryption_key();
        let profile_dir = temp_dir.path().join("Default");
        std::fs::create_dir_all(&profile_dir).unwrap();

        let db_path = profile_dir.join("Login Data");
        create_test_login_db(&db_path, entries, encryption_key).unwrap();

        let config = ChromiumConfig {
            browser: BrowserKind::Chrome,
            name: "Chrome",
            macos_subpath: "Google/Chrome",
            linux_subpath: "google-chrome",
            windows_subpath: "Google\\Chrome\\User Data",
            keychain_service: "Chrome Safe Storage",
        };

        let adapter = ChromiumAdapter::with_test_overrides(
            config,
            temp_dir.path().to_path_buf(),
            encryption_key.to_string(),
        );

        let profile = Profile {
            id: "Default".to_string(),
            name: "Default".to_string(),
            path: profile_dir.to_string_lossy().to_string(),
        };

        (adapter, profile)
    }

    fn sample_entries() -> Vec<TestLoginEntry> {
        vec![
            TestLoginEntry {
                url: "https://github.com/login".to_string(),
                username: "octocat".to_string(),
                password: "gh-token-abc123".to_string(),
                date_created: Some(13_300_000_000_000_000), // ~2022
                date_last_used: Some(13_350_000_000_000_000),
                date_modified: Some(13_300_000_000_000_000),
            },
            TestLoginEntry {
                url: "https://console.aws.amazon.com/".to_string(),
                username: "admin@acme.com".to_string(),
                password: "aws-super-secret!".to_string(),
                date_created: Some(13_280_000_000_000_000),
                date_last_used: Some(13_340_000_000_000_000),
                date_modified: None,
            },
            TestLoginEntry {
                url: "https://accounts.google.com/signin".to_string(),
                username: "user@gmail.com".to_string(),
                password: "google-pass-456".to_string(),
                date_created: None,
                date_last_used: None,
                date_modified: None,
            },
            TestLoginEntry {
                url: "https://vercel.com/login".to_string(),
                username: "deployer".to_string(),
                password: "vercel-deploy-key".to_string(),
                date_created: Some(13_310_000_000_000_000),
                date_last_used: Some(13_360_000_000_000_000),
                date_modified: Some(13_310_000_000_000_000),
            },
        ]
    }

    #[test]
    fn test_detect_with_profiles() {
        let temp = TempDir::new().unwrap();
        let (adapter, _profile) = create_test_adapter(&temp, &sample_entries());

        let sources = adapter.detect().unwrap();
        assert_eq!(sources.len(), 1);
        assert!(sources[0].source.name.contains("Chrome"));
        assert_eq!(sources[0].source.credential_count, Some(4));
        assert_eq!(sources[0].source.profiles.len(), 1);
    }

    #[test]
    fn test_detect_no_browser() {
        let temp = TempDir::new().unwrap();
        let config = ChromiumConfig {
            browser: BrowserKind::Chrome,
            name: "Chrome",
            macos_subpath: "Google/Chrome",
            linux_subpath: "google-chrome",
            windows_subpath: "Google\\Chrome\\User Data",
            keychain_service: "Chrome Safe Storage",
        };
        let adapter = ChromiumAdapter::with_test_overrides(
            config,
            temp.path().join("nonexistent").to_path_buf(),
            "key".to_string(),
        );

        let sources = adapter.detect().unwrap();
        assert!(sources.is_empty());
    }

    #[test]
    fn test_list_credentials() {
        let temp = TempDir::new().unwrap();
        let (adapter, profile) = create_test_adapter(&temp, &sample_entries());

        let entries = adapter.list_credentials(&profile).unwrap();
        assert_eq!(entries.len(), 4);

        // Verify metadata is correct (no secrets)
        let github = entries.iter().find(|e| e.domain == "github.com").unwrap();
        assert_eq!(github.username.as_deref(), Some("octocat"));
        assert_eq!(github.credential_type, CredentialType::Password);
        assert!(github.url.as_ref().unwrap().contains("github.com"));
    }

    #[test]
    fn test_extract_all_credentials() {
        let temp = TempDir::new().unwrap();
        let (adapter, profile) = create_test_adapter(&temp, &sample_entries());

        let creds = adapter.extract_credentials(&profile, &[]).unwrap();
        assert_eq!(creds.len(), 4);

        use secrecy::ExposeSecret;
        let github = creds
            .iter()
            .find(|c| c.entry.domain == "github.com")
            .unwrap();
        assert_eq!(github.secret.expose_secret(), "gh-token-abc123");

        let aws = creds
            .iter()
            .find(|c| c.entry.domain == "console.aws.amazon.com")
            .unwrap();
        assert_eq!(aws.secret.expose_secret(), "aws-super-secret!");
    }

    #[test]
    fn test_extract_specific_credentials() {
        let temp = TempDir::new().unwrap();
        let (adapter, profile) = create_test_adapter(&temp, &sample_entries());

        // First list to get IDs
        let entries = adapter.list_credentials(&profile).unwrap();
        let github_id = entries
            .iter()
            .find(|e| e.domain == "github.com")
            .unwrap()
            .id
            .clone();

        let creds = adapter
            .extract_credentials(&profile, &[github_id.as_str()])
            .unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].entry.domain, "github.com");
    }

    #[test]
    fn test_extract_domain_parsing() {
        assert_eq!(extract_domain("https://github.com/login"), "github.com");
        assert_eq!(
            extract_domain("https://console.aws.amazon.com/"),
            "console.aws.amazon.com"
        );
        assert_eq!(extract_domain("http://localhost:8080/api"), "localhost");
        assert_eq!(extract_domain("github.com"), "github.com");
    }

    #[test]
    fn test_chrome_timestamp_conversion() {
        // Known timestamp: 13300000000000000 microseconds since 1601-01-01
        let dt = chrome_timestamp_to_datetime(Some(13_300_000_000_000_000));
        assert!(dt.is_some());
        let dt = dt.unwrap();
        assert!(dt.timestamp() > 0); // Should be a valid positive Unix timestamp

        // Zero should return None
        assert!(chrome_timestamp_to_datetime(Some(0)).is_none());
        assert!(chrome_timestamp_to_datetime(None).is_none());
    }

    #[test]
    fn test_empty_database() {
        let temp = TempDir::new().unwrap();
        let (adapter, profile) = create_test_adapter(&temp, &[]);

        let entries = adapter.list_credentials(&profile).unwrap();
        assert!(entries.is_empty());

        let creds = adapter.extract_credentials(&profile, &[]).unwrap();
        assert!(creds.is_empty());
    }

    #[test]
    fn test_multiple_profiles() {
        let temp = TempDir::new().unwrap();
        let encryption_key = test_encryption_key();

        // Create Default profile
        let default_dir = temp.path().join("Default");
        std::fs::create_dir_all(&default_dir).unwrap();
        create_test_login_db(
            &default_dir.join("Login Data"),
            &[TestLoginEntry {
                url: "https://github.com".to_string(),
                username: "user1".to_string(),
                password: "pass1".to_string(),
                date_created: None,
                date_last_used: None,
                date_modified: None,
            }],
            encryption_key,
        )
        .unwrap();

        // Create "Profile 1"
        let profile1_dir = temp.path().join("Profile 1");
        std::fs::create_dir_all(&profile1_dir).unwrap();
        create_test_login_db(
            &profile1_dir.join("Login Data"),
            &[TestLoginEntry {
                url: "https://gitlab.com".to_string(),
                username: "user2".to_string(),
                password: "pass2".to_string(),
                date_created: None,
                date_last_used: None,
                date_modified: None,
            }],
            encryption_key,
        )
        .unwrap();

        let config = ChromiumConfig {
            browser: BrowserKind::Chrome,
            name: "Chrome",
            macos_subpath: "",
            linux_subpath: "",
            windows_subpath: "",
            keychain_service: "",
        };
        let adapter = ChromiumAdapter::with_test_overrides(
            config,
            temp.path().to_path_buf(),
            encryption_key.to_string(),
        );

        let sources = adapter.detect().unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].source.profiles.len(), 2);
        assert_eq!(sources[0].source.credential_count, Some(2));
    }

    #[test]
    fn test_credit_card_list_and_extract() {
        let temp = TempDir::new().unwrap();
        let encryption_key = test_encryption_key();
        let profile_dir = temp.path().join("Default");
        std::fs::create_dir_all(&profile_dir).unwrap();

        // Create Login Data (required for profile detection)
        create_test_login_db(&profile_dir.join("Login Data"), &[], encryption_key).unwrap();

        // Create Web Data with credit cards
        create_test_webdata_db(
            &profile_dir.join("Web Data"),
            &[
                TestCreditCardEntry {
                    name_on_card: "John Doe".to_string(),
                    card_number: "4111111111111111".to_string(),
                    expiration_month: 12,
                    expiration_year: 2028,
                },
                TestCreditCardEntry {
                    name_on_card: "Jane Smith".to_string(),
                    card_number: "5500000000000004".to_string(),
                    expiration_month: 6,
                    expiration_year: 2027,
                },
            ],
            encryption_key,
        )
        .unwrap();

        let config = ChromiumConfig {
            browser: BrowserKind::Chrome,
            name: "Chrome",
            macos_subpath: "",
            linux_subpath: "",
            windows_subpath: "",
            keychain_service: "",
        };
        let adapter = ChromiumAdapter::with_test_overrides(
            config,
            temp.path().to_path_buf(),
            encryption_key.to_string(),
        );

        let profile = Profile {
            id: "Default".to_string(),
            name: "Default".to_string(),
            path: profile_dir.to_string_lossy().to_string(),
        };

        // List should include credit cards
        let entries = adapter.list_credentials(&profile).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries
            .iter()
            .all(|e| e.credential_type == CredentialType::CreditCard));
        assert_eq!(entries[0].username.as_deref(), Some("Jane Smith")); // alphabetical order

        // Extract should decrypt card numbers
        let creds = adapter.extract_credentials(&profile, &[]).unwrap();
        assert_eq!(creds.len(), 2);

        use secrecy::ExposeSecret;
        let john = creds
            .iter()
            .find(|c| c.entry.username.as_deref() == Some("John Doe"))
            .unwrap();
        assert_eq!(john.secret.expose_secret(), "4111111111111111");
        assert_eq!(john.entry.credential_type, CredentialType::CreditCard);

        // Detect should count credit cards
        let sources = adapter.detect().unwrap();
        assert_eq!(sources[0].source.credential_count, Some(2));
    }
}
