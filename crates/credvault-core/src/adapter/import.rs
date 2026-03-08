use std::{collections::HashMap, fs, path::Path, sync::Arc};

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

#[derive(Debug, Clone)]
struct ImportedCredentialRecord {
    id: String,
    credential_type: CredentialType,
    domain: String,
    url: Option<String>,
    username: Option<String>,
    label: Option<String>,
    tags: Vec<String>,
    secret: String,
}

#[derive(Debug)]
struct ImportedFileAdapter {
    source: CredentialSource,
    entries: Vec<ImportedCredentialRecord>,
    index_by_id: HashMap<String, usize>,
}

impl ImportedFileAdapter {
    fn new(source: CredentialSource, entries: Vec<ImportedCredentialRecord>) -> Self {
        let index_by_id = entries
            .iter()
            .enumerate()
            .map(|(index, entry)| (entry.id.clone(), index))
            .collect();

        Self {
            source,
            entries,
            index_by_id,
        }
    }

    fn to_entry(&self, record: &ImportedCredentialRecord) -> CredentialEntry {
        CredentialEntry {
            id: record.id.clone(),
            source_id: self.source.id.clone(),
            credential_type: record.credential_type.clone(),
            domain: record.domain.clone(),
            url: record.url.clone(),
            username: record.username.clone(),
            label: record.label.clone(),
            created: None,
            last_used: None,
            modified: None,
            tags: record.tags.clone(),
            duplicate_group: None,
        }
    }
}

impl SourceAdapter for ImportedFileAdapter {
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
                let record = &self.entries[*index];

                Ok(Credential {
                    entry: self.to_entry(record),
                    secret: SecretString::new(record.secret.clone().into_boxed_str()),
                })
            })
            .collect()
    }
}

pub fn load_chrome_csv_export(path: impl AsRef<Path>) -> Result<DynSourceAdapter> {
    let path = path.as_ref();
    let mut reader = csv::Reader::from_path(path)?;
    let headers = reader.headers()?.clone();

    let name_index = header_index(&headers, &["name"]);
    let url_index = header_index(&headers, &["url"]);
    let username_index = header_index(&headers, &["username"]);
    let password_index = header_index(&headers, &["password"]);
    let note_index = header_index(&headers, &["note", "notes"]);

    let source_id = format!("chrome_csv:{}", sanitize_source_name(path));
    let source = CredentialSource {
        id: source_id.clone(),
        name: format!("Chrome CSV Export ({})", display_name(path)),
        source_type: SourceType::Browser(BrowserKind::Chrome),
        platform: Platform::Fixture,
        status: SourceStatus::Accessible,
        credential_count: None,
        profiles: vec![Profile {
            id: "csv-export".to_string(),
            name: "CSV Export".to_string(),
            path: Some(path.display().to_string()),
            is_default: true,
        }],
    };

    let mut entries = Vec::new();

    for (row_index, row) in reader.records().enumerate() {
        let row = row?;
        let url = row
            .get(url_index.ok_or_else(|| CredVaultError::ExportFileInvalid(path.to_path_buf()))?)
            .unwrap_or_default()
            .trim()
            .to_string();
        let password = row
            .get(
                password_index
                    .ok_or_else(|| CredVaultError::ExportFileInvalid(path.to_path_buf()))?,
            )
            .unwrap_or_default()
            .to_string();

        if url.is_empty() || password.is_empty() {
            continue;
        }

        let domain = extract_domain(&url).unwrap_or_else(|| url.clone());
        let username = username_index
            .and_then(|index| row.get(index))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let label = name_index
            .and_then(|index| row.get(index))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let mut tags = vec!["import".to_string(), "chrome-csv".to_string()];
        if let Some(note) = note_index
            .and_then(|index| row.get(index))
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            tags.push(format!("note:{note}"));
        }

        entries.push(ImportedCredentialRecord {
            id: format!("{source_id}:login:{:04}", row_index + 1),
            credential_type: CredentialType::Password,
            domain,
            url: Some(url),
            username,
            label,
            tags,
            secret: password,
        });
    }

    let mut source = source;
    source.credential_count = Some(entries.len() as u32);

    Ok(Arc::new(ImportedFileAdapter::new(source, entries)))
}

pub fn load_bitwarden_json_export(path: impl AsRef<Path>) -> Result<DynSourceAdapter> {
    let path = path.as_ref();
    let raw = fs::read_to_string(path)?;
    let export: BitwardenExport = serde_json::from_str(&raw)
        .map_err(|_| CredVaultError::ExportFileInvalid(path.to_path_buf()))?;

    let source_id = format!("bitwarden_json:{}", sanitize_source_name(path));
    let mut entries = Vec::new();

    for (index, item) in export.items.into_iter().enumerate() {
        let Some(login) = item.login else {
            continue;
        };
        let Some(secret) = login.password.filter(|value| !value.trim().is_empty()) else {
            continue;
        };

        let url = login
            .uris
            .as_ref()
            .and_then(|uris| uris.iter().find_map(|uri| uri.uri.clone()));
        let domain = url
            .as_deref()
            .and_then(extract_domain)
            .unwrap_or_else(|| item.name.to_lowercase().replace(' ', "-"));
        let username = login.username.filter(|value| !value.trim().is_empty());
        let mut tags = vec!["import".to_string(), "bitwarden-json".to_string()];
        if item.favorite.unwrap_or(false) {
            tags.push("favorite".to_string());
        }

        entries.push(ImportedCredentialRecord {
            id: format!("{source_id}:login:{:04}", index + 1),
            credential_type: CredentialType::Password,
            domain,
            url,
            username,
            label: Some(item.name),
            tags,
            secret,
        });
    }

    let source = CredentialSource {
        id: source_id,
        name: format!("Bitwarden JSON Export ({})", display_name(path)),
        source_type: SourceType::PasswordManager(crate::types::ManagerKind::Bitwarden),
        platform: Platform::Fixture,
        status: SourceStatus::Accessible,
        credential_count: Some(entries.len() as u32),
        profiles: vec![Profile {
            id: "json-export".to_string(),
            name: "JSON Export".to_string(),
            path: Some(path.display().to_string()),
            is_default: true,
        }],
    };

    Ok(Arc::new(ImportedFileAdapter::new(source, entries)))
}

fn header_index(headers: &csv::StringRecord, options: &[&str]) -> Option<usize> {
    headers.iter().position(|header| {
        let normalized = header.trim().to_ascii_lowercase();
        options.iter().any(|option| normalized == *option)
    })
}

fn sanitize_source_name(path: &Path) -> String {
    display_name(path)
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

fn display_name(path: &Path) -> String {
    path.file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("export")
        .to_string()
}

fn extract_domain(url: &str) -> Option<String> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return None;
    }

    let after_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed);
    let host_port = after_scheme.split('/').next().unwrap_or(after_scheme);
    let host = host_port.split('@').next_back().unwrap_or(host_port);
    let host = host.split(':').next().unwrap_or(host).trim_matches('.');

    if host.is_empty() {
        None
    } else {
        Some(host.to_lowercase())
    }
}

#[derive(Debug, Deserialize)]
struct BitwardenExport {
    #[serde(default)]
    items: Vec<BitwardenItem>,
}

#[derive(Debug, Deserialize)]
struct BitwardenItem {
    name: String,
    favorite: Option<bool>,
    login: Option<BitwardenLogin>,
}

#[derive(Debug, Deserialize)]
struct BitwardenLogin {
    username: Option<String>,
    password: Option<String>,
    uris: Option<Vec<BitwardenUri>>,
}

#[derive(Debug, Deserialize)]
struct BitwardenUri {
    uri: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::extract_domain;

    #[test]
    fn extracts_domain_from_common_url_shapes() {
        assert_eq!(
            extract_domain("https://github.com/login"),
            Some("github.com".to_string())
        );
        assert_eq!(
            extract_domain("https://user@example.com:443/secret"),
            Some("example.com".to_string())
        );
        assert_eq!(extract_domain(""), None);
    }
}
