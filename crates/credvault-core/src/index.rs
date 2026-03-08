//! Unified credential index — lists credentials across all sources with deduplication.

use crate::adapter::{self, SourceAdapter};
use crate::types::*;
use crate::{Error, Result};
use std::collections::HashMap;

/// List credentials from all (or specified) sources, with filtering and deduplication.
pub async fn list_credentials(
    source_ids: Option<&[&str]>,
    filter: Option<&CredentialFilter>,
) -> Result<CredentialIndex> {
    let adapters = adapter::get_adapters();
    list_with_adapters(&adapters, source_ids, filter)
}

/// List credentials using specific adapters (for testing).
pub fn list_with_adapters(
    adapters: &[Box<dyn SourceAdapter>],
    source_ids: Option<&[&str]>,
    filter: Option<&CredentialFilter>,
) -> Result<CredentialIndex> {
    let mut all_entries = Vec::new();
    let mut sources_scanned = Vec::new();

    for adapter in adapters {
        let detected = match adapter.detect() {
            Ok(d) => d,
            Err(_) => continue,
        };

        for d in detected {
            // Skip sources not in the filter
            if let Some(ids) = source_ids {
                if !ids.contains(&d.source.id.as_str()) {
                    continue;
                }
            }

            sources_scanned.push(d.source.id.clone());

            for profile in &d.source.profiles {
                match adapter.list_credentials(profile) {
                    Ok(entries) => {
                        all_entries.extend(entries);
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to list credentials from {} / {}: {e}",
                            d.source.name,
                            profile.name
                        );
                    }
                }
            }
        }
    }

    // Apply filter
    if let Some(filter) = filter {
        all_entries.retain(|e| filter.matches(e));
    }

    // Detect duplicates
    let duplicates = find_duplicates(&all_entries);

    Ok(CredentialIndex {
        entries: all_entries,
        duplicates,
        sources_scanned,
    })
}

/// Extract credentials by entry IDs using all available adapters.
pub async fn extract_credentials(entry_ids: &[&str]) -> Result<Vec<Credential>> {
    let adapters = adapter::get_adapters();
    extract_with_adapters(&adapters, entry_ids)
}

/// Extract credentials using specific adapters (for testing).
pub fn extract_with_adapters(
    adapters: &[Box<dyn SourceAdapter>],
    entry_ids: &[&str],
) -> Result<Vec<Credential>> {
    // Group entry IDs by their source prefix
    let mut by_source: HashMap<String, Vec<&str>> = HashMap::new();
    for id in entry_ids {
        // Entry IDs are formatted as "source-id:type:index"
        // We need to find which adapter/profile owns each entry
        let parts: Vec<&str> = id.split(':').collect();
        if parts.len() >= 2 {
            // The source part is everything before the second-to-last colon segment
            // e.g., "chrome-default:login:0001" → source = "chrome-default"
            let source = parts[..parts.len() - 2].join(":");
            if source.is_empty() && parts.len() >= 3 {
                let source = parts[..parts.len() - 2].join(":");
                by_source.entry(source).or_default().push(id);
            } else {
                by_source.entry(source).or_default().push(id);
            }
        }
    }

    let mut all_credentials = Vec::new();

    for adapter in adapters {
        let detected = match adapter.detect() {
            Ok(d) => d,
            Err(_) => continue,
        };

        for d in detected {
            for profile in &d.source.profiles {
                // Find which entry IDs belong to this source+profile
                let source_id = format!(
                    "{}-{}",
                    d.source.id.split('-').next().unwrap_or(&d.source.id),
                    profile.id.to_lowercase().replace(' ', "-")
                );

                // Check all source keys that might match
                let matching_ids: Vec<&str> = entry_ids
                    .iter()
                    .filter(|id| id.starts_with(&source_id))
                    .copied()
                    .collect();

                if matching_ids.is_empty() {
                    // Also try with the full source id
                    let matching_ids: Vec<&str> = entry_ids
                        .iter()
                        .filter(|id| id.starts_with(&d.source.id))
                        .copied()
                        .collect();

                    if !matching_ids.is_empty() {
                        match adapter.extract_credentials(profile, &matching_ids) {
                            Ok(creds) => all_credentials.extend(creds),
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to extract from {} / {}: {e}",
                                    d.source.name,
                                    profile.name
                                );
                            }
                        }
                    }
                } else {
                    match adapter.extract_credentials(profile, &matching_ids) {
                        Ok(creds) => all_credentials.extend(creds),
                        Err(e) => {
                            tracing::warn!(
                                "Failed to extract from {} / {}: {e}",
                                d.source.name,
                                profile.name
                            );
                        }
                    }
                }
            }
        }
    }

    if all_credentials.is_empty() && !entry_ids.is_empty() {
        return Err(Error::CredentialNotFound(format!(
            "No credentials found for IDs: {:?}",
            entry_ids
        )));
    }

    Ok(all_credentials)
}

/// Find duplicate credentials across sources (same domain + username).
fn find_duplicates(entries: &[CredentialEntry]) -> Vec<DuplicateGroup> {
    let mut groups: HashMap<(String, Option<String>), Vec<String>> = HashMap::new();

    for entry in entries {
        let key = (entry.domain.clone(), entry.username.clone());
        groups.entry(key).or_default().push(entry.id.clone());
    }

    groups
        .into_iter()
        .filter(|(_, ids)| ids.len() > 1)
        .map(|((domain, username), entry_ids)| DuplicateGroup {
            domain,
            username,
            entry_ids,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::chromium::{
        create_test_login_db, ChromiumAdapter, ChromiumConfig, TestLoginEntry,
    };
    use tempfile::TempDir;

    fn setup_test_adapter(
        temp: &TempDir,
        entries: &[TestLoginEntry],
    ) -> Vec<Box<dyn SourceAdapter>> {
        let encryption_key = "test-key";
        let profile_dir = temp.path().join("Default");
        std::fs::create_dir_all(&profile_dir).unwrap();
        create_test_login_db(&profile_dir.join("Login Data"), entries, encryption_key).unwrap();

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

        vec![Box::new(adapter)]
    }

    #[test]
    fn test_list_all_credentials() {
        let temp = TempDir::new().unwrap();
        let entries = vec![
            TestLoginEntry {
                url: "https://github.com".to_string(),
                username: "user1".to_string(),
                password: "pass1".to_string(),
                date_created: None,
                date_last_used: None,
                date_modified: None,
            },
            TestLoginEntry {
                url: "https://gitlab.com".to_string(),
                username: "user2".to_string(),
                password: "pass2".to_string(),
                date_created: None,
                date_last_used: None,
                date_modified: None,
            },
        ];
        let adapters = setup_test_adapter(&temp, &entries);

        let index = list_with_adapters(&adapters, None, None).unwrap();
        assert_eq!(index.entries.len(), 2);
        assert!(!index.sources_scanned.is_empty());
    }

    #[test]
    fn test_filter_by_domain() {
        let temp = TempDir::new().unwrap();
        let entries = vec![
            TestLoginEntry {
                url: "https://github.com".to_string(),
                username: "user1".to_string(),
                password: "pass1".to_string(),
                date_created: None,
                date_last_used: None,
                date_modified: None,
            },
            TestLoginEntry {
                url: "https://gitlab.com".to_string(),
                username: "user2".to_string(),
                password: "pass2".to_string(),
                date_created: None,
                date_last_used: None,
                date_modified: None,
            },
            TestLoginEntry {
                url: "https://aws.amazon.com".to_string(),
                username: "admin".to_string(),
                password: "pass3".to_string(),
                date_created: None,
                date_last_used: None,
                date_modified: None,
            },
        ];
        let adapters = setup_test_adapter(&temp, &entries);

        let filter = CredentialFilter {
            domains: Some(vec!["github.com".to_string()]),
            ..Default::default()
        };
        let index = list_with_adapters(&adapters, None, Some(&filter)).unwrap();
        assert_eq!(index.entries.len(), 1);
        assert_eq!(index.entries[0].domain, "github.com");
    }

    #[test]
    fn test_filter_by_search() {
        let temp = TempDir::new().unwrap();
        let entries = vec![
            TestLoginEntry {
                url: "https://github.com".to_string(),
                username: "octocat".to_string(),
                password: "pass1".to_string(),
                date_created: None,
                date_last_used: None,
                date_modified: None,
            },
            TestLoginEntry {
                url: "https://gitlab.com".to_string(),
                username: "developer".to_string(),
                password: "pass2".to_string(),
                date_created: None,
                date_last_used: None,
                date_modified: None,
            },
        ];
        let adapters = setup_test_adapter(&temp, &entries);

        let filter = CredentialFilter {
            search: Some("octocat".to_string()),
            ..Default::default()
        };
        let index = list_with_adapters(&adapters, None, Some(&filter)).unwrap();
        assert_eq!(index.entries.len(), 1);
        assert_eq!(index.entries[0].username.as_deref(), Some("octocat"));
    }

    #[test]
    fn test_wildcard_domain_filter() {
        let temp = TempDir::new().unwrap();
        let entries = vec![
            TestLoginEntry {
                url: "https://console.aws.amazon.com".to_string(),
                username: "admin".to_string(),
                password: "pass1".to_string(),
                date_created: None,
                date_last_used: None,
                date_modified: None,
            },
            TestLoginEntry {
                url: "https://s3.aws.amazon.com".to_string(),
                username: "admin".to_string(),
                password: "pass2".to_string(),
                date_created: None,
                date_last_used: None,
                date_modified: None,
            },
            TestLoginEntry {
                url: "https://github.com".to_string(),
                username: "user".to_string(),
                password: "pass3".to_string(),
                date_created: None,
                date_last_used: None,
                date_modified: None,
            },
        ];
        let adapters = setup_test_adapter(&temp, &entries);

        let filter = CredentialFilter {
            domains: Some(vec!["*.aws.amazon.com".to_string()]),
            ..Default::default()
        };
        let index = list_with_adapters(&adapters, None, Some(&filter)).unwrap();
        assert_eq!(index.entries.len(), 2);
    }

    #[test]
    fn test_duplicate_detection() {
        let entries = vec![
            CredentialEntry {
                id: "chrome:login:0001".to_string(),
                source_id: "chrome".to_string(),
                credential_type: CredentialType::Password,
                domain: "github.com".to_string(),
                url: None,
                username: Some("user1".to_string()),
                label: None,
                created: None,
                last_used: None,
                modified: None,
            },
            CredentialEntry {
                id: "firefox:login:0001".to_string(),
                source_id: "firefox".to_string(),
                credential_type: CredentialType::Password,
                domain: "github.com".to_string(),
                url: None,
                username: Some("user1".to_string()),
                label: None,
                created: None,
                last_used: None,
                modified: None,
            },
            CredentialEntry {
                id: "chrome:login:0002".to_string(),
                source_id: "chrome".to_string(),
                credential_type: CredentialType::Password,
                domain: "gitlab.com".to_string(),
                url: None,
                username: Some("user2".to_string()),
                label: None,
                created: None,
                last_used: None,
                modified: None,
            },
        ];

        let duplicates = find_duplicates(&entries);
        assert_eq!(duplicates.len(), 1);
        assert_eq!(duplicates[0].domain, "github.com");
        assert_eq!(duplicates[0].entry_ids.len(), 2);
    }
}
