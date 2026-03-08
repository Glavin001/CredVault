use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
};

use crate::{
    adapter::{fixture::load_fixture_adapters, DynSourceAdapter},
    error::{CredVaultError, Result},
    types::{
        Credential, CredentialEntry, CredentialFilter, CredentialIndex, CredentialSource,
        DuplicateGroup,
    },
};

#[derive(Default)]
pub struct SourceRegistry {
    adapters: HashMap<String, DynSourceAdapter>,
}

impl SourceRegistry {
    pub fn from_fixture_dir(directory: impl AsRef<Path>) -> Result<Self> {
        let adapters = load_fixture_adapters(directory)?;
        Ok(Self::from_adapters(adapters))
    }

    pub fn from_adapters(adapters: Vec<DynSourceAdapter>) -> Self {
        let adapters = adapters
            .into_iter()
            .map(|adapter| (adapter.source().id.clone(), adapter))
            .collect();
        Self { adapters }
    }

    pub fn add_adapter(&mut self, adapter: DynSourceAdapter) {
        self.adapters.insert(adapter.source().id.clone(), adapter);
    }

    pub fn discover_sources(&self) -> Vec<CredentialSource> {
        let mut sources: Vec<_> = self
            .adapters
            .values()
            .map(|adapter| adapter.source().clone())
            .collect();
        sources.sort_by(|left, right| left.name.cmp(&right.name));
        sources
    }

    pub fn list_credentials(
        &self,
        sources: Option<&[String]>,
        filter: Option<&CredentialFilter>,
    ) -> Result<CredentialIndex> {
        let selected_sources = self.resolve_sources(sources)?;
        let mut entries = Vec::new();
        let mut scanned = Vec::new();

        for adapter in selected_sources {
            scanned.push(adapter.source().id.clone());
            entries.extend(adapter.list_credentials()?);
        }

        if let Some(filter) = filter {
            entries = entries
                .into_iter()
                .filter(|entry| matches_filter(entry, filter))
                .collect();
        }

        entries.sort_by(|left, right| {
            left.domain
                .cmp(&right.domain)
                .then_with(|| left.username.cmp(&right.username))
                .then_with(|| left.source_id.cmp(&right.source_id))
        });

        let duplicates = attach_duplicate_groups(&mut entries);
        scanned.sort();

        Ok(CredentialIndex {
            entries,
            duplicates,
            sources_scanned: scanned,
        })
    }

    pub fn extract_credentials(&self, entry_ids: &[String]) -> Result<Vec<Credential>> {
        let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();

        for entry_id in entry_ids {
            let source_id = self
                .adapters
                .keys()
                .find(|source_id| entry_id.starts_with(&format!("{source_id}:")))
                .ok_or_else(|| CredVaultError::CredentialNotFound(entry_id.clone()))?;
            grouped
                .entry(source_id.clone())
                .or_default()
                .push(entry_id.clone());
        }

        let mut credentials = Vec::new();
        for (source_id, ids) in grouped {
            let adapter = self
                .adapters
                .get(&source_id)
                .ok_or_else(|| CredVaultError::SourceNotFound(source_id.clone()))?;
            credentials.extend(adapter.extract_credentials(&ids)?);
        }

        credentials.sort_by(|left, right| left.entry.id.cmp(&right.entry.id));
        Ok(credentials)
    }

    fn resolve_sources(&self, sources: Option<&[String]>) -> Result<Vec<&DynSourceAdapter>> {
        match sources {
            Some(source_ids) => source_ids
                .iter()
                .map(|source_id| {
                    self.adapters
                        .get(source_id)
                        .ok_or_else(|| CredVaultError::SourceNotFound(source_id.clone()))
                })
                .collect(),
            None => {
                let mut adapters: Vec<_> = self.adapters.values().collect();
                adapters.sort_by(|left, right| left.source().name.cmp(&right.source().name));
                Ok(adapters)
            }
        }
    }
}

fn attach_duplicate_groups(entries: &mut [CredentialEntry]) -> Vec<DuplicateGroup> {
    let mut groups: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();

    for entry in entries.iter() {
        let username = entry.username.clone().unwrap_or_default().to_lowercase();
        groups
            .entry((entry.domain.to_lowercase(), username))
            .or_default()
            .push(entry.id.clone());
    }

    let duplicate_map: HashMap<String, String> = groups
        .iter()
        .filter(|(_, ids)| ids.len() > 1)
        .enumerate()
        .flat_map(|(index, (_, ids))| {
            let group_id = format!("dup-{:04}", index + 1);
            ids.iter()
                .cloned()
                .map(move |entry_id| (entry_id, group_id.clone()))
        })
        .collect();

    for entry in entries.iter_mut() {
        entry.duplicate_group = duplicate_map.get(&entry.id).cloned();
    }

    groups
        .into_iter()
        .filter(|(_, ids)| ids.len() > 1)
        .enumerate()
        .map(|(index, ((domain, username), entry_ids))| DuplicateGroup {
            id: format!("dup-{:04}", index + 1),
            domain,
            username: if username.is_empty() {
                None
            } else {
                Some(username)
            },
            entry_ids,
        })
        .collect()
}

fn matches_filter(entry: &CredentialEntry, filter: &CredentialFilter) -> bool {
    if let Some(domains) = &filter.domains {
        if !domains
            .iter()
            .any(|pattern| wildcard_match(pattern, &entry.domain))
        {
            return false;
        }
    }

    if let Some(sources) = &filter.sources {
        if !sources.iter().any(|source| source == &entry.source_id) {
            return false;
        }
    }

    if let Some(types) = &filter.types {
        if !types.iter().any(|kind| kind == &entry.credential_type) {
            return false;
        }
    }

    if let Some(min_last_used) = filter.min_last_used {
        match entry.last_used {
            Some(last_used) if last_used >= min_last_used => {}
            _ => return false,
        }
    }

    if let Some(search) = &filter.search {
        let needle = search.to_lowercase();
        let haystacks = [
            entry.domain.to_lowercase(),
            entry.username.clone().unwrap_or_default().to_lowercase(),
            entry.label.clone().unwrap_or_default().to_lowercase(),
        ];

        if !haystacks.iter().any(|value| value.contains(&needle)) {
            return false;
        }
    }

    true
}

fn wildcard_match(pattern: &str, candidate: &str) -> bool {
    let pattern = pattern.to_lowercase();
    let candidate = candidate.to_lowercase();

    if pattern == "*" {
        return true;
    }

    if !pattern.contains('*') {
        return pattern == candidate;
    }

    let parts: Vec<&str> = pattern.split('*').collect();
    let mut remainder = candidate.as_str();
    let starts_with_wildcard = pattern.starts_with('*');
    let ends_with_wildcard = pattern.ends_with('*');

    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }

        if index == 0 && !starts_with_wildcard {
            if let Some(stripped) = remainder.strip_prefix(part) {
                remainder = stripped;
                continue;
            }
            return false;
        }

        if index == parts.len() - 1 && !ends_with_wildcard {
            return remainder.ends_with(part);
        }

        if let Some(position) = remainder.find(part) {
            remainder = &remainder[(position + part.len())..];
        } else {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::wildcard_match;

    #[test]
    fn wildcard_supports_exact_and_glob_patterns() {
        assert!(wildcard_match("github.com", "github.com"));
        assert!(wildcard_match("*.aws.amazon.com", "console.aws.amazon.com"));
        assert!(wildcard_match("github*", "github.enterprise.local"));
        assert!(!wildcard_match("*.aws.amazon.com", "github.com"));
    }
}
