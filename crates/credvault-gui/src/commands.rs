use credvault_core::{
    BundleContents, BundleFormat, BundleOptions, CredentialEntry, CredentialFilter,
    CredentialSource, CredentialType,
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ── Serializable response types ──────────────────────────────

#[derive(Serialize)]
pub struct ExportResult {
    pub path: String,
    pub size: usize,
}

#[derive(Deserialize)]
pub struct FilterParams {
    pub domains: Option<Vec<String>>,
    pub sources: Option<Vec<String>>,
    pub types: Option<Vec<String>>,
    pub search: Option<String>,
}

#[derive(Deserialize)]
pub struct ExportParams {
    pub entry_ids: Vec<String>,
    pub format: String,
    pub password: String,
    pub label: String,
    pub output_path: String,
    pub expires_hours: Option<u64>,
    pub include_metadata: bool,
}

#[derive(Deserialize)]
pub struct ReadBundleParams {
    pub path: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct ListResult {
    pub entries: Vec<CredentialEntry>,
    pub sources_scanned: Vec<String>,
    pub duplicate_count: usize,
}

#[derive(Serialize)]
pub struct ExtractedCredential {
    pub id: String,
    pub source_id: String,
    pub credential_type: CredentialType,
    pub domain: String,
    pub url: Option<String>,
    pub username: Option<String>,
    pub label: Option<String>,
    pub secret: String,
}

// ── Tauri commands ───────────────────────────────────────────

#[tauri::command]
pub async fn discover_sources() -> Result<Vec<CredentialSource>, String> {
    credvault_core::discover_sources()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn list_credentials(filter: Option<FilterParams>) -> Result<ListResult, String> {
    let cred_filter = filter.map(|f| {
        let types = f.types.map(|ts| {
            ts.iter()
                .filter_map(|t| match t.to_lowercase().as_str() {
                    "password" => Some(CredentialType::Password),
                    "creditcard" | "credit_card" => Some(CredentialType::CreditCard),
                    "cookie" => Some(CredentialType::Cookie),
                    "apikey" | "api_key" => Some(CredentialType::ApiKey),
                    "certificate" => Some(CredentialType::Certificate),
                    "sessiontoken" | "session_token" => Some(CredentialType::SessionToken),
                    _ => None,
                })
                .collect()
        });

        CredentialFilter {
            domains: f.domains,
            sources: f.sources,
            types,
            search: f.search,
        }
    });

    let index = credvault_core::list_credentials(None, cred_filter.as_ref())
        .await
        .map_err(|e| e.to_string())?;

    Ok(ListResult {
        duplicate_count: index.duplicates.len(),
        entries: index.entries,
        sources_scanned: index.sources_scanned,
    })
}

#[tauri::command]
pub async fn extract_credentials(
    entry_ids: Vec<String>,
) -> Result<Vec<ExtractedCredential>, String> {
    let id_refs: Vec<&str> = entry_ids.iter().map(|s| s.as_str()).collect();

    let credentials = credvault_core::extract_credentials(&id_refs)
        .await
        .map_err(|e| e.to_string())?;

    Ok(credentials
        .into_iter()
        .map(|c| {
            use secrecy::ExposeSecret;
            ExtractedCredential {
                id: c.entry.id,
                source_id: c.entry.source_id,
                credential_type: c.entry.credential_type,
                domain: c.entry.domain,
                url: c.entry.url,
                username: c.entry.username,
                label: c.entry.label,
                secret: c.secret.expose_secret().to_string(),
            }
        })
        .collect())
}

#[tauri::command]
pub async fn export_bundle(params: ExportParams) -> Result<ExportResult, String> {
    let id_refs: Vec<&str> = params.entry_ids.iter().map(|s| s.as_str()).collect();

    let credentials = credvault_core::extract_credentials(&id_refs)
        .await
        .map_err(|e| e.to_string())?;

    let format: BundleFormat = params.format.parse().map_err(|e: String| e)?;

    let expires = params
        .expires_hours
        .map(|hours| chrono::Utc::now() + chrono::Duration::hours(hours as i64));

    let options = BundleOptions {
        format,
        password: SecretString::from(params.password),
        label: params.label,
        expires,
        include_metadata: params.include_metadata,
    };

    let data = credvault_core::create_bundle(&credentials, &options).map_err(|e| e.to_string())?;

    let size = data.len();
    let path = PathBuf::from(&params.output_path);
    std::fs::write(&path, &data).map_err(|e| e.to_string())?;

    Ok(ExportResult {
        path: params.output_path,
        size,
    })
}

#[tauri::command]
pub async fn read_bundle(params: ReadBundleParams) -> Result<BundleContents, String> {
    let data = std::fs::read(&params.path).map_err(|e| e.to_string())?;
    let password = SecretString::from(params.password);

    credvault_core::read_bundle(&data, &password).map_err(|e| e.to_string())
}
