use std::path::PathBuf;

use credvault_core::{BundleFormat, BundleOptions, CredVault, CredentialFilter};
use napi::Error;
use napi_derive::napi;
use secrecy::SecretString;

fn to_napi_error(error: credvault_core::CredVaultError) -> Error {
    Error::from_reason(error.to_string())
}

#[napi]
pub fn discover_sources_json(fixtures_dir: String) -> napi::Result<String> {
    let vault = CredVault::from_fixture_dir(PathBuf::from(fixtures_dir)).map_err(to_napi_error)?;
    serde_json::to_string_pretty(&vault.discover_sources())
        .map_err(|error| Error::from_reason(error.to_string()))
}

#[napi]
pub fn list_credentials_json(
    fixtures_dir: String,
    filter_json: Option<String>,
) -> napi::Result<String> {
    let vault = CredVault::from_fixture_dir(PathBuf::from(fixtures_dir)).map_err(to_napi_error)?;
    let filter = filter_json
        .as_deref()
        .map(serde_json::from_str::<CredentialFilter>)
        .transpose()
        .map_err(|error| Error::from_reason(error.to_string()))?;
    let index = vault
        .list_credentials(None, filter.as_ref())
        .map_err(to_napi_error)?;
    serde_json::to_string_pretty(&index).map_err(|error| Error::from_reason(error.to_string()))
}

#[napi]
pub fn export_agent_config_json(
    fixtures_dir: String,
    entry_ids_json: String,
    label: String,
) -> napi::Result<String> {
    let vault = CredVault::from_fixture_dir(PathBuf::from(fixtures_dir)).map_err(to_napi_error)?;
    let entry_ids: Vec<String> = serde_json::from_str(&entry_ids_json)
        .map_err(|error| Error::from_reason(error.to_string()))?;
    let credentials = vault
        .extract_credentials(&entry_ids)
        .map_err(to_napi_error)?;
    let artifact = vault
        .create_bundle(
            &credentials,
            &BundleOptions {
                format: BundleFormat::AgentConfig,
                password: None,
                label,
                expires: None,
                include_metadata: true,
            },
        )
        .map_err(to_napi_error)?;
    String::from_utf8(artifact.bytes).map_err(|error| Error::from_reason(error.to_string()))
}

#[napi]
pub fn read_bundle_json(bundle_bytes: Vec<u8>, password: String) -> napi::Result<String> {
    let contents =
        credvault_core::read_bundle(&bundle_bytes, &SecretString::new(password.into_boxed_str()))
            .map_err(to_napi_error)?;

    #[derive(serde::Serialize)]
    struct SerializableBundle<'a> {
        label: &'a str,
        created: String,
        expires: Option<String>,
        credentials: Vec<SerializableCredential<'a>>,
    }

    #[derive(serde::Serialize)]
    struct SerializableCredential<'a> {
        id: &'a str,
        domain: &'a str,
        username: Option<&'a str>,
        source_id: &'a str,
    }

    let payload = SerializableBundle {
        label: &contents.label,
        created: contents.created.to_rfc3339(),
        expires: contents.expires.map(|value| value.to_rfc3339()),
        credentials: contents
            .credentials
            .iter()
            .map(|credential| SerializableCredential {
                id: &credential.entry.id,
                domain: &credential.entry.domain,
                username: credential.entry.username.as_deref(),
                source_id: &credential.entry.source_id,
            })
            .collect(),
    };

    serde_json::to_string_pretty(&payload).map_err(|error| Error::from_reason(error.to_string()))
}
