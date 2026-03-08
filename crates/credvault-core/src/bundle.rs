use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use chrono::{DateTime, Utc};
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::{
    error::{CredVaultError, Result},
    types::{
        BundleArtifact, BundleContents, BundleFormat, BundleOptions, Credential, CredentialType,
    },
};

const MAGIC: &[u8; 4] = b"CVLT";
const VERSION: u8 = 1;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BundlePayload {
    bundle_id: String,
    label: String,
    created: DateTime<Utc>,
    expires: Option<DateTime<Utc>>,
    credentials: Vec<SerializableCredential>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerializableCredential {
    id: String,
    source_id: String,
    credential_type: CredentialType,
    domain: String,
    url: Option<String>,
    username: Option<String>,
    label: Option<String>,
    created: Option<DateTime<Utc>>,
    last_used: Option<DateTime<Utc>>,
    modified: Option<DateTime<Utc>>,
    tags: Vec<String>,
    secret: String,
}

#[derive(Debug, Clone, Serialize)]
struct CsvRow<'a> {
    id: &'a str,
    source_id: &'a str,
    credential_type: &'a CredentialType,
    domain: &'a str,
    url: Option<&'a str>,
    username: Option<&'a str>,
    label: Option<&'a str>,
    secret: &'a str,
}

#[derive(Debug, Clone, Serialize)]
struct AgentConfig<'a> {
    credvault_agent_config: AgentConfigInner<'a>,
}

#[derive(Debug, Clone, Serialize)]
struct AgentConfigInner<'a> {
    version: u8,
    bundle_id: String,
    created: DateTime<Utc>,
    expires: Option<DateTime<Utc>>,
    label: &'a str,
    credentials: Vec<AgentCredential<'a>>,
}

#[derive(Debug, Clone, Serialize)]
struct AgentCredential<'a> {
    id: &'a str,
    domain: &'a str,
    #[serde(rename = "type")]
    credential_type: &'a CredentialType,
    username: Option<&'a str>,
    label: Option<&'a str>,
    secret: &'a str,
    tags: &'a [String],
}

pub fn create_bundle(
    credentials: &[Credential],
    options: &BundleOptions,
) -> Result<BundleArtifact> {
    match options.format {
        BundleFormat::CredVault => create_native_bundle(credentials, options),
        BundleFormat::Csv => create_csv_export(credentials),
        BundleFormat::Env => create_env_export(credentials),
        BundleFormat::AgentConfig => create_agent_config_export(credentials, options),
    }
}

pub fn read_bundle(data: &[u8], password: &SecretString) -> Result<BundleContents> {
    if data.len() < MAGIC.len() + 1 + SALT_LEN + NONCE_LEN {
        return Err(CredVaultError::InvalidBundleData);
    }

    if &data[..MAGIC.len()] != MAGIC {
        return Err(CredVaultError::UnsupportedBundleRead);
    }

    if data[MAGIC.len()] != VERSION {
        return Err(CredVaultError::InvalidBundleData);
    }

    let salt_start = MAGIC.len() + 1;
    let nonce_start = salt_start + SALT_LEN;
    let payload_start = nonce_start + NONCE_LEN;

    let salt = &data[salt_start..nonce_start];
    let nonce = &data[nonce_start..payload_start];
    let ciphertext = &data[payload_start..];

    let key = derive_bundle_key(password, salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| CredVaultError::InvalidBundleData)?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| CredVaultError::BundleDecryptionFailed)?;

    let payload: BundlePayload = serde_json::from_slice(&plaintext)?;

    let credentials = payload
        .credentials
        .into_iter()
        .map(|credential| Credential {
            entry: crate::types::CredentialEntry {
                id: credential.id,
                source_id: credential.source_id,
                credential_type: credential.credential_type,
                domain: credential.domain,
                url: credential.url,
                username: credential.username,
                label: credential.label,
                created: credential.created,
                last_used: credential.last_used,
                modified: credential.modified,
                tags: credential.tags,
                duplicate_group: None,
            },
            secret: SecretString::new(credential.secret.into_boxed_str()),
        })
        .collect();

    Ok(BundleContents {
        bundle_id: payload.bundle_id,
        label: payload.label,
        created: payload.created,
        expires: payload.expires,
        credentials,
    })
}

fn create_native_bundle(
    credentials: &[Credential],
    options: &BundleOptions,
) -> Result<BundleArtifact> {
    let password = options
        .password
        .as_ref()
        .ok_or(CredVaultError::MissingBundlePassword)?;

    let payload = BundlePayload {
        bundle_id: generate_bundle_id(),
        label: options.label.clone(),
        created: Utc::now(),
        expires: options.expires,
        credentials: credentials.iter().map(to_serializable_credential).collect(),
    };

    let plaintext = serde_json::to_vec(&payload)?;
    let mut salt = [0_u8; SALT_LEN];
    let mut nonce = [0_u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);

    let key = derive_bundle_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| CredVaultError::InvalidBundleData)?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
        .map_err(|_| CredVaultError::InvalidBundleData)?;

    let mut bytes = Vec::with_capacity(MAGIC.len() + 1 + SALT_LEN + NONCE_LEN + ciphertext.len());
    bytes.extend_from_slice(MAGIC);
    bytes.push(VERSION);
    bytes.extend_from_slice(&salt);
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&ciphertext);

    Ok(BundleArtifact {
        format: BundleFormat::CredVault,
        encrypted: true,
        file_extension: "credvault",
        bytes,
    })
}

fn create_csv_export(credentials: &[Credential]) -> Result<BundleArtifact> {
    let mut writer = csv::Writer::from_writer(Vec::new());

    for credential in credentials {
        let row = CsvRow {
            id: &credential.entry.id,
            source_id: &credential.entry.source_id,
            credential_type: &credential.entry.credential_type,
            domain: &credential.entry.domain,
            url: credential.entry.url.as_deref(),
            username: credential.entry.username.as_deref(),
            label: credential.entry.label.as_deref(),
            secret: credential.secret.expose_secret(),
        };
        writer.serialize(row)?;
    }

    let bytes = writer
        .into_inner()
        .map_err(|error| CredVaultError::Serialization(error.to_string()))?;

    Ok(BundleArtifact {
        format: BundleFormat::Csv,
        encrypted: false,
        file_extension: "csv",
        bytes,
    })
}

fn create_env_export(credentials: &[Credential]) -> Result<BundleArtifact> {
    let mut output = String::new();

    for (index, credential) in credentials.iter().enumerate() {
        let prefix = sanitize_env_key(&credential.entry.domain, index + 1);
        if let Some(username) = &credential.entry.username {
            output.push_str(&format!("{prefix}_USERNAME={username}\n"));
        }
        output.push_str(&format!(
            "{prefix}_SECRET={}\n",
            credential.secret.expose_secret()
        ));
    }

    Ok(BundleArtifact {
        format: BundleFormat::Env,
        encrypted: false,
        file_extension: "env",
        bytes: output.into_bytes(),
    })
}

fn create_agent_config_export(
    credentials: &[Credential],
    options: &BundleOptions,
) -> Result<BundleArtifact> {
    let bundle_id = generate_bundle_id();
    let created = Utc::now();

    let payload = AgentConfig {
        credvault_agent_config: AgentConfigInner {
            version: 1,
            bundle_id,
            created,
            expires: options.expires,
            label: &options.label,
            credentials: credentials
                .iter()
                .map(|credential| AgentCredential {
                    id: &credential.entry.id,
                    domain: &credential.entry.domain,
                    credential_type: &credential.entry.credential_type,
                    username: credential.entry.username.as_deref(),
                    label: credential.entry.label.as_deref(),
                    secret: credential.secret.expose_secret(),
                    tags: &credential.entry.tags,
                })
                .collect(),
        },
    };

    let bytes = serde_json::to_vec_pretty(&payload)?;

    Ok(BundleArtifact {
        format: BundleFormat::AgentConfig,
        encrypted: false,
        file_extension: "json",
        bytes,
    })
}

fn derive_bundle_key(password: &SecretString, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let mut key = [0_u8; KEY_LEN];
    Argon2::default()
        .hash_password_into(password.expose_secret().as_bytes(), salt, &mut key)
        .map_err(|_| CredVaultError::InvalidBundleData)?;
    Ok(key)
}

fn to_serializable_credential(credential: &Credential) -> SerializableCredential {
    SerializableCredential {
        id: credential.entry.id.clone(),
        source_id: credential.entry.source_id.clone(),
        credential_type: credential.entry.credential_type.clone(),
        domain: credential.entry.domain.clone(),
        url: credential.entry.url.clone(),
        username: credential.entry.username.clone(),
        label: credential.entry.label.clone(),
        created: credential.entry.created,
        last_used: credential.entry.last_used,
        modified: credential.entry.modified,
        tags: credential.entry.tags.clone(),
        secret: credential.secret.expose_secret().to_string(),
    }
}

fn sanitize_env_key(domain: &str, index: usize) -> String {
    let sanitized: String = domain
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("CV_{sanitized}_{index:02}")
}

fn generate_bundle_id() -> String {
    let mut random = [0_u8; 8];
    rand::thread_rng().fill_bytes(&mut random);
    format!(
        "cvlt-{}-{:016x}",
        Utc::now().timestamp_millis(),
        u64::from_be_bytes(random)
    )
}
