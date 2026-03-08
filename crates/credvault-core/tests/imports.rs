use std::path::PathBuf;

use credvault_core::{read_bundle, BundleFormat, BundleOptions, CredVault, CredentialFilter};
use secrecy::{ExposeSecret, SecretString};

fn export_fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/exports")
        .join(name)
}

#[test]
fn imports_chrome_csv_and_bitwarden_json_exports() {
    let vault = CredVault::builder()
        .with_chrome_csv_export(export_fixture("chrome-passwords.csv"))
        .expect("chrome export")
        .with_bitwarden_json_export(export_fixture("bitwarden-export.json"))
        .expect("bitwarden export")
        .build()
        .expect("vault");

    let sources = vault.discover_sources();
    assert_eq!(sources.len(), 2);
    assert!(sources
        .iter()
        .any(|source| source.name.contains("Chrome CSV Export")));
    assert!(sources
        .iter()
        .any(|source| source.name.contains("Bitwarden JSON Export")));

    let index = vault
        .list_credentials(
            None,
            Some(&CredentialFilter {
                domains: Some(vec!["github.com".to_string()]),
                ..CredentialFilter::default()
            }),
        )
        .expect("index");

    assert_eq!(index.entries.len(), 2);
    assert_eq!(index.duplicates.len(), 1);
}

#[test]
fn exports_bundle_from_real_import_sources() {
    let vault = CredVault::builder()
        .with_chrome_csv_export(export_fixture("chrome-passwords.csv"))
        .expect("chrome export")
        .with_bitwarden_json_export(export_fixture("bitwarden-export.json"))
        .expect("bitwarden export")
        .build()
        .expect("vault");

    let index = vault
        .list_credentials(
            None,
            Some(&CredentialFilter {
                domains: Some(vec!["platform.openai.com".to_string()]),
                ..CredentialFilter::default()
            }),
        )
        .expect("index");
    let ids: Vec<String> = index.entries.into_iter().map(|entry| entry.id).collect();
    let credentials = vault.extract_credentials(&ids).expect("credentials");

    let artifact = vault
        .create_bundle(
            &credentials,
            &BundleOptions {
                format: BundleFormat::CredVault,
                password: Some(SecretString::new("import-bundle-password".into())),
                label: "Imported Bundle".to_string(),
                expires: None,
                include_metadata: true,
            },
        )
        .expect("bundle");

    let contents = read_bundle(
        &artifact.bytes,
        &SecretString::new("import-bundle-password".into()),
    )
    .expect("read bundle");

    assert_eq!(contents.credentials.len(), 1);
    assert_eq!(contents.credentials[0].entry.domain, "platform.openai.com");
    assert_eq!(
        contents.credentials[0].secret.expose_secret(),
        "bitwarden-export-openai"
    );
}
