use std::path::PathBuf;

use credvault_core::{read_bundle, BundleFormat, BundleOptions, CredVault, CredentialFilter};
use secrecy::{ExposeSecret, SecretString};

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

#[test]
fn discovers_fixture_sources() {
    let vault = CredVault::from_fixture_dir(fixture_dir()).expect("fixture vault");
    let sources = vault.discover_sources();

    assert_eq!(sources.len(), 2);
    assert_eq!(sources[0].name, "Chrome (Fixture Default Profile)");
    assert_eq!(sources[1].name, "Chrome (Fixture Work Profile)");
}

#[test]
fn lists_credentials_and_marks_duplicates() {
    let vault = CredVault::from_fixture_dir(fixture_dir()).expect("fixture vault");
    let filter = CredentialFilter {
        domains: Some(vec!["github.com".to_string()]),
        ..CredentialFilter::default()
    };

    let index = vault.list_credentials(None, Some(&filter)).expect("index");

    assert_eq!(index.entries.len(), 2);
    assert_eq!(index.duplicates.len(), 1);
    assert!(index
        .entries
        .iter()
        .all(|entry| entry.duplicate_group.as_deref() == Some("dup-0001")));
}

#[test]
fn exports_and_reads_native_bundle() {
    let vault = CredVault::from_fixture_dir(fixture_dir()).expect("fixture vault");
    let credentials = vault
        .extract_credentials(&[
            "chrome-default-fixture:login:github-glavin".to_string(),
            "chrome-work-fixture:login:console-aws".to_string(),
        ])
        .expect("credentials");

    let artifact = vault
        .create_bundle(
            &credentials,
            &BundleOptions {
                format: BundleFormat::CredVault,
                password: Some(SecretString::new("bundle-secret".into())),
                label: "Dev Agent".to_string(),
                expires: None,
                include_metadata: true,
            },
        )
        .expect("bundle");

    let contents = read_bundle(&artifact.bytes, &SecretString::new("bundle-secret".into()))
        .expect("read bundle");

    assert_eq!(contents.label, "Dev Agent");
    assert_eq!(contents.credentials.len(), 2);
    assert!(contents
        .credentials
        .iter()
        .any(|credential| credential.entry.domain == "console.aws.amazon.com"));
    assert!(contents.credentials.iter().any(|credential| {
        credential.entry.domain == "github.com"
            && credential.secret.expose_secret() == "fixture-github-password-default"
    }));
}

#[test]
fn exports_env_format() {
    let vault = CredVault::from_fixture_dir(fixture_dir()).expect("fixture vault");
    let credentials = vault
        .extract_credentials(&["chrome-default-fixture:api:openai".to_string()])
        .expect("credentials");

    let artifact = vault
        .create_bundle(
            &credentials,
            &BundleOptions {
                format: BundleFormat::Env,
                password: None,
                label: "Dev Env".to_string(),
                expires: None,
                include_metadata: true,
            },
        )
        .expect("env export");

    let env = String::from_utf8(artifact.bytes).expect("utf8 env");
    assert!(env.contains("CV_API_OPENAI_COM_01_SECRET=sk-fixture-openai-key"));
}
