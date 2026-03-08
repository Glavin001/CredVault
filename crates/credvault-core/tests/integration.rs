//! Integration tests that exercise the full CredVault pipeline:
//! scan → list → extract → bundle → read
//!
//! These tests create mock Chrome browser databases to simulate
//! real credential extraction without needing actual browser installs.

use credvault_core::adapter::chromium::{
    create_test_login_db, ChromiumAdapter, ChromiumConfig, TestLoginEntry,
};
use credvault_core::adapter::SourceAdapter;
use credvault_core::*;
use secrecy::{ExposeSecret, SecretString};
use tempfile::TempDir;

/// Helper: create a mock Chrome setup with test credentials.
fn setup_mock_chrome(entries: &[TestLoginEntry]) -> (TempDir, ChromiumAdapter) {
    let temp = TempDir::new().unwrap();
    let encryption_key = "integration-test-key";
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

    (temp, adapter)
}

fn dev_credentials() -> Vec<TestLoginEntry> {
    vec![
        TestLoginEntry {
            url: "https://github.com/login".to_string(),
            username: "developer".to_string(),
            password: "ghp_xxxxxxxxxxxxxxxxxxxx".to_string(),
            date_created: Some(13_300_000_000_000_000),
            date_last_used: Some(13_350_000_000_000_000),
            date_modified: Some(13_300_000_000_000_000),
        },
        TestLoginEntry {
            url: "https://console.aws.amazon.com/".to_string(),
            username: "admin@company.com".to_string(),
            password: "Aws$ecret!2024".to_string(),
            date_created: Some(13_280_000_000_000_000),
            date_last_used: Some(13_340_000_000_000_000),
            date_modified: None,
        },
        TestLoginEntry {
            url: "https://app.vercel.com/login".to_string(),
            username: "deployer@company.com".to_string(),
            password: "vercel-token-abc123".to_string(),
            date_created: Some(13_310_000_000_000_000),
            date_last_used: Some(13_360_000_000_000_000),
            date_modified: Some(13_310_000_000_000_000),
        },
        TestLoginEntry {
            url: "https://registry.npmjs.org/".to_string(),
            username: "npm-user".to_string(),
            password: "npm_xxxxxxxxxxxx".to_string(),
            date_created: Some(13_290_000_000_000_000),
            date_last_used: Some(13_330_000_000_000_000),
            date_modified: None,
        },
        TestLoginEntry {
            url: "https://accounts.google.com/signin".to_string(),
            username: "personal@gmail.com".to_string(),
            password: "gmail-password-456".to_string(),
            date_created: Some(13_250_000_000_000_000),
            date_last_used: Some(13_355_000_000_000_000),
            date_modified: None,
        },
        TestLoginEntry {
            url: "https://www.facebook.com/login".to_string(),
            username: "personal@gmail.com".to_string(),
            password: "fb-password-789".to_string(),
            date_created: Some(13_260_000_000_000_000),
            date_last_used: Some(13_320_000_000_000_000),
            date_modified: None,
        },
    ]
}

#[test]
fn test_full_pipeline_credvault_format() {
    let (_temp, adapter) = setup_mock_chrome(&dev_credentials());

    // Step 1: Scan / Detect
    let sources = adapter.detect().unwrap();
    assert_eq!(sources.len(), 1);
    let source = &sources[0].source;
    assert_eq!(source.credential_count, Some(6));
    assert_eq!(source.status, SourceStatus::Accessible);

    // Step 2: List credentials (metadata only)
    let profile = &source.profiles[0];
    let entries = adapter.list_credentials(profile).unwrap();
    assert_eq!(entries.len(), 6);

    // Verify no secrets are exposed in entries
    for entry in &entries {
        assert!(!entry.id.is_empty());
        assert!(!entry.domain.is_empty());
        assert_eq!(entry.credential_type, CredentialType::Password);
    }

    // Step 3: Extract only work-related credentials
    let work_ids: Vec<&str> = entries
        .iter()
        .filter(|e| {
            ["github.com", "console.aws.amazon.com", "app.vercel.com", "registry.npmjs.org"]
                .contains(&e.domain.as_str())
        })
        .map(|e| e.id.as_str())
        .collect();
    assert_eq!(work_ids.len(), 4);

    let credentials = adapter.extract_credentials(profile, &work_ids).unwrap();
    assert_eq!(credentials.len(), 4);

    // Verify secrets are correctly decrypted
    let github = credentials
        .iter()
        .find(|c| c.entry.domain == "github.com")
        .unwrap();
    assert_eq!(github.secret.expose_secret(), "ghp_xxxxxxxxxxxxxxxxxxxx");
    assert_eq!(github.entry.username.as_deref(), Some("developer"));

    // Step 4: Create encrypted bundle
    let password = SecretString::from("my-bundle-password-2024!");
    let options = BundleOptions {
        format: BundleFormat::CredVault,
        password: password.clone(),
        label: "Work Dev Credentials".to_string(),
        expires: None,
        include_metadata: true,
    };

    let bundle_data = create_bundle(&credentials, &options).unwrap();

    // Verify it's a valid CVLT bundle
    assert_eq!(&bundle_data[..4], b"CVLT");
    assert_eq!(bundle_data[4], 0x01); // version 1

    // Step 5: Read the bundle back
    let contents = read_bundle(&bundle_data, &password).unwrap();
    assert_eq!(contents.label, "Work Dev Credentials");
    assert_eq!(contents.credentials.len(), 4);

    // Verify all credentials roundtripped correctly
    let gh_cred = contents
        .credentials
        .iter()
        .find(|c| c.domain == "github.com")
        .unwrap();
    assert_eq!(gh_cred.password, "ghp_xxxxxxxxxxxxxxxxxxxx");
    assert_eq!(gh_cred.username.as_deref(), Some("developer"));

    let aws_cred = contents
        .credentials
        .iter()
        .find(|c| c.domain == "console.aws.amazon.com")
        .unwrap();
    assert_eq!(aws_cred.password, "Aws$ecret!2024");
}

#[test]
fn test_full_pipeline_csv_format() {
    let (_temp, adapter) = setup_mock_chrome(&dev_credentials());
    let sources = adapter.detect().unwrap();
    let profile = &sources[0].source.profiles[0];

    let credentials = adapter.extract_credentials(profile, &[]).unwrap();

    let options = BundleOptions {
        format: BundleFormat::Csv,
        password: SecretString::from(""),
        label: "CSV Export".to_string(),
        expires: None,
        include_metadata: false,
    };

    let csv_data = create_bundle(&credentials, &options).unwrap();
    let csv_str = String::from_utf8(csv_data).unwrap();

    // Verify CSV structure
    let lines: Vec<&str> = csv_str.lines().collect();
    assert!(lines.len() >= 7); // header + 6 credentials
    assert_eq!(lines[0], "domain,url,username,password,type");

    // Verify all credentials are present
    assert!(csv_str.contains("github.com"));
    assert!(csv_str.contains("ghp_xxxxxxxxxxxxxxxxxxxx"));
    assert!(csv_str.contains("console.aws.amazon.com"));
    assert!(csv_str.contains("Aws$ecret!2024"));
}

#[test]
fn test_full_pipeline_env_format() {
    let (_temp, adapter) = setup_mock_chrome(&dev_credentials());
    let sources = adapter.detect().unwrap();
    let profile = &sources[0].source.profiles[0];

    // Extract only GitHub and AWS
    let entries = adapter.list_credentials(profile).unwrap();
    let ids: Vec<&str> = entries
        .iter()
        .filter(|e| e.domain == "github.com" || e.domain == "console.aws.amazon.com")
        .map(|e| e.id.as_str())
        .collect();

    let credentials = adapter.extract_credentials(profile, &ids).unwrap();
    assert_eq!(credentials.len(), 2);

    let options = BundleOptions {
        format: BundleFormat::Env,
        password: SecretString::from(""),
        label: "Env Export".to_string(),
        expires: None,
        include_metadata: false,
    };

    let env_data = create_bundle(&credentials, &options).unwrap();
    let env_str = String::from_utf8(env_data).unwrap();

    assert!(env_str.contains("GITHUB_COM_USERNAME=developer"));
    assert!(env_str.contains("GITHUB_COM_PASSWORD=ghp_xxxxxxxxxxxxxxxxxxxx"));
    assert!(env_str.contains("CONSOLE_AWS_AMAZON_COM_USERNAME=admin@company.com"));
    assert!(env_str.contains("CONSOLE_AWS_AMAZON_COM_PASSWORD=Aws$ecret!2024"));
}

#[test]
fn test_full_pipeline_agent_config_format() {
    let (_temp, adapter) = setup_mock_chrome(&dev_credentials());
    let sources = adapter.detect().unwrap();
    let profile = &sources[0].source.profiles[0];
    let credentials = adapter.extract_credentials(profile, &[]).unwrap();

    let options = BundleOptions {
        format: BundleFormat::AgentConfig,
        password: SecretString::from(""),
        label: "AI Coding Agent".to_string(),
        expires: None,
        include_metadata: true,
    };

    let json_data = create_bundle(&credentials, &options).unwrap();
    let config: serde_json::Value = serde_json::from_slice(&json_data).unwrap();

    let agent = &config["credvault_agent_config"];
    assert_eq!(agent["version"], 1);
    assert_eq!(agent["label"], "AI Coding Agent");
    assert_eq!(agent["credentials"].as_array().unwrap().len(), 6);
    assert_eq!(agent["permissions"]["can_rotate"], false);
    assert_eq!(agent["permissions"]["can_create_tokens"], false);

    // Verify credential structure
    let gh = agent["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["domain"] == "github.com")
        .unwrap();
    assert_eq!(gh["username"], "developer");
    assert_eq!(gh["password"], "ghp_xxxxxxxxxxxxxxxxxxxx");
    assert_eq!(gh["type"], "Password");
}

#[test]
fn test_bundle_wrong_password_rejected() {
    let (_temp, adapter) = setup_mock_chrome(&dev_credentials());
    let sources = adapter.detect().unwrap();
    let profile = &sources[0].source.profiles[0];
    let credentials = adapter.extract_credentials(profile, &[]).unwrap();

    let password = SecretString::from("correct-password");
    let options = BundleOptions {
        format: BundleFormat::CredVault,
        password,
        label: "Test".to_string(),
        expires: None,
        include_metadata: false,
    };

    let bundle_data = create_bundle(&credentials, &options).unwrap();

    // Try to read with wrong password
    let wrong_pw = SecretString::from("wrong-password");
    let result = read_bundle(&bundle_data, &wrong_pw);
    assert!(result.is_err());
}

#[test]
fn test_filtering_workflow() {
    let (_temp, adapter) = setup_mock_chrome(&dev_credentials());
    let adapters: Vec<Box<dyn SourceAdapter>> = vec![Box::new(adapter)];

    // Filter by domain
    let filter = CredentialFilter {
        domains: Some(vec!["github.com".to_string()]),
        ..Default::default()
    };
    let index =
        credvault_core::index::list_with_adapters(&adapters, None, Some(&filter)).unwrap();
    assert_eq!(index.entries.len(), 1);
    assert_eq!(index.entries[0].domain, "github.com");

    // Filter by search
    let filter = CredentialFilter {
        search: Some("company.com".to_string()),
        ..Default::default()
    };
    let index =
        credvault_core::index::list_with_adapters(&adapters, None, Some(&filter)).unwrap();
    assert_eq!(index.entries.len(), 2); // admin@company.com and deployer@company.com

    // Wildcard domain filter
    let filter = CredentialFilter {
        domains: Some(vec!["*.amazon.com".to_string()]),
        ..Default::default()
    };
    let index =
        credvault_core::index::list_with_adapters(&adapters, None, Some(&filter)).unwrap();
    assert_eq!(index.entries.len(), 1);
    assert_eq!(index.entries[0].domain, "console.aws.amazon.com");
}

#[test]
fn test_credential_deduplication() {
    // Create two "browsers" with overlapping credentials
    let temp1 = TempDir::new().unwrap();
    let temp2 = TempDir::new().unwrap();
    let key = "dedup-test-key";

    let shared_entries = vec![TestLoginEntry {
        url: "https://github.com/login".to_string(),
        username: "developer".to_string(),
        password: "password-from-chrome".to_string(),
        date_created: None,
        date_last_used: None,
        date_modified: None,
    }];

    // Chrome
    let chrome_dir = temp1.path().join("Default");
    std::fs::create_dir_all(&chrome_dir).unwrap();
    create_test_login_db(&chrome_dir.join("Login Data"), &shared_entries, key).unwrap();

    let chrome_config = ChromiumConfig {
        browser: BrowserKind::Chrome,
        name: "Chrome",
        macos_subpath: "",
        linux_subpath: "",
        windows_subpath: "",
        keychain_service: "",
    };
    let chrome = ChromiumAdapter::with_test_overrides(
        chrome_config,
        temp1.path().to_path_buf(),
        key.to_string(),
    );

    // Brave (same credential)
    let brave_dir = temp2.path().join("Default");
    std::fs::create_dir_all(&brave_dir).unwrap();
    create_test_login_db(
        &brave_dir.join("Login Data"),
        &[TestLoginEntry {
            url: "https://github.com/login".to_string(),
            username: "developer".to_string(),
            password: "password-from-brave".to_string(),
            date_created: None,
            date_last_used: None,
            date_modified: None,
        }],
        key,
    )
    .unwrap();

    let brave_config = ChromiumConfig {
        browser: BrowserKind::Brave,
        name: "Brave",
        macos_subpath: "",
        linux_subpath: "",
        windows_subpath: "",
        keychain_service: "",
    };
    let brave = ChromiumAdapter::with_test_overrides(
        brave_config,
        temp2.path().to_path_buf(),
        key.to_string(),
    );

    let adapters: Vec<Box<dyn SourceAdapter>> = vec![Box::new(chrome), Box::new(brave)];
    let index =
        credvault_core::index::list_with_adapters(&adapters, None, None).unwrap();

    // Should find both entries
    assert_eq!(index.entries.len(), 2);

    // Should detect them as duplicates (same domain + username)
    assert_eq!(index.duplicates.len(), 1);
    assert_eq!(index.duplicates[0].domain, "github.com");
    assert_eq!(
        index.duplicates[0].username.as_deref(),
        Some("developer")
    );
    assert_eq!(index.duplicates[0].entry_ids.len(), 2);
}

#[test]
fn test_bundle_file_write_and_read() {
    let (_temp, adapter) = setup_mock_chrome(&dev_credentials());
    let sources = adapter.detect().unwrap();
    let profile = &sources[0].source.profiles[0];
    let credentials = adapter.extract_credentials(profile, &[]).unwrap();

    let password = SecretString::from("file-test-password");
    let options = BundleOptions {
        format: BundleFormat::CredVault,
        password: password.clone(),
        label: "File Test Bundle".to_string(),
        expires: None,
        include_metadata: true,
    };

    let bundle_data = create_bundle(&credentials, &options).unwrap();

    // Write to a temp file
    let output_dir = TempDir::new().unwrap();
    let bundle_path = output_dir.path().join("test.credvault");
    std::fs::write(&bundle_path, &bundle_data).unwrap();

    // Read it back from the file
    let read_data = std::fs::read(&bundle_path).unwrap();
    let contents = read_bundle(&read_data, &password).unwrap();

    assert_eq!(contents.label, "File Test Bundle");
    assert_eq!(contents.credentials.len(), 6);
}
