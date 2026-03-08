use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use assert_cmd::Command;
use predicates::str::contains;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

#[test]
fn scan_lists_fixture_sources() {
    Command::new(assert_cmd::cargo::cargo_bin!("credvault"))
        .arg("--fixtures")
        .arg(fixture_dir())
        .arg("scan")
        .assert()
        .success()
        .stdout(contains("Chrome (Fixture Default Profile)"))
        .stdout(contains("Chrome (Fixture Work Profile)"));
}

#[test]
fn export_and_read_round_trip_bundle() {
    let unique_suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("unix time")
        .as_nanos();
    let bundle_path = std::env::temp_dir().join(format!("credvault-cli-{unique_suffix}.credvault"));

    Command::new(assert_cmd::cargo::cargo_bin!("credvault"))
        .arg("--fixtures")
        .arg(fixture_dir())
        .arg("export")
        .arg("--id")
        .arg("chrome-default-fixture:login:github-glavin")
        .arg("--format")
        .arg("credvault")
        .arg("--password")
        .arg("cli-password")
        .arg("--output")
        .arg(&bundle_path)
        .assert()
        .success()
        .stdout(contains("Exported 1 credentials"));

    Command::new(assert_cmd::cargo::cargo_bin!("credvault"))
        .arg("--fixtures")
        .arg(fixture_dir())
        .arg("read")
        .arg(&bundle_path)
        .arg("--password")
        .arg("cli-password")
        .assert()
        .success()
        .stdout(contains("Bundle:"))
        .stdout(contains("github.com"));

    let _ = std::fs::remove_file(bundle_path);
}
