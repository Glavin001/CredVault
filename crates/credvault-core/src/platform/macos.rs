//! macOS-specific platform support.

use crate::{Error, Result};
use std::process::Command;

/// Retrieve the Chromium encryption key from the macOS Keychain.
/// This triggers a system authentication prompt.
pub fn get_chromium_encryption_key(service_name: &str) -> Result<String> {
    let output = Command::new("security")
        .args(["find-generic-password", "-s", service_name, "-w"])
        .output()
        .map_err(|e| Error::Other(format!("Failed to run `security` command: {e}")))?;

    if !output.status.success() {
        return Err(Error::AuthRequired(
            service_name.to_string(),
            "Keychain access denied or item not found".to_string(),
        ));
    }

    let key = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(key)
}
