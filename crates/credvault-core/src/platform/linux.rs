//! Linux-specific platform support.

/// On Linux, Chrome uses gnome-keyring/kwallet via libsecret,
/// or falls back to a hardcoded key "peanuts".
pub fn get_chromium_encryption_key(_service_name: &str) -> Option<String> {
    // Try libsecret / gnome-keyring via secret-tool
    if let Ok(output) = std::process::Command::new("secret-tool")
        .args(["lookup", "application", "chrome"])
        .output()
    {
        if output.status.success() {
            let key = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !key.is_empty() {
                return Some(key);
            }
        }
    }

    // Fallback: hardcoded key used when no keyring is available
    Some("peanuts".to_string())
}
