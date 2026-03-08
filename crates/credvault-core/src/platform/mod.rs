//! Platform-specific abstractions for credential store access.

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

use std::path::PathBuf;

/// Expand ~ to the user's home directory.
pub fn expand_home(path: &str) -> Option<PathBuf> {
    if path.starts_with("~/") || path == "~" {
        let home = home_dir()?;
        Some(home.join(&path[2..]))
    } else {
        Some(PathBuf::from(path))
    }
}

/// Get the user's home directory.
pub fn home_dir() -> Option<PathBuf> {
    // Try HOME env var first (works on all Unix-likes)
    std::env::var_os("HOME").map(PathBuf::from).or_else(|| {
        // Fallback for Windows
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    })
}

/// Get the platform-specific Chromium data directory base.
pub fn chromium_base_dir(browser_subpath: &str) -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        expand_home(&format!("~/Library/Application Support/{browser_subpath}"))
    }

    #[cfg(target_os = "linux")]
    {
        expand_home(&format!("~/.config/{browser_subpath}"))
    }

    #[cfg(target_os = "windows")]
    {
        std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join(browser_subpath))
    }
}

/// Get the Firefox profiles directory.
pub fn firefox_base_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        expand_home("~/Library/Application Support/Firefox")
    }

    #[cfg(target_os = "linux")]
    {
        expand_home("~/.mozilla/firefox")
    }

    #[cfg(target_os = "windows")]
    {
        std::env::var_os("APPDATA").map(|d| PathBuf::from(d).join("Mozilla").join("Firefox"))
    }
}
