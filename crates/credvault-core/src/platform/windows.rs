//! Windows-specific platform support.
//! Uses DPAPI to decrypt the Chromium AES-256-GCM key from Local State.

use crate::{Error, Result};
use base64::Engine;
use std::path::Path;

/// Retrieve the Chromium AES-256-GCM key from the Local State file via DPAPI.
///
/// Flow:
/// 1. Read `Local State` JSON → `os_crypt.encrypted_key`
/// 2. Base64-decode → strip 5-byte "DPAPI" prefix
/// 3. CryptUnprotectData → raw 32-byte AES key
/// 4. Return as base64-encoded string (for transport through the String interface)
pub fn get_chromium_encryption_key(local_state_path: &Path) -> Result<String> {
    let data = std::fs::read_to_string(local_state_path).map_err(|e| {
        Error::Other(format!(
            "Failed to read Local State at {}: {e}",
            local_state_path.display()
        ))
    })?;

    let json: serde_json::Value = serde_json::from_str(&data)
        .map_err(|e| Error::Other(format!("Invalid Local State JSON: {e}")))?;

    let encrypted_key_b64 = json
        .get("os_crypt")
        .and_then(|o| o.get("encrypted_key"))
        .and_then(|k| k.as_str())
        .ok_or_else(|| Error::Other("Missing os_crypt.encrypted_key in Local State".to_string()))?;

    let encrypted_key = base64::engine::general_purpose::STANDARD
        .decode(encrypted_key_b64)
        .map_err(|e| Error::Other(format!("Failed to decode encrypted_key: {e}")))?;

    // Strip "DPAPI" prefix (5 bytes)
    if encrypted_key.len() < 5 || &encrypted_key[..5] != b"DPAPI" {
        return Err(Error::Decryption(
            "Encrypted key missing DPAPI prefix".to_string(),
        ));
    }

    let dpapi_blob = &encrypted_key[5..];
    let raw_key = dpapi_decrypt(dpapi_blob)?;

    // Return as base64 so it fits the String interface
    Ok(base64::engine::general_purpose::STANDARD.encode(&raw_key))
}

/// Decrypt a DPAPI-protected blob using CryptUnprotectData.
#[cfg(target_os = "windows")]
fn dpapi_decrypt(encrypted: &[u8]) -> Result<Vec<u8>> {
    use std::ptr;
    use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};

    unsafe {
        let input = CRYPT_INTEGER_BLOB {
            cbData: encrypted.len() as u32,
            pbData: encrypted.as_ptr() as *mut u8,
        };

        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };

        CryptUnprotectData(
            &input,
            Some(ptr::null_mut()),
            None,
            None,
            None,
            0,
            &mut output,
        )
        .map_err(|e| Error::Decryption(format!("DPAPI CryptUnprotectData failed: {e}")))?;

        let decrypted = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();

        // Free the DPAPI-allocated buffer
        windows::Win32::Foundation::LocalFree(windows::Win32::Foundation::HLOCAL(
            output.pbData as _,
        ));

        Ok(decrypted)
    }
}

/// Stub for non-Windows platforms (should never be called).
#[cfg(not(target_os = "windows"))]
fn dpapi_decrypt(_encrypted: &[u8]) -> Result<Vec<u8>> {
    Err(Error::PlatformNotSupported(
        "DPAPI is only available on Windows".to_string(),
    ))
}
