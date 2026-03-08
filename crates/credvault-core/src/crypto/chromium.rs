//! Chromium password decryption.
//!
//! Chromium stores passwords encrypted differently on each platform:
//! - macOS: AES-128-CBC with key derived via PBKDF2 from a Keychain-stored password
//! - Linux: Same as macOS but key comes from gnome-keyring or hardcoded "peanuts"
//! - Windows: DPAPI + AES-256-GCM (v80+)

use crate::{Error, Result};

/// Decrypt a Chromium password blob on macOS/Linux.
///
/// The encrypted blob format (v10):
/// - 3 bytes: version prefix "v10" (macOS) or "v11" (Linux)
/// - Remaining bytes: AES-128-CBC ciphertext (IV = 16 bytes of 0x20)
///
/// Key derivation:
/// - PBKDF2-SHA1(password=keychain_key, salt="saltysalt", iterations=1003, keylen=16)
pub fn decrypt_chromium_password(encrypted: &[u8], raw_key: &str) -> Result<String> {
    if encrypted.is_empty() {
        return Ok(String::new());
    }

    // Check for v10/v11 prefix (macOS/Linux)
    if encrypted.len() < 4 {
        return Err(Error::Decryption("Encrypted blob too short".to_string()));
    }

    let version_prefix = &encrypted[..3];
    if version_prefix != b"v10" && version_prefix != b"v11" {
        // May be unencrypted or Windows format
        return Err(Error::Decryption(format!(
            "Unknown encryption version prefix: {:?}",
            version_prefix
        )));
    }

    let ciphertext = &encrypted[3..];

    // Derive the AES key using PBKDF2-SHA1
    let mut derived_key = [0u8; 16];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(raw_key.as_bytes(), b"saltysalt", 1003, &mut derived_key);

    // Decrypt AES-128-CBC with IV = 16 bytes of 0x20
    let iv = [0x20u8; 16];
    decrypt_aes_cbc(&derived_key, &iv, ciphertext)
}

/// AES-128-CBC decryption with PKCS7 unpadding.
fn decrypt_aes_cbc(key: &[u8; 16], iv: &[u8; 16], ciphertext: &[u8]) -> Result<String> {
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

    let decryptor = Aes128CbcDec::new(key.into(), iv.into());

    let mut buf = ciphertext.to_vec();
    let plaintext = decryptor
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| Error::Decryption(format!("AES-CBC decryption failed: {e}")))?;

    String::from_utf8(plaintext.to_vec())
        .map_err(|e| Error::Decryption(format!("Decrypted password is not valid UTF-8: {e}")))
}

/// Create a test-encrypted password blob (for testing purposes).
/// Encrypts using the same algorithm Chrome uses on macOS/Linux.
pub fn encrypt_chromium_password(plaintext: &str, raw_key: &str) -> Vec<u8> {
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

    // Derive key
    let mut derived_key = [0u8; 16];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(raw_key.as_bytes(), b"saltysalt", 1003, &mut derived_key);

    let iv = [0x20u8; 16];
    let encryptor = Aes128CbcEnc::new(&derived_key.into(), &iv.into());

    let mut buf = vec![0u8; plaintext.len() + 16]; // room for padding
    buf[..plaintext.len()].copy_from_slice(plaintext.as_bytes());

    let ciphertext = encryptor
        .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
        .expect("encryption buffer too small");

    let mut result = Vec::with_capacity(3 + ciphertext.len());
    result.extend_from_slice(b"v10");
    result.extend_from_slice(ciphertext);
    result
}

/// Decrypt a Chromium password blob on Windows (v80+).
///
/// Format: "v10" (3 bytes) + nonce (12 bytes) + AES-256-GCM ciphertext+tag
///
/// The `raw_key_b64` is a base64-encoded 32-byte AES key (from DPAPI decryption).
pub fn decrypt_chromium_password_windows(encrypted: &[u8], raw_key_b64: &str) -> Result<String> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    use base64::Engine;

    if encrypted.is_empty() {
        return Ok(String::new());
    }

    // v10 prefix (3) + nonce (12) + at least 1 byte ciphertext + tag (16)
    if encrypted.len() < 3 + 12 + 16 {
        return Err(Error::Decryption(
            "Windows encrypted blob too short".to_string(),
        ));
    }

    let prefix = &encrypted[..3];
    if prefix != b"v10" {
        return Err(Error::Decryption(format!(
            "Expected v10 prefix, got: {:?}",
            prefix
        )));
    }

    let raw_key = base64::engine::general_purpose::STANDARD
        .decode(raw_key_b64)
        .map_err(|e| Error::Decryption(format!("Invalid base64 key: {e}")))?;

    if raw_key.len() != 32 {
        return Err(Error::Decryption(format!(
            "Expected 32-byte AES key, got {} bytes",
            raw_key.len()
        )));
    }

    let nonce_bytes = &encrypted[3..15];
    let ciphertext_with_tag = &encrypted[15..];

    let cipher = Aes256Gcm::new_from_slice(&raw_key)
        .map_err(|e| Error::Decryption(format!("AES-256-GCM key init failed: {e}")))?;

    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext_with_tag)
        .map_err(|e| Error::Decryption(format!("AES-256-GCM decryption failed: {e}")))?;

    String::from_utf8(plaintext)
        .map_err(|e| Error::Decryption(format!("Decrypted password is not valid UTF-8: {e}")))
}

/// Create a test-encrypted password blob in Windows format (AES-256-GCM).
pub fn encrypt_chromium_password_windows(plaintext: &str, raw_key_b64: &str) -> Vec<u8> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    use base64::Engine;

    let raw_key = base64::engine::general_purpose::STANDARD
        .decode(raw_key_b64)
        .expect("invalid base64 key");

    let cipher = Aes256Gcm::new_from_slice(&raw_key).expect("key init failed");

    // Use a fixed nonce for testing determinism
    let nonce_bytes = [0x01u8; 12];
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext_with_tag = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .expect("encryption failed");

    let mut result = Vec::with_capacity(3 + 12 + ciphertext_with_tag.len());
    result.extend_from_slice(b"v10");
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext_with_tag);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = "test-keychain-password";
        let password = "my-secret-password-123!";

        let encrypted = encrypt_chromium_password(password, key);
        let decrypted = decrypt_chromium_password(&encrypted, key).unwrap();

        assert_eq!(decrypted, password);
    }

    #[test]
    fn test_decrypt_empty() {
        let result = decrypt_chromium_password(&[], "key");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "");
    }

    #[test]
    fn test_decrypt_too_short() {
        let result = decrypt_chromium_password(&[1, 2], "key");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_unknown_version() {
        let result = decrypt_chromium_password(b"v99someciphertext", "key");
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_various_lengths() {
        let key = "chrome-safe-storage-key";
        let passwords = [
            "",
            "a",
            "short",
            "exactly16bytes!!",
            "this is a longer password with special chars: @#$%^&*()",
            "unicode: café résumé naïve 日本語",
        ];

        for password in &passwords {
            let encrypted = encrypt_chromium_password(password, key);
            let decrypted = decrypt_chromium_password(&encrypted, key).unwrap();
            assert_eq!(&decrypted, password, "Roundtrip failed for: {password}");
        }
    }

    #[test]
    fn test_linux_peanuts_key() {
        // Linux Chrome uses "peanuts" as the key when no keyring is available
        let key = "peanuts";
        let password = "github-token-abc123";

        let encrypted = encrypt_chromium_password(password, key);
        let decrypted = decrypt_chromium_password(&encrypted, key).unwrap();
        assert_eq!(decrypted, password);
    }

    #[test]
    fn test_windows_aes256gcm_roundtrip() {
        use base64::Engine;
        // Generate a 32-byte key and base64-encode it
        let raw_key = [0xABu8; 32];
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(raw_key);

        let password = "windows-secret-password!";
        let encrypted = encrypt_chromium_password_windows(password, &key_b64);
        let decrypted = decrypt_chromium_password_windows(&encrypted, &key_b64).unwrap();
        assert_eq!(decrypted, password);
    }

    #[test]
    fn test_windows_aes256gcm_various_lengths() {
        use base64::Engine;
        let raw_key = [0x42u8; 32];
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(raw_key);

        let passwords = ["", "a", "medium-length-pw", "unicode: café 日本語"];
        for password in &passwords {
            let encrypted = encrypt_chromium_password_windows(password, &key_b64);
            let decrypted = decrypt_chromium_password_windows(&encrypted, &key_b64).unwrap();
            assert_eq!(&decrypted, password, "Roundtrip failed for: {password}");
        }
    }

    #[test]
    fn test_windows_wrong_key_fails() {
        use base64::Engine;
        let key1 = base64::engine::general_purpose::STANDARD.encode([0xAAu8; 32]);
        let key2 = base64::engine::general_purpose::STANDARD.encode([0xBBu8; 32]);

        let encrypted = encrypt_chromium_password_windows("secret", &key1);
        let result = decrypt_chromium_password_windows(&encrypted, &key2);
        assert!(result.is_err());
    }
}
