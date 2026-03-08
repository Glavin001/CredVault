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
}
