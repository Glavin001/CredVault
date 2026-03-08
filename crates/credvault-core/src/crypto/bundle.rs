//! Bundle encryption and decryption using AES-256-GCM with Argon2id key derivation.
//!
//! Bundle format:
//!   [4 bytes]  Magic: "CVLT"
//!   [1 byte]   Version: 0x01
//!   [32 bytes] Salt (for Argon2id)
//!   [12 bytes] Nonce (for AES-256-GCM)
//!   [N bytes]  Ciphertext (AES-256-GCM encrypted MessagePack payload)
//!              (last 16 bytes of ciphertext are the GCM auth tag)

use crate::{Error, Result};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use secrecy::{ExposeSecret, SecretString};

const MAGIC: &[u8; 4] = b"CVLT";
const VERSION: u8 = 0x01;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = 4 + 1 + SALT_LEN + NONCE_LEN; // 49 bytes

/// Encrypt a payload into a CredVault bundle.
pub fn encrypt_bundle(plaintext: &[u8], password: &SecretString) -> Result<Vec<u8>> {
    use rand::RngCore;

    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut salt);
    rand::rng().fill_bytes(&mut nonce_bytes);

    let key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new(&key.into());
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| Error::Other(format!("Bundle encryption failed: {e}")))?;

    let mut bundle = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    bundle.extend_from_slice(MAGIC);
    bundle.push(VERSION);
    bundle.extend_from_slice(&salt);
    bundle.extend_from_slice(&nonce_bytes);
    bundle.extend_from_slice(&ciphertext);

    Ok(bundle)
}

/// Decrypt a CredVault bundle.
pub fn decrypt_bundle(data: &[u8], password: &SecretString) -> Result<Vec<u8>> {
    if data.len() < HEADER_LEN + 16 {
        // At minimum: header + 16 byte GCM tag
        return Err(Error::InvalidBundle(
            "Bundle too small to be valid".to_string(),
        ));
    }

    if &data[..4] != MAGIC {
        return Err(Error::InvalidBundle(
            "Invalid magic bytes — not a CredVault bundle".to_string(),
        ));
    }

    if data[4] != VERSION {
        return Err(Error::InvalidBundle(format!(
            "Unsupported bundle version: {}",
            data[4]
        )));
    }

    let salt = &data[5..5 + SALT_LEN];
    let nonce_bytes = &data[5 + SALT_LEN..5 + SALT_LEN + NONCE_LEN];
    let ciphertext = &data[HEADER_LEN..];

    let key = derive_key(password, salt)?;
    let cipher = Aes256Gcm::new(&key.into());
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| Error::BundleDecryptionFailed)
}

/// Derive a 256-bit key from a password using Argon2id.
fn derive_key(password: &SecretString, salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];

    // Argon2id with moderate parameters suitable for interactive use
    let params = argon2::Params::new(65536, 3, 4, Some(32))
        .map_err(|e| Error::Other(format!("Argon2 params error: {e}")))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    argon2
        .hash_password_into(password.expose_secret().as_bytes(), salt, &mut key)
        .map_err(|e| Error::Other(format!("Key derivation failed: {e}")))?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let password = SecretString::from("test-bundle-password");
        let plaintext = b"hello world, these are my credentials!";

        let encrypted = encrypt_bundle(plaintext, &password).unwrap();
        let decrypted = decrypt_bundle(&encrypted, &password).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_password() {
        let password = SecretString::from("correct-password");
        let wrong = SecretString::from("wrong-password");
        let plaintext = b"secret data";

        let encrypted = encrypt_bundle(plaintext, &password).unwrap();
        let result = decrypt_bundle(&encrypted, &wrong);

        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_magic() {
        let result = decrypt_bundle(b"NOTCVLTxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", &SecretString::from("pw"));
        assert!(matches!(result, Err(Error::InvalidBundle(_))));
    }

    #[test]
    fn test_bundle_too_small() {
        let result = decrypt_bundle(b"CVLT", &SecretString::from("pw"));
        assert!(matches!(result, Err(Error::InvalidBundle(_))));
    }

    #[test]
    fn test_large_payload() {
        let password = SecretString::from("password123");
        let plaintext = vec![42u8; 100_000]; // 100KB

        let encrypted = encrypt_bundle(&plaintext, &password).unwrap();
        let decrypted = decrypt_bundle(&encrypted, &password).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_header_structure() {
        let password = SecretString::from("pw");
        let encrypted = encrypt_bundle(b"test", &password).unwrap();

        assert_eq!(&encrypted[..4], b"CVLT");
        assert_eq!(encrypted[4], 0x01);
        assert!(encrypted.len() > HEADER_LEN + 16); // at least header + tag
    }
}
