//! Firefox NSS credential decryption.
//!
//! Firefox encrypts passwords using NSS (Network Security Services):
//! - Master key stored in `key4.db` (SQLite), protected by PBES2 or legacy PBE
//! - Credentials in `logins.json`, encrypted with 3DES-CBC using the master key
//!
//! Supports:
//! - Modern Firefox (58+): PBES2 with PBKDF2-HMAC-SHA256 + AES-256-CBC
//! - Legacy Firefox: PBE with SHA1 + 3DES-CBC
//! - No master password (most common case)

use crate::{Error, Result};
use std::path::Path;

// Well-known ASN.1 OIDs
const OID_PBES2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d];
#[allow(dead_code)]
const OID_PBKDF2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c];
#[allow(dead_code)]
const OID_AES256_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a];
const OID_SHA1_3DES: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x05, 0x01, 0x03,
];
#[allow(dead_code)]
const OID_HMAC_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09];

/// Extract the master decryption key from Firefox's key4.db.
///
/// Tries empty master password first (most common), fails if a master password is set.
pub fn extract_master_key(key4_path: &Path, global_salt: &[u8]) -> Result<Vec<u8>> {
    let conn = rusqlite::Connection::open(key4_path)?;

    // Read the encrypted master key from nssPrivate table
    let a11: Vec<u8> = conn
        .query_row(
            "SELECT a11 FROM nssPrivate WHERE a11 IS NOT NULL LIMIT 1",
            [],
            |row| row.get(0),
        )
        .map_err(|e| Error::Other(format!("No master key in key4.db: {e}")))?;

    // Try with empty master password
    let master_password = b"";
    decrypt_nss_entry(global_salt, master_password, &a11)
        .map_err(|_| Error::AuthRequired(
            "Firefox".to_string(),
            "Master password is set — CredVault only supports Firefox profiles without a master password".to_string(),
        ))
}

/// Read global salt and verify the password check from key4.db metaData.
pub fn read_key4_metadata(key4_path: &Path) -> Result<Vec<u8>> {
    let conn = rusqlite::Connection::open(key4_path)?;

    let (item1, item2): (Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT item1, item2 FROM metaData WHERE id = 'password'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|e| Error::Other(format!("Cannot read key4.db metaData: {e}")))?;

    // item1 = global_salt, item2 = encrypted password check
    // Verify empty password works by decrypting item2
    let check = decrypt_nss_entry(&item1, b"", &item2).map_err(|_| {
        Error::AuthRequired(
            "Firefox".to_string(),
            "Master password required".to_string(),
        )
    })?;

    // Check value should be "password-check\x02\x02"
    if !check.starts_with(b"password-check") {
        return Err(Error::Decryption(
            "Password check failed — master password may be set".to_string(),
        ));
    }

    Ok(item1) // return global_salt
}

/// Decrypt a single Firefox login field (encryptedUsername or encryptedPassword).
///
/// The field is base64-encoded ASN.1:
/// ```text
/// SEQUENCE {
///   SEQUENCE {
///     OID (key identifier)
///     SEQUENCE { OCTET STRING (IV) }
///   }
///   OCTET STRING (encrypted data)
/// }
/// ```
/// Decrypted with 3DES-CBC using the master key.
pub fn decrypt_login_field(master_key: &[u8], base64_field: &str) -> Result<String> {
    use base64::Engine;

    let data = base64::engine::general_purpose::STANDARD
        .decode(base64_field)
        .map_err(|e| Error::Decryption(format!("Invalid base64 in login field: {e}")))?;

    let parsed = parse_der(&data)?;

    // Extract IV and encrypted data from ASN.1
    let outer_seq = expect_sequence(&parsed)?;
    if outer_seq.len() < 2 {
        return Err(Error::Decryption("Login field ASN.1 too short".to_string()));
    }

    let algo_seq = expect_sequence(&outer_seq[0])?;
    if algo_seq.len() < 2 {
        return Err(Error::Decryption(
            "Login field algo sequence too short".to_string(),
        ));
    }

    let iv_seq = expect_sequence(&algo_seq[1])?;
    if iv_seq.is_empty() {
        return Err(Error::Decryption("Missing IV in login field".to_string()));
    }
    let iv = expect_octet_string(&iv_seq[0])?;

    let encrypted = expect_octet_string(&outer_seq[1])?;

    // Decrypt with 3DES-CBC
    let plaintext = decrypt_3des_cbc(master_key, iv, encrypted)?;

    // Remove PKCS#7 padding and trailing nulls
    let unpadded = remove_pkcs7_padding(&plaintext)?;

    String::from_utf8(unpadded.to_vec())
        .map_err(|e| Error::Decryption(format!("Decrypted value is not valid UTF-8: {e}")))
}

/// Decrypt an NSS-encrypted entry (from key4.db or metaData).
/// Supports both PBES2 (modern) and PBE-SHA1-3DES (legacy).
fn decrypt_nss_entry(
    global_salt: &[u8],
    master_password: &[u8],
    encoded: &[u8],
) -> Result<Vec<u8>> {
    let parsed = parse_der(encoded)?;
    let outer = expect_sequence(&parsed)?;
    if outer.len() < 2 {
        return Err(Error::Decryption("NSS entry too short".to_string()));
    }

    let algo_seq = expect_sequence(&outer[0])?;
    if algo_seq.is_empty() {
        return Err(Error::Decryption("Missing algorithm OID".to_string()));
    }

    let oid = expect_oid(&algo_seq[0])?;
    let encrypted = expect_octet_string(&outer[1])?;

    if oid == OID_PBES2 {
        decrypt_pbes2(global_salt, master_password, algo_seq, encrypted)
    } else if oid == OID_SHA1_3DES {
        decrypt_pbe_sha1_3des(global_salt, master_password, algo_seq, encrypted)
    } else {
        Err(Error::Decryption(format!(
            "Unknown NSS encryption algorithm OID: {oid:02x?}"
        )))
    }
}

/// Modern Firefox: PBES2 with PBKDF2-HMAC-SHA256 + AES-256-CBC.
fn decrypt_pbes2(
    global_salt: &[u8],
    master_password: &[u8],
    algo_seq: &[DerValue],
    encrypted: &[u8],
) -> Result<Vec<u8>> {
    // algo_seq[1] = SEQUENCE { SEQUENCE { PBKDF2 params }, SEQUENCE { AES params } }
    if algo_seq.len() < 2 {
        return Err(Error::Decryption(
            "PBES2 algo sequence too short".to_string(),
        ));
    }

    let params = expect_sequence(&algo_seq[1])?;
    if params.len() < 2 {
        return Err(Error::Decryption("PBES2 params too short".to_string()));
    }

    // PBKDF2 parameters
    let kdf_seq = expect_sequence(&params[0])?;
    if kdf_seq.len() < 2 {
        return Err(Error::Decryption("PBKDF2 sequence too short".to_string()));
    }
    let kdf_params = expect_sequence(&kdf_seq[1])?;
    if kdf_params.len() < 2 {
        return Err(Error::Decryption("PBKDF2 params too short".to_string()));
    }

    let entry_salt = expect_octet_string(&kdf_params[0])?;
    let iterations = expect_integer(&kdf_params[1])?;

    let key_length = if kdf_params.len() > 2 {
        expect_integer(&kdf_params[2])? as usize
    } else {
        32 // default AES-256
    };

    // AES-256-CBC parameters
    let aes_seq = expect_sequence(&params[1])?;
    if aes_seq.len() < 2 {
        return Err(Error::Decryption("AES params too short".to_string()));
    }
    let iv = expect_octet_string(&aes_seq[1])?;

    // Key derivation: SHA1(global_salt + master_password) → PBKDF2-HMAC-SHA256
    let mut hp = sha1::Sha1::new();
    use sha1::Digest;
    hp.update(global_salt);
    hp.update(master_password);
    let hp_result = hp.finalize();

    let mut derived_key = vec![0u8; key_length];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
        &hp_result,
        entry_salt,
        iterations as u32,
        &mut derived_key,
    );

    // AES-256-CBC decrypt
    decrypt_aes256_cbc(&derived_key, iv, encrypted)
}

/// Legacy Firefox: PBE with SHA1 + 3DES-CBC.
fn decrypt_pbe_sha1_3des(
    global_salt: &[u8],
    master_password: &[u8],
    algo_seq: &[DerValue],
    encrypted: &[u8],
) -> Result<Vec<u8>> {
    if algo_seq.len() < 2 {
        return Err(Error::Decryption("PBE sequence too short".to_string()));
    }

    let params = expect_sequence(&algo_seq[1])?;
    if params.len() < 2 {
        return Err(Error::Decryption("PBE params too short".to_string()));
    }

    let entry_salt = expect_octet_string(&params[0])?;

    // NSS PBE key derivation (matches Mozilla's implementation):
    // hp = SHA1(global_salt + master_password)
    // pes = SHA1(hp + entry_salt)
    // chp = SHA1(pes + entry_salt)
    // k1 = pes, k2 = chp
    // key = k1[0..24] (first 20 bytes of pes + first 4 bytes of chp)
    // iv = chp[len-8..] (last 8 bytes)

    use sha1::Digest;

    let hp = sha1::Sha1::digest([global_salt, master_password].concat());
    let pes = sha1::Sha1::digest([hp.as_slice(), entry_salt].concat());
    let chp = sha1::Sha1::digest([&pes[..], entry_salt].concat());

    // Build 3DES key (24 bytes) and IV (8 bytes)
    let mut key = Vec::with_capacity(24);
    key.extend_from_slice(&pes);
    key.extend_from_slice(&chp[..4]);

    let iv = &chp[12..]; // last 8 bytes

    decrypt_3des_cbc(&key, iv, encrypted)
}

/// 3DES-CBC decryption.
fn decrypt_3des_cbc(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
    type TdesEde3CbcDec = cbc::Decryptor<des::TdesEde3>;

    if key.len() != 24 {
        return Err(Error::Decryption(format!(
            "3DES key must be 24 bytes, got {}",
            key.len()
        )));
    }

    if iv.len() != 8 {
        return Err(Error::Decryption(format!(
            "3DES IV must be 8 bytes, got {}",
            iv.len()
        )));
    }

    let decryptor = TdesEde3CbcDec::new_from_slices(key, iv)
        .map_err(|e| Error::Decryption(format!("3DES init failed: {e}")))?;

    let mut buf = ciphertext.to_vec();
    let plaintext = decryptor
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|e| Error::Decryption(format!("3DES-CBC decryption failed: {e}")))?;

    Ok(plaintext.to_vec())
}

/// AES-256-CBC decryption.
fn decrypt_aes256_cbc(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

    let decryptor = Aes256CbcDec::new_from_slices(key, iv)
        .map_err(|e| Error::Decryption(format!("AES-256-CBC init failed: {e}")))?;

    let mut buf = ciphertext.to_vec();
    let plaintext = decryptor
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|e| Error::Decryption(format!("AES-256-CBC decryption failed: {e}")))?;

    Ok(plaintext.to_vec())
}

/// Remove PKCS#7 padding from decrypted plaintext.
fn remove_pkcs7_padding(data: &[u8]) -> Result<&[u8]> {
    if data.is_empty() {
        return Ok(data);
    }

    let pad_len = *data.last().unwrap() as usize;
    if pad_len == 0 || pad_len > data.len() || pad_len > 16 {
        // No valid padding — strip trailing nulls instead
        let end = data.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        return Ok(&data[..end]);
    }

    // Verify all padding bytes match
    if data[data.len() - pad_len..]
        .iter()
        .all(|&b| b == pad_len as u8)
    {
        Ok(&data[..data.len() - pad_len])
    } else {
        // Invalid padding — strip trailing nulls
        let end = data.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        Ok(&data[..end])
    }
}

// ============================================================
// Minimal ASN.1 DER parser
// ============================================================

#[derive(Debug, Clone)]
enum DerValue {
    Sequence(Vec<DerValue>),
    OctetString(Vec<u8>),
    Oid(Vec<u8>),
    Integer(i64),
    #[allow(dead_code)]
    Other(u8, Vec<u8>),
}

fn parse_der(data: &[u8]) -> Result<DerValue> {
    let (val, _) = parse_der_inner(data)?;
    Ok(val)
}

fn parse_der_inner(data: &[u8]) -> Result<(DerValue, usize)> {
    if data.is_empty() {
        return Err(Error::Decryption("Empty DER data".to_string()));
    }

    let tag = data[0];
    let (length, header_len) = parse_der_length(&data[1..])?;
    let total_len = 1 + header_len + length;

    if data.len() < total_len {
        return Err(Error::Decryption("DER data truncated".to_string()));
    }

    let content = &data[1 + header_len..total_len];

    let value = match tag {
        0x30 | 0x31 => {
            // SEQUENCE or SET
            let mut items = Vec::new();
            let mut offset = 0;
            while offset < content.len() {
                let (item, consumed) = parse_der_inner(&content[offset..])?;
                items.push(item);
                offset += consumed;
            }
            DerValue::Sequence(items)
        }
        0x04 => DerValue::OctetString(content.to_vec()),
        0x06 => DerValue::Oid(content.to_vec()),
        0x02 => {
            let mut val: i64 = 0;
            for &b in content {
                val = (val << 8) | b as i64;
            }
            DerValue::Integer(val)
        }
        _ => DerValue::Other(tag, content.to_vec()),
    };

    Ok((value, total_len))
}

fn parse_der_length(data: &[u8]) -> Result<(usize, usize)> {
    if data.is_empty() {
        return Err(Error::Decryption("Missing DER length".to_string()));
    }

    let first = data[0];
    if first < 0x80 {
        Ok((first as usize, 1))
    } else {
        let num_bytes = (first & 0x7f) as usize;
        if num_bytes == 0 || num_bytes > 4 || data.len() < 1 + num_bytes {
            return Err(Error::Decryption("Invalid DER length encoding".to_string()));
        }
        let mut length: usize = 0;
        for &b in &data[1..1 + num_bytes] {
            length = (length << 8) | b as usize;
        }
        Ok((length, 1 + num_bytes))
    }
}

fn expect_sequence(val: &DerValue) -> Result<&Vec<DerValue>> {
    match val {
        DerValue::Sequence(items) => Ok(items),
        _ => Err(Error::Decryption("Expected SEQUENCE".to_string())),
    }
}

fn expect_octet_string(val: &DerValue) -> Result<&[u8]> {
    match val {
        DerValue::OctetString(data) => Ok(data),
        _ => Err(Error::Decryption("Expected OCTET STRING".to_string())),
    }
}

fn expect_oid(val: &DerValue) -> Result<&[u8]> {
    match val {
        DerValue::Oid(data) => Ok(data),
        _ => Err(Error::Decryption("Expected OID".to_string())),
    }
}

fn expect_integer(val: &DerValue) -> Result<i64> {
    match val {
        DerValue::Integer(n) => Ok(*n),
        _ => Err(Error::Decryption("Expected INTEGER".to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remove_pkcs7_padding() {
        // Standard PKCS7 padding
        let data = b"hello\x03\x03\x03";
        assert_eq!(remove_pkcs7_padding(data).unwrap(), b"hello");

        // No padding (trailing nulls)
        let data = b"hello\x00\x00\x00";
        assert_eq!(remove_pkcs7_padding(data).unwrap(), b"hello");

        // Full block of padding
        let data = [8u8; 8];
        assert_eq!(remove_pkcs7_padding(&data).unwrap(), b"");

        // Empty
        assert_eq!(remove_pkcs7_padding(b"").unwrap(), b"");
    }

    #[test]
    fn test_parse_der_sequence() {
        // Simple SEQUENCE { INTEGER 42 }
        let data = [0x30, 0x03, 0x02, 0x01, 0x2a];
        let parsed = parse_der(&data).unwrap();
        let seq = expect_sequence(&parsed).unwrap();
        assert_eq!(seq.len(), 1);
        assert_eq!(expect_integer(&seq[0]).unwrap(), 42);
    }

    #[test]
    fn test_parse_der_octet_string() {
        let data = [0x04, 0x03, 0x01, 0x02, 0x03];
        let parsed = parse_der(&data).unwrap();
        assert_eq!(expect_octet_string(&parsed).unwrap(), &[1, 2, 3]);
    }

    #[test]
    fn test_3des_cbc_roundtrip() {
        use aes::cipher::{block_padding::NoPadding, BlockEncryptMut, KeyIvInit};
        type TdesEde3CbcEnc = cbc::Encryptor<des::TdesEde3>;

        let key = [0x42u8; 24];
        let iv = [0x00u8; 8];
        let plaintext = b"testdata"; // exactly 8 bytes (1 block)

        let enc = TdesEde3CbcEnc::new_from_slices(&key, &iv).unwrap();
        let mut buf = plaintext.to_vec();
        let ciphertext = enc
            .encrypt_padded_mut::<NoPadding>(&mut buf, 8)
            .unwrap()
            .to_vec();

        let decrypted = decrypt_3des_cbc(&key, &iv, &ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext);
    }
}
