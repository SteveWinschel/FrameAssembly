//! Cryptographic primitives for the SNMPv3 User-Based Security Model (USM, RFC 3414 / RFC 3826 / RFC 7860).
//!
//! This module implements the RFC 3414 and RFC 7860 1-megabyte password-to-key stretching and
//! authoritative `snmpEngineID` key-localization algorithms across MD5, SHA-1, SHA-256, SHA-384,
//! and SHA-512, alongside truncated HMAC message authentication code calculation (`96`, `128`,
//! `192`, and `256` bits), RFC 3414 CBC-DES ScopedPDU encryption with zero-padded block alignment,
//! and RFC 3826 CFB128-AES-128 encryption using the 128-bit engine boots/time/salt IV.

use aes::Aes128;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use cbc::cipher::{BlockModeEncrypt, KeyIvInit, block_padding};

use des::Des;
use hmac::{Hmac, KeyInit, Mac};
use md5::Md5;
use sha1::Sha1;
use sha2::Digest;
use sha2::{Sha256, Sha384, Sha512};

/// Type alias for DES-CBC encryptor.
type DesCbcEnc = cbc::Encryptor<Des>;
/// Type alias for AES-128-CFB encryptor.
type Aes128CfbEnc = cfb_mode::Encryptor<Aes128>;
/// Type alias for HMAC-MD5.
type HmacMd5 = Hmac<Md5>;
/// Type alias for HMAC-SHA1.
type HmacSha1 = Hmac<Sha1>;
/// Type alias for HMAC-SHA256.
type HmacSha256 = Hmac<Sha256>;
/// Type alias for HMAC-SHA384.
type HmacSha384 = Hmac<Sha384>;
/// Type alias for HMAC-SHA512.
type HmacSha512 = Hmac<Sha512>;

/// Generates the localized key using MD5.
pub fn password_to_key_md5(password: &[u8], engine_id: &[u8]) -> Vec<u8> {
    password_to_key_generic::<Md5>(password, engine_id)
}

/// Generates the localized key using SHA1.
pub fn password_to_key_sha1(password: &[u8], engine_id: &[u8]) -> Vec<u8> {
    password_to_key_generic::<Sha1>(password, engine_id)
}

/// Derives a localized key using a generic Digest.
fn password_to_key_generic<D: Digest + Default>(password: &[u8], engine_id: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let mut hasher = D::default();
    let mut buf = [0u8; 64];
    let mut cp = 0;
    let mut password_index = 0;
    while cp < 1048576 {
        for slot in &mut buf {
            *slot = password[password_index % password.len()];
            password_index += 1;
        }
        hasher.update(buf);
        cp += 64;
    }
    let key = hasher.finalize();

    let mut hasher2 = D::default();
    hasher2.update(&key);
    hasher2.update(engine_id);
    hasher2.update(&key);
    hasher2.finalize().to_vec()
}

/// Generates the localized key using SHA-256
pub fn password_to_key_sha256(password: &[u8], engine_id: &[u8]) -> Vec<u8> {
    password_to_key_generic::<Sha256>(password, engine_id)
}

/// Generates the localized key using SHA-384
pub fn password_to_key_sha384(password: &[u8], engine_id: &[u8]) -> Vec<u8> {
    password_to_key_generic::<Sha384>(password, engine_id)
}

/// Generates the localized key using SHA-512
pub fn password_to_key_sha512(password: &[u8], engine_id: &[u8]) -> Vec<u8> {
    password_to_key_generic::<Sha512>(password, engine_id)
}

/// Computes a truncated HMAC authentication tag with explicit non-empty key validation.
fn sign_hmac_truncated<M: Mac + KeyInit>(
    key: &[u8],
    data: &[u8],
    trunc_len: usize,
    alg_name: &str,
) -> Result<Vec<u8>, String> {
    if key.is_empty() {
        return Err(alloc::format!("{alg_name} authentication key cannot be empty"));
    }
    let mut mac = M::new_from_slice(key)
        .map_err(|_| alloc::format!("Invalid {alg_name} authentication key length: {}", key.len()))?;
    mac.update(data);
    Ok(mac
        .finalize()
        .into_bytes()
        .iter()
        .take(trunc_len)
        .copied()
        .collect())
}

/// Signs data using HMAC-MD5-96 (RFC 3414).
pub fn sign_md5(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    sign_hmac_truncated::<HmacMd5>(key, data, 12, "HMAC-MD5")
}

/// Signs data using HMAC-SHA-96 (RFC 3414).
pub fn sign_sha1(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    sign_hmac_truncated::<HmacSha1>(key, data, 12, "HMAC-SHA-1")
}

/// Signs data using HMAC-SHA-256-192 (RFC 7860).
pub fn sign_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    sign_hmac_truncated::<HmacSha256>(key, data, 24, "HMAC-SHA-256")
}

/// Signs data using HMAC-SHA-384-256 (RFC 7860).
pub fn sign_sha384(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    sign_hmac_truncated::<HmacSha384>(key, data, 32, "HMAC-SHA-384")
}

/// Signs data using HMAC-SHA-512-384 (RFC 7860).
pub fn sign_sha512(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    sign_hmac_truncated::<HmacSha512>(key, data, 48, "HMAC-SHA-512")
}

/// Encrypts data using DES-CBC according to RFC 3414 Section 8.1.1.2.
///
/// Plaintext `data` is padded with zeros at the end only if its length is
/// not an integral multiple of 8 octets. If `data.len()` is already an
/// integral multiple of 8, no padding is added.
pub fn encrypt_des(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let encryptor = DesCbcEnc::new_from_slices(key, iv).map_err(|_| {
        alloc::format!(
            "Invalid DES-CBC key/IV length (expected 8-byte key and 8-byte IV, got {} and {})",
            key.len(),
            iv.len()
        )
    })?;
    let pad_len = if data.len().is_multiple_of(8) {
        0
    } else {
        8 - (data.len() % 8)
    };
    let mut buf = vec![0u8; data.len() + pad_len];
    buf[..data.len()].copy_from_slice(data);
    let res = encryptor
        .encrypt_padded::<block_padding::ZeroPadding>(&mut buf, data.len())
        .map_err(|_| "DES-CBC padding buffer error".to_string())?;
    Ok(res.to_vec())
}

/// Encrypts data using AES-128-CFB according to RFC 3826.
pub fn encrypt_aes128(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let encryptor = Aes128CfbEnc::new_from_slices(key, iv).map_err(|_| {
        alloc::format!(
            "Invalid AES-128-CFB key/IV length (expected 16-byte key and 16-byte IV, got {} and {})",
            key.len(),
            iv.len()
        )
    })?;
    let mut out = data.to_vec();
    encryptor.encrypt(&mut out);
    Ok(out)
}
