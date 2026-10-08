use aes::Aes128;
use alloc::vec::Vec;
use cbc::cipher::{BlockModeEncrypt, KeyIvInit, block_padding};

use des::Des;
use sha2::Digest;
use hmac::{Hmac, KeyInit, Mac};
use md5::Md5;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

type DesCbcEnc = cbc::Encryptor<Des>;
type Aes128CfbEnc = cfb_mode::Encryptor<Aes128>;
type HmacMd5 = Hmac<Md5>;
type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

/// Generates the localized key using MD5
pub fn password_to_key_md5(password: &[u8], engine_id: &[u8]) -> Vec<u8> {
    let mut hasher = Md5::new();
    let mut buf = [0u8; 64];
    let mut cp = 0;
    let mut password_index = 0;
    while cp < 1048576 {
        for i in 0..64 {
            buf[i] = password[password_index % password.len()];
            password_index += 1;
        }
        hasher.update(&buf);
        cp += 64;
    }
    let key = hasher.finalize();

    let mut hasher2 = Md5::new();
    hasher2.update(&key);
    hasher2.update(engine_id);
    hasher2.update(&key);
    hasher2.finalize().to_vec()
}

/// Generates the localized key using SHA1
pub fn password_to_key_sha1(password: &[u8], engine_id: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    let mut buf = [0u8; 64];
    let mut cp = 0;
    let mut password_index = 0;
    while cp < 1048576 {
        for i in 0..64 {
            buf[i] = password[password_index % password.len()];
            password_index += 1;
        }
        hasher.update(&buf);
        cp += 64;
    }
    let key = hasher.finalize();

    let mut hasher2 = Sha1::new();
    hasher2.update(&key);
    hasher2.update(engine_id);
    hasher2.update(&key);
    hasher2.finalize().to_vec()
}

fn password_to_key_generic<D: Digest + Default>(password: &[u8], engine_id: &[u8]) -> Vec<u8> {
    let mut hasher = D::default();
    let mut buf = [0u8; 64];
    let mut cp = 0;
    let mut password_index = 0;
    while cp < 1048576 {
        for i in 0..64 {
            buf[i] = password[password_index % password.len()];
            password_index += 1;
        }
        hasher.update(&buf);
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

/// Signs data using HMAC-MD5-96
pub fn sign_md5(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacMd5::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize()
        .into_bytes()
        .iter()
        .take(12)
        .copied()
        .collect()
}

/// Signs data using HMAC-SHA-96
pub fn sign_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha1::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize()
        .into_bytes()
        .iter()
        .take(12)
        .copied()
        .collect()
}

/// Signs data using HMAC-SHA-256 (192 bits)
pub fn sign_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize()
        .into_bytes()
        .iter()
        .take(24)
        .copied()
        .collect()
}

/// Signs data using HMAC-SHA-384 (256 bits)
pub fn sign_sha384(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha384::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize()
        .into_bytes()
        .iter()
        .take(32)
        .copied()
        .collect()
}

/// Signs data using HMAC-SHA-512 (384 bits)
pub fn sign_sha512(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha512::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize()
        .into_bytes()
        .iter()
        .take(48)
        .copied()
        .collect()
}

/// Encrypts data using DES-CBC
pub fn encrypt_des(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    let encryptor = DesCbcEnc::new_from_slices(key, iv).unwrap();
    let mut buf = vec![0u8; data.len() + 8];
    buf[..data.len()].copy_from_slice(data);
    let res = encryptor
        .encrypt_padded::<block_padding::Pkcs7>(&mut buf, data.len())
        .unwrap();
    res.to_vec()
}

/// Encrypts data using AES-128-CFB
pub fn encrypt_aes128(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    let encryptor = Aes128CfbEnc::new_from_slices(key, iv).unwrap();
    let mut out = data.to_vec();
    encryptor.encrypt(&mut out);
    out
}
