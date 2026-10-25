# Production Code Templates for RustCrypto (`cipher 0.5.2`, `digest 0.11.3`, `block-padding 0.4.2`)

Every template in this reference is verified against the workspace dependencies in `Cargo.toml` (`aes = "0.9.3"`, `block-padding = "0.4.2"`, `cbc = "0.2.1"`, `cfb-mode = "0.9.1"`, `des = "0.9.0"`, `hmac = "0.13.0"`, `md-5 = "0.11.0"`, `sha1 = "0.11.0"`, `sha2 = "0.11.0"` [`0.11.1`]) and uses the exact transitive trait re-exports (`cbc::cipher`, `cbc::cipher::common`, `cfb_mode::cipher`, `hmac::Mac`, `sha2::Digest`, `sha2::digest::common`) so no direct `cipher`, `digest`, or `crypto-common` entry is required in `Cargo.toml`.

---

## 1. AES-128 & AES-256 CBC Encryption with `Pkcs7` (In-Place & Buffer-to-Buffer)

Demonstrates both in-place buffer encryption (`encrypt_padded::<Pkcs7>`, `decrypt_padded::<Pkcs7>`) and non-overlapping buffer-to-buffer transformations (`encrypt_padded_b2b::<Pkcs7>`, `decrypt_padded_b2b::<Pkcs7>`) without requiring the `alloc` feature flag on `cbc`.

```rust
use aes::{Aes128, Aes256};
use block_padding::Pkcs7;
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use std::fmt;

/// Typed errors for AES-CBC encryption and decryption operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AesCbcError {
    /// Key or IV length did not match the cipher's required sizes.
    InvalidKeyOrIvLength,
    /// Output buffer capacity was insufficient to hold the padded ciphertext.
    OutputBufferTooSmall {
        /// Number of bytes provided in the target buffer.
        provided: usize,
        /// Minimum capacity required for PKCS#7 padding (`(pt_len / 16 + 1) * 16`).
        required: usize,
    },
    /// Ciphertext length was not a multiple of 16 bytes or PKCS#7 padding was invalid.
    InvalidPaddingOrCiphertext,
}

impl fmt::Display for AesCbcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyOrIvLength => write!(f, "invalid AES key or 16-byte CBC IV length"),
            Self::OutputBufferTooSmall { provided, required } => write!(
                f,
                "output buffer too small for PKCS#7 padding: provided {provided}B, required {required}B"
            ),
            Self::InvalidPaddingOrCiphertext => {
                write!(f, "invalid PKCS#7 padding or corrupted AES-CBC ciphertext")
            }
        }
    }
}

impl std::error::Error for AesCbcError {}

/// Computes the exact ciphertext byte length for a plaintext of `pt_len` bytes
/// when padded with a reversible 16-byte block padding scheme (`Pkcs7`, `Iso7816`, `AnsiX923`, `Iso10126`).
#[inline]
pub const fn pkcs7_padded_len_16(pt_len: usize) -> usize {
    (pt_len / 16 + 1) * 16
}

/// Encrypts `plaintext` in-place inside `buffer` using AES-128-CBC and PKCS#7 padding.
///
/// # Buffer Contract
/// - `buffer[..pt_len]` must contain the plaintext bytes.
/// - `buffer.len()` must be at least `pkcs7_padded_len_16(pt_len)`.
pub fn aes128_cbc_encrypt_in_place<'a>(
    key: &[u8; 16],
    iv: &[u8; 16],
    buffer: &'a mut [u8],
    pt_len: usize,
) -> Result<&'a [u8], AesCbcError> {
    let required = pkcs7_padded_len_16(pt_len);
    if buffer.len() < required || pt_len > buffer.len() {
        return Err(AesCbcError::OutputBufferTooSmall {
            provided: buffer.len(),
            required,
        });
    }

    let encryptor = cbc::Encryptor::<Aes128>::new(key.into(), iv.into());
    encryptor
        .encrypt_padded::<Pkcs7>(buffer, pt_len)
        .map_err(|_| AesCbcError::OutputBufferTooSmall {
            provided: buffer.len(),
            required,
        })
}

/// Decrypts `ciphertext` in-place using AES-128-CBC and strips PKCS#7 padding.
pub fn aes128_cbc_decrypt_in_place<'a>(
    key: &[u8; 16],
    iv: &[u8; 16],
    ciphertext: &'a mut [u8],
) -> Result<&'a [u8], AesCbcError> {
    let decryptor = cbc::Decryptor::<Aes128>::new(key.into(), iv.into());
    decryptor
        .decrypt_padded::<Pkcs7>(ciphertext)
        .map_err(|_| AesCbcError::InvalidPaddingOrCiphertext)
}

/// Encrypts `plaintext` into a separate `out_buffer` using AES-256-CBC and PKCS#7 padding.
pub fn aes256_cbc_encrypt_b2b<'a>(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
    out_buffer: &'a mut [u8],
) -> Result<&'a [u8], AesCbcError> {
    let required = pkcs7_padded_len_16(plaintext.len());
    if out_buffer.len() < required {
        return Err(AesCbcError::OutputBufferTooSmall {
            provided: out_buffer.len(),
            required,
        });
    }

    let encryptor = cbc::Encryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|_| AesCbcError::InvalidKeyOrIvLength)?;
    encryptor
        .encrypt_padded_b2b::<Pkcs7>(plaintext, out_buffer)
        .map_err(|_| AesCbcError::OutputBufferTooSmall {
            provided: out_buffer.len(),
            required,
        })
}

/// Decrypts `ciphertext` into a separate `out_buffer` using AES-256-CBC and strips PKCS#7 padding.
pub fn aes256_cbc_decrypt_b2b<'a>(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    out_buffer: &'a mut [u8],
) -> Result<&'a [u8], AesCbcError> {
    let decryptor = cbc::Decryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|_| AesCbcError::InvalidKeyOrIvLength)?;
    decryptor
        .decrypt_padded_b2b::<Pkcs7>(ciphertext, out_buffer)
        .map_err(|_| AesCbcError::InvalidPaddingOrCiphertext)
}
```

---

## 2. SNMPv3 USM 1-Megabyte Key Localization (RFC 3414 §A.2.1 & RFC 7860)

Matches the exact implementation in `src/builders/l7/snmp/crypto.rs`. Streams `1,048,576` bytes ($16,384 \times 64$ bytes) of repeated passphrase through any `Digest` (`Md5`, `Sha1`, `Sha256`, `Sha384`, `Sha512`) to compute the master key `Ku`, followed by `Kul = Hash(Ku || engine_id || Ku)`.

```rust
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// Supported SNMPv3 USM authentication / key-localization hash algorithms (RFC 3414 & RFC 7860).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbAuthHash {
    /// `usmHMACMD5AuthProtocol` (RFC 3414) — 16-byte `Kul`, 12-byte wire MAC.
    Md5,
    /// `usmHMACSHAAuthProtocol` (RFC 3414) — 20-byte `Kul`, 12-byte wire MAC.
    Sha1,
    /// `usmHMAC192SHA256AuthProtocol` (RFC 7860) — 32-byte `Kul`, 24-byte wire MAC.
    Sha256,
    /// `usmHMAC256SHA384AuthProtocol` (RFC 7860) — 48-byte `Kul`, 32-byte wire MAC.
    Sha384,
    /// `usmHMAC384SHA512AuthProtocol` (RFC 7860) — 64-byte `Kul`, 48-byte wire MAC.
    Sha512,
}

impl UsbAuthHash {
    /// Returns the truncated wire MAC byte length (`msgAuthenticationParameters`) per RFC 3414 / RFC 7860.
    #[inline]
    pub const fn wire_mac_len(self) -> usize {
        match self {
            Self::Md5 | Self::Sha1 => 12,
            Self::Sha256 => 24,
            Self::Sha384 => 32,
            Self::Sha512 => 48,
        }
    }
}

/// Generic RFC 3414 §A.2.1 / RFC 7860 password-to-localized-key (`Kul`) derivation.
///
/// # Security & Safety Invariants
/// - Guards against empty passwords (`password.is_empty()`) before performing modulo arithmetic.
/// - Processes `1,048,576` bytes (`16,384` chunks of `64` bytes) in constant stack space (`[0u8; 64]`).
pub fn localize_snmpv3_key_generic<D: Digest + Default>(
    password: &[u8],
    engine_id: &[u8],
) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }

    // Pass 1: Stretch password to 1,048,576 bytes (1 MB) -> Master Key `Ku`
    let mut hasher = D::new();
    let mut count = 0usize;
    let mut password_index = 0usize;
    let mut buf = [0u8; 64];

    while count < 1_048_576 {
        for byte in &mut buf {
            *byte = password[password_index % password.len()];
            password_index += 1;
        }
        hasher.update(buf);
        count += 64;
    }
    let ku = hasher.finalize();

    // Pass 2: Localize `Ku` with the authoritative `msgAuthoritativeEngineID` -> `Kul`
    let mut loc_hasher = D::new();
    loc_hasher.update(&ku);
    loc_hasher.update(engine_id);
    loc_hasher.update(&ku);
    loc_hasher.finalize().to_vec()
}

/// Dispatches RFC 3414 / RFC 7860 key localization for the runtime `UsbAuthHash` variant.
pub fn derive_snmpv3_kul(
    protocol: UsbAuthHash,
    password: &[u8],
    engine_id: &[u8],
) -> Vec<u8> {
    match protocol {
        UsbAuthHash::Md5 => localize_snmpv3_key_generic::<Md5>(password, engine_id),
        UsbAuthHash::Sha1 => localize_snmpv3_key_generic::<Sha1>(password, engine_id),
        UsbAuthHash::Sha256 => localize_snmpv3_key_generic::<Sha256>(password, engine_id),
        UsbAuthHash::Sha384 => localize_snmpv3_key_generic::<Sha384>(password, engine_id),
        UsbAuthHash::Sha512 => localize_snmpv3_key_generic::<Sha512>(password, engine_id),
    }
}
```

---

## 3. SNMPv3 USM AES-128-CFB Encryption & Decryption (RFC 3826 §3.1.2)

Demonstrates `cfb_mode::Encryptor<Aes128>` and `cfb_mode::Decryptor<Aes128>` using the 16-byte IV constructed from `msgAuthoritativeEngineBoots` (4B BE), `msgAuthoritativeEngineTime` (4B BE), and the 64-bit `salt` (`msgPrivacyParameters`, 8B). In `cipher 0.5.2` / `cfb-mode 0.9.1`, `cfb_mode::Encryptor` and `cfb_mode::Decryptor` expose inherent `.encrypt(&mut [u8])` and `.decrypt(&mut [u8])` methods that operate on any byte length without padding.

```rust
use aes::Aes128;
use cfb_mode::cipher::KeyIvInit;

/// Constructs the 16-byte AES-128-CFB initialization vector per RFC 3826 §3.1.2.1:
/// `IV = engine_boots (4B BE) || engine_time (4B BE) || salt (8B)`.
#[inline]
pub fn build_rfc3826_aes_iv(engine_boots: u32, engine_time: u32, salt: &[u8; 8]) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[0..4].copy_from_slice(&engine_boots.to_be_bytes());
    iv[4..8].copy_from_slice(&engine_time.to_be_bytes());
    iv[8..16].copy_from_slice(salt);
    iv
}

/// Encrypts an ASN.1 BER-encoded `ScopedPdu` using AES-128-CFB per RFC 3826 §3.1.2.
///
/// Truncates `priv_kul` to its first 16 bytes (`&priv_kul[0..16]`) as required by RFC 3826 §3.2.1.
pub fn encrypt_usm_aes128_cfb(
    priv_kul: &[u8],
    engine_boots: u32,
    engine_time: u32,
    salt: &[u8; 8],
    scoped_pdu_ber: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if priv_kul.len() < 16 {
        return Err("AES-128-CFB localized privacy key (Kul) must be at least 16 bytes");
    }

    let aes_key = &priv_kul[0..16];
    let iv = build_rfc3826_aes_iv(engine_boots, engine_time, salt);

    let mut buf = scoped_pdu_ber.to_vec();
    let encryptor = cfb_mode::Encryptor::<Aes128>::new_from_slices(aes_key, &iv)
        .map_err(|_| "invalid AES-128-CFB key or IV length")?;
    encryptor.encrypt(&mut buf);
    Ok(buf)
}

/// Decrypts an AES-128-CFB encrypted `ScopedPdu` per RFC 3826 §3.1.3.
pub fn decrypt_usm_aes128_cfb(
    priv_kul: &[u8],
    engine_boots: u32,
    engine_time: u32,
    salt: &[u8; 8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if priv_kul.len() < 16 {
        return Err("AES-128-CFB localized privacy key (Kul) must be at least 16 bytes");
    }

    let aes_key = &priv_kul[0..16];
    let iv = build_rfc3826_aes_iv(engine_boots, engine_time, salt);

    let mut buf = ciphertext.to_vec();
    let decryptor = cfb_mode::Decryptor::<Aes128>::new_from_slices(aes_key, &iv)
        .map_err(|_| "invalid AES-128-CFB key or IV length")?;
    decryptor.decrypt(&mut buf);
    Ok(buf)
}
```

---

## 4. SNMPv3 USM DES-CBC `ZeroPadding` Encryption & `NoPadding` BER Decryption Invariant (RFC 3414 §8.1.1)

Demonstrates:
- RFC 3414 §8.1.1.1 DES key (`kul[0..8]`) and `pre_iv` (`kul[8..16]`) extraction, XORing `pre_iv ^ salt` to form the 8-byte CBC IV, and `ZeroPadding` encryption (`encrypt_padded::<ZeroPadding>`).
- **The `NoPadding` vs. `ZeroPadding` BER Decryption Invariant (`tests/snmp_spec_tests.rs:194`)**:
  - When decrypting an ASN.1 BER `ScopedPdu` encrypted with `ZeroPadding`, if the final VarBind ends in `0x00` (e.g., `INT 0` = `02 01 00` or `NULLVAL` = `05 00`) and the `ScopedPdu` length is an exact multiple of 8 bytes, `decrypt_padded::<ZeroPadding>` strips the valid trailing `0x00` of the BER TLV from the returned slice!
  - Because an ASN.1 BER `ScopedPdu` (`0x30`) is self-delimiting via its outer TLV length, decrypting with `decrypt_padded::<NoPadding>` leaves all decrypted bytes intact for `rasn::ber::decode`.

```rust
use cbc::cipher::{
    BlockModeDecrypt, BlockModeEncrypt, KeyIvInit,
    block_padding::{NoPadding, ZeroPadding},
};
use des::Des;

/// Computes the 8-byte DES-CBC IV per RFC 3414 §8.1.1.1: `iv[i] = pre_iv[i] ^ salt[i]`.
#[inline]
pub fn build_rfc3414_des_iv(pre_iv: &[u8; 8], salt: &[u8; 8]) -> [u8; 8] {
    let mut iv = [0u8; 8];
    for i in 0..8 {
        iv[i] = pre_iv[i] ^ salt[i];
    }
    iv
}

/// Checks whether an 8-byte DES key is one of the 16 weak or semi-weak keys defined in FIPS 46-3.
#[inline]
pub fn is_weak_des_key(key: &[u8; 8]) -> bool {
    des::weak_key_test(key.into())
}

/// Encrypts an ASN.1 BER-encoded `ScopedPdu` using DES-CBC and `ZeroPadding` per RFC 3414 §8.1.1.2.
///
/// - If `scoped_pdu_ber.len() % 8 == 0`, `ZeroPadding` adds **0** bytes (`PaddedData::NoPad`).
/// - If `scoped_pdu_ber.len() % 8 != 0`, `ZeroPadding` appends `1..=7` zero bytes (`0x00`).
pub fn encrypt_usm_des_cbc(
    priv_kul: &[u8],
    salt: &[u8; 8],
    scoped_pdu_ber: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if priv_kul.len() < 16 {
        return Err("DES-CBC localized privacy key (Kul) must be at least 16 bytes");
    }

    let des_key: &[u8; 8] = priv_kul[0..8].try_into().unwrap();
    let pre_iv: &[u8; 8] = priv_kul[8..16].try_into().unwrap();
    let iv = build_rfc3414_des_iv(pre_iv, salt);

    let pt_len = scoped_pdu_ber.len();
    let mut buf = scoped_pdu_ber.to_vec();
    buf.resize(pt_len + 8, 0u8);

    let encryptor = cbc::Encryptor::<Des>::new(des_key.into(), (&iv).into());
    let ct_slice = encryptor
        .encrypt_padded::<ZeroPadding>(&mut buf, pt_len)
        .map_err(|_| "DES-CBC ZeroPadding encryption failed")?;
    Ok(ct_slice.to_vec())
}

/// Decrypts a DES-CBC `EncryptedPdu` using `NoPadding` (NOT `ZeroPadding`!) so that an
/// 8-byte-aligned BER `ScopedPdu` ending in `0x00` (`INT 0` = `02 01 00` or `NULLVAL` = `05 00`)
/// never has its final BER TLV byte stripped before `rasn::ber::decode`.
pub fn decrypt_usm_des_cbc_raw_blocks(
    priv_kul: &[u8],
    salt: &[u8; 8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if priv_kul.len() < 16 {
        return Err("DES-CBC localized privacy key (Kul) must be at least 16 bytes");
    }
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(8) {
        return Err("DES-CBC ciphertext length must be a non-zero multiple of 8 bytes");
    }

    let des_key: &[u8; 8] = priv_kul[0..8].try_into().unwrap();
    let pre_iv: &[u8; 8] = priv_kul[8..16].try_into().unwrap();
    let iv = build_rfc3414_des_iv(pre_iv, salt);

    let mut buf = ciphertext.to_vec();
    let decryptor = cbc::Decryptor::<Des>::new(des_key.into(), (&iv).into());
    decryptor
        .decrypt_padded::<NoPadding>(&mut buf)
        .map_err(|_| "DES-CBC NoPadding block decryption failed")?;
    Ok(buf)
}
```

---

## 5. Triple-DES (`TdesEde3`) CBC Encryption with Weak-Key & Keying-Option Screening

Demonstrates `des::TdesEde3` (24-byte key, 8-byte block) with NIST SP 800-67 Keying Option 1 validation ($K_1 \neq K_2 \neq K_3$ and no individual 8-byte subkey is a weak/semi-weak DES key).

```rust
use block_padding::Pkcs7;
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use des::TdesEde3;

/// Validates a 24-byte 3DES EDE3 key against NIST SP 800-67 Keying Option 1 requirements.
pub fn validate_tdes_ede3_key(key: &[u8; 24]) -> Result<(), &'static str> {
    let k1: &[u8; 8] = key[0..8].try_into().unwrap();
    let k2: &[u8; 8] = key[8..16].try_into().unwrap();
    let k3: &[u8; 8] = key[16..24].try_into().unwrap();

    if k1 == k2 || k2 == k3 || k1 == k3 {
        return Err("3DES Keying Option 1 violation: subkeys K1, K2, K3 must be distinct");
    }
    if des::weak_key_test(k1.into())
        || des::weak_key_test(k2.into())
        || des::weak_key_test(k3.into())
    {
        return Err("3DES key contains a weak or semi-weak DES subkey");
    }
    Ok(())
}

/// Encrypts `plaintext` with 3DES-EDE3-CBC (`TdesEde3`) and PKCS#7 padding.
pub fn tdes_ede3_cbc_encrypt(
    key: &[u8; 24],
    iv: &[u8; 8],
    plaintext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    validate_tdes_ede3_key(key)?;

    let pt_len = plaintext.len();
    let required = (pt_len / 8 + 1) * 8;
    let mut buf = vec![0u8; required];
    buf[..pt_len].copy_from_slice(plaintext);

    let encryptor = cbc::Encryptor::<TdesEde3>::new(key.into(), iv.into());
    let ct = encryptor
        .encrypt_padded::<Pkcs7>(&mut buf, pt_len)
        .map_err(|_| "3DES-CBC PKCS#7 padding failed")?;
    Ok(ct.to_vec())
}

/// Decrypts `ciphertext` with 3DES-EDE3-CBC (`TdesEde3`) and validates PKCS#7 padding.
pub fn tdes_ede3_cbc_decrypt(
    key: &[u8; 24],
    iv: &[u8; 8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    validate_tdes_ede3_key(key)?;

    let mut buf = ciphertext.to_vec();
    let decryptor = cbc::Decryptor::<TdesEde3>::new(key.into(), iv.into());
    let pt = decryptor
        .decrypt_padded::<Pkcs7>(&mut buf)
        .map_err(|_| "3DES-CBC PKCS#7 unpadding failed")?;
    Ok(pt.to_vec())
}
```

---

## 6. Resumable Multi-Chunk CFB Stream Encryption (`cfb_mode::BufEncryptor`)

Unlike one-shot `cfb_mode::Encryptor<C>::encrypt(self, data)` which consumes the cipher instance, `cfb_mode::BufEncryptor<C>` and `cfb_mode::BufDecryptor<C>` maintain internal block feedback state across arbitrary chunk boundaries.

```rust
use aes::Aes128;
use cfb_mode::cipher::KeyIvInit;
use cfb_mode::{BufDecryptor, BufEncryptor};

/// Encrypts two non-contiguous payload chunks as a single contiguous AES-128-CFB stream.
pub fn stream_aes128_cfb_chunks(
    key: &[u8; 16],
    iv: &[u8; 16],
    chunk_a: &mut [u8],
    chunk_b: &mut [u8],
) {
    let mut stream_enc = BufEncryptor::<Aes128>::new(key.into(), iv.into());
    stream_enc.encrypt(chunk_a);
    stream_enc.encrypt(chunk_b);
}

/// Decrypts two chunks encrypted by `stream_aes128_cfb_chunks` back into plaintext.
pub fn decrypt_stream_aes128_cfb_chunks(
    key: &[u8; 16],
    iv: &[u8; 16],
    chunk_a: &mut [u8],
    chunk_b: &mut [u8],
) {
    let mut stream_dec = BufDecryptor::<Aes128>::new(key.into(), iv.into());
    stream_dec.decrypt(chunk_a);
    stream_dec.decrypt(chunk_b);
}
```

---

## 7. Multi-Algorithm Digests, `finalize_reset`, & Hardware Acceleration Check

Demonstrates unified hashing across `Md5`, `Sha1`, `Sha256`, `Sha384`, and `Sha512`, zero-allocation loop reuse via `Digest::finalize_reset`, and runtime CPU feature inspection via `aes::hardware_accelerated()`.

```rust
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// Hashes a batch of slices using a single reusable `Sha256` instance via `Digest::finalize_reset`.
pub fn sha256_batch_reuse(messages: &[&[u8]]) -> Vec<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut results = Vec::with_capacity(messages.len());
    for msg in messages {
        hasher.update(msg);
        let digest: [u8; 32] = hasher.finalize_reset().into();
        results.push(digest);
    }
    results
}

/// Computes MD5, SHA-1, SHA-384, and SHA-512 digests in one pass for diagnostic fingerprinting.
pub fn multi_hash_fingerprint(data: &[u8]) -> ([u8; 16], [u8; 20], [u8; 48], [u8; 64]) {
    let md5_out: [u8; 16] = Md5::digest(data).into();
    let sha1_out: [u8; 20] = Sha1::digest(data).into();
    let sha384_out: [u8; 48] = Sha384::digest(data).into();
    let sha512_out: [u8; 64] = Sha512::digest(data).into();
    (md5_out, sha1_out, sha384_out, sha512_out)
}

/// Reports whether AES hardware acceleration (AES-NI on x86/x86_64 or ARMv8 Crypto) is active.
#[inline]
pub fn is_aes_hw_accelerated() -> bool {
    aes::hardware_accelerated()
}
```

---

## 8. Full & Left-Truncated HMAC (`Mac::verify_truncated_left`) and `HmacReset<D>` (`hmac 0.13.0`)

Demonstrates:
- Full-length constant-time HMAC verification (`Mac::verify_slice`).
- Left-truncated constant-time HMAC verification (`Mac::verify_truncated_left`) with the **mandatory** `candidate_tag.len() == expected_wire_len` guard (because `verify_truncated_left` accepts any slice length in `1..=OutputSize`).
- Reusable `hmac::HmacReset<Sha256>` across multiple packets using `Mac::reset(&mut self)` (`Hmac<D>` itself does not implement `Reset` in `hmac 0.13.0`).

```rust
use hmac::{Hmac, HmacReset, KeyInit, Mac};
use md5::Md5;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

/// Type alias for HMAC-MD5 (RFC 2104 / RFC 3414).
pub type HmacMd5 = Hmac<Md5>;
/// Type alias for HMAC-SHA1 (RFC 2104 / RFC 3414).
pub type HmacSha1 = Hmac<Sha1>;
/// Type alias for HMAC-SHA256 (RFC 6234 / RFC 7860).
pub type HmacSha256 = Hmac<Sha256>;
/// Type alias for HMAC-SHA384 (RFC 6234 / RFC 7860).
pub type HmacSha384 = Hmac<Sha384>;
/// Type alias for HMAC-SHA512 (RFC 6234 / RFC 7860).
pub type HmacSha512 = Hmac<Sha512>;

/// Verifies a full 32-byte HMAC-SHA256 tag in constant time using `Mac::verify_slice`.
pub fn verify_hmac_sha256_full(key: &[u8], message: &[u8], candidate_tag: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any byte length");
    mac.update(message);
    mac.verify_slice(candidate_tag).is_ok()
}

/// Verifies a truncated SNMPv3 USM wire MAC in constant time using `Mac::verify_truncated_left`
/// after enforcing the exact RFC 3414 / RFC 7860 wire tag length (`12`, `24`, `32`, or `48` bytes).
pub fn verify_usm_truncated_hmac(
    protocol: super::UsbAuthHash,
    auth_kul: &[u8],
    whole_msg_with_zeroed_mac: &[u8],
    candidate_wire_tag: &[u8],
) -> bool {
    let expected_len = protocol.wire_mac_len();
    // CRITICAL: verify_truncated_left accepts any length in 1..=OutputSize, so we MUST
    // verify the exact protocol-mandated wire length first!
    if candidate_wire_tag.len() != expected_len {
        return false;
    }

    macro_rules! verify_left {
        ($hmac_ty:ty) => {{
            let mut mac = <$hmac_ty>::new_from_slice(auth_kul).expect("HMAC accepts any key size");
            mac.update(whole_msg_with_zeroed_mac);
            mac.verify_truncated_left(candidate_wire_tag).is_ok()
        }};
    }

    match protocol {
        super::UsbAuthHash::Md5 => verify_left!(HmacMd5),
        super::UsbAuthHash::Sha1 => verify_left!(HmacSha1),
        super::UsbAuthHash::Sha256 => verify_left!(HmacSha256),
        super::UsbAuthHash::Sha384 => verify_left!(HmacSha384),
        super::UsbAuthHash::Sha512 => verify_left!(HmacSha512),
    }
}

/// Signs a batch of packets with the same key using `HmacReset<Sha256>` and `Mac::reset(&mut self)`
/// to avoid re-keying the inner/outer HMAC pads on every packet.
pub fn sign_packet_batch_with_hmac_reset(key: &[u8], packets: &[&[u8]]) -> Vec<[u8; 32]> {
    let mut mac =
        HmacReset::<Sha256>::new_from_slice(key).expect("HMAC accepts keys of any byte length");
    let mut tags = Vec::with_capacity(packets.len());
    for pkt in packets {
        mac.update(pkt);
        let tag: [u8; 32] = mac.finalize_reset().into_bytes().into();
        tags.push(tag);
    }
    tags
}
```

---

## 9. Comparative Block Padding Pipeline (`block-padding 0.4.2`: `Pkcs7`, `Iso7816`, `AnsiX923`, `Iso10126`, `ZeroPadding`, `NoPadding`)

In `block-padding 0.4.2`, `RawPadding`, `PadType`, and `UnpadError` do not exist, and `pub trait Padding: 'static` has **zero** type parameters. Block size `B: ArraySize` is supplied as a generic type parameter on the methods `P::pad::<B>(&mut block, pos)`, `P::pad_detached::<B>(blocks, pos) -> PaddedData<'_, B>`, and `P::unpad::<B>(blocks: &[Block<B>]) -> Result<&[u8], block_padding::Error>`.

```rust
use aes::Block as AesBlock;
use aes::cipher::consts::U16;
use block_padding::{
    AnsiX923, Error as PaddingError, Iso10126, Iso7816, NoPadding, PaddedData, Padding, Pkcs7,
    ZeroPadding,
};

/// Pads a sub-block slice (`0..16` bytes for reversible schemes, `1..16` bytes for `ZeroPadding`)
/// into a 16-byte `AesBlock` using the zero-type-parameter `P: Padding` trait in `block-padding 0.4.2`.
pub fn pad_single_aes_block<P: Padding>(payload: &[u8]) -> Result<[u8; 16], &'static str> {
    if payload.len() >= 16 {
        return Err("single-block pad example requires payload.len() < 16");
    }
    let mut block = AesBlock::default();
    block[..payload.len()].copy_from_slice(payload);
    P::pad::<U16>(&mut block, payload.len());
    Ok(block.into())
}

/// Unpads a 16-byte `AesBlock` using `P::unpad::<U16>(core::slice::from_ref(block))`.
pub fn unpad_single_aes_block<P: Padding>(
    block_bytes: &[u8; 16],
) -> Result<&[u8], PaddingError> {
    let block: &AesBlock = block_bytes.into();
    P::unpad::<U16>(core::slice::from_ref(block))
}

/// Compares the wire representation of `Pkcs7`, `Iso7816`, `AnsiX923`, `Iso10126`, `ZeroPadding`, and `NoPadding`.
pub fn demonstrate_padding_schemes() -> Result<(), &'static str> {
    let sample = b"SNMPv3-USM"; // 10 bytes -> 6 pad bytes needed for 16-byte block

    let pkcs7_blk = pad_single_aes_block::<Pkcs7>(sample)?;
    assert_eq!(&pkcs7_blk[10..16], &[0x06, 0x06, 0x06, 0x06, 0x06, 0x06]);
    assert_eq!(unpad_single_aes_block::<Pkcs7>(&pkcs7_blk).unwrap(), sample);

    let iso_blk = pad_single_aes_block::<Iso7816>(sample)?;
    assert_eq!(&iso_blk[10..16], &[0x80, 0x00, 0x00, 0x00, 0x00, 0x00]);
    assert_eq!(unpad_single_aes_block::<Iso7816>(&iso_blk).unwrap(), sample);

    let ansi_blk = pad_single_aes_block::<AnsiX923>(sample)?;
    assert_eq!(&ansi_blk[10..16], &[0x00, 0x00, 0x00, 0x00, 0x00, 0x06]);
    assert_eq!(unpad_single_aes_block::<AnsiX923>(&ansi_blk).unwrap(), sample);
    assert_eq!(unpad_single_aes_block::<Iso10126>(&ansi_blk).unwrap(), sample);

    let zero_blk = pad_single_aes_block::<ZeroPadding>(sample)?;
    assert_eq!(&zero_blk[10..16], &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    assert_eq!(unpad_single_aes_block::<ZeroPadding>(&zero_blk).unwrap(), sample);

    // Demonstrate PaddedData::NoPad when pos == 0 on ZeroPadding
    let mut aligned_blk = AesBlock::default();
    let detached = ZeroPadding::pad_detached::<U16>(core::slice::from_mut(&mut aligned_blk), 0);
    assert!(matches!(detached, PaddedData::NoPad));

    // NoPadding requires a full 16-byte block and leaves all 16 bytes intact
    let aligned = b"0123456789ABCDEF";
    assert_eq!(unpad_single_aes_block::<NoPadding>(aligned).unwrap(), aligned);

    Ok(())
}
```

---

## 10. Multi-Protocol Network Cryptography (RADIUS RFC 2865, TACACS+ RFC 8907, STUN RFC 5389, WebSocket RFC 6455, & Blumenthal AES-192/256 SNMPv3 USM)

Demonstrates production cryptographic engines for four additional Layer 7 protocols and Cisco/Draft Blumenthal AES-192/256 SNMPv3 privacy:
1. **RADIUS (RFC 2865)**: Response Authenticator (`MD5(Code || ID || Length || ReqAuth || Attrs || Secret)`) and User-Password (Attr 2) 16-byte MD5 XOR chaining.
2. **TACACS+ (RFC 8907 §4.5)**: Body obfuscation pseudo-pad `MD5(session_id_be4 || key || version || seq_no [|| prev_hash])`.
3. **STUN (RFC 5389 §15.4)** `MESSAGE-INTEGRITY` (20-byte `Hmac<Sha1>`) and **WebSocket (RFC 6455 §4.2.2)** `Sec-WebSocket-Accept` (`SHA1(key || "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")`).
4. **Cisco / Draft Blumenthal SNMPv3 AES-192 & AES-256 (`draft-blumenthal-aes-usm-04`)**: Key extension for short `Kul` digests and `cfb_mode::Encryptor<Aes192>` / `cfb_mode::Encryptor<Aes256>`.

```rust
use aes::{Aes192, Aes256};
use cfb_mode::cipher::KeyIvInit;
use hmac::{Hmac, KeyInit, Mac};
use md5::Md5;
use sha1::Sha1;
use sha2::Digest;

// ============================================================================
// 10.1 RADIUS (RFC 2865): Response Authenticator & User-Password MD5 Chaining
// ============================================================================

/// Computes the 16-byte RADIUS Response Authenticator per RFC 2865 §3:
/// `MD5(Code || ID || Length_be2 || RequestAuthenticator_16B || Attributes || SharedSecret)`.
pub fn radius_response_authenticator(
    code: u8,
    id: u8,
    length: u16,
    request_authenticator: &[u8; 16],
    response_attributes: &[u8],
    shared_secret: &[u8],
) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update([code, id]);
    hasher.update(length.to_be_bytes());
    hasher.update(request_authenticator);
    hasher.update(response_attributes);
    hasher.update(shared_secret);
    hasher.finalize().into()
}

/// Encrypts (or decrypts) a RADIUS User-Password (Attribute 2) using RFC 2865 §5.2
/// 16-byte MD5 XOR chaining:
/// - $b_1 = \text{MD5}(S \parallel \text{RA})$, $c_1 = p_1 \oplus b_1$
/// - $b_i = \text{MD5}(S \parallel c_{i-1})$, $c_i = p_i \oplus b_i$
pub fn radius_encrypt_user_password(
    password: &[u8],
    shared_secret: &[u8],
    request_authenticator: &[u8; 16],
) -> Vec<u8> {
    let padded_len = if password.is_empty() {
        16
    } else {
        password.len().div_ceil(16) * 16
    };
    let mut padded = vec![0u8; padded_len];
    padded[..password.len()].copy_from_slice(password);

    let mut out = Vec::with_capacity(padded_len);
    let mut prev_block: &[u8] = request_authenticator;

    for chunk in padded.chunks_exact(16) {
        let mut hasher = Md5::new();
        hasher.update(shared_secret);
        hasher.update(prev_block);
        let pad: [u8; 16] = hasher.finalize().into();

        let mut c_block = [0u8; 16];
        for i in 0..16 {
            c_block[i] = chunk[i] ^ pad[i];
        }
        out.extend_from_slice(&c_block);
        prev_block = &out[out.len() - 16..];
    }
    out
}

// ============================================================================
// 10.2 TACACS+ (RFC 8907 §4.5): Iterated MD5 Pseudo-Pad Body Obfuscation
// ============================================================================

/// Obfuscates or de-obfuscates a TACACS+ packet body in-place per RFC 8907 §4.5:
/// `pad_1 = MD5(session_id_be4 || key || version || seq_no)`
/// `pad_i = MD5(session_id_be4 || key || version || seq_no || pad_{i-1})`
///
/// Leaves `body` untouched if `flags & 0x01 != 0` (`TAC_PLUS_UNENCRYPTED_FLAG`) or `key.is_empty()`.
pub fn tacacs_obfuscate_body_in_place(
    session_id: u32,
    secret_key: &[u8],
    version: u8,
    seq_no: u8,
    flags: u8,
    body: &mut [u8],
) {
    if (flags & 0x01) != 0 || secret_key.is_empty() || body.is_empty() {
        return;
    }

    let session_be = session_id.to_be_bytes();
    let mut prev_pad: Option<[u8; 16]> = None;

    for chunk in body.chunks_mut(16) {
        let mut hasher = Md5::new();
        hasher.update(session_be);
        hasher.update(secret_key);
        hasher.update([version, seq_no]);
        if let Some(prev) = &prev_pad {
            hasher.update(prev);
        }
        let pad: [u8; 16] = hasher.finalize().into();
        for (b, p) in chunk.iter_mut().zip(pad.iter()) {
            *b ^= *p;
        }
        prev_pad = Some(pad);
    }
}

// ============================================================================
// 10.3 STUN (RFC 5389 §15.4) & WebSocket (RFC 6455 §4.2.2) SHA-1 / HMAC-SHA1
// ============================================================================

/// Computes the 20-byte RFC 5389 §15.4 STUN `MESSAGE-INTEGRITY` HMAC-SHA1 tag.
pub fn stun_message_integrity_hmac_sha1(key: &[u8], stun_bytes_up_to_attr: &[u8]) -> [u8; 20] {
    let mut mac =
        <Hmac<Sha1> as KeyInit>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(stun_bytes_up_to_attr);
    mac.finalize().into_bytes().into()
}

/// Computes the 20-byte raw SHA-1 digest for RFC 6455 §4.2.2 `Sec-WebSocket-Accept`:
/// `SHA1(client_key_b64.trim() || "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")`.
pub fn websocket_accept_sha1_digest(client_key_b64: &str) -> [u8; 20] {
    const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut hasher = Sha1::new();
    hasher.update(client_key_b64.trim().as_bytes());
    hasher.update(WS_GUID);
    hasher.finalize().into()
}

// ============================================================================
// 10.4 Cisco / Draft Blumenthal SNMPv3 AES-192 & AES-256-CFB Key Extension
// ============================================================================

/// Extends a localized USM key (`Kul`) per `draft-blumenthal-aes-usm-04` §3.1.2.1 when
/// the underlying hash output (e.g., `Md5` = 16B or `Sha1` = 20B) is shorter than
/// the required `target_len` (`24` bytes for `Aes192`, `32` bytes for `Aes256`).
pub fn extend_blumenthal_aes_kul<D: Digest + Default>(
    initial_kul: &[u8],
    engine_id: &[u8],
    target_len: usize,
) -> Vec<u8> {
    if initial_kul.is_empty() {
        return Vec::new();
    }
    let mut extended = initial_kul.to_vec();
    while extended.len() < target_len {
        let next_kul = super::localize_snmpv3_key_generic::<D>(&extended, engine_id);
        extended.extend_from_slice(&next_kul);
    }
    extended.truncate(target_len);
    extended
}

/// Encrypts a BER-encoded `ScopedPdu` using Blumenthal AES-192-CFB (`24`-byte key) or
/// AES-256-CFB (`32`-byte key) with the RFC 3826 16-byte `boots || time || salt` IV.
pub fn encrypt_usm_aes192_or_256_cfb(
    is_aes256: bool,
    extended_priv_kul: &[u8],
    engine_boots: u32,
    engine_time: u32,
    salt: &[u8; 8],
    scoped_pdu_ber: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let iv = super::build_rfc3826_aes_iv(engine_boots, engine_time, salt);
    let mut out = scoped_pdu_ber.to_vec();

    if is_aes256 {
        if extended_priv_kul.len() < 32 {
            return Err("AES-256-CFB requires at least 32 bytes of localized privacy key");
        }
        let enc = cfb_mode::Encryptor::<Aes256>::new_from_slices(&extended_priv_kul[0..32], &iv)
            .map_err(|_| "invalid AES-256 key/IV")?;
        enc.encrypt(&mut out);
    } else {
        if extended_priv_kul.len() < 24 {
            return Err("AES-192-CFB requires at least 24 bytes of localized privacy key");
        }
        let enc = cfb_mode::Encryptor::<Aes192>::new_from_slices(&extended_priv_kul[0..24], &iv)
            .map_err(|_| "invalid AES-192 key/IV")?;
        enc.encrypt(&mut out);
    }
    Ok(out)
}
```
