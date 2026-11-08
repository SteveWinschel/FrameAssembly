---
trigger: glob
globs: "src/builders/l7/snmp/crypto.rs, src/builders/l7/snmp/builder.rs, src/builders/l7/radius.rs, src/builders/l7/tacacs.rs, Cargo.toml, tests/*snmp*.rs"
description: "RustCrypto (aes 0.9.4, des 0.9.0, cbc 0.2.1, cfb-mode 0.9.1, block-padding 0.4.2, hmac 0.13.0, md-5/sha1/sha2 0.11.0, cipher 0.5.2, digest 0.11.3, ctutils 0.4.2) engineering and SNMPv3 USM security rules."
---

# RustCrypto Engineering & Security Guardrails

Adhere strictly to these version-exact RustCrypto rules (`Cargo.toml` specs: `aes = "0.9.3"`, `des = "0.9.0"`, `cbc = "0.2.1"`, `cfb-mode = "0.9.1"`, `block-padding = "0.4.2"`, `hmac = "0.13.0"`, `md-5 = "0.11.0"`, `sha1 = "0.11.0"`, `sha2 = "0.11.0"`; resolved `Cargo.lock` versions: `aes 0.9.4`, `cipher 0.5.2`, `digest 0.11.3`, `crypto-common 0.2.2`, `inout 0.2.5`, `ctutils 0.4.2`, `hybrid-array 0.4.15`):

## 1. Transitive Trait Re-Exports & `cipher 0.5.2` / `block-padding 0.4.2` / `hmac 0.13.0` APIs
- **Import Foundational Traits Through Direct Crates**: Because `cipher`, `digest`, `crypto-common`, `inout`, and `hybrid-array` are transitive in `Cargo.lock`, always import them via public re-exports:
  - `use cbc::cipher::{BlockModeEncrypt, BlockModeDecrypt, KeyIvInit, block_padding::{NoPadding, Pkcs7, ZeroPadding}};`
  - `use cfb_mode::cipher::KeyIvInit;` (`cfb_mode::Encryptor<C>` and `Decryptor<C>` expose inherent byte-stream `.encrypt(&mut [u8])`, `.decrypt(&mut [u8])`, and `.encrypt_inout(InOutBuf)` methods).
  - `use cbc::cipher::common::{KeyInit, KeyIvInit}` and `use sha2::digest::common` (never `crypto_common`!) and `use cbc::cipher::inout::InOutBuf;`.
  - `use hmac::{EagerHash, Hmac, HmacReset, KeyInit, Mac};` and `use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};`. Note that in `hmac 0.13.0`, `Hmac<D>` and `HmacReset<D>` require `D: EagerHash` (implemented by `Md5`, `Sha1`, `Sha224`, `Sha256`, `Sha384`, `Sha512`); use `SimpleHmac<D>` / `SimpleHmacReset<D>` when generic over `D: Digest + BlockSizeUser`.
- **Ban Removed Pre-`0.5` / `generic-array` Symbols**:
  - `RawPadding`, `PadType`, `UnpadError`, and `AsyncStreamCipher` **do not exist** in `block-padding 0.4.2` / `cipher 0.5.2` (`pub trait Padding: 'static` has zero type parameters and takes block size on methods: `P::pad::<B>`, `P::unpad::<B>`).
  - Convert fixed Rust arrays `[u8; N]` / `&[u8; N]` to `hybrid_array::Array<T, U>` via `.into()` (never add legacy `generic-array`).
  - Never call `encrypt_padded_vec` (`alloc` feature on `cbc` is not enabled); use slice-based `encrypt_padded::<P>(&mut buf, pt_len)` and `.to_vec()`.

## 2. Block Modes, IV Construction & The SNMPv3 DES-CBC `NoPadding` BER Invariant
- **Never Use ECB**: Always wrap `Aes128` / `Des` in `cbc::Encryptor<C>` or `cfb_mode::Encryptor<C>`.
- **SNMPv3 USM Privacy IVs (`src/builders/l7/snmp/builder.rs`)**:
  - FrameAssembly uses a deterministic 8-byte `msgPrivacyParameters` salt (`[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]`) for reproducible PCAPNG output.
  - **DES-CBC (RFC 3414 §8.1.1.1)**: Requires `priv_kul.len() >= 16`; `des_key = &priv_kul[0..8]`, `pre_iv = &priv_kul[8..16]`, `iv[i] = pre_iv[i] ^ salt[i]`.
  - **AES-128-CFB (RFC 3826 §3.1.2.1)**: Requires `priv_kul.len() >= 16`; `aes_key = &priv_kul[0..16]`, 16-byte IV = `engine_boots.to_be_bytes() (4B) || engine_time.to_be_bytes() (4B) || salt (8B)`. Zero padding bytes (stream mode).
- **CRITICAL — SNMPv3 DES-CBC `ZeroPadding` Encrypt vs. `NoPadding` BER Decrypt**:
  - **Encrypt**: Use `encrypt_padded::<ZeroPadding>(&mut buf, pt_len)` (appends `0` bytes when `pt_len % 8 == 0`, or `1..=7` `0x00` bytes otherwise; never `Pkcs7`).
  - **Decrypt (in QA / spec tests)**: **NEVER** pass `decrypt_padded::<ZeroPadding>` output to `rasn::ber::decode::<ScopedPdu>`! If an 8-byte-aligned BER `ScopedPdu` ends in `0x00` (`INT 0` = `02 01 00` or `NULLVAL` = `05 00`), `ZeroPadding` strips the valid trailing BER byte! Always decrypt with `decrypt_padded::<NoPadding>(&mut ct_buf)` and let the self-delimiting outer BER `0x30` TLV length bound `rasn::ber::decode`.

## 3. SNMPv3 USM Key Localization & Constant-Time Truncated HMACs
- **Empty-Password Guard in RFC 3414 §A.2.1 (`1,048,576`-Byte Loop)**: Always check `if password.is_empty() { return Vec::new(); }` before `password[password_index % password.len()]` (and reject empty USM passwords in `build_snmp3_payload`), then localize `Kul = Hash(Ku || engine_id || Ku)`. For Blumenthal AES-192/256 with short hashes (`Md5`/`Sha1`), extend `Kul` iteratively via `localize(current_kul, engine_id)`.
- **Exact RFC 3414 & RFC 7860 Wire MAC Lengths**:
  - `MD5`: `12`B (`96`b) | `SHA`: `12`B (`96`b) | `SHA224`: `16`B (`128`b) | `SHA256`: `24`B (`192`b) | `SHA384`: `32`B (`256`b) | `SHA512`: `48`B (`384`b).
- **Constant-Time Verification (`ctutils 0.4.2` / `hmac 0.13.0`)**:
  - Never compare MAC slices with `==`. Use `mac.verify_slice(tag)` for full tags.
  - For truncated USM tags, **first** assert `candidate_tag.len() == expected_wire_mac_len` (`verify_truncated_left` accepts any `1..=OutputSize`, including a 1-byte tag!), then call `mac.verify_truncated_left(candidate_tag)`.
  - Use `HmacReset<D>` when resetting a pre-keyed MAC in a loop (`Hmac<D>` omits `Reset`).