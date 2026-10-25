---
trigger: glob
globs: "src/builders/l7/snmp/crypto.rs, src/builders/l7/snmp/builder.rs, src/builders/l7/radius.rs, src/builders/l7/tacacs.rs, tests/*snmp*.rs"
description: "RustCrypto (aes 0.9.3, des 0.9.0, cbc 0.2.1, cfb-mode 0.9.1, block-padding 0.4.2, hmac 0.13.0, md-5/sha1/sha2 0.11.x, cipher 0.5.2, digest 0.11.3, inout 0.2.5, ctutils 0.4.5) rules."
---

# RustCrypto Engineering & Security Guardrails

When writing or modifying cryptographic code using `aes`, `des`, `cbc`, `cfb-mode`, `block-padding`, `hmac`, `md-5`, `sha1`, or `sha2`, adhere strictly to the following version-exact rules:

---

## 1. Transitive Trait Imports, `hybrid-array` & `block-padding 0.4.2` / `cipher 0.5.2` Discipline

- **Import Foundational Traits via Mode/Hash Re-Exports**: Because `cipher` (`0.5.2`), `digest` (`0.11.3`), and `crypto-common` (`0.2.2`) are transitive dependencies in `Cargo.lock` rather than direct entries in `Cargo.toml`, always import traits through their public crate re-exports:
  - `use cbc::cipher::{BlockModeEncrypt, BlockModeDecrypt, KeyIvInit, block_padding::{NoPadding, Pkcs7, ZeroPadding}};`
  - `use cfb_mode::cipher::KeyIvInit;` (`cfb_mode::Encryptor<C>` and `cfb_mode::Decryptor<C>` implement `BlockModeEncrypt` / `BlockModeDecrypt` and expose inherent `.encrypt(&mut [u8])`, `.decrypt(&mut [u8])`, `.encrypt_b2b`, `.decrypt_b2b`, and `.encrypt_inout(InOutBuf)` methods)
  - `use cbc::cipher::common` and `use sha2::digest::common` for `crypto-common 0.2.2` traits (`KeySizeUser`, `IvSizeUser`, `BlockSizeUser`, `OutputSizeUser`) — **never** `sha2::digest::crypto_common`!
  - `use hmac::{Hmac, HmacReset, KeyInit, Mac, SimpleHmac, SimpleHmacReset};`
  - `use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};`
- **Never Use Removed `block-padding 0.3` or `cipher 0.4` Symbols**:
  - In `block-padding 0.4.2`, **`RawPadding`, `PadType`, and `UnpadError` do NOT exist**!
  - `block_padding::Padding` has **zero** type parameters (`pub trait Padding: 'static`) and exposes generic methods `P::pad::<B>(block: &mut Block<B>, pos: usize)`, `P::pad_detached::<B>(blocks: &mut [Block<B>], pos: usize) -> PaddedData<'_, B>`, and `P::unpad::<B>(blocks: &[Block<B>]) -> Result<&[u8], block_padding::Error>` (where `blocks` is a slice `&[Block<B>]`, e.g., `core::slice::from_ref(block)` for a single block).
  - Available padding types in `block-padding 0.4.2`: `Pkcs7`, `Iso7816`, `AnsiX923`, `Iso10126`, `ZeroPadding`, and `NoPadding`, alongside `PaddedData::{Pad, NoPad, Error}` and `block_padding::Error`.
  - In `cipher 0.5.2`, **`AsyncStreamCipher` does NOT exist**! `cfb-mode 0.9.1` implements `BlockModeEncrypt` and `BlockModeDecrypt` plus inherent byte-stream methods `.encrypt(&mut [u8])`, `.decrypt(&mut [u8])`, `.encrypt_b2b`, `.decrypt_b2b`, and `.encrypt_inout(InOutBuf)`.
- **Never Depend on Legacy `generic-array`**: Modern RustCrypto (`cipher 0.5+`, `digest 0.11+`) uses `hybrid-array` (`0.4.15`). Convert fixed-size Rust arrays (`&[u8; N]` or `[u8; N]`) directly via `.into()` and convert `Output<D>` / `Array<u8, N>` back to `[u8; N]` via `.into()` or `.as_slice()`.
- **Do Not Assume `alloc` `_vec` Helpers Are Enabled**: Methods such as `encrypt_padded_vec` require the `alloc` feature on `cbc`/`cipher`, which is not enabled by default. Always use slice-based `encrypt_padded::<P>(&mut buf, pt_len)` or `encrypt_padded_b2b::<P>(pt, &mut out)` and convert the returned `&[u8]` slice (`ct.to_vec()`).

---

## 2. Block Cipher Modes, IV Uniqueness, & The SNMPv3 DES-CBC `NoPadding` BER Decryption Invariant

- **Never Use Raw `BlockCipherEncrypt` for Multi-Block Payloads**: Never call `Aes128::encrypt_block` or `Des::encrypt_block` in a loop over message blocks (which implements insecure ECB mode). Always wrap block ciphers in an explicit mode (`cbc::Encryptor<C>`, `cfb_mode::Encryptor<C>`).
- **Never Reuse `(Key, IV)` Pairs**:
  - In **CBC mode** (`cbc 0.2.1`), the IV (`16`B for AES, `8`B for DES/3DES) must be unpredictable (`pre_iv ^ salt` in SNMPv3 DES-CBC or CSPRNG nonce).
  - In **CFB mode** (`cfb-mode 0.9.1`), reusing a `(Key, IV)` pair reduces the first block to a two-time pad ($C_1 \oplus C_2 = P_1 \oplus P_2$). For SNMPv3 AES-128/192/256-CFB (RFC 3826 §3.1.2.1), construct the 16-byte IV strictly as `engine_boots.to_be_bytes() (4B) || engine_time.to_be_bytes() (4B) || salt (8B)`.
- **Respect `Pkcs7` vs. `ZeroPadding` vs. `NoPadding` Semantics**:
  - **Reversible Padding (`Pkcs7`, `Iso7816`, `AnsiX923`, `Iso10126`)**: Always allocate at least `(pt_len / B + 1) * B` bytes. Even when `pt_len % B == 0`, reversible padding appends a full extra block (`B` bytes).
  - **SNMPv3 DES-CBC Encryption (`ZeroPadding`, RFC 3414 §8.1.1.2)**: `ZeroPadding` adds **0** bytes when `pt_len % 8 == 0` (`PaddedData::NoPad`) and `1..=7` `0x00` bytes when `pt_len % 8 != 0` (`PaddedData::Pad`). Always use the exact `&[u8]` slice returned by `encrypt_padded::<ZeroPadding>(&mut buf, pt_len)` (`ct.to_vec()`).
  - **CRITICAL — SNMPv3 DES-CBC BER Decryption (`NoPadding` vs. `ZeroPadding` Invariant)**:
    - When decrypting an ASN.1 BER `ScopedPdu` encrypted with `ZeroPadding` (see `tests/snmp_spec_tests.rs:194`), **never pass the slice returned by `decrypt_padded::<ZeroPadding>` to `rasn::ber::decode`**!
    - If the final VarBind in the `ScopedPdu` ends in `0x00` (for example, `INT 0` = `02 01 00` or `NULLVAL` = `05 00`) and the total BER `ScopedPdu` length happens to be an exact multiple of 8 bytes, `decrypt_padded::<ZeroPadding>` strips all trailing `0x00` bytes from the returned slice—truncating the valid BER TLV!
    - Because an ASN.1 BER `ScopedPdu` (`0x30`) is self-delimiting via its outer TLV length field, always decrypt DES-CBC `EncryptedPdu` payloads using `decrypt_padded::<NoPadding>(&mut ciphertext_buf)` and pass the resulting slice directly to `rasn::ber::decode::<ScopedPdu>`.
  - **`cfb_mode::Encryptor<Aes128>`**: Never apply block padding to CFB-128 ciphertexts; CFB-128 operates at byte granularity and preserves exact plaintext length.

---

## 3. SNMPv3 USM Key Localization, Blumenthal AES-192/256 & Truncated HMAC Invariants

- **Guard Against Empty Passwords in RFC 3414 §A.2.1 Key Localization**:
  - Before running the `1,048,576`-byte (`16,384 * 64`B) password-stretching loop (`password[password_index % password.len()]`), **always** check `if password.is_empty() { return Vec::new(); }` to prevent a runtime division-by-zero panic.
  - Localize the master key `Ku` in Pass 2 strictly as `Kul = Hash(Ku || engine_id || Ku)`.
- **Extract Privacy Keys & Support Blumenthal AES-192 / AES-256 Key Extension**:
  - **DES-CBC (RFC 3414 §8.1.1.1)**: Requires `priv_kul.len() >= 16`. Slice `des_key = &priv_kul[0..8]`, `pre_iv = &priv_kul[8..16]`, and compute `iv[i] = pre_iv[i] ^ salt[i]` for `i in 0..8`.
  - **AES-128-CFB (RFC 3826 §3.2.1)**: Requires `priv_kul.len() >= 16`. Slice `aes_key = &priv_kul[0..16]`.
  - **Cisco / Draft Blumenthal AES-192 & AES-256 (`draft-blumenthal-aes-usm-04`, `Aes192` / `Aes256` in `aes 0.9.3`)**:
    - Requires 24 bytes (`Aes192`) or 32 bytes (`Aes256`). When paired with `Sha256` (32B `Kul`), `Sha384` (48B `Kul`), or `Sha512` (64B `Kul`), slice `&priv_kul[0..24]` or `&priv_kul[0..32]` directly.
    - When paired with a shorter hash (`Md5` = 16B or `Sha1` = 20B `Kul`), extend `Kul` by iteratively running `password_to_key_generic::<D>(current_kul, engine_id)` (or chaining `Kul_2 = localize(Kul_1, engine_id)`) and concatenating until $\ge 24$ or $\ge 32$ bytes are available.
- **Enforce Exact RFC 3414 & RFC 7860 HMAC Truncation Lengths**:
  - `Md5` (`usmHMACMD5AuthProtocol`, RFC 3414): **`12` bytes** (`96` bits)
  - `Sha1` (`usmHMACSHAAuthProtocol`, RFC 3414): **`12` bytes** (`96` bits)
  - `Sha224` (`usmHMAC128SHA224AuthProtocol`, RFC 7860): **`16` bytes** (`128` bits)
  - `Sha256` (`usmHMAC192SHA256AuthProtocol`, RFC 7860): **`24` bytes** (`192` bits)
  - `Sha384` (`usmHMAC256SHA384AuthProtocol`, RFC 7860): **`32` bytes** (`256` bits)
  - `Sha512` (`usmHMAC384SHA512AuthProtocol`, RFC 7860): **`48` bytes** (`384` bits)

---

## 4. Constant-Time MAC Verification (`verify_truncated_left`), `HmacReset<D>` & Multi-Protocol Network Crypto

- **Constant-Time Full & Left-Truncated MAC Verification (`hmac 0.13.0` / `ctutils 0.4.5`)**:
  - Never compare MAC tags with `==` on raw slices!
  - For full-length HMAC verification, call `mac.verify_slice(candidate_tag)` (which delegates to `ctutils::CtEq` inside `CtOutput`).
  - For truncated wire tags (SNMPv3 USM `12`/`16`/`24`/`32`/`48`-byte tags), use `mac.verify_truncated_left(candidate_tag)`, **AFTER** explicitly checking `if candidate_tag.len() != expected_wire_mac_len { return Err(MacError); }`! `Mac::verify_truncated_left` accepts any slice length in `1..=OutputSize` (including a 1-byte tag!), so the caller **must** enforce the exact protocol wire length before calling `verify_truncated_left`.
- **Reusable HMAC State Across Packets (`HmacReset<D>` / `SimpleHmacReset<D>`)**:
  - In `hmac 0.13.0`, `Hmac<D>` and `SimpleHmac<D>` do **not** implement `digest::Reset` or `FixedOutputReset` (to avoid storing the outer key state when one-shot signing is used). When reusing a pre-keyed HMAC across multiple packets in a hot loop via `Mac::reset(&mut self)` or `finalize_into_reset`, use `hmac::HmacReset<D>` (or `hmac::SimpleHmacReset<D>`).
- **Multi-Protocol L7 Cryptographic Verification Rules**:
  1. **RADIUS (RFC 2865)**:
     - **Response Authenticator (`Access-Accept`/`Reject`/`Challenge`, `Accounting-Response`)**: Compute `MD5(Code || ID || Length_be2 || RequestAuthenticator_16B || ResponseAttributes || SharedSecret)`.
     - **User-Password Attribute (Type 2, RFC 2865 §5.2)**: Pad password with `0x00` to a non-zero multiple of 16 bytes ($p_1, p_2, \dots, p_k$). Compute $b_1 = \text{MD5}(\text{Secret} \parallel \text{RequestAuthenticator})$, $c_1 = p_1 \oplus b_1$, and for $i > 1$, $b_i = \text{MD5}(\text{Secret} \parallel c_{i-1})$, $c_i = p_i \oplus b_i$.
  2. **TACACS+ (RFC 8907 §4.5)**:
     - When `flags & 0x01 == 0` (`TAC_PLUS_UNENCRYPTED_FLAG` clear), XOR the body with the iterated MD5 pseudo-pad: $h_1 = \text{MD5}(\text{session\_id\_be4} \parallel \text{secret\_key} \parallel \text{version} \parallel \text{seq\_no})$ and $h_i = \text{MD5}(\text{session\_id\_be4} \parallel \text{secret\_key} \parallel \text{version} \parallel \text{seq\_no} \parallel h_{i-1})$.
  3. **STUN (RFC 5389 §15.4) & WebSocket (RFC 6455 §4.2.2)**:
     - **STUN `MESSAGE-INTEGRITY` (`0x0008`)**: 20-byte `Hmac<Sha1>` over the STUN header (with header length adjusted to include the 24-byte `MESSAGE-INTEGRITY` TLV, excluding attributes after `MESSAGE-INTEGRITY`).
     - **WebSocket `Sec-WebSocket-Accept`**: Base64 of the 20-byte `Sha1::digest(format!("{client_key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))`.
  4. **DES / 3DES Key Screening**: Screen DES/3DES subkeys via `des::weak_key_test(subkey.into())` and enforce $K_1 \neq K_2 \neq K_3$ for `TdesEde3`.
