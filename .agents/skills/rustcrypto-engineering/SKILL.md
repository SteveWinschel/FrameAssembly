---
name: rustcrypto-engineering
description: Comprehensive engineering guide, trait selection matrix, and production code templates for modern RustCrypto (aes 0.9.3, des 0.9.0, cbc 0.2.1, cfb-mode 0.9.1, block-padding 0.4.2, hmac 0.13.0, md-5 0.11.0, sha1 0.11.0, sha2 0.11.1, and transitive cipher 0.5.2, digest 0.11.3, hybrid-array 0.4.15, ctutils 0.4.5, inout 0.2.5) including SNMPv3 USM RFC 3414/3826/7860 cryptography.
---

# RustCrypto Engineering & Cryptographic Primitives Reference

## 1. Architectural Overview & Philosophy

The **RustCrypto** ecosystem provides pure-Rust, `no_std`-compatible, hardware-accelerated cryptographic primitives designed around composable type-system traits. In the modern RustCrypto release train (`cipher 0.5.2`, `digest 0.11.3`, `block-padding 0.4.2`, `hybrid-array 0.4.15`), several foundational paradigm shifts govern all symmetric encryption, padding, hashing, and message authentication code:

1. **Migration from `generic-array` to `hybrid-array` (`0.4.15`)**:
   - The legacy `generic-array` crate has been replaced by `hybrid-array` (`hybrid_array::Array<T, U>`), backed by `typenum 1.20.1` type-level integers (`U8`, `U16`, `U20`, `U24`, `U32`, `U48`, `U64`).
   - `hybrid_array::Array` implements seamless `From<[T; N]>`, `Into<[T; N]>`, `AsRef<[T]>`, and `TryFrom<&[T]>` conversions for standard Rust const-generic arrays, eliminating friction between type-level sizes and native `[u8; N]` arrays.
2. **Zero-Type-Parameter `block-padding 0.4.2` & `cipher 0.5.2` Mode Unification**:
   - In `block-padding 0.4.2`, **`RawPadding`, `PadType`, and `UnpadError` do NOT exist**, and `Padding` has **zero** type parameters (`pub trait Padding: 'static`). Instead, block size `B: ArraySize` is passed as a method-level generic parameter: `P::pad::<B>(block: &mut Block<B>, pos: usize)`, `P::pad_detached::<B>(blocks: &mut [Block<B>], pos: usize) -> PaddedData<'_, B>`, and `P::unpad::<B>(blocks: &[Block<B>]) -> Result<&[u8], block_padding::Error>`.
   - In `cipher 0.5.2`, **`AsyncStreamCipher` does NOT exist**. Both `cbc 0.2.1` and `cfb-mode 0.9.1` implement `BlockModeEncrypt` and `BlockModeDecrypt`, while `cfb_mode::Encryptor<C>` and `cfb_mode::Decryptor<C>` also expose inherent byte-stream methods: `.encrypt(&mut [u8])`, `.decrypt(&mut [u8])`, `.encrypt_b2b(in, out)`, `.decrypt_b2b(in, out)`, and `.encrypt_inout(InOutBuf)`.
3. **Strict Separation of Block Ciphers and Modes of Operation**:
   - Block cipher crates (`aes 0.9.3`, `des 0.9.0`) implement **only** raw single-block transformations (`BlockCipherEncrypt`, `BlockCipherDecrypt`) over fixed-width blocks (16 bytes for AES, 8 bytes for DES/3DES).
   - Multi-block encryption and IV management are delegated entirely to mode crates (`cbc 0.2.1`, `cfb-mode 0.9.1`), which wrap a raw cipher (`cbc::Encryptor<Aes128>`, `cfb_mode::Encryptor<Aes128>`, `cbc::Encryptor<Des>`).
4. **In-Place & Buffer-to-Buffer (`inout 0.2.5`) Memory Discipline**:
   - All encryption, decryption, and padding operations are engineered around `inout::InOutBuf<'_, '_, u8>`, allowing callers to choose between zero-allocation in-place mutation (`&mut [u8]`) and non-overlapping input-to-output buffer transformations (`&[u8]` -> `&mut [u8]`).
   - Convenience `_vec` methods require the `alloc` feature on `cipher`/`cbc`, which is **disabled by default** when depending only on `cbc = "0.2.1"`. Always prefer stack/slice-based `encrypt_padded` / `decrypt_padded` or explicit buffer sizing.
5. **Constant-Time Verification via `ctutils 0.4.5`, `CtOutput`, & `verify_truncated_left`**:
   - Modern `digest 0.11.3` and `hmac 0.13.0` use `ctutils` (`CtEq`, `Choice`) inside `CtOutput<T>`. Full MAC tags are verified via `mac.verify_slice(tag)` and left-truncated wire tags via `mac.verify_truncated_left(tag)` (after checking `tag.len() == expected_wire_len`).
6. **Transitive Trait Re-Exports (`cbc::cipher::common`, `sha2::digest::common`)**:
   - When `Cargo.toml` lists concrete algorithm and mode crates (`aes`, `des`, `cbc`, `cfb-mode`, `block-padding`, `hmac`, `md-5`, `sha1`, `sha2`) without explicitly listing `cipher`, `digest`, or `crypto-common`, always import foundational traits through their public re-exports:
     - `use cbc::cipher::{BlockModeEncrypt, BlockModeDecrypt, KeyIvInit, block_padding::{NoPadding, Pkcs7, ZeroPadding}};`
     - `use cfb_mode::cipher::KeyIvInit;`
     - `use cbc::cipher::common` and `use sha2::digest::common` (note: the re-export module is named `common`, **not** `crypto_common`!)
     - `use hmac::{Hmac, HmacReset, KeyInit, Mac, SimpleHmac, SimpleHmacReset};`
     - `use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};`

---

## 2. Crate & Version Matrix

### Direct Workspace Dependencies (`Cargo.toml`)

| Crate | Version (`Cargo.lock`) | Core Types & Structs | Primary Role & RFC Alignment |
| :--- | :--- | :--- | :--- |
| **`aes`** | `0.9.3` | `Aes128`, `Aes192`, `Aes256`, `Aes128Enc`, `Aes128Dec`, `Block` (`16`B) | FIPS 197 AES block cipher (`16`/`24`/`32`B keys, `16`B block) with AES-NI / ARMv8 Crypto runtime detection (`aes::hardware_accelerated()`). |
| **`des`** | `0.9.0` | `Des`, `TdesEde2`, `TdesEde3`, `weak_key_test` | FIPS 46-3 DES (`8`B key, `8`B block) and SP 800-67 3DES EDE2 (`16`B key) / EDE3 (`24`B key) + weak/semi-weak key detection. |
| **`cbc`** | `0.2.1` | `Encryptor<C>`, `Decryptor<C>` | NIST SP 800-38A Cipher Block Chaining (CBC) mode implementing `BlockModeEncrypt`, `BlockModeDecrypt`, and `KeyIvInit`. |
| **`cfb-mode`** | `0.9.1` | `Encryptor<C>`, `Decryptor<C>`, `BufEncryptor<C>`, `BufDecryptor<C>` | Full-block Cipher Feedback (CFB-128 / CFB-64) mode (RFC 3826 SNMPv3 AES-128-CFB & Draft Blumenthal AES-192/256-CFB). |
| **`block-padding`** | `0.4.2` | `Padding`, `Pkcs7`, `Iso7816`, `AnsiX923`, `Iso10126`, `ZeroPadding`, `NoPadding`, `PaddedData`, `Error` | Zero-type-parameter `Padding` trait (`P::pad::<B>`, `P::pad_detached::<B>`, `P::unpad::<B>`). *Note: `RawPadding`, `PadType`, and `UnpadError` do not exist in `0.4.2`!* |
| **`hmac`** | `0.13.0` | `Hmac<D>`, `HmacReset<D>`, `SimpleHmac<D>`, `SimpleHmacReset<D>`, `Mac`, `KeyInit` | RFC 2104 Keyed-Hash Message Authentication Code (`Hmac<D>` for one-shot/streaming; `HmacReset<D>` when `Reset` / `FixedOutputReset` is needed across packets). |
| **`md-5`** | `0.11.0` | `Md5` (`16`B output, `64`B block) | RFC 1321 MD5 digest (SNMPv3 `usmHMACMD5AuthProtocol`, RADIUS RFC 2865 Authenticator & User-Password XOR, TACACS+ RFC 8907 pseudo-pad). |
| **`sha1`** | `0.11.0` | `Sha1` (`20`B output, `64`B block) | FIPS 180-4 / RFC 3174 SHA-1 digest (SNMPv3 `usmHMACSHAAuthProtocol`, STUN RFC 5389 `MESSAGE-INTEGRITY`, WebSocket RFC 6455 `Sec-WebSocket-Accept`). |
| **`sha2`** | `0.11.0` (`0.11.1`) | `Sha224`, `Sha256`, `Sha384`, `Sha512`, `Sha512_224`, `Sha512_256` | FIPS 180-4 / RFC 6234 SHA-2 family (SNMPv3 RFC 7860 `usmHMAC192SHA256AuthProtocol`, `usmHMAC256SHA384AuthProtocol`, `usmHMAC384SHA512AuthProtocol`). |

### Transitive Foundation Crates (`Cargo.lock`)

| Crate | Version | Exact Re-Export Path | Core Types & Traits Provided |
| :--- | :--- | :--- | :--- |
| **`cipher`** | `0.5.2` | `cbc::cipher`, `cfb_mode::cipher`, `aes::cipher`, `des::cipher` | `KeyInit`, `KeyIvInit`, `BlockCipherEncrypt`, `BlockCipherDecrypt`, `BlockModeEncrypt`, `BlockModeDecrypt`, `InvalidLength`, `inout::PadError`, `block_padding::Error`. |
| **`digest`** | `0.11.3` | `sha2::digest`, `hmac::digest` | `Digest`, `Mac`, `Update`, `Reset`, `FixedOutput`, `FixedOutputReset`, `CtOutput`, `MacError`, `InvalidLength`. |
| **`crypto-common`** | `0.2.2` | `cbc::cipher::common`, `sha2::digest::common` | `Key<B>`, `Iv<B>`, `Block<B>`, `Output<D>`, `KeySizeUser`, `IvSizeUser`, `BlockSizeUser`, `OutputSizeUser`, `InnerInit`. |
| **`inout`** | `0.2.5` | `cbc::cipher::inout` | `InOut<'inp, 'out, T>`, `InOutBuf<'inp, 'out, T>`, `PadError`, `NotEqualError`. |
| **`ctutils`** | `0.4.5` | Internal to `digest::CtOutput` | `CtEq`, `CtSelect`, `Choice` (constant-time equality & selection). |
| **`hybrid-array`** | `0.4.15` | `cbc::cipher::Array`, `sha2::digest::array::Array` | `Array<T, U>`, `ArraySize`, `typenum::consts::{U8, U16, U20, U24, U32, U48, U64}`. |

---

## 3. Core Trait Architecture & Selection Matrix

### 3.1 Key & IV Initialization (`crypto-common 0.2.2` / `cipher 0.5.2`)

| Trait | Required By | Primary Initialization Methods | Error Handling |
| :--- | :--- | :--- | :--- |
| **`KeyInit`** | `Aes128`, `Aes192`, `Aes256`, `Des`, `TdesEde2`, `TdesEde3`, `Hmac<D>`, `HmacReset<D>` | `new(key: &Key<Self>) -> Self`<br>`new_from_slice(key: &[u8]) -> Result<Self, InvalidLength>` | Use `new(&key.into())` when `key: [u8; N]` is statically sized; use `new_from_slice` when key comes from a slice (`&kul[0..16]`). Note: `Hmac::<D>::new_from_slice` accepts **any** key length (`0..=usize::MAX`). |
| **`KeyIvInit`** | `cbc::Encryptor<C>`, `cbc::Decryptor<C>`, `cfb_mode::Encryptor<C>`, `cfb_mode::Decryptor<C>`, `cfb_mode::BufEncryptor<C>` | `new(key: &Key<Self>, iv: &Iv<Self>) -> Self`<br>`new_from_slices(key: &[u8], iv: &[u8]) -> Result<Self, InvalidLength>` | Returns `Err(InvalidLength)` if either `key.len() != KeySize::USIZE` or `iv.len() != IvSize::USIZE`. |

### 3.2 Encryption & Decryption Trait Matrix (`cipher 0.5.2`)

| Trait / Method Group | Implemented By | Core Operations | When to Choose |
| :--- | :--- | :--- | :--- |
| **`BlockCipherEncrypt` / `BlockCipherDecrypt`** | `Aes128`, `Aes192`, `Aes256`, `Des`, `TdesEde2`, `TdesEde3` | `encrypt_block(&self, block: &mut Block<Self>)`<br>`encrypt_block_b2b(&self, in: &Block<Self>, out: &mut Block<Self>)`<br>`encrypt_blocks(&self, blocks: &mut [Block<Self>])` | **Raw single-block primitives ONLY** (e.g., building custom CMAC, key-wrap, or hardware test vectors). **NEVER** use directly over multi-block messages (equivalent to insecure ECB mode). |
| **`BlockModeEncrypt`** | `cbc::Encryptor<C>`, `cfb_mode::Encryptor<C>` | `encrypt_padded<P: Padding>(self, buf: &mut [u8], pt_len: usize) -> Result<&[u8], PadError>`<br>`encrypt_padded_b2b<P: Padding>(self, pt: &[u8], out: &mut [u8]) -> Result<&[u8], PadError>`<br>`encrypt_blocks_inout(&mut self, blocks: InOutBuf<Block<Self>>)` | **Block-aligned modes (CBC)**. Consumes `self` when finalizing padding (`encrypt_padded`), returning the exact slice `&buf[..ct_len]` containing the padded ciphertext. |
| **`BlockModeDecrypt`** | `cbc::Decryptor<C>`, `cfb_mode::Decryptor<C>` | `decrypt_padded<P: Padding>(self, buf: &mut [u8]) -> Result<&[u8], block_padding::Error>`<br>`decrypt_padded_b2b<P: Padding>(self, ct: &[u8], out: &mut [u8]) -> Result<&[u8], block_padding::Error>`<br>`decrypt_blocks_inout(&mut self, blocks: InOutBuf<Block<Self>>)` | **Block-aligned modes (CBC)**. Consumes `self`, decrypts in-place or buffer-to-buffer, validates padding `P`, and returns the unpadded plaintext slice `&buf[..pt_len]`. |
| **Inherent `cfb_mode` Byte-Stream Methods** | `cfb_mode::Encryptor<C>`, `cfb_mode::Decryptor<C>` | `encrypt(self, data: &mut [u8])`<br>`decrypt(self, data: &mut [u8])`<br>`encrypt_b2b(self, in: &[u8], out: &mut [u8]) -> Result<(), NotEqualError>`<br>`encrypt_inout(self, data: InOutBuf<u8>)` | **Full-block CFB mode (SNMPv3 AES-128/192/256-CFB)**. Operates on arbitrary byte lengths (`data.len()` does not need to be a multiple of 16 bytes) without block padding! |
| **Buffered CFB State** | `cfb_mode::BufEncryptor<C>`, `cfb_mode::BufDecryptor<C>` | `encrypt(&mut self, data: &mut [u8])`<br>`get_state(&self) -> (&Iv<C>, usize)`<br>`from_state(cipher: C, iv: Iv<C>, pos: usize) -> Self` | **Streaming/chunked CFB encryption** across non-contiguous network fragments where internal feedback state (`iv`, `pos`) must persist across chunks. |

### 3.3 Block Padding Selection Matrix (`block-padding 0.4.2`)

In `block-padding 0.4.2`, `pub trait Padding: 'static` has **zero** type parameters and returns `PaddedData<'_, B>` from `P::pad_detached::<B>` and `Result<&[u8], block_padding::Error>` from `P::unpad::<B>(blocks: &[Block<B>])`:

| Padding Type | `PaddedData` Variant on `pos == 0` | Wire Format Rule | Reversible for Arbitrary Binary Data? | Protocol & RFC Use Cases |
| :--- | :--- | :--- | :--- | :--- |
| **`Pkcs7`** | `PaddedData::Pad` | Appends `N` bytes (`1 <= N <= B`), each equal to `N as u8`. Always adds a full block (`B` bytes) if `pt_len % B == 0`. | **Yes** (unambiguous). | General-purpose CBC encryption, TLS, IPsec ESP, Kerberos, CMS/PKCS#7. |
| **`Iso7816`** | `PaddedData::Pad` | Appends `0x80` followed by `0..B-1` zero bytes (`0x00`). Always adds at least 1 byte. | **Yes** (unambiguous). | Smartcard APDU payloads (ISO/IEC 7816-4), cryptographic tokens. |
| **`AnsiX923`** | `PaddedData::Pad` | Appends `0..B-1` zero bytes (`0x00`) followed by a final byte equal to the pad length `N`. | **Yes** (unambiguous). | Financial messaging standards (ANSI X9.23), legacy TLS/SSL. |
| **`Iso10126`** | `PaddedData::Pad` | Unpad reads the last byte `N` (`1 <= N <= B`) and strips `N` trailing bytes without inspecting intermediate pad bytes (`pad` falls back to `AnsiX923`). | **Yes** (unambiguous). | Legacy XML Encryption (W3C XMLENC) and ISO 10126-2. |
| **`ZeroPadding`** | `PaddedData::NoPad` | Appends `0x00` bytes **only** if `pt_len % B != 0` (`1..=B-1` bytes). **Adds `0` bytes if `pt_len % B == 0`!** | **No** for binary data ending in `0x00` (unpad strips all trailing `0x00`). | **SNMPv3 USM DES-CBC Encryption (`usmDESPrivProtocol`, RFC 3414 §8.1.1.2)**. |
| **`NoPadding`** | `PaddedData::NoPad` | Adds `0` bytes (`PaddedData::Error` if `pos != 0`). `unpad` returns the full block slice unchanged. | **Yes** (for pre-aligned or self-delimiting BER inputs). | **SNMPv3 USM DES-CBC BER Decryption**, pre-aligned blocks, custom trailers. |

> **CRITICAL — SNMPv3 DES-CBC `ZeroPadding` vs. `NoPadding` BER Decryption Invariant (`tests/snmp_spec_tests.rs:194`)**:
> - When **encrypting** an ASN.1 BER `ScopedPdu` with DES-CBC (RFC 3414 §8.1.1.2), always use `encrypt_padded::<ZeroPadding>(&mut buf, pt_len)` and convert the returned slice (`ct.to_vec()`). It appends `0` bytes when `pt_len % 8 == 0` (`PaddedData::NoPad`) and `1..=7` `0x00` bytes when `pt_len % 8 != 0`.
> - When **decrypting** a DES-CBC `EncryptedPdu`, **do NOT pass the slice returned by `decrypt_padded::<ZeroPadding>` to `rasn::ber::decode`**! If the final VarBind in the `ScopedPdu` ends in `0x00` (for example, `INT 0` = `02 01 00` or `NULLVAL` = `05 00`) and the `ScopedPdu` length is an exact multiple of 8 bytes, `ZeroPadding::unpad` strips the valid trailing `0x00` byte(s) of the BER TLV from the returned slice!
> - Instead, because an ASN.1 BER `ScopedPdu` (`0x30`) is self-delimiting via its outer TLV length header, always decrypt using **`decrypt_padded::<NoPadding>(&mut buf)`** and pass the full decrypted slice to `rasn::ber::decode::<ScopedPdu>`.

---

## 4. Deep Dive: Cryptographic Digests & HMAC (`digest 0.11.3`, `hmac 0.13.0`)

### 4.1 Digest Algorithm Matrix

| Struct | Crate | Output Size (`OutputSize`) | Internal Block Size (`BlockSize`) | OID (`const-oid`) | SNMPv3 USM / Protocol Usage |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`Md5`** | `md-5 0.11.0` | `16` bytes (`U16`, 128-bit) | `64` bytes (`U64`) | `1.2.840.113549.2.5` | RFC 3414 `usmHMACMD5AuthProtocol` (`12`B MAC), RADIUS Authenticator & User-Password XOR, TACACS+ pseudo-pad (`MD5(session_id \|\| key \|\| version \|\| seq_no)`). |
| **`Sha1`** | `sha1 0.11.0` | `20` bytes (`U20`, 160-bit) | `64` bytes (`U64`) | `1.3.14.3.2.26` | RFC 3414 `usmHMACSHAAuthProtocol` (`12`B MAC), STUN RFC 5389 `MESSAGE-INTEGRITY` (`20`B HMAC-SHA1), WebSocket RFC 6455 `Sec-WebSocket-Accept`. |
| **`Sha224`** | `sha2 0.11.1` | `28` bytes (`U28`, 224-bit) | `64` bytes (`U64`) | `2.16.840.1.101.3.4.2.4` | RFC 7860 `usmHMAC128SHA224AuthProtocol` (`16`B truncated MAC). |
| **`Sha256`** | `sha2 0.11.1` | `32` bytes (`U32`, 256-bit) | `64` bytes (`U64`) | `2.16.840.1.101.3.4.2.1` | RFC 7860 `usmHMAC192SHA256AuthProtocol` (`24`B truncated MAC). |
| **`Sha384`** | `sha2 0.11.1` | `48` bytes (`U48`, 384-bit) | `64` bytes (`U64`) | `2.16.840.1.101.3.4.2.2` | RFC 7860 `usmHMAC256SHA384AuthProtocol` (`32`B truncated MAC). |
| **`Sha512`** | `sha2 0.11.1` | `64` bytes (`U64`, 512-bit) | `128` bytes (`U128`) | `2.16.840.1.101.3.4.2.3` | RFC 7860 `usmHMAC384SHA512AuthProtocol` (`48`B truncated MAC). |

### 4.2 `Hmac<D>` vs. `HmacReset<D>` & `Mac::verify_truncated_left` (`hmac 0.13.0`)

1. **`Hmac<D>` vs. `HmacReset<D>` (`SimpleHmac<D>` vs. `SimpleHmacReset<D>`)**:
   - In `hmac 0.13.0`, `Hmac<D>` stores only the active inner hash state and finalized outer key pad to minimize stack footprint, so `Hmac<D>` **does not implement `digest::Reset` or `FixedOutputReset`**.
   - When you need to reuse a pre-keyed HMAC instance across multiple packets via `Mac::reset(&mut self)` or `FixedOutputReset::finalize_into_reset(&mut self, out)`, use **`hmac::HmacReset<D>`** (or `hmac::SimpleHmacReset<D>`).
2. **Full & Left-Truncated Constant-Time MAC Verification**:
   - **Full tag (`OutputSize` bytes)**: Call `mac.verify_slice(candidate_tag) -> Result<(), MacError>`.
   - **Left-truncated wire tag (`12`/`16`/`24`/`32`/`48` bytes)**: Call `mac.verify_truncated_left(candidate_tag) -> Result<(), MacError>` **only after** verifying `candidate_tag.len() == expected_wire_len`! Because `verify_truncated_left` accepts any slice length in `1..=OutputSize::USIZE` (even a 1-byte tag!), callers **must** check the exact protocol-mandated tag length first.

---

## 5. Deep Dive: SNMPv3 USM Cryptographic Pipeline (RFC 3414, RFC 3826, RFC 7860, & Draft Blumenthal AES-192/256)

### 5.1 RFC 3414 §A.2.1 & RFC 7860 1-Megabyte Key Localization (`Ku` -> `Kul`)

1. **Empty-Password Guardrail (CRITICAL)**: Always check `if password.is_empty() { return Vec::new(); }` before indexing `password[password_index % password.len()]`.
2. **Pass 1 — Master Key (`Ku`, 1,048,576 bytes = $2^{20}$ bytes)**: Stream `16,384` chunks of `64` bytes into `D::new()` and finalize into `ku`.
3. **Pass 2 — Localized Key (`Kul`)**: Compute `Kul = Hash(Ku || engine_id || Ku)` (`16`B for `Md5`, `20`B for `Sha1`, `28`B for `Sha224`, `32`B for `Sha256`, `48`B for `Sha384`, `64`B for `Sha512`).

### 5.2 SNMPv3 USM Privacy Protocols: DES-CBC, AES-128-CFB, & Blumenthal AES-192/256-CFB

| Feature | **DES-CBC (`usmDESPrivProtocol`, RFC 3414 §8.1.1)** | **AES-128-CFB (`usmAesCfb128Protocol`, RFC 3826 §3.1.2)** | **Blumenthal AES-192 / AES-256-CFB (`draft-blumenthal-aes-usm-04`)** |
| :--- | :--- | :--- | :--- |
| **RustCrypto Mode Type** | `cbc::Encryptor<des::Des>` / `cbc::Decryptor<des::Des>` | `cfb_mode::Encryptor<aes::Aes128>` / `cfb_mode::Decryptor<aes::Aes128>` | `cfb_mode::Encryptor<aes::Aes192>` / `cfb_mode::Encryptor<aes::Aes256>` |
| **Required Key Slice** | `16` bytes: `des_key = &kul[0..8]`, `pre_iv = &kul[8..16]` | `16` bytes: `aes_key = &kul[0..16]` | `24` bytes (`Aes192`) or `32` bytes (`Aes256`). If `kul.len() < needed` (e.g. `Md5`/`Sha1`), extend via `Kul_next = localize(Kul_prev, engine_id)`! |
| **IV Construction** | **8 bytes**: `iv[i] = pre_iv[i] ^ salt[i]` | **16 bytes**: `boots_be4 \|\| time_be4 \|\| salt_8` | **16 bytes**: `boots_be4 \|\| time_be4 \|\| salt_8` |
| **Padding Strategy** | Encrypt: `ZeroPadding`; BER Decrypt: **`NoPadding`** | **None** (CFB-128 stream mode) | **None** (CFB-128 stream mode) |

---

## 6. Multi-Protocol Network Cryptography (RADIUS, TACACS+, STUN, WebSocket)

1. **RADIUS (RFC 2865)**:
   - **Response Authenticator (`Access-Accept`/`Reject`/`Challenge`, `Accounting-Response`)**: `MD5(Code || ID || Length_be2 || ReqAuth_16B || ResponseAttributes || Secret)`.
   - **User-Password Attribute (Attr 2, RFC 2865 §5.2)**: Pad password with `0x00` to a multiple of 16 bytes ($p_1 \dots p_k$). XOR-chain 16-byte blocks: $c_1 = p_1 \oplus \text{MD5}(\text{Secret} \parallel \text{ReqAuth})$, $c_i = p_i \oplus \text{MD5}(\text{Secret} \parallel c_{i-1})$.
2. **TACACS+ Body Obfuscation (RFC 8907 §4.5)**:
   - When `flags & 0x01 == 0` (`TAC_PLUS_UNENCRYPTED_FLAG` not set), XOR the body after the 12-byte header with the concatenated MD5 pseudo-pad: $h_1 = \text{MD5}(\text{session\_id\_be4} \parallel \text{key} \parallel \text{version} \parallel \text{seq\_no})$ and $h_i = \text{MD5}(\text{session\_id\_be4} \parallel \text{key} \parallel \text{version} \parallel \text{seq\_no} \parallel h_{i-1})$.
3. **STUN (RFC 5389 §15.4) & WebSocket (RFC 6455 §4.2.2)**:
   - **STUN `MESSAGE-INTEGRITY` (`0x0008`)**: 20-byte `Hmac<Sha1>` computed over the STUN message up to (but excluding) the `MESSAGE-INTEGRITY` TLV, with the STUN header length field adjusted to include the 24-byte `MESSAGE-INTEGRITY` attribute.
   - **WebSocket `Sec-WebSocket-Accept`**: Base64 encoding of the 20-byte `Sha1` digest of `format!("{client_key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11")`.

---

## 7. Reference Links

- **Production Code Templates**: See [`references/patterns.md`](file:///home/steve/frameassembly/.agents/skills/rustcrypto-engineering/references/patterns.md) for 10 self-contained, compile-verified implementation templates covering AES-CBC, SNMPv3 USM 1MB key localization, AES-128-CFB, DES-CBC with `ZeroPadding` encrypt and `NoPadding` BER decrypt, 3DES, resumable `BufEncryptor`, multi-algorithm digests, `verify_truncated_left` + `HmacReset<D>`, `block-padding 0.4.2` pipelines, and RADIUS / TACACS+ / STUN / WebSocket / Blumenthal AES-192/256 network crypto.
- **Guardrails & Best Practices**: See [`.agents/rules/rustcrypto-best-practices.md`](file:///home/steve/frameassembly/.agents/rules/rustcrypto-best-practices.md).
