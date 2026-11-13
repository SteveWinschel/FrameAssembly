//! IPsec Encapsulating Security Payload (ESP, RFC 4303) Layer 3 wire builder.
//!
//! Serializes an [`IpsecSpec`] / [`EspSpec`] into an RFC 4303 IPsec ESP wire payload encapsulated
//! directly inside IPv4 or IPv6 with protocol / Next Header number `50` (`0x32`). The builder
//! writes the 32-bit big-endian Security Parameters Index (`spi`, default `0x1000`), 32-bit
//! big-endian Sequence Number (`seq`, default `1`), explicit Initialization Vector (`iv`, default
//! 8 zeroed bytes), encrypted payload (or 16-byte `0xAA` dummy ciphertext when unspecified), ESP
//! trailer (`Pad Length = 0` and `Next Header` default `59`), and trailing Integrity Check Value (`icv`).
//!
//! Canonical `.frasm` syntax:
//! `a -> b [esp | ipsec] [spi <u32>] [seq <u32>] [iv "<hex>"] [icv "<hex>"] [nextheader <u8>] [payload "<str>" | hexpayload "<hex>"]`

use crate::ast::*;
use alloc::vec::Vec;

/// Builds an RFC 4303 IPsec Encapsulating Security Payload (`esp`) body and returns `(bytes, 50)`.
pub fn build_ipsec_esp_payload(spec: &IpsecSpec, payload: &[u8]) -> (Vec<u8>, u8) {
    let spi = spec.spi.unwrap_or(0x1000);
    let seq = spec.seq.unwrap_or(1);
    let next_hdr = spec.next_header.unwrap_or(59); // No Next Header

    let mut esp = Vec::with_capacity(32 + payload.len());
    esp.extend_from_slice(&spi.to_be_bytes());
    esp.extend_from_slice(&seq.to_be_bytes());

    if let Some(iv) = &spec.iv {
        esp.extend_from_slice(iv);
    } else {
        esp.extend_from_slice(&[0u8; 8]); // 8-byte IV
    }

    if payload.is_empty() {
        esp.extend_from_slice(&[0xAA; 16]); // Dummy ciphertext
    } else {
        esp.extend_from_slice(payload);
    }

    // Pad length 0, Next Header
    esp.push(0);
    esp.push(next_hdr);

    if let Some(icv) = &spec.icv {
        esp.extend_from_slice(icv);
    } else {
        esp.extend_from_slice(&[0u8; 12]); // 12-byte HMAC-SHA1-96 ICV
    }

    (esp, 50)
}
