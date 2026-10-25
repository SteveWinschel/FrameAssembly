//! IPsec security protocol wire builders (RFC 4302 Authentication Header & RFC 4303 ESP).
//!
//! Re-exports the RFC 4302 IPsec Authentication Header wire builder ([`build_ipsec_ah_payload`], IP
//! protocol `51`) and the RFC 4303 IPsec Encapsulating Security Payload wire builder
//! ([`build_ipsec_esp_payload`], IP protocol `50`). Both builders serialize Security Parameters
//! Index (`SPI`), anti-replay Sequence Number (`SEQ`), Initialization Vector (`IV`), `Next Header`
//! (`NEXT_HEADER`), and Integrity Check Value (`ICV`) fields for transport-mode and tunnel-mode SAs.
//!
//! Canonical `.fasm` syntax:
//! `a -> b [IPSEC | ESP | AH] [SPI <u32>] [SEQ <u32>] [IV "<hex>"] [ICV "<hex>"] [NEXT_HEADER <u8>]`

use crate::ast::IpsecSpec;
use alloc::vec::Vec;

#[doc(inline)]
pub use super::ah::build_ipsec_ah_payload;

/// Builds an RFC 4303 IPsec Encapsulating Security Payload (`ESP`) body and returns `(bytes, 50)`.
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

