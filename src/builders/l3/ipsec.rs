//! IPsec security protocol wire builders (RFC 4302 Authentication Header & RFC 4303 ESP).
//!
//! Re-exports the RFC 4302 IPsec Authentication Header wire builder ([`build_ipsec_ah_payload`], IP
//! protocol `51`) and the RFC 4303 IPsec Encapsulating Security Payload wire builder
//! ([`build_ipsec_esp_payload`], IP protocol `50`). Both builders serialize Security Parameters
//! Index (`spi`), anti-replay Sequence Number (`seq`), Initialization Vector (`iv`), `Next Header`
//! (`nextheader`), and Integrity Check Value (`icv`) fields for transport-mode and tunnel-mode SAs.
//!
//! Canonical `.frasm` syntax:
//! `a -> b [ipsec | esp | ah] [spi <u32>] [seq <u32>] [iv "<hex>"] [icv "<hex>"] [nextheader <u8>]`

use crate::ast::IpsecSpec;
use alloc::vec::Vec;

#[doc(inline)]
pub use super::ah::build_ipsec_ah_payload;

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

