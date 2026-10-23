//! ESP Layer 3 protocol wire builder.

use crate::ast::*;
use alloc::vec::Vec;

/// Builds an RFC 4303 IPsec ESP packet body.
pub fn build_ipsec_esp_payload(spec: &IpsecSpec, payload: &[u8]) -> (Vec<u8>, u8) {
    let spi = spec.spi.unwrap_or(0x1000);
    let seq = spec.seq.unwrap_or(1);
    let next_hdr = spec.next_header.unwrap_or(59); // No Next Header

    let mut esp = Vec::with_capacity(32 + payload.len());
    esp.extend_from_slice(&spi.to_be_bytes());
    esp.extend_from_slice(&seq.to_be_bytes());

    if let Some(ref iv) = spec.iv {
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

    if let Some(ref icv) = spec.icv {
        esp.extend_from_slice(icv);
    } else {
        esp.extend_from_slice(&[0u8; 12]); // 12-byte HMAC-SHA1-96 ICV
    }

    (esp, 50)
}
