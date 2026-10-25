//! IPsec Authentication Header (AH, RFC 4302) Layer 3 wire builder.
//!
//! Serializes an [`AhSpec`] into an RFC 4302 IPsec Authentication Header payload encapsulated
//! directly inside IPv4 or IPv6 with protocol / Next Header number `51` (`0x33`). The wire builder
//! constructs a 24-byte base AH header containing the 8-bit `Next Header` (`NEXT_HEADER`, default
//! `59`), 8-bit `Payload Len` (`4` in 32-bit words minus 2), 16-bit zeroed `Reserved` field, 32-bit
//! big-endian `SPI` (default `0x2000`), 32-bit big-endian `Sequence Number` (`SEQ`, default `1`),
//! and 96-bit (or user-supplied) Integrity Check Value (`ICV`), followed by the authenticated payload.
//!
//! Canonical `.fasm` syntax:
//! `a -> b AH [SPI <u32>] [SEQ <u32>] [ICV "<hex>"] [NEXT_HEADER <u8>] [PAYLOAD "<str>" | HEXPAYLOAD "<hex>"]`

use crate::ast::*;
use alloc::vec::Vec;

/// Builds an RFC 4302 IPsec Authentication Header (`AH`) packet body and returns `(bytes, 51)`.
pub fn build_ipsec_ah_payload(spec: &AhSpec, payload: &[u8]) -> (Vec<u8>, u8) {
    let spi = spec.spi.unwrap_or(0x2000);
    let seq = spec.seq.unwrap_or(1);
    let next_hdr = spec.next_header.unwrap_or(59);

    let icv_bytes: &[u8] = if let Some(icv) = &spec.icv {
        icv
    } else {
        &[0u8; 12]
    };
    let hdr_len_words = ((12 + icv_bytes.len()).div_ceil(4)).saturating_sub(2) as u8;

    let mut ah = Vec::with_capacity(12 + icv_bytes.len() + payload.len());
    ah.push(next_hdr);
    ah.push(hdr_len_words); // Payload Length in 4-byte words minus 2 (24 bytes total -> 4)
    ah.extend_from_slice(&[0, 0]); // Reserved
    ah.extend_from_slice(&spi.to_be_bytes());
    ah.extend_from_slice(&seq.to_be_bytes());
    ah.extend_from_slice(icv_bytes);
    ah.extend_from_slice(payload);

    (ah, 51)
}

