//! AH Layer 3 protocol wire builder.

use crate::ast::*;
use alloc::vec::Vec;

/// Builds an RFC 4302 IPsec AH packet body.
pub fn build_ipsec_ah_payload(spec: &AhSpec, payload: &[u8]) -> (Vec<u8>, u8) {
    let spi = spec.spi.unwrap_or(0x2000);
    let seq = spec.seq.unwrap_or(1);
    let next_hdr = spec.next_header.unwrap_or(59);

    let mut ah = Vec::with_capacity(24 + payload.len());
    ah.push(next_hdr);
    ah.push(4); // Payload Length in 4-byte words minus 2 (24 bytes total -> 4)
    ah.extend_from_slice(&[0, 0]); // Reserved
    ah.extend_from_slice(&spi.to_be_bytes());
    ah.extend_from_slice(&seq.to_be_bytes());

    if let Some(ref icv) = spec.icv {
        ah.extend_from_slice(icv);
    } else {
        ah.extend_from_slice(&[0u8; 12]); // 12-byte ICV
    }
    ah.extend_from_slice(payload);

    (ah, 51)
}
