//! GRE Layer 3 protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 2784 / RFC 2890 GRE payload.
pub fn build_gre_payload(
    _ctx: &WireContext,
    spec: &GreSpec,
    payload: &[u8],
) -> (Vec<u8>, u8) {
    let mut flags: u16 = 0;
    if spec.checksum {
        flags |= 0x8000;
    }
    if spec.key.is_some() {
        flags |= 0x2000;
    }
    if spec.seq.is_some() {
        flags |= 0x1000;
    }

    let proto = spec.proto.unwrap_or(0x0800);
    let mut gre = Vec::with_capacity(16 + payload.len());
    gre.extend_from_slice(&flags.to_be_bytes());
    gre.extend_from_slice(&proto.to_be_bytes());

    if spec.checksum {
        gre.extend_from_slice(&0_u16.to_be_bytes()); // Checksum placeholder
        gre.extend_from_slice(&0_u16.to_be_bytes()); // Reserved
    }
    if let Some(key) = spec.key {
        gre.extend_from_slice(&key.to_be_bytes());
    }
    if let Some(seq) = spec.seq {
        gre.extend_from_slice(&seq.to_be_bytes());
    }

    if payload.is_empty() {
        gre.extend_from_slice(b"FrameAssembly GRE Inner Packet");
    } else {
        gre.extend_from_slice(payload);
    }

    (gre, 47)
}
