//! Generic Routing Encapsulation (GRE, RFC 2784 / RFC 2890) Layer 3 wire builder.
//!
//! Serializes a [`GreSpec`] into an RFC 2784 and RFC 2890 compliant GRE tunnel header encapsulated
//! directly over IPv4 or IPv6 using IP protocol number `47` (`0x2F`). The builder dynamically sets
//! the 16-bit GRE Flags word (`0x8000` Checksum Present `C` bit when `CHECKSUM` is specified,
//! `0x2000` Key Present `K` bit when `GRE_KEY` is present, and `0x1000` Sequence Number Present `S`
//! bit when `GRE_SEQ` is present), appends the 16-bit EtherType `Protocol Type` (`GRE_PROTO`,
//! default `0x0800`), optional 32-bit Checksum/Reserved, Key, and Sequence words, and the inner packet.
//!
//! Canonical `.fasm` syntax:
//! `a -> b GRE [GRE_KEY <u32>] [GRE_SEQ <u32>] [GRE_PROTO <u16>] [CHECKSUM] [PAYLOAD "<str>" | HEXPAYLOAD "<hex>"]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 2784 / RFC 2890 GRE tunnel payload and returns `(bytes, 47)` for IP encapsulation.
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

    if spec.checksum {
        let cksum = crate::packet::internet_checksum(&[&gre]);
        gre[4..6].copy_from_slice(&cksum.to_be_bytes());
    }

    (gre, 47)
}

