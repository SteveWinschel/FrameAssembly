//! Generic Network Virtualization Encapsulation (GENEVE, RFC 8926) Layer 3 wire builder.
//!
//! Serializes a [`GeneveSpec`] into an RFC 8926 GENEVE tunnel frame carried over UDP destination
//! port `6081`. The 8-byte fixed GENEVE header encodes a 2-bit `Ver` (`0`) and 6-bit `Opt Len`
//! (`1` when an `OPT_CLASS` TLV option is present, `0` otherwise), an 8-bit `Flags` byte (`0`),
//! a 16-bit IEEE EtherType `Protocol Type` (`PROTOCOL_TYPE`, default `0x6558` Transparent Ethernet
//! Bridging), a 24-bit big-endian Virtual Network Identifier (`VNI`, default `4096`), and an 8-bit
//! `Reserved` zero byte, optionally followed by a 4-byte TLV option header (`OPT_CLASS`, `OPT_TYPE`)
//! and the inner passenger frame.
//!
//! Canonical `.fasm` syntax:
//! `a -> b GENEVE [VNI <u24>] [OPT_CLASS <u16>] [OPT_TYPE <u8>] [PROTOCOL_TYPE <u16>] [PAYLOAD "<str>" | HEXPAYLOAD "<hex>"]`

use crate::ast::*;
use alloc::vec::Vec;

/// Builds an RFC 8926 GENEVE overlay payload and returns `(bytes, 6081)` for UDP encapsulation.
pub fn build_geneve_payload(spec: &GeneveSpec, payload: &[u8]) -> (Vec<u8>, u16) {
    let vni = spec.vni.unwrap_or(4096) & 0x00FF_FFFF;
    let proto = spec.protocol_type.unwrap_or(0x6558); // Transparent Ethernet Bridging

    let opt_len = if spec.opt_class.is_some() { 1_u8 } else { 0_u8 };
    let mut geneve = Vec::with_capacity(12 + payload.len());
    // Ver (2 bits: 0), Opt Len (6 bits)
    geneve.push(opt_len & 0x3F);
    geneve.push(0); // Flags
    geneve.extend_from_slice(&proto.to_be_bytes());
    geneve.push((vni >> 16) as u8);
    geneve.push((vni >> 8) as u8);
    geneve.push(vni as u8);
    geneve.push(0); // Reserved

    if let Some(opt_class) = spec.opt_class {
        geneve.extend_from_slice(&opt_class.to_be_bytes());
        geneve.push(spec.opt_type.unwrap_or(0));
        geneve.push(0); // Length in 4-byte multiples
    }

    if payload.is_empty() {
        if proto == 0x6558 {
            // Synthesize a valid 14B Ethernet II + 20B IPv4 + 8B UDP inner passenger frame (42 bytes)
            let mut inner_ip = [
                0x45, 0x00, 0x00, 28, 0x00, 0x01, 0x00, 0x00, 64, 17, 0x00, 0x00, 10, 0, 0, 1,
                10, 0, 0, 2,
            ];
            let ip_cksum = crate::packet::internet_checksum(&[&inner_ip]);
            inner_ip[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

            geneve.extend_from_slice(&[0x00, 0x00, 0x5e, 0x00, 0x53, 0x02]); // Inner Dst MAC
            geneve.extend_from_slice(&[0x00, 0x00, 0x5e, 0x00, 0x53, 0x01]); // Inner Src MAC
            geneve.extend_from_slice(&0x0800_u16.to_be_bytes()); // Inner EtherType: IPv4
            geneve.extend_from_slice(&inner_ip);
            geneve.extend_from_slice(&[0x30, 0x39, 0x00, 0x50, 0x00, 0x08, 0x00, 0x00]); // Inner UDP
        } else {
            geneve.extend_from_slice(b"FrameAssembly GENEVE Inner Data");
        }
    } else {
        geneve.extend_from_slice(payload);
    }

    (geneve, 6081)
}

