//! GENEVE Layer 3 protocol wire builder.

use crate::ast::*;
use alloc::vec::Vec;

/// Builds an RFC 8926 GENEVE payload over UDP 6081.
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
        geneve.extend_from_slice(b"FrameAssembly GENEVE Inner Data");
    } else {
        geneve.extend_from_slice(payload);
    }

    (geneve, 6081)
}
