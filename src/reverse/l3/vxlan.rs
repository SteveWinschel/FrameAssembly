//! Virtual eXtensible Local Area Network (VXLAN, RFC 7348) Layer 3 PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for RFC 7348 `vxlan` overlay
//! tunnel packets carried over UDP port `4789`. It validates the 8-byte VXLAN header and `I` flag
//! byte (`0x08`), extracts the 24-bit Virtual Network Identifier (`vni`), and elides the default
//! 42-byte FrameAssembly overlay inner frame when unchanged.

use alloc::string::String;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u32, push_if, sd};

use super::is_default_overlay_inner;

/// Decompiles an RFC 7348 `vxlan` UDP payload (port `4789`) into a [`ProtocolDissection`].
pub(crate) fn dissect_vxlan(b: &[u8]) -> Option<ProtocolDissection> {
    if b.len() < 8 || b[0] != 0x08 {
        return None;
    }
    let (vni, mut t) = (be_u32(b, 4) >> 8, String::from("vxlan"));
    push_if(&mut t, "vni", vni, 4096);
    let rem = if is_default_overlay_inner(&b[8..]) {
        &[][..]
    } else {
        &b[8..]
    };
    Some(sd(Protocol::Vxlan, t, rem.to_vec()))
}
