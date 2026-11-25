//! Generic Network Virtualization Encapsulation (GENEVE, RFC 8926) Layer 3 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for RFC 8926 `geneve` overlay
//! tunnel packets carried over UDP port `6081`. It validates the GENEVE version and variable
//! option-length fields, extracts the 24-bit Virtual Network Identifier (`vni`), inner EtherType
//! (`protocoltype`), and optional TLV header (`optclass`, `opttype`), and elides the default
//! 42-byte FrameAssembly overlay inner frame when unchanged.

use alloc::string::String;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u16, be_u32, push_hex, push_if, sd};

use super::is_default_overlay_inner;

/// Decompiles an RFC 8926 `geneve` UDP payload (port `6081`) into a [`ProtocolDissection`].
pub(crate) fn dissect_geneve(b: &[u8]) -> Option<ProtocolDissection> {
    let obl = ((b.first()? & 0x3F) as usize) * 4;
    if b.len() < 8 + obl || (b[0] >> 6) != 0 {
        return None;
    }
    let proto = be_u16(b, 2);
    let (vni, mut t) = (be_u32(b, 4) >> 8, String::from("geneve"));
    push_if(&mut t, "vni", vni, 4096);
    push_hex(&mut t, "protocoltype", u64::from(proto), 0x6558, 4);
    if obl >= 4 {
        let _ = write!(t, " optclass 0x{:04x}", be_u16(b, 8));
        push_if(&mut t, "opttype", b[10], 0);
    }
    let inner = &b[8 + obl..];
    let is_default_inner = if proto == 0x6558 {
        is_default_overlay_inner(inner)
    } else if matches!(proto, 0x0800 | 0x86DD) {
        inner == crate::builders::l3::gre::default_gre_inner_packet(proto).as_slice()
    } else {
        inner == b"FrameAssembly GENEVE Inner Data"
    };
    let rem = if is_default_inner { &[][..] } else { inner };
    Some(sd(Protocol::Geneve, t, rem.to_vec()))
}
