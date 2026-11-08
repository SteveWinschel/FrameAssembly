//! Link Aggregation Control Protocol (LACP, IEEE 802.3ad / 802.1AX) Layer 2 PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for IEEE 802.3ad / 802.1AX
//! Link Aggregation Control Protocol (`LACP`, Slow Protocols EtherType `0x8809`, subtype `0x01`)
//! frames in FrameAssembly. It decodes Actor and Partner TLV parameters including system MAC
//! identifiers (`actor_sys`, `partner_sys`), operational keys (`actor_key`, `partner_key`), port
//! numbers (`actor_port`, `partner_port`), and state bitmasks (`actor_state`, `partner_state`).

use alloc::string::String;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::topology::is_unicast_mac;
use crate::reverse::{
    ProtocolDissection, be_u16, format_mac_lower, mac_at, push_hex, push_if, push_mac_if, sd,
};

/// Decompiles an IEEE 802.3ad `LACP` frame (`0x8809`) into a [`ProtocolDissection`].
pub(crate) fn dissect_lacp(b: &[u8], src_mac: [u8; 6], dst_mac: [u8; 6]) -> ProtocolDissection {
    let mut t = String::from("lacp");
    push_mac_if(&mut t, "actor_sys", mac_at(b, 6), src_mac);
    push_if(&mut t, "actor_key", be_u16(b, 12), 1);
    push_if(&mut t, "actor_port", be_u16(b, 16), 1);
    push_hex(&mut t, "actor_state", u64::from(b[18]), 0x3D, 2);
    let psys = mac_at(b, 26);
    if !is_unicast_mac(dst_mac) || psys != dst_mac {
        let _ = write!(t, " partner_sys {}", format_mac_lower(psys));
    }
    push_if(&mut t, "partner_key", be_u16(b, 32), 1);
    push_if(&mut t, "partner_port", be_u16(b, 36), 1);
    push_hex(&mut t, "partner_state", u64::from(b[38]), 0x3D, 2);
    sd(Protocol::Lacp, t, b[110..].to_vec())
}
