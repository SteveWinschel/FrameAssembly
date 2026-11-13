//! Link Aggregation Control Protocol (LACP, IEEE 802.3ad / 802.1AX) Layer 2 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for IEEE 802.3ad / 802.1AX
//! Link Aggregation Control Protocol (`lacp`, Slow Protocols EtherType `0x8809`, subtype `0x01`)
//! frames in FrameAssembly. It decodes Actor and Partner TLV parameters including system MAC
//! identifiers (`actorsys`, `partnersys`), operational keys (`actorkey`, `partnerkey`), port
//! numbers (`actorport`, `partnerport`), and state bitmasks (`actorstate`, `partnerstate`).

use alloc::string::String;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::topology::is_unicast_mac;
use crate::reverse::{
    ProtocolDissection, be_u16, format_mac_lower, mac_at, push_hex, push_if, push_mac_if, sd,
};

/// Decompiles an IEEE 802.3ad `lacp` frame (`0x8809`) into a [`ProtocolDissection`].
pub(crate) fn dissect_lacp(b: &[u8], src_mac: [u8; 6], dst_mac: [u8; 6]) -> ProtocolDissection {
    let mut t = String::from("lacp");
    push_mac_if(&mut t, "actorsys", mac_at(b, 6), src_mac);
    push_if(&mut t, "actorkey", be_u16(b, 12), 1);
    push_if(&mut t, "actorport", be_u16(b, 16), 1);
    push_hex(&mut t, "actorstate", u64::from(b[18]), 0x3D, 2);
    let psys = mac_at(b, 26);
    if !is_unicast_mac(dst_mac) || psys != dst_mac {
        let _ = write!(t, " partnersys {}", format_mac_lower(psys));
    }
    push_if(&mut t, "partnerkey", be_u16(b, 32), 1);
    push_if(&mut t, "partnerport", be_u16(b, 36), 1);
    push_hex(&mut t, "partnerstate", u64::from(b[38]), 0x3D, 2);
    sd(Protocol::Lacp, t, b[110..].to_vec())
}
