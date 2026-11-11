//! Spanning Tree Protocol (STP / RSTP, IEEE 802.1D / 802.1w) Layer 2 PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for IEEE 802.1D Spanning Tree
//! Protocol (`stp`) and IEEE 802.1w Rapid Spanning Tree Protocol (`rstp`) Bridge Protocol Data
//! Units (BPDUs) encapsulated in IEEE 802.3 LLC (`DSAP=0x42, SSAP=0x42, Control=0x03`). It decodes
//! BPDU version (`rstp`), topology flags (`flags`), root and bridge identifiers (`rootid`,
//! `bridgeid`), root path cost (`cost`), port identifier (`portid`), and timer fields (`maxage`,
//! `hellotime`, `forwarddelay`).

use alloc::format;
use alloc::string::String;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::{
    ProtocolDissection, be_u16, be_u32, format_mac_lower, mac_at, push_hex, push_if, sd,
};

/// Formats an 8-byte IEEE 802.1D Bridge Identifier (`<prio>:<mac>`).
fn format_stp_bridge_id(bytes: &[u8]) -> (u16, [u8; 6], String) {
    let (prio, mac) = (be_u16(bytes, 0), mac_at(bytes, 2));
    (prio, mac, format!("{prio}:{}", format_mac_lower(mac)))
}

/// Decompiles an IEEE 802.1D / 802.1w `stp` / `rstp` BPDU over 802.3 LLC (`0x424203`).
pub(crate) fn dissect_stp(bpdu: &[u8], src_mac: [u8; 6]) -> ProtocolDissection {
    let (is_rstp, flags) = (bpdu[2] >= 2, bpdu[4]);
    let (r_prio, r_mac, r_str) = format_stp_bridge_id(&bpdu[5..13]);
    let (b_prio, b_mac, b_str) = format_stp_bridge_id(&bpdu[17..25]);
    let mut t = String::from(if is_rstp { "stp rstp" } else { "stp" });
    push_hex(&mut t, "flags", u64::from(flags), 0x00, 2);
    if r_prio != 32768 || r_mac != src_mac {
        let _ = write!(t, " rootid \"{r_str}\"");
    }
    push_if(&mut t, "cost", be_u32(bpdu, 13), 0);
    if b_prio != 32768 || b_mac != src_mac {
        let _ = write!(t, " bridgeid \"{b_str}\"");
    }
    push_hex(&mut t, "portid", u64::from(be_u16(bpdu, 25)), 0x8001, 4);
    push_if(&mut t, "maxage", be_u16(bpdu, 29) >> 8, 20);
    push_if(&mut t, "hellotime", be_u16(bpdu, 31) >> 8, 2);
    push_if(&mut t, "forwarddelay", be_u16(bpdu, 33) >> 8, 15);
    let hdr_len = if is_rstp && bpdu.len() >= 36 { 36 } else { 35 };
    sd(
        Protocol::Stp,
        t,
        bpdu.get(hdr_len..).unwrap_or(&[]).to_vec(),
    )
}
