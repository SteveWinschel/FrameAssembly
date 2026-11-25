//! ISO/IEC 10589 IS-IS Layer 2 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for ISO/IEC 10589 IS-IS
//! routing PDUs over IEEE 802.3 LLC (`FE:FE:03`, Intradomain Routing Protocol Discriminator
//! `0x83`). It decodes LAN/P2P Hellos (`l1iih`, `l2iih`, `p2piih`), Link State PDUs (`l1lsp`,
//! `l2lsp`), and Sequence Numbers PDUs (`l1csnp`, `l2csnp`, `l1psnp`, `l2psnp`), along with
//! System ID, Area Addresses (`1`), Holdtime, Priority, LAN ID, Circuit Type, Remaining Lifetime,
//! Sequence Number, and Dynamic Hostname (`137`).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::l7::{checked_be_u16, checked_be_u32, quote_raw_str};
use crate::reverse::{ProtocolDissection, bytes_to_hex_lower, push_if, sd};

/// Formats a 6-byte IS-IS System ID in canonical dotted notation (`xxxx.xxxx.xxxx`).
fn format_isis_sysid(bytes: &[u8]) -> Option<String> {
    if bytes.len() != 6 {
        return None;
    }
    Some(format!(
        "{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    ))
}

/// Formats a 7-byte IS-IS LAN ID (`<sysid>.<pseudonode>`).
fn format_isis_lanid(bytes: &[u8]) -> Option<String> {
    if bytes.len() != 7 {
        return None;
    }
    Some(format!(
        "{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}.{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6]
    ))
}

/// Decompiles an ISO/IEC 10589 IS-IS PDU (with or without leading `FE:FE:03` LLC) into a [`ProtocolDissection`].
pub(crate) fn dissect_isis(b: &[u8], src_mac: [u8; 6]) -> ProtocolDissection {
    let pdu = b.strip_prefix(&[0xFE, 0xFE, 0x03]).unwrap_or(b);
    if pdu.len() < 17 || pdu.first().copied() != Some(0x83) {
        return sd(Protocol::Isis, String::from("isis"), pdu.to_vec());
    }

    let pdu_code = pdu.get(4).copied().unwrap_or(0) & 0x1F;
    let (kw, hdr_len, pdu_len_off): (&str, usize, usize) = match pdu_code {
        15 => ("", 27, 17),
        16 => ("l2iih", 27, 17),
        17 => ("p2piih", 20, 17),
        18 => ("l1lsp", 27, 8),
        20 => ("l2lsp", 27, 8),
        24 => ("l1csnp", 33, 8),
        25 => ("l2csnp", 33, 8),
        26 => ("l1psnp", 17, 8),
        27 => ("l2psnp", 17, 8),
        _ => return sd(Protocol::Isis, String::from("isis"), pdu.to_vec()),
    };

    let mut t = String::from("isis");
    if !kw.is_empty() {
        let _ = write!(t, " {kw}");
    }
    if pdu.len() < hdr_len {
        return sd(Protocol::Isis, t, pdu.get(8..).unwrap_or(&[]).to_vec());
    }

    let mut parsed_sid = src_mac;
    match pdu_code {
        15..=17 => {
            let def_ckt = match pdu_code {
                15 => 1,
                16 => 2,
                _ => 3,
            };
            let ckt = pdu.get(8).copied().unwrap_or(def_ckt) & 0x03;
            push_if(&mut t, "circuittype", ckt, def_ckt);
            if let Some(sid) = pdu.get(9..15) {
                parsed_sid.copy_from_slice(sid);
                if sid != src_mac
                    && let Some(sid_str) = format_isis_sysid(sid)
                {
                    let _ = write!(t, " sysid \"{sid_str}\"");
                }
            }
            if let Some(hold) = checked_be_u16(pdu, 15) {
                push_if(&mut t, "holdtime", hold, 30);
            }
            if pdu_code == 15 || pdu_code == 16 {
                let prio = pdu.get(19).copied().unwrap_or(64) & 0x7F;
                push_if(&mut t, "priority", prio, 64);
                if let Some(lid) = pdu.get(20..27)
                    && (lid[..6] != parsed_sid || lid[6] != 0x01)
                    && let Some(lid_str) = format_isis_lanid(lid)
                {
                    let _ = write!(t, " lanid \"{lid_str}\"");
                }
            }
        }
        18 | 20 => {
            if let Some(lifetime) = checked_be_u16(pdu, 10) {
                push_if(&mut t, "lifetime", lifetime, 1200);
            }
            if let Some(sid) = pdu.get(12..18)
                && sid != src_mac
                && let Some(sid_str) = format_isis_sysid(sid)
            {
                let _ = write!(t, " sysid \"{sid_str}\"");
            }
            if let Some(lid) = pdu.get(12..19)
                && lid[6] != 0x00
                && let Some(lid_str) = format_isis_lanid(lid)
            {
                let _ = write!(t, " lanid \"{lid_str}\"");
            }
            if let Some(seq) = checked_be_u32(pdu, 20) {
                push_if(&mut t, "seqnum", seq, 1);
            }
        }
        24..=27 => {
            if let Some(sid) = pdu.get(10..16)
                && sid != src_mac
                && let Some(sid_str) = format_isis_sysid(sid)
            {
                let _ = write!(t, " sysid \"{sid_str}\"");
            }
        }
        _ => {}
    }

    let has_default_area = matches!(pdu_code, 15 | 16 | 17 | 18 | 20);
    let tlv_limit = checked_be_u16(pdu, pdu_len_off)
        .map(usize::from)
        .unwrap_or(pdu.len())
        .min(pdu.len())
        .max(hdr_len);

    let mut pos = hdr_len;
    let mut ext = Vec::new();
    while pos + 2 <= tlv_limit {
        let Some(&tlv_type) = pdu.get(pos) else {
            break;
        };
        let Some(&tlv_len_u8) = pdu.get(pos + 1) else {
            break;
        };
        let tlv_len = usize::from(tlv_len_u8);
        let Some(end) = pos.checked_add(2).and_then(|v| v.checked_add(tlv_len)) else {
            break;
        };
        if end > tlv_limit {
            break;
        }
        let Some(val) = pdu.get(pos + 2..end) else {
            break;
        };
        let raw_tlv = pdu.get(pos..end).unwrap_or(&[]);
        pos = end;

        match tlv_type {
            1 => {
                let alen = val.first().copied().map(usize::from).unwrap_or(0);
                if alen >= 1
                    && 1 + alen == val.len()
                    && let Some(area) = val.get(1..1 + alen)
                {
                    if !(has_default_area && area == [0x49, 0x00, 0x01]) {
                        let _ = write!(t, " area \"{}\"", bytes_to_hex_lower(area));
                    }
                } else {
                    ext.extend_from_slice(raw_tlv);
                }
            }
            129 if has_default_area && val == [0xCC] => {}
            137 => {
                if let Ok(name) = core::str::from_utf8(val) {
                    let _ = write!(t, " hostname \"{}\"", quote_raw_str(name));
                } else {
                    ext.extend_from_slice(raw_tlv);
                }
            }
            _ => ext.extend_from_slice(raw_tlv),
        }
    }

    if let Some(rem) = pdu.get(pos..) {
        ext.extend_from_slice(rem);
    }

    sd(Protocol::Isis, t, ext)
}
