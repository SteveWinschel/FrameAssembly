//! Layer 2 Tunneling Protocol (L2TPv2 RFC 2661 & L2TPv3 RFC 3931) Layer 3 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for L2TPv2 over UDP port `1701`
//! and L2TPv3 over IP protocol `115` or UDP port `1701`. It distinguishes control messages (`T=1`
//! or L2TPv3 `Session ID == 0`) from `data` pseudowire frames, parses Message Type AVPs (`hello`,
//! `sccrq`, `sccrp`, `scccn`, `stopccn`), extracts `tunnelid`, `sessionid`, `ns`, `nr`, and
//! `flags`, preserves `transport udp` on L2TPv3-over-UDP frames, and elides default inner frames.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::{ProtocolDissection, be_u16, be_u32, push_hex, push_if, sd, sd_tp};

use super::is_default_overlay_inner;

/// Maps an L2TP control Message Type `u16` code to its lowercase `.frasm` keyword or string.
fn format_l2tp_msg_type(code: u16, t: &mut String) {
    match code {
        1 => t.push_str(" sccrq"),
        2 => t.push_str(" sccrp"),
        3 => t.push_str(" scccn"),
        4 => t.push_str(" stopccn"),
        6 => {} // Default HELLO elided
        other => {
            let _ = write!(t, " msgtype {other}");
        }
    }
}

/// Inspects control AVPs starting at `avps`, returning `(msg_type, assigned_sid, avp_consumed_len)`.
fn parse_l2tp_avps(avps: &[u8], ver: u8, tunnel_id: u32) -> (Option<u16>, Option<u32>, usize) {
    let mut pos = 0usize;
    let mut msg_code: Option<u16> = None;
    let mut assigned_sid: Option<u32> = None;
    let mut sccrq_seen = 0u8;

    while pos + 6 <= avps.len() {
        let len = (be_u16(avps, pos) & 0x03FF) as usize;
        if len < 6 || pos + len > avps.len() {
            break;
        }
        let vendor = be_u16(avps, pos + 2);
        let attr = be_u16(avps, pos + 4);
        let val = &avps[pos + 6..pos + len];
        if vendor == 0 && attr == 0 && val.len() == 2 && msg_code.is_none() {
            msg_code = Some(be_u16(val, 0));
            pos += len;
            continue;
        }
        if vendor == 0 && attr == 63 && val.len() == 4 && ver == 3 && assigned_sid.is_none() {
            assigned_sid = Some(be_u32(val, 0));
            pos += len;
            continue;
        }
        if msg_code == Some(1) && vendor == 0 {
            let is_default_sccrq_avp = match attr {
                2 => val == [0x01, 0x00],
                3 => val == [0, 0, 0, 3],
                7 => val == b"FrameAssembly",
                9 => ver == 2 && val == (tunnel_id as u16).to_be_bytes(),
                60 => ver == 3 && val == tunnel_id.to_be_bytes(),
                _ => false,
            };
            if is_default_sccrq_avp {
                sccrq_seen = sccrq_seen.saturating_add(1);
                pos += len;
                continue;
            }
        }
        break;
    }
    let _ = sccrq_seen;
    (msg_code, assigned_sid, pos)
}

/// Decompiles an L2TP control message whose header starts at `ctrl[0..]` (after any IP-115 `0` SID).
fn dissect_l2tp_control(
    ctrl: &[u8],
    ver: u8,
    explicit_tp: Option<TransportProto>,
) -> Option<ProtocolDissection> {
    if ctrl.len() < 12 {
        return None;
    }
    let flags_ver = be_u16(ctrl, 0);
    let has_len = (flags_ver & 0x4000) != 0;
    let has_seq = (flags_ver & 0x0800) != 0;
    if !has_len || !has_seq {
        return None;
    }
    let msg_len = be_u16(ctrl, 2) as usize;
    if msg_len < 12 || msg_len > ctrl.len() {
        return None;
    }

    let mut t = String::from("l2tp");
    if ver == 3 {
        t.push_str(" v3");
    }
    let (tunnel_id, session_id_opt) = if ver == 3 {
        (be_u32(ctrl, 4), None)
    } else {
        (u32::from(be_u16(ctrl, 4)), Some(u32::from(be_u16(ctrl, 6))))
    };
    let ns = be_u16(ctrl, 8);
    let nr = be_u16(ctrl, 10);

    let (msg_code, assigned_sid, avp_consumed) = parse_l2tp_avps(&ctrl[12..msg_len], ver, tunnel_id);
    if let Some(mc) = msg_code {
        format_l2tp_msg_type(mc, &mut t);
    }
    push_if(&mut t, "tunnelid", tunnel_id, 1);
    if let Some(sid) = session_id_opt {
        push_if(&mut t, "sessionid", sid, 0);
    } else if let Some(asid) = assigned_sid {
        let _ = write!(t, " sessionid {asid}");
    }
    push_if(&mut t, "ns", ns, 0);
    push_if(&mut t, "nr", nr, 0);
    let def_flags = if ver == 3 { 0xC803_u64 } else { 0xC802_u64 };
    push_hex(&mut t, "flags", u64::from(flags_ver), def_flags, 4);

    let mut res = ctrl[12 + avp_consumed..msg_len].to_vec();
    res.extend_from_slice(&ctrl[msg_len..]);
    Some(sd_tp(Protocol::L2tp, t, res, explicit_tp))
}

/// Decompiles an L2TPv2 (UDP `1701`) or L2TPv3 (IP proto `115` / UDP `1701`) payload.
pub(crate) fn dissect_l2tp(b: &[u8], over_ip: bool) -> Option<ProtocolDissection> {
    if over_ip {
        if b.len() < 4 {
            return None;
        }
        let sid = be_u32(b, 0);
        if sid == 0 {
            let ctrl = b.get(4..)?;
            if ctrl.len() < 12 || (be_u16(ctrl, 0) & 0x800F) != 0x8003 {
                return None;
            }
            return dissect_l2tp_control(ctrl, 3, None);
        }
        if b.len() < 8 {
            return None;
        }
        let mut t = String::from("l2tp v3 data");
        push_if(&mut t, "sessionid", sid, 1);
        if (b[4] & 0x40) != 0 {
            let _ = write!(t, " ns {}", be_u16(b, 6));
            if b[4] != 0x40 {
                push_hex(&mut t, "flags", u64::from(b[4]) << 8, 0x4000, 4);
            }
        }
        let inner = &b[8..];
        let rem = if is_default_overlay_inner(inner) {
            &[][..]
        } else {
            inner
        };
        return Some(sd(Protocol::L2tp, t, rem.to_vec()));
    }

    if b.len() < 8 {
        return None;
    }
    let flags_ver = be_u16(b, 0);
    let ver = (flags_ver & 0x000F) as u8;
    let is_ctrl = (flags_ver & 0x8000) != 0;

    if ver == 2 && (is_ctrl || (flags_ver & 0x34F0) == 0) {
        if is_ctrl {
            return dissect_l2tp_control(b, 2, None);
        }
        let has_len = (flags_ver & 0x4000) != 0;
        let has_seq = (flags_ver & 0x0800) != 0;
        let mut pos = 2usize;
        let mut end = b.len();
        if has_len {
            let l = be_u16(b, pos) as usize;
            if l < 6 || l > b.len() {
                return None;
            }
            end = l;
            pos += 2;
        }
        if pos + 4 > end {
            return None;
        }
        let tunnel_id = u32::from(be_u16(b, pos));
        let session_id = u32::from(be_u16(b, pos + 2));
        pos += 4;
        let mut ns = 0u16;
        let mut nr = 0u16;
        if has_seq {
            if pos + 4 > end {
                return None;
            }
            ns = be_u16(b, pos);
            nr = be_u16(b, pos + 2);
            pos += 4;
        }
        let mut t = String::from("l2tp data");
        push_if(&mut t, "tunnelid", tunnel_id, 1);
        push_if(&mut t, "sessionid", session_id, 1);
        if has_seq {
            let _ = write!(t, " ns {ns}");
            push_if(&mut t, "nr", nr, 0);
        }
        let def_flags = if has_seq { 0x4802_u64 } else { 0x4002_u64 };
        push_hex(&mut t, "flags", u64::from(flags_ver), def_flags, 4);

        let inner = &b[pos..end];
        let def_v4 = crate::builders::l3::gre::default_gre_inner_packet(0x0800);
        let is_def_ppp = inner.len() == 4 + def_v4.len()
            && inner[0..4] == [0xFF, 0x03, 0x00, 0x21]
            && inner[4..] == def_v4[..];
        let mut res = if is_def_ppp {
            Vec::new()
        } else {
            inner.to_vec()
        };
        res.extend_from_slice(&b[end..]);
        return Some(sd(Protocol::L2tp, t, res));
    }

    if ver == 3 && is_ctrl {
        return dissect_l2tp_control(b, 3, Some(TransportProto::Udp));
    }

    // L2TPv3 Data over UDP (4B non-zero Session ID + 4B L2-specific sublayer)
    let sid = be_u32(b, 0);
    if sid != 0 && b.len() >= 8 {
        let mut t = String::from("l2tp v3 data");
        push_if(&mut t, "sessionid", sid, 1);
        if (b[4] & 0x40) != 0 {
            let _ = write!(t, " ns {}", be_u16(b, 6));
            if b[4] != 0x40 {
                push_hex(&mut t, "flags", u64::from(b[4]) << 8, 0x4000, 4);
            }
        }
        let inner = &b[8..];
        let rem = if is_default_overlay_inner(inner) {
            &[][..]
        } else {
            inner
        };
        return Some(sd_tp(
            Protocol::L2tp,
            t,
            rem.to_vec(),
            Some(TransportProto::Udp),
        ));
    }

    None
}
