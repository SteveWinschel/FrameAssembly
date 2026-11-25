//! Label Distribution Protocol (LDP, RFC 5036) Layer 3 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for RFC 5036 Label
//! Distribution Protocol (`ldp`) PDUs over TCP and UDP port `646`. It validates the 10-byte LDP
//! PDU header (`Version = 1`) and 8-byte message header, decodes `hello`, `init`, `keepalive`,
//! `notification`, `labelmapping`, `labelrequest`, `labelwithdraw`, and `labelrelease` along with
//! `lsrid`, `labelspace`, `msgid`, `holdtime`, `label`, `prefix`, and `status`, preserving UDP/SCTP
//! transport flags cleanly.

use alloc::format;
use alloc::string::String;
use core::fmt::Write as _;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::ast::{Protocol, TransportProto};
use crate::reverse::{ProtocolDissection, be_u16, be_u32, ipv4_at, push_if, sd_tp};

/// Decompiles an RFC 5036 `ldp` PDU (TCP/UDP port `646`) into a [`ProtocolDissection`].
pub(crate) fn dissect_ldp(
    transport: TransportProto,
    is_ipv6: bool,
    b: &[u8],
    src_ip: Option<IpAddr>,
) -> Option<ProtocolDissection> {
    if b.len() < 18 || be_u16(b, 0) != 1 {
        return None;
    }
    let pdu_len = be_u16(b, 2) as usize;
    let pdu_end = 4usize.checked_add(pdu_len)?;
    if pdu_len < 14 || pdu_end > b.len() {
        return None;
    }
    let lsr_id = ipv4_at(b, 4);
    let label_space = be_u16(b, 8);
    let msg_code = be_u16(b, 10) & 0x7FFF;
    let msg_len = be_u16(b, 12) as usize;
    let msg_end = 14usize.checked_add(msg_len)?;
    if msg_len < 4 || msg_end > pdu_end {
        return None;
    }
    let msg_id = be_u32(b, 14);

    let msg_kw = match msg_code {
        0x0001 => "notification",
        0x0100 => "hello",
        0x0200 => "init",
        0x0201 => "keepalive",
        0x0400 => "labelmapping",
        0x0401 => "labelrequest",
        0x0402 => "labelwithdraw",
        0x0403 => "labelrelease",
        _ => return None,
    };

    let mut t = String::from("ldp");
    let is_udp = matches!(transport, TransportProto::Udp);
    let is_default_msg = (is_udp && msg_code == 0x0100) || (!is_udp && msg_code == 0x0201);
    if !is_default_msg {
        let _ = write!(t, " {msg_kw}");
    }

    let def_lsr = match src_ip {
        Some(IpAddr::V4(v4)) if !v4.is_unspecified() => v4,
        _ => Ipv4Addr::new(10, 0, 0, 1),
    };
    push_if(&mut t, "lsrid", lsr_id, def_lsr);
    push_if(&mut t, "labelspace", label_space, 0);
    push_if(&mut t, "msgid", msg_id, 1);

    let mut pos = 18usize;
    while pos + 4 <= msg_end {
        let tlv_type = be_u16(b, pos) & 0x3FFF;
        let tlv_len = be_u16(b, pos + 2) as usize;
        let val_start = pos + 4;
        let Some(val_end) = val_start.checked_add(tlv_len) else {
            break;
        };
        if val_end > msg_end {
            break;
        }
        let val = &b[val_start..val_end];
        match tlv_type {
            0x0400 if val.len() >= 2 => {
                push_if(&mut t, "holdtime", be_u16(val, 0), 15);
            }
            0x0500 if val.len() >= 4 => {
                push_if(&mut t, "holdtime", be_u16(val, 2), 45);
            }
            0x0300 if val.len() >= 4 => {
                push_if(&mut t, "status", be_u32(val, 0), 0);
            }
            0x0200 if val.len() >= 4 => {
                let lbl = be_u32(val, 0) & 0x000F_FFFF;
                if msg_code != 0x0400 || lbl != 16 {
                    let _ = write!(t, " label {lbl}");
                }
            }
            0x0100 if val.len() >= 4 && val[0] == 0x02 => {
                let afi = be_u16(val, 1);
                let plen = val[3];
                let blen = usize::from(plen).div_ceil(8);
                if afi == 1 && plen <= 32 && 4 + blen <= val.len() {
                    let mut oct = [0u8; 4];
                    for (i, &byte) in val[4..4 + blen].iter().enumerate() {
                        if i < 4 {
                            oct[i] = byte;
                        }
                    }
                    let ip = Ipv4Addr::from(oct);
                    if is_ipv6 || ip != Ipv4Addr::new(10, 0, 0, 0) || plen != 24 {
                        let pstr = format!("{ip}/{plen}");
                        let _ = write!(t, " prefix \"{pstr}\"");
                    }
                } else if afi == 2 && plen <= 128 && 4 + blen <= val.len() {
                    let mut oct = [0u8; 16];
                    for (i, &byte) in val[4..4 + blen].iter().enumerate() {
                        if i < 16 {
                            oct[i] = byte;
                        }
                    }
                    let ip = Ipv6Addr::from(oct);
                    if !is_ipv6 || ip != Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0) || plen != 32 {
                        let pstr = format!("{ip}/{plen}");
                        let _ = write!(t, " prefix \"{pstr}\"");
                    }
                }
            }
            _ => {}
        }
        pos = val_end;
    }

    let explicit_tp = if matches!(transport, TransportProto::Udp | TransportProto::Sctp) {
        Some(transport)
    } else {
        None
    };
    let res = b.get(pdu_end..).unwrap_or(&[]).to_vec();
    Some(sd_tp(Protocol::Ldp, t, res, explicit_tp))
}
