//! Intelligent Platform Management Interface (`ipmi`) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RMCP, ASF v2.0, IPMI v1.5, and
//! IPMI v2.0 (`RMCP+`) management datagrams carried over UDP port `623`. It validates the 4-byte
//! RMCP header, dissects ASF Presence `ping` and `pong` messages, checks IPMI v1.5 and RMCP+ v2.0
//! session wrappers and pre-session (`opensession`, `opensessionresp`, `rakp1` through `rakp4`)
//! bodies, verifies IPMB header and body checksums, and preserves trailing bytes in `residual_payload`.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::Protocol;
use crate::reverse::ProtocolDissection;

use super::ok_dissect;

/// Canonical 16-byte ASF v2.0 Presence Pong payload used to elide default Pong data.
const DEFAULT_ASF_PONG_DATA: [u8; 16] = [
    0x00, 0x00, 0x11, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Canonical 32-byte RMCP+ Open Session Request template suffix (from byte 1 onward).
const OPEN_SESSION_REQ_TAIL: [u8; 31] = [
    0x04, 0x00, 0x00, 0x44, 0x33, 0x22, 0x11, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
];

/// Canonical 36-byte RMCP+ Open Session Response template suffix (from byte 2 onward).
const OPEN_SESSION_RESP_TAIL: [u8; 34] = [
    0x04, 0x00, 0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x08, 0x00, 0x00,
    0x00, 0x00,
];

/// Reads a checked little-endian `u32` from `buf` at `off`.
fn checked_le_u32(buf: &[u8], off: usize) -> Option<u32> {
    let b = buf.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Dissects an RMCP / ASF / IPMI v1.5 / RMCP+ v2.0 packet on UDP port `623`.
pub(crate) fn dissect_ipmi(payload: &[u8]) -> Option<ProtocolDissection> {
    if payload.len() < 12 || payload.get(0..3)? != [0x06, 0x00, 0xFF] {
        return None;
    }

    match payload[3] {
        0x06 => dissect_asf(payload),
        0x07 => dissect_ipmi_session(payload),
        _ => None,
    }
}

/// Dissects an RMCP ASF v2.0 Presence Ping (`0x80`) or Presence Pong (`0x40`) frame.
fn dissect_asf(payload: &[u8]) -> Option<ProtocolDissection> {
    if payload.get(4..8)? != [0x00, 0x00, 0x11, 0xBE] || payload.get(10) != Some(&0x00) {
        return None;
    }
    let mtype = match payload[8] {
        0x80 => "ping",
        0x40 => "pong",
        _ => return None,
    };
    let msg_tag = payload[9];
    let data_len = usize::from(payload[11]);
    let data = payload.get(12..)?;
    if data.len() != data_len {
        return None;
    }

    let mut tokens = alloc::format!("ipmi {mtype}");
    if msg_tag != 0 {
        let _ = write!(tokens, " seqnum {msg_tag}");
    }
    let residual = if mtype == "pong" && data == DEFAULT_ASF_PONG_DATA {
        Vec::new()
    } else {
        data.to_vec()
    };
    ok_dissect(Protocol::Ipmi, tokens, residual)
}

/// Dissects an IPMI v1.5 or RMCP+ v2.0 session-wrapped packet.
fn dissect_ipmi_session(payload: &[u8]) -> Option<ProtocolDissection> {
    let auth_type = *payload.get(4)?;
    if auth_type == 0x00 {
        // IPMI v1.5 unauthenticated session
        if payload.len() < 21 {
            return None;
        }
        let seq_num = checked_le_u32(payload, 5)?;
        let session_id = checked_le_u32(payload, 9)?;
        let ipmb_len = usize::from(*payload.get(13)?);
        let ipmb = payload.get(14..)?;
        if ipmb.len() != ipmb_len {
            return None;
        }
        return dissect_ipmb_and_emit(1, session_id, seq_num, ipmb);
    }

    if auth_type == 0x06 {
        // IPMI v2.0 RMCP+
        if payload.len() < 16 {
            return None;
        }
        let ptype = payload[5];
        let session_id = checked_le_u32(payload, 6)?;
        let seq_num = checked_le_u32(payload, 10)?;
        let plen = usize::from(u16::from_le_bytes([payload[14], payload[15]]));
        let body = payload.get(16..)?;
        if body.len() != plen {
            return None;
        }

        if ptype == 0x00 {
            return dissect_ipmb_and_emit(2, session_id, seq_num, body);
        }

        let kw = match ptype {
            0x10 => "opensession",
            0x11 => "opensessionresp",
            0x12 => "rakp1",
            0x13 => "rakp2",
            0x14 => "rakp3",
            0x15 => "rakp4",
            _ => return None,
        };
        let mut tokens = alloc::format!("ipmi msgtype \"{kw}\"");
        if session_id != 0 {
            let _ = write!(tokens, " sessionid 0x{session_id:08x}");
        }
        if seq_num != 0 {
            let _ = write!(tokens, " seqnum {seq_num}");
        }
        let residual = match ptype {
            0x10 if body.len() == 32 && body.get(1..) == Some(&OPEN_SESSION_REQ_TAIL) => {
                if body[0] != 0 {
                    let _ = write!(tokens, " rqseq {}", body[0]);
                }
                Vec::new()
            }
            0x11 if body.len() == 36 && body.get(2..) == Some(&OPEN_SESSION_RESP_TAIL) => {
                if body[0] != 0 {
                    let _ = write!(tokens, " rqseq {}", body[0]);
                }
                if body[1] != 0 {
                    let _ = write!(tokens, " status {}", body[1]);
                }
                Vec::new()
            }
            0x12 if body.len() == 28
                && body.get(1..8) == Some(&[0x00, 0x00, 0x00, 0x88, 0x77, 0x66, 0x55])
                && body.get(8..24) == Some(&[0xA1u8; 16])
                && body.get(24..28) == Some(&[0x04, 0x00, 0x00, 0x00]) =>
            {
                if body[0] != 0 {
                    let _ = write!(tokens, " rqseq {}", body[0]);
                }
                Vec::new()
            }
            0x13 if body.len() == 40
                && body.get(2..8) == Some(&[0x00, 0x00, 0x44, 0x33, 0x22, 0x11])
                && body.get(8..24) == Some(&[0xB2u8; 16])
                && body.get(24..40) == Some(&[0xC3u8; 16]) =>
            {
                if body[0] != 0 {
                    let _ = write!(tokens, " rqseq {}", body[0]);
                }
                if body[1] != 0 {
                    let _ = write!(tokens, " status {}", body[1]);
                }
                Vec::new()
            }
            0x14 if body.len() == 8
                && body.get(2..8) == Some(&[0x00, 0x00, 0x88, 0x77, 0x66, 0x55]) =>
            {
                if body[0] != 0 {
                    let _ = write!(tokens, " rqseq {}", body[0]);
                }
                if body[1] != 0 {
                    let _ = write!(tokens, " status {}", body[1]);
                }
                Vec::new()
            }
            0x15 if body.len() == 8
                && body.get(2..8) == Some(&[0x00, 0x00, 0x44, 0x33, 0x22, 0x11]) =>
            {
                if body[0] != 0 {
                    let _ = write!(tokens, " rqseq {}", body[0]);
                }
                if body[1] != 0 {
                    let _ = write!(tokens, " status {}", body[1]);
                }
                Vec::new()
            }
            _ => body.to_vec(),
        };
        return ok_dissect(Protocol::Ipmi, tokens, residual);
    }

    None
}

/// Dissects a validated IPMB payload and emits canonical `ipmi` tokens.
fn dissect_ipmb_and_emit(
    version: u8,
    session_id: u32,
    seq_num: u32,
    ipmb: &[u8],
) -> Option<ProtocolDissection> {
    if ipmb.len() < 7 {
        return None;
    }
    let (rs_addr, netfn_lun, chk1) = (ipmb[0], ipmb[1], ipmb[2]);
    if rs_addr.wrapping_add(netfn_lun).wrapping_add(chk1) != 0 {
        return None;
    }
    let body_sum = ipmb[3..].iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    if body_sum != 0 {
        return None;
    }
    let netfn = netfn_lun >> 2;
    let lun1 = netfn_lun & 0x03;
    let rq_addr = ipmb[3];
    let rqseq_lun = ipmb[4];
    let rqseq = rqseq_lun >> 2;
    let lun2 = rqseq_lun & 0x03;
    let cmd = ipmb[5];
    let is_resp = (netfn & 1) == 1;
    let expected_addrs = if is_resp {
        rs_addr == 0x81 && rq_addr == 0x20
    } else {
        rs_addr == 0x20 && rq_addr == 0x81
    };
    if !expected_addrs || lun1 != lun2 {
        return None;
    }

    let (status, data_slice) = if is_resp {
        if ipmb.len() < 8 {
            return None;
        }
        (ipmb[6], &ipmb[7..ipmb.len() - 1])
    } else {
        (0u8, &ipmb[6..ipmb.len() - 1])
    };

    let mut tokens = String::from("ipmi");
    if version != 1 {
        let _ = write!(tokens, " version {version}");
    }
    if is_resp {
        tokens.push_str(" response");
        if netfn != 0x07 {
            let _ = write!(tokens, " netfn 0x{netfn:02x}");
        }
    } else if netfn != 0x06 {
        let _ = write!(tokens, " netfn 0x{netfn:02x}");
    }
    if cmd != 0x01 {
        let _ = write!(tokens, " cmd 0x{cmd:02x}");
    }
    if lun1 != 0 {
        let _ = write!(tokens, " lun {lun1}");
    }
    if rqseq != 1 {
        let _ = write!(tokens, " rqseq {rqseq}");
    }
    if session_id != 0 {
        let _ = write!(tokens, " sessionid 0x{session_id:08x}");
    }
    if seq_num != 0 {
        let _ = write!(tokens, " seqnum {seq_num}");
    }
    if is_resp && status != 0 {
        let _ = write!(tokens, " status 0x{status:02x}");
    }

    ok_dissect(Protocol::Ipmi, tokens, data_slice.to_vec())
}
