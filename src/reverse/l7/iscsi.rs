//! Internet Small Computer Systems Interface (`iscsi`, RFC 7143) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for RFC 7143 `iscsi` PDUs over TCP
//! and SCTP port `3260` (plus custom ports carrying valid `Login` or `SCSI` BHS frames). It
//! validates the 48-byte Basic Header Segment (`TotalAHSLength == 0`, 24-bit `DataSegmentLength`,
//! and zeroed 4-byte alignment padding), decodes `Login`, `Logout`, `SCSI Command` (`INQUIRY`,
//! `READ(10)`, `WRITE(10)`), `SCSI Response`, `Data-In`/`Data-Out`, `NOP-Out`/`NOP-In`, `Text`,
//! and `Reject`, elides default parameters, and preserves residual payload bytes.

use alloc::string::String;
use core::fmt::Write as _;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

use super::{checked_be_u16, checked_be_u32, is_valid_raw_string_body, push_str_mod};

/// Appends common non-default iSCSI sequence/tag fields (`itt`, `cmdsn`, `statsn`) to `tokens`.
fn push_common_iscsi_tags(
    tokens: &mut String,
    itt: u32,
    default_itt: u32,
    cmdsn: Option<(u32, u32)>,
    statsn: Option<(u32, u32)>,
) {
    if itt != default_itt {
        let _ = write!(tokens, " itt 0x{itt:08x}");
    }
    if let Some((val, def)) = cmdsn
        && val != def
    {
        let _ = write!(tokens, " cmdsn {val}");
    }
    if let Some((val, def)) = statsn
        && val != def
    {
        let _ = write!(tokens, " statsn {val}");
    }
}

/// Parses `InitiatorName=...TargetName=...SessionType=Normal\0AuthMethod=None\0` from Login Request data.
fn parse_login_req_kv(data: &[u8]) -> Option<(&str, &str, &[u8])> {
    let s = core::str::from_utf8(data).ok()?;
    let after_init = s.strip_prefix("InitiatorName=")?;
    let (init_val, after_init_nul) = after_init.split_once('\0')?;
    let after_tgt = after_init_nul.strip_prefix("TargetName=")?;
    let (tgt_val, after_tgt_nul) = after_tgt.split_once('\0')?;
    let rest = after_tgt_nul.strip_prefix("SessionType=Normal\0AuthMethod=None\0")?;
    if !is_valid_raw_string_body(init_val) || !is_valid_raw_string_body(tgt_val) {
        return None;
    }
    let consumed = s.len() - rest.len();
    Some((init_val, tgt_val, data.get(consumed..)?))
}

/// Dissects an RFC 7143 `iscsi` PDU over TCP or SCTP.
pub(crate) fn dissect_iscsi(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(transport, TransportProto::Tcp | TransportProto::Sctp)
        || payload.len() < 48
        || !payload.len().is_multiple_of(4)
        || payload[4] != 0
    {
        return None;
    }
    let b0 = payload[0];
    let b1 = payload[1];
    let data_len =
        ((payload[5] as usize) << 16) | ((payload[6] as usize) << 8) | (payload[7] as usize);
    let pad = (4 - (data_len % 4)) % 4;
    let total = 48usize.checked_add(data_len)?.checked_add(pad)?;
    if total != payload.len() {
        return None;
    }
    if payload.get(48 + data_len..total)?.iter().any(|&b| b != 0) {
        return None;
    }

    let on_iscsi_port = src_port == 3260 || dst_port == 3260;
    let data = payload.get(48..48 + data_len)?;
    let itt = checked_be_u32(payload, 16)?;
    let mut tokens = String::from("iscsi");
    let residual: &[u8] = match b0 {
        0x43 => {
            // Login Request
            let (init_val, tgt_val, rem) = parse_login_req_kv(data)?;
            if b1 != 0x87 {
                let _ = write!(tokens, " flags 0x{b1:02x}");
            }
            if init_val != "iqn.2026-01.dev.frameassembly:initiator" {
                push_str_mod(&mut tokens, "initiator", init_val);
            }
            if tgt_val != "iqn.2026-01.dev.frameassembly:target" {
                push_str_mod(&mut tokens, "target", tgt_val);
            }
            let cmdsn = checked_be_u32(payload, 24)?;
            let statsn = checked_be_u32(payload, 28)?;
            push_common_iscsi_tags(&mut tokens, itt, 1, Some((cmdsn, 1)), Some((statsn, 0)));
            rem
        }
        0x23 if on_iscsi_port => {
            // Login Response
            let rem = data.strip_prefix(b"TargetPortalGroupTag=1\0AuthMethod=None\0")?;
            tokens.push_str(" cmd \"loginresponse\"");
            if b1 != 0x87 {
                let _ = write!(tokens, " flags 0x{b1:02x}");
            }
            let statsn = checked_be_u32(payload, 24)?;
            let exp_cmdsn = checked_be_u32(payload, 28)?;
            let cmdsn = exp_cmdsn.saturating_sub(1);
            let status = payload[36];
            if status != 0 {
                let _ = write!(tokens, " status {status}");
            }
            push_common_iscsi_tags(&mut tokens, itt, 1, Some((cmdsn, 1)), Some((statsn, 0)));
            rem
        }
        0x46 if on_iscsi_port => {
            tokens.push_str(" logout");
            if b1 != 0x80 {
                let _ = write!(tokens, " flags 0x{b1:02x}");
            }
            let cmdsn = checked_be_u32(payload, 24)?;
            let statsn = checked_be_u32(payload, 28)?;
            push_common_iscsi_tags(&mut tokens, itt, 1, Some((cmdsn, 1)), Some((statsn, 0)));
            data
        }
        0x26 if on_iscsi_port => {
            tokens.push_str(" cmd \"logoutresponse\"");
            if b1 != 0x80 {
                let _ = write!(tokens, " flags 0x{b1:02x}");
            }
            if payload[2] != 0 {
                let _ = write!(tokens, " status {}", payload[2]);
            }
            let statsn = checked_be_u32(payload, 24)?;
            let exp_cmdsn = checked_be_u32(payload, 28)?;
            let cmdsn = exp_cmdsn.saturating_sub(1);
            push_common_iscsi_tags(&mut tokens, itt, 1, Some((cmdsn, 1)), Some((statsn, 0)));
            data
        }
        0x01 if on_iscsi_port => {
            let lun = checked_be_u16(payload, 8)?;
            let cmdsn = checked_be_u32(payload, 24)?;
            let statsn = checked_be_u32(payload, 28)?;
            let cdb_op = payload[32];
            let lba = checked_be_u32(payload, 34)?;
            let default_flags = match cdb_op {
                0x28 => {
                    tokens.push_str(" read");
                    0xC1
                }
                0x2A => {
                    tokens.push_str(" write");
                    0xA1
                }
                0x12 => {
                    tokens.push_str(" cmd \"command\"");
                    0xC1
                }
                _ => return None,
            };
            if b1 != default_flags {
                let _ = write!(tokens, " flags 0x{b1:02x}");
            }
            if lun != 0 {
                let _ = write!(tokens, " lun {lun}");
            }
            if matches!(cdb_op, 0x28 | 0x2A) && lba != 0 {
                let _ = write!(tokens, " offset {lba}");
            }
            push_common_iscsi_tags(&mut tokens, itt, 1, Some((cmdsn, 1)), Some((statsn, 0)));
            data
        }
        0x21 if on_iscsi_port => {
            tokens.push_str(" response");
            if b1 != 0x80 {
                let _ = write!(tokens, " flags 0x{b1:02x}");
            }
            if payload[3] != 0 {
                let _ = write!(tokens, " status {}", payload[3]);
            }
            let statsn = checked_be_u32(payload, 24)?;
            let exp_cmdsn = checked_be_u32(payload, 28)?;
            let cmdsn = exp_cmdsn.saturating_sub(1);
            push_common_iscsi_tags(&mut tokens, itt, 1, Some((cmdsn, 1)), Some((statsn, 0)));
            data
        }
        0x25 if on_iscsi_port => {
            tokens.push_str(" data");
            if b1 != 0x81 {
                let _ = write!(tokens, " flags 0x{b1:02x}");
            }
            if payload[3] != 0 {
                let _ = write!(tokens, " status {}", payload[3]);
            }
            let lun = checked_be_u16(payload, 8)?;
            if lun != 0 {
                let _ = write!(tokens, " lun {lun}");
            }
            let offset = checked_be_u32(payload, 40)?;
            if offset != 0 {
                let _ = write!(tokens, " offset {offset}");
            }
            let statsn = checked_be_u32(payload, 24)?;
            let exp_cmdsn = checked_be_u32(payload, 28)?;
            let cmdsn = exp_cmdsn.saturating_sub(1);
            push_common_iscsi_tags(&mut tokens, itt, 1, Some((cmdsn, 1)), Some((statsn, 0)));
            data
        }
        0x05 if on_iscsi_port => {
            tokens.push_str(" cmd \"dataout\"");
            if b1 != 0x80 {
                let _ = write!(tokens, " flags 0x{b1:02x}");
            }
            let lun = checked_be_u16(payload, 8)?;
            if lun != 0 {
                let _ = write!(tokens, " lun {lun}");
            }
            let offset = checked_be_u32(payload, 40)?;
            if offset != 0 {
                let _ = write!(tokens, " offset {offset}");
            }
            let statsn = checked_be_u32(payload, 28)?;
            push_common_iscsi_tags(&mut tokens, itt, 1, None, Some((statsn, 0)));
            data
        }
        0x00 if on_iscsi_port => {
            tokens.push_str(" nop");
            if b1 != 0x80 {
                let _ = write!(tokens, " flags 0x{b1:02x}");
            }
            let lun = checked_be_u16(payload, 8)?;
            if lun != 0 {
                let _ = write!(tokens, " lun {lun}");
            }
            let cmdsn = checked_be_u32(payload, 24)?;
            let statsn = checked_be_u32(payload, 28)?;
            push_common_iscsi_tags(&mut tokens, itt, 1, Some((cmdsn, 1)), Some((statsn, 0)));
            data
        }
        0x20 if on_iscsi_port => {
            tokens.push_str(" cmd \"nopin\"");
            if b1 != 0x80 {
                let _ = write!(tokens, " flags 0x{b1:02x}");
            }
            let lun = checked_be_u16(payload, 8)?;
            if lun != 0 {
                let _ = write!(tokens, " lun {lun}");
            }
            let statsn = checked_be_u32(payload, 24)?;
            let exp_cmdsn = checked_be_u32(payload, 28)?;
            let cmdsn = exp_cmdsn.saturating_sub(1);
            push_common_iscsi_tags(&mut tokens, itt, 1, Some((cmdsn, 1)), Some((statsn, 0)));
            data
        }
        0x04 if on_iscsi_port => {
            let s = core::str::from_utf8(data).ok()?;
            let after_st = s.strip_prefix("SendTargets=")?;
            let (st_val, rest_str) = after_st.split_once('\0')?;
            if !is_valid_raw_string_body(st_val) {
                return None;
            }
            tokens.push_str(" text");
            if b1 != 0x80 {
                let _ = write!(tokens, " flags 0x{b1:02x}");
            }
            if st_val != "All" {
                push_str_mod(&mut tokens, "target", st_val);
            }
            let cmdsn = checked_be_u32(payload, 24)?;
            let statsn = checked_be_u32(payload, 28)?;
            push_common_iscsi_tags(&mut tokens, itt, 1, Some((cmdsn, 1)), Some((statsn, 0)));
            let consumed = s.len() - rest_str.len();
            data.get(consumed..)?
        }
        0x24 if on_iscsi_port => {
            tokens.push_str(" cmd \"textresponse\"");
            if b1 != 0x80 {
                let _ = write!(tokens, " flags 0x{b1:02x}");
            }
            let statsn = checked_be_u32(payload, 24)?;
            let exp_cmdsn = checked_be_u32(payload, 28)?;
            let cmdsn = exp_cmdsn.saturating_sub(1);
            push_common_iscsi_tags(&mut tokens, itt, 1, Some((cmdsn, 1)), Some((statsn, 0)));
            data
        }
        0x3F if on_iscsi_port => {
            tokens.push_str(" opcode 0x3f");
            if b1 != 0x80 {
                let _ = write!(tokens, " flags 0x{b1:02x}");
            }
            if payload[2] != 0 {
                let _ = write!(tokens, " status {}", payload[2]);
            }
            let statsn = checked_be_u32(payload, 24)?;
            let exp_cmdsn = checked_be_u32(payload, 28)?;
            let cmdsn = exp_cmdsn.saturating_sub(1);
            push_common_iscsi_tags(&mut tokens, itt, 0xFFFF_FFFF, Some((cmdsn, 1)), Some((statsn, 0)));
            data
        }
        _ => return None,
    };

    Some(ProtocolDissection {
        protocol: Protocol::Iscsi,
        tokens,
        residual_payload: residual.to_vec(),
        explicit_transport: None,
    })
}
