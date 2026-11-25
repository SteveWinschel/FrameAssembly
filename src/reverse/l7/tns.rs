//! Oracle Transparent Network Substrate (`tns`) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for Oracle `tns` frames over TCP and
//! SCTP ports `1521`, `2483`, and `2484`, plus custom-port `CONNECT` frames matching the
//! `(DESCRIPTION=(CONNECT_DATA=` descriptor prefix. It validates the 8-byte TNS header (`length`,
//! `packetChecksum == 0`, `reserved == 0`, `headerChecksum == 0`), decodes `CONNECT`, `ACCEPT`,
//! `REFUSE`, `REDIRECT`, `DATA`, `MARKER`, `ACK`, `NULL`, `ABORT`, `RESEND`, and `ATTENTION`,
//! elides default fields, and preserves trailing bytes.

use alloc::string::String;
use core::fmt::Write as _;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

use super::{checked_be_u16, is_valid_raw_string_body, push_str_mod};

/// Dissects a TNS `CONNECT` (`type = 1`) descriptor body starting at byte `8`.
fn dissect_tns_connect<'a>(
    payload: &'a [u8],
    tokens: &mut String,
) -> Option<&'a [u8]> {
    if payload.len() < 58 {
        return None;
    }
    let version = checked_be_u16(payload, 8)?;
    let compat = checked_be_u16(payload, 10)?;
    let svc_opts = checked_be_u16(payload, 12)?;
    let sdu = checked_be_u16(payload, 14)?;
    let tdu = checked_be_u16(payload, 16)?;
    let nt_char = checked_be_u16(payload, 18)?;
    let line_turn = checked_be_u16(payload, 20)?;
    let val_one = checked_be_u16(payload, 22)?;
    let cd_len = checked_be_u16(payload, 24)? as usize;
    let cd_off = checked_be_u16(payload, 26)? as usize;
    if compat != 300
        || sdu != 8192
        || tdu != 65535
        || nt_char != 0x4F98
        || line_turn != 0
        || val_one != 1
        || cd_off != 58
        || payload.get(28..32) != Some(&2048u32.to_be_bytes())
        || payload.get(32..58)?.iter().any(|&b| b != 0)
    {
        return None;
    }
    let cd_end = 58usize.checked_add(cd_len)?;
    let cd_str = core::str::from_utf8(payload.get(58..cd_end)?).ok()?;
    let inner = cd_str
        .strip_prefix("(DESCRIPTION=(CONNECT_DATA=(")?
        .strip_suffix(")))")?;

    if let Some(after_svc) = inner.strip_prefix("SERVICE_NAME=") {
        if let Some((svc, sid)) = after_svc.split_once(")(SID=") {
            if !is_valid_raw_string_body(svc) || !is_valid_raw_string_body(sid) {
                return None;
            }
            push_str_mod(tokens, "service", svc);
            push_str_mod(tokens, "sid", sid);
        } else {
            if !is_valid_raw_string_body(after_svc) {
                return None;
            }
            if after_svc != "ORCL" {
                push_str_mod(tokens, "service", after_svc);
            }
        }
    } else {
        let sid = inner.strip_prefix("SID=")?;
        if !is_valid_raw_string_body(sid) {
            return None;
        }
        push_str_mod(tokens, "sid", sid);
    }

    if version != 314 {
        let _ = write!(tokens, " version {version}");
    }
    if svc_opts != 0x0C41 {
        let _ = write!(tokens, " flags 0x{svc_opts:04x}");
    }
    payload.get(cd_end..)
}

/// Dissects an Oracle TNS packet over TCP or SCTP.
pub(crate) fn dissect_tns(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(transport, TransportProto::Tcp | TransportProto::Sctp) || payload.len() < 8 {
        return None;
    }
    let total_len = checked_be_u16(payload, 0)? as usize;
    if total_len != payload.len()
        || checked_be_u16(payload, 2)? != 0
        || payload[5] != 0
        || checked_be_u16(payload, 6)? != 0
    {
        return None;
    }
    let pkt_type = payload[4];
    let on_tns_port = matches!(src_port, 1521 | 2483 | 2484) || matches!(dst_port, 1521 | 2483 | 2484);
    if !on_tns_port && pkt_type != 1 {
        return None;
    }

    let mut tokens = String::from("tns");
    let residual: &[u8];

    match pkt_type {
        1 => {
            residual = dissect_tns_connect(payload, &mut tokens)?;
        }
        2 => {
            if payload.len() < 24 {
                return None;
            }
            let version = checked_be_u16(payload, 8)?;
            let svc_opts = checked_be_u16(payload, 10)?;
            if checked_be_u16(payload, 12)? != 8192
                || checked_be_u16(payload, 14)? != 65535
                || checked_be_u16(payload, 16)? != 1
                || checked_be_u16(payload, 18)? != 0
                || checked_be_u16(payload, 20)? != 24
                || checked_be_u16(payload, 22)? != 0
            {
                return None;
            }
            tokens.push_str(" accept");
            if version != 314 {
                let _ = write!(tokens, " version {version}");
            }
            if svc_opts != 0x0C41 {
                let _ = write!(tokens, " flags 0x{svc_opts:04x}");
            }
            residual = payload.get(24..)?;
        }
        4 => {
            if payload.len() < 12 || payload[8] != 0x22 || payload[9] != 0x00 {
                return None;
            }
            let rlen = checked_be_u16(payload, 10)? as usize;
            let rend = 12usize.checked_add(rlen)?;
            let rstr = core::str::from_utf8(payload.get(12..rend)?).ok()?;
            let err_s = rstr
                .strip_prefix("(DESCRIPTION=(ERR=")?
                .strip_suffix("))")?;
            let errcode: u16 = err_s.parse().ok()?;
            tokens.push_str(" refuse");
            if errcode != 12514 {
                let _ = write!(tokens, " errcode {errcode}");
            }
            residual = payload.get(rend..)?;
        }
        5 => {
            if payload.len() < 10 {
                return None;
            }
            let rlen = checked_be_u16(payload, 8)? as usize;
            let rend = 10usize.checked_add(rlen)?;
            let rstr = core::str::from_utf8(payload.get(10..rend)?).ok()?;
            let host = rstr
                .strip_prefix("(ADDRESS=(PROTOCOL=TCP)(HOST=")?
                .strip_suffix(")(PORT=1521))")?;
            if !is_valid_raw_string_body(host) {
                return None;
            }
            tokens.push_str(" redirect");
            if host != "127.0.0.1" {
                push_str_mod(&mut tokens, "service", host);
            }
            residual = payload.get(rend..)?;
        }
        6 => {
            if payload.len() < 10 {
                return None;
            }
            let data_flags = checked_be_u16(payload, 8)?;
            tokens.push_str(" data");
            if data_flags != 0 {
                let _ = write!(tokens, " flags 0x{data_flags:04x}");
            }
            let tail = payload.get(10..)?;
            if !tail.is_empty()
                && let Ok(sql_str) = core::str::from_utf8(tail)
                && is_valid_raw_string_body(sql_str)
            {
                push_str_mod(&mut tokens, "sql", sql_str);
                residual = &[];
            } else {
                residual = tail;
            }
        }
        12 => {
            residual = payload.get(8..)?.strip_prefix(&[0x01, 0x00, 0x02])?;
            tokens.push_str(" marker");
        }
        3 => {
            tokens.push_str(" msgtype \"ack\"");
            residual = payload.get(8..)?;
        }
        7 => {
            tokens.push_str(" msgtype \"null\"");
            residual = payload.get(8..)?;
        }
        9 => {
            tokens.push_str(" msgtype \"abort\"");
            residual = payload.get(8..)?;
        }
        11 => {
            tokens.push_str(" msgtype \"resend\"");
            residual = payload.get(8..)?;
        }
        14 => {
            tokens.push_str(" msgtype \"attention\"");
            residual = payload.get(8..)?;
        }
        _ => return None,
    }

    Some(ProtocolDissection {
        protocol: Protocol::Tns,
        tokens,
        residual_payload: residual.to_vec(),
        explicit_transport: None,
    })
}
