//! Cisco Skinny Client Control Protocol (`sccp`) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for Cisco Skinny Client Control
//! Protocol (`sccp`) messages carried over TCP port `2000` (or alternate transport overrides).
//! It validates the 12-byte little-endian Skinny header (`DataLength >= 4`, `HeaderVersion`,
//! `MessageID`), verifies per-message body sizes across `Register`, `RegisterAck`, `KeepAlive`,
//! `KeepAliveAck`, `OffHook`, `OnHook`, `KeypadButton`, `CallState`, `StartTone`, `StopTone`,
//! `OpenReceiveChannel`, and `OpenReceiveChannelAck`, elides defaults, and preserves trailing bytes.

use alloc::string::String;
use core::fmt::Write as _;
use core::net::{IpAddr, Ipv4Addr};

use crate::ast::{Protocol, TransportProto};
use crate::reverse::{ProtocolDissection, le_u32, sd_tp};

use super::quote_raw_str;

/// Reads a checked little-endian `u32` at `offset` from `buf`.
fn checked_le_u32(buf: &[u8], offset: usize) -> Option<u32> {
    let b = buf.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Dissects a Cisco Skinny Client Control Protocol (`sccp`) message on port `2000`.
pub(crate) fn dissect_sccp(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if src_port != 2000 && dst_port != 2000 {
        return None;
    }
    if payload.len() < 12 {
        return None;
    }
    let data_len = usize::try_from(le_u32(payload, 0)).ok()?;
    if data_len < 4 {
        return None;
    }
    let total_pdu = 8usize.checked_add(data_len)?;
    if total_pdu > payload.len() {
        return None;
    }

    let hdr_ver = le_u32(payload, 4);
    let msg_id = le_u32(payload, 8);
    let body = payload.get(12..total_pdu)?;
    let residual = payload.get(total_pdu..)?.to_vec();

    let mut tokens = String::from("sccp");
    match msg_id {
        0x0000 => {
            if !body.is_empty() {
                return None;
            }
            tokens.push_str(" keepalive");
        }
        0x0100 => {
            if !body.is_empty() {
                return None;
            }
            tokens.push_str(" keepaliveack");
        }
        0x0001 => {
            if body.len() != 36
                || checked_le_u32(body, 16)? != 0
                || checked_le_u32(body, 28)? != 7
                || checked_le_u32(body, 32)? != 0
            {
                return None;
            }
            let raw_name = &body[0..16];
            let nul_pos = raw_name.iter().position(|&b| b == 0).unwrap_or(raw_name.len());
            if !raw_name[nul_pos..].iter().all(|&b| b == 0) {
                return None;
            }
            let dev_name = core::str::from_utf8(&raw_name[..nul_pos]).ok()?;
            let line = checked_le_u32(body, 20)?;
            let ip = IpAddr::V4(Ipv4Addr::new(body[24], body[25], body[26], body[27]));
            if dev_name != "SEP001122334455" {
                let _ = write!(tokens, " devicename \"{}\"", quote_raw_str(dev_name));
            }
            if line != 1 {
                let _ = write!(tokens, " line {line}");
            }
            if ip != IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)) {
                let _ = write!(tokens, " addr {ip}");
            }
        }
        0x0081 => {
            if body.len() != 20
                || checked_le_u32(body, 0)? != 30
                || &body[4..12] != b"M/D/YA\x00\x00"
                || checked_le_u32(body, 12)? != 30
                || checked_le_u32(body, 16)? != 0
            {
                return None;
            }
            tokens.push_str(" registerack");
        }
        0x0006 | 0x0007 | 0x0083 => {
            if body.len() != 8 {
                return None;
            }
            let kw = match msg_id {
                0x0006 => "offhook",
                0x0007 => "onhook",
                _ => "stoptone",
            };
            let line = checked_le_u32(body, 0)?;
            let call_id = checked_le_u32(body, 4)?;
            let _ = write!(tokens, " {kw}");
            if line != 1 {
                let _ = write!(tokens, " line {line}");
            }
            if call_id != 100 {
                let _ = write!(tokens, " callid {call_id}");
            }
        }
        0x0003 => {
            if body.len() != 12 {
                return None;
            }
            let button = checked_le_u32(body, 0)?;
            let line = checked_le_u32(body, 4)?;
            let call_id = checked_le_u32(body, 8)?;
            tokens.push_str(" keypadbutton");
            if button != 1 {
                let _ = write!(tokens, " button {button}");
            }
            if line != 1 {
                let _ = write!(tokens, " line {line}");
            }
            if call_id != 100 {
                let _ = write!(tokens, " callid {call_id}");
            }
        }
        0x0111 => {
            if body.len() != 24
                || checked_le_u32(body, 12)? != 0
                || checked_le_u32(body, 16)? != 0
                || checked_le_u32(body, 20)? != 0
            {
                return None;
            }
            let state = checked_le_u32(body, 0)?;
            let line = checked_le_u32(body, 4)?;
            let call_id = checked_le_u32(body, 8)?;
            tokens.push_str(" callstate");
            if state != 1 {
                let _ = write!(tokens, " state {state}");
            }
            if line != 1 {
                let _ = write!(tokens, " line {line}");
            }
            if call_id != 100 {
                let _ = write!(tokens, " callid {call_id}");
            }
        }
        0x0082 => {
            if body.len() != 16 || checked_le_u32(body, 4)? != 0 {
                return None;
            }
            let tone = checked_le_u32(body, 0)?;
            let line = checked_le_u32(body, 8)?;
            let call_id = checked_le_u32(body, 12)?;
            tokens.push_str(" starttone");
            if tone != 0x21 {
                let _ = write!(tokens, " tone 0x{tone:x}");
            }
            if line != 1 {
                let _ = write!(tokens, " line {line}");
            }
            if call_id != 100 {
                let _ = write!(tokens, " callid {call_id}");
            }
        }
        0x0105 => {
            if body.len() != 92
                || checked_le_u32(body, 4)? != 1
                || checked_le_u32(body, 8)? != 20
                || checked_le_u32(body, 12)? != 4
            {
                return None;
            }
            let call_id = checked_le_u32(body, 0)?;
            if checked_le_u32(body, 24)? != call_id {
                return None;
            }
            tokens.push_str(" openreceivechannel");
            if call_id != 100 {
                let _ = write!(tokens, " callid {call_id}");
            }
        }
        0x0022 => {
            if body.len() != 16 || checked_le_u32(body, 0)? != 0 {
                return None;
            }
            let ip = IpAddr::V4(Ipv4Addr::new(body[4], body[5], body[6], body[7]));
            let media_port = checked_le_u32(body, 8)?;
            let call_id = checked_le_u32(body, 12)?;
            tokens.push_str(" openreceivechannelack");
            if ip != IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)) {
                let _ = write!(tokens, " addr {ip}");
            }
            if media_port != 20000 {
                let _ = write!(tokens, " mediaport {media_port}");
            }
            if call_id != 100 {
                let _ = write!(tokens, " callid {call_id}");
            }
        }
        _ => return None,
    }

    if hdr_ver != 0 {
        let _ = write!(tokens, " version {hdr_ver}");
    }
    let explicit_transport = match transport {
        TransportProto::Tcp => None,
        tp => Some(tp),
    };
    Some(sd_tp(Protocol::Sccp, tokens, residual, explicit_transport))
}
