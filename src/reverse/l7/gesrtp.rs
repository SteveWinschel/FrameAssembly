//! GE Fanuc Service Request Transport Protocol (GE-SRTP) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `gesrtp` frames over TCP or SCTP
//! port `18245`. It validates the 56-byte little-endian GE-SRTP header (`0x00` Init, `0x01`
//! InitAck, `0x02` Request with `0xC0` mailbox, and `0x03` Response with `0xD4`/`0x94` mailbox),
//! exact trailing `text_len` framing, and decodes `seqnum`, `func`, `area`, `addr`, `count`,
//! `value`, `status`, and residual payload octets while eliding default values.

use alloc::format;
use alloc::string::String;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

/// Dissects a GE Fanuc `gesrtp` 56-byte header + trailing payload frame on TCP/SCTP port `18245`.
pub(crate) fn dissect_gesrtp(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(transport, TransportProto::Tcp | TransportProto::Sctp)
        || !(src_port == 18245 || dst_port == 18245)
        || payload.len() < 56
        || payload[1] != 0x00
        || payload[54..56] != [0x00, 0x00]
    {
        return None;
    }

    let text_len = u16::from_le_bytes([payload[4], payload[5]]) as usize;
    let expected_len = 56usize.checked_add(text_len)?;
    if expected_len != payload.len() {
        return None;
    }

    let ptype = payload[0];
    let seq = u16::from_le_bytes([payload[2], payload[3]]);
    let mut tokens = String::from("gesrtp");

    match ptype {
        0x00 | 0x01 => {
            if payload[6..54].iter().any(|&b| b != 0) {
                return None;
            }
            tokens.push_str(if ptype == 0x00 { " init" } else { " initack" });
            if seq != 0 {
                tokens.push_str(&format!(" seqnum {seq}"));
            }
        }
        0x02 => {
            if payload[6..9] != [0, 0, 0]
                || payload[9] != 0x01
                || payload[10..17] != [0; 7]
                || payload[17] != 0x01
                || payload[18..30] != [0; 12]
                || payload[30] != 0xC0
                || payload[31] != (seq & 0xFF) as u8
                || payload[32..42] != [0; 10]
                || payload[52..54] != [0, 0]
            {
                return None;
            }
            if seq != 1 {
                tokens.push_str(&format!(" seqnum {seq}"));
            }
            let func = payload[42];
            match func {
                0x00 => tokens.push_str(" func \"id\""),
                0x03 => tokens.push_str(" func \"programname\""),
                0x04 => {}
                0x05 => tokens.push_str(" func \"readtaskmem\""),
                0x07 => tokens.push_str(" write"),
                0x08 => tokens.push_str(" func \"writetaskmem\""),
                0x20 => tokens.push_str(" func \"getpriv\""),
                0x21 => tokens.push_str(" func \"setpriv\""),
                0x23 => tokens.push_str(" func \"cpuctrl\""),
                0x4F => tokens.push_str(" func \"settime\""),
                other => tokens.push_str(&format!(" func \"0x{other:02x}\"")),
            }
            let area = payload[43];
            if area != 0x08 {
                tokens.push_str(&format!(" area 0x{area:02x}"));
            }
            let addr = u16::from_le_bytes([payload[44], payload[45]]);
            if addr != 0 {
                tokens.push_str(&format!(" addr {addr}"));
            }
            let count = u16::from_le_bytes([payload[46], payload[47]]);
            if count != 1 {
                tokens.push_str(&format!(" count {count}"));
            }
            let val = u32::from_le_bytes([payload[48], payload[49], payload[50], payload[51]]);
            if val != 0 {
                tokens.push_str(&format!(" value {val}"));
            }
        }
        0x03 => {
            let expected_mbox = if text_len > 0 { 0x94 } else { 0xD4 };
            if payload[6..9] != [0, 0, 0]
                || payload[9] != 0x01
                || payload[10..17] != [0; 7]
                || payload[17] != 0x01
                || payload[18..30] != [0; 12]
                || payload[30] != expected_mbox
                || payload[31] != (seq & 0xFF) as u8
                || payload[32..42] != [0; 10]
                || payload[48..54] != [0; 6]
            {
                return None;
            }
            tokens.push_str(" response");
            if seq != 1 {
                tokens.push_str(&format!(" seqnum {seq}"));
            }
            let status = u16::from_le_bytes([payload[42], payload[43]]);
            if status != 0 {
                tokens.push_str(&format!(" status {status}"));
            }
            let val = u32::from_le_bytes([payload[44], payload[45], payload[46], payload[47]]);
            if val != 0 {
                tokens.push_str(&format!(" value {val}"));
            }
        }
        _ => return None,
    }

    Some(ProtocolDissection {
        protocol: Protocol::Gesrtp,
        tokens,
        residual_payload: payload[56..].to_vec(),
        explicit_transport: None,
    })
}
