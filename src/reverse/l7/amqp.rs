//! Advanced Message Queuing Protocol v0-9-1 (AMQP) Layer 7 PCAP-to-`.fasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `AMQP` 0-9-1 frames over TCP
//! (ports `5672`, `5671`, `15672`, and custom ports matching the `AMQP\x00\x00\x09\x01` protocol
//! header or `0xCE`-terminated method/heartbeat frame envelope). It decodes `protocol_header`,
//! `heartbeat`, `connection_start`, `channel_open`, `basic_publish`, and `basic_deliver` frames
//! along with `channel`, `exchange`, and `routing_key` fields.

use alloc::format;
use alloc::string::String;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

/// Checks whether `s` can be emitted inside `"..."` for a parser field that uses
/// `parse_raw_string_lit` (which strips outer quotes without unescaping).
fn is_valid_raw_str(s: &str) -> bool {
    !s.contains('"')
        && s.chars().all(|c| !c.is_control())
        && (s.bytes().rev().take_while(|&b| b == b'\\').count() % 2 == 0)
}

/// Parses an AMQP 0-9-1 1-byte length-prefixed `shortstr`.
fn parse_amqp_shortstr(input: &[u8]) -> Option<(&str, &[u8])> {
    let len = *input.first()? as usize;
    if input.len() < 1 + len {
        return None;
    }
    let s = core::str::from_utf8(&input[1..1 + len]).ok()?;
    if !is_valid_raw_str(s) {
        return None;
    }
    Some((s, &input[1 + len..]))
}

/// Dissects an `AMQP` 0-9-1 protocol header, heartbeat, or method frame over TCP.
pub(crate) fn dissect_amqp(
    transport: TransportProto,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if payload.is_empty() || !matches!(transport, TransportProto::Tcp) {
        return None;
    }

    if let Some(rem) = payload.strip_prefix(b"AMQP\x00\x00\x09\x01") {
        return Some(ProtocolDissection {
            protocol: Protocol::Amqp,
            tokens: String::from("amqp protocol_header"),
            residual_payload: rem.to_vec(),
            explicit_transport: None,
        });
    }

    if payload.len() < 8 {
        return None;
    }
    let ftype = payload[0];
    let channel = u16::from_be_bytes([payload[1], payload[2]]);
    let size = u32::from_be_bytes([payload[3], payload[4], payload[5], payload[6]]) as usize;
    if payload.len() != 8 + size || payload[7 + size] != 0xCE {
        return None;
    }
    let body = &payload[7..7 + size];

    if ftype == 8 {
        let mut tokens = String::from("amqp heartbeat");
        if channel != 0 {
            tokens.push_str(&format!(" channel {channel}"));
        }
        return Some(ProtocolDissection {
            protocol: Protocol::Amqp,
            tokens,
            residual_payload: body.to_vec(),
            explicit_transport: None,
        });
    }

    if ftype != 1 || body.len() < 4 {
        return None;
    }
    let class_id = u16::from_be_bytes([body[0], body[1]]);
    let method_id = u16::from_be_bytes([body[2], body[3]]);
    let args = &body[4..];
    let mut tokens = String::from("amqp");
    let residual: &[u8];

    match (class_id, method_id) {
        (10, 10) => {
            let fixed = b"\x00\x09\x00\x00\x00\x00\x00\x00\x00\x05PLAIN\x00\x00\x00\x05en_US";
            let rem = args.strip_prefix(fixed.as_slice())?;
            tokens.push_str(" connection_start");
            if channel != 0 {
                tokens.push_str(&format!(" channel {channel}"));
            }
            residual = rem;
        }
        (20, 10) => {
            if args.first() != Some(&0) {
                return None;
            }
            tokens.push_str(" channel_open");
            if channel != 1 {
                tokens.push_str(&format!(" channel {channel}"));
            }
            let after_zero = &args[1..];
            if let Some((ex, after_ex)) = parse_amqp_shortstr(after_zero)
                && let Some((rk, after_rk)) = parse_amqp_shortstr(after_ex)
                && (!ex.is_empty() || !rk.is_empty())
            {
                if !ex.is_empty() {
                    tokens.push_str(&format!(" exchange \"{ex}\""));
                }
                if !rk.is_empty() {
                    tokens.push_str(&format!(" routing_key \"{rk}\""));
                }
                residual = after_rk;
            } else {
                residual = after_zero;
            }
        }
        (60, 40) => {
            if args.len() < 3 || &args[0..2] != b"\x00\x00" {
                return None;
            }
            tokens.push_str(" basic_publish");
            if channel != 1 {
                tokens.push_str(&format!(" channel {channel}"));
            }
            let (ex, after_ex) = parse_amqp_shortstr(&args[2..])?;
            let (rk, after_rk) = parse_amqp_shortstr(after_ex)?;
            if after_rk.first() != Some(&0) {
                return None;
            }
            if !ex.is_empty() {
                tokens.push_str(&format!(" exchange \"{ex}\""));
            }
            if !rk.is_empty() {
                tokens.push_str(&format!(" routing_key \"{rk}\""));
            }
            residual = &after_rk[1..];
        }
        (60, 60) => {
            let prefix = b"\x04ctag\x00\x00\x00\x00\x00\x00\x00\x01\x00";
            let after_prefix = args.strip_prefix(prefix.as_slice())?;
            tokens.push_str(" basic_deliver");
            if channel != 1 {
                tokens.push_str(&format!(" channel {channel}"));
            }
            let (ex, after_ex) = parse_amqp_shortstr(after_prefix)?;
            let (rk, after_rk) = parse_amqp_shortstr(after_ex)?;
            if !ex.is_empty() {
                tokens.push_str(&format!(" exchange \"{ex}\""));
            }
            if !rk.is_empty() {
                tokens.push_str(&format!(" routing_key \"{rk}\""));
            }
            residual = after_rk;
        }
        _ => return None,
    }

    Some(ProtocolDissection {
        protocol: Protocol::Amqp,
        tokens,
        residual_payload: residual.to_vec(),
        explicit_transport: None,
    })
}
