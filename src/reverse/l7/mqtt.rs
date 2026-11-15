//! Message Queuing Telemetry Transport v3.1.1 (MQTT, OASIS Standard) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `mqtt` v3.1.1 control packets over
//! TCP ports `1883` and `8883` (as well as custom-port `connect` packets carrying the
//! `\x00\x04MQTT\x04\x02` variable header signature). It decodes `connect`, `connack`, `publish`,
//! `puback`, `subscribe`, `suback`, `pingreq`, `pingresp`, and `disconnect` frames into canonical
//! `.frasm` statements.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

/// Checks whether `s` can be emitted inside `"..."` for a parser field that uses
/// `parse_raw_string_lit` (which strips outer quotes without unescaping).
fn is_valid_raw_str(s: &str) -> bool {
    !s.contains('"')
        && s.chars().all(|c| !c.is_control())
        && (s.bytes().rev().take_while(|&b| b == b'\\').count() % 2 == 0)
}

/// Decodes a canonical 1..=4 byte MQTT v3.1.1 Remaining Length varint, returning `(rem_len, hdr_len)`.
fn decode_mqtt_varint(payload: &[u8]) -> Option<(usize, usize)> {
    if payload.len() < 2 {
        return None;
    }
    let mut rem_len = 0usize;
    let mut multiplier = 1usize;
    let mut idx = 1usize;
    loop {
        let enc = *payload.get(idx)?;
        rem_len += ((enc & 0x7F) as usize) * multiplier;
        idx += 1;
        if (enc & 0x80) == 0 {
            if idx > 2 && enc == 0 {
                return None;
            }
            return Some((rem_len, idx));
        }
        if idx >= 5 {
            return None;
        }
        multiplier *= 128;
    }
}

/// Dissects an `mqtt` v3.1.1 control packet over TCP.
pub(crate) fn dissect_mqtt(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(transport, TransportProto::Tcp) {
        return None;
    }
    let (rem_len, hdr_len) = decode_mqtt_varint(payload)?;
    let pkt_end = hdr_len.checked_add(rem_len)?;
    if payload.len() != pkt_end {
        return None;
    }
    let b0 = payload[0];
    let body = &payload[hdr_len..pkt_end];
    let has_connect_sig = b0 == 0x10 && body.starts_with(b"\x00\x04MQTT\x04\x02");
    if !has_connect_sig
        && !(matches!(dst_port, 1883 | 8883) || matches!(src_port, 1883 | 8883))
    {
        return None;
    }

    let mut tokens = String::from("mqtt");
    let mut residual = Vec::new();

    match b0 {
        0x10 => {
            if body.len() < 12 || &body[0..8] != b"\x00\x04MQTT\x04\x02" {
                return None;
            }
            let keepalive = u16::from_be_bytes([body[8], body[9]]);
            let cid_len = u16::from_be_bytes([body[10], body[11]]) as usize;
            if body.len() < 12 + cid_len {
                return None;
            }
            let cid = core::str::from_utf8(&body[12..12 + cid_len]).ok()?;
            if !is_valid_raw_str(cid) {
                return None;
            }
            tokens.push_str(" connect");
            if cid != "client-01" {
                tokens.push_str(&format!(" clientid \"{cid}\""));
            }
            if keepalive != 60 {
                tokens.push_str(&format!(" keepalive {keepalive}"));
            }
            residual = body[12 + cid_len..].to_vec();
        }
        0x20 => {
            if body.len() != 2 || body[0] != 0 {
                return None;
            }
            tokens.push_str(" connack");
            if body[1] != 0 {
                tokens.push_str(&format!(" returncode {}", body[1]));
            }
        }
        0x30..=0x3F => {
            if body.len() < 2 {
                return None;
            }
            let qos = (b0 >> 1) & 0x03;
            let retain = (b0 & 0x01) != 0;
            let tlen = u16::from_be_bytes([body[0], body[1]]) as usize;
            let hdr_end = 2 + tlen + if qos > 0 { 2 } else { 0 };
            if qos > 2 || body.len() < hdr_end {
                return None;
            }
            let topic = core::str::from_utf8(&body[2..2 + tlen]).ok()?;
            if !is_valid_raw_str(topic) {
                return None;
            }
            tokens.push_str(" publish");
            if topic != "test/topic" {
                tokens.push_str(&format!(" topic \"{topic}\""));
            }
            if qos != 0 {
                tokens.push_str(&format!(" qos {qos}"));
                let pid = u16::from_be_bytes([body[2 + tlen], body[3 + tlen]]);
                if pid != 1 {
                    tokens.push_str(&format!(" pktid {pid}"));
                }
            }
            if retain {
                tokens.push_str(" retain");
            }
            let content = &body[hdr_end..];
            residual = if content == b"data" {
                Vec::new()
            } else {
                content.to_vec()
            };
        }
        0x40 => {
            if body.len() != 2 {
                return None;
            }
            let pid = u16::from_be_bytes([body[0], body[1]]);
            tokens.push_str(" puback");
            if pid != 1 {
                tokens.push_str(&format!(" pktid {pid}"));
            }
        }
        0x82 => {
            if body.len() < 5 {
                return None;
            }
            let pid = u16::from_be_bytes([body[0], body[1]]);
            let tlen = u16::from_be_bytes([body[2], body[3]]) as usize;
            if body.len() < 5 + tlen {
                return None;
            }
            let topic = core::str::from_utf8(&body[4..4 + tlen]).ok()?;
            if !is_valid_raw_str(topic) {
                return None;
            }
            let qos = body[4 + tlen];
            tokens.push_str(" subscribe");
            if pid != 1 {
                tokens.push_str(&format!(" pktid {pid}"));
            }
            if topic != "test/topic" {
                tokens.push_str(&format!(" topic \"{topic}\""));
            }
            if qos != 0 {
                tokens.push_str(&format!(" qos {qos}"));
            }
            residual = body[5 + tlen..].to_vec();
        }
        0x90 => {
            if body.len() != 3 {
                return None;
            }
            let pid = u16::from_be_bytes([body[0], body[1]]);
            let rc = body[2];
            tokens.push_str(" suback");
            if pid != 1 {
                tokens.push_str(&format!(" pktid {pid}"));
            }
            if rc != 0 {
                tokens.push_str(&format!(" returncode {rc}"));
            }
        }
        0xC0 if body.is_empty() => tokens.push_str(" pingreq"),
        0xD0 if body.is_empty() => tokens.push_str(" pingresp"),
        0xE0 if body.is_empty() => tokens.push_str(" disconnect"),
        _ => return None,
    }

    Some(ProtocolDissection {
        protocol: Protocol::Mqtt,
        tokens,
        residual_payload: residual,
        explicit_transport: None,
    })
}
