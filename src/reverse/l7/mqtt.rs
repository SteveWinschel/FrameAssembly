//! Message Queuing Telemetry Transport v3.1.1 / v5.0 (MQTT, OASIS Standard) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `mqtt` v3.1.1 and MQTT 5.0 control
//! packets over TCP and SCTP ports `1883` and `8883` (plus custom-port `connect` packets carrying
//! the `\x00\x04MQTT\x04\x02` or `\x00\x04MQTT\x05\x02` variable header signatures). It decodes
//! canonical multi-byte Remaining Length varints up to `268,435,455` without overflow, empty
//! `publish` payloads (`payload ""`), and MQTT 5.0 `v5*` control packets.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

use super::quote_raw_str;

/// Checks whether `s` contains no control characters so it can safely be emitted as a quoted modifier.
fn is_printable_mqtt_str(s: &str) -> bool {
    s.chars().all(|c| !c.is_control())
}

/// Decodes a canonical 1..=4 byte MQTT Remaining Length varint up to `268,435,455`.
fn decode_mqtt_varint(payload: &[u8]) -> Option<(usize, usize)> {
    if payload.len() < 2 {
        return None;
    }
    let mut rem_len = 0usize;
    let mut multiplier = 1usize;
    let mut idx = 1usize;
    loop {
        let enc = *payload.get(idx)?;
        let add = ((enc & 0x7F) as usize).checked_mul(multiplier)?;
        rem_len = rem_len.checked_add(add)?;
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
        multiplier = multiplier.checked_mul(128)?;
    }
}

/// Dissects an `mqtt` v3.1.1 or v5.0 control packet over TCP or SCTP.
pub(crate) fn dissect_mqtt(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(transport, TransportProto::Tcp | TransportProto::Sctp) {
        return None;
    }
    let (rem_len, hdr_len) = decode_mqtt_varint(payload)?;
    let pkt_end = hdr_len.checked_add(rem_len)?;
    if payload.len() != pkt_end {
        return None;
    }
    let b0 = payload[0];
    let body = &payload[hdr_len..pkt_end];
    let has_connect_sig = b0 == 0x10
        && (body.starts_with(b"\x00\x04MQTT\x04\x02")
            || body.starts_with(b"\x00\x04MQTT\x05\x02"));
    if !has_connect_sig
        && !(matches!(dst_port, 1883 | 8883) || matches!(src_port, 1883 | 8883))
    {
        return None;
    }

    let mut tokens = String::from("mqtt");
    let mut residual = Vec::new();

    match b0 {
        0x10 => {
            if body.len() >= 13
                && &body[0..8] == b"\x00\x04MQTT\x05\x02"
                && body[10] == 0x00
            {
                let keepalive = u16::from_be_bytes([body[8], body[9]]);
                let cid_len = u16::from_be_bytes([body[11], body[12]]) as usize;
                let cid_end = 13usize.checked_add(cid_len)?;
                if body.len() < cid_end {
                    return None;
                }
                let cid = core::str::from_utf8(&body[13..cid_end]).ok()?;
                if !is_printable_mqtt_str(cid) {
                    return None;
                }
                tokens.push_str(" pkttype \"v5connect\"");
                if cid != "client-01" {
                    tokens.push_str(&format!(" clientid \"{}\"", quote_raw_str(cid)));
                }
                if keepalive != 60 {
                    tokens.push_str(&format!(" keepalive {keepalive}"));
                }
                residual = body[cid_end..].to_vec();
            } else if body.len() >= 12 && &body[0..8] == b"\x00\x04MQTT\x04\x02" {
                let keepalive = u16::from_be_bytes([body[8], body[9]]);
                let cid_len = u16::from_be_bytes([body[10], body[11]]) as usize;
                let cid_end = 12usize.checked_add(cid_len)?;
                if body.len() < cid_end {
                    return None;
                }
                let cid = core::str::from_utf8(&body[12..cid_end]).ok()?;
                if !is_printable_mqtt_str(cid) {
                    return None;
                }
                tokens.push_str(" connect");
                if cid != "client-01" {
                    tokens.push_str(&format!(" clientid \"{}\"", quote_raw_str(cid)));
                }
                if keepalive != 60 {
                    tokens.push_str(&format!(" keepalive {keepalive}"));
                }
                residual = body[cid_end..].to_vec();
            } else {
                return None;
            }
        }
        0x20 => {
            if body.len() == 2 && body[0] == 0 {
                tokens.push_str(" connack");
                if body[1] != 0 {
                    tokens.push_str(&format!(" returncode {}", body[1]));
                }
            } else if body.len() == 3 && body[0] == 0 && body[2] == 0 {
                tokens.push_str(" pkttype \"v5connack\"");
                if body[1] != 0 {
                    tokens.push_str(&format!(" returncode {}", body[1]));
                }
            } else {
                return None;
            }
        }
        0x30..=0x3F => {
            if body.len() < 2 {
                return None;
            }
            let qos = (b0 >> 1) & 0x03;
            let retain = (b0 & 0x01) != 0;
            let tlen = u16::from_be_bytes([body[0], body[1]]) as usize;
            let hdr_end = 2usize
                .checked_add(tlen)?
                .checked_add(if qos > 0 { 2 } else { 0 })?;
            if qos > 2 || body.len() < hdr_end {
                return None;
            }
            let topic = core::str::from_utf8(&body[2..2 + tlen]).ok()?;
            if !is_printable_mqtt_str(topic) {
                return None;
            }
            tokens.push_str(" publish");
            if topic != "test/topic" {
                tokens.push_str(&format!(" topic \"{}\"", quote_raw_str(topic)));
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
            if content.is_empty() {
                tokens.push_str(" payload \"\"");
            } else if content != b"data" {
                residual = content.to_vec();
            }
        }
        0x40 => {
            if body.len() == 2 {
                let pid = u16::from_be_bytes([body[0], body[1]]);
                tokens.push_str(" puback");
                if pid != 1 {
                    tokens.push_str(&format!(" pktid {pid}"));
                }
            } else if body.len() == 4 && body[2..4] == [0x00, 0x00] {
                let pid = u16::from_be_bytes([body[0], body[1]]);
                tokens.push_str(" pkttype \"v5puback\"");
                if pid != 1 {
                    tokens.push_str(&format!(" pktid {pid}"));
                }
            } else {
                return None;
            }
        }
        0x82 => {
            if body.len() < 5 {
                return None;
            }
            let pid = u16::from_be_bytes([body[0], body[1]]);
            let tlen_v3 = u16::from_be_bytes([body[2], body[3]]) as usize;
            if tlen_v3 > 0
                && let Some(qidx) = 4usize.checked_add(tlen_v3)
                && body.len() > qidx
                && body[qidx] <= 2
                && let Ok(topic) = core::str::from_utf8(&body[4..qidx])
                && is_printable_mqtt_str(topic)
            {
                let qos = body[qidx];
                tokens.push_str(" subscribe");
                if pid != 1 {
                    tokens.push_str(&format!(" pktid {pid}"));
                }
                if topic != "test/topic" {
                    tokens.push_str(&format!(" topic \"{}\"", quote_raw_str(topic)));
                }
                if qos != 0 {
                    tokens.push_str(&format!(" qos {qos}"));
                }
                residual = body[qidx + 1..].to_vec();
            } else if body.len() >= 6 && body[2] == 0x00 {
                let tlen_v5 = u16::from_be_bytes([body[3], body[4]]) as usize;
                let qidx = 5usize.checked_add(tlen_v5)?;
                if tlen_v5 == 0 || body.len() <= qidx || body[qidx] > 2 {
                    return None;
                }
                let topic = core::str::from_utf8(&body[5..qidx]).ok()?;
                if !is_printable_mqtt_str(topic) {
                    return None;
                }
                let qos = body[qidx];
                tokens.push_str(" pkttype \"v5subscribe\"");
                if pid != 1 {
                    tokens.push_str(&format!(" pktid {pid}"));
                }
                if topic != "test/topic" {
                    tokens.push_str(&format!(" topic \"{}\"", quote_raw_str(topic)));
                }
                if qos != 0 {
                    tokens.push_str(&format!(" qos {qos}"));
                }
                residual = body[qidx + 1..].to_vec();
            } else {
                return None;
            }
        }
        0x90 => {
            if body.len() == 3 {
                let pid = u16::from_be_bytes([body[0], body[1]]);
                let rc = body[2];
                tokens.push_str(" suback");
                if pid != 1 {
                    tokens.push_str(&format!(" pktid {pid}"));
                }
                if rc != 0 {
                    tokens.push_str(&format!(" returncode {rc}"));
                }
            } else if body.len() == 4 && body[2] == 0x00 {
                let pid = u16::from_be_bytes([body[0], body[1]]);
                let rc = body[3];
                tokens.push_str(" pkttype \"v5suback\"");
                if pid != 1 {
                    tokens.push_str(&format!(" pktid {pid}"));
                }
                if rc != 0 {
                    tokens.push_str(&format!(" returncode {rc}"));
                }
            } else {
                return None;
            }
        }
        0xC0 if body.is_empty() => tokens.push_str(" pingreq"),
        0xD0 if body.is_empty() => tokens.push_str(" pingresp"),
        0xE0 if body.is_empty() => tokens.push_str(" disconnect"),
        0xE0 if body == [0x00, 0x00] => tokens.push_str(" pkttype \"v5disconnect\""),
        _ => return None,
    }

    Some(ProtocolDissection {
        protocol: Protocol::Mqtt,
        tokens,
        residual_payload: residual,
        explicit_transport: None,
    })
}
