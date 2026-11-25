//! Message Queuing Telemetry Transport v3.1.1 / v5.0 (MQTT, OASIS) wire payload builder.
//!
//! This module implements [`build_mqtt_payload`], which serializes an [`MqttSpec`]
//! AST specification into an OASIS MQTT v3.1.1 / v5.0 control packet over TCP port 1883 (or 8883
//! for MQTTS). It constructs the 1-byte Fixed Header (control packet type `1..=14`, QoS bits, and
//! RETAIN flag), encodes the variable-length Remaining Length field (capped at `268,435,455` bytes
//! per RFC), serializes Variable Header fields (with optional MQTT 5.0 Property Length varints for
//! `v5` packet types), and handles empty `publish` payloads cleanly.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Maximum OASIS MQTT variable-length integer value (`268,435,455` bytes = 4 encoded bytes).
const MAX_MQTT_VARINT: usize = 268_435_455;

/// Encodes an OASIS MQTT v3.1.1 / v5.0 variable-length Remaining Length integer (`1..=4` bytes).
fn push_mqtt_varint(buf: &mut Vec<u8>, rem: usize) {
    let mut rem = rem.min(MAX_MQTT_VARINT);
    loop {
        let mut enc = (rem & 0x7F) as u8;
        rem >>= 7;
        if rem > 0 {
            enc |= 0x80;
        }
        buf.push(enc);
        if rem == 0 {
            break;
        }
    }
}

/// Appends a 2-byte big-endian length-prefixed UTF-8 string clamped to `u16::MAX`.
fn push_mqtt_utf8(buf: &mut Vec<u8>, s: &str) {
    let raw = s.as_bytes();
    let len = u16::try_from(raw.len()).unwrap_or(u16::MAX);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&raw[..usize::from(len)]);
}

/// Builds an MQTT v3.1.1 / v5.0 control packet payload.
pub fn build_mqtt_payload(
    _ctx: &WireContext,
    spec: &MqttSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let pkt_norm = spec
        .pkt_type
        .unwrap_or("connect")
        .to_ascii_uppercase()
        .replace(['_', '-'], "");
    let (is_v5, pkt_type_str): (bool, &str) = if let Some(s) = pkt_norm.strip_prefix("MQTT5") {
        (true, if s.is_empty() { "CONNECT" } else { s })
    } else if let Some(s) = pkt_norm.strip_prefix("V5") {
        (true, if s.is_empty() { "CONNECT" } else { s })
    } else if let Some(s) = pkt_norm.strip_suffix("V5") {
        (true, if s.is_empty() { "CONNECT" } else { s })
    } else if let Some(s) = pkt_norm.strip_suffix('5') {
        (true, if s.is_empty() { "CONNECT" } else { s })
    } else {
        (false, pkt_norm.as_str())
    };

    if pkt_type_str == "CONNACK" {
        return if is_v5 {
            vec![0x20, 0x03, 0x00, spec.return_code.unwrap_or(0), 0x00]
        } else {
            vec![0x20, 0x02, 0x00, spec.return_code.unwrap_or(0)]
        };
    } else if pkt_type_str == "PUBLISH" {
        let qos = spec
            .qos
            .unwrap_or(if spec.pkt_id.is_some() { 1 } else { 0 })
            & 0x03;
        let retain_bit = u8::from(spec.retain.unwrap_or(false));
        let b0 = 0x30 | (qos << 1) | retain_bit;

        let topic = spec.topic.unwrap_or("test/topic");
        let content: &[u8] = if !payload_bytes.is_empty() {
            payload_bytes
        } else if let Some(explicit) = spec.payload {
            explicit.as_bytes()
        } else {
            b"data"
        };

        let mut body = Vec::new();
        push_mqtt_utf8(&mut body, topic);
        if qos > 0 || spec.pkt_id.is_some() {
            body.extend_from_slice(&spec.pkt_id.unwrap_or(1).to_be_bytes());
        }
        if is_v5 {
            push_mqtt_varint(&mut body, 0); // MQTT 5.0 Properties length = 0
        }
        let room = MAX_MQTT_VARINT.saturating_sub(body.len());
        body.extend_from_slice(&content[..content.len().min(room)]);

        let mut pkt = Vec::with_capacity(5 + body.len());
        pkt.push(b0);
        push_mqtt_varint(&mut pkt, body.len());
        pkt.extend_from_slice(&body);
        return pkt;
    } else if pkt_type_str == "PUBACK" {
        let pkt_id = spec.pkt_id.unwrap_or(1).to_be_bytes();
        return if is_v5 {
            vec![
                0x40,
                0x04,
                pkt_id[0],
                pkt_id[1],
                spec.return_code.unwrap_or(0),
                0x00,
            ]
        } else {
            vec![0x40, 0x02, pkt_id[0], pkt_id[1]]
        };
    } else if pkt_type_str == "SUBSCRIBE" {
        let topic = spec.topic.unwrap_or("test/topic");
        let qos = spec.qos.unwrap_or(0) & 0x03;
        let mut body = Vec::new();
        body.extend_from_slice(&spec.pkt_id.unwrap_or(1).to_be_bytes());
        if is_v5 {
            push_mqtt_varint(&mut body, 0); // MQTT 5.0 Properties length = 0
        }
        push_mqtt_utf8(&mut body, topic);
        body.push(qos);
        if !payload_bytes.is_empty() {
            let room = MAX_MQTT_VARINT.saturating_sub(body.len());
            body.extend_from_slice(&payload_bytes[..payload_bytes.len().min(room)]);
        }
        let mut pkt = Vec::with_capacity(5 + body.len());
        pkt.push(0x82); // SUBSCRIBE (Type 8, reserved flags 0x02)
        push_mqtt_varint(&mut pkt, body.len());
        pkt.extend_from_slice(&body);
        return pkt;
    } else if pkt_type_str == "SUBACK" {
        let pkt_id = spec.pkt_id.unwrap_or(1).to_be_bytes();
        let rc = spec.return_code.unwrap_or(spec.qos.unwrap_or(0) & 0x03);
        return if is_v5 {
            vec![0x90, 0x04, pkt_id[0], pkt_id[1], 0x00, rc]
        } else {
            vec![0x90, 0x03, pkt_id[0], pkt_id[1], rc]
        };
    } else if pkt_type_str == "PINGREQ" {
        return vec![0xC0, 0x00];
    } else if pkt_type_str == "PINGRESP" {
        return vec![0xD0, 0x00];
    } else if pkt_type_str == "DISCONNECT" {
        return if is_v5 {
            vec![0xE0, 0x02, spec.return_code.unwrap_or(0), 0x00]
        } else {
            vec![0xE0, 0x00]
        };
    }

    // Default: CONNECT packet
    let client_id = spec.client_id.unwrap_or("client-01");
    let mut var_header = Vec::new();
    var_header.extend_from_slice(&[0x00, 0x04, b'M', b'Q', b'T', b'T']); // Protocol Name
    var_header.push(if is_v5 { 5 } else { 4 }); // Protocol Level 5 (v5.0) or 4 (v3.1.1)
    var_header.push(0x02); // CleanSession / CleanStart
    var_header.extend_from_slice(&spec.keepalive.unwrap_or(60).to_be_bytes()); // Keep Alive
    if is_v5 {
        push_mqtt_varint(&mut var_header, 0); // MQTT 5.0 Properties length = 0
    }
    push_mqtt_utf8(&mut var_header, client_id);

    if !payload_bytes.is_empty() {
        let room = MAX_MQTT_VARINT.saturating_sub(var_header.len());
        var_header.extend_from_slice(&payload_bytes[..payload_bytes.len().min(room)]);
    }

    let mut pkt = Vec::with_capacity(5 + var_header.len());
    pkt.push(0x10); // CONNECT (Type 1)
    push_mqtt_varint(&mut pkt, var_header.len());
    pkt.extend_from_slice(&var_header);
    pkt
}
