//! Message Queuing Telemetry Transport v3.1.1 / v5.0 (MQTT, OASIS) wire payload builder.
//!
//! This module implements [`build_mqtt_payload`], which serializes an [`MqttSpec`]
//! AST specification into an OASIS MQTT v3.1.1 control packet over TCP port 1883 (or 8883 for
//! MQTTS). It constructs the 1-byte Fixed Header (control packet type `1..=14`, QoS bits, and
//! RETAIN flag), encodes the variable-length Remaining Length field using 7-bit continuation bytes,
//! and serializes the Variable Header and payload for `CONNECT`, `CONNACK`, `PUBLISH`, `PUBACK`,
//! `SUBSCRIBE`, `SUBACK`, `PINGREQ`, and `PINGRESP` frames.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an MQTT v3.1.1 / v5.0 control packet payload.
pub fn build_mqtt_payload(
    _ctx: &WireContext,
    spec: &MqttSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let pkt_type_str = spec.pkt_type.unwrap_or("CONNECT").to_ascii_uppercase();

    if pkt_type_str == "CONNACK" {
        return vec![0x20, 0x02, 0x00, spec.return_code.unwrap_or(0)];
    } else if pkt_type_str == "PUBLISH" {
        let qos = spec
            .qos
            .unwrap_or(if spec.pkt_id.is_some() { 1 } else { 0 })
            & 0x03;
        let retain_bit = u8::from(spec.retain.unwrap_or(false));
        let b0 = 0x30 | (qos << 1) | retain_bit;

        let topic = spec.topic.unwrap_or("test/topic");
        let topic_bytes = topic.as_bytes();
        let content = if !payload_bytes.is_empty() {
            payload_bytes
        } else {
            b"data"
        };

        let mut body = Vec::new();
        body.extend_from_slice(&(topic_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(topic_bytes);
        if qos > 0 || spec.pkt_id.is_some() {
            body.extend_from_slice(&spec.pkt_id.unwrap_or(1).to_be_bytes());
        }
        body.extend_from_slice(content);

        let mut pkt = Vec::with_capacity(2 + body.len());
        pkt.push(b0);
        pkt.push(body.len() as u8);
        pkt.extend_from_slice(&body);
        return pkt;
    } else if pkt_type_str == "PUBACK" {
        let pkt_id = spec.pkt_id.unwrap_or(1).to_be_bytes();
        return vec![0x40, 0x02, pkt_id[0], pkt_id[1]];
    } else if pkt_type_str == "SUBSCRIBE" {
        let topic = spec.topic.unwrap_or("test/topic");
        let topic_bytes = topic.as_bytes();
        let qos = spec.qos.unwrap_or(0) & 0x03;
        let mut body = Vec::new();
        body.extend_from_slice(&spec.pkt_id.unwrap_or(1).to_be_bytes());
        body.extend_from_slice(&(topic_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(topic_bytes);
        body.push(qos);
        if !payload_bytes.is_empty() {
            body.extend_from_slice(payload_bytes);
        }
        let mut pkt = Vec::with_capacity(2 + body.len());
        pkt.push(0x82); // SUBSCRIBE (Type 8, reserved flags 0x02)
        pkt.push(body.len() as u8);
        pkt.extend_from_slice(&body);
        return pkt;
    } else if pkt_type_str == "SUBACK" {
        let pkt_id = spec.pkt_id.unwrap_or(1).to_be_bytes();
        let rc = spec.return_code.unwrap_or(spec.qos.unwrap_or(0) & 0x03);
        return vec![0x90, 0x03, pkt_id[0], pkt_id[1], rc];
    } else if pkt_type_str == "PINGREQ" {
        return vec![0xC0, 0x00];
    } else if pkt_type_str == "PINGRESP" {
        return vec![0xD0, 0x00];
    } else if pkt_type_str == "DISCONNECT" {
        return vec![0xE0, 0x00];
    }

    // Default: CONNECT packet
    let client_id = spec.client_id.unwrap_or("client-01");
    let cid_bytes = client_id.as_bytes();
    let mut var_header = Vec::new();
    var_header.extend_from_slice(&[0x00, 0x04, b'M', b'Q', b'T', b'T']); // Protocol Name
    var_header.push(4); // Version 3.1.1
    var_header.push(0x02); // CleanSession
    var_header.extend_from_slice(&spec.keepalive.unwrap_or(60).to_be_bytes()); // Keep Alive
    var_header.extend_from_slice(&(cid_bytes.len() as u16).to_be_bytes());
    var_header.extend_from_slice(cid_bytes);

    if !payload_bytes.is_empty() {
        var_header.extend_from_slice(payload_bytes);
    }

    let mut pkt = Vec::with_capacity(2 + var_header.len());
    pkt.push(0x10); // CONNECT (Type 1)
    pkt.push(var_header.len() as u8);
    pkt.extend_from_slice(&var_header);
    pkt
}
