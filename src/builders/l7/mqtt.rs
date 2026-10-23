//! MQTT protocol wire builder.

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
        let topic = spec.topic.unwrap_or("test/topic");
        let topic_bytes = topic.as_bytes();
        let content = if !payload_bytes.is_empty() {
            payload_bytes
        } else {
            b"data"
        };
        let var_len = 2 + topic_bytes.len() + content.len();
        let mut pkt = Vec::with_capacity(2 + var_len);
        pkt.push(0x30); // PUBLISH (QoS 0)
        pkt.push(var_len as u8);
        pkt.extend_from_slice(&(topic_bytes.len() as u16).to_be_bytes());
        pkt.extend_from_slice(topic_bytes);
        pkt.extend_from_slice(content);
        return pkt;
    } else if pkt_type_str == "PINGREQ" {
        return vec![0xC0, 0x00];
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
