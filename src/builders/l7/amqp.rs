//! Advanced Message Queuing Protocol v0-9-1 (AMQP 0-9-1) wire payload builder.
//!
//! This module implements [`build_amqp_payload`], which serializes an [`AmqpSpec`]
//! AST node into an AMQP 0-9-1 wire frame over TCP port 5672 (or 5671 for AMQPS). Depending on the
//! selected flags, it emits the 8-byte `AMQP\x00\x00\x09\x01` protocol header, a Type 8 Heartbeat
//! frame, or a Type 1 Method frame (1-byte type, 16-bit channel, 32-bit size, 16-bit Class ID,
//! 16-bit Method ID, bounded `shortstr` exchange/routing-key arguments, and trailing `0xCE`
//! frame-end marker) for `Connection.Start`, `Channel.Open`, `Basic.Publish`, and `Basic.Deliver`.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Appends an AMQP 0-9-1 `shortstr` (1-byte length <= 255 followed by UTF-8 octets).
fn push_amqp_shortstr(out: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(255);
    out.push(len as u8);
    out.extend_from_slice(&bytes[..len]);
}

/// Builds an AMQP 0-9-1 protocol header or frame payload.
pub fn build_amqp_payload(
    _ctx: &WireContext,
    spec: &AmqpSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let has_method_or_frame = spec.is_connection_start
        || spec.is_channel_open
        || spec.is_basic_publish
        || spec.is_basic_deliver
        || spec.is_heartbeat
        || spec.channel.is_some()
        || spec.exchange.is_some()
        || spec.routing_key.is_some();

    if spec.is_protocol_header || !has_method_or_frame {
        let mut pkt = b"AMQP\x00\x00\x09\x01".to_vec();
        if !payload_bytes.is_empty() {
            pkt.extend_from_slice(payload_bytes);
        }
        return pkt;
    }

    if spec.is_heartbeat {
        let channel = spec.channel.unwrap_or(0);
        let size = u32::try_from(payload_bytes.len()).unwrap_or(u32::MAX);
        let mut pkt = Vec::with_capacity(8 + payload_bytes.len());
        pkt.push(8); // Frame Type 8: Heartbeat
        pkt.extend_from_slice(&channel.to_be_bytes());
        pkt.extend_from_slice(&size.to_be_bytes());
        if !payload_bytes.is_empty() {
            pkt.extend_from_slice(payload_bytes);
        }
        pkt.push(0xCE); // Frame-End octet
        return pkt;
    }

    let (class_id, method_id, default_channel): (u16, u16, u16) = if spec.is_connection_start {
        (10, 10, 0)
    } else if spec.is_channel_open {
        (20, 10, 1)
    } else if spec.is_basic_deliver {
        (60, 60, 1)
    } else if spec.is_basic_publish || spec.exchange.is_some() || spec.routing_key.is_some() {
        (60, 40, 1)
    } else {
        (20, 10, 1)
    };

    let channel = spec.channel.unwrap_or(default_channel);
    let mut body = Vec::new();
    body.extend_from_slice(&class_id.to_be_bytes());
    body.extend_from_slice(&method_id.to_be_bytes());

    if (class_id, method_id) == (10, 10) {
        // Connection.Start: version-major (0), version-minor (9), server-properties (0), mechanisms ("PLAIN"), locales ("en_US")
        body.push(0);
        body.push(9);
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&5u32.to_be_bytes());
        body.extend_from_slice(b"PLAIN");
        body.extend_from_slice(&5u32.to_be_bytes());
        body.extend_from_slice(b"en_US");
    } else if (class_id, method_id) == (20, 10) {
        // Channel.Open: reserved-1 shortstr ("")
        body.push(0);
        if spec.exchange.is_some() || spec.routing_key.is_some() {
            push_amqp_shortstr(&mut body, spec.exchange.unwrap_or(""));
            push_amqp_shortstr(&mut body, spec.routing_key.unwrap_or(""));
        }
    } else if (class_id, method_id) == (60, 40) {
        // Basic.Publish: ticket (0u16), exchange (shortstr), routing-key (shortstr), mandatory/immediate (0u8)
        body.extend_from_slice(&0u16.to_be_bytes());
        push_amqp_shortstr(&mut body, spec.exchange.unwrap_or(""));
        push_amqp_shortstr(&mut body, spec.routing_key.unwrap_or(""));
        body.push(0);
    } else if (class_id, method_id) == (60, 60) {
        // Basic.Deliver: consumer-tag (shortstr), delivery-tag (u64), redelivered (u8), exchange (shortstr), routing-key (shortstr)
        push_amqp_shortstr(&mut body, "ctag");
        body.extend_from_slice(&1u64.to_be_bytes());
        body.push(0);
        push_amqp_shortstr(&mut body, spec.exchange.unwrap_or(""));
        push_amqp_shortstr(&mut body, spec.routing_key.unwrap_or(""));
    }

    if !payload_bytes.is_empty() {
        body.extend_from_slice(payload_bytes);
    }

    let size = u32::try_from(body.len()).unwrap_or(u32::MAX);
    let mut pkt = Vec::with_capacity(8 + body.len());
    pkt.push(1); // Frame Type 1: Method
    pkt.extend_from_slice(&channel.to_be_bytes());
    pkt.extend_from_slice(&size.to_be_bytes());
    pkt.extend_from_slice(&body);
    pkt.push(0xCE); // Frame-End octet
    pkt
}
