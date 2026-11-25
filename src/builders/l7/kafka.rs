//! Apache Kafka Binary Wire Protocol (TCP port `9092`) Layer 7 wire builder.
//!
//! This module serializes [`KafkaSpec`] into Apache Kafka TCP protocol frames with the 4-byte
//! big-endian `message_size` prefix, `RequestHeader v1` / `ResponseHeader v0`, and non-flexible
//! v0 bodies for `Produce` (`0`, including IEEE 802.3 CRC32 MessageSet v0), `Fetch` (`1`),
//! `Metadata` (`3`), `Heartbeat` (`12`), and `ApiVersions` (`18`).

use alloc::vec::Vec;

use crate::ast::*;
use crate::builders::WireContext;
use crate::packet::ieee8023_crc32;

/// Appends a Kafka STRING (`i16` length + UTF-8 bytes) or NULLABLE_STRING (`-1` if `None`).
fn push_kafka_str(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.extend_from_slice(&(bytes.len() as i16).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Appends a single Kafka MessageSet v0 record with IEEE 802.3 CRC32.
fn push_message_set_v0(buf: &mut Vec<u8>, offset: i64, key: Option<&str>, value: &[u8]) {
    let key_bytes_len: usize = match key {
        Some(k) => 4 + k.len(),
        None => 4,
    };
    let val_bytes_len: usize = 4 + value.len();
    let mut inner = Vec::with_capacity(2 + key_bytes_len + val_bytes_len);
    inner.push(0); // magic v0
    inner.push(0); // attributes
    if let Some(k) = key {
        inner.extend_from_slice(&(k.len() as i32).to_be_bytes());
        inner.extend_from_slice(k.as_bytes());
    } else {
        inner.extend_from_slice(&(-1i32).to_be_bytes());
    }
    inner.extend_from_slice(&(value.len() as i32).to_be_bytes());
    inner.extend_from_slice(value);

    let crc = ieee8023_crc32(&inner);
    let msg_size = (4 + inner.len()) as i32;
    let total_set_size = (8 + 4 + 4 + inner.len()) as i32;

    buf.extend_from_slice(&total_set_size.to_be_bytes());
    buf.extend_from_slice(&offset.to_be_bytes());
    buf.extend_from_slice(&msg_size.to_be_bytes());
    buf.extend_from_slice(&crc.to_be_bytes());
    buf.extend_from_slice(&inner);
}

/// Resolves Kafka `api_key` from explicit `spec.api` or implied field selectors.
fn resolve_kafka_api_key(spec: &KafkaSpec<'_>, has_payload: bool) -> i16 {
    match spec.api {
        Some("produce") | Some("0") => 0,
        Some("fetch") | Some("1") => 1,
        Some("metadata") | Some("3") => 3,
        Some("heartbeat") | Some("12") => 12,
        Some("apiversions") | Some("18") => 18,
        Some(other) => other.parse::<i16>().unwrap_or(18),
        None => {
            if spec.group.is_some() {
                12
            } else if spec.key.is_some()
                || spec.value.is_some()
                || spec.acks.is_some()
                || (has_payload && !spec.is_response && spec.offset.is_none())
            {
                0
            } else if spec.offset.is_some() {
                1
            } else if spec.topic.is_some() || spec.partition.is_some() {
                3
            } else {
                18
            }
        }
    }
}

/// Builds an Apache Kafka wire frame from `spec` and optional `payload_bytes`.
pub fn build_kafka_payload(
    _ctx: &WireContext,
    spec: &KafkaSpec<'_>,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let api_key = resolve_kafka_api_key(spec, !payload_bytes.is_empty());
    let api_version = spec.api_version.unwrap_or(0) as i16;
    let corr_id = spec.correlation_id.unwrap_or(1);
    let client_id = spec.client_id.unwrap_or("frameassembly");
    let topic = spec.topic.unwrap_or("test-topic");
    let partition = spec.partition.unwrap_or(0);
    let offset = spec.offset.unwrap_or(0) as i64;
    let errcode = spec.errcode.unwrap_or(0);
    let acks = spec.acks.unwrap_or(1);
    let group = spec.group.unwrap_or("group1");

    let mut frame = Vec::with_capacity(96 + payload_bytes.len());
    if !spec.is_response {
        frame.extend_from_slice(&api_key.to_be_bytes());
        frame.extend_from_slice(&api_version.to_be_bytes());
        frame.extend_from_slice(&corr_id.to_be_bytes());
        push_kafka_str(&mut frame, client_id);

        match api_key {
            18 => {
                frame.extend_from_slice(payload_bytes);
            }
            3 => {
                frame.extend_from_slice(&1i32.to_be_bytes());
                push_kafka_str(&mut frame, topic);
                frame.extend_from_slice(payload_bytes);
            }
            0 => {
                let val: &[u8] = if let Some(v) = spec.value {
                    v.as_bytes()
                } else if !payload_bytes.is_empty() {
                    payload_bytes
                } else {
                    b"hello"
                };
                frame.extend_from_slice(&acks.to_be_bytes());
                frame.extend_from_slice(&1000i32.to_be_bytes());
                frame.extend_from_slice(&1i32.to_be_bytes());
                push_kafka_str(&mut frame, topic);
                frame.extend_from_slice(&1i32.to_be_bytes());
                frame.extend_from_slice(&partition.to_be_bytes());
                push_message_set_v0(&mut frame, offset, spec.key, val);
            }
            1 => {
                frame.extend_from_slice(&(-1i32).to_be_bytes());
                frame.extend_from_slice(&500i32.to_be_bytes());
                frame.extend_from_slice(&1i32.to_be_bytes());
                frame.extend_from_slice(&1i32.to_be_bytes());
                push_kafka_str(&mut frame, topic);
                frame.extend_from_slice(&1i32.to_be_bytes());
                frame.extend_from_slice(&partition.to_be_bytes());
                frame.extend_from_slice(&offset.to_be_bytes());
                frame.extend_from_slice(&1_048_576i32.to_be_bytes());
                frame.extend_from_slice(payload_bytes);
            }
            12 => {
                push_kafka_str(&mut frame, group);
                frame.extend_from_slice(&1i32.to_be_bytes());
                push_kafka_str(&mut frame, "");
                frame.extend_from_slice(payload_bytes);
            }
            _ => {
                frame.extend_from_slice(payload_bytes);
            }
        }
    } else {
        frame.extend_from_slice(&corr_id.to_be_bytes());
        match api_key {
            18 => {
                frame.extend_from_slice(&errcode.to_be_bytes());
                frame.extend_from_slice(&1i32.to_be_bytes());
                frame.extend_from_slice(&18i16.to_be_bytes());
                frame.extend_from_slice(&0i16.to_be_bytes());
                frame.extend_from_slice(&3i16.to_be_bytes());
                frame.extend_from_slice(payload_bytes);
            }
            3 => {
                frame.extend_from_slice(&1i32.to_be_bytes()); // brokers
                frame.extend_from_slice(&1i32.to_be_bytes()); // node_id
                push_kafka_str(&mut frame, "broker");
                frame.extend_from_slice(&9092i32.to_be_bytes());
                frame.extend_from_slice(&1i32.to_be_bytes()); // topics
                frame.extend_from_slice(&errcode.to_be_bytes());
                push_kafka_str(&mut frame, topic);
                frame.extend_from_slice(&1i32.to_be_bytes()); // partitions
                frame.extend_from_slice(&0i16.to_be_bytes()); // part err
                frame.extend_from_slice(&partition.to_be_bytes());
                frame.extend_from_slice(&1i32.to_be_bytes()); // leader
                frame.extend_from_slice(&1i32.to_be_bytes()); // replicas len
                frame.extend_from_slice(&1i32.to_be_bytes()); // replica 1
                frame.extend_from_slice(&1i32.to_be_bytes()); // isr len
                frame.extend_from_slice(&1i32.to_be_bytes()); // isr 1
                frame.extend_from_slice(payload_bytes);
            }
            0 => {
                frame.extend_from_slice(&1i32.to_be_bytes());
                push_kafka_str(&mut frame, topic);
                frame.extend_from_slice(&1i32.to_be_bytes());
                frame.extend_from_slice(&partition.to_be_bytes());
                frame.extend_from_slice(&errcode.to_be_bytes());
                frame.extend_from_slice(&offset.to_be_bytes());
                frame.extend_from_slice(payload_bytes);
            }
            1 => {
                frame.extend_from_slice(&1i32.to_be_bytes());
                push_kafka_str(&mut frame, topic);
                frame.extend_from_slice(&1i32.to_be_bytes());
                frame.extend_from_slice(&partition.to_be_bytes());
                frame.extend_from_slice(&errcode.to_be_bytes());
                frame.extend_from_slice(&1i64.to_be_bytes()); // high_watermark
                if let Some(v) = spec.value {
                    push_message_set_v0(&mut frame, offset, spec.key, v.as_bytes());
                } else if spec.key.is_some() || !payload_bytes.is_empty() {
                    let v: &[u8] = if payload_bytes.is_empty() {
                        b"hello"
                    } else {
                        payload_bytes
                    };
                    push_message_set_v0(&mut frame, offset, spec.key, v);
                } else {
                    frame.extend_from_slice(&0i32.to_be_bytes());
                }
            }
            12 => {
                frame.extend_from_slice(&errcode.to_be_bytes());
                frame.extend_from_slice(payload_bytes);
            }
            _ => {
                frame.extend_from_slice(payload_bytes);
            }
        }
    }

    let mut out = Vec::with_capacity(4 + frame.len());
    out.extend_from_slice(&(frame.len() as i32).to_be_bytes());
    out.extend_from_slice(&frame);
    out
}
