//! Apache Kafka Binary Wire Protocol (TCP port `9092`) Layer 7 decompiler.
//!
//! This module implements fuzz-safe reverse dissection for `kafka` TCP/SCTP packets on port
//! `9092`. It validates the 4-byte length prefix, disambiguates client `RequestHeader v1` and
//! broker `ResponseHeader v0` frames for `ApiVersions` (`18`), `Metadata` (`3`), `Produce` (`0`),
//! `Fetch` (`1`), and `Heartbeat` (`12`) (including IEEE 802.3 CRC32 MessageSet verification),
//! and elides default values for clean roundtrips.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::{Protocol, TransportProto};
use crate::packet::ieee8023_crc32;
use crate::reverse::ProtocolDissection;

use super::{is_valid_raw_string_body, push_str_if, quote_raw_str};

/// Reads a big-endian `i16` at `pos`, advancing `pos`.
fn read_i16(data: &[u8], pos: &mut usize) -> Option<i16> {
    let b = data.get(*pos..pos.checked_add(2)?)?;
    *pos += 2;
    Some(i16::from_be_bytes([b[0], b[1]]))
}

/// Reads a big-endian `i32` at `pos`, advancing `pos`.
fn read_i32(data: &[u8], pos: &mut usize) -> Option<i32> {
    let b = data.get(*pos..pos.checked_add(4)?)?;
    *pos += 4;
    Some(i32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Reads a big-endian `i64` at `pos`, advancing `pos`.
fn read_i64(data: &[u8], pos: &mut usize) -> Option<i64> {
    let b = data.get(*pos..pos.checked_add(8)?)?;
    *pos += 8;
    Some(i64::from_be_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

/// Reads a Kafka STRING (`i16` length + UTF-8 validated for raw `.frasm` string output).
fn read_kafka_str<'a>(data: &'a [u8], pos: &mut usize) -> Option<&'a str> {
    let len = read_i16(data, pos)?;
    if len < 0 {
        return None;
    }
    let ulen = len as usize;
    let slice = data.get(*pos..pos.checked_add(ulen)?)?;
    *pos += ulen;
    let s = core::str::from_utf8(slice).ok()?;
    is_valid_raw_string_body(s).then_some(s)
}

/// Reads a Kafka MessageSet v0 single record (`offset`, optional `key`, raw `value` bytes).
fn read_message_set_v0(set: &[u8]) -> Option<(i64, Option<&str>, &[u8])> {
    let mut pos = 0usize;
    let offset = read_i64(set, &mut pos)?;
    let msg_size = read_i32(set, &mut pos)?;
    if msg_size < 14 || pos.checked_add(msg_size as usize)? != set.len() {
        return None;
    }
    let crc = read_i32(set, &mut pos)? as u32;
    let inner = set.get(pos..)?;
    if ieee8023_crc32(inner) != crc || inner.len() < 10 || inner[0] != 0 || inner[1] != 0 {
        return None;
    }
    let mut ipos = 2usize;
    let key_len = read_i32(inner, &mut ipos)?;
    let key = if key_len == -1 {
        None
    } else if key_len >= 0 {
        let kb = inner.get(ipos..ipos.checked_add(key_len as usize)?)?;
        ipos += key_len as usize;
        let ks = core::str::from_utf8(kb).ok()?;
        if !is_valid_raw_string_body(ks) {
            return None;
        }
        Some(ks)
    } else {
        return None;
    };
    let val_len = read_i32(inner, &mut ipos)?;
    if val_len < 0 {
        return None;
    }
    let val = inner.get(ipos..ipos.checked_add(val_len as usize)?)?;
    ipos += val_len as usize;
    if ipos != inner.len() {
        return None;
    }
    Some((offset, key, val))
}

/// Appends common Kafka header/topic/partition/value/offset/err modifiers cleanly.
fn append_common_mods(
    tokens: &mut String,
    api_version: Option<i16>,
    corr_id: i32,
    client_id: Option<&str>,
    errcode: Option<i16>,
) {
    if let Some(ver) = api_version
        && ver != 0
    {
        let _ = write!(tokens, " version {}", ver as u16);
    }
    if corr_id != 1 {
        let _ = write!(tokens, " correlationid {corr_id}");
    }
    if let Some(cid) = client_id {
        push_str_if(tokens, "clientid", cid, "frameassembly");
    }
    if let Some(ec) = errcode
        && ec != 0
    {
        let _ = write!(tokens, " errcode {ec}");
    }
}

/// Attempts to dissect `frame` (after 4-byte length prefix) as a Kafka RequestHeader v1 message.
fn try_dissect_request(frame: &[u8]) -> Option<ProtocolDissection> {
    let mut pos = 0usize;
    let api_key = read_i16(frame, &mut pos)?;
    let api_version = read_i16(frame, &mut pos)?;
    if api_version < 0 {
        return None;
    }
    let corr_id = read_i32(frame, &mut pos)?;
    let client_id = read_kafka_str(frame, &mut pos)?;

    let mut tokens = String::from("kafka");
    let mut residual = Vec::new();

    match api_key {
        18 => {
            append_common_mods(&mut tokens, Some(api_version), corr_id, Some(client_id), None);
            residual.extend_from_slice(frame.get(pos..)?);
        }
        3 => {
            if read_i32(frame, &mut pos)? != 1 {
                return None;
            }
            let topic = read_kafka_str(frame, &mut pos)?;
            tokens.push_str(" metadata");
            append_common_mods(&mut tokens, Some(api_version), corr_id, Some(client_id), None);
            push_str_if(&mut tokens, "topic", topic, "test-topic");
            residual.extend_from_slice(frame.get(pos..)?);
        }
        0 => {
            let acks = read_i16(frame, &mut pos)?;
            let timeout = read_i32(frame, &mut pos)?;
            let tcnt = read_i32(frame, &mut pos)?;
            if timeout != 1000 || tcnt != 1 {
                return None;
            }
            let topic = read_kafka_str(frame, &mut pos)?;
            if read_i32(frame, &mut pos)? != 1 {
                return None;
            }
            let partition = read_i32(frame, &mut pos)?;
            let set_len = read_i32(frame, &mut pos)?;
            if set_len <= 0 || pos.checked_add(set_len as usize)? != frame.len() {
                return None;
            }
            let (offset, key, val) = read_message_set_v0(frame.get(pos..)?)?;
            tokens.push_str(" produce");
            append_common_mods(&mut tokens, Some(api_version), corr_id, Some(client_id), None);
            push_str_if(&mut tokens, "topic", topic, "test-topic");
            if partition != 0 {
                let _ = write!(tokens, " partition {partition}");
            }
            if offset != 0 {
                let _ = write!(tokens, " offset {}", offset as u64);
            }
            if acks != 1 {
                let _ = write!(tokens, " acks {acks}");
            }
            if let Some(k) = key {
                let _ = write!(tokens, " key \"{}\"", quote_raw_str(k));
            }
            if let Some(vs) = core::str::from_utf8(val).ok().filter(|s| is_valid_raw_string_body(s)) {
                push_str_if(&mut tokens, "value", vs, "hello");
            } else {
                residual.extend_from_slice(val);
            }
        }
        1 => {
            if read_i32(frame, &mut pos)? != -1
                || read_i32(frame, &mut pos)? != 500
                || read_i32(frame, &mut pos)? != 1
                || read_i32(frame, &mut pos)? != 1
            {
                return None;
            }
            let topic = read_kafka_str(frame, &mut pos)?;
            if read_i32(frame, &mut pos)? != 1 {
                return None;
            }
            let partition = read_i32(frame, &mut pos)?;
            let offset = read_i64(frame, &mut pos)?;
            if read_i32(frame, &mut pos)? != 1_048_576 {
                return None;
            }
            tokens.push_str(" fetch");
            append_common_mods(&mut tokens, Some(api_version), corr_id, Some(client_id), None);
            push_str_if(&mut tokens, "topic", topic, "test-topic");
            if partition != 0 {
                let _ = write!(tokens, " partition {partition}");
            }
            if offset != 0 {
                let _ = write!(tokens, " offset {}", offset as u64);
            }
            residual.extend_from_slice(frame.get(pos..)?);
        }
        12 => {
            let group = read_kafka_str(frame, &mut pos)?;
            if read_i32(frame, &mut pos)? != 1 || !read_kafka_str(frame, &mut pos)?.is_empty() {
                return None;
            }
            tokens.push_str(" heartbeat");
            append_common_mods(&mut tokens, Some(api_version), corr_id, Some(client_id), None);
            push_str_if(&mut tokens, "group", group, "group1");
            residual.extend_from_slice(frame.get(pos..)?);
        }
        _ => return None,
    }

    Some(ProtocolDissection {
        protocol: Protocol::Kafka,
        tokens,
        residual_payload: residual,
        explicit_transport: None,
    })
}

/// Attempts to dissect `frame` (after 4-byte length prefix) as a Kafka ResponseHeader v0 message.
fn try_dissect_response(frame: &[u8]) -> Option<ProtocolDissection> {
    let mut pos = 0usize;
    let corr_id = read_i32(frame, &mut pos)?;
    let rest = frame.get(pos..)?;

    // HeartbeatResponse: exact 2-byte error_code
    if rest.len() == 2 {
        let mut rpos = 0usize;
        let errcode = read_i16(rest, &mut rpos)?;
        let mut tokens = String::from("kafka heartbeat response");
        append_common_mods(&mut tokens, None, corr_id, None, Some(errcode));
        return Some(ProtocolDissection {
            protocol: Protocol::Kafka,
            tokens,
            residual_payload: Vec::new(),
            explicit_transport: None,
        });
    }

    // ApiVersionsResponse: error_code(2) + cnt=1(4) + [18, 0, 3](6) + residual
    if rest.len() >= 12 && rest[2..12] == [0, 0, 0, 1, 0, 18, 0, 0, 0, 3] {
        let errcode = i16::from_be_bytes([rest[0], rest[1]]);
        let mut tokens = String::from("kafka response");
        append_common_mods(&mut tokens, None, corr_id, None, Some(errcode));
        return Some(ProtocolDissection {
            protocol: Protocol::Kafka,
            tokens,
            residual_payload: rest[12..].to_vec(),
            explicit_transport: None,
        });
    }

    // MetadataResponse: brokers=[1, "broker", 9092] + topics=[err, topic, parts=[0, part, 1, [1], [1]]]
    if rest.len() >= 20 && rest[0..16] == [0, 0, 0, 1, 0, 0, 0, 1, 0, 6, b'b', b'r', b'o', b'k', b'e', b'r'] {
        let mut mpos = 16usize;
        if read_i32(rest, &mut mpos)? != 9092 || read_i32(rest, &mut mpos)? != 1 {
            return None;
        }
        let errcode = read_i16(rest, &mut mpos)?;
        let topic = read_kafka_str(rest, &mut mpos)?;
        if read_i32(rest, &mut mpos)? != 1 || read_i16(rest, &mut mpos)? != 0 {
            return None;
        }
        let partition = read_i32(rest, &mut mpos)?;
        if read_i32(rest, &mut mpos)? != 1
            || read_i32(rest, &mut mpos)? != 1
            || read_i32(rest, &mut mpos)? != 1
            || read_i32(rest, &mut mpos)? != 1
            || read_i32(rest, &mut mpos)? != 1
        {
            return None;
        }
        let mut tokens = String::from("kafka metadata response");
        append_common_mods(&mut tokens, None, corr_id, None, Some(errcode));
        push_str_if(&mut tokens, "topic", topic, "test-topic");
        if partition != 0 {
            let _ = write!(tokens, " partition {partition}");
        }
        return Some(ProtocolDissection {
            protocol: Protocol::Kafka,
            tokens,
            residual_payload: rest.get(mpos..)?.to_vec(),
            explicit_transport: None,
        });
    }

    // ProduceResponse or FetchResponse: topics_count=1 + topic + parts_count=1 + part + errcode
    let mut rpos = 0usize;
    if read_i32(rest, &mut rpos)? == 1 {
        let topic = read_kafka_str(rest, &mut rpos)?;
        if read_i32(rest, &mut rpos)? == 1 {
            let partition = read_i32(rest, &mut rpos)?;
            let errcode = read_i16(rest, &mut rpos)?;
            let tail = rest.get(rpos..)?;
            if tail.len() >= 12 {
                let first_i64 = i64::from_be_bytes([
                    tail[0], tail[1], tail[2], tail[3], tail[4], tail[5], tail[6], tail[7],
                ]);
                let rec_len = i32::from_be_bytes([tail[8], tail[9], tail[10], tail[11]]);
                if first_i64 == 1
                    && rec_len >= 0
                    && tail.len() == 12usize.checked_add(rec_len as usize)?
                {
                    let mut tokens = String::from("kafka fetch response");
                    append_common_mods(&mut tokens, None, corr_id, None, Some(errcode));
                    push_str_if(&mut tokens, "topic", topic, "test-topic");
                    if partition != 0 {
                        let _ = write!(tokens, " partition {partition}");
                    }
                    let mut residual = Vec::new();
                    if rec_len > 0 {
                        let (offset, key, val) = read_message_set_v0(&tail[12..])?;
                        if offset != 0 {
                            let _ = write!(tokens, " offset {}", offset as u64);
                        }
                        if let Some(k) = key {
                            let _ = write!(tokens, " key \"{}\"", quote_raw_str(k));
                        }
                        if let Some(vs) =
                            core::str::from_utf8(val).ok().filter(|s| is_valid_raw_string_body(s))
                        {
                            let _ = write!(tokens, " value \"{}\"", quote_raw_str(vs));
                        } else {
                            residual.extend_from_slice(val);
                        }
                    }
                    return Some(ProtocolDissection {
                        protocol: Protocol::Kafka,
                        tokens,
                        residual_payload: residual,
                        explicit_transport: None,
                    });
                }
            }
            if tail.len() >= 8 {
                let offset = i64::from_be_bytes([
                    tail[0], tail[1], tail[2], tail[3], tail[4], tail[5], tail[6], tail[7],
                ]);
                let mut tokens = String::from("kafka produce response");
                append_common_mods(&mut tokens, None, corr_id, None, Some(errcode));
                push_str_if(&mut tokens, "topic", topic, "test-topic");
                if partition != 0 {
                    let _ = write!(tokens, " partition {partition}");
                }
                if offset != 0 {
                    let _ = write!(tokens, " offset {}", offset as u64);
                }
                return Some(ProtocolDissection {
                    protocol: Protocol::Kafka,
                    tokens,
                    residual_payload: tail[8..].to_vec(),
                    explicit_transport: None,
                });
            }
        }
    }

    None
}

/// Dissects an Apache Kafka binary wire protocol packet carried over TCP or SCTP port `9092`.
pub(crate) fn dissect_kafka(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(transport, TransportProto::Tcp | TransportProto::Sctp)
        || !(src_port == 9092 || dst_port == 9092)
        || payload.len() < 8
    {
        return None;
    }
    let msg_size = i32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    if msg_size < 4 || payload.len() != 4usize.checked_add(msg_size as usize)? {
        return None;
    }
    let frame = &payload[4..];
    if src_port == 9092 && dst_port != 9092 {
        try_dissect_response(frame).or_else(|| try_dissect_request(frame))
    } else {
        try_dissect_request(frame).or_else(|| try_dissect_response(frame))
    }
}
