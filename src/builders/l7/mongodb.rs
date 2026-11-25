//! MongoDB Wire Protocol (`OP_MSG`, opCode 2013) Layer 7 payload builder.
//!
//! This module implements [`build_mongodb_payload`], which serializes a [`MongodbSpec`] AST
//! specification into a MongoDB `OP_MSG` (`2013`) wire packet over TCP port 27017. It constructs
//! the 16-byte little-endian `MsgHeader` (`messageLength`, `requestID`, `responseTo`, `opCode`),
//! 32-bit `flagBits`, a Section Kind `0` BSON body document encoding database commands (`ping`,
//! `find`, `insert`, `delete`), collection names, embedded `filter` subdocuments, `$db` targets,
//! or server `ok`/`errmsg`/`code` replies, plus an optional trailing CRC-32C checksum when bit 0
//! of `flagBits` is set.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Reflected Castagnoli CRC-32C polynomial used for optional MongoDB `OP_MSG` checksums.
const CRC32C_POLY: u32 = 0x82F6_3B78;

/// Computes the Castagnoli CRC-32C checksum over `data` for `OP_MSG` `checksumPresent` frames.
fn crc32c(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if (crc & 1) != 0 {
                (crc >> 1) ^ CRC32C_POLY
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Appends a NUL-terminated BSON C-string key (stripping embedded NUL octets) onto `buf`.
fn push_bson_cstring(buf: &mut Vec<u8>, key: &str) {
    for b in key.bytes() {
        if b != 0 {
            buf.push(b);
        }
    }
    buf.push(0x00);
}

/// Appends a BSON UTF-8 string element (`0x02`) onto `buf`.
fn push_bson_string(buf: &mut Vec<u8>, key: &str, val: &str) {
    buf.push(0x02);
    push_bson_cstring(buf, key);
    let len_with_nul = u32::try_from(val.len().saturating_add(1)).unwrap_or(u32::MAX);
    buf.extend_from_slice(&len_with_nul.to_le_bytes());
    buf.extend_from_slice(val.as_bytes());
    buf.push(0x00);
}

/// Appends a BSON 32-bit integer element (`0x10`) onto `buf`.
fn push_bson_i32(buf: &mut Vec<u8>, key: &str, val: i32) {
    buf.push(0x10);
    push_bson_cstring(buf, key);
    buf.extend_from_slice(&val.to_le_bytes());
}

/// Appends a BSON 64-bit IEEE 754 floating-point element (`0x01`) onto `buf`.
fn push_bson_f64(buf: &mut Vec<u8>, key: &str, val: f64) {
    buf.push(0x01);
    push_bson_cstring(buf, key);
    buf.extend_from_slice(&val.to_le_bytes());
}

/// Appends a BSON Generic Binary element (`0x05`, subtype `0x00`) onto `buf`.
fn push_bson_binary(buf: &mut Vec<u8>, key: &str, data: &[u8]) {
    buf.push(0x05);
    push_bson_cstring(buf, key);
    let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.push(0x00); // Generic binary subtype
    buf.extend_from_slice(data);
}

/// Appends a BSON embedded subdocument element (`0x03`) constructed by `build_inner`.
fn push_bson_doc_elem(buf: &mut Vec<u8>, key: &str, build_inner: impl FnOnce(&mut Vec<u8>)) {
    buf.push(0x03);
    push_bson_cstring(buf, key);
    let start = buf.len();
    buf.extend_from_slice(&[0u8; 4]);
    build_inner(buf);
    buf.push(0x00);
    let doc_len = i32::try_from(buf.len() - start).unwrap_or(i32::MAX);
    buf[start..start + 4].copy_from_slice(&doc_len.to_le_bytes());
}

/// Returns `true` when `cmd_lower` is a MongoDB command taking a collection name string value.
fn is_collection_command(cmd_lower: &str) -> bool {
    matches!(
        cmd_lower,
        "find" | "insert" | "update" | "delete" | "aggregate" | "count" | "distinct" | "findandmodify"
    )
}

/// Builds a MongoDB `OP_MSG` (`opCode = 2013`) wire packet payload.
pub fn build_mongodb_payload(
    _ctx: &WireContext,
    spec: &MongodbSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let is_err = spec.is_err || spec.errcode.is_some() || spec.errmsg.is_some();
    let is_resp = !is_err && spec.is_response;
    let req_id = spec.req_id.unwrap_or(1);
    let response_to = spec.response_to.unwrap_or(u32::from(is_err || is_resp));
    let flag_bits = spec.flags.unwrap_or(0);

    let mut doc = Vec::with_capacity(48 + payload_bytes.len());
    doc.extend_from_slice(&[0u8; 4]);

    if is_err {
        push_bson_f64(&mut doc, "ok", 0.0);
        push_bson_string(&mut doc, "errmsg", spec.errmsg.unwrap_or("command failed"));
        push_bson_i32(&mut doc, "code", i32::from(spec.errcode.unwrap_or(1)));
    } else if is_resp {
        push_bson_f64(&mut doc, "ok", 1.0);
    } else {
        let has_col_ctx = spec.collection.is_some() || spec.filter.is_some();
        let raw_cmd = spec
            .cmd
            .unwrap_or(if has_col_ctx { "find" } else { "ping" });
        let cmd_lower = raw_cmd.to_ascii_lowercase();
        if spec.collection.is_some() || is_collection_command(&cmd_lower) {
            push_bson_string(&mut doc, raw_cmd, spec.collection.unwrap_or("items"));
        } else {
            push_bson_i32(&mut doc, raw_cmd, 1);
        }
        if let Some(filter_str) = spec.filter {
            push_bson_doc_elem(&mut doc, "filter", |sub| {
                push_bson_string(sub, "q", filter_str);
            });
        }
        push_bson_string(&mut doc, "$db", spec.db.unwrap_or("admin"));
    }

    if !payload_bytes.is_empty() {
        push_bson_binary(&mut doc, "data", payload_bytes);
    }
    doc.push(0x00);
    let doc_len = i32::try_from(doc.len()).unwrap_or(i32::MAX);
    doc[0..4].copy_from_slice(&doc_len.to_le_bytes());

    let has_checksum = (flag_bits & 0x0000_0001) != 0;
    let msg_len = i32::try_from(21usize + doc.len() + if has_checksum { 4 } else { 0 })
        .unwrap_or(i32::MAX);

    let mut pkt = Vec::with_capacity(msg_len as usize);
    pkt.extend_from_slice(&msg_len.to_le_bytes());
    pkt.extend_from_slice(&req_id.to_le_bytes());
    pkt.extend_from_slice(&response_to.to_le_bytes());
    pkt.extend_from_slice(&2013i32.to_le_bytes());
    pkt.extend_from_slice(&flag_bits.to_le_bytes());
    pkt.push(0x00); // Section Kind 0: Body
    pkt.extend_from_slice(&doc);

    if has_checksum {
        let csum = crc32c(&pkt);
        pkt.extend_from_slice(&csum.to_le_bytes());
    }

    pkt
}
