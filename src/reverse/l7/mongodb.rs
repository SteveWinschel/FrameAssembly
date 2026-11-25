//! MongoDB Wire Protocol (`OP_MSG`, opCode 2013) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `mongodb` `OP_MSG` (`2013`)
//! request and response packets over TCP and SCTP ports `27017..=27019` and custom ports matching
//! the `OP_MSG` header and Section Kind `0` BSON document layout. It validates `messageLength`,
//! optional CRC-32C checksums (`flags & 1`), and BSON element framing, emitting `ping`, `query`,
//! `response`, `err`, `cmd`, `collection`, `db`, `filter`, `reqid`, `responseto`, `flags`,
//! `errcode`, `errmsg`, and binary `data` as `residual_payload`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::{ProtocolDissection, le_u32};

use super::{is_valid_raw_string_body, push_str_mod, quote_raw_str};

/// Reflected Castagnoli CRC-32C polynomial used for optional MongoDB `OP_MSG` checksums.
const CRC32C_POLY: u32 = 0x82F6_3B78;

/// Computes the Castagnoli CRC-32C checksum over `data`.
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

/// Reads a NUL-terminated UTF-8 C-string key starting at `pos` inside `doc`, returning `(str, next_pos)`.
fn read_cstring(doc: &[u8], pos: usize) -> Option<(&str, usize)> {
    let tail = doc.get(pos..)?;
    let nul_rel = tail.iter().position(|&b| b == 0)?;
    let s = core::str::from_utf8(tail.get(..nul_rel)?).ok()?;
    Some((s, pos + nul_rel + 1))
}

/// Reads a BSON UTF-8 string value (`i32` LE length including NUL + bytes + `0x00`) at `pos`.
fn read_bson_string(doc: &[u8], pos: usize) -> Option<(&str, usize)> {
    let len_bytes = doc.get(pos..pos.checked_add(4)?)?;
    let slen = i32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]);
    if slen < 1 {
        return None;
    }
    let slen_usize = slen as usize;
    let str_start = pos + 4;
    let str_end = str_start.checked_add(slen_usize)?;
    let raw = doc.get(str_start..str_end)?;
    if raw.last() != Some(&0) {
        return None;
    }
    let s = core::str::from_utf8(raw.get(..slen_usize - 1)?).ok()?;
    if !is_valid_raw_string_body(s) {
        return None;
    }
    Some((s, str_end))
}

/// Decoded fields extracted from a MongoDB `OP_MSG` Section Kind `0` BSON body document.
struct DecodedMongoDoc<'a> {
    /// Optional floating-point `"ok"` reply status (`1.0` or `0.0`).
    ok_val: Option<f64>,
    /// Optional error message string (`"errmsg"`).
    errmsg: Option<&'a str>,
    /// Optional numeric error code (`"code"`).
    errcode: Option<i32>,
    /// Primary command key name (first element when not a server reply).
    cmd: Option<&'a str>,
    /// Collection name string when the command value is a BSON UTF-8 string.
    col: Option<&'a str>,
    /// Embedded `"filter"` subdocument query string (`"q"`).
    filter: Option<&'a str>,
    /// Target database name (`"$db"`).
    db: Option<&'a str>,
    /// Optional Generic Binary `"data"` payload bytes.
    data_bin: Option<&'a [u8]>,
}

/// Decodes a validated MongoDB `OP_MSG` BSON body document slice (`doc` includes 4B len and `0x00` EOO).
fn decode_mongo_bson(doc: &[u8]) -> Option<DecodedMongoDoc<'_>> {
    if doc.len() < 5 || doc.last() != Some(&0) {
        return None;
    }
    let decl_len = i32::from_le_bytes([doc[0], doc[1], doc[2], doc[3]]);
    if decl_len < 5 || (decl_len as usize) != doc.len() {
        return None;
    }
    let end = doc.len() - 1;
    let mut pos = 4usize;
    let mut out = DecodedMongoDoc {
        ok_val: None,
        errmsg: None,
        errcode: None,
        cmd: None,
        col: None,
        filter: None,
        db: None,
        data_bin: None,
    };

    while pos < end {
        let etype = *doc.get(pos)?;
        pos += 1;
        let (key, next_pos) = read_cstring(doc, pos)?;
        pos = next_pos;

        match (etype, key) {
            (0x01, "ok") if out.ok_val.is_none() => {
                let raw = doc.get(pos..pos.checked_add(8)?)?;
                let mut arr = [0u8; 8];
                arr.copy_from_slice(raw);
                out.ok_val = Some(f64::from_le_bytes(arr));
                pos += 8;
            }
            (0x02, "errmsg") if out.errmsg.is_none() => {
                let (s, np) = read_bson_string(doc, pos)?;
                out.errmsg = Some(s);
                pos = np;
            }
            (0x10, "code") if out.errcode.is_none() => {
                let raw = doc.get(pos..pos.checked_add(4)?)?;
                out.errcode = Some(i32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]));
                pos += 4;
            }
            (0x02, "$db") if out.db.is_none() => {
                let (s, np) = read_bson_string(doc, pos)?;
                out.db = Some(s);
                pos = np;
            }
            (0x03, "filter") if out.filter.is_none() => {
                let raw_len = doc.get(pos..pos.checked_add(4)?)?;
                let sub_len =
                    i32::from_le_bytes([raw_len[0], raw_len[1], raw_len[2], raw_len[3]]);
                if sub_len < 5 {
                    return None;
                }
                let sub_end = pos.checked_add(sub_len as usize)?;
                let sub = doc.get(pos..sub_end)?;
                if sub.last() != Some(&0) || sub.get(4) != Some(&0x02) {
                    return None;
                }
                let (sub_k, sub_p) = read_cstring(sub, 5)?;
                if sub_k != "q" {
                    return None;
                }
                let (fval, sub_after) = read_bson_string(sub, sub_p)?;
                if sub_after != sub.len() - 1 {
                    return None;
                }
                out.filter = Some(fval);
                pos = sub_end;
            }
            (0x05, "data") if out.data_bin.is_none() => {
                let raw_len = doc.get(pos..pos.checked_add(4)?)?;
                let bin_len =
                    i32::from_le_bytes([raw_len[0], raw_len[1], raw_len[2], raw_len[3]]);
                if bin_len < 0 {
                    return None;
                }
                let subtype = *doc.get(pos + 4)?;
                if subtype != 0x00 {
                    return None;
                }
                let data_start = pos + 5;
                let data_end = data_start.checked_add(bin_len as usize)?;
                out.data_bin = Some(doc.get(data_start..data_end)?);
                pos = data_end;
            }
            (0x02, cmd_key) if out.cmd.is_none() && is_valid_raw_string_body(cmd_key) => {
                let (col_s, np) = read_bson_string(doc, pos)?;
                out.cmd = Some(cmd_key);
                out.col = Some(col_s);
                pos = np;
            }
            (0x10, cmd_key) if out.cmd.is_none() && is_valid_raw_string_body(cmd_key) => {
                let raw = doc.get(pos..pos.checked_add(4)?)?;
                if i32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) != 1 {
                    return None;
                }
                out.cmd = Some(cmd_key);
                pos += 4;
            }
            _ => return None,
        }
    }

    Some(out)
}

/// Dissects a `mongodb` `OP_MSG` (`2013`) wire packet over TCP or SCTP.
pub(crate) fn dissect_mongodb(
    transport: TransportProto,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(transport, TransportProto::Tcp | TransportProto::Sctp) || payload.len() < 26 {
        return None;
    }
    let msg_len = i32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    if msg_len < 26 || (msg_len as usize) != payload.len() {
        return None;
    }
    let req_id = le_u32(payload, 4);
    let response_to = le_u32(payload, 8);
    let opcode = i32::from_le_bytes([payload[12], payload[13], payload[14], payload[15]]);
    if opcode != 2013 {
        return None;
    }
    let flag_bits = le_u32(payload, 16);
    let has_checksum = (flag_bits & 0x0000_0001) != 0;
    let body_end = if has_checksum {
        if payload.len() < 30 {
            return None;
        }
        let csum_pos = payload.len() - 4;
        if crc32c(payload.get(..csum_pos)?) != le_u32(payload, csum_pos) {
            return None;
        }
        csum_pos
    } else {
        payload.len()
    };

    if payload.get(20) != Some(&0x00) {
        return None;
    }
    let doc = payload.get(21..body_end)?;
    let decoded = decode_mongo_bson(doc)?;

    let mut tokens = String::from("mongodb");
    let default_resp_to: u32;

    if decoded.ok_val == Some(0.0)
        && let (Some(errmsg), Some(errcode)) = (decoded.errmsg, decoded.errcode)
    {
        let code_u16 = u16::try_from(errcode).ok()?;
        tokens.push_str(" err");
        if code_u16 != 1 {
            let _ = write!(tokens, " errcode {code_u16}");
        }
        if errmsg != "command failed" {
            push_str_mod(&mut tokens, "errmsg", errmsg);
        }
        default_resp_to = 1;
    } else if decoded.ok_val == Some(1.0) && decoded.cmd.is_none() && decoded.db.is_none() {
        tokens.push_str(" response");
        default_resp_to = 1;
    } else if let (Some(cmd), Some(db)) = (decoded.cmd, decoded.db) {
        if cmd == "ping" && decoded.col.is_none() && decoded.filter.is_none() {
            // Bare `mongodb` default (`{"ping": 1, "$db": "admin"}`)
        } else if cmd == "find" && decoded.col.is_some() {
            tokens.push_str(" query");
            if let Some(col) = decoded.col
                && col != "items"
            {
                tokens.push_str(&format!(" collection \"{}\"", quote_raw_str(col)));
            }
        } else {
            push_str_mod(&mut tokens, "cmd", cmd);
            if let Some(col) = decoded.col {
                tokens.push_str(&format!(" collection \"{}\"", quote_raw_str(col)));
            }
        }
        if let Some(f) = decoded.filter {
            tokens.push_str(&format!(" filter \"{}\"", quote_raw_str(f)));
        }
        if db != "admin" {
            tokens.push_str(&format!(" db \"{}\"", quote_raw_str(db)));
        }
        default_resp_to = 0;
    } else {
        return None;
    }

    if req_id != 1 {
        let _ = write!(tokens, " reqid {req_id}");
    }
    if response_to != default_resp_to {
        let _ = write!(tokens, " responseto {response_to}");
    }
    if flag_bits != 0 {
        let _ = write!(tokens, " flags {flag_bits}");
    }

    let residual: Vec<u8> = decoded.data_bin.unwrap_or(&[]).to_vec();
    Some(ProtocolDissection {
        protocol: Protocol::Mongodb,
        tokens,
        residual_payload: residual,
        explicit_transport: None,
    })
}
