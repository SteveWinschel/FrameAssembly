//! Microsoft SQL Server Tabular Data Stream (MS-TDS, TCP port `1433`) Layer 7 decompiler.
//!
//! This module implements fuzz-safe reverse dissection for `mssql` MS-TDS v7.4 frames on TCP
//! (or SCTP) port `1433`, covering `SQLBatch` (`0x01` with 22-byte `ALL_HEADERS` + UTF-16LE
//! text), `PRELOGIN` (`0x12`), `LOGIN7` (`0x10`), `Tabular Result` `DONE`/`ERROR` (`0x04`),
//! and `Attention` (`0x06`) while eliding defaults for exact `a -> b mssql` roundtrips.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

use super::{is_valid_raw_string_body, push_str_if, quote_raw_str};

/// Decodes an even-length UTF-16LE slice into a validated raw `.frasm` string.
fn decode_utf16le_raw(bytes: &[u8]) -> Option<String> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&c| u16::from_le_bytes(c))
        .collect();
    let s = String::from_utf16(&units).ok()?;
    is_valid_raw_string_body(&s).then_some(s)
}

/// Checks if `bytes` equals the canonical 22-byte MS-TDS `ALL_HEADERS` TransactionDescriptor block.
fn is_default_all_headers(bytes: &[u8]) -> bool {
    bytes.len() == 22
        && bytes[0..4] == 22u32.to_le_bytes()
        && bytes[4..8] == 18u32.to_le_bytes()
        && bytes[8..10] == 2u16.to_le_bytes()
        && bytes[10..18] == [0u8; 8]
        && bytes[18..22] == 1u32.to_le_bytes()
}

/// Canonical 33-byte `PRELOGIN` body emitted by the builder when `payload_bytes` is empty.
const DEFAULT_PRELOGIN_BODY: [u8; 33] = [
    0x00, 0x00, 21, 0x00, 6, 0x01, 0x00, 27, 0x00, 1, 0x02, 0x00, 28, 0x00, 1, 0x03, 0x00, 29,
    0x00, 4, 0xFF, 15, 0, 0, 0, 0, 0, 0x02, 0x00, 0, 0, 0, 0,
];

/// Dissects an MS-TDS (`mssql`) packet carried over TCP or SCTP port `1433`.
pub(crate) fn dissect_mssql(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(transport, TransportProto::Tcp | TransportProto::Sctp)
        || !(src_port == 1433 || dst_port == 1433)
        || payload.len() < 8
    {
        return None;
    }
    let pkt_type = payload[0];
    let status = payload[1];
    let tds_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    let spid = u16::from_be_bytes([payload[4], payload[5]]);
    let pkt_id = payload[6];
    let window = payload[7];
    if status != 0x01 || window != 0x00 || tds_len != payload.len() || tds_len < 8 {
        return None;
    }
    let body = &payload[8..];

    let mut tokens = String::from("mssql");
    let mut residual = Vec::new();

    match pkt_type {
        0x01 => {
            if body.len() < 22 || !is_default_all_headers(&body[0..22]) {
                return None;
            }
            let sql = decode_utf16le_raw(&body[22..])?;
            push_str_if(&mut tokens, "sql", &sql, "SELECT 1");
        }
        0x12 => {
            tokens.push_str(" prelogin");
            if body != DEFAULT_PRELOGIN_BODY {
                residual.extend_from_slice(body);
            }
        }
        0x10 => {
            tokens.push_str(" login");
            if body.len() < 94 {
                return None;
            }
            let login_len = u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as usize;
            let tds_ver = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
            if login_len != body.len() || tds_ver != 0x7400_0004 || body[72..78] != [0u8; 6] {
                return None;
            }
            let read_pair = |off: usize| -> (usize, usize) {
                let ib = u16::from_le_bytes([body[off], body[off + 1]]) as usize;
                let cch = u16::from_le_bytes([body[off + 2], body[off + 3]]) as usize;
                (ib, cch)
            };
            let (off_host, cch_host) = read_pair(36);
            let (off_user, cch_user) = read_pair(40);
            let (_, cch_pass) = read_pair(44);
            let (off_app, cch_app) = read_pair(48);
            let (off_srv, cch_srv) = read_pair(52);
            let (off_clt, cch_clt) = read_pair(60);
            let (off_db, cch_db) = read_pair(68);
            if cch_pass != 0 {
                return None;
            }
            let slice_str = |ib: usize, cch: usize| -> Option<String> {
                let end = ib.checked_add(cch.checked_mul(2)?)?;
                decode_utf16le_raw(body.get(ib..end)?)
            };
            let host = slice_str(off_host, cch_host)?;
            let user = slice_str(off_user, cch_user)?;
            let app = slice_str(off_app, cch_app)?;
            let srv = slice_str(off_srv, cch_srv)?;
            let clt = slice_str(off_clt, cch_clt)?;
            let db = slice_str(off_db, cch_db)?;
            if host != "client" || app != "FrameAssembly" || srv != "mssql" || clt != "ODBC" {
                return None;
            }
            let data_end = off_db.checked_add(cch_db.checked_mul(2)?)?;
            if off_host != 94 || data_end > body.len() {
                return None;
            }
            residual.extend_from_slice(body.get(data_end..)?);
            push_str_if(&mut tokens, "user", &user, "sa");
            push_str_if(&mut tokens, "db", &db, "master");
        }
        0x04 => {
            if body.len() == 13
                && body[0] == 0xFD
                && body[1..3] == 0x0000u16.to_le_bytes()
                && body[3..5] == 0x00C1u16.to_le_bytes()
                && body[5..13] == 0u64.to_le_bytes()
            {
                tokens.push_str(" ok");
            } else if body.len() >= 13 && body[body.len() - 13..] == [
                0xFD, 0x02, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0,
            ] {
                let target_end = body.len() - 13;
                let mut found: Option<(usize, u32, String)> = None;
                for p in 0..target_end {
                    if body[p] == 0xAA && target_end - p >= 17 {
                        let tok_len = u16::from_le_bytes([body[p + 1], body[p + 2]]) as usize;
                        if p.checked_add(3).and_then(|v| v.checked_add(tok_len)) == Some(target_end)
                            && tok_len >= 14
                        {
                            let cch_msg = u16::from_le_bytes([body[p + 9], body[p + 10]]) as usize;
                            if let Some(msg_bytes_len) = cch_msg.checked_mul(2)
                                && tok_len == 14usize.saturating_add(msg_bytes_len)
                                && body[p + 7] == 1
                                && body[p + 8] == 14
                                && body[p + 11 + msg_bytes_len..target_end]
                                    == [0, 0, 1, 0, 0, 0]
                                && let Some(msg) =
                                    decode_utf16le_raw(&body[p + 11..p + 11 + msg_bytes_len])
                            {
                                let ec = i32::from_le_bytes([
                                    body[p + 3],
                                    body[p + 4],
                                    body[p + 5],
                                    body[p + 6],
                                ]) as u32;
                                found = Some((p, ec, msg));
                                break;
                            }
                        }
                    }
                }
                let (err_pos, errcode, msg) = found?;
                tokens.push_str(" err");
                if errcode != 18456 {
                    let _ = write!(tokens, " errcode {errcode}");
                }
                if msg != "Login failed" {
                    let _ = write!(tokens, " sql \"{}\"", quote_raw_str(&msg));
                }
                residual.extend_from_slice(&body[..err_pos]);
            } else if body.len() > 13
                && body[body.len() - 13..] == [0xFD, 0, 0, 0xC1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            {
                tokens.push_str(" ok");
                residual.extend_from_slice(&body[..body.len() - 13]);
            } else {
                return None;
            }
        }
        0x06 => {
            tokens.push_str(" attention");
            residual.extend_from_slice(body);
        }
        _ => return None,
    }

    if spid != 0 {
        let _ = write!(tokens, " spid {spid}");
    }
    if pkt_id != 1 {
        let _ = write!(tokens, " pktid {pkt_id}");
    }

    Some(ProtocolDissection {
        protocol: Protocol::Mssql,
        tokens,
        residual_payload: residual,
        explicit_transport: None,
    })
}
