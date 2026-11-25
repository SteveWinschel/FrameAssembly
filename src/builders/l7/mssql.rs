//! Microsoft SQL Server Tabular Data Stream (MS-TDS, TCP port `1433`) Layer 7 wire builder.
//!
//! This module serializes [`MssqlSpec`] into MS-TDS v7.4 frames with the 8-byte TDS packet header
//! (`Type`, `Status`, `Length`, `SPID`, `PacketID`, `Window`). It encodes `SQLBatch` (`0x01`) with
//! mandatory 22-byte `ALL_HEADERS` + UTF-16LE SQL, `PRELOGIN` (`0x12`), `LOGIN7` (`0x10`),
//! `DONE` (`0x04`/`0xFD`), `ERROR` (`0x04`/`0xAA`+`0xFD`), and `Attention` (`0x06`).

use alloc::vec::Vec;

use crate::ast::*;
use crate::builders::WireContext;

/// Appends UTF-16LE code units of `s` into `buf`.
fn push_utf16le(buf: &mut Vec<u8>, s: &str) {
    for unit in s.encode_utf16() {
        buf.extend_from_slice(&unit.to_le_bytes());
    }
}

/// Resolves MS-TDS packet type byte from [`MssqlSpec`].
fn resolve_tds_type(spec: &MssqlSpec<'_>) -> u8 {
    if spec.is_prelogin {
        return 0x12;
    }
    if spec.is_login {
        return 0x10;
    }
    if spec.is_err || spec.errcode.is_some() || spec.is_ok {
        return 0x04;
    }
    if spec.is_query {
        return 0x01;
    }
    match spec.pkt_type {
        Some("prelogin") | Some("18") => 0x12,
        Some("login") | Some("login7") | Some("16") => 0x10,
        Some("reply") | Some("response") | Some("ok") | Some("err") | Some("4") => 0x04,
        Some("attention") | Some("6") => 0x06,
        Some("batch") | Some("query") | Some("1") | None => 0x01,
        Some(other) => other.parse::<u8>().unwrap_or(0x01),
    }
}

/// Builds a 33-byte MS-TDS `PRELOGIN` body (`VERSION`, `ENCRYPTION`, `INSTOPT`, `THREADID`, `0xFF`).
fn build_prelogin_body() -> Vec<u8> {
    let mut body = Vec::with_capacity(33);
    // Option table: 4 entries * 5 bytes + 1-byte 0xFF terminator = 21 bytes
    body.extend_from_slice(&[0x00, 0x00, 21, 0x00, 6]); // VERSION @ 21, len 6
    body.extend_from_slice(&[0x01, 0x00, 27, 0x00, 1]); // ENCRYPTION @ 27, len 1
    body.extend_from_slice(&[0x02, 0x00, 28, 0x00, 1]); // INSTOPT @ 28, len 1
    body.extend_from_slice(&[0x03, 0x00, 29, 0x00, 4]); // THREADID @ 29, len 4
    body.push(0xFF);
    body.extend_from_slice(&[15, 0, 0, 0, 0, 0]); // SQL Server 15.0.0.0
    body.push(0x02); // ENCRYPT_NOT_SUP
    body.push(0x00); // default empty instance
    body.extend_from_slice(&[0, 0, 0, 0]); // ThreadId 0
    body
}

/// Builds an MS-TDS 7.4 `LOGIN7` (`0x10`) packet body with fixed 94-byte header + UTF-16LE strings.
fn build_login7_body(user: &str, db: &str) -> Vec<u8> {
    /// Appends UTF-16LE `s` to `strings` and returns `(byte_offset, utf16_code_unit_count)`.
    fn add_str(strings: &mut Vec<u8>, s: &str) -> (u16, u16) {
        let off = (94 + strings.len()) as u16;
        let cch = s.encode_utf16().count() as u16;
        push_utf16le(strings, s);
        (off, cch)
    }

    let host = "client";
    let app = "FrameAssembly";
    let server = "mssql";
    let clt_int = "ODBC";

    let mut strings = Vec::with_capacity(128);
    let (off_host, cch_host) = add_str(&mut strings, host);
    let (off_user, cch_user) = add_str(&mut strings, user);
    let off_pass = (94 + strings.len()) as u16;
    let (off_app, cch_app) = add_str(&mut strings, app);
    let (off_srv, cch_srv) = add_str(&mut strings, server);
    let (off_clt, cch_clt) = add_str(&mut strings, clt_int);
    let (off_db, cch_db) = add_str(&mut strings, db);

    let total_len = (94 + strings.len()) as u32;
    let mut body = Vec::with_capacity(total_len as usize);
    body.extend_from_slice(&total_len.to_le_bytes()); // Length
    body.extend_from_slice(&0x7400_0004u32.to_le_bytes()); // TDS 7.4
    body.extend_from_slice(&4096u32.to_le_bytes()); // PacketSize
    body.extend_from_slice(&0x0700_0000u32.to_le_bytes()); // ClientProgVer
    body.extend_from_slice(&1u32.to_le_bytes()); // ClientPID
    body.extend_from_slice(&0u32.to_le_bytes()); // ConnectionID
    body.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // OptionFlags1..3 + TypeFlags
    body.extend_from_slice(&0i32.to_le_bytes()); // ClientTimeZone
    body.extend_from_slice(&0x0000_0409u32.to_le_bytes()); // ClientLCID

    body.extend_from_slice(&off_host.to_le_bytes());
    body.extend_from_slice(&cch_host.to_le_bytes());
    body.extend_from_slice(&off_user.to_le_bytes());
    body.extend_from_slice(&cch_user.to_le_bytes());
    body.extend_from_slice(&off_pass.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes()); // Password len 0
    body.extend_from_slice(&off_app.to_le_bytes());
    body.extend_from_slice(&cch_app.to_le_bytes());
    body.extend_from_slice(&off_srv.to_le_bytes());
    body.extend_from_slice(&cch_srv.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes()); // Unused/Ext offset
    body.extend_from_slice(&0u16.to_le_bytes()); // Unused/Ext len
    body.extend_from_slice(&off_clt.to_le_bytes());
    body.extend_from_slice(&cch_clt.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes()); // Language offset
    body.extend_from_slice(&0u16.to_le_bytes()); // Language len
    body.extend_from_slice(&off_db.to_le_bytes());
    body.extend_from_slice(&cch_db.to_le_bytes());
    body.extend_from_slice(&[0u8; 6]); // ClientID
    body.extend_from_slice(&0u16.to_le_bytes()); // ibSSPI
    body.extend_from_slice(&0u16.to_le_bytes()); // cbSSPI
    body.extend_from_slice(&0u16.to_le_bytes()); // ibAtchDBFile
    body.extend_from_slice(&0u16.to_le_bytes()); // cchAtchDBFile
    body.extend_from_slice(&0u16.to_le_bytes()); // ibChangePassword
    body.extend_from_slice(&0u16.to_le_bytes()); // cchChangePassword
    body.extend_from_slice(&0u32.to_le_bytes()); // cbSSPILong
    body.extend_from_slice(&strings);
    body
}

/// Builds an MS-TDS `SQLBatch` (`0x01`) body with 22-byte `ALL_HEADERS` + UTF-16LE SQL.
fn build_sql_batch_body(sql: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(22 + sql.len() * 2);
    body.extend_from_slice(&22u32.to_le_bytes()); // ALL_HEADERS TotalLength
    body.extend_from_slice(&18u32.to_le_bytes()); // TxDesc HeaderLength
    body.extend_from_slice(&2u16.to_le_bytes()); // HeaderType = TransactionDescriptor
    body.extend_from_slice(&[0u8; 8]); // TransactionDescriptor
    body.extend_from_slice(&1u32.to_le_bytes()); // OutstandingRequestCount
    push_utf16le(&mut body, sql);
    body
}

/// Builds an MS-TDS `Tabular Result` (`0x04`) `DONE` or `ERROR` + `DONE` body.
fn build_reply_body(is_err: bool, errcode: u32, msg: &str, extra: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(64 + extra.len());
    body.extend_from_slice(extra);
    if is_err {
        let mut msg_utf16 = Vec::with_capacity(msg.len() * 2);
        push_utf16le(&mut msg_utf16, msg);
        let cch_msg = msg.encode_utf16().count() as u16;
        let tok_len = (14 + msg_utf16.len()) as u16;
        body.push(0xAA); // ERROR token
        body.extend_from_slice(&tok_len.to_le_bytes());
        body.extend_from_slice(&(errcode as i32).to_le_bytes());
        body.push(1); // State
        body.push(14); // Class
        body.extend_from_slice(&cch_msg.to_le_bytes());
        body.extend_from_slice(&msg_utf16);
        body.push(0); // ServerName len 0
        body.push(0); // ProcName len 0
        body.extend_from_slice(&1i32.to_le_bytes()); // LineNumber
        body.push(0xFD); // DONE token
        body.extend_from_slice(&0x0002u16.to_le_bytes()); // DONE_ERROR
        body.extend_from_slice(&0x0000u16.to_le_bytes()); // CurCmd
        body.extend_from_slice(&0u64.to_le_bytes()); // DoneRowCount
    } else {
        body.push(0xFD); // DONE token
        body.extend_from_slice(&0x0000u16.to_le_bytes()); // DONE_FINAL
        body.extend_from_slice(&0x00C1u16.to_le_bytes()); // SELECT
        body.extend_from_slice(&0u64.to_le_bytes()); // DoneRowCount
    }
    body
}

/// Builds an MS-TDS payload from `spec` and optional `payload_bytes`.
pub fn build_mssql_payload(
    _ctx: &WireContext,
    spec: &MssqlSpec<'_>,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let pkt_type = resolve_tds_type(spec);
    let spid = spec.spid.unwrap_or(0);
    let pkt_id = spec.pkt_id.unwrap_or(1);

    let body = match pkt_type {
        0x12 => {
            if !payload_bytes.is_empty() {
                payload_bytes.to_vec()
            } else {
                build_prelogin_body()
            }
        }
        0x10 => {
            let user = spec.user.unwrap_or("sa");
            let db = spec.db.unwrap_or("master");
            let mut b = build_login7_body(user, db);
            if !payload_bytes.is_empty() {
                b.extend_from_slice(payload_bytes);
                let new_len = b.len() as u32;
                b[0..4].copy_from_slice(&new_len.to_le_bytes());
            }
            b
        }
        0x04 => {
            let is_err = (spec.is_err || spec.errcode.is_some()) && !spec.is_ok;
            let errcode = spec.errcode.unwrap_or(18456);
            let msg = spec.sql.unwrap_or("Login failed");
            build_reply_body(is_err, errcode, msg, payload_bytes)
        }
        0x06 => payload_bytes.to_vec(),
        _ => {
            let sql = if let Some(s) = spec.sql {
                s
            } else if !payload_bytes.is_empty() {
                core::str::from_utf8(payload_bytes).unwrap_or("SELECT 1")
            } else {
                "SELECT 1"
            };
            build_sql_batch_body(sql)
        }
    };

    let total_len = 8usize.saturating_add(body.len());
    let mut out = Vec::with_capacity(total_len);
    out.push(pkt_type);
    out.push(0x01); // Status: EOM
    out.extend_from_slice(&(total_len as u16).to_be_bytes());
    out.extend_from_slice(&spid.to_be_bytes());
    out.push(pkt_id);
    out.push(0x00); // Window
    out.extend_from_slice(&body);
    out
}
