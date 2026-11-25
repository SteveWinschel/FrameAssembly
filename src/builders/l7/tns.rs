//! Oracle Transparent Network Substrate (TNS) Layer 7 wire payload builder.
//!
//! This module implements [`build_tns_payload`], which serializes a [`TnsSpec`] AST specification
//! into an Oracle Transparent Network Substrate (TNS) frame over TCP port 1521. It constructs the
//! 8-byte big-endian TNS packet header (`length`, `packetChecksum`, `type`, `reserved`,
//! `headerChecksum`) and formats type-specific bodies for `CONNECT` (`1` with
//! `(DESCRIPTION=(CONNECT_DATA=...))`), `ACCEPT` (`2`), `ACK` (`3`), `REFUSE` (`4` with ORA error
//! stack), `REDIRECT` (`5`), `DATA` (`6` with `dataFlags` and SQL payload), `NULL` (`7`), `ABORT`
//! (`9`), `RESEND` (`11`), and `MARKER` (`12`).

use crate::ast::*;
use crate::builders::WireContext;
use alloc::format;
use alloc::vec::Vec;

/// Resolves a TNS message type string or numeric code to its 8-bit TNS packet type.
fn parse_tns_type(raw: &str) -> u8 {
    let trimmed = raw.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        && let Ok(val) = u8::from_str_radix(hex, 16)
    {
        return val;
    }
    if let Ok(val) = trimmed.parse::<u8>() {
        return val;
    }
    match trimmed.to_ascii_uppercase().replace(['_', '-'], "").as_str() {
        "CONNECT" => 1,
        "ACCEPT" => 2,
        "ACK" => 3,
        "REFUSE" => 4,
        "REDIRECT" => 5,
        "DATA" => 6,
        "NULL" => 7,
        "ABORT" => 9,
        "RESEND" => 11,
        "MARKER" => 12,
        "ATTENTION" => 14,
        _ => 1,
    }
}

/// Builds an Oracle Transparent Network Substrate (TNS) wire packet payload.
pub fn build_tns_payload(
    _ctx: &WireContext,
    spec: &TnsSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let raw_type = spec.msg_type.unwrap_or(if spec.sql.is_some() {
        "data"
    } else if spec.errcode.is_some() {
        "refuse"
    } else {
        "connect"
    });
    let pkt_type = parse_tns_type(raw_type);
    let version = spec.version.unwrap_or(314);
    let mut body = Vec::new();

    match pkt_type {
        1 => {
            // TNS CONNECT (50-byte connect header -> connect data at offset 58)
            let svc_opts = spec.flags.unwrap_or(0x0C41);
            let connect_data = match (spec.sid, spec.service) {
                (Some(sid), Some(svc)) => {
                    format!("(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME={svc})(SID={sid})))")
                }
                (Some(sid), None) => format!("(DESCRIPTION=(CONNECT_DATA=(SID={sid})))"),
                (None, svc) => {
                    let s = svc.unwrap_or("ORCL");
                    format!("(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME={s})))")
                }
            };
            let cd_bytes = connect_data.as_bytes();
            let cd_len = u16::try_from(cd_bytes.len()).unwrap_or(u16::MAX);
            body.extend_from_slice(&version.to_be_bytes());
            body.extend_from_slice(&300u16.to_be_bytes()); // versionCompatible
            body.extend_from_slice(&svc_opts.to_be_bytes()); // serviceOptions
            body.extend_from_slice(&8192u16.to_be_bytes()); // sduSize
            body.extend_from_slice(&65535u16.to_be_bytes()); // maximumTduSize
            body.extend_from_slice(&0x4F98u16.to_be_bytes()); // ntProtocolCharacteristics
            body.extend_from_slice(&0u16.to_be_bytes()); // lineTurnaroundValue
            body.extend_from_slice(&1u16.to_be_bytes()); // valueOfOneInHardware
            body.extend_from_slice(&cd_len.to_be_bytes());
            body.extend_from_slice(&58u16.to_be_bytes()); // offsetToConnectData
            body.extend_from_slice(&2048u32.to_be_bytes()); // maxReceivableConnectData
            body.extend_from_slice(&[0u8; 26]); // connectFlags + trace/unique connection ID
            body.extend_from_slice(cd_bytes);
            if !payload_bytes.is_empty() {
                body.extend_from_slice(payload_bytes);
            }
        }
        2 => {
            // TNS ACCEPT (16-byte accept header -> offset 24)
            let svc_opts = spec.flags.unwrap_or(0x0C41);
            body.extend_from_slice(&version.to_be_bytes());
            body.extend_from_slice(&svc_opts.to_be_bytes());
            body.extend_from_slice(&8192u16.to_be_bytes());
            body.extend_from_slice(&65535u16.to_be_bytes());
            body.extend_from_slice(&1u16.to_be_bytes());
            body.extend_from_slice(&0u16.to_be_bytes()); // lengthOfAcceptData
            body.extend_from_slice(&24u16.to_be_bytes()); // offsetToAcceptData
            body.extend_from_slice(&0u16.to_be_bytes()); // acceptFlags0..1
            if !payload_bytes.is_empty() {
                body.extend_from_slice(payload_bytes);
            }
        }
        4 => {
            // TNS REFUSE
            let errcode = spec.errcode.unwrap_or(12514);
            let refuse_str = format!("(DESCRIPTION=(ERR={errcode}))");
            let rb = refuse_str.as_bytes();
            let rlen = u16::try_from(rb.len()).unwrap_or(u16::MAX);
            body.push(0x22); // userReason
            body.push(0x00); // systemReason
            body.extend_from_slice(&rlen.to_be_bytes());
            body.extend_from_slice(rb);
            if !payload_bytes.is_empty() {
                body.extend_from_slice(payload_bytes);
            }
        }
        5 => {
            // TNS REDIRECT
            let host = spec.service.unwrap_or("127.0.0.1");
            let redir_str = format!("(ADDRESS=(PROTOCOL=TCP)(HOST={host})(PORT=1521))");
            let rb = redir_str.as_bytes();
            let rlen = u16::try_from(rb.len()).unwrap_or(u16::MAX);
            body.extend_from_slice(&rlen.to_be_bytes());
            body.extend_from_slice(rb);
            if !payload_bytes.is_empty() {
                body.extend_from_slice(payload_bytes);
            }
        }
        6 => {
            // TNS DATA
            let data_flags = spec.flags.unwrap_or(0);
            body.extend_from_slice(&data_flags.to_be_bytes());
            if let Some(sql) = spec.sql {
                body.extend_from_slice(sql.as_bytes());
            }
            if !payload_bytes.is_empty() {
                body.extend_from_slice(payload_bytes);
            }
        }
        12 => {
            // TNS MARKER (Reset marker)
            body.extend_from_slice(&[0x01, 0x00, 0x02]);
            if !payload_bytes.is_empty() {
                body.extend_from_slice(payload_bytes);
            }
        }
        _ => {
            if !payload_bytes.is_empty() {
                body.extend_from_slice(payload_bytes);
            }
        }
    }

    let total_len = u16::try_from(8usize + body.len()).unwrap_or(u16::MAX);
    let mut pkt = Vec::with_capacity(8 + body.len());
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes()); // packetChecksum
    pkt.push(pkt_type);
    pkt.push(0x00); // reserved
    pkt.extend_from_slice(&0u16.to_be_bytes()); // headerChecksum
    pkt.extend_from_slice(&body);
    pkt
}
