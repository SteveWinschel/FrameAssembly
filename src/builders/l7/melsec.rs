//! Mitsubishi MELSEC MC Protocol / SLMP Binary 3E Frame wire payload builder.
//!
//! This module implements [`build_melsec_payload`], which serializes a [`MelsecSpec`] AST node
//! into a Mitsubishi Electric MELSEC MC Protocol (SLMP Binary 3E Frame) packet over TCP or UDP
//! port 5000. Every packet begins with the 9-byte little-endian 3E encapsulation header (`50 00`
//! request or `D0 00` response subheader, `network`, `pc`, `io`, `station`, and 16-bit data
//! length), followed by request monitoring `timer`, `cmd` (`0x0401` Batch Read, `0x1401` Batch
//! Write, `0x0403` Read Random, `0x1402` Write Random), `subcmd`, 24-bit head `addr`, `device`,
//! and `count`, or response `endcode` and register data.

use alloc::vec::Vec;

use crate::ast::*;
use crate::builders::WireContext;

/// Parses a MELSEC command mnemonic or hex/decimal code string into a 16-bit SLMP command ID.
fn parse_melsec_cmd(raw: &str) -> u16 {
    let norm = raw.trim().to_ascii_uppercase().replace(['_', '-'], "");
    match norm.as_str() {
        "READ" | "BATCHREAD" => 0x0401,
        "WRITE" | "BATCHWRITE" => 0x1401,
        "READRANDOM" => 0x0403,
        "WRITERANDOM" => 0x1402,
        "RUN" | "REMOTERUN" => 0x1001,
        "STOP" | "REMOTESTOP" => 0x1002,
        _ => {
            if let Some(hex) = norm.strip_prefix("0X") {
                u16::from_str_radix(hex, 16).unwrap_or(0x0401)
            } else {
                norm.parse::<u16>().unwrap_or(0x0401)
            }
        }
    }
}

/// Appends `count` uniform MELSEC word (`(subcmd & 1) == 0`) or bit nibble-pair items of `val`.
fn push_melsec_data(out: &mut Vec<u8>, subcmd: u16, count: u16, val: u16) {
    if (subcmd & 0x0001) != 0 {
        let byte_len = usize::from(count).div_ceil(2);
        out.resize(out.len() + byte_len, (val & 0xFF) as u8);
    } else {
        let word = val.to_le_bytes();
        for _ in 0..count {
            out.extend_from_slice(&word);
        }
    }
}

/// Builds a Mitsubishi MELSEC MC Protocol / SLMP Binary 3E Frame payload.
pub fn build_melsec_payload(
    _ctx: &WireContext,
    spec: &MelsecSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let cmd_code = parse_melsec_cmd(spec.cmd.unwrap_or("read"));
    let subcmd = spec.subcmd.unwrap_or(0);
    let is_resp = spec.is_response || spec.endcode.is_some();

    let mut body = Vec::with_capacity(16 + payload_bytes.len());
    if is_resp {
        let endcode = spec.endcode.unwrap_or(0);
        body.extend_from_slice(&endcode.to_le_bytes());
        if !payload_bytes.is_empty() {
            body.extend_from_slice(payload_bytes);
        } else if endcode == 0 && cmd_code == 0x0401 {
            let count = spec.count.unwrap_or(1).clamp(1, 960);
            push_melsec_data(&mut body, subcmd, count, spec.value.unwrap_or(0));
        }
    } else {
        let timer = spec.timer.unwrap_or(0x0010);
        body.extend_from_slice(&timer.to_le_bytes());
        body.extend_from_slice(&cmd_code.to_le_bytes());
        body.extend_from_slice(&subcmd.to_le_bytes());
        if cmd_code == 0x0401 || cmd_code == 0x1401 {
            let addr = spec.addr.unwrap_or(0) & 0xFF_FFFF;
            let addr_bytes = addr.to_le_bytes();
            body.extend_from_slice(&addr_bytes[..3]);
            body.push(spec.device.unwrap_or(0xA8));
            if cmd_code == 0x1401 && !payload_bytes.is_empty() {
                let default_cnt = if (subcmd & 0x0001) != 0 {
                    payload_bytes.len() * 2
                } else {
                    payload_bytes.len().div_ceil(2)
                }
                .clamp(1, 960) as u16;
                let count = spec.count.unwrap_or(default_cnt);
                body.extend_from_slice(&count.to_le_bytes());
                body.extend_from_slice(payload_bytes);
            } else {
                let count = spec.count.unwrap_or(1).clamp(1, 960);
                body.extend_from_slice(&count.to_le_bytes());
                if cmd_code == 0x1401 {
                    push_melsec_data(&mut body, subcmd, count, spec.value.unwrap_or(0));
                } else if !payload_bytes.is_empty() {
                    body.extend_from_slice(payload_bytes);
                }
            }
        } else if !payload_bytes.is_empty() {
            body.extend_from_slice(payload_bytes);
        }
    }

    let data_len = u16::try_from(body.len()).unwrap_or(u16::MAX);
    let mut pkt = Vec::with_capacity(9 + body.len());
    if is_resp {
        pkt.extend_from_slice(&[0xD0, 0x00]);
    } else {
        pkt.extend_from_slice(&[0x50, 0x00]);
    }
    pkt.push(spec.network.unwrap_or(0x00));
    pkt.push(spec.pc.unwrap_or(0xFF));
    pkt.extend_from_slice(&spec.io.unwrap_or(0x03FF).to_le_bytes());
    pkt.push(spec.station.unwrap_or(0x00));
    pkt.extend_from_slice(&data_len.to_le_bytes());
    pkt.extend_from_slice(&body);
    pkt
}
