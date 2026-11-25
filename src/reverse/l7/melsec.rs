//! Mitsubishi MELSEC MC Protocol / SLMP Binary 3E Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for Mitsubishi `melsec` Binary 3E
//! frames (`0x50 0x00` requests and `0xD0 0x00` responses) over TCP, UDP, and SCTP transports
//! (ports `5000`, `5007`, and custom ports matching canonical 3E headers). It decodes `network`,
//! `pc`, `io`, `station`, `timer`, `read`/`write`/numeric `cmd`, `subcmd`, `device`, 24-bit
//! `addr`, `count`, `value`, `endcode`, and `response`, preserving unmatched bytes in
//! `residual_payload` and emitting `transport udp` on UDP captures.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

/// Checks whether `data` consists of `count` repeated 16-bit little-endian words (`<= 960`).
fn decode_uniform_le_words(data: &[u8]) -> Option<(u16, u16)> {
    if data.len() < 2 || !data.len().is_multiple_of(2) || data.len() / 2 > 960 {
        return None;
    }
    let val = u16::from_le_bytes([data[0], data[1]]);
    let all_same = data
        .as_chunks::<2>()
        .0
        .iter()
        .all(|&c| u16::from_le_bytes(c) == val);
    all_same.then_some(((data.len() / 2) as u16, val))
}

/// Dissects a Mitsubishi `melsec` Binary 3E Frame over TCP, UDP, or SCTP.
pub(crate) fn dissect_melsec(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if payload.len() < 11
        || !matches!(
            transport,
            TransportProto::Tcp | TransportProto::Udp | TransportProto::Sctp
        )
    {
        return None;
    }
    let is_resp = match (payload[0], payload[1]) {
        (0x50, 0x00) => false,
        (0xD0, 0x00) => true,
        _ => return None,
    };

    let network = payload[2];
    let pc = payload[3];
    let io = u16::from_le_bytes([payload[4], payload[5]]);
    let station = payload[6];
    let data_len = u16::from_le_bytes([payload[7], payload[8]]) as usize;
    if 9usize.checked_add(data_len)? != payload.len() {
        return None;
    }
    let on_known_port = matches!(src_port, 5000 | 5007) || matches!(dst_port, 5000 | 5007);
    if !on_known_port && !(network == 0 && pc == 0xFF && io == 0x03FF && station == 0) {
        return None;
    }

    let body = &payload[9..];
    let mut tokens = String::from("melsec");
    let explicit_transport = if matches!(transport, TransportProto::Udp) {
        Some(TransportProto::Udp)
    } else {
        None
    };

    let residual: Vec<u8>;
    if is_resp {
        if body.len() < 2 {
            return None;
        }
        let endcode = u16::from_le_bytes([body[0], body[1]]);
        let data = &body[2..];
        if endcode == 0 && data.is_empty() {
            tokens.push_str(" write");
        }
        tokens.push_str(" response");
        if endcode != 0 {
            let _ = write!(tokens, " endcode 0x{endcode:04x}");
            residual = data.to_vec();
        } else if data.is_empty() {
            residual = Vec::new();
        } else if let Some((count, val)) = decode_uniform_le_words(data) {
            if count != 1 {
                let _ = write!(tokens, " count {count}");
            }
            if val != 0 {
                let _ = write!(tokens, " value {val}");
            }
            residual = Vec::new();
        } else {
            residual = data.to_vec();
        }
    } else {
        if body.len() < 6 {
            return None;
        }
        let timer = u16::from_le_bytes([body[0], body[1]]);
        let cmd = u16::from_le_bytes([body[2], body[3]]);
        let subcmd = u16::from_le_bytes([body[4], body[5]]);
        match cmd {
            0x0401 => {}
            0x1401 => tokens.push_str(" write"),
            other => {
                let _ = write!(tokens, " cmd 0x{other:04x}");
            }
        }
        if subcmd != 0 {
            let _ = write!(tokens, " subcmd 0x{subcmd:04x}");
        }
        if timer != 0x0010 {
            let _ = write!(tokens, " timer {timer}");
        }

        let tail = &body[6..];
        if cmd == 0x0401 || cmd == 0x1401 {
            if tail.len() < 6 {
                return None;
            }
            let addr = u32::from_le_bytes([tail[0], tail[1], tail[2], 0]);
            let device = tail[3];
            let count = u16::from_le_bytes([tail[4], tail[5]]);
            if device != 0xA8 {
                let _ = write!(tokens, " device 0x{device:02x}");
            }
            if addr != 0 {
                let _ = write!(tokens, " addr {addr}");
            }
            let data = &tail[6..];
            if cmd == 0x0401 {
                if count != 1 {
                    let _ = write!(tokens, " count {count}");
                }
                residual = data.to_vec();
            } else if (subcmd & 0x0001) == 0
                && usize::from(count) * 2 == data.len()
                && let Some((w_cnt, val)) = decode_uniform_le_words(data)
                && w_cnt == count
            {
                if count != 1 {
                    let _ = write!(tokens, " count {count}");
                }
                if val != 0 {
                    let _ = write!(tokens, " value {val}");
                }
                residual = Vec::new();
            } else if (subcmd & 0x0001) != 0
                && usize::from(count).div_ceil(2) == data.len()
                && !data.is_empty()
                && data.iter().all(|&b| b == data[0])
            {
                if count != 1 {
                    let _ = write!(tokens, " count {count}");
                }
                if data[0] != 0 {
                    let _ = write!(tokens, " value {}", data[0]);
                }
                residual = Vec::new();
            } else {
                if count != 1 {
                    let _ = write!(tokens, " count {count}");
                }
                residual = data.to_vec();
            }
        } else {
            residual = tail.to_vec();
        }
    }

    if network != 0x00 {
        let _ = write!(tokens, " network {network}");
    }
    if pc != 0xFF {
        let _ = write!(tokens, " pc {pc}");
    }
    if io != 0x03FF {
        let _ = write!(tokens, " io 0x{io:04x}");
    }
    if station != 0x00 {
        let _ = write!(tokens, " station {station}");
    }

    Some(ProtocolDissection {
        protocol: Protocol::Melsec,
        tokens,
        residual_payload: residual,
        explicit_transport,
    })
}
