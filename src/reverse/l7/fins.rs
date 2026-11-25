//! Omron Factory Interface Network Service (FINS) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for Omron `fins` frames carried over
//! UDP port `9600` (raw FINS header) and TCP port `9600` (16-byte `"FINS"` TCP framing wrapper
//! with `0x00000002` Frame Send command, emitting `transport tcp`). It decodes the 10-byte FINS
//! routing header (`icf`, `dna`, `da1`, `da2`, `sna`, `sa1`, `sa2`, `sid`), MRC/SRC command codes
//! (`read`, `write`, `cmd`), memory `area`, `addr`, `count`, `value`, `errcode`, and `response`
//! status while preserving unmatched bytes in `residual_payload`.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

/// Appends the `.frasm` command selector for a 16-bit FINS MRC/SRC command code.
fn push_fins_cmd_token(tokens: &mut String, cmd: u16) {
    match cmd {
        0x0101 => {}
        0x0102 => tokens.push_str(" write"),
        other => {
            let _ = write!(tokens, " cmd 0x{other:04x}");
        }
    }
}

/// Checks whether a response slice consists of `count` repeated 2-byte big-endian words (`>= 0x80`).
fn decode_uniform_words(data: &[u8]) -> Option<(u16, u16)> {
    if data.len() < 2 || !data.len().is_multiple_of(2) || data.len() / 2 > 999 {
        return None;
    }
    let val = u16::from_be_bytes([data[0], data[1]]);
    let all_same = data
        .as_chunks::<2>()
        .0
        .iter()
        .all(|&c| u16::from_be_bytes(c) == val);
    all_same.then_some(((data.len() / 2) as u16, val))
}

/// Dissects an Omron `fins` UDP or FINS/TCP message on port `9600`.
pub(crate) fn dissect_fins(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(
        transport,
        TransportProto::Udp | TransportProto::Tcp | TransportProto::Sctp
    ) {
        return None;
    }

    let (fins, explicit_transport) = if matches!(transport, TransportProto::Tcp) {
        if payload.len() < 28 || &payload[0..4] != b"FINS" {
            return None;
        }
        let tcp_len = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
        let tcp_cmd = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let tcp_err = u32::from_be_bytes([payload[12], payload[13], payload[14], payload[15]]);
        if tcp_len.checked_add(8) != Some(payload.len()) || tcp_cmd != 2 || tcp_err != 0 {
            return None;
        }
        (&payload[16..], Some(TransportProto::Tcp))
    } else {
        if src_port != 9600 && dst_port != 9600 {
            return None;
        }
        (payload, None)
    };

    if fins.len() < 12 || fins[1] != 0x00 || fins[2] != 0x02 || (fins[0] & 0x3E) != 0 {
        return None;
    }

    let icf = fins[0];
    let is_resp = (icf & 0x40) != 0;
    let default_icf = if is_resp { 0xC0 } else { 0x80 };
    let (dna, da1, da2) = (fins[3], fins[4], fins[5]);
    let (sna, sa1, sa2) = (fins[6], fins[7], fins[8]);
    let sid = fins[9];
    let cmd = u16::from_be_bytes([fins[10], fins[11]]);
    let body = &fins[12..];

    let mut tokens = String::from("fins");
    push_fins_cmd_token(&mut tokens, cmd);
    if is_resp {
        tokens.push_str(" response");
    }
    if icf != default_icf {
        let _ = write!(tokens, " icf 0x{icf:02x}");
    }
    if dna != 0 {
        let _ = write!(tokens, " dna {dna}");
    }
    if da1 != 0 {
        let _ = write!(tokens, " da1 {da1}");
    }
    if da2 != 0 {
        let _ = write!(tokens, " da2 {da2}");
    }
    if sna != 0 {
        let _ = write!(tokens, " sna {sna}");
    }
    if sa1 != 0 {
        let _ = write!(tokens, " sa1 {sa1}");
    }
    if sa2 != 0 {
        let _ = write!(tokens, " sa2 {sa2}");
    }
    if sid != 1 {
        let _ = write!(tokens, " sid {sid}");
    }

    let residual: Vec<u8>;
    if is_resp {
        if body.len() < 2 {
            return None;
        }
        let errcode = u16::from_be_bytes([body[0], body[1]]);
        if errcode != 0 {
            let _ = write!(tokens, " errcode 0x{errcode:04x}");
        }
        let data = &body[2..];
        if cmd == 0x0101 && errcode == 0 {
            if let Some((count, val)) = decode_uniform_words(data) {
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
            residual = data.to_vec();
        }
    } else if cmd == 0x0101 || cmd == 0x0102 {
        if body.len() < 6 || body[3] != 0x00 {
            return None;
        }
        let area = body[0];
        let addr = u16::from_be_bytes([body[1], body[2]]);
        let count = u16::from_be_bytes([body[4], body[5]]);
        if area != 0x82 {
            let _ = write!(tokens, " area 0x{area:02x}");
        }
        if addr != 0 {
            let _ = write!(tokens, " addr {addr}");
        }
        let tail = &body[6..];
        if cmd == 0x0101 {
            if count != 1 {
                let _ = write!(tokens, " count {count}");
            }
            residual = tail.to_vec();
        } else if area >= 0x80
            && usize::from(count) * 2 == tail.len()
            && let Some((w_cnt, val)) = decode_uniform_words(tail)
            && w_cnt == count
        {
            if count != 1 {
                let _ = write!(tokens, " count {count}");
            }
            if val != 0 {
                let _ = write!(tokens, " value {val}");
            }
            residual = Vec::new();
        } else if area < 0x80
            && usize::from(count) == tail.len()
            && !tail.is_empty()
            && tail.iter().all(|&b| b == tail[0])
        {
            if count != 1 {
                let _ = write!(tokens, " count {count}");
            }
            if tail[0] != 0 {
                let _ = write!(tokens, " value {}", tail[0]);
            }
            residual = Vec::new();
        } else {
            if count != 1 {
                let _ = write!(tokens, " count {count}");
            }
            residual = tail.to_vec();
        }
    } else {
        residual = body.to_vec();
    }

    Some(ProtocolDissection {
        protocol: Protocol::Fins,
        tokens,
        residual_payload: residual,
        explicit_transport,
    })
}
