//! Modbus Application Protocol v1.1b3 (MBAP + PDU) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `modbus` TCP, UDP, and SCTP frames
//! on port `502`. It validates the 7-byte MBAP header (`txid`, `protoid`, `mbap_len`, `unitid`) and
//! decodes standard function codes (`1..=6`, `15`, `16`), extended diagnostic/MEI/file function codes
//! (`7`, `8`, `11`, `12`, `17`, `20..=24`, `43`), `0x80`-bit exception responses (`errcode`), byte-
//! counted multi-write requests (`0x0F`/`0x10`) preserving arbitrary write payloads, and `isresponse`.

use alloc::format;
use alloc::string::String;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

/// Appends the `.frasm` function selector for base Modbus function code `base_func` (`1..=127`).
fn push_modbus_func_token(tokens: &mut String, base_func: u8) {
    match base_func {
        1 => tokens.push_str(" readcoils"),
        2 => tokens.push_str(" readdiscreteinputs"),
        3 => {}
        4 => tokens.push_str(" readinputregisters"),
        5 => tokens.push_str(" writesinglecoil"),
        6 => tokens.push_str(" writesingleregister"),
        15 => tokens.push_str(" func \"writemultiplecoils\""),
        16 => tokens.push_str(" writemultipleregisters"),
        other => tokens.push_str(&format!(" func \"{other}\"")),
    }
}

/// Returns whether base Modbus function code `base_func` is supported by the `modbus` forward builder.
fn is_supported_base_func(base_func: u8) -> bool {
    matches!(
        base_func,
        1..=8 | 11 | 12 | 15..=17 | 20..=24 | 43
    )
}

/// Dissects a `modbus` TCP/UDP/SCTP MBAP + PDU packet on port `502`.
pub(crate) fn dissect_modbus(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if payload.len() < 8
        || !matches!(
            transport,
            TransportProto::Tcp | TransportProto::Udp | TransportProto::Sctp
        )
        || !(dst_port == 502 || src_port == 502)
    {
        return None;
    }
    let txid = u16::from_be_bytes([payload[0], payload[1]]);
    let proto_id = u16::from_be_bytes([payload[2], payload[3]]);
    let mbap_len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    let unit_id = payload[6];
    let func = payload[7];
    let is_exc = (func & 0x80) != 0;
    let base_func = func & 0x7F;

    let total_len = 6usize.checked_add(mbap_len)?;
    if mbap_len < 2 || total_len != payload.len() || (!is_exc && !is_supported_base_func(base_func)) {
        return None;
    }
    if is_exc && base_func == 0 {
        return None;
    }

    let pdu = &payload[8..];
    let explicit_transport = if matches!(transport, TransportProto::Udp) {
        Some(TransportProto::Udp)
    } else {
        None
    };
    let mut tokens = String::from("modbus");
    push_modbus_func_token(&mut tokens, base_func);

    if txid != 1 {
        tokens.push_str(&format!(" txid {txid}"));
    }
    if proto_id != 0 {
        tokens.push_str(&format!(" protoid {proto_id}"));
    }
    if unit_id != 1 {
        tokens.push_str(&format!(" unitid {unit_id}"));
    }

    if is_exc {
        let exc = *pdu.first()?;
        tokens.push_str(&format!(" errcode {exc}"));
        return Some(ProtocolDissection {
            protocol: Protocol::Modbus,
            tokens,
            residual_payload: pdu[1..].to_vec(),
            explicit_transport,
        });
    }

    if matches!(func, 7 | 11 | 12 | 17) {
        return Some(ProtocolDissection {
            protocol: Protocol::Modbus,
            tokens,
            residual_payload: pdu.to_vec(),
            explicit_transport,
        });
    }

    if func == 43 {
        let residual = if let Some(rest) = pdu.strip_prefix(&[0x0E, 0x01, 0x81, 0x00, 0x00, 0x00]) {
            tokens.push_str(" isresponse");
            rest
        } else {
            pdu.strip_prefix(&[0x0E, 0x01, 0x00])?
        };
        return Some(ProtocolDissection {
            protocol: Protocol::Modbus,
            tokens,
            residual_payload: residual.to_vec(),
            explicit_transport,
        });
    }

    if matches!(func, 1 | 2) && !pdu.is_empty() && (1..=250).contains(&pdu[0]) {
        let bc = pdu[0] as usize;
        if pdu.len() > bc
            && (pdu.len() != 4 || (bc == 3 && u16::from_be_bytes([pdu[2], pdu[3]]) == 0))
        {
            let fill = pdu[1];
            if pdu[1..1 + bc].iter().all(|&b| b == fill) {
                tokens.push_str(" isresponse");
                if bc > 1 {
                    tokens.push_str(&format!(" count {}", bc * 8));
                }
                if fill != 0 {
                    tokens.push_str(&format!(" value {fill}"));
                }
                return Some(ProtocolDissection {
                    protocol: Protocol::Modbus,
                    tokens,
                    residual_payload: pdu[1 + bc..].to_vec(),
                    explicit_transport,
                });
            }
        }
    } else if matches!(func, 3 | 4 | 20 | 21 | 23 | 24)
        && !pdu.is_empty()
        && (2..=250).contains(&pdu[0])
        && pdu[0].is_multiple_of(2)
    {
        let bc = pdu[0] as usize;
        let count = bc / 2;
        if pdu.len() > bc && pdu.len() != 4 {
            let val = u16::from_be_bytes([pdu[1], pdu[2]]);
            let all_same = pdu[1..1 + bc]
                .as_chunks::<2>()
                .0
                .iter()
                .all(|&c| u16::from_be_bytes(c) == val);
            if all_same {
                tokens.push_str(" isresponse");
                if count != 1 {
                    tokens.push_str(&format!(" count {count}"));
                }
                if val != 0 {
                    tokens.push_str(&format!(" value {val}"));
                }
                return Some(ProtocolDissection {
                    protocol: Protocol::Modbus,
                    tokens,
                    residual_payload: pdu[1 + bc..].to_vec(),
                    explicit_transport,
                });
            }
        }
    }

    if func == 22 {
        if pdu.len() < 6 {
            return None;
        }
        let addr = u16::from_be_bytes([pdu[0], pdu[1]]);
        let and_mask = u16::from_be_bytes([pdu[2], pdu[3]]);
        let or_mask = u16::from_be_bytes([pdu[4], pdu[5]]);
        if addr != 0 {
            tokens.push_str(&format!(" addr {addr}"));
        }
        if and_mask != 0xFFFF {
            tokens.push_str(&format!(" value {and_mask}"));
        }
        if or_mask != 0 {
            tokens.push_str(&format!(" count {or_mask}"));
        }
        return Some(ProtocolDissection {
            protocol: Protocol::Modbus,
            tokens,
            residual_payload: pdu[6..].to_vec(),
            explicit_transport,
        });
    }

    if pdu.len() < 4 {
        return None;
    }
    let addr = u16::from_be_bytes([pdu[0], pdu[1]]);
    let second = u16::from_be_bytes([pdu[2], pdu[3]]);
    if addr != 0 {
        tokens.push_str(&format!(" addr {addr}"));
    }

    let residual = match func {
        1..=4 | 20 | 21 | 23 | 24 => {
            if second != 1 {
                tokens.push_str(&format!(" count {second}"));
            }
            &pdu[4..]
        }
        5 | 6 | 8 => {
            if second != 0 {
                tokens.push_str(&format!(" value {second}"));
            }
            &pdu[4..]
        }
        15 => {
            let bc = usize::from(second).div_ceil(8);
            if (1..=1968).contains(&second) && pdu.len() == 5 + bc && pdu[4] as usize == bc {
                if second != 1 {
                    tokens.push_str(&format!(" count {second}"));
                }
                let fill = pdu[5];
                if pdu[5..5 + bc].iter().all(|&b| b == fill) {
                    if fill != 0 {
                        tokens.push_str(&format!(" value {fill}"));
                    }
                    &pdu[5 + bc..]
                } else {
                    &pdu[5..]
                }
            } else {
                tokens.push_str(" isresponse");
                if second != 1 {
                    tokens.push_str(&format!(" count {second}"));
                }
                &pdu[4..]
            }
        }
        16 => {
            let bc = usize::from(second) * 2;
            if (1..=125).contains(&second) && pdu.len() == 5 + bc && pdu[4] as usize == bc {
                if second != 1 {
                    tokens.push_str(&format!(" count {second}"));
                }
                let val = u16::from_be_bytes([pdu[5], pdu[6]]);
                let all_same = pdu[5..5 + bc]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .all(|&c| u16::from_be_bytes(c) == val);
                if all_same {
                    if val != 0 {
                        tokens.push_str(&format!(" value {val}"));
                    }
                    &pdu[5 + bc..]
                } else {
                    &pdu[5..]
                }
            } else {
                tokens.push_str(" isresponse");
                if second != 1 {
                    tokens.push_str(&format!(" count {second}"));
                }
                &pdu[4..]
            }
        }
        _ => return None,
    };

    Some(ProtocolDissection {
        protocol: Protocol::Modbus,
        tokens,
        residual_payload: residual.to_vec(),
        explicit_transport,
    })
}
