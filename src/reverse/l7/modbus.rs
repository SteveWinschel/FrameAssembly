//! Modbus Application Protocol v1.1b3 (MBAP + PDU) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `modbus` TCP and UDP frames on port
//! `502`. It validates the 7-byte MBAP header (`txid`, `protoid`, `mbap_len`, `unitid`) and decodes
//! function codes `1` (`readcoils`), `2` (`readdiscreteinputs`), `3` (`readholdingregisters`),
//! `4` (`readinputregisters`), `5` (`writesinglecoil`), `6` (`writesingleregister`), and `16`
//! (`writemultipleregisters`) across request and `isresponse` PDUs.

use alloc::format;
use alloc::string::String;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

/// Dissects a `modbus` TCP/UDP MBAP + PDU packet on port `502`.
pub(crate) fn dissect_modbus(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if payload.len() < 8
        || !matches!(transport, TransportProto::Tcp | TransportProto::Udp)
        || !(dst_port == 502 || src_port == 502)
    {
        return None;
    }
    let is_tcp = matches!(transport, TransportProto::Tcp);
    let txid = u16::from_be_bytes([payload[0], payload[1]]);
    let proto_id = u16::from_be_bytes([payload[2], payload[3]]);
    let mbap_len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    let unit_id = payload[6];
    let func = payload[7];

    if mbap_len < 2 || 6 + mbap_len != payload.len() || !matches!(func, 1..=6 | 16) {
        return None;
    }
    let pdu = &payload[8..];
    let mut tokens = String::from("modbus");

    match func {
        1 => tokens.push_str(" readcoils"),
        2 => tokens.push_str(" readdiscreteinputs"),
        3 => {}
        4 => tokens.push_str(" readinputregisters"),
        5 => tokens.push_str(" writesinglecoil"),
        6 => tokens.push_str(" writesingleregister"),
        16 => tokens.push_str(" writemultipleregisters"),
        _ => return None,
    }
    if txid != 1 {
        tokens.push_str(&format!(" txid {txid}"));
    }
    if proto_id != 0 {
        tokens.push_str(&format!(" protoid {proto_id}"));
    }
    if unit_id != 1 {
        tokens.push_str(&format!(" unitid {unit_id}"));
    }

    if !pdu.is_empty() && pdu[0] >= 2 && pdu[0].is_multiple_of(2) {
        let bc = pdu[0] as usize;
        let count = bc / 2;
        if pdu.len() > bc && pdu.len() != 4 {
            let val = u16::from_be_bytes([pdu[1], pdu[2]]);
            let all_same = pdu[1..1 + bc]
                .chunks_exact(2)
                .all(|c| u16::from_be_bytes([c[0], c[1]]) == val);
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
                    explicit_transport: if !is_tcp {
                        Some(TransportProto::Udp)
                    } else {
                        None
                    },
                });
            }
        }
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
        1..=4 => {
            if second != 1 {
                tokens.push_str(&format!(" count {second}"));
            }
            &pdu[4..]
        }
        5 | 6 => {
            if second != 0 {
                tokens.push_str(&format!(" value {second}"));
            }
            &pdu[4..]
        }
        16 => {
            let count = second as usize;
            if second != 1 {
                tokens.push_str(&format!(" count {second}"));
            }
            let bc = count * 2;
            if pdu.len() >= 5 + bc && pdu[4] as usize == bc && count > 0 {
                let val = u16::from_be_bytes([pdu[5], pdu[6]]);
                let all_same = pdu[5..5 + bc]
                    .chunks_exact(2)
                    .all(|c| u16::from_be_bytes([c[0], c[1]]) == val);
                if all_same {
                    tokens.push_str(&format!(" value {val}"));
                    &pdu[5 + bc..]
                } else {
                    &pdu[4..]
                }
            } else {
                &pdu[4..]
            }
        }
        _ => return None,
    };

    Some(ProtocolDissection {
        protocol: Protocol::Modbus,
        tokens,
        residual_payload: residual.to_vec(),
        explicit_transport: if !is_tcp {
            Some(TransportProto::Udp)
        } else {
            None
        },
    })
}
