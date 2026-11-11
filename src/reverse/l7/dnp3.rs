//! Distributed Network Protocol 3 (DNP3, IEEE 1815) Layer 7 PCAP-to-`.fasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `dnp3` IEEE 1815 frames (`0x05 0x64`
//! start bytes + `0xC4` control byte) over TCP and UDP transports (port `20000` and custom serial
//! terminal server ports). It strips per-16-byte block CRC-16 trailers, verifies the link-header
//! CRC-16 (`calculate_dnp3_crc`), and decodes application function codes (`confirm`, `read`,
//! `write`, `select`, `operate`, `directoperate`, `"response"`, `unsolicitedresponse`), `src`,
//! `dst`, `group`, and `variation`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

/// Dissects a `dnp3` IEEE 1815 frame (`0x05 0x64`), stripping per-16B block CRC-16s.
pub(crate) fn dissect_dnp3(
    transport: TransportProto,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(transport, TransportProto::Tcp | TransportProto::Udp)
        || payload.len() < 15
        || &payload[0..2] != b"\x05\x64"
        || payload[3] != 0xC4
    {
        return None;
    }
    let is_tcp = matches!(transport, TransportProto::Tcp);
    let link_len = payload[2] as usize;
    let dst = u16::from_le_bytes([payload[4], payload[5]]);
    let src = u16::from_le_bytes([payload[6], payload[7]]);
    let hdr_crc = u16::from_le_bytes([payload[8], payload[9]]);
    let expected_crc = crate::builders::l7::dnp3::calculate_dnp3_crc(&payload[0..8]);

    let mut transport_bytes = Vec::new();
    let mut rem = &payload[10..];
    while !rem.is_empty() {
        if rem.len() < 3 {
            return None;
        }
        let block_len = rem.len().min(18);
        let data_len = block_len - 2;
        transport_bytes.extend_from_slice(&rem[..data_len]);
        rem = &rem[block_len..];
    }

    if link_len != 5 + transport_bytes.len()
        || transport_bytes.len() < 3
        || transport_bytes[0] != 0xC0
        || transport_bytes[1] != 0xC0
    {
        return None;
    }

    let func = transport_bytes[2];
    let mut tokens = String::from("dnp3");
    match func {
        0 => tokens.push_str(" confirm"),
        1 => {}
        2 => tokens.push_str(" write"),
        3 => tokens.push_str(" select"),
        4 => tokens.push_str(" operate"),
        5 => tokens.push_str(" directoperate"),
        129 => tokens.push_str(" func \"response\""),
        130 => tokens.push_str(" unsolicitedresponse"),
        _ => return None,
    }
    if src != 100 {
        tokens.push_str(&format!(" src {src}"));
    }
    if dst != 1 {
        tokens.push_str(&format!(" dst {dst}"));
    }

    let residual = if transport_bytes.len() >= 6 && transport_bytes[5] == 0x06 {
        let g = transport_bytes[3];
        let v = transport_bytes[4];
        tokens.push_str(&format!(" group {g}"));
        if v != 1 {
            tokens.push_str(&format!(" variation {v}"));
        }
        transport_bytes[6..].to_vec()
    } else {
        transport_bytes[3..].to_vec()
    };

    if hdr_crc != expected_crc {
        tokens.push_str(&format!(" crc 0x{hdr_crc:04x}"));
    }

    Some(ProtocolDissection {
        protocol: Protocol::Dnp3,
        tokens,
        residual_payload: residual,
        explicit_transport: if !is_tcp {
            Some(TransportProto::Udp)
        } else {
            None
        },
    })
}
