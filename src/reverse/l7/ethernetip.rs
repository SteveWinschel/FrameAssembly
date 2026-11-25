//! EtherNet/IP and Common Industrial Protocol (ODVA CIP) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `ethernetip` 24-byte encapsulation
//! headers and Common Packet Format (CPF) / CIP bodies over TCP, UDP, and SCTP transports (ports
//! `44818` and `2222`, plus custom ports matching valid encapsulation command codes). It decodes
//! `nop`, `listservices`, `listinterfaces`, `listidentity`, `registersession`, `unregistersession`,
//! `sendrrdata` (CPF `0x0000` + `0x00B2`), and `sendunitdata` (CPF `0x00A1` + `0x00B1`), along with
//! `sessionhandle`, `status`, `context`, and 8-bit (`0x20`/`0x24`/`0x30`) or 16-bit padded
//! (`0x21`/`0x25`/`0x31`) CIP EPATH (`cipservice`, `cipclass`, `cipinstance`, `cipattr`) fields.

use alloc::format;
use alloc::string::String;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

/// Decodes an 8-bit/16-bit logical CIP segment at the front of `ep`, returning `(value, rest)`.
fn parse_cip_segment(ep: &[u8], tag_8bit: u8, tag_16bit: u8) -> Option<(u16, &[u8])> {
    if ep.len() >= 2 && ep[0] == tag_8bit {
        Some((u16::from(ep[1]), &ep[2..]))
    } else if ep.len() >= 4 && ep[0] == tag_16bit && ep[1] == 0x00 {
        let val = u16::from_le_bytes([ep[2], ep[3]]);
        if val <= 0xFF {
            return None;
        }
        Some((val, &ep[4..]))
    } else {
        None
    }
}

/// Decodes a CIP explicit service header + logical EPATH (`class`, `instance`, optional `attr`).
fn decode_cip_epath(cip: &[u8]) -> Option<(u8, u16, u16, Option<u16>)> {
    if cip.len() < 6 {
        return None;
    }
    let svc = cip[0];
    let epath_len = usize::from(cip[1]) * 2;
    if cip.len() != 2 + epath_len {
        return None;
    }
    let ep = &cip[2..];
    let (cls, ep) = parse_cip_segment(ep, 0x20, 0x21)?;
    let (inst, ep) = parse_cip_segment(ep, 0x24, 0x25)?;
    let attr = if ep.is_empty() {
        None
    } else {
        let (a, rem) = parse_cip_segment(ep, 0x30, 0x31)?;
        if !rem.is_empty() {
            return None;
        }
        Some(a)
    };
    Some((svc, cls, inst, attr))
}

/// Appends decoded non-default CIP EPATH modifiers to `tokens`.
fn push_cip_tokens(
    tokens: &mut String,
    svc: u8,
    cls: u16,
    inst: u16,
    attr: Option<u16>,
) {
    if svc != 0x0E {
        tokens.push_str(&format!(" cipservice 0x{svc:02x}"));
    }
    if cls != 0x01 {
        tokens.push_str(&format!(" cipclass 0x{cls:02x}"));
    }
    if inst != 0x01 {
        tokens.push_str(&format!(" cipinstance {inst}"));
    }
    if let Some(a) = attr {
        tokens.push_str(&format!(" cipattr {a}"));
    }
}

/// Dissects an `ethernetip` 24-byte encapsulation header + CPF/CIP body over TCP, UDP, or SCTP.
pub(crate) fn dissect_ethernetip(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if payload.len() < 24
        || !matches!(
            transport,
            TransportProto::Tcp | TransportProto::Udp | TransportProto::Sctp
        )
    {
        return None;
    }
    let cmd_code = u16::from_le_bytes([payload[0], payload[1]]);
    let on_known_port =
        matches!(dst_port, 44818 | 2222) || matches!(src_port, 44818 | 2222);
    if !on_known_port && !matches!(cmd_code, 0x0063 | 0x0065 | 0x0066 | 0x006F | 0x0070) {
        return None;
    }

    let body_len = u16::from_le_bytes([payload[2], payload[3]]) as usize;
    let session = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let status = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);
    let context = u64::from_le_bytes([
        payload[12],
        payload[13],
        payload[14],
        payload[15],
        payload[16],
        payload[17],
        payload[18],
        payload[19],
    ]);
    let options = u32::from_le_bytes([payload[20], payload[21], payload[22], payload[23]]);

    let total_len = 24usize.checked_add(body_len)?;
    if options != 0 || total_len != payload.len() {
        return None;
    }
    let body = &payload[24..];
    let mut tokens = String::from("ethernetip");
    let residual: &[u8];

    match cmd_code {
        0x0000 => {
            tokens.push_str(" nop");
            residual = body;
        }
        0x0004 => {
            tokens.push_str(" listservices");
            residual = body;
        }
        0x0064 => {
            tokens.push_str(" listinterfaces");
            residual = body;
        }
        0x0065 => {
            let rem = body.strip_prefix(&[0x01, 0x00, 0x00, 0x00])?;
            tokens.push_str(" registersession");
            residual = rem;
        }
        0x0066 => {
            tokens.push_str(" unregistersession");
            residual = body;
        }
        0x0063 => {
            tokens.push_str(" listidentity");
            residual = body;
        }
        0x006F | 0x0070 => {
            if cmd_code == 0x006F {
                tokens.push_str(" sendrrdata");
                if body.len() >= 16
                    && &body[0..14] == b"\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\xB2\x00"
                    && u16::from_le_bytes([body[14], body[15]]) as usize == body.len() - 16
                {
                    if let Some((svc, cls, inst, attr)) = decode_cip_epath(&body[16..]) {
                        push_cip_tokens(&mut tokens, svc, cls, inst, attr);
                        residual = &[];
                    } else {
                        residual = body;
                    }
                } else {
                    residual = body;
                }
            } else {
                tokens.push_str(" sendunitdata");
                if body.len() >= 22
                    && &body[0..18]
                        == b"\x00\x00\x00\x00\x00\x00\x02\x00\xA1\x00\x04\x00\x01\x00\x00\x00\xB1\x00"
                    && u16::from_le_bytes([body[18], body[19]]) as usize == body.len() - 20
                    && &body[20..22] == b"\x01\x00"
                {
                    if let Some((svc, cls, inst, attr)) = decode_cip_epath(&body[22..]) {
                        push_cip_tokens(&mut tokens, svc, cls, inst, attr);
                        residual = &[];
                    } else {
                        residual = body;
                    }
                } else {
                    residual = body;
                }
            }
        }
        _ => return None,
    }

    if session != 0 {
        tokens.push_str(&format!(" sessionhandle 0x{session:08x}"));
    }
    if status != 0 {
        tokens.push_str(&format!(" status {status}"));
    }
    if context != 0 {
        tokens.push_str(&format!(" context 0x{context:x}"));
    }

    Some(ProtocolDissection {
        protocol: Protocol::Ethernetip,
        tokens,
        residual_payload: residual.to_vec(),
        explicit_transport: if matches!(transport, TransportProto::Udp) {
            Some(TransportProto::Udp)
        } else {
            None
        },
    })
}
