//! EtherNet/IP and Common Industrial Protocol (ODVA CIP) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `ethernetip` 24-byte encapsulation
//! headers and Common Packet Format (CPF) / CIP bodies over TCP and UDP transports (ports `44818`
//! and `2222`, plus custom ports matching valid encapsulation command codes). It decodes `nop`,
//! `listservices`, `listinterfaces`, `listidentity`, `registersession`, `unregistersession`,
//! `sendrrdata`, and `sendunitdata` along with `sessionhandle`, `status`, `context`, and CIP
//! EPATH (`cipservice`, `cipclass`, `cipinstance`, `cipattr`) modifiers.

use alloc::format;
use alloc::string::String;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

/// Dissects an `ethernetip` 24-byte encapsulation header + CPF/CIP body over TCP or UDP.
pub(crate) fn dissect_ethernetip(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if payload.len() < 24 || !matches!(transport, TransportProto::Tcp | TransportProto::Udp) {
        return None;
    }
    let is_tcp = matches!(transport, TransportProto::Tcp);
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

    if options != 0 || 24 + body_len != payload.len() {
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
            if cmd_code == 0x0070 {
                tokens.push_str(" sendunitdata");
            } else {
                tokens.push_str(" sendrrdata");
            }
            if body.len() >= 16
                && &body[0..14] == b"\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\xB2\x00"
                && u16::from_le_bytes([body[14], body[15]]) as usize == body.len() - 16
            {
                let cip = &body[16..];
                if cip.len() == 6 && cip[1] == 2 && cip[2] == 0x20 && cip[4] == 0x24 {
                    let svc = cip[0];
                    let cls = cip[3];
                    let inst = cip[5];
                    if svc != 0x0E {
                        tokens.push_str(&format!(" cipservice 0x{svc:02x}"));
                    }
                    if cls != 0x01 {
                        tokens.push_str(&format!(" cipclass 0x{cls:02x}"));
                    }
                    if inst != 0x01 {
                        tokens.push_str(&format!(" cipinstance {inst}"));
                    }
                    residual = &[];
                } else if cip.len() == 8
                    && cip[1] == 3
                    && cip[2] == 0x20
                    && cip[4] == 0x24
                    && cip[6] == 0x30
                {
                    let svc = cip[0];
                    let cls = cip[3];
                    let inst = cip[5];
                    let attr = cip[7];
                    if svc != 0x0E {
                        tokens.push_str(&format!(" cipservice 0x{svc:02x}"));
                    }
                    if cls != 0x01 {
                        tokens.push_str(&format!(" cipclass 0x{cls:02x}"));
                    }
                    if inst != 0x01 {
                        tokens.push_str(&format!(" cipinstance {inst}"));
                    }
                    tokens.push_str(&format!(" cipattr {attr}"));
                    residual = &[];
                } else {
                    residual = body;
                }
            } else {
                residual = body;
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
        explicit_transport: if !is_tcp {
            Some(TransportProto::Udp)
        } else {
            None
        },
    })
}
