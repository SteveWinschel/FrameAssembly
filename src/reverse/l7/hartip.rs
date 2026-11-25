//! HART-IP (HCF Spec 085 Industrial Field Instrumentation) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe wire-to-AST dissection for `hartip` frames over UDP, TCP,
//! and SCTP transports (port `5094` and custom gateway ports matching canonical Session Initiate
//! or LRC-verified Token-Passing PDUs). It decodes the 8-byte HART-IP header (`version`,
//! `msgtype`/`isresponse`, `msgid`/`close`/`keepalive`, `status`, `txid`), Session Initiate
//! `mode` and inactivity `holdtime`, and embedded HART Token-Passing polling `addr`, `cmd`,
//! response status stripping, and LRC verification.

use alloc::format;
use alloc::string::String;

use crate::ast::{Protocol, TransportProto};
use crate::builders::l7::hartip::DEFAULT_HARTIP_INACTIVITY_MS;
use crate::reverse::{ProtocolDissection, be_u16, be_u32};

/// Dissects a FieldComm Group `hartip` UDP, TCP, or SCTP packet.
pub(crate) fn dissect_hartip(
    transport: TransportProto,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if !matches!(
        transport,
        TransportProto::Udp | TransportProto::Tcp | TransportProto::Sctp
    ) || payload.len() < 8
    {
        return None;
    }

    let version = payload[0];
    let msg_type = payload[1];
    let msg_id = payload[2];
    let status = payload[3];
    let txid = be_u16(payload, 4);
    let msg_len = usize::from(be_u16(payload, 6));
    if msg_len != payload.len() || msg_type > 3 || msg_id > 5 {
        return None;
    }

    let on_known_port = src_port == 5094 || dst_port == 5094;
    if !on_known_port && version != 1 {
        return None;
    }

    let body = &payload[8..];
    let mut tokens = String::from("hartip");
    let residual: &[u8];

    match msg_id {
        0 => {
            if body.len() < 5 {
                return None;
            }
            let master_type = body[0];
            let timer = be_u32(body, 1);
            if !on_known_port && (master_type > 1 || timer != DEFAULT_HARTIP_INACTIVITY_MS) {
                return None;
            }
            if master_type != 1 {
                tokens.push_str(&format!(" mode {master_type}"));
            }
            if timer != DEFAULT_HARTIP_INACTIVITY_MS {
                tokens.push_str(&format!(" holdtime {timer}"));
            }
            residual = &body[5..];
        }
        1 => {
            if !on_known_port {
                return None;
            }
            tokens.push_str(" close");
            residual = body;
        }
        2 => {
            if !on_known_port {
                return None;
            }
            tokens.push_str(" keepalive");
            residual = body;
        }
        3 => {
            if body.len() < 5 {
                return None;
            }
            let expected_delim = if msg_type == 1 { 0x06u8 } else { 0x02u8 };
            let delim = body[0];
            let addr = body[1];
            let cmd = body[2];
            let byte_count = usize::from(body[3]);
            if delim != expected_delim
                || addr > 63
                || 4usize.checked_add(byte_count)?.checked_add(1)? != body.len()
            {
                return None;
            }
            let lrc_acc = body.iter().fold(0u8, |acc, &b| acc ^ b);
            if lrc_acc != 0 {
                return None;
            }
            if msg_type == 1 {
                if byte_count < 2 || body[4..6] != [0x00, 0x00] {
                    return None;
                }
                residual = &body[6..body.len() - 1];
            } else {
                residual = &body[4..body.len() - 1];
            }
            if addr == 0 && cmd == 0 {
                tokens.push_str(" msgid 3");
            } else {
                if addr != 0 {
                    tokens.push_str(&format!(" addr {addr}"));
                }
                if cmd != 0 {
                    tokens.push_str(&format!(" cmd {cmd}"));
                }
            }
        }
        4 | 5 => {
            if !on_known_port {
                return None;
            }
            tokens.push_str(&format!(" msgid {msg_id}"));
            residual = body;
        }
        _ => return None,
    }

    if version != 1 {
        tokens.push_str(&format!(" version {version}"));
    }
    match msg_type {
        0 => {}
        1 => tokens.push_str(" isresponse"),
        2 => tokens.push_str(" msgtype \"publish\""),
        3 => tokens.push_str(" msgtype \"nak\""),
        _ => return None,
    }
    if status != 0 {
        tokens.push_str(&format!(" status {status}"));
    }
    if txid != 1 {
        tokens.push_str(&format!(" txid {txid}"));
    }

    Some(ProtocolDissection {
        protocol: Protocol::Hartip,
        tokens,
        residual_payload: residual.to_vec(),
        explicit_transport: if matches!(transport, TransportProto::Tcp) {
            Some(TransportProto::Tcp)
        } else {
            None
        },
    })
}
