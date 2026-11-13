//! Network File System v3/v4 (NFS, RFC 1813 / RFC 7530 / RFC 8881) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe ONC-RPC / SunRPC (`prog == 100_003`, `rpc_vers == 2`) wire-to-AST
//! dissection for `nfs` frames over 4-byte record-marked TCP and raw UDP transports (port `2049`
//! and custom ports with a valid SunRPC NFS Call header). It decodes `"null"`, `"getattr"`, `compound`,
//! `lookup`, `"read"`, and `"write"` procedures along with XDR-padded `tag` and `path` strings.

use alloc::format;
use alloc::string::String;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

/// Checks whether `s` can be emitted inside `"..."` for a parser field that uses
/// `parse_raw_string_lit` (which strips outer quotes without unescaping).
fn is_valid_raw_str(s: &str) -> bool {
    !s.contains('"')
        && s.chars().all(|c| !c.is_control())
        && (s.bytes().rev().take_while(|&b| b == b'\\').count() % 2 == 0)
}

/// Reads a big-endian `u32` from `b[off..off + 4]`.
fn be_u32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Parses an XDR length-prefixed, 4-byte padded string from `input`.
fn parse_xdr_str(input: &[u8]) -> Option<(&str, &[u8])> {
    if input.len() < 4 {
        return None;
    }
    let len = be_u32(input, 0) as usize;
    let pad = (4 - (len % 4)) % 4;
    let total = 4usize.checked_add(len)?.checked_add(pad)?;
    if input.len() < total {
        return None;
    }
    let s = core::str::from_utf8(&input[4..4 + len]).ok()?;
    if !is_valid_raw_str(s) {
        return None;
    }
    Some((s, &input[total..]))
}

/// Dissects an `nfs` SunRPC Call message over TCP or UDP.
pub(crate) fn dissect_nfs(
    transport: TransportProto,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if payload.is_empty() || !matches!(transport, TransportProto::Tcp | TransportProto::Udp) {
        return None;
    }
    let is_tcp = matches!(transport, TransportProto::Tcp);

    let rpc = if payload.len() >= 44 && (be_u32(payload, 0) & 0x8000_0000) != 0 {
        &payload[4..]
    } else if !is_tcp && payload.len() >= 40 {
        payload
    } else {
        return None;
    };

    let xid = be_u32(rpc, 0);
    let msg_type = be_u32(rpc, 4);
    let rpc_vers = be_u32(rpc, 8);
    let prog = be_u32(rpc, 12);
    let vers = be_u32(rpc, 16);
    let proc_num = be_u32(rpc, 20);

    if msg_type != 0 || rpc_vers != 2 || prog != 100_003 {
        return None;
    }

    let mut rest = &rpc[40..];
    let mut tokens = String::from("nfs");

    match proc_num {
        0 => tokens.push_str(" proc \"null\""),
        1 => {
            if rest.is_empty() {
                tokens.push_str(" proc \"getattr\"");
            } else {
                tokens.push_str(" compound");
            }
        }
        3 => {}
        6 => tokens.push_str(" proc \"read\""),
        7 => tokens.push_str(" proc \"write\""),
        _ => return None,
    }

    if vers != 4 {
        tokens.push_str(&format!(" vers {vers}"));
    }
    if xid != 0x1234_5678 {
        tokens.push_str(&format!(" xid 0x{xid:08x}"));
    }

    if proc_num == 1 && !rest.is_empty() {
        if let Some((tag_str, after_tag)) = parse_xdr_str(rest) {
            rest = after_tag;
            if !tag_str.is_empty() {
                tokens.push_str(&format!(" tag \"{tag_str}\""));
            }
            if let Some((path_str, after_path)) = parse_xdr_str(rest) {
                rest = after_path;
                tokens.push_str(&format!(" path \"{path_str}\""));
            }
        }
    } else if proc_num != 1 && !rest.is_empty() {
        if let Some((first_str, after_first)) = parse_xdr_str(rest) {
            if let Some((second_str, after_second)) = parse_xdr_str(after_first) {
                tokens.push_str(&format!(" tag \"{first_str}\" path \"{second_str}\""));
                rest = after_second;
            } else {
                tokens.push_str(&format!(" path \"{first_str}\""));
                rest = after_first;
            }
        }
    }

    Some(ProtocolDissection {
        protocol: Protocol::Nfs,
        tokens,
        residual_payload: rest.to_vec(),
        explicit_transport: if !is_tcp {
            Some(TransportProto::Udp)
        } else {
            None
        },
    })
}
