//! Network File System v3/v4 (NFS, RFC 1813 / RFC 7530 / RFC 8881) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements fuzz-safe ONC-RPC / SunRPC (`prog == 100_003`, `rpc_vers == 2`) wire-to-AST
//! dissection for `nfs` frames over 4-byte record-marked TCP/SCTP and raw UDP transports (port
//! `2049` and custom ports with a valid SunRPC NFS Call header). It decodes procedures `0..=21`
//! (`null`, `getattr`/`compound`, `setattr`, `lookup`, `access`, `readlink`, `read`, `write`,
//! `create`, `mkdir`, `symlink`, `mknod`, `remove`, `rmdir`, `rename`, `link`, `readdir`,
//! `readdirplus`, `fsstat`, `fsinfo`, `pathconf`, `commit`, plus numeric fallback) and XDR `tag`/`path`.

use alloc::format;
use alloc::string::String;

use crate::ast::{Protocol, TransportProto};
use crate::reverse::ProtocolDissection;

use super::quote_raw_str;

/// Checks whether `s` contains no control characters so it can safely be emitted as a quoted field.
fn is_printable_nfs_str(s: &str) -> bool {
    s.chars().all(|c| !c.is_control())
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
    if !is_printable_nfs_str(s) {
        return None;
    }
    Some((s, &input[total..]))
}

/// Dissects an `nfs` SunRPC Call message over TCP, UDP, or SCTP.
pub(crate) fn dissect_nfs(
    transport: TransportProto,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> Option<ProtocolDissection> {
    if payload.is_empty()
        || !matches!(
            transport,
            TransportProto::Tcp | TransportProto::Udp | TransportProto::Sctp
        )
    {
        return None;
    }
    let is_udp = matches!(transport, TransportProto::Udp);

    let rpc = if !is_udp {
        if payload.len() < 44 {
            return None;
        }
        let mark = be_u32(payload, 0);
        if (mark & 0x8000_0000) == 0 || ((mark & 0x7FFF_FFFF) as usize) != payload.len() - 4 {
            return None;
        }
        &payload[4..]
    } else if payload.len() >= 40 {
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
        2 => tokens.push_str(" proc \"setattr\""),
        3 => {}
        4 => tokens.push_str(" proc \"access\""),
        5 => tokens.push_str(" proc \"readlink\""),
        6 => tokens.push_str(" proc \"read\""),
        7 => tokens.push_str(" proc \"write\""),
        8 => tokens.push_str(" proc \"create\""),
        9 => tokens.push_str(" proc \"mkdir\""),
        10 => tokens.push_str(" proc \"symlink\""),
        11 => tokens.push_str(" proc \"mknod\""),
        12 => tokens.push_str(" proc \"remove\""),
        13 => tokens.push_str(" proc \"rmdir\""),
        14 => tokens.push_str(" proc \"rename\""),
        15 => tokens.push_str(" proc \"link\""),
        16 => tokens.push_str(" proc \"readdir\""),
        17 => tokens.push_str(" proc \"readdirplus\""),
        18 => tokens.push_str(" proc \"fsstat\""),
        19 => tokens.push_str(" proc \"fsinfo\""),
        20 => tokens.push_str(" proc \"pathconf\""),
        21 => tokens.push_str(" proc \"commit\""),
        other => tokens.push_str(&format!(" proc \"{other}\"")),
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
                tokens.push_str(&format!(" tag \"{}\"", quote_raw_str(tag_str)));
            }
            if let Some((path_str, after_path)) = parse_xdr_str(rest) {
                rest = after_path;
                tokens.push_str(&format!(" path \"{}\"", quote_raw_str(path_str)));
            }
        }
    } else if proc_num != 1
        && !rest.is_empty()
        && let Some((first_str, after_first)) = parse_xdr_str(rest)
    {
        if let Some((second_str, after_second)) = parse_xdr_str(after_first) {
            tokens.push_str(&format!(
                " tag \"{}\" path \"{}\"",
                quote_raw_str(first_str),
                quote_raw_str(second_str)
            ));
            rest = after_second;
        } else {
            tokens.push_str(&format!(" path \"{}\"", quote_raw_str(first_str)));
            rest = after_first;
        }
    }

    Some(ProtocolDissection {
        protocol: Protocol::Nfs,
        tokens,
        residual_payload: rest.to_vec(),
        explicit_transport: if is_udp {
            Some(TransportProto::Udp)
        } else {
            None
        },
    })
}
