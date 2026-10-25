//! Network File System v2/v3/v4 (NFS, RFC 1813 / RFC 7530) over ONC RPC v2 wire payload builder.
//!
//! This module implements [`build_nfs_payload`], which constructs an ONC RPC v2 (RFC 5531) Call
//! message carrying an NFSv2, NFSv3, or NFSv4 procedure over TCP or UDP port 2049. It prepends the
//! 4-byte XDR Record Marking header (with last-fragment bit `0x80000000`), serializes the 40-byte
//! RPC Call header (XID `0x6E667301`, Call type `0`, RPC version `2`, Program `100003`, NFS version,
//! procedure code, and `AUTH_NULL` credentials), and XDR-encodes optional compound `TAG` and `PATH`
//! strings with 4-byte zero padding.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an ONC RPC / NFS file system protocol packet payload.
pub fn build_nfs_payload(
    _ctx: &WireContext,
    spec: &NfsSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let xid = spec.xid.unwrap_or(0x12345678);
    let vers = spec.vers.unwrap_or(4);
    let proc_str = spec.proc_name.unwrap_or("LOOKUP").to_ascii_uppercase();
    let proc_num: u32 = match proc_str.as_str() {
        "NULL" => 0,
        "GETATTR" => 1,
        "LOOKUP" => 3,
        "READ" => 6,
        "WRITE" => 7,
        "COMPOUND" => 1,
        _ => 3,
    };

    let mut rpc_call = Vec::new();
    rpc_call.extend_from_slice(&xid.to_be_bytes());
    rpc_call.extend_from_slice(&0u32.to_be_bytes()); // Msg Type: 0 (Call)
    rpc_call.extend_from_slice(&2u32.to_be_bytes()); // RPC Version: 2
    rpc_call.extend_from_slice(&100003u32.to_be_bytes()); // Program: 100003 (NFS)
    rpc_call.extend_from_slice(&vers.to_be_bytes()); // NFS Version
    rpc_call.extend_from_slice(&proc_num.to_be_bytes()); // Procedure
    rpc_call.extend_from_slice(&0u32.to_be_bytes()); // Cred flavor AUTH_NONE (0)
    rpc_call.extend_from_slice(&0u32.to_be_bytes()); // Cred length 0
    rpc_call.extend_from_slice(&0u32.to_be_bytes()); // Verf flavor AUTH_NONE (0)
    rpc_call.extend_from_slice(&0u32.to_be_bytes()); // Verf length 0

    if spec.tag.is_some() || proc_str == "COMPOUND" {
        let tag_bytes = spec.tag.unwrap_or("").as_bytes();
        rpc_call.extend_from_slice(&(tag_bytes.len() as u32).to_be_bytes());
        rpc_call.extend_from_slice(tag_bytes);
        let pad = (4 - (tag_bytes.len() % 4)) % 4;
        rpc_call.resize(rpc_call.len() + pad, 0);
    }

    if let Some(path) = spec.path {
        let path_bytes = path.as_bytes();
        rpc_call.extend_from_slice(&(path_bytes.len() as u32).to_be_bytes());
        rpc_call.extend_from_slice(path_bytes);
        let pad = (4 - (path_bytes.len() % 4)) % 4;
        rpc_call.resize(rpc_call.len() + pad, 0);
    }

    if !payload_bytes.is_empty() {
        rpc_call.extend_from_slice(payload_bytes);
    }

    // ONC RPC Record Marking header for TCP (4 bytes: 0x80000000 | length)
    let length = rpc_call.len() as u32;
    let mark = 0x80000000u32 | (length & 0x7FFFFFFF);
    let mut pkt = Vec::with_capacity(4 + rpc_call.len());
    pkt.extend_from_slice(&mark.to_be_bytes());
    pkt.extend_from_slice(&rpc_call);
    pkt
}
