//! NFS protocol wire builder.

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
    let proc_num: u32 = match spec.proc_name.unwrap_or("LOOKUP").to_ascii_uppercase().as_str() {
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
    rpc_call.extend_from_slice(&spec.vers.unwrap_or(4).to_be_bytes()); // Version 4
    rpc_call.extend_from_slice(&proc_num.to_be_bytes()); // Procedure
    rpc_call.extend_from_slice(&0u32.to_be_bytes()); // Cred flavor AUTH_NONE (0)
    rpc_call.extend_from_slice(&0u32.to_be_bytes()); // Cred length 0
    rpc_call.extend_from_slice(&0u32.to_be_bytes()); // Verf flavor AUTH_NONE (0)
    rpc_call.extend_from_slice(&0u32.to_be_bytes()); // Verf length 0

    if let Some(path) = spec.path {
        rpc_call.extend_from_slice(&(path.len() as u32).to_be_bytes());
        rpc_call.extend_from_slice(path.as_bytes());
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
