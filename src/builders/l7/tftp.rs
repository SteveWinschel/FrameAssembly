//! TFTP protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 1350 TFTP packet payload.
pub fn build_tftp_payload(
    _ctx: &WireContext,
    spec: &TftpSpec,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let mut pkt = Vec::new();
    let filename = spec.filename.unwrap_or("boot.bin");
    let mode = spec.mode.unwrap_or("octet");

    if spec.is_wrq {
        pkt.extend_from_slice(&2u16.to_be_bytes()); // WRQ opcode 2
        pkt.extend_from_slice(filename.as_bytes());
        pkt.push(0);
        pkt.extend_from_slice(mode.as_bytes());
        pkt.push(0);
    } else if spec.is_data {
        pkt.extend_from_slice(&3u16.to_be_bytes()); // DATA opcode 3
        pkt.extend_from_slice(&spec.block.unwrap_or(1).to_be_bytes());
        if !payload_bytes.is_empty() {
            pkt.extend_from_slice(payload_bytes);
        }
    } else if spec.is_ack {
        pkt.extend_from_slice(&4u16.to_be_bytes()); // ACK opcode 4
        pkt.extend_from_slice(&spec.block.unwrap_or(1).to_be_bytes());
    } else if spec.is_error {
        pkt.extend_from_slice(&5u16.to_be_bytes()); // ERROR opcode 5
        pkt.extend_from_slice(&spec.errcode.unwrap_or(1).to_be_bytes());
        let errmsg = spec.errmsg.unwrap_or("File not found");
        pkt.extend_from_slice(errmsg.as_bytes());
        pkt.push(0);
    } else {
        // Default: RRQ opcode 1
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(filename.as_bytes());
        pkt.push(0);
        pkt.extend_from_slice(mode.as_bytes());
        pkt.push(0);
    }

    if (spec.is_rrq || (!spec.is_wrq && !spec.is_data && !spec.is_ack && !spec.is_error))
        && !payload_bytes.is_empty()
    {
        pkt.extend_from_slice(payload_bytes);
    }
    pkt
}
