//! Trivial File Transfer Protocol (TFTP) (RFC 1350 / RFC 2347 (Options) / RFC 2348 (blksize)) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire Trivial File Transfer Protocol (TFTP) frames over UDP port 69.
//! The wire encoder constructs a 2-byte big-endian Opcode header (`1` RRQ Read Request, `2` WRQ Write Request, `3` DATA block transfer, `4` ACK block acknowledgment, `5` ERROR response) followed by NUL-terminated Filename + Mode strings for RRQ/WRQ, 16-bit Block Number + up to 512 bytes of data for DATA/ACK, or 16-bit ErrorCode + NUL-terminated ErrMsg string for ERROR. When optional fields in [`TftpSpec`]
//! are omitted in the `.fasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.fasm` syntax:
//! `a -> b TFTP [RRQ | WRQ | DATA | ACK | ERROR] [FILENAME <str>] [MODE <str>] [BLOCK <u16>] [ERRCODE <u16>] [ERRMSG <str>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;

/// Builds an RFC 1350 TFTP packet payload.
/// Syntax mapping: `TFTP [RRQ | WRQ | DATA | ACK | ERROR] [FILENAME <str>] [MODE <str>] [BLOCK <u16>] [ERRCODE <u16>] [ERRMSG <str>]`
#[doc(alias = "TFTP")]
#[doc(alias = "RFC1350")]
#[doc(alias = "RRQ")]
#[doc(alias = "WRQ")]
#[doc(alias = "FILENAME")]
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
