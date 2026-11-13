//! Cisco NetFlow v5 (`netflow`) Layer 7 network flow telemetry PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for Cisco `netflow` Version 5 export
//! datagrams (24-byte header + 48-byte flow record) carried over UDP port `2055` or matching the
//! deterministic FrameAssembly NetFlow v5 header signature. It extracts flow source and
//! destination IPv4 addresses (`srcip`, `dstip`), inner IP protocol (`proto`), packet count
//! (`packets`), and byte count (`octets`).

use alloc::string::String;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u16, be_u32, ipv4_at};

use super::{append_flow_record_tokens, ok_dissect};

/// Dissects a Cisco `netflow` v5 telemetry datagram (24B header + 48B flow record).
pub(crate) fn dissect_netflow(payload: &[u8], sp: u16, dp: u16) -> Option<ProtocolDissection> {
    if payload.len() < 72
        || be_u16(payload, 0) != 5
        || !(sp == 2055
            || dp == 2055
            || (be_u16(payload, 2) == 1
                && be_u32(payload, 4) == 1000
                && be_u32(payload, 8) == 1_700_000_000))
    {
        return None;
    }
    let mut tokens = String::from("netflow");
    append_flow_record_tokens(
        &mut tokens,
        ipv4_at(payload, 24),
        ipv4_at(payload, 28),
        payload[62],
        be_u32(payload, 40),
        be_u32(payload, 44),
    );
    ok_dissect(Protocol::Netflow, tokens, payload[72..].to_vec())
}
