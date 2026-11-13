//! IP Flow Information Export (`ipfix`, RFC 7011 / RFC 7012) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 7011 `ipfix` (Version 10) flow
//! telemetry datagrams (16-byte message header + 4-byte set header + 29-byte flow record) over UDP
//! port `4739` or matching the deterministic FrameAssembly IPFIX header signature. It decodes
//! `domainid`, `srcip`, `dstip`, `proto`, `packets`, and `octets` into canonical `.frasm` tokens.

use alloc::string::String;

use crate::ast::Protocol;
use crate::reverse::{ProtocolDissection, be_u16, be_u32, be_u64, ipv4_at, push_if};

use super::{append_flow_record_tokens, ok_dissect};

/// Dissects an RFC 7011 `ipfix` v10 telemetry datagram (16B header + 4B set header + 29B record).
pub(crate) fn dissect_ipfix(payload: &[u8], sp: u16, dp: u16) -> Option<ProtocolDissection> {
    if payload.len() < 49
        || be_u16(payload, 0) != 10
        || !(sp == 4739
            || dp == 4739
            || (be_u32(payload, 4) == 1_700_000_000
                && be_u32(payload, 8) == 1
                && be_u16(payload, 16) == 256
                && be_u16(payload, 18) == 33))
    {
        return None;
    }
    let mut tokens = String::from("ipfix");
    push_if(&mut tokens, "domainid", be_u32(payload, 12), 0);
    append_flow_record_tokens(
        &mut tokens,
        ipv4_at(payload, 20),
        ipv4_at(payload, 24),
        payload[32],
        be_u64(payload, 33) as u32,
        be_u64(payload, 41) as u32,
    );
    ok_dissect(Protocol::Ipfix, tokens, payload[49..].to_vec())
}
