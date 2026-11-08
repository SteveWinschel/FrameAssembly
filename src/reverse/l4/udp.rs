//! User Datagram Protocol (UDP, RFC 768) Layer 4 PCAP-to-`.fasm` decompiler.
//!
//! This module implements the fuzz-safe PCAP and PCAPNG decompiler for RFC 768 User Datagram
//! Protocol (`UDP`, IP protocol `17`) headers in FrameAssembly. It slices the 8-byte UDP transport
//! header to extract source and destination ports (`srcport`, `dstport`) and exposes the inner
//! datagram payload slice for Layer 3-over-UDP, Layer 7, or raw `udp` decompilation.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ast::{L4Modifiers, Protocol};
use crate::reverse::{ProtocolDissection, be_u16, sd};

/// Slices an 8-byte UDP header from `ip_body`, populating `l4.src_port`, `l4.dst_port`, and
/// `l4_payload`, and returning `Some((src_port, dst_port))` when at least 8 bytes are present.
pub(crate) fn dissect_udp_header(
    ip_body: &[u8],
    l4: &mut L4Modifiers,
    l4_payload: &mut Vec<u8>,
) -> Option<(u16, u16)> {
    if ip_body.len() < 8 {
        return None;
    }
    let (sp, dp, ap) = (be_u16(ip_body, 0), be_u16(ip_body, 2), &ip_body[8..]);
    *l4_payload = ap.to_vec();
    (l4.src_port, l4.dst_port) = (Some(sp), Some(dp));
    Some((sp, dp))
}

/// Constructs a raw `udp` [`ProtocolDissection`] preserving `payload` as residual payload bytes.
pub(crate) fn dissect_udp(payload: &[u8]) -> ProtocolDissection {
    sd(Protocol::Udp, String::from("udp"), payload.to_vec())
}
