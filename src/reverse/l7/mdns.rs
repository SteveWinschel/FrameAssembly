//! Multicast DNS (`mdns`, RFC 6762) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 6762 Multicast DNS (`mdns`)
//! discovery queries and service responses carried over UDP port `5353` (typically targeting
//! `224.0.0.251` on IPv4 or `ff02::fb` on IPv6). It delegates DNS wire-format header validation,
//! pointer-compressed domain name decoding, question section extraction, and resource record
//! dissection to [`super::dns::dissect_dns_or_mdns`], emitting canonical `mdns query` and
//! `mdns response` `.frasm` statements.

use crate::reverse::ProtocolDissection;

/// Dissects an RFC 6762 `mdns` message over UDP port `5353`.
pub(crate) fn dissect_mdns(payload: &[u8]) -> Option<ProtocolDissection> {
    super::dns::dissect_dns_or_mdns(payload, false, true)
}
