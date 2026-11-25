//! Multicast DNS (`mdns`, RFC 6762 / RFC 6891) Layer 7 PCAP-to-`.frasm` decompiler.
//!
//! This module implements the fuzz-safe reverse dissector for RFC 6762 Multicast DNS (`mdns`)
//! discovery queries and service responses carried over UDP port `5353` (typically targeting
//! `224.0.0.251` on IPv4 or `ff02::fb` on IPv6). It delegates header validation, RFC 6762 `0x0000`
//! transaction ID elision, cycle-checked domain name compression, binary `SOA`/`SRV` and multi-RR
//! dissection, and EDNS0 `OPT` record decoding to [`super::dns::dissect_dns_or_mdns`].

use crate::reverse::ProtocolDissection;

/// Dissects an RFC 6762 `mdns` message over UDP port `5353`.
pub(crate) fn dissect_mdns(payload: &[u8]) -> Option<ProtocolDissection> {
    super::dns::dissect_dns_or_mdns(payload, false, true)
}
