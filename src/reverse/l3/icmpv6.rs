//! ICMPv6 (RFC 4443 / RFC 4861 / RFC 2710 / RFC 3810) Layer 3 PCAP-to-`.frasm` dispatcher.
//!
//! This module implements the unified IPv6 Next Header `58` (`ICMPv6`) dispatcher
//! ([`dissect_icmpv6`]) for FrameAssembly's PCAP and PCAPNG decompiler. It routes ICMPv6 frames by
//! message type and minimum PDU length across:
//! - [`super::ndp::dissect_ndp`] for RFC 4861 Neighbor Discovery Protocol (`133..=136` and 40-byte
//!   `137`, including IPv6 Neighbor Solicitation / Advertisement frames produced by dual-stack
//!   `arp`),
//! - [`super::mld::dissect_mld`] for RFC 2710 / RFC 3810 Multicast Listener Discovery (`130..=132`
//!   and `143` when at least 24 bytes), and
//! - [`super::icmp::dissect_icmpv6`] for RFC 4443 diagnostic messages (`128` Echo Request, `129`
//!   Echo Reply, `1` Destination Unreachable, `3` Time Exceeded, and generic ICMPv6 types).

use core::net::IpAddr;

use crate::reverse::ProtocolDissection;

use super::{icmp, mld, ndp};

/// Dispatches an IPv6 Next Header `58` (`ICMPv6`) payload to [`ndp::dissect_ndp`],
/// [`mld::dissect_mld`], or [`icmp::dissect_icmpv6`].
pub(crate) fn dissect_icmpv6(
    ip_body: &[u8],
    src_mac: [u8; 6],
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
) -> ProtocolDissection {
    match ip_body.first().copied() {
        Some(133..=136) => ndp::dissect_ndp(ip_body, src_mac, dst_ip),
        Some(137) if ip_body.len() >= 40 => ndp::dissect_ndp(ip_body, src_mac, dst_ip),
        Some(130..=132 | 143) if ip_body.len() >= 24 => mld::dissect_mld(ip_body),
        _ => icmp::dissect_icmpv6(ip_body, src_ip),
    }
}
