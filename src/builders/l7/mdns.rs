//! MDNS protocol wire builder.

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::IpAddr;
use super::dns::build_dns_payload;

/// Builds an RFC 6762 mDNS payload and returns the payload, target multicast IP, and port (5353).
pub fn build_mdns_payload(
    ctx: &WireContext,
    spec: &DnsSpec,
    payload_bytes: &[u8],
) -> (Vec<u8>, IpAddr, u16) {
    let payload = build_dns_payload(ctx, spec, payload_bytes, false);
    let target_ip = if ctx.src_ip.is_ipv4() {
        IpAddr::V4(core::net::Ipv4Addr::new(224, 0, 0, 251))
    } else {
        IpAddr::V6(core::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb))
    };
    (payload, target_ip, 5353)
}
