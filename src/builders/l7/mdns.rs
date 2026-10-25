//! Multicast DNS (mDNS) (RFC 6762 / RFC 6763 (DNS-SD)) Layer 7 wire packet builder.
//!
//! This module synthesizes deterministic on-the-wire Multicast DNS (mDNS) frames over UDP port 5353 (IPv4 multicast 224.0.0.251 / IPv6 ff02::fb).
//! The wire encoder constructs a 12-byte RFC 1035 DNS wire header (16-bit ID usually 0x0000, 16-bit Flags 0x0000 query or 0x8400 authoritative response, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT) carrying link-local .local domain labels, PTR/SRV/TXT/A/AAAA resource records, and cache-flush class bits. When optional fields in [`MdnsSpec`]
//! are omitted in the `.fasm` source, RFC-compliant default values are automatically populated.
//!
//! Canonical `.fasm` syntax:
//! `a -> b MDNS [QUERY | RESPONSE] [TXID <u16>] [QNAME <str>] [QTYPE <str>] [RDATA <str>] [RCODE <u8>] [ANS_TTL <u32>]`

use crate::ast::*;
use crate::builders::WireContext;
use alloc::vec::Vec;
use core::net::IpAddr;
use super::dns::build_dns_payload;

/// Builds an RFC 6762 mDNS payload and returns the payload, target multicast IP, and port (5353).
/// Syntax mapping: `MDNS [QUERY | RESPONSE] [TXID <u16>] [QNAME <str>] [QTYPE <str>] [RDATA <str>] [RCODE <u8>] [ANS_TTL <u32>]`
#[doc(alias = "MDNS")]
#[doc(alias = "RFC6762")]
#[doc(alias = "RFC6763")]
#[doc(alias = "BONJOUR")]
#[doc(alias = "DNSSD")]
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
