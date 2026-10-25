//! Multicast DNS (mDNS) (RFC 6762 / RFC 6763 (DNS-SD)) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! Multicast DNS (mDNS) packets over UDP port 5353 (IPv4 multicast 224.0.0.251 / IPv6 ff02::fb). On the wire, the protocol uses a 12-byte RFC 1035 DNS wire header (16-bit ID usually 0x0000, 16-bit Flags 0x0000 query or 0x8400 authoritative response, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT) carrying link-local .local domain labels, PTR/SRV/TXT/A/AAAA resource records, and cache-flush class bits.
//! Every field in [`MdnsSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.fasm` syntax:
//! `a -> b MDNS [QUERY | RESPONSE] [TXID <u16>] [QNAME <str>] [QTYPE <str>] [RDATA <str>] [RCODE <u8>] [ANS_TTL <u32>]`

/// Multicast DNS (mDNS) (RFC 6762 / RFC 6763 (DNS-SD)) specification.
///
/// Syntax mapping: `MDNS [QUERY | RESPONSE] [TXID <u16>] [QNAME <str>] [QTYPE <str>] [RDATA <str>] [RCODE <u8>] [ANS_TTL <u32>]`
#[doc(alias = "MDNS")]
#[doc(alias = "RFC 6762")]
#[doc(alias = "RFC6762")]
#[doc(alias = "RFC 6763")]
#[doc(alias = "RFC6763")]
#[doc(alias = "BONJOUR")]
#[doc(alias = "DNSSD")]
#[doc(alias = "QUERY")]
#[doc(alias = "RESPONSE")]
#[doc(alias = "TXID")]
#[doc(alias = "QNAME")]
#[doc(alias = "QTYPE")]
#[doc(alias = "RDATA")]
#[doc(alias = "RCODE")]
#[doc(alias = "ANS_TTL")]
pub use super::dns::MdnsSpec;
