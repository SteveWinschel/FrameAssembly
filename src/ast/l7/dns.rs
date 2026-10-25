//! Domain Name System (DNS) (RFC 1035 / RFC 3596 / RFC 6891) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! Domain Name System (DNS) packets over UDP/TCP port 53. On the wire, the protocol uses a 12-byte fixed DNS header (16-bit Transaction ID, 16-bit Flags QR/Opcode/AA/TC/RD/RA/Z/RCODE, 16-bit QDCOUNT, 16-bit ANCOUNT, 16-bit NSCOUNT, 16-bit ARCOUNT) followed by length-prefixed QNAME labels, 16-bit QTYPE, 16-bit QCLASS, and resource record RDATA sections.
//! Every field in [`DnsSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.fasm` syntax:
//! `a -> b DNS [QUERY | RESPONSE] [TXID <u16>] [QNAME <str>] [QTYPE <str>] [RDATA <str>] [RCODE <u8>] [ANS_TTL <u32>] [TRANSPORT TCP]`

/// RFC 1035 / RFC 6762 Domain Name System specification.
///
/// Syntax mapping: `DNS [QUERY | RESPONSE] [TXID <u16>] [QNAME <str>] [QTYPE <str>] [RDATA <str>] [RCODE <u8>] [ANS_TTL <u32>] [TRANSPORT TCP]`
#[doc(alias = "DNS")]
#[doc(alias = "RFC 1035")]
#[doc(alias = "RFC1035")]
#[doc(alias = "RFC 3596")]
#[doc(alias = "RFC3596")]
#[doc(alias = "RFC 6891")]
#[doc(alias = "QUERY")]
#[doc(alias = "RESPONSE")]
#[doc(alias = "TXID")]
#[doc(alias = "QNAME")]
#[doc(alias = "QTYPE")]
#[doc(alias = "RDATA")]
#[doc(alias = "RCODE")]
#[doc(alias = "ANS_TTL")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsSpec<'a> {
    /// Query flag (`QUERY`).
    pub is_query: bool,
    /// Response flag (`RESPONSE`).
    pub is_response: bool,
    /// Transaction ID (`TXID <u16>`).
    pub txid: Option<u16>,
    /// Question domain name (`QNAME <str>`).
    pub qname: Option<&'a str>,
    /// Question record type (`QTYPE <str>`).
    pub qtype: Option<&'a str>,
    /// Answer resource data (`RDATA <str>`).
    pub rdata: Option<&'a str>,
    /// Response return code (`RCODE <u8>`).
    pub rcode: Option<u8>,
    /// Answer time-to-live in seconds (`ANS_TTL <u32>`).
    pub ans_ttl: Option<u32>,
}

/// Type alias for Multicast DNS specification (RFC 6762).
///
/// Syntax mapping: `MDNS [QUERY | RESPONSE] [TXID <u16>] [QNAME <str>] [QTYPE <str>] [RDATA <str>] [RCODE <u8>] [ANS_TTL <u32>]`
#[doc(alias = "MDNS")]
#[doc(alias = "RFC 6762")]
#[doc(alias = "RFC6762")]
#[doc(alias = "RFC 6763")]
#[doc(alias = "QUERY")]
#[doc(alias = "RESPONSE")]
#[doc(alias = "TXID")]
#[doc(alias = "QNAME")]
#[doc(alias = "QTYPE")]
#[doc(alias = "RDATA")]
#[doc(alias = "RCODE")]
#[doc(alias = "ANS_TTL")]
pub type MdnsSpec<'a> = DnsSpec<'a>;
