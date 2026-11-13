//! Domain Name System (DNS) (RFC 1035 / RFC 3596 / RFC 6891) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! Domain Name System (DNS) packets over UDP/TCP port 53. On the wire, the protocol uses a 12-byte fixed DNS header (16-bit Transaction ID, 16-bit Flags QR/Opcode/AA/TC/RD/RA/Z/RCODE, 16-bit QDCOUNT, 16-bit ANCOUNT, 16-bit NSCOUNT, 16-bit ARCOUNT) followed by length-prefixed QNAME labels, 16-bit QTYPE, 16-bit QCLASS, and resource record RDATA sections.
//! Every field in [`DnsSpec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.frasm` syntax:
//! `a -> b dns [query | response] [txid <u16>] [qname <str>] [qtype <str>] [rdata <str>] [rcode <u8>] [ansttl <u32>] [transport tcp]`

/// RFC 1035 / RFC 6762 Domain Name System specification.
///
/// Syntax mapping: `dns [query | response] [txid <u16>] [qname <str>] [qtype <str>] [rdata <str>] [rcode <u8>] [ansttl <u32>] [transport tcp]`
#[doc(alias = "dns")]
#[doc(alias = "RFC 1035")]
#[doc(alias = "RFC1035")]
#[doc(alias = "RFC 3596")]
#[doc(alias = "RFC3596")]
#[doc(alias = "RFC 6891")]
#[doc(alias = "query")]
#[doc(alias = "response")]
#[doc(alias = "txid")]
#[doc(alias = "qname")]
#[doc(alias = "qtype")]
#[doc(alias = "rdata")]
#[doc(alias = "rcode")]
#[doc(alias = "ansttl")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsSpec<'a> {
    /// Query flag (`query`).
    pub is_query: bool,
    /// Response flag (`response`).
    pub is_response: bool,
    /// Transaction ID (`txid <u16>`).
    pub txid: Option<u16>,
    /// Question domain name (`qname <str>`).
    pub qname: Option<&'a str>,
    /// Question record type (`qtype <str>`).
    pub qtype: Option<&'a str>,
    /// Answer resource data (`rdata <str>`).
    pub rdata: Option<&'a str>,
    /// Response return code (`rcode <u8>`).
    pub rcode: Option<u8>,
    /// Answer time-to-live in seconds (`ansttl <u32>`).
    pub ans_ttl: Option<u32>,
}

/// Type alias for Multicast DNS specification (RFC 6762).
///
/// Syntax mapping: `mdns [query | response] [txid <u16>] [qname <str>] [qtype <str>] [rdata <str>] [rcode <u8>] [ansttl <u32>]`
#[doc(alias = "mdns")]
#[doc(alias = "RFC 6762")]
#[doc(alias = "RFC6762")]
#[doc(alias = "RFC 6763")]
#[doc(alias = "query")]
#[doc(alias = "response")]
#[doc(alias = "txid")]
#[doc(alias = "qname")]
#[doc(alias = "qtype")]
#[doc(alias = "rdata")]
#[doc(alias = "rcode")]
#[doc(alias = "ansttl")]
pub type MdnsSpec<'a> = DnsSpec<'a>;
