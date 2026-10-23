//! Domain Name System (DNS) AST definitions.

/// RFC 1035 / RFC 6762 Domain Name System specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsSpec<'a> {
    /// Query flag.
    pub is_query: bool,
    /// Response flag.
    pub is_response: bool,
    /// Transaction ID.
    pub txid: Option<u16>,
    /// Question domain name.
    pub qname: Option<&'a str>,
    /// Question record type.
    pub qtype: Option<&'a str>,
    /// Answer resource data.
    pub rdata: Option<&'a str>,
    /// Response return code.
    pub rcode: Option<u8>,
    /// Answer time-to-live in seconds.
    pub ans_ttl: Option<u32>,
}

/// Type alias for Multicast DNS specification (RFC 6762).
pub type MdnsSpec<'a> = DnsSpec<'a>;
