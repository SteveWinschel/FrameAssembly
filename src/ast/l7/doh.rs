//! DNS over HTTPS (DoH, RFC 8484) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! cleartext RFC 8484 DNS over HTTPS (`doh`) requests and responses over TCP port 80 (and
//! supporting reverse dissection on TCP ports 80 and 443). On the wire, requests encode an
//! HTTP/1.1 `POST /dns-query` (or base64url `GET /dns-query?dns=...`) exchange carrying
//! `Content-Type: application/dns-message` and `Accept: application/dns-message` around a binary
//! RFC 1035 / RFC 6891 DNS message payload, while responses emit `HTTP/1.1 200 OK` with the
//! `application/dns-message` DNS answer body. Every field in [`DohSpec`] is optional.
//!
//! Canonical `.frasm` syntax:
//! `a -> b doh [query | response] [get | post | method <str>] [uri <str>] [hosthdr <str>] [useragent <str>] [status <u16>] [reason <str>] [txid <u16>] [qname <str>] [qtype <str>] [rdata <str>]... [rcode <u8>] [ansttl <u32>] [edns0] [udpsize <u16>] [dobit]`

use alloc::vec::Vec;

/// RFC 8484 DNS over HTTPS specification.
///
/// Syntax mapping: `doh [query | response] [get | post | method <str>] [uri <str>] [hosthdr <str>] [useragent <str>] [status <u16>] [reason <str>] [txid <u16>] [qname <str>] [qtype <str>] [rdata <str>]... [rcode <u8>] [ansttl <u32>] [edns0] [udpsize <u16>] [dobit]`
#[doc(alias = "doh")]
#[doc(alias = "RFC 8484")]
#[doc(alias = "RFC8484")]
#[doc(alias = "query")]
#[doc(alias = "response")]
#[doc(alias = "method")]
#[doc(alias = "uri")]
#[doc(alias = "hosthdr")]
#[doc(alias = "useragent")]
#[doc(alias = "status")]
#[doc(alias = "reason")]
#[doc(alias = "txid")]
#[doc(alias = "qname")]
#[doc(alias = "qtype")]
#[doc(alias = "rdata")]
#[doc(alias = "rcode")]
#[doc(alias = "ansttl")]
#[doc(alias = "edns0")]
#[doc(alias = "udpsize")]
#[doc(alias = "dobit")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DohSpec<'a> {
    /// DNS query flag (`query`).
    pub is_query: bool,
    /// DNS/HTTP response flag (`response`).
    pub is_response: bool,
    /// HTTP request method (`get`, `post`, or `method <str>`, default `"POST"`).
    pub method: Option<&'a str>,
    /// HTTP request target URI (`uri <str>`, default `"/dns-query"`).
    pub uri: Option<&'a str>,
    /// HTTP `Host` header override (`hosthdr <str>`).
    pub host_hdr: Option<&'a str>,
    /// HTTP `User-Agent` header override (`useragent <str>`).
    pub user_agent: Option<&'a str>,
    /// HTTP response status code (`status <u16>`, default `200` on response).
    pub status: Option<u16>,
    /// HTTP response reason phrase (`reason <str>`, default `"OK"`).
    pub reason: Option<&'a str>,
    /// DNS Transaction ID (`txid <u16>`, RFC 8484 default `0`).
    pub txid: Option<u16>,
    /// DNS question domain name (`qname <str>`, default `"example.com"`).
    pub qname: Option<&'a str>,
    /// DNS question record type (`qtype <str>`, default `"A"`).
    pub qtype: Option<&'a str>,
    /// Primary DNS answer resource data (`rdata <str>`).
    pub rdata: Option<&'a str>,
    /// DNS response return code (`rcode <u8>`).
    pub rcode: Option<u8>,
    /// DNS answer time-to-live in seconds (`ansttl <u32>`).
    pub ans_ttl: Option<u32>,
    /// Enable EDNS0 OPT pseudo-RR (`edns0`).
    pub edns0: bool,
    /// EDNS0 UDP payload size in bytes (`udpsize <u16>`).
    pub udp_size: Option<u16>,
    /// EDNS0 DNSSEC OK (`DO`) bit (`dobit`).
    pub do_bit: bool,
    /// Repeated DNS answer resource data entries (`rdata <str>`).
    pub rdata_list: Vec<&'a str>,
}
