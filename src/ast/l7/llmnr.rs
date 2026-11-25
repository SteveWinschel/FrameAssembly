//! Link-Local Multicast Name Resolution (`llmnr`, RFC 4795) Layer 7 AST definitions.
//!
//! This module defines the zero-copy Abstract Syntax Tree (AST) configuration parameters for
//! synthesizing RFC 4795 Link-Local Multicast Name Resolution (`llmnr`) queries and responses over
//! UDP or TCP port 5355 (defaulting to IPv4 multicast `224.0.0.252` or IPv6 `ff02::1:3` on UDP
//! queries when destination IP is multicast or unspecified, and unicast on responses or TCP). On the
//! wire, LLMNR uses a 12-byte DNS-derived header carrying `C`/`TC`/`T` flags, `QNAME`, `QTYPE`, and
//! resource records. Canonical `.frasm` syntax:
//! `a -> b llmnr [query | response] [txid <u16>] [qname <str>] [qtype <str>] [rdata <str>]... [rcode <u8>] [ansttl <u32>] [flags <u16>] [transport tcp]`.

use alloc::vec::Vec;

/// RFC 4795 Link-Local Multicast Name Resolution (`llmnr`) Layer 7 protocol specification.
///
/// Syntax mapping: `llmnr [query | response] [txid <u16>] [qname <str>] [qtype <str>] [rdata <str>]... [rcode <u8>] [ansttl <u32>] [flags <u16>] [transport tcp]`
#[doc(alias = "llmnr")]
#[doc(alias = "RFC 4795")]
#[doc(alias = "RFC4795")]
#[doc(alias = "query")]
#[doc(alias = "response")]
#[doc(alias = "txid")]
#[doc(alias = "qname")]
#[doc(alias = "qtype")]
#[doc(alias = "rdata")]
#[doc(alias = "rcode")]
#[doc(alias = "ansttl")]
#[doc(alias = "flags")]
#[doc(alias = "5355")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LlmnrSpec<'a> {
    /// Query flag (`query`, sets `QR = 0`).
    pub is_query: bool,
    /// Response flag (`response`, sets `QR = 1`).
    pub is_response: bool,
    /// 16-bit Transaction ID (`txid <u16>`, default `0x1234`).
    pub txid: Option<u16>,
    /// Question host name (`qname <str>`, default `"fileserver"`).
    pub qname: Option<&'a str>,
    /// Question record type (`qtype <str>`, e.g., `"a"`, `"aaaa"`, `"ptr"`, `"any"`, default `"a"`).
    pub qtype: Option<&'a str>,
    /// Answer resource record data (`rdata <str>`).
    pub rdata: Option<&'a str>,
    /// All answer resource data values when multiple `rdata` modifiers are specified.
    pub rdata_list: Vec<&'a str>,
    /// 4-bit response code (`rcode <u8>`, default `0`).
    pub rcode: Option<u8>,
    /// Answer TTL in seconds (`ansttl <u32>`, RFC 4795 default `30`).
    pub ans_ttl: Option<u32>,
    /// Explicit 16-bit RFC 4795 header flags override (`flags <u16>`, e.g. `0x8400` Conflict).
    pub flags: Option<u16>,
}
