//! Hypertext Transfer Protocol Version 2 (HTTP/2) (RFC 9113 (HTTP/2) / RFC 7541 (HPACK)) Layer 7 AST definitions.
//!
//! This module defines the abstract syntax tree (AST) configuration parameters for synthesizing
//! Hypertext Transfer Protocol Version 2 (HTTP/2) packets over TCP port 443 (h2 over TLS) or TCP port 80 (h2c cleartext). On the wire, the protocol uses a 24-octet client connection preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`) and 9-octet binary frame headers containing 24-bit payload Length, 8-bit Frame Type (`0x0` DATA, `0x1` HEADERS, `0x4` SETTINGS, `0x6` PING, `0x7` GOAWAY, `0x8` WINDOW_UPDATE), 8-bit Flags (`END_STREAM = 0x1`, `END_HEADERS = 0x4`, `ACK = 0x1`), 1-bit Reserved flag, and 31-bit Stream Identifier.
//! Every field in [`Http2Spec`] is optional so authors can emit zero-configuration default
//! frames or override specific protocol header fields and attributes.
//!
//! Canonical `.fasm` syntax:
//! `a -> b HTTP2 [PREFACE | SETTINGS | HEADERS | DATA | WINDOW_UPDATE | PING | GOAWAY] [STREAM_ID <u32>]`

use core::marker::PhantomData;
/// RFC 9113 HTTP/2 framing specification.
///
/// Syntax mapping: `HTTP2 [PREFACE | SETTINGS | HEADERS | DATA | WINDOW_UPDATE | PING | GOAWAY] [STREAM_ID <u32>]`
#[doc(alias = "HTTP2")]
#[doc(alias = "H2")]
#[doc(alias = "RFC 9113")]
#[doc(alias = "RFC9113")]
#[doc(alias = "RFC 7540")]
#[doc(alias = "RFC7540")]
#[doc(alias = "PREFACE")]
#[doc(alias = "SETTINGS")]
#[doc(alias = "HEADERS")]
#[doc(alias = "DATA")]
#[doc(alias = "WINDOW_UPDATE")]
#[doc(alias = "PING")]
#[doc(alias = "GOAWAY")]
#[doc(alias = "STREAM_ID")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Http2Spec<'a> {
    /// Connection preface flag.
    pub is_preface: bool,
    /// SETTINGS frame flag.
    pub is_settings: bool,
    /// HEADERS frame flag.
    pub is_headers: bool,
    /// DATA frame flag.
    pub is_data: bool,
    /// WINDOW_UPDATE frame flag.
    pub is_window_update: bool,
    /// PING frame flag.
    pub is_ping: bool,
    /// GOAWAY frame flag.
    pub is_goaway: bool,
    /// Stream identifier.
    pub stream_id: Option<u32>,
    /// Optional phantom reference.
    pub _marker: PhantomData<&'a ()>,
}
