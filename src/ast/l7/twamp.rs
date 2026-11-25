//! Two-Way Active Measurement Protocol (`twamp`, RFC 5357 / RFC 6038 / RFC 8545) Layer 7 AST definitions.
//!
//! This module defines [`TwampSpec`], the zero-copy abstract syntax tree (AST) representation for
//! synthesizing Two-Way Active Measurement Protocol packets across both the UDP port `862`
//! TWAMP-Test data plane (Session-Sender and Session-Reflector measurement packets) and the TCP
//! port `862` TWAMP-Control signaling plane (`Server-Greeting`, `Set-Up-Response`, `Server-Start`,
//! `Request-TW-Session`, `Accept-Session`, `Start-Sessions`, `Start-Ack`, and `Stop-Sessions`
//! via `transport tcp`). Every field in [`TwampSpec`] is optional so bare `twamp` emits a valid
//! 41-byte unauthenticated TWAMP-Test measurement packet with zero mandatory modifiers.
//!
//! Canonical `.frasm` syntax:
//! `a -> b twamp [sender | reflector | greeting | setupresponse | serverstart | requestsession | acceptsession | startsessions | startack | stopsessions | msgtype <str>] [seqnum <u32>] [timestamp <u64>] [errorestimate <u16>] [senderttl <u8>] [mode <u32>] [count <u32>] [status <u8>] [port <u16>] [padding <u16>] [transport tcp]`

/// RFC 5357 Two-Way Active Measurement Protocol (`twamp`) specification.
///
/// Syntax mapping: `twamp [sender | reflector | greeting | setupresponse | serverstart | requestsession | acceptsession | startsessions | startack | stopsessions | msgtype <str>] [seqnum <u32>] [timestamp <u64>] [errorestimate <u16>] [senderttl <u8>] [mode <u32>] [count <u32>] [status <u8>] [port <u16>] [padding <u16>] [transport tcp]`
#[doc(alias = "twamp")]
#[doc(alias = "RFC 5357")]
#[doc(alias = "RFC5357")]
#[doc(alias = "862")]
#[doc(alias = "sender")]
#[doc(alias = "reflector")]
#[doc(alias = "greeting")]
#[doc(alias = "setupresponse")]
#[doc(alias = "serverstart")]
#[doc(alias = "requestsession")]
#[doc(alias = "acceptsession")]
#[doc(alias = "startsessions")]
#[doc(alias = "startack")]
#[doc(alias = "stopsessions")]
#[doc(alias = "msgtype")]
#[doc(alias = "seqnum")]
#[doc(alias = "timestamp")]
#[doc(alias = "errorestimate")]
#[doc(alias = "senderttl")]
#[doc(alias = "mode")]
#[doc(alias = "count")]
#[doc(alias = "status")]
#[doc(alias = "port")]
#[doc(alias = "padding")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TwampSpec<'a> {
    /// TWAMP-Test or TWAMP-Control message type (`"sender"`, `"reflector"`, `"greeting"`, `"setupresponse"`, `"serverstart"`, `"requestsession"`, `"acceptsession"`, `"startsessions"`, `"startack"`, `"stopsessions"`).
    pub msg_type: Option<&'a str>,
    /// 32-bit TWAMP-Test packet sequence number (`seqnum <u32>`; default `1`).
    pub seq_num: Option<u32>,
    /// 64-bit NTP-format timestamp (`timestamp <u64>`; default `0`).
    pub timestamp: Option<u64>,
    /// 16-bit TWAMP-Test error estimate field (`errorestimate <u16>`; default `0x8001`).
    pub error_estimate: Option<u16>,
    /// 8-bit Sender TTL value carried in TWAMP-Test Reflector packets (`senderttl <u8>`; default `255`).
    pub sender_ttl: Option<u8>,
    /// 32-bit TWAMP-Control security mode mask (`mode <u32>`; default `1` for Unauthenticated).
    pub mode: Option<u32>,
    /// 32-bit PBKDF2 iteration count in Server-Greeting (`1024`) or session count in Stop-Sessions (`1`).
    pub count: Option<u32>,
    /// 8-bit TWAMP-Control Accept status code (`status <u8>`; default `0` for OK).
    pub status: Option<u8>,
    /// 16-bit test receiver port in Request-TW-Session or Accept-Session (`port <u16>`; default `862`).
    pub port: Option<u16>,
    /// Zero-padding byte count in TWAMP-Test Sender or Request-TW-Session Padding Length (`padding <u16>`; default `27`).
    pub padding: Option<u16>,
}
