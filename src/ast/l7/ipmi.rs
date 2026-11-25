//! Intelligent Platform Management Interface (`ipmi`, RMCP / ASF v2.0 / IPMI v1.5 / RMCP+ v2.0) Layer 7 AST definitions.
//!
//! This module defines [`IpmiSpec`], the zero-copy abstract syntax tree (AST) representation for
//! synthesizing Remote Management Control Protocol (`RMCP`), Alert Standard Forum (`ASF`), IPMI v1.5,
//! and IPMI v2.0 (`RMCP+`) out-of-band server management packets over UDP port `623`. Every field in
//! [`IpmiSpec`] is optional so bare `ipmi` frames synthesize a valid IPMI v1.5 Get Device ID request
//! with zero mandatory modifiers, while authors can selectively emit ASF Presence `ping`/`pong`,
//! RMCP+ pre-session handshakes (`opensession`, `opensessionresp`, `rakp1` through `rakp4`), or
//! custom NetFn, LUN, command, completion status, and session counters.
//!
//! Canonical `.frasm` syntax:
//! `a -> b ipmi [ping | pong | msgtype <str>] [version <u8>] [request | response] [netfn <u8>] [cmd <u8>] [lun <u8>] [rqseq <u8>] [sessionid <u32>] [seqnum <u32>] [status <u8>]`

/// Intelligent Platform Management Interface (RMCP / ASF / IPMI v1.5 / RMCP+ v2.0) specification.
///
/// Syntax mapping: `ipmi [ping | pong | msgtype <str>] [version <u8>] [request | response] [netfn <u8>] [cmd <u8>] [lun <u8>] [rqseq <u8>] [sessionid <u32>] [seqnum <u32>] [status <u8>]`
#[doc(alias = "ipmi")]
#[doc(alias = "RMCP")]
#[doc(alias = "ASF")]
#[doc(alias = "RMCP+")]
#[doc(alias = "IPMB")]
#[doc(alias = "623")]
#[doc(alias = "ping")]
#[doc(alias = "pong")]
#[doc(alias = "msgtype")]
#[doc(alias = "version")]
#[doc(alias = "request")]
#[doc(alias = "response")]
#[doc(alias = "netfn")]
#[doc(alias = "cmd")]
#[doc(alias = "lun")]
#[doc(alias = "rqseq")]
#[doc(alias = "sessionid")]
#[doc(alias = "seqnum")]
#[doc(alias = "status")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IpmiSpec<'a> {
    /// RMCP or RMCP+ message type (`"ipmi"`, `"ping"`, `"pong"`, `"opensession"`, `"opensessionresp"`, `"rakp1"` through `"rakp4"`).
    pub msg_type: Option<&'a str>,
    /// IPMI session wrapper version (`1` for IPMI v1.5, `2` for IPMI v2.0 RMCP+; default `1`).
    pub version: Option<u8>,
    /// Marks the IPMI message as a BMC response (`true` forces odd NetFn and prepends completion code).
    pub is_response: bool,
    /// 6-bit IPMI Network Function code (`0..=63`; default `0x06` App request or `0x07` App response).
    pub netfn: Option<u8>,
    /// 8-bit IPMI command code (`0..=255`; default `0x01` Get Device ID).
    pub cmd: Option<u8>,
    /// 2-bit IPMI Logical Unit Number (`0..=3`; default `0`).
    pub lun: Option<u8>,
    /// 6-bit IPMB request sequence or RMCP+ message tag (`0..=63`; default `1` for IPMB, `0` for RMCP+).
    pub rqseq: Option<u8>,
    /// 32-bit IPMI session identifier (`sessionid <u32>`; default `0`).
    pub session_id: Option<u32>,
    /// 32-bit IPMI session sequence number or ASF message tag (`seqnum <u32>`; default `0`).
    pub seq_num: Option<u32>,
    /// 8-bit IPMI completion code or RMCP+ status code (`status <u8>`; default `0x00` Normal).
    pub status: Option<u8>,
}
