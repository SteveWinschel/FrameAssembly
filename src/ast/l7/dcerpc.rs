//! Distributed Computing Environment / Remote Procedure Call (`dcerpc`, C706 / MS-RPCE) Layer 7 AST definitions.
//!
//! This module defines the zero-copy Abstract Syntax Tree (AST) configuration parameters for
//! synthesizing connection-oriented DCE/RPC v5 (`ncacn_ip_tcp`) protocol data units over TCP port
//! 135 (RPC Endpoint Mapper) and dynamically assigned high ports (`49152+`). On the wire, every PDU
//! starts with a 16-byte common header (`rpc_vers = 5`, `PTYPE`, `pfc_flags`, little-endian data
//! representation `0x10 00 00 00`, `frag_length`, `auth_length`, and `call_id`), followed by `Bind`,
//! `Bind_ack`, `Bind_nak`, `Alter_context`, `Request`, `Response`, or `Fault` structures. Canonical
//! `.frasm` syntax:
//! `a -> b dcerpc [bind | bindack | bindnak | request | response | fault | altercontext] [msgtype <str>] [uuid <str>] [vers <str>] [opnum <u16>] [callid <u32>] [ctxid <u16>] [flags <u8>] [status <u32>]`.

/// Connection-oriented DCE/RPC v5 (MS-RPCE / CAE RPC) protocol specification.
///
/// Syntax mapping: `dcerpc [bind | bindack | bindnak | request | response | fault | altercontext] [msgtype <str>] [uuid <str>] [vers <str>] [opnum <u16>] [callid <u32>] [ctxid <u16>] [flags <u8>] [status <u32>]`
#[doc(alias = "dcerpc")]
#[doc(alias = "MS-RPCE")]
#[doc(alias = "EPM")]
#[doc(alias = "DRSUAPI")]
#[doc(alias = "SAMR")]
#[doc(alias = "bind")]
#[doc(alias = "bindack")]
#[doc(alias = "bindnak")]
#[doc(alias = "request")]
#[doc(alias = "response")]
#[doc(alias = "fault")]
#[doc(alias = "altercontext")]
#[doc(alias = "msgtype")]
#[doc(alias = "uuid")]
#[doc(alias = "vers")]
#[doc(alias = "opnum")]
#[doc(alias = "callid")]
#[doc(alias = "ctxid")]
#[doc(alias = "flags")]
#[doc(alias = "status")]
#[doc(alias = "135")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DcerpcSpec<'a> {
    /// DCE/RPC PDU type (`bind`, `bindack`, `bindnak`, `request`, `response`, `fault`, `altercontext`, or numeric code).
    pub pdu_type: Option<&'a str>,
    /// Interface or Object UUID string (`uuid <str>`, dashed UUID or service alias such as `"epm"`, `"drsuapi"`, `"samr"`).
    pub uuid: Option<&'a str>,
    /// Interface `major.minor` version string (`vers <str>`, default `"3.0"` for EPM).
    pub if_version: Option<&'a str>,
    /// 16-bit RPC operation number for `request` PDUs (`opnum <u16>`).
    pub opnum: Option<u16>,
    /// 32-bit DCE/RPC Call ID (`callid <u32>`, default `1`).
    pub call_id: Option<u32>,
    /// 16-bit Presentation Context ID (`ctxid <u16>`, default `0`).
    pub ctx_id: Option<u16>,
    /// 8-bit PFC header flags byte (`flags <u8>`, default `0x03`).
    pub flags: Option<u8>,
    /// 32-bit Fault status, Bind_nak reject reason, or Bind_ack result code (`status <u32>`).
    pub status: Option<u32>,
}
