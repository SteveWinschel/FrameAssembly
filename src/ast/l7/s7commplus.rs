//! Siemens S7 Communication Plus (S7commPlus, TIA Portal S7-1200/S7-1500) AST definitions.
//!
//! This module defines [`S7commplusSpec`], the zero-copy AST representation of a Siemens
//! S7commPlus frame encapsulated inside RFC 1006 TPKT (`0x03 0x00`) and ISO 8073 COTP DT Data
//! (`0x02 0xF0 0x80`) over TCP port 102. Unlike legacy `s7comm` (`0x32` magic), S7commPlus frames
//! open and close with the `0x72` protocol identifier, version byte (`1..=3`), big-endian data
//! length, opcode (`0x31` Request, `0x32` Response, `0x33` Notification), 16-bit function code
//! (`Explore`, `CreateObject`, `GetMultiVariables`, `SetVariable`, `Invoke`), sequence number,
//! session ID, transport flags, and target object ID. Canonical `.frasm` syntax:
//! `s7commplus [version <u8>] [opcode <u8|str>] [isresponse] [func <str|u16>] [seqnum <u16>] [sessionid <u32>] [id <u32>] [flags <u8>]`.

/// Siemens S7commPlus (`0x72` over TPKT/COTP) protocol specification.
///
/// Syntax mapping: `s7commplus [version <u8>] [opcode <u8|str>] [isresponse] [func <str|u16>] [seqnum <u16>] [sessionid <u32>] [id <u32>] [flags <u8>]`
#[doc(alias = "s7commplus")]
#[doc(alias = "S7commPlus")]
#[doc(alias = "S7-1500")]
#[doc(alias = "S7-1200")]
#[doc(alias = "TIA Portal")]
#[doc(alias = "102")]
#[doc(alias = "version")]
#[doc(alias = "opcode")]
#[doc(alias = "isresponse")]
#[doc(alias = "func")]
#[doc(alias = "seqnum")]
#[doc(alias = "sessionid")]
#[doc(alias = "id")]
#[doc(alias = "flags")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct S7commplusSpec<'a> {
    /// S7commPlus protocol version byte (`version <u8>`, `1..=3`, default `1`).
    pub version: Option<u8>,
    /// 8-bit S7commPlus opcode (`opcode <u8|str>`, `0x31` Request, `0x32` Response, `0x33` Notification).
    pub opcode: Option<u8>,
    /// Response flag (`isresponse` / `response`), defaulting opcode to `0x32` and transport flags to `0x00`.
    pub is_response: bool,
    /// S7commPlus 16-bit function selector (`func <str|u16>`, e.g., `"explore"`, `"createobject"`, `"getmultivariables"`, default `"createobject"`).
    pub func: Option<&'a str>,
    /// 16-bit S7commPlus sequence number (`seqnum <u16>`, default `1`).
    pub seq_num: Option<u16>,
    /// 32-bit S7commPlus session identifier (`sessionid <u32>`, default `0`).
    pub session_id: Option<u32>,
    /// 32-bit S7commPlus target object or relation identifier (`id <u32>`, default `0`).
    pub object_id: Option<u32>,
    /// 8-bit S7commPlus transport flags byte (`flags <u8>`, default `0x36` on request, `0x00` on response).
    pub flags: Option<u8>,
}
