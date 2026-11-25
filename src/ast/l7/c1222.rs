//! ANSI C12.22 / IEEE 1703 Smart Grid Metering Protocol Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`C1222Spec`], the zero-copy AST representation of an ANSI C12.22
//! (IEEE Std 1703) smart metering ACSE + EPSEM message over UDP port 1153 (default) or TCP port
//! 1153. On the wire, a C12.22 frame wraps connectionless ACSE BER headers (`0x60` APDU, `[2]`
//! `calledap`, optional `[4]` `calledid`, `[6]` `callingap`, optional `[8]` `callingid`, and
//! `[30]` `0xBE -> 0x28 -> 0x81` `user-information`) around an EPSEM control byte and C12.19
//! table service (`0x30` Full Read, `0x40` Full Write, `0x20` Identify, `0x50` Logon, `0x52`
//! Logoff, `0x21` Terminate, `0x00` OK response). Canonical `.frasm` syntax:
//! `c1222 [read | write | identify | logon | logoff | terminate | response | ok | service <str|u8>] [callingap <oid>] [calledap <oid>] [callingid <u32>] [calledid <u32>] [epsemctrl <u8>] [edclass <u32>] [tableid <u16>] [value <u16>] [errcode <u8>]`.

/// ANSI C12.22 / IEEE 1703 Smart Grid ACSE + EPSEM specification.
///
/// Syntax mapping: `c1222 [read | write | identify | logon | logoff | terminate | response | ok | service <str|u8>] [callingap <oid>] [calledap <oid>] [callingid <u32>] [calledid <u32>] [epsemctrl <u8>] [edclass <u32>] [tableid <u16>] [value <u16>] [errcode <u8>]`
#[doc(alias = "c1222")]
#[doc(alias = "ANSI C12.22")]
#[doc(alias = "IEEE 1703")]
#[doc(alias = "EPSEM")]
#[doc(alias = "1153")]
#[doc(alias = "read")]
#[doc(alias = "write")]
#[doc(alias = "identify")]
#[doc(alias = "logon")]
#[doc(alias = "logoff")]
#[doc(alias = "terminate")]
#[doc(alias = "response")]
#[doc(alias = "ok")]
#[doc(alias = "service")]
#[doc(alias = "callingap")]
#[doc(alias = "calledap")]
#[doc(alias = "callingid")]
#[doc(alias = "calledid")]
#[doc(alias = "epsemctrl")]
#[doc(alias = "edclass")]
#[doc(alias = "tableid")]
#[doc(alias = "value")]
#[doc(alias = "errcode")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct C1222Spec<'a> {
    /// EPSEM service request or response selector (`read`, `write`, `identify`, `logon`, `logoff`, `terminate`, `response`, `ok`, or `service <str|u8>`, default `"read"` `0x30`).
    pub service: Option<&'a str>,
    /// Calling Application Process Title OID (`callingap <oid>`, default `"2.16.840.1.114416.2"`).
    pub calling_ap: Option<&'a str>,
    /// Called Application Process Title OID (`calledap <oid>`, default `"2.16.840.1.114416.1"`).
    pub called_ap: Option<&'a str>,
    /// Optional Calling AP Invocation Identifier (`callingid <u32>`).
    pub calling_id: Option<u32>,
    /// Optional Called AP Invocation Identifier (`calledid <u32>`).
    pub called_id: Option<u32>,
    /// 8-bit EPSEM control flags byte (`epsemctrl <u8>`, default `0x00`).
    pub epsem_ctrl: Option<u8>,
    /// Optional 32-bit End-Device Class identifier (`edclass <u32>`, sets `0x10` in `epsemctrl`).
    pub ed_class: Option<u32>,
    /// 16-bit C12.19 table identifier for `read` and `write` (`tableid <u16>`, default `1`).
    pub table_id: Option<u16>,
    /// 16-bit table payload word for `write` and `response` (`value <u16>`, default `0`).
    pub value: Option<u16>,
    /// 8-bit EPSEM response error code (`errcode <u8>`, e.g., `1` ERR, `2` SNS, `3` ISC, `4` ONP).
    pub errcode: Option<u8>,
}
