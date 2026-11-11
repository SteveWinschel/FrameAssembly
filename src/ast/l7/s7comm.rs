//! Siemens S7 Communication (S7comm, ISO-on-TCP RFC 1006) Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`S7commSpec`], the zero-copy AST representation of a Siemens SIMATIC S7
//! PLC communication frame over TCP port 102 (ISO-on-TCP, RFC 1006). On the wire, an S7comm packet
//! encapsulates a 4-byte TPKT header (Version `3`, 16-bit total length) and a 3-byte COTP DT Data
//! header (`0x02 0xF0 0x80`) around a 10-byte S7 header (`0x32` Protocol ID, `rosctr` message type,
//! PDU Reference, parameter length, and data length) plus `Setup_Communication` (`0xF0`),
//! `Read_Var` (`0x04`), `Write_Var` (`0x05`), or `PLC_Control` (`0x28`) parameters. Canonical `.fasm` syntax:
//! `s7comm [rosctr <str>] [pduref <u16>] [func <str>] [area <u8>] [dbnum <u16>] [offset <u32>] [count <u16>]`.

/// Siemens SIMATIC S7 Communication (S7comm over TPKT/COTP) protocol specification.
///
/// Syntax mapping: `s7comm [rosctr <str>] [pduref <u16>] [func <str>] [area <u8>] [dbnum <u16>] [offset <u32>] [count <u16>]`
#[doc(alias = "s7comm")]
#[doc(alias = "RFC 1006")]
#[doc(alias = "RFC1006")]
#[doc(alias = "ISO-on-TCP")]
#[doc(alias = "TPKT")]
#[doc(alias = "COTP")]
#[doc(alias = "rosctr")]
#[doc(alias = "pduref")]
#[doc(alias = "func")]
#[doc(alias = "area")]
#[doc(alias = "dbnum")]
#[doc(alias = "offset")]
#[doc(alias = "count")]
#[doc(alias = "102")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct S7commSpec<'a> {
    /// Remote Operating Service Control type (`rosctr <str>`, e.g., `"JOB"`, `"ACK"`, `"ACK_DATA"`, `"USERDATA"`).
    pub rosctr: Option<&'a str>,
    /// 16-bit S7 PDU Reference correlation identifier (`pduref <u16>`, default `1`).
    pub pdu_ref: Option<u16>,
    /// S7 parameter function name (`func <str>`, e.g., `"SETUP_COMM"`, `"READ_VAR"`, `"WRITE_VAR"`, `"PLC_CONTROL"`).
    pub func: Option<&'a str>,
    /// S7ANY memory area code (`area <u8>`, default `0x84` for Data Blocks).
    pub area: Option<u8>,
    /// Data Block number (`dbnum <u16>`, default `1`).
    pub db_num: Option<u16>,
    /// Byte/bit offset within the target memory area (`offset <u32>`, default `0`).
    pub offset: Option<u32>,
    /// Item byte/element count for `readvar` / `writevar` requests (`count <u16>`, default `1`).
    pub count: Option<u16>,
}
