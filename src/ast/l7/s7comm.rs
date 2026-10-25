//! Siemens S7 Communication (S7comm, ISO-on-TCP RFC 1006) Abstract Syntax Tree (AST) definitions.
//!
//! This module defines [`S7commSpec`], the zero-copy AST representation of a Siemens SIMATIC S7
//! PLC communication frame over TCP port 102 (ISO-on-TCP, RFC 1006). On the wire, an S7comm packet
//! encapsulates a 4-byte TPKT header (Version `3`, 16-bit total length) and a 3-byte COTP DT Data
//! header (`0x02 0xF0 0x80`) around a 10-byte S7 header (`0x32` Protocol ID, `ROSCTR` message type,
//! PDU Reference, parameter length, and data length) plus `Setup_Communication` (`0xF0`),
//! `Read_Var` (`0x04`), `Write_Var` (`0x05`), or `PLC_Control` (`0x28`) parameters. Canonical `.fasm` syntax:
//! `S7COMM [ROSCTR <str>] [PDU_REF <u16>] [FUNC <str>] [AREA <u8>] [DB_NUM <u16>] [OFFSET <u32>] [COUNT <u16>]`.

/// Siemens SIMATIC S7 Communication (S7comm over TPKT/COTP) protocol specification.
///
/// Syntax mapping: `S7COMM [ROSCTR <str>] [PDU_REF <u16>] [FUNC <str>] [AREA <u8>] [DB_NUM <u16>] [OFFSET <u32>] [COUNT <u16>]`
#[doc(alias = "S7COMM")]
#[doc(alias = "RFC 1006")]
#[doc(alias = "RFC1006")]
#[doc(alias = "ISO-on-TCP")]
#[doc(alias = "TPKT")]
#[doc(alias = "COTP")]
#[doc(alias = "ROSCTR")]
#[doc(alias = "PDU_REF")]
#[doc(alias = "FUNC")]
#[doc(alias = "AREA")]
#[doc(alias = "DB_NUM")]
#[doc(alias = "OFFSET")]
#[doc(alias = "COUNT")]
#[doc(alias = "102")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct S7commSpec<'a> {
    /// Remote Operating Service Control type (`ROSCTR <str>`, e.g., `"JOB"`, `"ACK"`, `"ACK_DATA"`, `"USERDATA"`).
    pub rosctr: Option<&'a str>,
    /// 16-bit S7 PDU Reference correlation identifier (`PDU_REF <u16>`, default `1`).
    pub pdu_ref: Option<u16>,
    /// S7 parameter function name (`FUNC <str>`, e.g., `"SETUP_COMM"`, `"READ_VAR"`, `"WRITE_VAR"`, `"PLC_CONTROL"`).
    pub func: Option<&'a str>,
    /// S7ANY memory area code (`AREA <u8>`, default `0x84` for Data Blocks).
    pub area: Option<u8>,
    /// Data Block number (`DB_NUM <u16>`, default `1`).
    pub db_num: Option<u16>,
    /// Byte/bit offset within the target memory area (`OFFSET <u32>`, default `0`).
    pub offset: Option<u32>,
    /// Item byte/element count for `READ_VAR` / `WRITE_VAR` requests (`COUNT <u16>`, default `1`).
    pub count: Option<u16>,
}
